//! `octopus ap`: the OpenWrt access points.
//!
//!   key            the router's SSH key for them (made once); prints the
//!                  public half for the access point image
//!   push [NAME]    run each access point's script (/etc/octopus/ap/NAME.sh,
//!                  from the live generation) on it over SSH; unchanged ones
//!                  are skipped unless --force
//!   status         the last push of each
//!
//! `apply` and `rollback` push every script the access point hasn't taken
//! yet (by its SHA-256 in the state file). An access point that can't be
//! reached doesn't fail them: it is marked and the next apply catches up.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use octopus_render::wifi::AP_DIR;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::os::{self, Res, log, now};

pub const KEY: &str = "/etc/octopus/ap.key";
const KNOWN_HOSTS: &str = "/etc/octopus/ap.known_hosts";
pub const STATE: &str = "/var/octopus/ap-state.json";
/// One push at a time (apply, rollback, `ap push`, the web UI's button).
const LOCK: &str = "/var/octopus/ap.lock";

/// The name an access point's host key is pinned under: its name, not its
/// address, so moving it to another address can't redirect a push.
fn alias(name: &str) -> String {
    format!("octopus-ap-{name}")
}

/// Is this access point's host key pinned? An entry from before the pins
/// (by address, trusted on first contact) becomes its pin.
fn pinned(name: &str, address: &str) -> bool {
    let text = fs::read_to_string(KNOWN_HOSTS).unwrap_or_default();
    let a = alias(name);
    if text.lines().any(|l| l.split_whitespace().next() == Some(a.as_str())) {
        return true;
    }
    let old: Vec<String> = text
        .lines()
        .filter(|l| l.split_whitespace().next().is_some_and(|h| h.split(',').any(|x| x == address)))
        .filter_map(|l| l.split_once(' ').map(|(_, key)| format!("{a} {key}")))
        .collect();
    if old.is_empty() {
        return false;
    }
    let all = format!("{text}{}\n", old.join("\n"));
    os::write_atomic(Path::new(KNOWN_HOSTS), all.as_bytes(), 0o644, "root", "wheel").is_ok()
}

/// `octopus ap trust NAME`: pin the host key the access point shows now
/// (compare its fingerprint with the access point's console:
/// `dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key`).
fn trust(name: &str) -> Res<()> {
    let script = fs::read_to_string(format!("{AP_DIR}/{name}.sh"))
        .map_err(|_| format!("no access point {name} in the live generation"))?;
    let (_, address) = target(&script).ok_or("no octopus-ap header")?;
    let scan = os::run("ssh-keyscan", &["-T", "8", "-t", "ed25519", &address])?;
    let line = scan.lines().find(|l| !l.starts_with('#')).ok_or(format!("{address}: no host key"))?;
    let (_, key) = line.split_once(' ').ok_or("unexpected ssh-keyscan output")?;
    let a = alias(name);
    let text = fs::read_to_string(KNOWN_HOSTS).unwrap_or_default();
    let entry = format!("{a} {key}");
    let mut keep: Vec<&str> = text.lines().filter(|l| l.split_whitespace().next() != Some(a.as_str())).collect();
    keep.push(&entry);
    os::write_atomic(Path::new(KNOWN_HOSTS), (keep.join("\n") + "\n").as_bytes(), 0o644, "root", "wheel")?;
    let fp = Command::new("ssh-keygen")
        .args(["-l", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            if let Some(mut i) = c.stdin.take() {
                let _ = i.write_all(format!("{address} {key}\n").as_bytes());
            }
            c.wait_with_output()
        })
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    log(&format!("ap {name}: host key at {address} pinned: {fp}"));
    out!("{name} ({address}): {fp}\npinned; compare it with the access point's console");
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ApState {
    pub address: String,
    pub ok: bool,
    /// applied, unchanged, or the error
    pub result: String,
    pub at: u64,
    /// SHA-256 of the script it last took.
    #[serde(default)]
    pub sha: String,
}

pub fn root() -> Res<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("run as root (the key and the state are root's)".into());
    }
    Ok(())
}

pub fn load_state() -> BTreeMap<String, ApState> {
    fs::read_to_string(STATE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Make the key if it is missing; the public half.
pub fn key() -> Res<String> {
    if !Path::new(KEY).exists() {
        os::run("ssh-keygen", &["-q", "-t", "ed25519", "-N", "", "-C", "octopus-ap", "-f", KEY])?;
        log("ap: made the access points' SSH key");
    }
    fs::read_to_string(format!("{KEY}.pub")).map(|s| s.trim().to_string()).map_err(|e| format!("{KEY}.pub: {e}"))
}

/// (name, address) from a script's first lines.
fn target(script: &str) -> Option<(String, String)> {
    let l = script.lines().find(|l| l.starts_with("# octopus-ap "))?;
    let mut name = None;
    let mut addr = None;
    for kv in l.trim_start_matches("# octopus-ap ").split_whitespace() {
        match kv.split_once('=') {
            Some(("name", v)) => name = Some(v.to_string()),
            Some(("address", v)) => addr = Some(v.to_string()),
            _ => {}
        }
    }
    Some((name?, addr?))
}

/// Push one script. Never fails the caller: the outcome goes to the state file.
pub fn push_file(path: &str, force: bool) -> (String, ApState) {
    let script = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return (path.to_string(), ApState { result: format!("{path}: {e}"), at: now(), ..Default::default() });
        }
    };
    let Some((name, address)) = target(&script) else {
        return (path.to_string(), ApState { result: "no octopus-ap header".into(), at: now(), ..Default::default() });
    };
    let sha = format!("{:x}", Sha256::digest(script.as_bytes()));
    let _l = os::lock_wait(Path::new(LOCK), 300);
    let outcome = if pinned(&name, &address) {
        run_ssh(&name, &address, &sha, force, &script)
    } else {
        Err(format!("its host key isn't pinned: `octopus ap trust {name}` on the router (check the fingerprint)"))
    };
    let st = match outcome {
        Ok(out) => ApState {
            address,
            ok: true,
            result: out.trim().lines().last().unwrap_or("applied").to_string(),
            at: now(),
            sha: sha.clone(),
        },
        Err(e) => ApState { address, ok: false, result: e, at: now(), sha: String::new() },
    };
    // recorded before anything is printed: whoever reads our output may be gone
    let mut all = load_state();
    all.insert(name.clone(), st.clone());
    let _ = os::write_atomic(
        Path::new(STATE),
        serde_json::to_string_pretty(&all).unwrap_or_default().as_bytes(),
        0o644,
        "root",
        "wheel",
    );
    log(&format!("ap {name}: {} {}", if st.ok { "ok" } else { "FAILED" }, st.result));
    (name, st)
}

fn run_ssh(name: &str, address: &str, sha: &str, force: bool, script: &str) -> Res<String> {
    if !Path::new(KEY).exists() {
        return Err(format!("no {KEY}: run `octopus ap key` and put the key on the access point"));
    }
    let mut child = Command::new("ssh")
        .args(["-i", KEY, "-o", &format!("UserKnownHostsFile={KNOWN_HOSTS}"), "-o", "StrictHostKeyChecking=yes"])
        .args(["-o", &format!("HostKeyAlias={}", alias(name))])
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
        ])
        .arg(format!("root@{address}"))
        // the hash goes on stdin: argv is in everyone's ps
        .arg("sh -s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;
    let input = format!("SHA={sha}\nFORCE={}\n{script}", if force { "1" } else { "" });
    child.stdin.take().map(|mut i| i.write_all(input.as_bytes())).transpose().map_err(|e| format!("ssh: {e}"))?;
    // the script answers within seconds; reloads run after it, in the background
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(_status) = child.try_wait().map_err(|e| e.to_string())? {
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            return Err("no answer in 60 s".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let o = child.wait_with_output().map_err(|e| e.to_string())?;
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    if o.status.success() {
        Ok(out)
    } else {
        let err = String::from_utf8_lossy(&o.stderr);
        Err(err.trim().lines().last().unwrap_or("failed").to_string())
    }
}

/// Every access point's script (or one).
pub fn push(only: Option<&str>, force: bool) -> Res<Vec<(String, ApState)>> {
    let mut files: Vec<String> = fs::read_dir(AP_DIR)
        .map(|d| d.flatten().map(|e| e.path().to_string_lossy().into_owned()).filter(|p| p.ends_with(".sh")).collect())
        .unwrap_or_default();
    files.sort();
    if let Some(n) = only {
        files.retain(|p| p == &format!("{AP_DIR}/{n}.sh"));
        if files.is_empty() {
            return Err(format!("no access point {n} in the live generation"));
        }
    }
    Ok(files.iter().map(|f| push_file(f, force)).collect())
}

/// After apply or rollback: every access point whose live script isn't the
/// one it last took (changed now, or left behind by a push that was cut short).
pub fn push_stale() -> Vec<String> {
    let state = load_state();
    let mut files: Vec<String> = fs::read_dir(AP_DIR)
        .map(|d| d.flatten().map(|e| e.path().to_string_lossy().into_owned()).filter(|p| p.ends_with(".sh")).collect())
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .filter(|p| {
            let name = Path::new(p).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let sha = fs::read(p).map(|c| format!("{:x}", Sha256::digest(&c))).unwrap_or_default();
            state.get(&name).is_none_or(|s| s.sha != sha)
        })
        .map(|p| {
            let (name, st) = push_file(p, false);
            if st.ok {
                format!("ap {name}: {}", st.result)
            } else {
                format!("ap {name} NOT updated: {} (octopus ap push)", st.result)
            }
        })
        .collect()
}

pub fn cmd(sub: &str, name: Option<&str>, force: bool) -> Res<()> {
    match sub {
        "key" => {
            out!("{}", key()?);
            Ok(())
        }
        "push" => {
            let mut failed = 0;
            for (n, st) in push(name, force)? {
                out!("{n:<16} {:<15} {} {}", st.address, if st.ok { "ok" } else { "FAILED" }, st.result);
                failed += usize::from(!st.ok);
            }
            if failed > 0 { Err(format!("{failed} access point(s) not updated")) } else { Ok(()) }
        }
        "trust" => trust(name.ok_or("ap trust NAME")?),
        "status" => {
            for (n, st) in load_state() {
                out!("{n:<16} {:<15} {} {} ({})", st.address, if st.ok { "ok" } else { "FAILED" }, st.result, st.at);
            }
            Ok(())
        }
        _ => Err("usage: octopus ap key | push [NAME] [--force] | trust NAME | status".into()),
    }
}
