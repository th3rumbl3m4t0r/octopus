//! `octopus ap`: the OpenWrt access points.
//!
//!   key            the router's SSH key for them (made once); prints the
//!                  public half for the access point image
//!   push [NAME]    run each access point's script (/etc/octopus/ap/NAME.sh,
//!                  from the live generation) on it over SSH; unchanged ones
//!                  are skipped unless --force
//!   status         the last push of each
//!
//! `apply` and `rollback` push the scripts that changed. An access point
//! that can't be reached doesn't fail them: it is marked and the next push
//! catches up.

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

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ApState {
    pub address: String,
    pub ok: bool,
    /// applied, unchanged, or the error
    pub result: String,
    pub at: u64,
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
    let outcome = run_ssh(&address, &sha, force, &script);
    let st = match outcome {
        Ok(out) => {
            ApState { address, ok: true, result: out.trim().lines().last().unwrap_or("applied").to_string(), at: now() }
        }
        Err(e) => ApState { address, ok: false, result: e, at: now() },
    };
    log(&format!("ap {name}: {} {}", if st.ok { "ok" } else { "FAILED" }, st.result));
    let mut all = load_state();
    all.insert(name.clone(), st.clone());
    let _ = os::write_atomic(
        Path::new(STATE),
        serde_json::to_string_pretty(&all).unwrap_or_default().as_bytes(),
        0o644,
        "root",
        "wheel",
    );
    (name, st)
}

fn run_ssh(address: &str, sha: &str, force: bool, script: &str) -> Res<String> {
    if !Path::new(KEY).exists() {
        return Err(format!("no {KEY}: run `octopus ap key` and put the key on the access point"));
    }
    let mut child = Command::new("ssh")
        .args(["-i", KEY, "-o", &format!("UserKnownHostsFile={KNOWN_HOSTS}"), "-o", "StrictHostKeyChecking=accept-new"])
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
        .arg(format!("SHA={sha} FORCE={} sh -s", if force { "1" } else { "" }))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;
    child.stdin.take().map(|mut i| i.write_all(script.as_bytes())).transpose().map_err(|e| format!("ssh: {e}"))?;
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

/// After apply or rollback wrote these files.
pub fn push_changed(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| p.starts_with(AP_DIR) && p.ends_with(".sh"))
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
            println!("{}", key()?);
            Ok(())
        }
        "push" => {
            let mut failed = 0;
            for (n, st) in push(name, force)? {
                println!("{n:<16} {:<15} {} {}", st.address, if st.ok { "ok" } else { "FAILED" }, st.result);
                failed += usize::from(!st.ok);
            }
            if failed > 0 { Err(format!("{failed} access point(s) not updated")) } else { Ok(()) }
        }
        "status" => {
            for (n, st) in load_state() {
                println!(
                    "{n:<16} {:<15} {} {} ({})",
                    st.address,
                    if st.ok { "ok" } else { "FAILED" },
                    st.result,
                    st.at
                );
            }
            Ok(())
        }
        _ => Err("usage: octopus ap key | push [NAME] [--force] | status".into()),
    }
}
