//! Applying a generation, commit-confirm, rollback.
//!
//! apply:   write changed files, fix rc state, restart what changed, then
//!          record the generation as pending and start a watchdog. Without
//!          `octopus confirm` before the deadline the watchdog re-applies the
//!          previous confirmed generation. A reboot while pending does the
//!          same (`octopus boot` from /etc/rc.d/octopus).
//! failure: any error while applying re-applies the previous generation
//!          immediately.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use octopus_render::{Service, Subsystem};
use serde::{Deserialize, Serialize};

use crate::gens::{self, Manifest, owned_by_glob};
use crate::os::{self, Res, log, now, run};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub current: Option<u32>,
    pub confirmed: Option<u32>,
    pub pending: Option<Pending>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub generation: u32,
    pub previous: u32,
    pub deadline: u64,
}

fn state_path() -> PathBuf {
    gens::root().join("state.json")
}

pub fn lock_path() -> PathBuf {
    gens::root().join("lock")
}

pub fn load_state() -> State {
    fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

pub fn save_state(s: &State) -> Res<()> {
    let t = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    os::write_atomic(&state_path(), t.as_bytes(), 0o644, "root", "wheel")
}

/// Current enabled/flags of a service according to rcctl.
fn service_state(name: &str) -> Option<(bool, String)> {
    let status = Command::new("rcctl")
        .args(["get", name, "status"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    match status.code() {
        Some(0) => Some((true, run("rcctl", &["get", name, "flags"]).unwrap_or_default().trim().to_string())),
        Some(1) => Some((false, String::new())),
        _ => None,
    }
}

/// rc state of the given services right now, for the baseline.
pub fn services_now(names: &[Service]) -> Vec<Service> {
    names
        .iter()
        .map(|s| {
            // a service that doesn't exist yet (our own) was off before octopus
            let (enabled, flags) = service_state(&s.name).unwrap_or((false, String::new()));
            Service {
                name: s.name.clone(),
                enabled,
                flags: enabled.then_some(flags),
                subsystem: s.subsystem,
                restart: s.restart,
            }
        })
        .collect()
}

/// Every enabled service needs an rc.d script before we touch anything.
pub fn preflight(m: &Manifest) -> Res<()> {
    for s in m.services.iter().filter(|s| s.enabled) {
        if !std::path::Path::new(&format!("/etc/rc.d/{}", s.name)).exists() {
            return Err(format!(
                "service {} is enabled but /etc/rc.d/{} is missing (install the octopus package set)",
                s.name, s.name
            ));
        }
    }
    Ok(())
}

fn live_sha(path: &str) -> Option<(String, u32)> {
    use std::os::unix::fs::MetadataExt;
    let c = fs::read(path).ok()?;
    let mode = fs::metadata(path).ok()?.mode() & 0o7777;
    Some((gens::sha(&c), mode))
}

#[derive(Debug, Default)]
pub struct Plan {
    pub write: Vec<String>,
    pub delete: Vec<String>,
    pub subsystems: BTreeSet<Subsystem>,
}

/// What applying `target` over the live system would change. `from` is the
/// generation that is live now, if any.
pub fn plan(target: &Manifest, from: Option<&Manifest>) -> Plan {
    let mut p = Plan::default();
    for f in &target.files {
        if live_sha(&f.path) != Some((f.sha256.clone(), f.mode)) {
            p.write.push(f.path.clone());
            p.subsystems.insert(f.subsystem);
        }
    }
    let keep: BTreeSet<&str> = target.files.iter().map(|f| f.path.as_str()).collect();
    let mut candidates: BTreeSet<String> = target.absent.iter().cloned().collect();
    if let Some(m) = from {
        candidates.extend(m.files.iter().map(|f| f.path.clone()));
    }
    if let Ok(rd) = fs::read_dir("/etc") {
        for e in rd.flatten() {
            let path = format!("/etc/{}", e.file_name().to_string_lossy());
            if owned_by_glob(&path) {
                candidates.insert(path);
            }
        }
    }
    for c in candidates {
        if !keep.contains(c.as_str()) && fs::symlink_metadata(&c).is_ok() {
            p.subsystems.insert(gens::subsystem_of(&c));
            p.delete.push(c);
        }
    }
    p
}

fn kind_of(ifname: &str) -> Option<&'static str> {
    ["vlan", "svlan", "pppoe", "wg", "pflow", "vether", "veb", "vport", "bridge", "carp", "gif", "gre"]
        .into_iter()
        .find(|p| ifname.starts_with(p) && ifname[p.len()..].chars().all(|c| c.is_ascii_digit()))
}

/// Recreated from scratch when its file changes. A vport is only
/// re-addressed: destroying it would take it out of its bridge.
fn is_pseudo(ifname: &str) -> bool {
    kind_of(ifname).is_some_and(|k| k != "vport")
}

/// Order: ports, vports, then vlans on the ports, pppoe on the vlans, the
/// rest, and bridges last (their members must exist).
fn if_rank(ifname: &str) -> u8 {
    match kind_of(ifname) {
        None | Some("vport") => 0,
        Some("vlan" | "svlan") => 1,
        Some("pppoe") => 2,
        Some("veb" | "bridge") => 4,
        Some(_) => 3,
    }
}

/// Apply `target` (already stored) over what's live. Returns the actions taken.
pub fn apply_manifest(target: &Manifest, from: Option<&Manifest>) -> Res<Vec<String>> {
    let mut done = vec![];
    let p = plan(target, from);

    // files
    for path in &p.write {
        let f = target.files.iter().find(|f| &f.path == path).unwrap();
        let c = gens::content(target.generation, path)?;
        os::write_atomic(std::path::Path::new(path), &c, f.mode, &f.owner, &f.group)?;
        done.push(format!("wrote {path}"));
    }
    for path in &p.delete {
        fs::remove_file(path).map_err(|e| format!("{path}: {e}"))?;
        done.push(format!("removed {path}"));
    }

    // rc state; services the live generation had and the target doesn't
    // mention are ones octopus turned on: turn them off again
    let mut restart: BTreeSet<String> = BTreeSet::new();
    // new flags only take effect on a restart, never a reload
    let mut reflag: BTreeSet<String> = BTreeSet::new();
    let mut stop: BTreeSet<String> = BTreeSet::new();
    let mut wanted = target.services.clone();
    if let Some(f) = from {
        for s in &f.services {
            if s.enabled && !wanted.iter().any(|w| w.name == s.name) {
                wanted.push(Service { enabled: false, flags: None, ..s.clone() });
            }
        }
    }
    for s in &wanted {
        let Some((enabled, flags)) = service_state(&s.name) else {
            if s.enabled {
                return Err(format!("service {} does not exist", s.name));
            }
            continue;
        };
        if s.enabled {
            let want_flags = s.flags.clone().unwrap_or_default();
            if !enabled {
                run("rcctl", &["set", &s.name, "status", "on"])?;
                done.push(format!("enabled {}", s.name));
                restart.insert(s.name.clone());
            }
            if s.flags.is_some() && flags != want_flags {
                let mut args = vec!["set", s.name.as_str(), "flags"];
                args.extend(want_flags.split_whitespace());
                run("rcctl", &args)?;
                done.push(format!("{} flags: {want_flags}", s.name));
                restart.insert(s.name.clone());
                reflag.insert(s.name.clone());
            }
            if s.restart && p.subsystems.contains(&s.subsystem) {
                restart.insert(s.name.clone());
            }
            if !service_running(&s.name) {
                restart.insert(s.name.clone());
            }
        } else if enabled {
            run("rcctl", &["set", &s.name, "status", "off"])?;
            done.push(format!("disabled {}", s.name));
            stop.insert(s.name.clone());
        }
    }

    // network first: pf expands `self` and interface addresses at load time
    if p.subsystems.contains(&Subsystem::Net) {
        let mut ifs: Vec<(String, bool)> = vec![];
        for path in p.write.iter().chain(&p.delete) {
            if let Some(i) = path.strip_prefix("/etc/hostname.") {
                ifs.push((i.to_string(), p.delete.contains(path)));
            }
        }
        // removals in reverse dependency order, then (re)configuration
        ifs.sort_by_key(|(i, _)| std::cmp::Reverse(if_rank(i)));
        for (i, _) in ifs.iter().filter(|(_, del)| *del) {
            if kind_of(i).is_some() {
                let _ = run("ifconfig", &[i, "destroy"]);
            } else {
                let _ = run("ifconfig", &[i, "-inet", "down"]);
            }
            done.push(format!("unconfigured {i}"));
        }
        ifs.sort_by_key(|(i, _)| if_rank(i));
        for (i, _) in ifs.iter().filter(|(_, del)| !*del) {
            if is_pseudo(i) {
                let _ = run("ifconfig", &[i, "destroy"]);
            } else {
                let _ = run("ifconfig", &[i, "-inet"]);
            }
            run("sh", &["/etc/netstart", i])?;
            done.push(format!("netstart {i}"));
        }
        if p.write.iter().chain(&p.delete).any(|x| x == "/etc/mygate") {
            let _ = run("route", &["-qn", "delete", "default"]);
            if let Ok(gw) = fs::read_to_string("/etc/mygate") {
                run("route", &["-qn", "add", "default", gw.trim()])?;
            }
            done.push("default route".into());
        }
    }
    if p.write.iter().any(|x| x == "/etc/myname")
        && let Ok(name) = fs::read_to_string("/etc/myname")
    {
        run("hostname", &[name.trim()])?;
        done.push(format!("hostname {}", name.trim()));
    }
    if p.subsystems.contains(&Subsystem::Sysctl) {
        // set what the file says; a removed line keeps its current value until reboot
        for l in fs::read_to_string("/etc/sysctl.conf").unwrap_or_default().lines() {
            let l = l.split('#').next().unwrap_or("").trim();
            if !l.is_empty() {
                run("sysctl", &["-q", l])?;
                done.push(format!("sysctl {l}"));
            }
        }
    }
    if p.subsystems.contains(&Subsystem::Pf) || p.subsystems.contains(&Subsystem::Net) {
        run("pfctl", &["-f", "/etc/pf.conf"])?;
        let _ = run("pfctl", &["-e"]);
        done.push("pfctl -f /etc/pf.conf".into());
    }

    for name in &stop {
        let _ = run("rcctl", &["stop", name]);
        done.push(format!("stopped {name}"));
    }
    // reload where the daemon re-reads cleanly, restart otherwise
    for name in &restart {
        let action = match name.as_str() {
            "sshd" | "syslogd" if service_running(name) && !reflag.contains(name) => "reload",
            _ => "restart",
        };
        run("rcctl", &[action, name])?;
        done.push(format!("{action} {name}"));
    }
    // last: the access points (one that can't be reached doesn't fail this)
    if p.subsystems.contains(&Subsystem::Ap) {
        done.extend(crate::ap::push_changed(&p.write));
    }
    Ok(done)
}

fn service_running(name: &str) -> bool {
    os::ok("rcctl", &["check", name])
}

pub const SOURCE: &str = "/etc/octopus/router.toml";
pub const BIN: &str = "/usr/local/sbin/octopus";

/// /etc/octopus/router.toml follows the live generation, so it always
/// describes what is running (and the web UI edits that).
pub fn install_source(generation: u32) -> Res<()> {
    let p = gens::dir(generation).join("router.toml");
    match fs::read(&p) {
        Ok(c) => os::write_atomic(std::path::Path::new(SOURCE), &c, 0o644, "root", "wheel"),
        Err(_) => Ok(()), // the baseline has none
    }
}

/// Spawn the commit-confirm watchdog, detached from our session.
pub fn spawn_watchdog(generation: u32, deadline: u64) -> Res<()> {
    // OpenBSD can't tell a process its own path (current_exe fails there)
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(BIN));
    let mut cmd = Command::new(exe);
    cmd.args(["_watchdog", &generation.to_string(), &deadline.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("watchdog: {e}"))?;
    Ok(())
}

/// Run `octopus ARGS` detached (after a confirm: acme-client for new public
/// sites, which may take a while and must not hold the web UI's request).
pub fn spawn_detached(args: &[&str]) -> Res<()> {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(BIN));
    let mut cmd = Command::new(exe);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("{}: {e}", args.join(" ")))?;
    Ok(())
}

pub fn watchdog(generation: u32, deadline: u64) -> Res<()> {
    loop {
        let st = load_state();
        match &st.pending {
            Some(p) if p.generation == generation => {}
            _ => return Ok(()), // confirmed or superseded
        }
        if now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let _l = loop {
        match os::lock(&lock_path()) {
            Ok(l) => break l,
            Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
    };
    let st = load_state();
    if let Some(p) = &st.pending
        && p.generation == generation
    {
        log(&format!("generation {generation} not confirmed in time; rolling back to {}", p.previous));
        revert_pending(&st)?;
    }
    Ok(())
}

/// Re-apply the generation that was live before the pending one.
pub fn revert_pending(st: &State) -> Res<()> {
    let p = st.pending.as_ref().ok_or("nothing is pending")?;
    let from = gens::load(p.generation).ok();
    let to = gens::load(p.previous)?;
    let actions = apply_manifest(&to, from.as_ref())?;
    for a in &actions {
        log(&format!("rollback: {a}"));
    }
    let new = State { current: Some(p.previous), confirmed: Some(p.previous), pending: None };
    save_state(&new)?;
    install_source(p.previous)?;
    log(&format!("rolled back to generation {}", p.previous));
    Ok(())
}
