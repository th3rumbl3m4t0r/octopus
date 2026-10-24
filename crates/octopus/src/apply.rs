//! Applying a generation, commit-confirm, rollback.
//!
//! apply:   record the generation as pending (write-ahead) and start the
//!          watchdog, then write changed files, fix rc state and restart
//!          what changed. Without `octopus confirm` before the window ends
//!          the watchdog re-applies the previous confirmed generation. If
//!          the apply itself dies halfway (a signal, a crash, power), the
//!          watchdog sees it gone and reverts at once, and a reboot reverts
//!          at boot (`octopus boot` from /etc/rc.local).
//! failure: any error while applying re-applies the previous generation
//!          immediately.
//! revert:  best effort: every step runs even when one fails, pf and sshd
//!          first; a revert with errors stays pending and the watchdog
//!          tries again.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
    /// Wall clock, for people and for `octopus boot`; the watchdog counts
    /// `window` on the monotonic clock, so setting the date moves nothing.
    pub deadline: u64,
    /// Seconds to confirm, counted from the end of the apply.
    #[serde(default)]
    pub window: u64,
    /// Still being applied (its process holds the lock). A watchdog that
    /// finds the lock free while this is set reverts at once.
    #[serde(default)]
    pub applying: bool,
    /// kern.boottime of the boot that applied it: `octopus boot` leaves a
    /// generation applied during this same boot (rc.firsttime) to its watchdog.
    #[serde(default)]
    pub boot: String,
    /// A revert has started: too late to confirm.
    #[serde(default)]
    pub reverting: bool,
    /// Reverts that ended with errors; the watchdog tries again.
    #[serde(default)]
    pub revert_failures: u32,
}

/// Reverts with errors are retried this often (the watchdog, backing off).
const REVERT_TRIES: u32 = 5;

fn state_path() -> PathBuf {
    gens::root().join("state.json")
}

pub fn lock_path() -> PathBuf {
    gens::root().join("lock")
}

/// The commit-confirm state. Missing is a fresh router; unreadable is an
/// error: guessing would make generation 0 the rollback target.
pub fn load_state() -> Res<State> {
    match fs::read_to_string(state_path()) {
        Ok(t) => serde_json::from_str(&t)
            .map_err(|e| format!("{} is damaged ({e}); fix or remove it by hand", state_path().display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(format!("{}: {e}", state_path().display())),
    }
}

pub fn save_state(s: &State) -> Res<()> {
    let t = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    os::write_atomic(&state_path(), t.as_bytes(), 0o644, "root", "wheel")
}

/// When this system booted, to tell this boot from the last.
pub fn boot_id() -> String {
    run("sysctl", &["-n", "kern.boottime"]).map(|s| s.trim().to_string()).unwrap_or_default()
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
    /// Already as wanted on disk, but different from the generation that
    /// should be live (`from`): a revert that failed halfway, or a
    /// generation that was never recorded. Their subsystems are redone.
    pub rerun: Vec<String>,
    pub subsystems: BTreeSet<Subsystem>,
}

impl Plan {
    /// Everything whose daemon-side action is due.
    fn touched(&self) -> impl Iterator<Item = &String> {
        self.write.iter().chain(&self.delete).chain(&self.rerun)
    }
}

/// What applying `target` over the live system would change. `from` is the
/// generation that is live now, if any.
pub fn plan(target: &Manifest, from: Option<&Manifest>) -> Plan {
    let mut p = Plan::default();
    for f in &target.files {
        if live_sha(&f.path) != Some((f.sha256.clone(), f.mode)) {
            p.write.push(f.path.clone());
            p.subsystems.insert(f.subsystem);
        } else if let Some(m) = from
            && m.files.iter().find(|x| x.path == f.path).is_none_or(|x| x.sha256 != f.sha256)
        {
            p.rerun.push(f.path.clone());
            p.subsystems.insert(f.subsystem);
        }
    }
    let keep: BTreeSet<&str> = target.files.iter().map(|f| f.path.as_str()).collect();
    let mut candidates: BTreeSet<String> = target.absent.iter().cloned().collect();
    if let Some(m) = from {
        candidates.extend(m.files.iter().map(|f| f.path.clone()));
    }
    // every file any stored generation wrote is ours: a generation whose
    // apply was never recorded leaves no orphans behind
    for n in gens::list() {
        if let Ok(m) = gens::load(n) {
            candidates.extend(m.files.into_iter().map(|f| f.path));
        }
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
        if keep.contains(c.as_str()) {
            continue;
        }
        if fs::symlink_metadata(&c).is_ok() {
            p.subsystems.insert(gens::subsystem_of(&c));
            p.delete.push(c);
        } else if from.is_some_and(|m| m.files.iter().any(|f| f.path == c)) {
            // gone already, but the generation that should be live has it
            p.subsystems.insert(gens::subsystem_of(&c));
            p.rerun.push(c);
        }
    }
    p
}

/// Same files, same contents: nothing would change by recording `b` over `a`.
pub fn same_files(a: &Manifest, b: &Manifest) -> bool {
    let set =
        |m: &Manifest| m.files.iter().map(|f| (f.path.clone(), f.sha256.clone(), f.mode)).collect::<BTreeSet<_>>();
    set(a) == set(b) && a.services == b.services
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

/// Steps of an apply: a forward apply stops at the first error (the caller
/// reverts); a revert carries on and reports every error at the end.
struct Steps {
    best_effort: bool,
    done: Vec<String>,
    errors: Vec<String>,
}

impl Steps {
    fn check<T>(&mut self, r: Res<T>) -> Res<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) if self.best_effort => {
                log(&format!("revert: {e}"));
                self.errors.push(e);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn run(&mut self, cmd: &str, args: &[&str], what: String) -> Res<()> {
        if self.check(run(cmd, args))?.is_some() {
            self.done.push(what);
        }
        Ok(())
    }
}

/// Apply `target` (already stored) over what's live. Returns the actions
/// taken; stops at the first error.
pub fn apply_manifest(target: &Manifest, from: Option<&Manifest>) -> Res<Vec<String>> {
    let mut st = Steps { best_effort: false, done: vec![], errors: vec![] };
    steps(&mut st, target, from)?;
    Ok(st.done)
}

/// Apply `target` doing every step whatever fails: (actions, errors).
pub fn revert_manifest(target: &Manifest, from: Option<&Manifest>) -> (Vec<String>, Vec<String>) {
    let mut st = Steps { best_effort: true, done: vec![], errors: vec![] };
    let _ = steps(&mut st, target, from);
    (st.done, st.errors)
}

fn steps(st: &mut Steps, target: &Manifest, from: Option<&Manifest>) -> Res<()> {
    let p = plan(target, from);

    // files
    for path in &p.write {
        let f = target.files.iter().find(|f| &f.path == path).unwrap();
        let w = gens::content(target.generation, path)
            .and_then(|c| os::write_atomic(std::path::Path::new(path), &c, f.mode, &f.owner, &f.group));
        if st.check(w)?.is_some() {
            st.done.push(format!("wrote {path}"));
        }
    }
    for path in &p.delete {
        if st.check(fs::remove_file(path).map_err(|e| format!("{path}: {e}")))?.is_some() {
            st.done.push(format!("removed {path}"));
        }
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
                st.check::<()>(Err(format!("service {} does not exist", s.name)))?;
            }
            continue;
        };
        if s.enabled {
            let want_flags = s.flags.clone().unwrap_or_default();
            if !enabled {
                st.run("rcctl", &["set", &s.name, "status", "on"], format!("enabled {}", s.name))?;
                restart.insert(s.name.clone());
            }
            if s.flags.is_some() && flags != want_flags {
                let mut args = vec!["set", s.name.as_str(), "flags"];
                args.extend(want_flags.split_whitespace());
                st.run("rcctl", &args, format!("{} flags: {want_flags}", s.name))?;
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
            st.run("rcctl", &["set", &s.name, "status", "off"], format!("disabled {}", s.name))?;
            stop.insert(s.name.clone());
        }
    }

    // network first: pf expands `self` and interface addresses at load time
    if p.subsystems.contains(&Subsystem::Net) {
        let mut ifs: Vec<(String, bool)> = vec![];
        for path in p.touched() {
            if let Some(i) = path.strip_prefix("/etc/hostname.") {
                ifs.push((i.to_string(), fs::symlink_metadata(path).is_err()));
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
            st.done.push(format!("unconfigured {i}"));
        }
        ifs.sort_by_key(|(i, _)| if_rank(i));
        for (i, _) in ifs.iter().filter(|(_, del)| !*del) {
            if is_pseudo(i) {
                let _ = run("ifconfig", &[i, "destroy"]);
            } else {
                let _ = run("ifconfig", &[i, "-inet"]);
            }
            st.run("sh", &["/etc/netstart", i], format!("netstart {i}"))?;
        }
        if p.touched().any(|x| x == "/etc/mygate") {
            let _ = run("route", &["-qn", "delete", "default"]);
            if let Ok(gw) = fs::read_to_string("/etc/mygate") {
                st.run("route", &["-qn", "add", "default", gw.trim()], "default route".into())?;
            }
        }
    }
    if p.touched().any(|x| x == "/etc/myname")
        && let Ok(name) = fs::read_to_string("/etc/myname")
    {
        st.run("hostname", &[name.trim()], format!("hostname {}", name.trim()))?;
    }
    if p.subsystems.contains(&Subsystem::Sysctl) {
        // set what the file says; a removed line keeps its current value until reboot
        for l in fs::read_to_string("/etc/sysctl.conf").unwrap_or_default().lines() {
            let l = l.split('#').next().unwrap_or("").trim();
            if !l.is_empty() {
                st.run("sysctl", &["-q", l], format!("sysctl {l}"))?;
            }
        }
    }
    // a revert always reloads pf: the ruleset may be anything after a failure
    if p.subsystems.contains(&Subsystem::Pf) || p.subsystems.contains(&Subsystem::Net) || st.best_effort {
        st.run("pfctl", &["-f", "/etc/pf.conf"], "pfctl -f /etc/pf.conf".into())?;
        let _ = run("pfctl", &["-e"]);
    }

    for name in &stop {
        let _ = run("rcctl", &["stop", name]);
        st.done.push(format!("stopped {name}"));
    }
    // reload where the daemon re-reads cleanly, restart otherwise; sshd
    // first (the way back in), the web UI last and detached: restarting it
    // cuts the connection of whoever asked for this apply
    let mut order: Vec<&String> = restart.iter().filter(|n| *n != "octopus_web").collect();
    order.sort_by_key(|n| *n != "sshd");
    for name in order {
        let action = match name.as_str() {
            "sshd" | "syslogd" if service_running(name) && !reflag.contains(name) => "reload",
            _ => "restart",
        };
        st.run("rcctl", &[action, name], format!("{action} {name}"))?;
    }
    if restart.contains("octopus_web") {
        restart_web_later();
        st.done.push("restart octopus_web (in a few seconds)".into());
    }
    // last: the access points (one that can't be reached doesn't fail this)
    st.done.extend(crate::ap::push_stale());
    Ok(())
}

/// At boot, for the live generation: the ports must be the ones it was
/// applied to (interfaces named by the order they are found: a missing or
/// added NIC renumbers the rest, and the WAN cable could get the mgmt
/// tier), and its pf ruleset must be the one loaded (a missing port makes
/// pfctl refuse the whole file, and rc's temporary ruleset stays).
pub fn boot_checks(m: &Manifest) {
    let (now, moved) = moved_ports(m);
    if !moved.is_empty() {
        lockdown(m, &now, &moved);
        return;
    }
    // locked down at an earlier boot: the ports are back
    let _ = fs::remove_file(lockdown_path());
    let rules = run("pfctl", &["-sr"]).unwrap_or_default();
    if !rules.contains("label \"urpf\"") {
        log("boot: pf isn't running the generated ruleset; loading /etc/pf.conf");
        if let Err(e) = run("pfctl", &["-f", "/etc/pf.conf"]) {
            log(&format!("boot: pf.conf doesn't load: {e}"));
        }
    }
    // the DNS daemon first: nginx and others resolve names when they start
    let enabled: Vec<&str> = ["octopus_pfhelper", "octopus_dns", "octopus_hickory"]
        .into_iter()
        .filter(|d| m.services.iter().any(|s| s.name == *d && s.enabled))
        .collect();
    if !enabled.is_empty() {
        let mut args = vec!["order"];
        args.extend(enabled);
        let _ = run("rcctl", &args);
    }
}

/// The ports as found now (MAC to name), and those of `m` that aren't
/// where it put them.
fn moved_ports(m: &Manifest) -> (std::collections::BTreeMap<String, String>, Vec<String>) {
    if m.ifmap.is_empty() {
        return Default::default();
    }
    let now = octopus_config::ifmap::parse_ifconfig(&run("ifconfig", &["-a"]).unwrap_or_default());
    let moved = m
        .ifmap
        .iter()
        .filter(|(mac, name)| now.get(*mac) != Some(*name))
        .map(|(mac, name)| match now.get(mac) {
            Some(n) => format!("{mac} was {name}, is {n}"),
            None => format!("{mac} ({name}) is missing"),
        })
        .collect();
    (now, moved)
}

/// The lockdown ruleset; it exists while the router is locked down.
fn lockdown_path() -> PathBuf {
    gens::root().join("lockdown.pf")
}

pub fn locked_down() -> bool {
    lockdown_path().exists()
}

/// After an apply, with changes or none: a boot lockdown ends once the ports
/// are where the live generation `m` puts them. Its pf ruleset is loaded
/// (the apply reloads pf only when pf.conf changed) and DHCP starts again.
pub fn lift_lockdown(m: &Manifest) -> Res<Option<String>> {
    if !locked_down() {
        return Ok(None);
    }
    let (_, moved) = moved_ports(m);
    if !moved.is_empty() {
        return Err(format!("still locked down, the ports aren't where generation {} puts them: {}", m.generation, moved.join("; ")));
    }
    run("pfctl", &["-f", "/etc/pf.conf"]).map_err(|e| format!("still locked down: /etc/pf.conf doesn't load: {e}"))?;
    if m.services.iter().any(|s| s.name == "octopus_kea" && s.enabled) {
        let _ = run("rcctl", &["start", "octopus_kea"]);
    }
    let _ = fs::remove_file(lockdown_path());
    log("lockdown lifted: the ports are back; pf.conf loaded, DHCP started");
    Ok(Some("lockdown lifted: pf.conf loaded, DHCP started".into()))
}

/// The ports moved: nothing but SSH to the router from ports that aren't
/// the WAN's (by MAC), and no DHCP, until someone applies again.
fn lockdown(m: &Manifest, now: &std::collections::BTreeMap<String, String>, moved: &[String]) {
    let cfg = fs::read_to_string(gens::dir(m.generation).join("router.toml"))
        .ok()
        .and_then(|t| octopus_config::parse(&t).ok());
    let wan_mac = cfg
        .as_ref()
        .and_then(|c| c.wan.as_ref().and_then(|w| c.interfaces.get(&w.interface)))
        .and_then(|i| octopus_config::ifmap::normalize_mac(&i.mac));
    let ssh = cfg.as_ref().map_or(22, |c| c.ssh.port);
    // the WAN cable (found by its MAC) gets nothing, and is no bridge's port
    let wan_if = wan_mac.as_ref().and_then(|m| now.get(m));
    let mut pf =
        String::from("# octopus boot: the ports moved; locked down until the next apply\nset skip on lo\nblock all\n");
    if let Some(w) = wan_if {
        pf += &format!("block in quick on {w}\n");
        for veb in fs::read_dir("/etc").map(|d| d.flatten().collect::<Vec<_>>()).unwrap_or_default() {
            let name = veb.file_name().to_string_lossy().into_owned();
            if let Some(v) = name.strip_prefix("hostname.").filter(|v| v.starts_with("veb")) {
                let _ = run("ifconfig", &[v, "del", w]);
            }
        }
    }
    pf += &format!("pass in quick proto tcp to self port {ssh}\n");
    let path = lockdown_path();
    let _ = os::write_atomic(&path, pf.as_bytes(), 0o600, "root", "wheel");
    let loaded = run("pfctl", &["-f", &path.to_string_lossy()]);
    let _ = run("rcctl", &["stop", "octopus_kea"]);
    log(&format!(
        "boot: LOCKED DOWN: the ports aren't where generation {} put them ({}); pf allows only SSH, and nothing from the WAN port{}; run `octopus apply` (it binds the ports by MAC again) from the console or over SSH",
        m.generation,
        moved.join("; "),
        if loaded.is_ok() { "" } else { " (and even that ruleset didn't load)" }
    ));
}

/// Restart the web UI a moment from now, detached: when the web UI asked
/// for this apply, it gets its answer first.
pub fn restart_web_later() {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "sleep 3; exec /usr/sbin/rcctl restart octopus_web"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    if let Err(e) = cmd.spawn() {
        log(&format!("restart octopus_web: {e}"));
    }
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

/// Spawn the commit-confirm watchdog for a pending generation, detached
/// from our session. It reads the window from the state file.
pub fn spawn_watchdog(generation: u32, previous: u32) -> Res<()> {
    // OpenBSD can't tell a process its own path (current_exe fails there)
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(BIN));
    let mut cmd = Command::new(exe);
    cmd.args(["_watchdog", &generation.to_string(), &previous.to_string()])
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

/// The watchdog of a pending generation: reverts it to `previous` when the
/// window passes without a confirm, at once when the apply that is still
/// marked running has died, and again (backing off) when a revert had errors.
pub fn watchdog(generation: u32, previous: u32) -> Res<()> {
    // the window is counted on the monotonic clock from when the apply ended
    let mut opened: Option<Instant> = None;
    let mut known: Option<Pending> = None;
    loop {
        match load_state() {
            Ok(st) => match st.pending {
                Some(p) if p.generation == generation => {
                    if p.applying {
                        opened = None;
                        // the apply holds the lock while it runs: free means it died
                        if let Ok(l) = os::lock(&lock_path()) {
                            drop(l);
                            if load_state().ok().and_then(|s| s.pending).is_some_and(|q| q.applying) {
                                log(&format!("generation {generation}: its apply ended without finishing"));
                                break;
                            }
                        }
                    } else {
                        let window = if p.window > 0 { p.window } else { p.deadline.saturating_sub(now()) };
                        if opened.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(window) {
                            break;
                        }
                    }
                    known = Some(p);
                }
                _ => return Ok(()), // confirmed, reverted or superseded
            },
            // unreadable: keep counting what we know, then revert
            Err(e) => {
                log(&format!("watchdog: {e}"));
                let window = known.as_ref().map_or(60, |p| p.window.max(1));
                if opened.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(window) {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    for attempt in 0.. {
        let _l = loop {
            match os::lock(&lock_path()) {
                Ok(l) => break l,
                Err(_) => std::thread::sleep(Duration::from_secs(1)),
            }
        };
        let st = match load_state() {
            Ok(st) => st,
            Err(_) => State {
                current: Some(generation),
                confirmed: Some(previous),
                pending: Some(known.clone().unwrap_or(Pending {
                    generation,
                    previous,
                    deadline: now(),
                    window: 0,
                    applying: false,
                    boot: String::new(),
                    reverting: false,
                    revert_failures: 0,
                })),
            },
        };
        match &st.pending {
            Some(p) if p.generation == generation => {}
            _ => return Ok(()),
        }
        log(&format!("generation {generation} not confirmed; rolling back to {previous}"));
        match revert_pending(&st) {
            Ok(()) => return Ok(()),
            Err(e) => {
                log(&format!("rollback of generation {generation}: {e}"));
                if attempt + 1 >= REVERT_TRIES {
                    return Err(e);
                }
            }
        }
        drop(_l);
        std::thread::sleep(Duration::from_secs(15 << attempt.min(4)));
    }
    Ok(())
}

/// Re-apply the generation that was live before the pending one, doing
/// every step even when some fail. With errors it stays pending (marked
/// reverting, so it can't be confirmed) for the watchdog to try again;
/// after REVERT_TRIES it is recorded as reverted anyway, and logged.
pub fn revert_pending(st: &State) -> Res<()> {
    let p = st.pending.clone().ok_or("nothing is pending")?;
    let from = gens::load(p.generation).ok();
    let to = gens::load(p.previous)?;
    // from here on it can't be confirmed
    let mut marked = st.clone();
    if let Some(q) = marked.pending.as_mut() {
        q.reverting = true;
        q.applying = false;
    }
    save_state(&marked)?;
    let (actions, errors) = revert_manifest(&to, from.as_ref());
    if errors.is_empty() || p.revert_failures + 1 >= REVERT_TRIES {
        save_state(&State { current: Some(p.previous), confirmed: Some(p.previous), pending: None })?;
        let _ = install_source(p.previous);
    } else if let Some(q) = marked.pending.as_mut() {
        q.revert_failures += 1;
        save_state(&marked)?;
    }
    for a in &actions {
        log(&format!("rollback: {a}"));
    }
    if errors.is_empty() {
        log(&format!("rolled back to generation {}", p.previous));
        Ok(())
    } else {
        Err(format!("rolled back to generation {} with errors: {}", p.previous, errors.join("; ")))
    }
}
