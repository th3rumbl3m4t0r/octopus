//! `octopus power`: what a power cut can do to the disks.
//!
//!   run              (octopus_power, root) every few seconds: ask the UPS feed
//!                    (/etc/octopus/power.json). On battery for protect_after
//!                    seconds, every file system but /, /var and /tmp goes
//!                    read-only; after root_after (at once on a low battery, or
//!                    when the feed goes quiet on battery) / too. Back on mains
//!                    for restore_after, they are writable again.
//!   status           the guard's state and the boot's fsck repair
//!
//! The feed is read by `_power-probe URL`, a child running as nobody: ftp(1)
//! fetches it, the child parses the JSON and prints one word. The root
//! process only ever reads that word (design R6).
//!
//! fsck_repair: OpenBSD's /etc/rc stops at a shell when the boot's `fsck -p`
//! finds damage it won't repair ("Automatic file system check failed;
//! help!"), so the router stays down until someone runs fsck at its screen.
//! pfSense runs `fsck -y` and boots on. With fsck_repair, octopus keeps that
//! one change in do_fsck (boot and supervise put it back after an upgrade);
//! an /etc/rc it doesn't recognise is left alone and reported.

use std::fs;
use std::io::Read as _;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::os::{self, Res, log, now};

const CONF: &str = "/etc/octopus/power.json";
pub const STATE: &str = "/var/octopus/power-state.json";
const RC: &str = "/etc/rc";
const EVERY: Duration = Duration::from_secs(5);
/// The probe gets this long, ftp(1)'s connect included.
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
/// The feed silent this long while on battery counts as a low battery: its
/// host shuts down near the end.
const QUIET: u64 = 30;
/// Written all the time (logs, leases, generations, state): never read-only.
const KEEP_WRITABLE: [&str; 2] = ["/var", "/tmp"];
const PROBE_USER: &str = "nobody";

#[derive(Deserialize, Clone)]
struct Conf {
    ups: Option<String>,
    protect_after: u64,
    root_after: u64,
    restore_after: u64,
    #[serde(default)]
    fsck_repair: bool,
}

/// What the feed says.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Reading {
    Mains,
    Battery,
    Low,
    Unknown,
}

impl Reading {
    fn word(self) -> &'static str {
        match self {
            Reading::Mains => "mains",
            Reading::Battery => "battery",
            Reading::Low => "low",
            Reading::Unknown => "unknown",
        }
    }

    fn of_word(s: &str) -> Reading {
        match s {
            "mains" => Reading::Mains,
            "battery" => Reading::Battery,
            "low" => Reading::Low,
            _ => Reading::Unknown,
        }
    }
}

/// How far the file systems are protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Level {
    #[default]
    Normal,
    /// all but /, /var and /tmp read-only
    Protected,
    /// / too
    Root,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    level: Level,
    battery_since: Option<u64>,
    mains_since: Option<u64>,
    quiet_since: Option<u64>,
    /// what this guard made read-only (and only that is made writable again)
    readonly: Vec<String>,
    reading: String,
    at: u64,
}

/// ups-api's JSON: on battery, and low on it. A low battery while on mains
/// is a charging one.
fn reading_of(json: &str) -> Reading {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return Reading::Unknown };
    match (v["status"]["on_battery"].as_bool(), v["status"]["low_battery"].as_bool()) {
        (Some(true), Some(true)) => Reading::Low,
        (Some(true), _) => Reading::Battery,
        (Some(false), _) => Reading::Mains,
        _ => Reading::Unknown,
    }
}

/// The level the file systems should be at now. A silent feed on mains
/// changes nothing; on battery it counts as battery, and as low once it has
/// been quiet for QUIET seconds.
fn next(c: &Conf, s: &mut State, r: Reading, now: u64) -> Level {
    if r == Reading::Unknown {
        s.quiet_since.get_or_insert(now);
    } else {
        s.quiet_since = None;
    }
    let on_battery = match r {
        Reading::Battery | Reading::Low => true,
        Reading::Mains => false,
        Reading::Unknown => s.battery_since.is_some(),
    };
    if on_battery {
        s.mains_since = None;
        let gone = now.saturating_sub(*s.battery_since.get_or_insert(now));
        let low = r == Reading::Low || s.quiet_since.is_some_and(|q| now.saturating_sub(q) >= QUIET);
        let mut want = s.level;
        if low || gone >= c.protect_after {
            want = want.max(Level::Protected);
        }
        if c.root_after > 0 && (low || gone >= c.root_after) {
            want = want.max(Level::Root);
        }
        return want;
    }
    if r == Reading::Mains {
        s.battery_since = None;
        let back = now.saturating_sub(*s.mains_since.get_or_insert(now));
        if s.level != Level::Normal && back >= c.restore_after {
            return Level::Normal;
        }
    }
    s.level
}

/// The file systems the guard may make read-only: fstab's read-write FFS
/// ones, without / and those the router keeps writing.
fn targets(fstab: &str) -> Vec<String> {
    fstab
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (mp, fstype, opts) = (*f.get(1)?, *f.get(2)?, *f.get(3)?);
            let kept = mp == "/" || KEEP_WRITABLE.iter().any(|k| mp == *k || mp.starts_with(&format!("{k}/")));
            (!l.trim_start().starts_with('#') && fstype == "ffs" && opts.split(',').any(|o| o == "rw") && !kept)
                .then(|| mp.to_string())
        })
        .collect()
}

/// Mount points mounted read-only now (mount(8)'s list).
fn mounted_readonly() -> Vec<String> {
    os::run("mount", &[])
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("read-only"))
        .filter_map(|l| l.split(" on ").nth(1)?.split(" type ").next().map(str::to_string))
        .collect()
}

/// Bring the file systems to `want`; what fails is tried again next round.
fn enforce(want: Level, s: &mut State) {
    if want == Level::Normal {
        // / first: the others' mount points live on it
        s.readonly.sort_by_key(|m| m != "/");
        let mut left = vec![];
        for mp in std::mem::take(&mut s.readonly) {
            match os::run("mount", &["-u", "-w", &mp]) {
                Ok(_) => log(&format!("power: {mp} writable again")),
                Err(e) => {
                    log(&format!("power: {mp} stays read-only: {e}"));
                    left.push(mp);
                }
            }
        }
        s.readonly = left;
        if s.readonly.is_empty() {
            s.level = Level::Normal;
        }
        return;
    }
    let mut want_ro = targets(&fs::read_to_string("/etc/fstab").unwrap_or_default());
    if want == Level::Root {
        want_ro.push("/".into());
    }
    let already = mounted_readonly();
    let _ = os::run("sync", &[]);
    let mut all = true;
    let todo: Vec<String> = want_ro.into_iter().filter(|m| !s.readonly.contains(m)).collect();
    for mp in &todo {
        if already.contains(mp) {
            continue; // read-only by itself: not ours to make writable
        }
        // a file open for writing refuses the plain downgrade; -f revokes it
        let r = os::run("mount", &["-u", "-r", mp]).or_else(|_| os::run("mount", &["-u", "-r", "-f", mp]));
        match r {
            Ok(_) => s.readonly.push(mp.clone()),
            Err(e) => {
                all = false;
                log(&format!("power: {mp} can't go read-only yet: {e}"));
            }
        }
    }
    if all {
        s.level = want;
    }
}

/// The feed's word, from `_power-probe` running as nobody.
fn read_feed(url: &str) -> Reading {
    let Some((uid, gid)) = os::ids_of(PROBE_USER) else { return Reading::Unknown };
    let child = Command::new(crate::apply::BIN)
        .args(["_power-probe", url])
        .uid(uid)
        .gid(gid)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return Reading::Unknown };
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Reading::Unknown;
            }
        }
    }
    let mut word = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = out.take(16).read_to_string(&mut word);
    }
    Reading::of_word(word.trim())
}

/// `octopus _power-probe URL` (as nobody): the feed, as one word.
pub fn probe(url: &str) -> Res<()> {
    let body = os::run("ftp", &["-V", "-w", "5", "-o", "-", url]).unwrap_or_default();
    out!("{}", reading_of(&body).word());
    Ok(())
}

fn load_state() -> State {
    fs::read_to_string(STATE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_state(s: &State) {
    let text = serde_json::to_string_pretty(s).unwrap_or_default() + "\n";
    if let Err(e) = os::write_atomic(Path::new(STATE), text.as_bytes(), 0o644, "root", "wheel") {
        log(&format!("power: {e}"));
    }
}

fn load_conf() -> Option<Conf> {
    serde_json::from_str(&fs::read_to_string(CONF).ok()?).ok()
}

fn run() -> Res<()> {
    let c = load_conf().ok_or(format!("{CONF}: missing or unreadable"))?;
    let url = c.ups.clone().ok_or("power.json has no ups feed")?;
    let mut s = load_state();
    // after a reboot nothing is read-only any more: only keep what still is
    let ro = mounted_readonly();
    s.readonly.retain(|m| ro.contains(m));
    if s.readonly.is_empty() {
        s.level = Level::Normal;
    }
    log(&format!("power: watching {url}"));
    let mut last = None;
    loop {
        let r = read_feed(&url);
        let t = now();
        if last != Some(r) {
            log(&format!("power: the feed says {}", r.word()));
            last = Some(r);
        }
        let want = next(&c, &mut s, r, t);
        // enforce raises s.level only once all of it took: what failed is retried
        if want != s.level {
            log(&format!("power: {:?} -> {:?}", s.level, want));
            enforce(want, &mut s);
        }
        s.reading = r.word().into();
        s.at = t;
        save_state(&s);
        std::thread::sleep(EVERY);
    }
}

/// Read-only by the guard right now: apply and rollback wait for the mains.
pub fn readonly_now() -> Vec<String> {
    let s = load_state();
    let ro = mounted_readonly();
    s.readonly.into_iter().filter(|m| ro.contains(m)).collect()
}

// ---- fsck repair in /etc/rc

const RC_STOP: &str = "\t8)\techo \"Automatic file system check failed; help!\"\n\t\texit 1\n\t\t;;\n";
const RC_REPAIR: &str = "\t8)\t# octopus (power.fsck_repair): repair it and boot on, as pfSense does\n\
\t\techo \"Automatic file system check failed; repairing it (fsck -y).\"\n\
\t\tfor _n in 1 2; do\n\
\t\t\tfsck -y \"$@\"\n\
\t\t\t_r=$?\n\
\t\t\t[[ $_r == 8 ]] || break\n\
\t\tdone\n\
\t\tcase $_r in\n\
\t\t0)\t;;\n\
\t\t4)\techo \"Rebooting...\"\n\
\t\t\treboot\n\
\t\t\techo \"Reboot failed; help!\"\n\
\t\t\texit 1\n\
\t\t\t;;\n\
\t\t*)\techo \"Repair failed; help!\"\n\
\t\t\texit 1\n\
\t\t\t;;\n\
\t\tesac\n\
\t\t;;\n";

#[derive(Debug, PartialEq)]
enum Rc {
    /// OpenBSD's: it stops at a shell
    Stops,
    Repairs,
    /// neither: a release whose do_fsck this version doesn't know
    Unknown,
}

fn rc_state(text: &str) -> Rc {
    match (text.matches(RC_REPAIR).count(), text.matches(RC_STOP).count()) {
        (1, 0) => Rc::Repairs,
        (0, 1) => Rc::Stops,
        _ => Rc::Unknown,
    }
}

/// /etc/rc as `want` says, or None when it is already so or unknown.
fn rc_patched(text: &str, want: bool) -> Option<String> {
    match (rc_state(text), want) {
        (Rc::Stops, true) => Some(text.replacen(RC_STOP, RC_REPAIR, 1)),
        (Rc::Repairs, false) => Some(text.replacen(RC_REPAIR, RC_STOP, 1)),
        _ => None,
    }
}

/// From `boot` and `supervise`: /etc/rc repairs a failed check when
/// power.fsck_repair says so, and is OpenBSD's own otherwise. Quiet unless it
/// changes something; not while / is read-only.
pub fn ensure_rc() {
    let want = load_conf().is_some_and(|c| c.fsck_repair);
    let Ok(text) = fs::read_to_string(RC) else { return };
    let Some(new) = rc_patched(&text, want) else { return };
    if mounted_readonly().iter().any(|m| m == "/") {
        return;
    }
    match os::write_atomic(Path::new(RC), new.as_bytes(), 0o644, "root", "wheel") {
        Ok(()) if want => log("power: /etc/rc repairs a failed file system check at boot (fsck -y)"),
        Ok(()) => log("power: /etc/rc is OpenBSD's own again (a failed check stops at a shell)"),
        Err(e) => log(&format!("power: /etc/rc: {e}")),
    }
}

pub fn status_json() -> Value {
    let c = load_conf();
    let s = load_state();
    let rc = match fs::read_to_string(RC).map(|t| rc_state(&t)) {
        Ok(Rc::Repairs) => "repairs",
        Ok(Rc::Stops) => "stops at a shell",
        _ => "unknown do_fsck: not changed",
    };
    json!({
        "ups": c.as_ref().and_then(|c| c.ups.clone()),
        "level": s.level, "reading": s.reading, "at": s.at, "readonly": s.readonly,
        "battery_since": s.battery_since,
        "fsck_repair": c.as_ref().is_some_and(|c| c.fsck_repair), "rc": rc,
    })
}

pub fn cmd(pos: &[String]) -> Res<()> {
    match pos.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["run"] => run(),
        ["status"] | [] => {
            let v = status_json();
            out!("ups feed      {}", v["ups"].as_str().unwrap_or("none"));
            out!("feed says     {} (at {})", v["reading"].as_str().unwrap_or("-"), v["at"]);
            out!("level         {}", v["level"].as_str().unwrap_or("normal"));
            out!("read-only     {}", v["readonly"]);
            out!(
                "fsck repair   {} (/etc/rc {})",
                if v["fsck_repair"] == true { "on" } else { "off" },
                v["rc"].as_str().unwrap_or("")
            );
            Ok(())
        }
        _ => Err("usage: octopus power run | status".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> Conf {
        Conf {
            ups: Some("http://192.0.2.1:8765/".into()),
            protect_after: 30,
            root_after: 300,
            restore_after: 60,
            fsck_repair: true,
        }
    }

    #[test]
    fn feed_words() {
        // as ups-api on .125 says it
        let online = r#"{"summary": "online", "status": {"on_battery": false, "low_battery": false, "flags": {"OL": "on line power"}}}"#;
        assert_eq!(reading_of(online), Reading::Mains);
        assert_eq!(reading_of(r#"{"status": {"on_battery": true, "low_battery": false}}"#), Reading::Battery);
        assert_eq!(reading_of(r#"{"status": {"on_battery": true, "low_battery": true}}"#), Reading::Low);
        // charging after an outage is mains
        assert_eq!(reading_of(r#"{"status": {"on_battery": false, "low_battery": true}}"#), Reading::Mains);
        assert_eq!(reading_of("<html>502</html>"), Reading::Unknown);
        assert_eq!(reading_of(r#"{"status": {}}"#), Reading::Unknown);
        for r in [Reading::Mains, Reading::Battery, Reading::Low, Reading::Unknown] {
            assert_eq!(Reading::of_word(r.word()), r);
        }
        assert_eq!(Reading::of_word("mains\nrm -rf"), Reading::Unknown);
    }

    #[test]
    fn outage_then_mains() {
        let c = conf();
        let mut s = State::default();
        // a blip shorter than protect_after changes nothing
        assert_eq!(next(&c, &mut s, Reading::Battery, 0), Level::Normal);
        assert_eq!(next(&c, &mut s, Reading::Battery, 29), Level::Normal);
        assert_eq!(next(&c, &mut s, Reading::Mains, 31), Level::Normal);
        // a real one
        assert_eq!(next(&c, &mut s, Reading::Battery, 100), Level::Normal);
        assert_eq!(next(&c, &mut s, Reading::Battery, 130), Level::Protected);
        s.level = Level::Protected;
        assert_eq!(next(&c, &mut s, Reading::Battery, 399), Level::Protected);
        assert_eq!(next(&c, &mut s, Reading::Battery, 400), Level::Root);
        s.level = Level::Root;
        // mains back: writable only after restore_after, and a relapse restarts the wait
        assert_eq!(next(&c, &mut s, Reading::Mains, 500), Level::Root);
        assert_eq!(next(&c, &mut s, Reading::Battery, 530), Level::Root);
        assert_eq!(next(&c, &mut s, Reading::Mains, 540), Level::Root);
        assert_eq!(next(&c, &mut s, Reading::Mains, 599), Level::Root);
        assert_eq!(next(&c, &mut s, Reading::Mains, 600), Level::Normal);
    }

    #[test]
    fn low_battery_and_a_quiet_feed() {
        let c = conf();
        let mut s = State::default();
        assert_eq!(next(&c, &mut s, Reading::Low, 0), Level::Root);
        // a feed gone quiet on mains changes nothing, however long
        let mut s = State::default();
        assert_eq!(next(&c, &mut s, Reading::Unknown, 0), Level::Normal);
        assert_eq!(next(&c, &mut s, Reading::Unknown, 10_000), Level::Normal);
        // on battery it counts as battery, and as low after QUIET
        let mut s = State::default();
        assert_eq!(next(&c, &mut s, Reading::Battery, 0), Level::Normal);
        assert_eq!(next(&c, &mut s, Reading::Unknown, 5), Level::Normal);
        assert_eq!(next(&c, &mut s, Reading::Unknown, 5 + QUIET), Level::Root);
        // root_after = 0: / never goes read-only, not even on a low battery
        let c0 = Conf { root_after: 0, ..conf() };
        let mut s = State::default();
        assert_eq!(next(&c0, &mut s, Reading::Low, 0), Level::Protected);
        assert_eq!(next(&c0, &mut s, Reading::Battery, 100_000), Level::Protected);
    }

    #[test]
    fn fstab_targets() {
        // an OpenBSD router's fstab
        let fstab = "1a2b3c4d5e6f7a8b.b none swap sw\n\
                     1a2b3c4d5e6f7a8b.a / ffs rw 1 1\n\
                     1a2b3c4d5e6f7a8b.l /home ffs rw,nodev,nosuid 1 2\n\
                     1a2b3c4d5e6f7a8b.d /tmp ffs rw,nodev,nosuid 1 2\n\
                     1a2b3c4d5e6f7a8b.f /usr ffs rw,nodev 1 2\n\
                     1a2b3c4d5e6f7a8b.g /usr/X11R6 ffs rw,nodev 1 2\n\
                     1a2b3c4d5e6f7a8b.h /usr/local ffs rw,wxallowed,nodev 1 2\n\
                     1a2b3c4d5e6f7a8b.k /usr/obj ffs rw,nodev,nosuid 1 2\n\
                     1a2b3c4d5e6f7a8b.j /usr/src ffs rw,nodev,nosuid 1 2\n\
                     1a2b3c4d5e6f7a8b.e /var ffs rw,nodev,nosuid 1 2\n\
                     #1a2b3c4d5e6f7a8b.m /old ffs rw 1 2\n\
                     1a2b3c4d5e6f7a8b.n /var/log ffs rw 1 2\n\
                     1a2b3c4d5e6f7a8b.o /mnt ffs ro 1 2\n";
        assert_eq!(targets(fstab), ["/home", "/usr", "/usr/X11R6", "/usr/local", "/usr/obj", "/usr/src"]);
    }

    /// OpenBSD 7.9's do_fsck, as in its /etc/rc
    const DO_FSCK_79: &str = "do_fsck() {\n\tfsck -p \"$@\"\n\tcase $? in\n\t0)\t;;\n\t2)\texit 1\n\t\t;;\n\
\t4)\techo \"Rebooting...\"\n\t\treboot\n\t\techo \"Reboot failed; help!\"\n\t\texit 1\n\t\t;;\n\
\t8)\techo \"Automatic file system check failed; help!\"\n\t\texit 1\n\t\t;;\n\
\t12)\techo \"Boot interrupted.\"\n\t\texit 1\n\t\t;;\n\
\t130)\t# Interrupt before catcher installed.\n\t\texit 1\n\t\t;;\n\
\t*)\techo \"Unknown error; help!\"\n\t\texit 1\n\t\t;;\n\tesac\n}\n";

    #[test]
    fn rc_repair_round_trip() {
        let rc = format!("#!/bin/ksh\n# head\n{DO_FSCK_79}\ndo_fsck\n");
        assert_eq!(rc_state(&rc), Rc::Stops);
        assert_eq!(rc_patched(&rc, false), None);
        let on = rc_patched(&rc, true).unwrap();
        assert_eq!(rc_state(&on), Rc::Repairs);
        assert!(on.contains("fsck -y \"$@\""));
        assert!(on.contains("\t12)\techo \"Boot interrupted.\""));
        assert_eq!(rc_patched(&on, true), None);
        assert_eq!(rc_patched(&on, false).unwrap(), rc);
        // a release whose do_fsck changed is left alone
        let other = rc.replace("check failed; help!", "check failed, help!");
        assert_eq!(rc_state(&other), Rc::Unknown);
        assert_eq!(rc_patched(&other, true), None);
    }
}
