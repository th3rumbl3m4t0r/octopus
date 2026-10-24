//! `octopus guard`: who may use the restricted tiers' addresses.
//!
//!   run              (octopus_guard, root) every few seconds: read the ARP
//!                    table; a device on a restricted address (a tier with
//!                    `macs`, /etc/octopus/guard.json) whose MAC isn't listed,
//!                    a listed prefix's, or that address's reservation is cut
//!                    off from the router: `rule block out on <vport> src MAC`
//!                    on the bridge. It can still reach others on the wire,
//!                    not the router (no gateway, no DNS, no DHCP renewal).
//!   release MAC      lift a block (also --staged, the web UI's button)
//!   status           the blocked devices
//!
//! The blocks survive restarts (/var/octopus/guard-state.json) and are put
//! back when the bridge is recreated. They end after a day unless the
//! device does it again, and a port takes at most MAX_BLOCKS of them.
//!
//! The ARP table is evidence anyone on the wire can forge (a request whose
//! sender is someone else's MAC). So a MAC that may use a restricted tier
//! sharing that port, or that holds a lease from Kea, is never blocked:
//! the guard keeps honest devices in their tier, it is not a lock.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use octopus_config::ifmap::normalize_mac;
use serde::{Deserialize, Serialize};

use crate::os::{self, Res, log, now};

const CONF: &str = "/etc/octopus/guard.json";
pub const STATE: &str = "/var/octopus/guard-state.json";
const STAGED: &str = "/var/octopus/staged/guard.json";
const EVERY: Duration = Duration::from_secs(5);
/// Held by a pass and by a release: one changes the state at a time.
const LOCK: &str = "/var/octopus/guard.lock";
/// A block lasts this long after the device was last seen doing it.
const KEEP: u64 = 24 * 3600;
/// Blocks per port: each is a rule the bridge walks for every frame.
const MAX_BLOCKS: usize = 64;

#[derive(Deserialize)]
struct Conf {
    restricted: Vec<Port>,
}

#[derive(Deserialize, Clone)]
struct Port {
    veb: String,
    vport: String,
    tier: String,
    prefix: ipnet::Ipv4Net,
    router: Ipv4Addr,
    macs: Vec<String>,
    reserved: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Blocked {
    pub ip: String,
    pub tier: String,
    pub veb: String,
    pub vport: String,
    pub at: u64,
    /// When it was last seen on a restricted address (blocks end KEEP after).
    #[serde(default)]
    pub seen: u64,
}

pub fn load_state() -> BTreeMap<String, Blocked> {
    fs::read_to_string(STATE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_state(st: &BTreeMap<String, Blocked>) -> Res<()> {
    os::write_atomic(
        Path::new(STATE),
        serde_json::to_string_pretty(st).unwrap_or_default().as_bytes(),
        0o644,
        "root",
        "wheel",
    )
}

/// May `mac` use `ip` in this tier?
fn entitled(p: &Port, ip: &str, mac: &str) -> bool {
    p.reserved.get(ip).is_some_and(|m| m == mac) || p.macs.iter().any(|m| mac.starts_with(m.as_str()))
}

/// (ip, mac, interface) of the ARP table's resolved, non-local entries.
fn arp() -> Vec<(Ipv4Addr, String, String)> {
    let out = os::run("arp", &["-an"]).unwrap_or_default();
    out.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 || f.get(4).is_some_and(|x| x.contains('l')) || f.get(3).is_some_and(|x| *x == "permanent") {
                return None;
            }
            Some((f[0].parse().ok()?, normalize_mac(f[1])?, f[2].to_string()))
        })
        .collect()
}

/// The bridge rules on a port right now.
fn rules(veb: &str, vport: &str) -> String {
    os::run("ifconfig", &[veb, "rules", vport]).unwrap_or_default()
}

fn block(veb: &str, vport: &str, mac: &str) -> Res<()> {
    os::run("ifconfig", &[veb, "rule", "block", "out", "on", vport, "src", mac]).map(|_| ())
}

/// One pass: new offenders blocked, old blocks ended, missing rules put back.
fn pass(conf: &Conf, st: &mut BTreeMap<String, Blocked>) -> Res<bool> {
    let mut changed = false;
    let leased = crate::status::leased_macs();
    for (ip, mac, ifname) in arp() {
        let Some(p) = conf.restricted.iter().find(|p| p.vport == ifname && p.prefix.contains(&ip)) else { continue };
        if ip == p.router {
            continue;
        }
        if let Some(b) = st.get_mut(&mac) {
            // still at it: the block lasts (written down now and then, not every pass)
            if now().saturating_sub(b.seen) > 600 {
                b.seen = now();
                changed = true;
            }
            continue;
        }
        // listed for a tier on this port, or known to Kea: an ARP entry alone
        // (anyone can forge one with someone else's MAC) doesn't cut it off
        let siblings = || conf.restricted.iter().filter(|o| o.veb == p.veb && o.vport == p.vport);
        if entitled(p, &ip.to_string(), &mac) || siblings().any(|o| entitled(o, "", &mac)) || leased.contains(&mac) {
            continue;
        }
        if st.values().filter(|b| b.vport == p.vport).count() >= MAX_BLOCKS {
            log(&format!("guard: {mac} used {ip}, but {} already has {MAX_BLOCKS} blocks; not blocking more", p.vport));
            continue;
        }
        block(&p.veb, &p.vport, &mac)?;
        let _ = os::run("arp", &["-d", &ip.to_string()]);
        log(&format!(
            "guard: {mac} used {ip} ({} is for listed devices only): cut off from the router on {}",
            p.tier, p.vport
        ));
        st.insert(
            mac,
            Blocked {
                ip: ip.to_string(),
                tier: p.tier.clone(),
                veb: p.veb.clone(),
                vport: p.vport.clone(),
                at: now(),
                seen: now(),
            },
        );
        changed = true;
    }
    // blocks end a day after the device was last seen at it
    let old: Vec<String> =
        st.iter().filter(|(_, b)| now().saturating_sub(b.seen.max(b.at)) > KEEP).map(|(m, _)| m.clone()).collect();
    for mac in old {
        if let Some(b) = st.remove(&mac) {
            unblock(&b, st)?;
            log(&format!("guard: {mac} released after a day without using {}", b.ip));
            changed = true;
        }
    }
    // a recreated bridge forgot its rules
    let mut have: BTreeMap<(String, String), String> = BTreeMap::new();
    for (mac, b) in st.iter() {
        let rs = have.entry((b.veb.clone(), b.vport.clone())).or_insert_with(|| rules(&b.veb, &b.vport));
        if !rs.contains(&format!("src {mac}")) {
            block(&b.veb, &b.vport, mac)?;
        }
    }
    Ok(changed)
}

/// The port's rules rebuilt without `b` (veb can only flush them all).
fn unblock(b: &Blocked, rest: &BTreeMap<String, Blocked>) -> Res<()> {
    os::run("ifconfig", &[&b.veb, "flushrule", &b.vport])?;
    for (m, o) in rest.iter().filter(|(_, o)| o.veb == b.veb && o.vport == b.vport) {
        block(&o.veb, &o.vport, m)?;
    }
    Ok(())
}

fn run() -> Res<()> {
    log("guard: watching the restricted tiers");
    loop {
        // the state on disk is the truth (a release changes it); a failed
        // write is logged and tried again: the guard never stops for it
        if let Ok(_l) = os::lock_wait(Path::new(LOCK), 30) {
            let mut st = load_state();
            match fs::read_to_string(CONF)
                .map_err(|e| e.to_string())
                .and_then(|t| serde_json::from_str::<Conf>(&t).map_err(|e| e.to_string()))
            {
                Ok(conf) => {
                    let r = pass(&conf, &mut st);
                    if let Err(e) = &r {
                        log(&format!("guard: {e}"));
                    }
                    // what was done before an error is saved too
                    if (r.is_err() || r.as_ref().is_ok_and(|c| *c))
                        && let Err(e) = save_state(&st)
                    {
                        log(&format!("guard: {STATE}: {e}"));
                    }
                }
                Err(e) => log(&format!("guard: {CONF}: {e}")),
            }
        }
        std::thread::sleep(EVERY);
    }
}

/// Lift a block: the port's rules are rebuilt without it.
fn release(mac: &str) -> Res<()> {
    let mac = normalize_mac(mac).ok_or_else(|| format!("{mac:?}: not a MAC address"))?;
    let _l = os::lock_wait(Path::new(LOCK), 30)?;
    let mut st = load_state();
    let b = st.remove(&mac).ok_or_else(|| format!("{mac} is not blocked"))?;
    unblock(&b, &st)?;
    save_state(&st)?;
    log(&format!("guard: {mac} released (it had used {})", b.ip));
    out!("{mac} released");
    Ok(())
}

pub fn cmd(args: &[String], staged: bool) -> Res<()> {
    if staged {
        let text = crate::os::read_owned(std::path::Path::new(STAGED), crate::os::WEB_USER, 1024);
        let _ = fs::remove_file(STAGED);
        let v: serde_json::Value = serde_json::from_str(&text?).map_err(|e| format!("staged: {e}"))?;
        return release(v["mac"].as_str().unwrap_or(""));
    }
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["run"] => run(),
        ["release", mac] => release(mac),
        ["status"] | [] => {
            for (mac, b) in load_state() {
                out!("{mac}  used {:<15} ({}) on {}  since {}", b.ip, b.tier, b.vport, b.at);
            }
            Ok(())
        }
        _ => Err("usage: octopus guard run | release MAC | status".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_may_use_a_restricted_address() {
        let p = Port {
            veb: "veb0".into(),
            vport: "vport0".into(),
            tier: "cd".into(),
            prefix: "192.168.1.0/24".parse().unwrap(),
            router: "192.168.1.1".parse().unwrap(),
            macs: vec!["bc:24:11".into(), "02:00:5e:10:00:0a".into()],
            reserved: [("192.168.1.20".to_string(), "02:00:00:00:00:20".to_string())].into(),
        };
        assert!(entitled(&p, "192.168.1.50", "bc:24:11:00:00:62"), "a listed prefix");
        assert!(entitled(&p, "192.168.1.51", "02:00:5e:10:00:0a"), "a listed MAC");
        assert!(entitled(&p, "192.168.1.20", "02:00:00:00:00:20"), "its reservation");
        assert!(!entitled(&p, "192.168.1.6", "02:00:00:00:00:20"), "a reserved device on another address");
        assert!(!entitled(&p, "192.168.1.6", "02:00:5e:10:00:d9"), "a desktop that picked a CD address");
    }
}
