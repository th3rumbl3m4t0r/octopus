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
//! back when the bridge is recreated.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use octopus_config::ifmap::normalize_mac;
use serde::{Deserialize, Serialize};

use crate::os::{self, Res, log, now};

const CONF: &str = "/etc/octopus/guard.json";
pub const STATE: &str = "/var/octopus/guard-state.json";
const STAGED: &str = "/var/octopus/staged/guard.json";
const EVERY: Duration = Duration::from_secs(5);

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

/// One pass: new offenders blocked, missing rules put back.
fn pass(conf: &Conf, st: &mut BTreeMap<String, Blocked>) -> Res<bool> {
    let mut changed = false;
    for (ip, mac, ifname) in arp() {
        let Some(p) = conf.restricted.iter().find(|p| p.vport == ifname && p.prefix.contains(&ip)) else { continue };
        if ip == p.router || entitled(p, &ip.to_string(), &mac) || st.contains_key(&mac) {
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
            Blocked { ip: ip.to_string(), tier: p.tier.clone(), veb: p.veb.clone(), vport: p.vport.clone(), at: now() },
        );
        changed = true;
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

fn run() -> Res<()> {
    log("guard: watching the restricted tiers");
    let mut st = load_state();
    loop {
        match fs::read_to_string(CONF)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Conf>(&t).map_err(|e| e.to_string()))
        {
            Ok(conf) => match pass(&conf, &mut st) {
                Ok(true) => save_state(&st)?,
                Ok(false) => {}
                Err(e) => log(&format!("guard: {e}")),
            },
            Err(e) => log(&format!("guard: {CONF}: {e}")),
        }
        std::thread::sleep(EVERY);
        // a release by `octopus guard release` changed the state file
        let disk = load_state();
        if disk.len() != st.len() {
            st = disk;
        }
    }
}

/// Lift a block: the port's rules are rebuilt without it.
fn release(mac: &str) -> Res<()> {
    let mac = normalize_mac(mac).ok_or_else(|| format!("{mac:?}: not a MAC address"))?;
    let mut st = load_state();
    let b = st.remove(&mac).ok_or_else(|| format!("{mac} is not blocked"))?;
    os::run("ifconfig", &[&b.veb, "flushrule", &b.vport])?;
    for (m, o) in st.iter().filter(|(_, o)| o.veb == b.veb && o.vport == b.vport) {
        block(&o.veb, &o.vport, m)?;
    }
    save_state(&st)?;
    log(&format!("guard: {mac} released (it had used {})", b.ip));
    println!("{mac} released");
    Ok(())
}

pub fn cmd(args: &[String], staged: bool) -> Res<()> {
    if staged {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(STAGED)
            .map_err(|e| format!("{STAGED}: {e}"))?;
        let mut text = String::new();
        f.by_ref().take(1024).read_to_string(&mut text).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(STAGED);
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("staged: {e}"))?;
        return release(v["mac"].as_str().unwrap_or(""));
    }
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["run"] => run(),
        ["release", mac] => release(mac),
        ["status"] | [] => {
            for (mac, b) in load_state() {
                println!("{mac}  used {:<15} ({}) on {}  since {}", b.ip, b.tier, b.vport, b.at);
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
