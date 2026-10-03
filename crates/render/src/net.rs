//! /etc/hostname.*, /etc/mygate and /etc/resolv.conf.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::model::{PPPOE_IF, WG_IF};
use octopus_config::schema::*;

use crate::{Generation, SecretSource, Subsystem, header};

/// Interface group of every internal network: pf's `(octolan:network)`.
pub const LAN_GROUP: &str = "octolan";

pub(crate) fn render(r: &Router, secrets: &SecretSource, g: &mut Generation) -> Result<(), String> {
    let c = &r.cfg;
    // interface name -> lines; physical ports first, then pseudo-devices
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut secret_files = vec![];
    let line = |files: &mut BTreeMap<String, String>, ifname: &str, l: &str| {
        let f = files.entry(ifname.to_string()).or_insert_with(|| header("#", &[]));
        f.push_str(l);
        f.push('\n');
    };

    // every port that carries something gets brought up
    for (role, ifname) in &r.phys {
        let i = &c.interfaces[role];
        let desc = i.description.clone().unwrap_or_else(|| role.clone());
        line(&mut files, ifname, &format!("description \"{}\"", quote_safe(&desc)));
    }

    let mut bridged: std::collections::BTreeSet<String> = Default::default();
    // an interface several tiers share: its first address, then aliases
    let mut addressed: std::collections::BTreeSet<String> = Default::default();
    for n in &r.nets {
        if let (Some(parent), Some(vid)) = (&n.parent, n.vlan) {
            line(&mut files, &n.ifname, &format!("parent {parent} vnetid {vid}"));
            line(&mut files, &n.ifname, &format!("description \"{}\"", n.name));
        }
        let again = !addressed.insert(n.ifname.clone());
        if let (Some(_), true) = (&n.bridge, again) {
            line(&mut files, &n.ifname, &format!("inet alias {} {}", n.addr, n.prefix.netmask()));
            continue;
        }
        if let Some(b) = &n.bridge {
            // netstart brings veb0 up before vport0 (alphabetical): create it first
            // (the first network's lines as before VLANs: an unchanged file
            // leaves the bridge alone on upgrade)
            line(
                &mut files,
                b,
                &if bridged.insert(b.clone()) {
                    let mut l = format!("description \"{}\"\n!ifconfig {} create", n.name, n.ifname);
                    for m in &n.members {
                        let _ = write!(l, "\nadd {m}");
                    }
                    l
                } else {
                    format!("!ifconfig {} create", n.ifname)
                },
            );
            line(&mut files, b, &format!("add {}", n.ifname));
            if let Some(vid) = n.vlan {
                // a VLAN of the bridge: its vport in that VLAN, the ports carry it tagged
                line(&mut files, b, &format!("untagged {} {vid}", n.ifname));
                for m in &n.members {
                    line(&mut files, b, &format!("tagged {m} +{vid}"));
                }
            }
            line(&mut files, &n.ifname, &format!("description \"{}\"", n.name));
        }
        line(&mut files, &n.ifname, &format!("inet {} {}", n.addr, n.prefix.netmask()));
        if let Some(v6) = n.v6 {
            line(&mut files, &n.ifname, &format!("inet6 {} {}", v6.ula.addr(), v6.ula.prefix_len()));
        }
        // pf reaches every internal network's (dynamic, delegated) IPv6 prefix through the group
        line(&mut files, &n.ifname, &format!("group {LAN_GROUP}"));
    }

    if let (Some(w), Some(cw)) = (&r.wan, &c.wan) {
        if let Some(v) = &w.vlan_if {
            let mut l = format!("parent {} vnetid {}", w.phys, cw.vlan.unwrap_or_default());
            if let Some(p) = cw.vlan_prio {
                let _ = write!(l, " txprio {p}");
            }
            line(&mut files, v, &l);
            line(&mut files, v, "description \"wan\"");
        }
        let carrier = w.vlan_if.clone().unwrap_or_else(|| w.phys.clone());
        match &cw.mode() {
            None => {}
            Some(WanMode::Pppoe { user, password, auth }) => {
                let u = secrets.get(user)?;
                let p = secrets.get(password)?;
                // the carrier needs room for the 8-byte PPPoE header
                if cw.mtu + 8 != 1500 {
                    line(&mut files, &carrier, &format!("mtu {}", cw.mtu + 8));
                }
                line(
                    &mut files,
                    PPPOE_IF,
                    &format!(
                        "inet 0.0.0.0 255.255.255.255 NONE mtu {} \\\n\tpppoedev {carrier} authproto {auth} \\\n\tauthname '{u}' authkey '{p}' up",
                        cw.mtu
                    ),
                );
                line(&mut files, PPPOE_IF, "dest 0.0.0.1");
                line(&mut files, PPPOE_IF, "description \"wan\"");
                if c.ipv6.mode == Ipv6Mode::Pd {
                    line(&mut files, PPPOE_IF, "inet6 eui64");
                }
                line(&mut files, PPPOE_IF, "!/sbin/route add default -ifp pppoe0 0.0.0.1");
                if c.ipv6.mode == Ipv6Mode::Pd {
                    line(&mut files, PPPOE_IF, "!/sbin/route add -inet6 default -ifp pppoe0 fe80::%pppoe0");
                }
                secret_files.push(PPPOE_IF.to_string());
            }
            Some(WanMode::Dhcp) => {
                line(&mut files, &carrier, "inet autoconf");
                if c.ipv6.mode == Ipv6Mode::Pd {
                    line(&mut files, &carrier, "inet6 autoconf");
                }
            }
            Some(WanMode::Static { address, gateway }) => {
                line(&mut files, &carrier, &format!("inet {} {}", address.addr(), address.netmask()));
                g.file("/etc/mygate", format!("{gateway}\n"), Subsystem::Net);
            }
        }
    }

    if let Some(wg) = &c.wireguard {
        let key = secrets.get(&wg.private_key)?;
        line(&mut files, WG_IF, &format!("wgkey {key} wgport {}", wg.listen_port));
        for p in &wg.peers {
            let mut l = format!("wgpeer {} wgaip {}/32 wgdescr \"{}\"", p.public_key, p.address, p.name);
            if let Some(psk) = &p.preshared_key {
                let _ = write!(l, " wgpsk {}", secrets.get(psk)?);
            }
            line(&mut files, WG_IF, &l);
        }
        line(&mut files, WG_IF, &format!("inet {} {}", wg.address.addr(), wg.address.netmask()));
        line(&mut files, WG_IF, "description \"wireguard\"");
        secret_files.push(WG_IF.to_string());
    }

    if let Some(p) = &c.logging.pflow {
        // a collector on the router itself is reached over loopback
        let local = p.starts_with("127.");
        let src = if local {
            Some("127.0.0.1".to_string())
        } else {
            r.nets.iter().find(|n| n.kind == Kind::Mgmt).map(|n| n.addr.to_string())
        };
        if let Some(src) = src {
            line(&mut files, "pflow0", &format!("flowsrc {src} flowdst {p} pflowproto 10"));
        }
    }

    // static routes ride on the interface that reaches the gateway
    for rt in &c.routes {
        if rt.to == "default" {
            if c.wan.is_none() || matches!(c.wan.as_ref().and_then(|w| w.mode()), Some(WanMode::Dhcp)) {
                g.file("/etc/mygate", format!("{}\n", rt.via), Subsystem::Net);
            }
            continue;
        }
        if let Some(n) = r.net_of(rt.via) {
            line(&mut files, &n.ifname, &format!("!/sbin/route -qn add -inet {} {}", rt.to, rt.via));
        }
    }

    for (ifname, mut content) in files {
        // `up` last, after every address and option
        content.push_str("up\n");
        let secret = secret_files.contains(&ifname);
        let f = g.file(format!("/etc/hostname.{ifname}"), content, Subsystem::Net);
        f.mode = if secret { 0o600 } else { 0o640 };
        f.secret = secret;
    }

    // a router forwards; IPv6 forwarding follows the IPv6 mode
    let v6 = if c.ipv6.mode == Ipv6Mode::Pd { 1 } else { 0 };
    let sysctl = format!("{}net.inet.ip.forwarding=1\nnet.inet6.ip6.forwarding={v6}\n", header("#", &[]));
    g.file("/etc/sysctl.conf", sysctl, Subsystem::Sysctl);
    g.file("/etc/myname", format!("{}.{}\n", c.system.hostname, c.system.domain), Subsystem::Net);

    // the router resolves through its own DNS service
    let resolv = format!("{}nameserver 127.0.0.1\nsearch {}\nlookup file bind\n", header("#", &[]), c.system.domain);
    g.file("/etc/resolv.conf", resolv, Subsystem::Resolv);
    Ok(())
}

fn quote_safe(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '"' | '\\' | '\n' | '\r' | '$' | '`')).collect()
}
