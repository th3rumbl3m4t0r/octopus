//! Structural checks and the design invariants (INV-1..4). Anything here that
//! fails aborts a build; warnings are printed and kept with the generation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::diag::Diagnostics;
use crate::ifmap::normalize_mac;
use crate::model::{Endpoint, RULE_ALL, RULE_WAN, Router};
use crate::schema::*;
use crate::secrets::{self, Secrets};

/// Where anyone can get a name of their own (buckets, pages, apps).
const SHARED_SUFFIXES: &[&str] = &[
    "amazonaws.com",
    "cloudfront.net",
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "blob.core.windows.net",
    "azurewebsites.net",
    "azureedge.net",
    "herokuapp.com",
    "appspot.com",
    "googleusercontent.com",
    "storage.googleapis.com",
    "firebaseapp.com",
    "web.app",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "fastly.net",
    "digitaloceanspaces.com",
    "backblazeb2.com",
    "ngrok.io",
    "ngrok-free.app",
];

/// Words with a meaning of their own in router.toml, or in pf.conf as macro
/// (`$if_wg`) and label (`wg_lan:`, `rule:`) names.
const RESERVED: [&str; 19] = [
    "any",
    "self",
    "wan",
    "all",
    "egress",
    "lo",
    "internal",
    "internet",
    "cloudflare",
    "wg",
    "wg_mgmt",
    "wg_lan",
    "v6",
    "rule",
    "link",
    "fwd",
    "urpf",
    "lab_block",
    "martians",
];

fn ident_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A name that ends up in labels and comments of generated files: a-z, 0-9,
/// `_` and `-`, starting with a letter or digit.
fn name_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// An absolute path of plain characters: nothing a shell, rc.conf.local or
/// a daemon's config parser would read as syntax, and no `..`.
pub fn path_ok(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 255
        && !s.split('/').any(|p| p == "..")
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

/// A WireGuard key: 32 bytes in base64, 43 characters and `=` (the last
/// character carries 4 bits, so only every fourth letter can end it).
pub fn wg_key_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44
        && b[43] == b'='
        && b[..43].iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/'))
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

/// A host name or an address (IPv6 in brackets where a port may follow).
pub fn host_ok(s: &str) -> bool {
    let bare = s.strip_prefix('[').and_then(|x| x.strip_suffix(']'));
    match bare {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => s.parse::<Ipv4Addr>().is_ok() || (dns_name_ok(s) && !s.is_empty()),
    }
}

pub fn dns_label_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn dns_name_ok(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    s.len() <= 253 && s.split('.').all(dns_label_ok)
}

/// Parse a pf bandwidth like `22M`, `900K` or `1G` into bits per second.
pub fn parse_rate(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        'K' => (&s[..s.len() - 1], 1_000),
        'M' => (&s[..s.len() - 1], 1_000_000),
        'G' => (&s[..s.len() - 1], 1_000_000_000),
        _ => (s, 1),
    };
    // at most 100G: anything more is a typo, and the queue math stays in range
    num.parse::<u64>().ok().filter(|n| *n > 0).and_then(|n| n.checked_mul(mult)).filter(|b| *b <= 100_000_000_000)
}

/// Remote syslog target: (proto, host, port).
pub fn parse_remote(s: &str) -> Option<(&str, &str, Option<u16>)> {
    let (proto, rest) = s.split_once("://")?;
    if !matches!(proto, "udp" | "tcp" | "tls") {
        return None;
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => (h, Some(p.parse().ok()?)),
        _ => (rest, None),
    };
    // it becomes a syslog.conf action: a host and nothing else
    host_ok(host).then_some((proto, host, port))
}

/// An ntpd `constraints from` URL: https://, a host, an optional plain path.
pub fn constraint_ok(s: &str) -> bool {
    let rest = s.strip_prefix("https://").unwrap_or(s);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    host_ok(host) && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'~'))
}

/// Every string in the file, with where it is: control characters (a
/// newline above all) would start a new line in some generated file.
fn control_chars(c: &Config, d: &mut Diagnostics) {
    fn walk(v: &toml::Value, path: &str, d: &mut Diagnostics) {
        match v {
            toml::Value::String(s) if s.chars().any(char::is_control) => {
                d.error("E-TEXT", format!("{path}: no control characters (newlines, tabs, ...) in values"))
            }
            toml::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, &format!("{path}[{i}]"), d);
                }
            }
            toml::Value::Table(t) => {
                for (k, x) in t {
                    if k.chars().any(char::is_control) {
                        d.error("E-TEXT", format!("{path}: a key with control characters"));
                    }
                    walk(x, &if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, d);
                }
            }
            _ => {}
        }
    }
    match toml::Value::try_from(c) {
        Ok(v) => walk(&v, "", d),
        Err(e) => d.error("E-TEXT", format!("can't re-read the configuration: {e}")),
    }
}

pub fn check(r: &Router, secrets: Option<&Secrets>) -> Diagnostics {
    let mut d = Diagnostics::default();
    let c = &r.cfg;
    control_chars(c, &mut d);

    // ---- system
    if !dns_label_ok(&c.system.hostname) {
        d.error("E-SYS", format!("hostname {:?} is not a DNS label", c.system.hostname));
    }
    if !dns_name_ok(&c.system.domain) || c.system.domain.is_empty() {
        d.error("E-SYS", format!("domain {:?} is not a DNS name", c.system.domain));
    }
    let rel_ok = c
        .system
        .openbsd_release
        .split_once('.')
        .is_some_and(|(a, b)| a.parse::<u8>().is_ok() && b.len() == 1 && b.parse::<u8>().is_ok());
    if !rel_ok {
        d.error("E-SYS", format!("openbsd_release {:?} should look like 7.9", c.system.openbsd_release));
    }

    // ---- interfaces: one role per MAC
    let mut macs = BTreeMap::new();
    for (role, i) in &c.interfaces {
        if !name_ok(role, 31) {
            d.error("E-IF", format!("interface role {role:?}: use a-z, 0-9, _, - (max 31)"));
        }
        if let Some(n) = &i.name {
            let digits = n.trim_start_matches(|ch: char| ch.is_ascii_lowercase());
            if n.len() > 15
                || digits.len() == n.len()
                || digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                d.error("E-IF", format!("interface {role}: name {n:?} is not an interface name like igc0"));
            }
        }
        if let Some(m) = normalize_mac(&i.mac)
            && let Some(other) = macs.insert(m.clone(), role)
        {
            d.error("E-IF", format!("interfaces {other} and {role} share MAC {m}"));
        }
    }

    // ---- networks
    let mut names = BTreeSet::new();
    let mut untagged = BTreeMap::new();
    let mut tags = BTreeSet::new();
    if let Some(w) = &c.wan {
        match w.vlan {
            Some(v) => {
                tags.insert(v);
            }
            None => {
                untagged.insert(w.interface.clone(), "wan".to_string());
            }
        }
        if let Some(p) = w.vlan_prio
            && p > 7
        {
            d.error("E-WAN", "wan.vlan_prio must be 0..7");
        }
        if w.mtu < 1280 || w.mtu > 9000 {
            d.error("E-WAN", format!("wan.mtu {} out of range", w.mtu));
        }
        if let Some(m) = w.mss
            && u32::from(m) + 40 > u32::from(w.mtu)
        {
            d.error("E-WAN", format!("wan.mss {m} doesn't fit mtu {}", w.mtu));
        }
        if w.mode().is_none() {
            d.error("E-WAN", "wan: set exactly one of pppoe = {...}, dhcp = true, static = {...}");
        }
        if let Some(WanMode::Pppoe { user, password, auth }) = &w.mode() {
            for s in [user, password] {
                check_router_secret(&mut d, "wan.pppoe", s, secrets);
            }
            if !matches!(auth.as_str(), "chap" | "pap") {
                d.error("E-WAN", "wan.auth must be chap or pap");
            }
        }
    }
    for n in &c.networks {
        if !ident_ok(&n.name, 15) || RESERVED.contains(&n.name.as_str()) {
            d.error("E-NET", format!("network name {:?}: use a-z, 0-9, _ (max 15), not a reserved word", n.name));
        }
        if !names.insert(n.name.clone()) {
            d.error("E-NET", format!("duplicate network {}", n.name));
        }
        match (n.vlan, &n.interface) {
            (Some(v), _) if v == 0 || v > 4094 => {
                d.error("E-NET", format!("network {}: vlan {v} out of range", n.name))
            }
            (Some(v), _) => {
                if !tags.insert(v) {
                    d.error("E-NET", format!("network {}: vlan {v} used twice", n.name));
                }
            }
            (None, Some(role)) => {
                if let Some(other) = untagged.insert(role.clone(), n.name.clone()) {
                    d.error("E-NET", format!("networks {other} and {} are both untagged on {role}", n.name));
                }
            }
            (None, None) => {
                // a bridge takes its ports over completely
                for role in &n.bridge {
                    if let Some(other) = untagged.insert(role.clone(), n.name.clone()) {
                        d.error("E-NET", format!("{role} is in bridge {} and also used by {other}", n.name));
                    }
                }
            }
        }
        let p = n.address;
        if p.prefix_len() < 31 && (p.addr() == p.network() || p.addr() == p.broadcast()) {
            d.error("E-NET", format!("network {}: {} is the network or broadcast address", n.name, p.addr()));
        }
        if let Some(dh) = &n.dhcp {
            let ranges = dh.all_ranges();
            if ranges.is_empty() {
                d.error("E-DHCP", format!("network {}: dhcp needs range or ranges", n.name));
            }
            for (i, [a, b]) in ranges.iter().copied().enumerate() {
                if !p.contains(&a) || !p.contains(&b) || a > b {
                    d.error("E-DHCP", format!("network {}: dhcp range {a}-{b} is not inside {}", n.name, p.trunc()));
                } else if a <= p.addr() && p.addr() <= b {
                    d.error(
                        "E-DHCP",
                        format!("network {}: dhcp range {a}-{b} contains the router {}", n.name, p.addr()),
                    );
                }
                if a == p.network() || b == p.broadcast() {
                    d.error("E-DHCP", format!("network {}: dhcp range includes network/broadcast address", n.name));
                }
                for [c, e] in &ranges[i + 1..] {
                    if a <= *e && *c <= b {
                        d.error("E-DHCP", format!("network {}: dhcp ranges {a}-{b} and {c}-{e} overlap", n.name));
                    }
                }
            }
            if dh.lease_time > dh.max_lease_time {
                d.error("E-DHCP", format!("network {}: lease_time > max_lease_time", n.name));
            }
        }
        if n.kind == Kind::Servers && n.class == Some(Class::Realtime) {
            d.warn("E-NET", format!("network {}: servers with realtime class", n.name));
        }
    }
    // VLANs and bridges: a veb owns its ports; networks on the same set of
    // ports share it (untagged plus tagged), other bridges can't touch them
    let mut bridge_sets: Vec<(&str, BTreeSet<&str>)> = c
        .networks
        .iter()
        .filter(|n| n.interface.is_none() && n.bridge.len() >= 2)
        .map(|n| (n.name.as_str(), n.bridge.iter().map(String::as_str).collect()))
        .collect();
    if let Some(lan) = &c.lan {
        bridge_sets.push(("lan", lan.ports.iter().map(String::as_str).collect()));
        if lan.ports.is_empty() {
            d.error("E-LAN", "lan: no ports");
        }
        for n in c.networks.iter().filter(|n| n.vlan.is_none() && n.bridge.iter().any(|p| lan.ports.contains(p))) {
            d.error(
                "E-LAN",
                format!(
                    "tier {}: bridge uses house ports ([lan]); two untagged networks on one wire would share it: leave bridge out to put the tier there",
                    n.name
                ),
            );
        }
        for n in c.networks.iter().filter(|n| n.interface.as_ref().is_some_and(|i| lan.ports.contains(i))) {
            d.error(
                "E-LAN",
                format!(
                    "tier {}: {} is a house port ([lan]); leave interface out to put the tier there",
                    n.name,
                    n.interface.as_deref().unwrap_or("")
                ),
            );
        }
    }
    // the house ports: untagged tiers share them, chosen by MAC; one is the
    // fallback for every other cable
    let on_lan = |n: &Network| c.lan.is_some() && n.interface.is_none() && n.bridge.is_empty();
    let untagged: Vec<&Network> = c.networks.iter().filter(|n| on_lan(n) && n.vlan.is_none()).collect();
    if untagged.iter().filter(|n| n.wired).count() > 1 {
        d.error("E-LAN", "more than one tier is wired = true: one fallback for the cables");
    }
    if untagged.len() > 1 && !untagged.iter().any(|n| n.wired) {
        d.warn("E-LAN", "no tier is wired = true: a device on a cable whose MAC no tier lists gets no address");
    }
    for n in &c.networks {
        if !n.ports.is_empty() {
            let lan_ports = c.lan.as_ref().map(|l| l.ports.as_slice()).unwrap_or_default();
            if !on_lan(n) || n.vlan.is_none() {
                d.error(
                    "E-LAN",
                    format!("tier {}: ports picks the house ports that carry a VLAN tier ([lan], vlan)", n.name),
                );
            }
            for p in n.ports.iter().filter(|p| !lan_ports.contains(p)) {
                d.error("E-LAN", format!("tier {}: {p} is not a house port ([lan] ports)", n.name));
            }
        } else if on_lan(n)
            && n.vlan.is_some()
            && !r.is_guest(&n.name)
            && c.lan.as_ref().is_some_and(|l| l.ports.len() > 1)
        {
            d.warn(
                "E-LAN",
                format!(
                    "tier {}: VLAN {} is carried on every house port, so any device on a cable can join it by tagging; set ports to the access points' ports",
                    n.name,
                    n.vlan.unwrap_or(0)
                ),
            );
        }
    }
    let mut seen_macs: BTreeMap<String, &str> = BTreeMap::new();
    for n in &c.networks {
        if (!n.macs.is_empty() || n.wired) && !(on_lan(n) && n.vlan.is_none()) {
            d.error(
                "E-LAN",
                format!(
                    "tier {}: macs and wired choose between the tiers untagged on the house ports ([lan], no vlan)",
                    n.name
                ),
            );
        }
        if n.kind == Kind::Open && c.lan.is_none() && n.interface.is_none() && n.bridge.is_empty() {
            d.error("E-LAN", format!("tier {}: no interface or bridge, and no [lan]", n.name));
        }
        let prefixes: Vec<&str> = n.macs.iter().filter(|m| m.split(':').count() < 6).map(String::as_str).collect();
        if !prefixes.is_empty() {
            d.warn(
                "E-LAN",
                format!(
                    "tier {}: {} {} a prefix: any device that sets such a MAC is placed there and passes the guard",
                    n.name,
                    prefixes.join(", "),
                    if prefixes.len() == 1 { "is" } else { "are" }
                ),
            );
        }
        for m in &n.macs {
            let ok = !m.is_empty()
                && m.split(':').count() <= 6
                && m.split(':').all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()));
            if !ok {
                d.error("E-LAN", format!("tier {}: {m:?} is not a MAC or a prefix of one (bc:24:11)", n.name));
            }
            if let Some(other) = seen_macs.insert(m.to_ascii_lowercase(), &n.name) {
                d.warn("E-LAN", format!("{m} is in tiers {other} and {}", n.name));
            }
        }
    }
    for (i, (a, sa)) in bridge_sets.iter().enumerate() {
        for (b, sb) in &bridge_sets[i + 1..] {
            if sa != sb && !sa.is_disjoint(sb) {
                d.error("E-NET", format!("bridges {a} and {b} share some ports: one bridge per set of ports"));
            }
        }
    }
    for n in &c.networks {
        let bridged = n.interface.is_none() && (n.bridge.len() >= 2 || on_lan(n));
        if bridged && n.vlan == Some(1) {
            d.error("E-NET", format!("network {}: vlan 1 is a bridge's own untagged VLAN", n.name));
        }
        if let (Some(v), Some(role)) = (n.vlan, &n.interface)
            && let Some((b, ports)) = bridge_sets.iter().find(|(_, s)| s.contains(role.as_str()))
        {
            d.error(
                "E-NET",
                format!(
                    "network {}: {role} is in bridge {b}; put the VLAN on the bridge: bridge = [{}], vlan = {v}",
                    n.name,
                    ports.iter().map(|p| format!("\"{p}\"")).collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }
    for (i, a) in r.nets.iter().enumerate() {
        for b in &r.nets[i + 1..] {
            if a.prefix.contains(&b.prefix.network()) || b.prefix.contains(&a.prefix.network()) {
                d.error("E-NET", format!("networks {} ({}) and {} ({}) overlap", a.name, a.prefix, b.name, b.prefix));
            }
        }
    }

    // ---- hosts
    let mut host_names = BTreeSet::new();
    let mut host_ips = BTreeMap::new();
    let mut host_macs = BTreeMap::new();
    for h in &c.hosts {
        if !dns_label_ok(&h.name) {
            d.error("E-HOST", format!("host {:?} is not a DNS label", h.name));
        }
        for a in &h.aliases {
            if !dns_label_ok(a) {
                d.error("E-HOST", format!("host {}: alias {a:?} is not a DNS label", h.name));
            }
            if !host_names.insert(a.clone()) {
                d.error("E-HOST", format!("host name {a} used twice"));
            }
        }
        if !host_names.insert(h.name.clone()) {
            d.error("E-HOST", format!("host name {} used twice", h.name));
        }
        if let Some(other) = host_ips.insert(h.ip, h.name.clone()) {
            d.error("E-HOST", format!("hosts {other} and {} share {}", h.name, h.ip));
        }
        let tier = match &h.network {
            Some(name) => r.net(name).map(|x| x.1).ok_or_else(|| format!("host {}: unknown tier {name}", h.name)),
            None => r.net_of(h.ip).ok_or_else(|| format!("host {}: {} is in no tier's range", h.name, h.ip)),
        };
        match tier {
            Err(e) => d.error("E-HOST", e),
            Ok(n) => {
                if !n.prefix.contains(&h.ip) {
                    d.error("E-HOST", format!("host {}: {} is not in {} ({})", h.name, h.ip, n.name, n.prefix));
                }
                if h.ip == n.addr {
                    d.error("E-HOST", format!("host {}: {} is the router", h.name, h.ip));
                }
                let net = c.networks.iter().find(|x| x.name == n.name);
                if let (Some(_), Some(dh)) = (&h.mac, net.and_then(|x| x.dhcp.as_ref()))
                    && dh.all_ranges().iter().any(|[a, b]| *a <= h.ip && h.ip <= *b)
                {
                    d.warn("E-DHCP", format!("host {}: reservation {} is inside the dynamic range", h.name, h.ip));
                }
            }
        }
        if let Some(m) = &h.mac {
            match normalize_mac(m) {
                None => d.error("E-HOST", format!("host {}: bad MAC {m:?}", h.name)),
                Some(m) => {
                    if let Some(other) = host_macs.insert(m.clone(), h.name.clone()) {
                        d.error("E-HOST", format!("hosts {other} and {} share MAC {m}", h.name));
                    }
                }
            }
        }
    }

    // ---- tables
    let mut tnames = BTreeSet::new();
    for t in &c.tables {
        if !ident_ok(&t.name, 28) || RESERVED.contains(&t.name.as_str()) || t.name.starts_with("cls_") {
            d.error("E-TABLE", format!("table name {:?}: use a-z, 0-9, _ (max 28, no cls_ prefix)", t.name));
        }
        if !tnames.insert(&t.name) {
            d.error("E-TABLE", format!("duplicate table {}", t.name));
        }
        let mut seen = BTreeSet::new();
        for e in &t.entries {
            if !seen.insert(e) {
                d.warn("E-TABLE", format!("table {}: {e} listed twice", t.name));
            }
        }
    }

    // ---- forwards (INV-2: the only declared inbound paths)
    let mut fnames = BTreeSet::new();
    for f in &c.forwards {
        if !name_ok(&f.name, 31) {
            d.error("E-FWD", format!("forward {:?}: a name of a-z, 0-9, _, - (max 31)", f.name));
        }
        if !fnames.insert(&f.name) {
            d.error("E-FWD", format!("duplicate forward {}", f.name));
        }
        if !f.proto.has_ports() {
            d.error("INV-2", format!("forward {}: proto must be tcp, udp or tcp/udp", f.name));
        }
        match r.net_of(f.to) {
            None => d.error("INV-2", format!("forward {}: {} is not on an internal network", f.name, f.to)),
            Some(n) if n.addr == f.to => d.error("INV-2", format!("forward {}: target is the router itself", f.name)),
            Some(_) => {}
        }
        if f.to_port.is_some() && f.port.0.len() != 1 {
            // a range maps onto a range starting at to_port; a list can't
            d.error("E-FWD", format!("forward {}: to_port needs a single port or range", f.name));
        }
        if let (Some(tp), [(a, b)]) = (f.to_port, f.port.0.as_slice())
            && u32::from(tp) + u32::from(b - a) > 65535
        {
            d.error(
                "E-FWD",
                format!("forward {}: to_port {tp} + the range's {} ports goes past 65535", f.name, b - a + 1),
            );
        }
        match r.endpoint(&f.from) {
            Err(e) => d.error("E-FWD", format!("forward {}: from: {e}", f.name)),
            Ok(Endpoint::Net(_) | Endpoint::Router | Endpoint::Internal) => {
                d.error("E-FWD", format!("forward {}: from must be any, internet, a table or an address", f.name))
            }
            Ok(Endpoint::Any) => d.warn("INV-2", format!("forward {}: open to the whole internet", f.name)),
            Ok(e) => {
                if f.reflect && !r.overlaps_internal(&e) {
                    d.warn(
                        "E-FWD",
                        format!(
                            "forward {}: reflect has no effect, the source restriction excludes internal clients",
                            f.name
                        ),
                    );
                }
            }
        }
        if let Some(wg) = &c.wireguard
            && matches!(f.proto, Proto::Udp | Proto::TcpUdp)
            && f.port.contains(wg.listen_port)
        {
            d.error("INV-2", format!("forward {}: collides with the WireGuard port", f.name));
        }
    }

    // ---- rules
    let ssh = c.ssh.port;
    let web = c.web.enabled.then_some(c.web.port);
    for (i, rule) in c.rules.iter().enumerate() {
        let what = match &rule.description {
            Some(s) => format!("rule {} ({s})", i + 1),
            None => format!("rule {}", i + 1),
        };
        if rule.port.is_some() && !rule.proto.has_ports() {
            d.error("E-RULE", format!("{what}: port needs proto tcp, udp or tcp/udp"));
        }
        let from = r.endpoint(&rule.from).map_err(|e| d.error("E-RULE", format!("{what}: from: {e}")));
        let to = r.endpoint(&rule.to).map_err(|e| d.error("E-RULE", format!("{what}: to: {e}")));
        if rule.network == RULE_WAN {
            // INV-2: the only ways in are forwards (and the WireGuard port, public vhosts)
            if c.wan.is_none() {
                d.error("E-RULE", format!("{what}: network wan without a [wan]"));
            }
            if rule.action == Action::Pass {
                d.error(
                    "INV-2",
                    format!("{what}: nothing passes in from the internet but forwards; make it a forward"),
                );
            }
            if let Ok(f) = &from
                && r.is_internal(f)
            {
                d.warn("E-RULE", format!("{what}: from {} is internal, but the rule is on the WAN", rule.from));
            }
            // pf matches the WAN address and the WAN port: a forward to that
            // host on another WAN port still passes
            if let (Ok(t), Some(_)) = (&to, &rule.port)
                && r.is_internal(t)
                && !matches!(t, Endpoint::Router)
            {
                d.warn(
                    "E-RULE",
                    format!("{what}: on the WAN, the port is the WAN address's: a forward to {} on another port still passes", rule.to),
                );
            }
            continue;
        }
        let nets = r.rule_nets(&rule.network);
        if nets.is_empty() {
            d.error("E-RULE", format!("{what}: unknown network {} (a network, all or wan)", rule.network));
            continue;
        }
        let (Ok(from), Ok(to)) = (from, to) else { continue };
        // tiers on one interface are told apart by source address: a rule for
        // one of them takes the part of its source inside the tier's range
        if let [n] = nets.as_slice()
            && n.src.is_some()
            && rule.network != RULE_ALL
            && matches!(from, Endpoint::Table(_))
        {
            d.error(
                "E-RULE",
                format!(
                    "{what}: tier {} shares its ports with other tiers, so a table can't be its source; use network = \"all\"",
                    n.name
                ),
            );
        }
        if let (Some(a), Some(b)) = (r.endpoint_tier(&from), r.endpoint_tier(&to))
            && a.name != b.name
            && a.ifname == b.ifname
        {
            d.warn(
                "E-RULE",
                format!(
                    "{what}: {} and {} share the house ports: devices there talk to each other directly, pf only sees what goes through the router",
                    a.name, b.name
                ),
            );
        }
        // a rule on every network only matters where its source can be
        let nets: Vec<_> =
            nets.into_iter().filter(|n| rule.network != RULE_ALL || r.endpoint_in_net(&from, n)).collect();
        if rule.action != Action::Pass {
            continue;
        }
        let hits = |p: u16| match &rule.port {
            None => true,
            Some(ports) => ports.contains(p),
        };
        let tcp = matches!(rule.proto, Proto::Any | Proto::Tcp | Proto::TcpUdp);
        // INV-1: explicit pass to the router's management ports from a non-mgmt network
        let explicit_router = match &to {
            Endpoint::Router => true,
            Endpoint::Addr(_) | Endpoint::Table(_) => r.covers_router(&to),
            _ => false,
        };
        for net in &nets {
            if !matches!(net.kind, Kind::Mgmt | Kind::Open)
                && explicit_router
                && tcp
                && (hits(ssh) || web.is_some_and(hits))
            {
                d.error("INV-1", format!("{what}: passes {} to the router's management ports", net.name));
            }
            // INV-3: servers get no direct egress except links
            if net.kind == Kind::Servers && !r.is_internal(&to) {
                let how = if rule.network == RULE_ALL { "; name the networks instead of all" } else { "" };
                d.error(
                    "INV-3",
                    format!("{what}: servers network {} passes to the outside; use [[links]]{how}", net.name),
                );
            }
        }
        // INV-4: the interception rules come first, so these never match
        if !matches!(to, Endpoint::Router) && (hits(53) || hits(853)) && rule.port.is_some() {
            d.warn("INV-4", format!("{what}: DNS/DoT to other servers is intercepted before this rule"));
        }
    }

    // ---- links (INV-3)
    for (i, l) in c.links.iter().enumerate() {
        match r.net(&l.network) {
            None => d.error("E-LINK", format!("link {}: unknown network {}", i + 1, l.network)),
            Some((_, n)) if n.kind != Kind::Servers => {
                d.error("INV-3", format!("link {}: {} is not a servers network", i + 1, n.name))
            }
            _ => {}
        }
        match r.endpoint(&l.to) {
            Err(e) => d.error("E-LINK", format!("link {}: to: {e}", i + 1)),
            Ok(Endpoint::Any | Endpoint::Internet) => {
                d.error("INV-3", format!("link {}: a link to {} is unrestricted egress", i + 1, l.to))
            }
            Ok(_) => {}
        }
        if l.port.is_some() && !l.proto.has_ports() {
            d.error("E-LINK", format!("link {}: port needs proto tcp or udp", i + 1));
        }
    }

    // ---- routes
    let mut default_route = false;
    for rt in &c.routes {
        if rt.to == "default" {
            default_route = true;
        } else if rt.to.parse::<ipnet::Ipv4Net>().is_err() {
            d.error("E-ROUTE", format!("route to {:?}: not a prefix or default", rt.to));
        }
        if r.net_of(rt.via).is_none() {
            d.error("E-ROUTE", format!("route via {}: not on an internal network", rt.via));
        }
    }
    match c.wan.as_ref().and_then(|w| w.mode()) {
        Some(WanMode::Pppoe { .. } | WanMode::Static { .. }) if default_route => {
            d.error("E-ROUTE", "[[routes]] to default conflicts with the WAN's default route")
        }
        // netstart ignores /etc/mygate when any interface uses inet autoconf (mygate(5))
        Some(WanMode::Dhcp) if default_route => {
            d.error("E-ROUTE", "[[routes]] to default can't work with a DHCP WAN: OpenBSD ignores /etc/mygate then")
        }
        _ => {}
    }

    // ---- DNS
    if c.dns.upstreams.is_empty() {
        d.error("E-DNS", "dns.upstreams is empty");
    }
    for u in &c.dns.upstreams {
        if !dns_name_ok(&u.tls_name) {
            d.error("E-DNS", format!("upstream {}: tls_name {:?} is not a DNS name", u.ip, u.tls_name));
        }
    }
    if c.dns.upstreams.len() == 1 {
        d.warn("E-DNS", "only one DNS upstream; add a second for redundancy");
    }
    let zone = format!(".{}", c.system.domain);
    // every record and override is a zone file of its own: two of one name,
    // or one named like a zone we make anyway, would replace it
    let mut zone_names: BTreeSet<String> = BTreeSet::new();
    for n in c.dns.records.iter().map(|x| &x.name).chain(c.dns.overrides.iter().map(|x| &x.name)) {
        let n = n.trim_end_matches('.').to_ascii_lowercase();
        if n.ends_with(".in-addr.arpa") || n.ends_with(".ip6.arpa") || n == "use-application-dns.net" {
            d.error("E-DNS", format!("{n}: a zone the router makes itself"));
        }
        if !zone_names.insert(n.clone()) {
            d.error("E-DNS", format!("{n} is in dns.records or dns.overrides twice"));
        }
    }
    for rec in &c.dns.records {
        if !dns_name_ok(&rec.name) || !rec.name.contains('.') {
            d.error("E-DNS", format!("record {:?} is not a fully qualified name", rec.name));
        }
        if rec.name.ends_with(&zone) || rec.name == c.system.domain {
            d.error("E-DNS", format!("record {}: names in the internal zone are [[hosts]]", rec.name));
        }
    }

    // ---- NTP, logging
    if c.ntp.servers.is_empty() {
        d.error("E-NTP", "ntp.servers is empty");
    }
    for srv in &c.ntp.servers {
        if !host_ok(srv) {
            d.error("E-NTP", format!("ntp.servers {srv:?}: a host name or an address"));
        }
    }
    // the router's names come from its own DNS over TLS, which needs the
    // right time; ntpd starts before it and steps the clock only then
    let wan_dhcp = matches!(c.wan.as_ref().and_then(|w| w.mode()), Some(WanMode::Dhcp));
    if !c.ntp.servers.is_empty() && !wan_dhcp && c.ntp.servers.iter().all(|s| s.parse::<IpAddr>().is_err()) {
        d.warn(
            "E-NTP",
            "every ntp server is a name: at boot ntpd can't resolve them (the DNS service starts later and needs the right time for TLS), so a clock that is far off is never stepped; add one by address, e.g. 162.159.200.123 (time.cloudflare.com)",
        );
    }
    for k in &c.ntp.constraints {
        if !constraint_ok(k) {
            d.error("E-NTP", format!("ntp.constraints {k:?}: https://host or an address"));
        }
    }
    for s in &c.logging.remote {
        if parse_remote(s).is_none() {
            d.error("E-LOG", format!("logging.remote {s:?}: use udp://, tcp:// or tls://host[:port]"));
        } else if s.starts_with("udp://") {
            d.warn("E-LOG", format!("logging.remote {s}: plaintext UDP; the design asks for tls://"));
        }
    }
    if let Some(p) = &c.logging.pflow {
        match p.parse::<std::net::SocketAddrV4>() {
            Err(_) => d.error("E-LOG", format!("logging.pflow {p:?}: use ip:port")),
            // on the router itself it is octopus-collector, which listens there
            Ok(a) if a.ip().is_loopback() && a.to_string() != "127.0.0.1:2055" => {
                d.error("E-LOG", format!("logging.pflow {p}: the collector on the router is 127.0.0.1:2055"))
            }
            Ok(_) => {}
        }
    }

    // ---- traffic
    if let Some(t) = &c.traffic {
        for (k, v) in [("upload", &t.upload), ("download", &t.download)] {
            if parse_rate(v).is_none() {
                d.error("E-QUEUE", format!("traffic.{k} {v:?}: use e.g. 22M"));
            }
        }
        for dest in &t.destinations {
            for dom in &dest.domains {
                if !dns_name_ok(dom) {
                    d.error("E-QUEUE", format!("traffic destination {dom:?} is not a DNS name"));
                }
            }
        }
        for p in &t.ports {
            if !p.proto.has_ports() {
                d.error("E-QUEUE", "traffic.ports: proto must be tcp, udp or tcp/udp");
            }
        }
    }

    // ---- WireGuard
    if let Some(wg) = &c.wireguard {
        check_router_secret(&mut d, "wireguard.private_key", &wg.private_key, secrets);
        if r.nets.iter().any(|n| n.prefix.contains(&wg.address.network()) || wg.address.contains(&n.prefix.network())) {
            d.error("E-WG", format!("wireguard.address {} overlaps a network", wg.address));
        }
        let mut pn = BTreeSet::new();
        let mut pa = BTreeSet::new();
        for p in &wg.peers {
            if !name_ok(&p.name, 31) {
                d.error("E-WG", format!("peer {:?}: a name of a-z, 0-9, _, - (max 31)", p.name));
            }
            if !pn.insert(&p.name) {
                d.error("E-WG", format!("duplicate peer {}", p.name));
            }
            if !pa.insert(p.address) || p.address == wg.address.addr() || !wg.address.contains(&p.address) {
                d.error(
                    "E-WG",
                    format!("peer {}: address {} must be unique and inside {}", p.name, p.address, wg.address),
                );
            }
            if !matches!(p.policy, Kind::Mgmt | Kind::Lan) {
                d.error("E-WG", format!("peer {}: policy must be mgmt or lan", p.name));
            }
            if !wg_key_ok(&p.public_key) {
                d.error("E-WG", format!("peer {}: public_key is not a WireGuard key", p.name));
            }
            if let Some(k) = &p.preshared_key {
                check_router_secret(&mut d, "wireguard.peers.preshared_key", k, secrets);
            }
        }
    }

    // ---- vhosts: names inside the services root's constraints get its
    // leaves; names outside need a public site (Let's Encrypt) or cert/key
    let mut vnames = BTreeSet::new();
    let mut vids = BTreeSet::new();
    let domain = &c.system.domain;
    for v in &c.vhosts {
        let fqdn = v.fqdn(domain);
        if !vids.insert(v.name.clone()) {
            d.error("E-VHOST", format!("vhost {} defined twice", v.name));
        }
        // the name is in comments of nginx.conf and acme-client.conf even with hostnames
        if !dns_name_ok(&v.name) || !dns_name_ok(&fqdn) {
            d.error("E-VHOST", format!("vhost {:?}: not a DNS name", v.name));
        }
        let (inside, outside) = v.split_names(domain);
        for n in v.names(domain) {
            if !dns_name_ok(&n) || n.starts_with("*.") {
                d.error("E-VHOST", format!("vhost {}: {n:?} is not a DNS name (no wildcards)", v.name));
            }
            if !vnames.insert(n.clone()) {
                d.error("E-VHOST", format!("{n} is served by two vhosts"));
            }
            if c.hosts.iter().any(|h| n == format!("{}.{domain}", h.name)) {
                d.error("E-VHOST", format!("vhost {}: {n} clashes with a [[hosts]] name", v.name));
            }
        }
        if !outside.is_empty() && !v.public && v.cert.is_none() {
            d.error(
                "E-VHOST",
                format!(
                    "vhost {}: {} outside {domain} need public = true (Let's Encrypt) or cert and key; the services root is constrained to {domain}",
                    v.name,
                    outside.join(", ")
                ),
            );
        }
        if v.public {
            if outside.is_empty() {
                d.error("E-VHOST", format!("vhost {}: public needs hostnames outside {domain}", v.name));
            }
            if c.wan.is_none() {
                d.warn(
                    "E-VHOST",
                    format!("vhost {}: public without a [wan]: nothing opens it to the internet", v.name),
                );
            }
        } else if !v.allow_from.is_empty() {
            d.warn("E-VHOST", format!("vhost {}: allow_from only applies to public sites", v.name));
        }
        if !inside.is_empty() && !outside.is_empty() && v.cert.is_some() {
            d.warn(
                "E-VHOST",
                format!("vhost {}: cert covers {} too, not the services leaf", v.name, inside.join(", ")),
            );
        }
        match (&v.cert, &v.key) {
            (Some(_), None) | (None, Some(_)) => {
                d.error("E-VHOST", format!("vhost {}: cert and key go together", v.name))
            }
            (Some(a), Some(b)) => {
                for p in [a, b] {
                    if !path_ok(p) {
                        d.error("E-VHOST", format!("vhost {}: {p:?} must be an absolute path", v.name));
                    }
                }
            }
            _ => {}
        }
        for a in &v.allow_from {
            if a == "cloudflare" {
                continue;
            }
            match r.endpoint(a) {
                Ok(Endpoint::Addr(_) | Endpoint::Table(_)) => {}
                Ok(_) => d.error(
                    "E-VHOST",
                    format!("vhost {}: allow_from {a:?}: cloudflare, a table, an address or a prefix", v.name),
                ),
                Err(e) => d.error("E-VHOST", format!("vhost {}: allow_from: {e}", v.name)),
            }
        }
        match v.upstream.split_once("://") {
            Some(("http" | "https", rest))
                if !rest.is_empty()
                    && rest
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')) =>
            {
                if v.upstream.starts_with("http://") && v.upstream_ca.is_some() {
                    d.warn("E-VHOST", format!("vhost {fqdn}: upstream_ca is ignored for an http upstream"));
                }
            }
            _ => d.error("E-VHOST", format!("vhost {fqdn}: upstream must be http://host:port or https://host:port")),
        }
        if let Some(ca) = &v.upstream_ca
            && !path_ok(ca)
        {
            d.error("E-VHOST", format!("vhost {fqdn}: upstream_ca must be an absolute path"));
        }
        if let Some(n) = &v.upstream_name
            && !dns_name_ok(n)
        {
            d.error("E-VHOST", format!("vhost {fqdn}: upstream_name {n:?} is not a DNS name"));
        }
        let host = v.upstream.split_once("://").map(|x| x.1).unwrap_or("").rsplit_once(':').map(|x| x.0).unwrap_or("");
        if v.upstream.starts_with("https://")
            && v.verify_upstream
            && v.upstream_name.is_none()
            && host.parse::<std::net::IpAddr>().is_ok()
        {
            d.error("E-VHOST", format!("vhost {fqdn}: nginx can't verify an address; set upstream_name to the name in the upstream's certificate"));
        }
        if v.upstream.starts_with("https://") && !v.verify_upstream {
            d.warn("E-VHOST", format!("vhost {fqdn}: the upstream's certificate is not checked"));
        }
        // INV-1: a site that proxies the router's own sshd or web UI hands
        // them to whoever reaches the site
        let port: Option<u16> =
            v.upstream.split_once("://").and_then(|x| x.1.rsplit_once(':')).and_then(|x| x.1.parse().ok());
        let router_host = host.trim_matches(['[', ']']) == "localhost"
            || host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|ip| {
                ip.is_loopback()
                    || r.nets
                        .iter()
                        .any(|n| IpAddr::V4(n.addr) == ip || n.v6.is_some_and(|x| IpAddr::V6(x.ula.addr()) == ip))
                    || c.wireguard.as_ref().is_some_and(|w| IpAddr::V4(w.address.addr()) == ip)
            });
        if router_host && port.is_some_and(|p| p == ssh || web == Some(p)) {
            if v.public {
                d.error("INV-1", format!("vhost {fqdn}: a public site in front of the router's own ssh or web UI"));
            } else {
                d.warn(
                    "INV-1",
                    format!(
                        "vhost {fqdn}: proxies the router's own ssh or web UI to every tier that reaches the vhosts"
                    ),
                );
            }
        }
    }
    // pf can't see the name: one public site's sources are every public site's
    let lists: BTreeSet<Vec<String>> = c.vhosts.iter().filter(|v| v.public).map(|v| v.allow_from.clone()).collect();
    if lists.len() > 1 {
        d.warn(
            "E-VHOST",
            "public vhosts have different allow_from lists: pf lets in the union of them for every public site (a site open to all opens the others to all)",
        );
    }
    // split horizon answers public names with the router's address, which
    // guests and servers can't reach
    if c.vhosts.iter().any(|v| v.public)
        && r.nets.iter().any(|n| matches!(n.kind, Kind::Guest | Kind::Servers) || r.is_guest(&n.name))
    {
        d.warn(
            "E-VHOST",
            "public vhosts: inside, their names point at the router, which guests and servers can't reach; they don't get the public sites",
        );
    }

    // ---- Wi-Fi: SSIDs onto router networks, access points by their [[hosts]]
    if let Some(w) = &c.wifi {
        if w.country(&c.system.timezone).is_none() {
            d.error(
                "E-WIFI",
                format!(
                    "wifi: set country (two capital letters, e.g. CZ): it decides channels and power, and the time zone {} doesn't say",
                    c.system.timezone
                ),
            );
        } else if !w.country.is_empty() && (w.country.len() != 2 || !w.country.bytes().all(|b| b.is_ascii_uppercase()))
        {
            d.error("E-WIFI", format!("wifi.country {:?}: two capital letters, e.g. CZ", w.country));
        }
        let mut ssids = BTreeSet::new();
        for n in &w.networks {
            let what = format!("wifi network {:?}", n.ssid);
            if n.ssid.is_empty() || n.ssid.len() > 32 || n.ssid.chars().any(char::is_control) {
                d.error("E-WIFI", format!("{what}: 1 to 32 bytes, no control characters"));
            }
            if !ssids.insert(&n.ssid) {
                d.error("E-WIFI", format!("{what} defined twice"));
            }
            match r.net(&n.network) {
                None => d.error(
                    "E-WIFI",
                    format!(
                        "{what}: network {:?} is not one of the router's networks ({}); a new address range is a new network (settings, networks)",
                        n.network,
                        c.networks.iter().map(|x| x.name.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                ),
                Some((_, net)) if net.kind == Kind::Servers => {
                    d.warn("E-WIFI", format!("{what}: Wi-Fi into servers network {}", n.network))
                }
                _ => {}
            }
            match (&n.password, n.security) {
                (Some(_), WifiSecurity::Open) => d.warn("E-WIFI", format!("{what}: open, the password is not used")),
                (None, WifiSecurity::Open) => {}
                (None, _) => d.error("E-WIFI", format!("{what}: needs password = \"secret:wifi_...\"")),
                (Some(p), _) => {
                    check_secret_ref(&mut d, &what, p, secrets);
                    // the web UI sets wifi_* secrets and the access points get
                    // them: nothing else may travel that way
                    if secrets::key_of(p).is_some_and(|k| !k.starts_with("wifi_")) {
                        d.error("INV-8", format!("{what}: a Wi-Fi password is a secret:wifi_... key"));
                    }
                }
            }
            if n.bands.is_empty() {
                d.error("E-WIFI", format!("{what}: no bands"));
            }
            for a in &n.aps {
                if !w.aps.iter().any(|x| &x.name == a) {
                    d.error("E-WIFI", format!("{what}: unknown access point {a}"));
                }
            }
        }
        let mut names = BTreeSet::new();
        for ap in &w.aps {
            let what = format!("access point {}", ap.name);
            if !ident_ok(&ap.name, 31) || !names.insert(&ap.name) {
                d.error("E-WIFI", format!("{what}: a unique name of a-z, 0-9, _"));
            }
            // the radio refuses a channel of the other band, and the push would still say ok
            let ok_2g = |c: u16| (1..=14).contains(&c);
            let ok_5g = |c: u16| {
                ((36..=64).contains(&c) || (100..=144).contains(&c)) && c.is_multiple_of(4)
                    || (149..=177).contains(&c) && c % 4 == 1
            };
            for (band, ch, ok) in
                [("channel_2g", &ap.channel_2g, &ok_2g as &dyn Fn(u16) -> bool), ("channel_5g", &ap.channel_5g, &ok_5g)]
            {
                let valid = ch == "auto" || (ch.bytes().all(|b| b.is_ascii_digit()) && ch.parse::<u16>().is_ok_and(ok));
                if !valid {
                    d.error("E-WIFI", format!("{what}: {band} {ch:?} is auto or a channel of that band"));
                }
            }
            let Some(h) = c.hosts.iter().find(|h| h.name == ap.host) else {
                d.error("E-WIFI", format!("{what}: no [[hosts]] entry {} (its address)", ap.host));
                continue;
            };
            if h.mac.is_none() {
                d.warn("E-WIFI", format!("{what}: host {} has no mac, so no DHCP reservation", h.name));
            }
            let Some(home) = r.host_net(h) else { continue };
            // every SSID reaches the AP untagged (its own network) or as a VLAN
            for n in w.networks.iter().filter(|n| n.on(&ap.name)) {
                let Some((_, net)) = r.net(&n.network) else { continue };
                if net.name == home.name {
                    // untagged onto the house ports: Kea places those clients by
                    // MAC, and theirs aren't the tier's
                    let wired = c.networks.iter().any(|x| x.name == net.name && x.wired);
                    if net.src.is_some() && !wired {
                        d.error(
                            "E-WIFI",
                            format!(
                                "{what}: {:?} goes untagged into {}, which shares the house ports and places devices by MAC: its clients would land in another tier; give the SSID a VLAN tier",
                                n.ssid, net.name
                            ),
                        );
                    }
                    continue;
                }
                if net.vlan.is_none() {
                    d.error(
                        "E-WIFI",
                        format!(
                            "{what}: {:?} goes to {}, which has no vlan; the AP is in {} and reaches other networks only tagged",
                            n.ssid, net.name, home.name
                        ),
                    );
                } else if net.ports() != home.ports() {
                    d.warn(
                        "E-WIFI",
                        format!(
                            "{what}: VLAN {} ({}) is on other ports than {}: the switches must carry it to the AP",
                            net.vlan.unwrap_or(0),
                            net.name,
                            home.name
                        ),
                    );
                }
            }
        }
        if w.aps.is_empty() && !w.networks.is_empty() {
            d.warn("E-WIFI", "wifi networks but no access points: nothing broadcasts them");
        }
    }

    // ---- IPv6: prefix delegation on the WAN, one /64 slot per network
    if c.ipv6.mode == Ipv6Mode::Pd {
        if c.wan.is_none() {
            d.warn("E-V6", "ipv6 is on but there is no [wan]: only the unique local addresses will work");
        }
        if !(48..=64).contains(&c.ipv6.request) {
            d.error("E-V6", "ipv6.request must be 48..64");
        }
        let slots = 1u32 << (64 - c.ipv6.request.clamp(48, 64) as u32);
        let mut seen = BTreeMap::new();
        for n in r.nets.iter() {
            if let Some(v6) = n.v6 {
                if v6.slot as u32 >= slots {
                    d.error(
                        "E-V6",
                        format!(
                            "network {}: ipv6 slot {} doesn't fit a /{} (max {})",
                            n.name,
                            v6.slot,
                            c.ipv6.request,
                            slots - 1
                        ),
                    );
                }
                if let Some(other) = seen.insert(v6.slot, n.name.clone()) {
                    d.error("E-V6", format!("networks {other} and {} share ipv6 slot {}", n.name, v6.slot));
                }
            }
        }
        if let Some(u) = c.ipv6.ula
            && (u.prefix_len() != 48 || u.addr().segments()[0] & 0xfe00 != 0xfc00)
        {
            d.error("E-V6", "ipv6.ula must be an fc00::/7 /48");
        }
    }

    // ---- DNS views: clients picked by IPv4 source, never a fallback
    let mut vnames = BTreeSet::new();
    for v in &c.dns.views {
        if !ident_ok(&v.name, 20) || v.name == "default" {
            d.error("E-DNS", format!("dns view {:?}: use a-z, 0-9, _ (not \"default\")", v.name));
        }
        if !vnames.insert(&v.name) {
            d.error("E-DNS", format!("dns view {} defined twice", v.name));
        }
        if v.upstreams.is_empty() {
            d.error("E-DNS", format!("dns view {}: no upstreams", v.name));
        }
        for u in &v.upstreams {
            if !dns_name_ok(&u.tls_name) {
                d.error("E-DNS", format!("dns view {}: upstream {}: bad tls_name", v.name, u.ip));
            }
        }
        for cl in &v.clients {
            if let Err(e) = r.endpoint(cl) {
                d.error("E-DNS", format!("dns view {}: client {e}", v.name));
            }
        }
    }
    // overrides: zones of their own, so no clashes with our other zones
    let mut onames = BTreeSet::new();
    for o in &c.dns.overrides {
        let n = o.name.trim_end_matches('.').to_ascii_lowercase();
        if !dns_name_ok(&n) || !n.contains('.') {
            d.error("E-DNS", format!("override {:?}: a fully qualified name", o.name));
        }
        if n == c.system.domain || n.ends_with(&format!(".{}", c.system.domain)) {
            d.error("E-DNS", format!("override {n}: names in the internal zone are [[hosts]]"));
        }
        if !onames.insert(n.clone()) {
            d.error("E-DNS", format!("override {n} listed twice"));
        }
        if let IpAddr::V4(a) = o.ip
            && r.net_of(a).is_none()
            && !a.is_unspecified()
            && !a.is_loopback()
        {
            d.warn("E-DNS", format!("override {n}: {a} is not on an internal network"));
        }
    }
    if let Some(s) = c.dns.sinkhole {
        if c.dns.engine != DnsEngine::OctopusDns {
            d.error("E-DNS", "dns.sinkhole needs engine = \"octopus-dns\"");
        }
        if r.net_of(s).is_none() {
            d.warn("E-DNS", format!("dns.sinkhole {s} is not on an internal network"));
        }
    }
    if !c.dns.views.is_empty() && c.dns.engine != DnsEngine::OctopusDns {
        d.error("E-DNS", "dns.views need engine = \"octopus-dns\"");
    }
    if !c.dns.views.is_empty() && c.ipv6.mode == Ipv6Mode::Pd {
        d.warn(
            "E-DNS",
            "dns.views tell clients apart by address: one asking from its delegated (global) IPv6 address gets the default view; keep views for relaxing, not restricting",
        );
    }

    // ---- proxy (phase 5): servers only; the interception root stays there (INV-5)
    if let Some(p) = &c.proxy {
        for a in &p.allow {
            match r.net(&a.network) {
                None => d.error("E-PROXY", format!("proxy.allow: unknown network {}", a.network)),
                Some((_, n)) if n.kind != Kind::Servers => d.error(
                    "INV-5",
                    format!(
                        "proxy.allow: {} is not a servers network; personal networks are never intercepted",
                        n.name
                    ),
                ),
                _ => {}
            }
            for h in &a.hosts {
                let bare = h.strip_prefix("*.").unwrap_or(h);
                if !dns_name_ok(bare) || bare.contains('*') {
                    d.error("E-PROXY", format!("proxy.allow: {h:?} is not a host name or *.domain"));
                }
                // anyone can have a name below these: a wildcard there lets a
                // server send anything to anyone, over verified TLS
                let shared = bare.trim_end_matches('.').to_ascii_lowercase();
                if h.starts_with("*.")
                    && SHARED_SUFFIXES.iter().any(|s| shared == *s || shared.ends_with(&format!(".{s}")))
                {
                    d.warn(
                        "E-PROXY",
                        format!("proxy.allow: {h} lets anyone's sites below {bare} in (a server can send data to its own); list the exact names"),
                    );
                }
            }
        }
    }
    if c.proxy.is_none() && r.nets.iter().any(|n| n.kind == Kind::Servers) {
        d.warn("INV-3", "servers networks have no [proxy]: their web traffic is blocked (only [[links]] pass)");
    }

    // ---- analyzer (phase 6)
    let mut anames = BTreeSet::new();
    for a in &c.analyzer.rules {
        if !ident_ok(&a.name, 31) || !anames.insert(&a.name) {
            d.error("E-ANALYZER", format!("analyzer rule {:?}: a unique name of a-z, 0-9, _", a.name));
        }
        if a.network == "wan" {
            if c.wan.is_none() {
                d.error("E-ANALYZER", format!("analyzer rule {}: there is no [wan]", a.name));
            }
        } else if r.net(&a.network).is_none() {
            d.error("E-ANALYZER", format!("analyzer rule {}: unknown network {}", a.name, a.network));
        }
        if let Err(e) = crate::fcap::to_pcap(&a.fcap) {
            d.error("E-ANALYZER", format!("analyzer rule {}: fcap: {e}", a.name));
        }
        if a.regex.as_ref().is_some_and(|x| x.is_empty() || x.len() > 1000) {
            d.error("E-ANALYZER", format!("analyzer rule {}: regex must be 1..1000 characters", a.name));
        }
        if a.action == AnalyzerAction::Block && (a.block_for == 0 || a.block_for > 7 * 86400) {
            d.error("E-ANALYZER", format!("analyzer rule {}: block_for must be 1..604800 seconds", a.name));
        }
        if a.action == AnalyzerAction::Block
            && let Some((_, n)) = r.net(&a.network)
            && r.manages_router(n)
        {
            d.warn(
                "E-ANALYZER",
                format!(
                    "analyzer rule {}: {} can manage the router, so its devices are never blocked (a forged packet must not lock an admin out)",
                    a.name, n.name
                ),
            );
        }
    }

    // ---- remote syslog over TLS
    for (k, v) in [("tls_ca", &c.logging.tls_ca), ("tls_cert", &c.logging.tls_cert), ("tls_key", &c.logging.tls_key)] {
        // they become syslogd flags in rc.conf.local, which rc.subr hands to sh
        if let Some(p) = v
            && !path_ok(p)
        {
            d.error("E-LOG", format!("logging.{k}: an absolute path of a-z, A-Z, 0-9, /, ., _, -"));
        }
    }
    if c.logging.tls_cert.is_some() != c.logging.tls_key.is_some() {
        d.error("E-LOG", "logging.tls_cert and tls_key go together");
    }
    let tls = c.logging.remote.iter().any(|r| r.starts_with("tls://"));
    if !tls && (c.logging.tls_ca.is_some() || c.logging.tls_cert.is_some()) {
        d.warn("E-LOG", "logging.tls_* are set but no remote is tls://");
    }

    // ---- INV-1: someone must be able to manage the router
    if r.mgmt_addrs().is_empty() {
        d.error("INV-1", "no mgmt network or mgmt WireGuard peer: sshd would listen nowhere");
    }
    // open tiers manage the router only by a rule: someone must be able to
    let fixed = r.nets.iter().any(|n| n.kind == Kind::Mgmt)
        || c.wireguard.as_ref().is_some_and(|w| w.peers.iter().any(|p| p.policy == Kind::Mgmt));
    if !fixed && r.nets.iter().any(|n| n.kind == Kind::Open) {
        let allows = c.rules.iter().any(|rule| {
            rule.action == Action::Pass
                && rule.network != RULE_WAN
                && matches!(rule.proto, Proto::Any | Proto::Tcp | Proto::TcpUdp)
                && rule
                    .port
                    .as_ref()
                    .is_none_or(|p| p.contains(c.ssh.port) || (c.web.enabled && p.contains(c.web.port)))
                && r.endpoint(&rule.to).is_ok_and(|t| {
                    matches!(t, Endpoint::Router | Endpoint::Internal | Endpoint::Any) || r.covers_router(&t)
                })
        });
        if !allows {
            d.error(
                "INV-1",
                "no rule lets any tier reach the router's ssh or web UI: add one (allow, e.g. internal ranges to the router, tcp 22, 8443) or nobody can manage it",
            );
        }
    }
    if web == Some(ssh) {
        d.error("E-WEB", "web.port equals ssh.port");
    }

    d
}

/// A secret the router itself uses: never a wifi_* one (those the web UI
/// writes and the access points receive).
fn check_router_secret(d: &mut Diagnostics, what: &str, s: &str, secrets: Option<&Secrets>) {
    check_secret_ref(d, what, s, secrets);
    if secrets::key_of(s).is_some_and(|k| k.starts_with("wifi_")) {
        d.error("INV-8", format!("{what}: wifi_* secrets are for Wi-Fi passwords only"));
    }
}

fn check_secret_ref(d: &mut Diagnostics, what: &str, s: &str, secrets: Option<&Secrets>) {
    match secrets::key_of(s) {
        None => d.error("INV-8", format!("{what}: must be a secret:<key> reference, not a literal")),
        Some(k) => {
            if let Some(sec) = secrets
                && !sec.contains(k)
            {
                d.error("E-SECRET", format!("{what}: secret {k:?} is missing from secrets.toml"));
            }
        }
    }
}

/// All `secret:` references in the config, for `octopus secrets --check`.
pub fn secret_refs(c: &Config) -> Vec<String> {
    let mut v = vec![];
    if let Some(p) = c.wan.as_ref().and_then(|w| w.pppoe.as_ref()) {
        v.push(p.user.clone());
        v.push(p.password.clone());
    }
    if let Some(wg) = &c.wireguard {
        v.push(wg.private_key.clone());
        v.extend(wg.peers.iter().filter_map(|p| p.preshared_key.clone()));
    }
    v
}

/// IPv4 addresses the router answers on in each network.
pub fn router_ips(r: &Router) -> Vec<IpAddr> {
    r.nets.iter().map(|n| IpAddr::V4(n.addr)).collect()
}

pub fn is_private(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || IpNet::V4("100.64.0.0/10".parse().unwrap()).contains(&IpAddr::V4(ip))
}
