//! pfSense config.xml -> router.toml + secrets.toml + a report.
//!
//! The import is meant to be faithful where the design allows it and loud
//! where it doesn't: every rule that is dropped, changed or can't be carried
//! over gets a line in the report, and the result passes `octopus check`.
//!
//! Semantics: pfSense interface rules are first-match (quick) with an
//! implicit deny at the end. Octopus explicit rules are first-match too, but
//! are followed by the network's kind policy, so a network whose pfSense
//! rules don't end in "pass everything" gets an explicit final block.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use ipnet::{IpNet, Ipv4Net};
use octopus_config::Secrets;
use roxmltree::{Document, Node};

mod redact;
pub use redact::redact;

pub struct Import {
    pub router_toml: String,
    pub secrets: Secrets,
    pub report: Vec<String>,
}

type N<'a> = Node<'a, 'a>;

fn child<'a>(n: N<'a>, name: &str) -> Option<N<'a>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

fn children<'a>(n: N<'a>, name: &'a str) -> impl Iterator<Item = N<'a>> + 'a {
    n.children().filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn at<'a>(n: N<'a>, path: &str) -> Option<N<'a>> {
    path.split('/').try_fold(n, |n, p| child(n, p))
}

fn text(n: N, path: &str) -> Option<String> {
    let t = at(n, path)?.text()?.trim().to_string();
    (!t.is_empty()).then_some(t)
}

fn has(n: N, path: &str) -> bool {
    at(n, path).is_some()
}

/// pfSense names -> Octopus identifiers: lowercase, a-z0-9_, starts with a letter.
fn ident(s: &str, max: usize) -> String {
    let mut o: String =
        s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if !o.starts_with(|c: char| c.is_ascii_lowercase()) {
        o.insert(0, 'n');
    }
    o.truncate(max);
    o.trim_end_matches('_').to_string()
}

fn q(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn b64decode(s: &str) -> Option<String> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = vec![];
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&x| x == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    String::from_utf8(out).ok()
}

struct Iface {
    key: String,
    ifname: String,
    descr: String,
    addr: Option<Ipv4Net>,
    enabled: bool,
}

struct NetOut {
    key: String,
    name: String,
    role: String,
    addr: Ipv4Net,
    kind: &'static str,
    descr: String,
    dhcp: Option<(Ipv4Addr, Ipv4Addr, u32, u32)>,
}

struct RuleOut {
    network: String,
    action: &'static str,
    from: String,
    to: String,
    proto: Option<String>,
    port: Option<String>,
    log: bool,
    descr: String,
}

/// Import with interface MACs (ifname -> MAC) taken from the pfSense box.
pub fn import_with(xml: &str, macs: &BTreeMap<String, String>) -> Result<Import, String> {
    let doc = Document::parse(xml).map_err(|e| format!("config.xml: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "pfsense" {
        return Err("not a pfSense config.xml".into());
    }
    let mut rep: Vec<String> = vec![];
    let mut secrets = Secrets::default();
    let mut out = String::new();
    let sys = child(root, "system").ok_or("no <system>")?;
    let note = |rep: &mut Vec<String>, sev: &str, msg: String| rep.push(format!("- **{sev}** {msg}"));

    rep.push(format!(
        "# pfSense import report\n\nSource: config.xml (schema {}) of {}.{}, revision {}.\n",
        text(root, "version").unwrap_or_default(),
        text(sys, "hostname").unwrap_or_default(),
        text(sys, "domain").unwrap_or_default(),
        text(root, "revision/time").unwrap_or_default()
    ));
    rep.push("Severity: **drop** = not carried over, **change** = behaves differently, **todo** = owner decision or later phase, **info**.\n".into());

    // ---- interfaces
    let mut ifaces: Vec<Iface> = vec![];
    if let Some(ifs) = child(root, "interfaces") {
        for i in ifs.children().filter(|c| c.is_element()) {
            let addr = match (text(i, "ipaddr"), text(i, "subnet")) {
                (Some(a), Some(s)) => format!("{a}/{s}").parse::<Ipv4Net>().ok(),
                _ => None,
            };
            ifaces.push(Iface {
                key: i.tag_name().name().to_string(),
                ifname: text(i, "if").unwrap_or_default(),
                descr: text(i, "descr").unwrap_or_else(|| i.tag_name().name().to_uppercase()),
                addr,
                enabled: has(i, "enable"),
            });
        }
    }
    let vlans: Vec<(String, String, u16, Option<u8>)> = child(root, "vlans")
        .map(|v| {
            children(v, "vlan")
                .filter_map(|x| {
                    Some((
                        text(x, "vlanif")?,
                        text(x, "if")?,
                        text(x, "tag")?.parse().ok()?,
                        text(x, "pcp").and_then(|p| p.parse().ok()),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut roles: BTreeMap<String, String> = BTreeMap::new(); // physical ifname -> role
    let mut nets: Vec<NetOut> = vec![];
    let mut dhcp_notes = vec![];
    for i in &ifaces {
        let Some(addr) = i.addr else { continue };
        if !i.enabled {
            note(&mut rep, "drop", format!("interface {} ({}) is disabled in pfSense", i.descr, i.ifname));
            continue;
        }
        if i.ifname.contains('.') || i.ifname.starts_with("ppp") {
            note(&mut rep, "drop", format!("interface {} on {}: only untagged ports are imported", i.descr, i.ifname));
            continue;
        }
        let name = ident(&i.descr, 15);
        roles.insert(i.ifname.clone(), name.clone());
        let kind = if i.key == "lan" { "mgmt" } else { "lan" };
        // DHCP
        let dhcp = root
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().name() == i.key
                    && n.parent_element().is_some_and(|p| p.tag_name().name() == "dhcpd")
            })
            .filter(|d| has(*d, "enable"))
            .and_then(|d| {
                let mut a: Ipv4Addr = text(d, "range/from")?.parse().ok()?;
                let mut b: Ipv4Addr = text(d, "range/to")?.parse().ok()?;
                let (oa, ob) = (a, b);
                let r = addr.addr();
                let net = addr.trunc();
                if a <= net.network() {
                    a = Ipv4Addr::from(u32::from(net.network()) + 1);
                }
                if b >= net.broadcast() {
                    b = Ipv4Addr::from(u32::from(net.broadcast()) - 1);
                }
                if a <= r && r <= b {
                    if r == a {
                        a = Ipv4Addr::from(u32::from(r) + 1);
                    } else if r == b {
                        b = Ipv4Addr::from(u32::from(r) - 1);
                    } else {
                        a = Ipv4Addr::from(u32::from(r) + 1);
                    }
                }
                if (a, b) != (oa, ob) {
                    dhcp_notes.push(format!(
                        "DHCP range on {} was {oa}-{ob}; it contained the router or the network address, now {a}-{b}",
                        i.descr
                    ));
                }
                let lease = text(d, "defaultleasetime").and_then(|x| x.parse().ok()).unwrap_or(7200);
                let max = text(d, "maxleasetime").and_then(|x| x.parse().ok()).unwrap_or(86400);
                Some((a, b, lease, max.max(lease)))
            });
        nets.push(NetOut {
            key: i.key.clone(),
            name: name.clone(),
            role: name,
            addr,
            kind,
            descr: i.descr.clone(),
            dhcp,
        });
    }
    for d in dhcp_notes {
        note(&mut rep, "change", d);
    }
    if let Some(n) = nets.iter().find(|n| n.kind == "mgmt") {
        note(
            &mut rep,
            "change",
            format!(
                "{} (pfSense's LAN, where the anti-lockout rule applies) becomes the **mgmt** network: the only one where sshd and the web UI listen. The other networks lose SSH/web access to the router (INV-1).",
                n.name
            ),
        );
    }

    // ---- WAN
    let wan_if = ifaces.iter().find(|i| i.key == "wan");
    let mut wan_toml = String::new();
    if let Some(w) = wan_if {
        let ppp =
            child(root, "ppps").and_then(|p| children(p, "ppp").find(|x| text(*x, "if").as_deref() == Some(&w.ifname)));
        let mtu: u16 = text(*child(root, "interfaces").and_then(|i| child(i, "wan")).as_ref().unwrap(), "mtu")
            .and_then(|m| m.parse().ok())
            .unwrap_or(1500);
        let carrier = ppp.and_then(|p| text(p, "ports")).unwrap_or_else(|| w.ifname.clone());
        let (phys, vlan, prio) = match vlans.iter().find(|v| v.0 == carrier) {
            Some((_, parent, tag, pcp)) => (parent.clone(), Some(*tag), *pcp),
            None => (carrier.clone(), None, None),
        };
        roles.insert(phys.clone(), "wan".into());
        let _ = writeln!(wan_toml, "[wan]\ninterface = \"wan\"");
        if let Some(v) = vlan {
            let _ = writeln!(wan_toml, "vlan = {v}");
        }
        if let Some(p) = prio {
            let _ = writeln!(wan_toml, "vlan_prio = {p}\t# 802.1p priority, as in pfSense");
        }
        match ppp.map(|p| text(p, "type").unwrap_or_default()) {
            Some(t) if t == "pppoe" => {
                let p = ppp.unwrap();
                if let Some(u) = text(p, "username") {
                    secrets.insert("pppoe_user", u);
                }
                // pfSense stores the PPP password base64-encoded
                if let Some(pw) = text(p, "password").and_then(|x| b64decode(&x)) {
                    secrets.insert("pppoe_pass", pw);
                }
                let _ =
                    writeln!(wan_toml, "pppoe = {{ user = \"secret:pppoe_user\", password = \"secret:pppoe_pass\" }}");
                let unused: Vec<String> = children(child(root, "ppps").unwrap(), "ppp")
                    .filter(|x| {
                        text(*x, "type").as_deref() == Some("pppoe") && text(*x, "if").as_deref() != Some(&w.ifname)
                    })
                    .filter_map(|x| text(x, "if"))
                    .collect();
                if !unused.is_empty() {
                    note(
                        &mut rep,
                        "drop",
                        format!("unused PPPoE definitions {} (only {} is the WAN)", unused.join(", "), w.ifname),
                    );
                }
            }
            _ if w.addr.is_some() => {
                let a = w.addr.unwrap();
                let gw = child(root, "gateways")
                    .and_then(|g| children(g, "gateway_item").find(|x| text(*x, "interface").as_deref() == Some("wan")))
                    .and_then(|x| text(x, "gateway"))
                    .unwrap_or_default();
                let _ = writeln!(wan_toml, "static = {{ address = {}, gateway = {} }}", q(&a.to_string()), q(&gw));
            }
            _ => {
                let _ = writeln!(wan_toml, "dhcp = true");
            }
        }
        let _ = writeln!(wan_toml, "mtu = {mtu}\nmss = {}", mtu - 40);
    }

    // backup links etc.
    for i in &ifaces {
        if i.ifname.starts_with("ppp") && !i.ifname.starts_with("pppoe") {
            let ppp = child(root, "ppps")
                .and_then(|p| children(p, "ppp").find(|x| text(*x, "if").as_deref() == Some(&i.ifname)));
            let port = ppp.and_then(|p| text(p, "ports")).unwrap_or_default();
            note(
                &mut rep,
                "todo",
                format!(
                    "{} ({} on {port}, APN {}) is a serial modem link; Octopus has no failover WAN yet. Not imported.",
                    i.descr,
                    i.ifname,
                    ppp.and_then(|p| text(p, "apn")).unwrap_or_default()
                ),
            );
        }
    }

    // ---- tables
    let mut tables: Vec<(String, Vec<String>, Vec<String>)> = vec![];
    let mut alias_names: BTreeMap<String, String> = BTreeMap::new();
    if let Some(al) = child(root, "aliases") {
        for a in children(al, "alias") {
            let name = text(a, "name").unwrap_or_default();
            let t = text(a, "type").unwrap_or_default();
            if t != "network" && t != "host" {
                note(&mut rep, "drop", format!("alias {name} of type {t}: only host/network aliases become tables"));
                continue;
            }
            let entries: Vec<String> =
                text(a, "address").unwrap_or_default().split_whitespace().map(str::to_string).collect();
            let details: Vec<String> = text(a, "detail").unwrap_or_default().split("||").map(str::to_string).collect();
            let mut good = vec![];
            let mut comments = vec![];
            let mut seen = std::collections::BTreeSet::new();
            for (k, e) in entries.iter().enumerate() {
                match e.parse::<IpNet>().or_else(|_| e.parse::<std::net::IpAddr>().map(IpNet::from)) {
                    Ok(n) => {
                        if !seen.insert(n.trunc()) {
                            note(&mut rep, "info", format!("alias {name}: duplicate entry {e} dropped"));
                            continue;
                        }
                        if n != n.trunc() {
                            note(
                                &mut rep,
                                "change",
                                format!("alias {name}: {e} has host bits set; using {}", n.trunc()),
                            );
                        }
                        good.push(n.trunc().to_string());
                        comments.push(details.get(k).cloned().unwrap_or_default());
                    }
                    Err(_) => note(
                        &mut rep,
                        "drop",
                        format!("alias {name}: entry {e} is not an address (hostnames aren't resolved)"),
                    ),
                }
            }
            let id = ident(&name, 28);
            alias_names.insert(name.clone(), id.clone());
            tables.push((id, good, comments));
        }
    }

    let net_of_key = |k: &str| nets.iter().find(|n| n.key == k);

    // endpoint of a <source>/<destination>
    let endpoint = |n: Option<N>| -> Result<String, String> {
        let Some(n) = n else { return Ok("any".into()) };
        if has(n, "not") {
            return Err("negated address".into());
        }
        if has(n, "any") {
            return Ok("any".into());
        }
        if let Some(net) = text(n, "network") {
            if net == "(self)" || net.ends_with("ip") {
                return Ok("self".into());
            }
            if let Some(x) = net_of_key(&net) {
                return Ok(format!("net:{}", x.name));
            }
            return Err(format!("network {net}"));
        }
        if let Some(a) = text(n, "address") {
            if let Some(t) = alias_names.get(&a) {
                return Ok(format!("table:{t}"));
            }
            if a.parse::<IpNet>().is_ok() || a.parse::<std::net::IpAddr>().is_ok() {
                return Ok(a);
            }
            return Err(format!("address {a}"));
        }
        Ok("any".into())
    };
    let port_of = |n: Option<N>| {
        n.and_then(|n| text(n, "port")).map(|p| {
            // "3283-3283" -> "3283"
            match p.split_once('-') {
                Some((a, b)) if a == b => a.to_string(),
                _ => p,
            }
        })
    };
    let proto_of = |r: N| -> Option<String> {
        match text(r, "protocol").as_deref() {
            None | Some("any") => None,
            Some(p @ ("tcp" | "udp" | "tcp/udp" | "icmp" | "gre" | "esp")) => Some(p.to_string()),
            Some(other) => Some(format!("?{other}")),
        }
    };

    // ---- forwards
    let mut fwd_toml = String::new();
    let mut fwd_targets: Vec<(Ipv4Addr, String)> = vec![];
    let reflect_default = text(sys, "enablenatreflectionpurenat").as_deref() == Some("yes");
    if let Some(nat) = child(root, "nat") {
        for (k, r) in children(nat, "rule").enumerate() {
            let descr = text(r, "descr").unwrap_or_default();
            if has(r, "disabled") {
                note(&mut rep, "drop", format!("port forward {} is disabled", k + 1));
                continue;
            }
            if text(r, "interface").as_deref() != Some("wan")
                || text(r, "destination/network").as_deref() != Some("wanip")
            {
                note(
                    &mut rep,
                    "drop",
                    format!("port forward {} ({descr}): only WAN-address forwards are imported", k + 1),
                );
                continue;
            }
            let Some(target) = text(r, "target").and_then(|t| t.parse::<Ipv4Addr>().ok()) else {
                note(&mut rep, "drop", format!("port forward {}: target is not an address", k + 1));
                continue;
            };
            let from = match endpoint(child(r, "source")) {
                Ok(f) => f.trim_start_matches("table:").to_string(),
                Err(e) => {
                    note(&mut rep, "drop", format!("port forward {}: source {e} not supported", k + 1));
                    continue;
                }
            };
            let port = port_of(child(r, "destination")).unwrap_or_default();
            let local = text(r, "local-port").unwrap_or_else(|| port.clone());
            let proto = text(r, "protocol").unwrap_or_else(|| "tcp".into());
            let mut reflect = match text(r, "natreflection").as_deref() {
                Some("disable") => false,
                Some(_) => true,
                None => reflect_default,
            };
            if reflect && from != "any" {
                // pfSense applied the source restriction to reflection too, so
                // internal clients never matched
                let label = if descr.is_empty() {
                    format!("port forward {}", k + 1)
                } else {
                    format!("port forward {} ({descr})", k + 1)
                };
                note(
                    &mut rep,
                    "info",
                    format!(
                        "{label}: NAT reflection not imported, its source restriction ({from}) never matches internal clients"
                    ),
                );
                reflect = false;
            }
            let base = if descr.is_empty() { format!("{}-{port}", target.octets()[3]) } else { descr.clone() };
            let name = format!("{}_{}", ident(&base, 20), port.replace(['-', ':'], "_"));
            let _ = writeln!(fwd_toml, "\n[[forwards]]\nname = {}", q(&name));
            let _ = writeln!(fwd_toml, "proto = {}\nport = {}", q(&proto), port_value(&port));
            let _ = writeln!(fwd_toml, "from = {}\nto = {}", q(&from), q(&target.to_string()));
            if local != port {
                let _ = writeln!(fwd_toml, "to_port = {local}");
            }
            if reflect {
                let _ = writeln!(fwd_toml, "reflect = true");
            }
            if from == "any" {
                note(&mut rep, "info", format!("forward {name}: open to the whole internet"));
            }
            fwd_targets.push((target, port.clone()));
        }
    }

    // ---- filter rules
    let mut rules: Vec<RuleOut> = vec![];
    let mut per_net: BTreeMap<String, Vec<RuleOut>> = BTreeMap::new();
    let mut dropped_disabled = 0;
    if let Some(f) = child(root, "filter") {
        for (k, r) in children(f, "rule").enumerate() {
            let n = k + 1;
            let descr = text(r, "descr").unwrap_or_default();
            let what = if descr.is_empty() { format!("rule {n}") } else { format!("rule {n} ({descr})") };
            if has(r, "disabled") {
                dropped_disabled += 1;
                continue;
            }
            let iface = text(r, "interface").unwrap_or_default();
            let typ = text(r, "type").unwrap_or_else(|| "pass".into());
            if has(r, "floating") {
                if typ == "match" {
                    continue; // traffic shaper wizard queue assignment; summarised below
                }
                note(
                    &mut rep,
                    "drop",
                    format!(
                        "floating {what} on {iface}: `{}`; floating rules aren't imported (Octopus passes outbound traffic and filters where it enters)",
                        summary(r)
                    ),
                );
                continue;
            }
            if text(r, "ipprotocol").as_deref() == Some("inet6") {
                let sev = if iface == "wan" { "drop (security)" } else { "drop" };
                note(
                    &mut rep,
                    sev,
                    format!(
                        "{what} on {iface}: IPv6 rule `{}`; IPv6 is off in Octopus (blocked completely)",
                        summary(r)
                    ),
                );
                continue;
            }
            if iface == "wan" {
                if has(r, "associated-rule-id") && text(r, "associated-rule-id").is_some_and(|x| x.starts_with("nat_"))
                {
                    continue; // the forward's own pass rule
                }
                let dst = text(r, "destination/address").and_then(|a| a.parse::<Ipv4Addr>().ok());
                let dport = port_of(child(r, "destination"));
                if typ == "pass"
                    && dst.is_some_and(|d| fwd_targets.iter().any(|(t, p)| *t == d && Some(p) == dport.as_ref()))
                {
                    note(
                        &mut rep,
                        "info",
                        format!(
                            "WAN {what}: pass to {} port {}; covered by the forward to that host (the forward keeps its source restriction)",
                            dst.unwrap(),
                            dport.unwrap_or_default()
                        ),
                    );
                    continue;
                }
                if typ != "pass" {
                    continue; // blocks are the default
                }
                note(
                    &mut rep,
                    "drop (security)",
                    format!("WAN {what}: `{}` opens an inbound path that isn't a declared forward (INV-2)", summary(r)),
                );
                continue;
            }
            let Some(net) = net_of_key(&iface) else {
                note(&mut rep, "drop", format!("{what}: interface {iface} isn't imported"));
                continue;
            };
            let action = match typ.as_str() {
                "pass" => "pass",
                "block" => "block",
                "reject" => "reject",
                other => {
                    note(&mut rep, "drop", format!("{what}: rule type {other}"));
                    continue;
                }
            };
            let (from, to) = match (endpoint(child(r, "source")), endpoint(child(r, "destination"))) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => {
                    note(&mut rep, "drop", format!("{what}: {e} is not supported"));
                    continue;
                }
            };
            // a source that can't arrive on this interface (urpf drops it anyway)
            let src_ok = match from.as_str() {
                "any" => true,
                "self" => false,
                f if f.starts_with("net:") => f == format!("net:{}", net.name),
                f if f.starts_with("table:") => false,
                f => f
                    .parse::<IpNet>()
                    .map(|n| contains(&net.addr.trunc(), &n))
                    .or_else(|_| f.parse::<Ipv4Addr>().map(|a| net.addr.trunc().contains(&a)))
                    .unwrap_or(false),
            };
            if !src_ok {
                note(
                    &mut rep,
                    "drop",
                    format!("{what} on {}: source {from} can never enter through this network", net.name),
                );
                continue;
            }
            let from = if from == format!("net:{}", net.name) { "any".to_string() } else { from };
            let proto = proto_of(r);
            if proto.as_deref().is_some_and(|p| p.starts_with('?')) {
                note(&mut rep, "drop", format!("{what}: protocol {}", proto.unwrap()));
                continue;
            }
            let port = port_of(child(r, "destination"));
            per_net.entry(net.name.clone()).or_default().push(RuleOut {
                network: net.name.clone(),
                action,
                from,
                to,
                proto,
                port,
                log: has(r, "log"),
                descr: if descr.is_empty() {
                    format!("pfSense rule {n}")
                } else {
                    format!("pfSense rule {n}: {descr}")
                },
            });
        }
    }
    if dropped_disabled > 0 {
        note(&mut rep, "info", format!("{dropped_disabled} disabled filter rule(s) skipped"));
    }

    // first-match clean-up per network, in pfSense order
    for n in &nets {
        let list = per_net.remove(&n.name).unwrap_or_default();
        let mut kept: Vec<RuleOut> = vec![];
        let mut ends_open = false;
        for r in list {
            if ends_open {
                note(
                    &mut rep,
                    "drop",
                    format!("{} on {}: shadowed by an earlier pass-everything rule", r.descr, n.name),
                );
                continue;
            }
            let pass_all =
                r.action == "pass" && r.from == "any" && r.to == "any" && r.proto.is_none() && r.port.is_none();
            if pass_all {
                ends_open = true;
                if n.kind == "mgmt" {
                    if r.log {
                        note(
                            &mut rep,
                            "change",
                            format!(
                                "{} on {}: pass everything with logging; the mgmt policy passes everything without logging",
                                r.descr, n.name
                            ),
                        );
                    }
                    continue;
                }
            }
            kept.push(r);
        }
        if !ends_open {
            note(
                &mut rep,
                "change",
                format!(
                    "{}: pfSense's rules don't end in pass-everything, so its implicit deny is kept as an explicit final block. This also blocks DNS/NTP to the router there, as in pfSense. Remove the block to give it the normal lan policy.",
                    n.name
                ),
            );
            kept.push(RuleOut {
                network: n.name.clone(),
                action: "block",
                from: "any".into(),
                to: "any".into(),
                proto: None,
                port: None,
                log: true,
                descr: "pfSense implicit default deny".into(),
            });
        }
        rules.extend(kept);
    }

    // ---- DNS
    let mut upstreams = vec![];
    let servers: Vec<String> =
        children(sys, "dnsserver").filter_map(|n| n.text().map(|t| t.trim().to_string())).collect();
    for (k, s) in servers.iter().enumerate() {
        let host = text(sys, &format!("dns{}host", k + 1));
        match host {
            Some(h) => upstreams.push((s.clone(), h)),
            None => note(
                &mut rep,
                "drop",
                format!("DNS server {s} has no TLS hostname in pfSense; Octopus only forwards over validated DoT"),
            ),
        }
    }
    let unbound = child(root, "unbound");
    if let Some(u) = unbound {
        if !has(u, "forward_tls_upstream") {
            note(&mut rep, "change", "pfSense forwarded DNS in plaintext; Octopus uses DNS-over-TLS only".into());
        }
        if text(u, "custom_options").is_some() {
            note(&mut rep, "todo", "unbound custom options (query/reply logging) aren't carried over; per-query logging is octopus-dns (phase B)".into());
        }
    }
    let providers: std::collections::BTreeSet<&str> = upstreams
        .iter()
        .map(|(_, h)| if h.contains("cloudflare") || h.contains("one.one") { "cloudflare" } else { h.as_str() })
        .collect();
    if providers.len() < 2 {
        note(
            &mut rep,
            "todo",
            "all DNS upstreams are one provider; the design asks for two (e.g. add Quad9 9.9.9.9 / dns.quad9.net)"
                .into(),
        );
    }
    let domain = text(sys, "domain").unwrap_or_else(|| "home.arpa".into());
    let mut records = vec![];
    let mut overrides = vec![];
    if let Some(u) = unbound {
        for h in children(u, "hosts") {
            let (Some(host), Some(dom), Some(ip)) = (text(h, "host"), text(h, "domain"), text(h, "ip")) else {
                continue;
            };
            let fqdn = format!("{host}.{dom}");
            if dom == domain {
                overrides.push((host, ip, text(h, "descr")));
            } else {
                records.push((fqdn, ip));
            }
        }
    }

    // ---- assemble router.toml
    let hostname = ident(&text(sys, "hostname").unwrap_or_else(|| "octopus".into()), 63).replace('_', "-");
    let _ = writeln!(
        out,
        "# Octopus router.toml, imported from pfSense {}.{}.",
        text(sys, "hostname").unwrap_or_default(),
        domain
    );
    out += "# Read the import report before applying. Secrets are in secrets.toml.\n\n";
    let _ = writeln!(
        out,
        "[system]\nhostname = {}\ndomain = {}\nopenbsd_release = \"7.9\"\ntimezone = {}",
        q(&hostname),
        q(&domain),
        q(&text(sys, "timezone").unwrap_or_else(|| "UTC".into()))
    );
    if let Some(m) = text(sys, "maximumtableentries") {
        let _ = writeln!(out, "max_table_entries = {m}");
    }
    out += "\n# Ports by role, bound to MAC addresses. `name` is the pfSense name, used\n# only when compiling off the router.\n";
    for (ifname, role) in &roles {
        let _ = writeln!(out, "[interfaces.{role}]");
        match macs.get(ifname) {
            Some(m) => {
                let _ = writeln!(out, "mac = {}", q(m));
            }
            None => {
                let _ = writeln!(out, "mac = \"00:00:00:00:00:00\"\t# TODO: unknown, pass --ifconfig");
                note(&mut rep, "todo", format!("MAC of {ifname} unknown; fill in [interfaces.{role}]"));
            }
        }
        let _ = writeln!(out, "name = {}\n", q(ifname));
    }
    out += &wan_toml;
    for n in &nets {
        let _ = writeln!(
            out,
            "\n[[networks]]\nname = {}\ninterface = {}\naddress = {}\nkind = \"{}\"\ndescription = {}",
            q(&n.name),
            q(&n.role),
            q(&n.addr.to_string()),
            n.kind,
            q(&format!("pfSense {} ({})", n.descr, n.key))
        );
        if let Some((a, b, l, m)) = n.dhcp {
            let _ = writeln!(out, "dhcp = {{ range = [\"{a}\", \"{b}\"], lease_time = {l}, max_lease_time = {m} }}");
        }
    }
    for (host, ip, descr) in &overrides {
        let net = ip.parse::<Ipv4Addr>().ok().and_then(|a| nets.iter().find(|n| n.addr.trunc().contains(&a)));
        match net {
            Some(n) => {
                let _ = writeln!(out, "\n[[hosts]]\nname = {}\nnetwork = {}\nip = {}", q(host), q(&n.name), q(ip));
                if let Some(d) = descr {
                    let _ = writeln!(out, "description = {}", q(d));
                }
            }
            None => note(&mut rep, "drop", format!("host override {host} -> {ip}: not on an imported network")),
        }
    }
    for (name, entries, comments) in &tables {
        let _ = writeln!(out, "\n[[tables]]\nname = {}\nentries = [", q(name));
        for (e, c) in entries.iter().zip(comments) {
            if c.is_empty() || c.starts_with("Entry added") {
                let _ = writeln!(out, "  {},", q(e));
            } else {
                let _ = writeln!(out, "  {},\t# {}", q(e), c.replace('\n', " "));
            }
        }
        out += "]\n";
    }
    out += &fwd_toml;
    for r in &rules {
        let _ = writeln!(out, "\n[[rules]]\nnetwork = {}\naction = \"{}\"", q(&r.network), r.action);
        if r.from != "any" {
            let _ = writeln!(out, "from = {}", q(&r.from));
        }
        if r.to != "any" {
            let _ = writeln!(out, "to = {}", q(&r.to));
        }
        if let Some(p) = &r.proto {
            let _ = writeln!(out, "proto = {}", q(p));
        }
        if let Some(p) = &r.port {
            let _ = writeln!(out, "port = {}", port_value(p));
        }
        if r.log {
            out += "log = true\n";
        }
        let _ = writeln!(out, "description = {}", q(&r.descr));
    }

    out += "\n[dns]\nupstreams = [\n";
    for (ip, host) in &upstreams {
        let _ = writeln!(out, "  {{ ip = {}, tls_name = {} }},", q(ip), q(host));
    }
    out += "]\n";
    if !records.is_empty() {
        out += "# split horizon: answered locally, everything else in these domains is forwarded\nrecords = [\n";
        for (f, ip) in &records {
            let _ = writeln!(out, "  {{ name = {}, ip = {} }},", q(f), q(ip));
        }
        out += "]\n";
    }

    let ntp: Vec<String> =
        text(sys, "timeservers").unwrap_or_else(|| "pool.ntp.org".into()).split_whitespace().map(q).collect();
    let serve =
        child(root, "ntpd").is_some_and(|n| text(n, "enable").as_deref() == Some("enabled") || has(n, "interface"));
    let _ = writeln!(out, "\n[ntp]\nservers = [{}]\nserve = {serve}", ntp.join(", "));

    let port = child(sys, "ssh").and_then(|s| text(s, "port")).unwrap_or_else(|| "22".into());
    let _ = writeln!(
        out,
        "\n[ssh]\nport = {port}\npassword_auth = false\t# deploy keys in deploy/authorized_keys before cutover"
    );
    note(&mut rep, "change", "SSH: key-only, root `prohibit-password`; pfSense allowed password logins for admin. Put the owner's public keys in deploy/authorized_keys.".into());

    if let Some(s) = child(root, "syslog")
        && let Some(r) = text(s, "remoteserver")
    {
        let _ = writeln!(out, "\n[logging]\nremote = [{}]\t# design asks for tls://", q(&format!("udp://{r}")));
        note(
            &mut rep,
            "todo",
            format!("remote syslog to {r} stays plaintext UDP as in pfSense; the design asks for TLS to the log VM"),
        );
    }

    // shaper summary as a commented [traffic] section
    let wan_bw = child(root, "shaper")
        .and_then(|s| children(s, "queue").find(|q| text(*q, "interface").as_deref() == Some("wan")))
        .and_then(|q| Some(format!("{}{}", text(q, "bandwidth")?, text(q, "bandwidthtype")?)));
    let lan_up = child(root, "shaper")
        .and_then(|s| children(s, "queue").find(|q| text(*q, "interface").as_deref() == Some("lan")))
        .and_then(|q| {
            children(q, "queue").find(|c| text(*c, "upperlimit3").is_some()).and_then(|c| text(c, "upperlimit3"))
        });
    if wan_bw.is_some() || lan_up.is_some() {
        out += "\n# Queues are phase 4. pfSense shaped at the values below; measure the line\n# first (design 12.4), then set roots to about 90 % of it and uncomment.\n";
        let up = wan_bw.as_deref().and_then(mbit).unwrap_or(0);
        let down = lan_up.as_deref().and_then(mbit).unwrap_or(0);
        let _ = writeln!(
            out,
            "# [traffic]\n# upload = \"{up}M\"\t# pfSense WAN root: {}\n# download = \"{down}M\"\t# pfSense LAN upper limit: {}",
            wan_bw.unwrap_or_default(),
            lan_up.unwrap_or_default()
        );
        note(&mut rep, "todo", "traffic shaper (PRIQ upload, HFSC download, wizard port rules) not imported; [traffic] is left commented with pfSense's rates".into());
    }

    // ---- what isn't imported
    let mut vhost_toml = String::new();
    if let Some(h) = at(root, "installedpackages/haproxy") {
        // each frontend becomes a commented [[vhosts]] block to review
        let ca_names: BTreeMap<String, String> =
            children(root, "ca").filter_map(|c| Some((text(c, "refid")?, text(c, "descr")?))).collect();
        let pools: Vec<N> = at(h, "ha_pools").map(|p| children(p, "item").collect()).unwrap_or_default();
        let mut blocks = String::new();
        let mut names = vec![];
        for b in at(h, "ha_backends").map(|b| children(b, "item").collect::<Vec<_>>()).unwrap_or_default() {
            let Some(name) = text(b, "name") else { continue };
            let pool = text(b, "backend_serverpool")
                .and_then(|p| pools.iter().find(|x| text(**x, "name").as_deref() == Some(&p)).copied());
            let Some(server) = pool.and_then(|p| at(p, "ha_servers")).and_then(|s| children(s, "item").next()) else {
                continue;
            };
            let (Some(addr), Some(port)) = (text(server, "address"), text(server, "port")) else { continue };
            let scheme = if text(server, "ssl").as_deref() == Some("yes") { "https" } else { "http" };
            let ca = text(server, "ssl-server-ca").and_then(|r| ca_names.get(&r).cloned());
            names.push(format!("{name} -> {scheme}://{addr}:{port}"));
            let _ = writeln!(
                blocks,
                "\n# haproxy frontend {name:?} ({}) -> {addr}:{port}",
                text(b, "descr").unwrap_or_default()
            );
            let _ = writeln!(blocks, "# [[vhosts]]\n# name = {}", q(&ident(&name, 20).replace('_', "-")));
            let _ = writeln!(blocks, "# upstream = \"{scheme}://{addr}:{port}\"");
            if scheme == "https" {
                let _ = writeln!(blocks, "# upstream_name = \"<the name in {addr}'s certificate>\"");
                match &ca {
                    Some(c) => {
                        let _ = writeln!(
                            blocks,
                            "# upstream_ca = \"/etc/octopus/pki/upstream/{}.crt\"\t# pfSense CA {c:?}: export it from pfSense",
                            ident(c, 40)
                        );
                    }
                    None => blocks.push_str("# verify_upstream = false\t# haproxy didn't check this upstream\n"),
                }
                blocks.push_str("# websocket = true\n");
            }
        }
        if !blocks.is_empty() {
            vhost_toml = format!(
                "\n# ---- haproxy (pfSense) -> nginx vhosts (phase 2). They need the services root\n\
                 # (octopus pki init) and names in {domain}; review and uncomment.\n{blocks}"
            );
        }
        note(
            &mut rep,
            "todo",
            format!(
                "haproxy frontends ({}) are written as commented [[vhosts]] at the end of router.toml: \
                 check the upstream certificates, set up the services root, uncomment",
                names.join(", ")
            ),
        );
    }
    if let Some(v) = child(root, "virtualip") {
        for vip in children(v, "vip") {
            note(
                &mut rep,
                "drop",
                format!(
                    "virtual IP {} on {} ({})",
                    text(vip, "subnet").unwrap_or_default(),
                    text(vip, "interface").unwrap_or_default(),
                    text(vip, "descr").unwrap_or_default()
                ),
            );
        }
    }
    if root.children().any(|c| c.tag_name().name() == "ca") {
        let cas: Vec<String> = children(root, "ca").filter_map(|c| text(c, "descr")).collect();
        note(
            &mut rep,
            "todo",
            format!(
                "certificate authorities ({}) and certificates aren't imported; the services root is phase 2",
                cas.join(", ")
            ),
        );
    }
    let v6 = ifaces
        .iter()
        .any(|i| child(root, "interfaces").and_then(|x| child(x, &i.key)).and_then(|x| text(x, "ipaddrv6")).is_some());
    if v6 {
        note(&mut rep, "change", "pfSense had IPv6 on some networks (track6/SLAAC). Octopus imports it as off (blocked completely) until prefix delegation is implemented; owner decision (design 21).".into());
    }

    out += &vhost_toml;
    Ok(Import { router_toml: out, secrets, report: rep })
}

pub fn import(xml: &str) -> Result<Import, String> {
    import_with(xml, &BTreeMap::new())
}

fn contains(net: &Ipv4Net, n: &IpNet) -> bool {
    match n {
        IpNet::V4(x) => net.contains(x),
        IpNet::V6(_) => false,
    }
}

/// pfSense bandwidth ("21Mb", "83886.08Kb") in whole Mbit/s.
fn mbit(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches(['b', 'B']);
    let (num, mult) = match s.chars().last()? {
        'G' => (&s[..s.len() - 1], 1000.0),
        'M' => (&s[..s.len() - 1], 1.0),
        'K' => (&s[..s.len() - 1], 0.001),
        _ => (s, 0.000_001),
    };
    num.parse::<f64>().ok().map(|n| (n * mult) as u64)
}

fn port_value(p: &str) -> String {
    match p.parse::<u16>() {
        Ok(n) => n.to_string(),
        Err(_) => q(p),
    }
}

fn summary(r: N) -> String {
    let side = |n: Option<N>| -> String {
        let Some(n) = n else { return "any".into() };
        let mut s = if has(n, "any") {
            "any".to_string()
        } else {
            text(n, "network").or_else(|| text(n, "address")).unwrap_or_else(|| "any".into())
        };
        if has(n, "not") {
            s = format!("!{s}");
        }
        if let Some(p) = text(n, "port") {
            s += &format!(" port {p}");
        }
        s
    };
    format!(
        "{} {} {} from {} to {}",
        text(r, "type").unwrap_or_else(|| "pass".into()),
        text(r, "ipprotocol").unwrap_or_default(),
        text(r, "protocol").unwrap_or_else(|| "any".into()),
        side(child(r, "source")),
        side(child(r, "destination"))
    )
}
