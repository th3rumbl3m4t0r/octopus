//! The firewall page's rule (source, destination, allow / deny / nat) as
//! the router.toml entry it is: a `[[rules]]` entry on the network the
//! source is in (`all` for internal ranges, `wan` for a deny from outside),
//! a `[[forwards]]` entry for nat (the port forward is also what allows the
//! traffic), or a `[[links]]` entry for a servers network's way out (INV-3).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use octopus_config::Config;
use octopus_config::schema::{Kind, Ports};
use serde::Deserialize;
use serde_json::{Map, Value as Json, json};

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct FwRule {
    /// allow, deny or nat
    #[serde(rename = "type")]
    pub kind: String,
    /// endpoints as router.toml writes them: internet, internal, self,
    /// net:NAME, host:NAME, table:NAME, an address or a prefix
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub port: String,
    /// nat: the inside port, when it differs
    #[serde(default)]
    pub to_port: Option<u16>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub log: bool,
    /// nat: internal clients using the public address get forwarded too
    #[serde(default)]
    pub reflect: bool,
}

#[derive(Debug, PartialEq, Clone)]
enum Side {
    Outside,
    /// a network, or None for several
    Inside(Option<String>),
    Router,
}

fn nets(c: &Config) -> Vec<(String, ipnet::Ipv4Net, Kind)> {
    c.networks.iter().map(|n| (n.name.clone(), n.address.trunc(), n.kind)).collect()
}

fn side_of_net(c: &Config, a: &IpNet) -> Side {
    let IpNet::V4(a) = a else { return Side::Outside };
    match nets(c).into_iter().find(|(_, p, _)| p.contains(a)) {
        Some((n, _, _)) => Side::Inside(Some(n)),
        None if nets(c).iter().any(|(_, p, _)| a.contains(p)) => Side::Inside(None),
        None => Side::Outside,
    }
}

/// Where an endpoint is, and whether it stands for its whole network.
fn side(c: &Config, tok: &str) -> Result<(Side, bool), String> {
    let tok = tok.trim();
    match tok {
        "internet" => return Ok((Side::Outside, false)),
        "internal" => return Ok((Side::Inside(None), true)),
        "self" => return Ok((Side::Router, false)),
        "any" | "" => return Err("pick internal ranges or the internet, not anything".into()),
        _ => {}
    }
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return Ok((side_of_net(c, &IpNet::from(ip)), false));
    }
    if let Ok(n) = tok.parse::<IpNet>() {
        return Ok((side_of_net(c, &n.trunc()), false));
    }
    let (ns, name) = match tok.split_once(':') {
        Some((ns @ ("net" | "host" | "table"), name)) => (Some(ns), name),
        _ => (None, tok),
    };
    if ns.is_none_or(|n| n == "net") && c.networks.iter().any(|n| n.name == name) {
        return Ok((Side::Inside(Some(name.to_string())), true));
    }
    if ns.is_none_or(|n| n == "host")
        && let Some(h) = c.hosts.iter().find(|h| h.name == name)
    {
        return Ok((
            match &h.network {
                Some(n) => Side::Inside(Some(n.clone())),
                None => side_of_net(c, &IpNet::from(IpAddr::V4(h.ip))),
            },
            false,
        ));
    }
    if ns.is_none_or(|n| n == "table")
        && let Some(t) = c.tables.iter().find(|t| t.name == name)
    {
        let sides: Vec<Side> = t.entries.iter().map(|e| side_of_net(c, e)).collect();
        if sides.iter().all(|s| *s == Side::Outside) {
            return Ok((Side::Outside, false));
        }
        if sides.contains(&Side::Outside) {
            return Err(format!("table {name} has inside and outside addresses: split it"));
        }
        let first = &sides[0];
        return Ok((if sides.iter().all(|s| s == first) { first.clone() } else { Side::Inside(None) }, false));
    }
    Err(format!("{tok:?}: not internet, internal, self, a network, host, table, address or prefix"))
}

fn host_ip(c: &Config, tok: &str) -> Option<Ipv4Addr> {
    let name = tok.strip_prefix("host:").unwrap_or(tok);
    c.hosts.iter().find(|h| h.name == name).map(|h| h.ip).or_else(|| tok.parse().ok())
}

fn port_json(p: &str) -> Result<Option<Json>, String> {
    let p = p.trim();
    if p.is_empty() {
        return Ok(None);
    }
    let ports: Ports = p.parse()?;
    Ok(Some(match ports.0.as_slice() {
        [(a, b)] if a == b => json!(a),
        _ => json!(ports.to_string()),
    }))
}

fn slug(s: &str) -> String {
    let mut out: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .split('_')
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    out.truncate(24);
    out
}

/// The list and the entry for a rule. `replacing` is the forward being
/// edited (its name may stay).
pub fn entry(c: &Config, f: &FwRule, replacing: Option<usize>) -> Result<(&'static str, Json), String> {
    let (src, src_whole) = side(c, &f.source)?;
    let dst_tok = f.destination.trim();
    let (dst, _) = if dst_tok == "any" { (Side::Outside, false) } else { side(c, dst_tok)? };
    let proto = match f.proto.trim() {
        "" => "any",
        p @ ("any" | "tcp" | "udp" | "tcp/udp" | "icmp" | "gre" | "esp") => p,
        p => return Err(format!("protocol {p:?}: any, tcp, udp, tcp/udp, icmp, gre or esp")),
    };
    let port = port_json(&f.port)?;
    let mut o = Map::new();
    let desc = f.description.trim();

    match f.kind.as_str() {
        "nat" => {
            if src != Side::Outside {
                return Err("nat opens a port on the WAN address: the source is the internet (or outside addresses); traffic from inside is NATed out by itself".into());
            }
            let Some(to) = host_ip(c, dst_tok) else {
                return Err("nat goes to one inside host: pick a host or type its address".into());
            };
            if !matches!(dst, Side::Inside(Some(_))) {
                return Err(format!("{to} is not on an internal network"));
            }
            let port = port.ok_or("nat needs the port(s) opened on the WAN address")?;
            let proto = if proto == "any" { "tcp" } else { proto };
            if !matches!(proto, "tcp" | "udp" | "tcp/udp") {
                return Err("nat needs tcp, udp or tcp/udp".into());
            }
            let base = if desc.is_empty() { slug(&format!("{proto}_{}", f.port)) } else { slug(desc) };
            let mut name = base.clone();
            let taken = |n: &str| c.forwards.iter().enumerate().any(|(i, x)| x.name == n && Some(i) != replacing);
            let mut k = 2;
            while taken(&name) {
                name = format!("{base}_{k}");
                k += 1;
            }
            o.insert("name".into(), json!(name));
            o.insert("proto".into(), json!(proto));
            o.insert("port".into(), port);
            if f.source.trim() != "internet" {
                o.insert("from".into(), json!(f.source.trim()));
            }
            o.insert("to".into(), json!(to.to_string()));
            if let Some(p) = f.to_port {
                o.insert("to_port".into(), json!(p));
            }
            if f.reflect {
                o.insert("reflect".into(), json!(true));
            }
            if f.log {
                o.insert("log".into(), json!(true));
            }
            Ok(("forwards", Json::Object(o)))
        }
        "allow" | "deny" => {
            let allow = f.kind == "allow";
            // tiers: a source address is the same source address everywhere,
            // so rules from inside hold on every tier
            let tiers = c.lan.is_some();
            let network = match &src {
                Side::Router => return Err("the router's own traffic out is not filtered".into()),
                Side::Outside if allow => {
                    return Err("from the internet only nat opens a way in (a port on the WAN address to an inside host): choose nat".into());
                }
                Side::Outside => "wan".to_string(),
                Side::Inside(None) => "all".to_string(),
                Side::Inside(Some(n))
                    if tiers && !c.networks.iter().any(|x| &x.name == n && x.kind == Kind::Servers) =>
                {
                    "all".to_string()
                }
                Side::Inside(Some(n)) => n.clone(),
            };
            let servers = c.networks.iter().any(|n| n.name == network && n.kind == Kind::Servers);
            if allow && servers && dst == Side::Outside {
                // a servers network's only way out (INV-3)
                o.insert("network".into(), json!(network));
                o.insert("to".into(), json!(dst_tok));
                o.insert("proto".into(), json!(proto));
                if let Some(p) = port {
                    o.insert("port".into(), p);
                }
                if !desc.is_empty() {
                    o.insert("description".into(), json!(desc));
                }
                return Ok(("links", Json::Object(o)));
            }
            o.insert("network".into(), json!(network));
            o.insert("action".into(), json!(if allow { "pass" } else { "block" }));
            let from = f.source.trim();
            // `from` goes without saying for the network's own whole range
            let implied = (network == "wan" && from == "internet")
                || (network == "all" && from == "internal")
                || (network != "all" && network != "wan" && src_whole);
            if !implied {
                o.insert("from".into(), json!(from));
            }
            if dst_tok != "any" {
                o.insert("to".into(), json!(dst_tok));
            }
            if proto != "any" {
                o.insert("proto".into(), json!(proto));
            }
            if let Some(p) = port {
                o.insert("port".into(), p);
            }
            if f.log {
                o.insert("log".into(), json!(true));
            }
            if !desc.is_empty() {
                o.insert("description".into(), json!(desc));
            }
            Ok(("rules", Json::Object(o)))
        }
        k => Err(format!("type {k:?}: allow, deny or nat")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = r#"
[system]
hostname = "r"
domain = "home.arpa"
openbsd_release = "7.9"
[interfaces.w]
mac = "00:00:00:00:00:01"
name = "em0"
[interfaces.l]
mac = "00:00:00:00:00:02"
name = "em1"
[interfaces.s]
mac = "00:00:00:00:00:03"
name = "em2"
[wan]
interface = "w"
dhcp = true
[interfaces.m]
mac = "00:00:00:00:00:04"
name = "em3"
[[networks]]
name = "mgmt"
interface = "m"
address = "192.168.9.1/24"
kind = "mgmt"
[[networks]]
name = "lan"
interface = "l"
address = "10.0.0.1/24"
kind = "lan"
[[networks]]
name = "servers"
interface = "s"
address = "10.0.1.1/24"
kind = "servers"
[[hosts]]
name = "nas"
network = "servers"
ip = "10.0.1.5"
[[tables]]
name = "office"
entries = ["203.0.113.0/24"]
"#;

    fn rule(kind: &str, s: &str, d: &str, proto: &str, port: &str) -> FwRule {
        FwRule {
            kind: kind.into(),
            source: s.into(),
            destination: d.into(),
            proto: proto.into(),
            port: port.into(),
            to_port: None,
            description: String::new(),
            log: false,
            reflect: false,
        }
    }

    #[test]
    fn maps_to_rules_forwards_and_links() {
        let c = octopus_config::parse(C).unwrap();
        let e = |r: FwRule| entry(&c, &r, None);
        assert_eq!(
            e(rule("deny", "net:lan", "host:nas", "tcp", "22")).unwrap(),
            ("rules", json!({"network": "lan", "action": "block", "to": "host:nas", "proto": "tcp", "port": 22}))
        );
        assert_eq!(
            e(rule("allow", "internal", "internet", "udp", "123")).unwrap(),
            ("rules", json!({"network": "all", "action": "pass", "to": "internet", "proto": "udp", "port": 123}))
        );
        assert_eq!(e(rule("allow", "10.0.0.7", "host:nas", "tcp", "443")).unwrap().1["from"], json!("10.0.0.7"));
        let (l, f) = e(rule("nat", "internet", "host:nas", "", "8443")).unwrap();
        assert_eq!((l, f), ("forwards", json!({"name": "tcp_8443", "proto": "tcp", "port": 8443, "to": "10.0.1.5"})));
        assert_eq!(e(rule("nat", "table:office", "10.0.1.5", "tcp", "22")).unwrap().1["from"], json!("table:office"));
        assert_eq!(e(rule("allow", "net:servers", "table:office", "tcp", "22")).unwrap().0, "links");
        assert_eq!(e(rule("deny", "table:office", "host:nas", "", "")).unwrap().1["network"], json!("wan"));
        assert!(e(rule("allow", "internet", "host:nas", "tcp", "22")).unwrap_err().contains("nat"));
        assert!(e(rule("nat", "net:lan", "host:nas", "tcp", "22")).is_err());
        assert!(e(rule("nat", "internet", "internal", "tcp", "22")).is_err());
        assert!(e(rule("allow", "net:lan", "internet", "tcp", "banana")).is_err());
        // tiers: a source is the same everywhere, rules hold on every tier
        let tiers = octopus_config::parse(&C.replace(
            "[[networks]]\nname = \"lan\"\ninterface = \"l\"",
            "[lan]\nports = [\"l\"]\n\n[[networks]]\nname = \"lan\"",
        ))
        .unwrap();
        assert_eq!(
            entry(&tiers, &rule("deny", "net:lan", "internet", "tcp", "25"), None).unwrap(),
            (
                "rules",
                json!({"network": "all", "action": "block", "from": "net:lan", "to": "internet", "proto": "tcp", "port": 25})
            )
        );
        assert_eq!(
            entry(&tiers, &rule("allow", "internal", "host:nas", "", ""), None).unwrap().1["network"],
            json!("all")
        );
        // each mapped entry is a valid router.toml entry
        for (list, item) in [
            e(rule("deny", "net:lan", "host:nas", "tcp", "22")).unwrap(),
            e(rule("nat", "internet", "host:nas", "", "8000-8010")).unwrap(),
            e(rule("allow", "net:servers", "table:office", "tcp", "22")).unwrap(),
        ] {
            let mut doc: toml_edit::DocumentMut = C.parse().unwrap();
            crate::tree::append(&mut doc, &[crate::tree::Seg::Key(list.into())], &item).unwrap();
            let cfg = octopus_config::parse(&doc.to_string()).unwrap();
            let r = octopus_config::Router::resolve(cfg, &Default::default());
            let r = r.map_err(|d| d.0.iter().map(|x| x.msg.clone()).collect::<Vec<_>>()).unwrap();
            let d = octopus_config::check::check(&r, None);
            assert!(!d.has_errors(), "{list} {item}: {d}");
        }
    }
}
