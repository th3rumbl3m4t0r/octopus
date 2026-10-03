//! Structured edits of router.toml from the UI: generic ones at a path (the
//! settings page and most lists, see tree.rs), firewall rules (firewall.rs),
//! and the DNS page's view clients and sinkhole. toml_edit keeps the owner's
//! comments and layout. The result is only ever text: it goes through the
//! same check -> diff -> apply (commit-confirm) as a hand edit.

use serde::Deserialize;
use serde_json::{Value, json};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

use crate::firewall::FwRule;
use crate::tree::{self, Seg};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    ViewClientAdd {
        view: String,
        client: String,
    },
    ViewClientRemove {
        view: String,
        client: String,
    },
    OverrideAdd {
        name: String,
        ip: String,
        subdomains: bool,
    },
    OverrideRemove {
        name: String,
    },
    SinkholeSet {
        ip: String,
    },
    /// `path = value` (null removes)
    Set {
        path: Vec<Seg>,
        value: Value,
    },
    /// a new item at the end of the list at `path`
    Append {
        path: Vec<Seg>,
        value: Value,
    },
    Move {
        path: Vec<Seg>,
        from: usize,
        to: usize,
    },
    /// a firewall rule; `at` is the entry it replaces (list, index)
    Firewall {
        rule: FwRule,
        #[serde(default)]
        at: Option<(String, usize)>,
    },
    /// several edits as one change
    Batch {
        edits: Vec<Edit>,
    },
}

fn table_mut<'a>(doc: &'a mut DocumentMut, key: &str) -> Result<&'a mut Table, String> {
    if !doc.contains_key(key) {
        doc[key] = Item::Table(Table::new());
    }
    doc[key].as_table_mut().ok_or_else(|| format!("[{key}] is not a table"))
}

fn aot<'a>(t: &'a mut Table, key: &str) -> Result<&'a mut ArrayOfTables, String> {
    if !t.contains_key(key) {
        t.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    t[key].as_array_of_tables_mut().ok_or_else(|| format!("{key} must be written as [[...]] tables to edit it here"))
}

fn upstream(ip: &str, name: &str) -> toml_edit::InlineTable {
    let mut t = toml_edit::InlineTable::new();
    t.insert("ip", ip.into());
    t.insert("tls_name", name.into());
    t
}

fn clean(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 || s.contains(['"', '\\', '\n', '\r']) {
        return Err(format!("{s:?}: not a name or address"));
    }
    Ok(s.to_string())
}

pub fn apply(text: &str, e: &Edit) -> Result<String, String> {
    if let Edit::Batch { edits } = e {
        let mut t = text.to_string();
        for x in edits {
            t = apply(&t, x)?;
        }
        return Ok(t);
    }
    let mut doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| e.to_string())?;
    match e {
        Edit::Batch { .. } => unreachable!(),
        Edit::Set { path, value } => tree::set(&mut doc, path, value)?,
        Edit::Append { path, value } => tree::append(&mut doc, path, value)?,
        Edit::Move { path, from, to } => tree::move_item(&mut doc, path, *from, *to)?,
        Edit::Firewall { rule, at } => {
            let cfg = octopus_config::parse(text)?;
            let replacing = at.as_ref().filter(|(l, _)| l == "forwards").map(|(_, i)| *i);
            let (list, item) = crate::firewall::entry(&cfg, rule, replacing)?;
            match at {
                Some((l, i)) if l == list => tree::set(&mut doc, &[Seg::Key(l.clone()), Seg::Index(*i)], &item)?,
                Some((l, i)) => {
                    if !matches!(l.as_str(), "rules" | "forwards" | "links") {
                        return Err(format!("{l} is not a firewall list"));
                    }
                    tree::set(&mut doc, &[Seg::Key(l.clone()), Seg::Index(*i)], &Value::Null)?;
                    tree::append(&mut doc, &[Seg::Key(list.into())], &item)?;
                }
                None => tree::append(&mut doc, &[Seg::Key(list.into())], &item)?,
            }
        }
        Edit::ViewClientAdd { view, client } | Edit::ViewClientRemove { view, client } => {
            let client = clean(client)?;
            let dns = table_mut(&mut doc, "dns")?;
            let views = aot(dns, "views")?;
            let idx = views.iter().position(|t| t.get("name").and_then(|n| n.as_str()) == Some(view.as_str()));
            let t = match idx {
                Some(i) => views.get_mut(i).unwrap(),
                None if view == "unfiltered" && matches!(e, Edit::ViewClientAdd { .. }) => {
                    // the plain resolver, as the owner's setup has it
                    let mut t = Table::new();
                    t["name"] = value("unfiltered");
                    t["description"] = value("plain 1.1.1.1 for these hosts");
                    let mut ups = Array::new();
                    ups.push(upstream("1.1.1.1", "cloudflare-dns.com"));
                    ups.push(upstream("1.0.0.1", "cloudflare-dns.com"));
                    t["upstreams"] = value(ups);
                    t["clients"] = value(Array::new());
                    views.push(t);
                    views.get_mut(views.len() - 1).unwrap()
                }
                None => return Err(format!("no dns view {view:?}")),
            };
            if !t.contains_key("clients") {
                t["clients"] = value(Array::new());
            }
            let arr = t["clients"].as_array_mut().ok_or("clients is not a list")?;
            let has = arr.iter().position(|v| v.as_str() == Some(client.as_str()));
            match (e, has) {
                (Edit::ViewClientAdd { .. }, None) => arr.push(client),
                (Edit::ViewClientAdd { .. }, Some(_)) => return Err(format!("{client} is already in {view}")),
                (_, Some(i)) => {
                    arr.remove(i);
                }
                (_, None) => return Err(format!("{client} is not in {view}")),
            }
            arr.fmt();
        }
        Edit::OverrideAdd { name, ip, subdomains } => {
            let name = clean(name)?.trim_end_matches('.').to_ascii_lowercase();
            let ip: std::net::IpAddr = ip.trim().parse().map_err(|_| format!("{ip:?} is not an address"))?;
            let dns = table_mut(&mut doc, "dns")?;
            let o = aot(dns, "overrides")?;
            if o.iter().any(|t| t.get("name").and_then(|n| n.as_str()) == Some(name.as_str())) {
                return Err(format!("{name} is already overridden"));
            }
            let mut t = Table::new();
            t["name"] = value(name);
            t["ip"] = value(ip.to_string());
            t["subdomains"] = value(*subdomains);
            o.push(t);
        }
        Edit::OverrideRemove { name } => {
            let dns = table_mut(&mut doc, "dns")?;
            let o = aot(dns, "overrides")?;
            let i = o
                .iter()
                .position(|t| t.get("name").and_then(|n| n.as_str()) == Some(name.as_str()))
                .ok_or(format!("{name} is not overridden"))?;
            o.remove(i);
        }
        Edit::SinkholeSet { ip } => {
            let dns = table_mut(&mut doc, "dns")?;
            if ip.trim().is_empty() {
                dns.remove("sinkhole");
            } else {
                let a: std::net::Ipv4Addr = ip.trim().parse().map_err(|_| format!("{ip:?} is not an IPv4 address"))?;
                dns["sinkhole"] = value(a.to_string());
            }
        }
    }
    Ok(doc.to_string())
}

/// What the UI shows about a config text: DNS setup, hosts, networks, rules.
pub fn summary(text: &str) -> Value {
    let Ok(c) = octopus_config::parse(text) else { return json!(null) };
    let ups = |u: &[octopus_config::schema::Upstream]| {
        u.iter().map(|x| json!({"ip": x.ip.to_string(), "tls_name": x.tls_name})).collect::<Vec<_>>()
    };
    json!({
        "dns": {
            "engine": c.dns.engine,
            "upstreams": ups(&c.dns.upstreams),
            "views": c.dns.views.iter().map(|v| json!({"name": v.name, "upstreams": ups(&v.upstreams), "clients": v.clients, "description": v.description})).collect::<Vec<_>>(),
            "overrides": c.dns.overrides.iter().map(|o| json!({"name": o.name, "ip": o.ip.to_string(), "subdomains": o.subdomains})).collect::<Vec<_>>(),
            "sinkhole": c.dns.sinkhole.map(|s| s.to_string()),
        },
        "hosts": c.hosts.iter().map(|h| json!({"name": h.name, "ip": h.ip.to_string(), "network": h.network})).collect::<Vec<_>>(),
        "networks": c.networks.iter().map(|n| json!({"name": n.name, "address": n.address.to_string(), "kind": n.kind.to_string()})).collect::<Vec<_>>(),
        "wan": c.wan.is_some(),
        // the Wi-Fi regulatory domain: set, or the time zone's (null: unknown)
        "wifi_country": c.wifi.as_ref().map_or_else(
            || octopus_config::schema::zone_country(&c.system.timezone).map(str::to_string),
            |w| w.country(&c.system.timezone),
        ),
        "wifi_country_set": c.wifi.as_ref().is_some_and(|w| !w.country.is_empty()),
        "timezone": c.system.timezone,
        "analyzer": c.analyzer.rules.iter().map(|a| json!({"name": a.name, "network": a.network, "fcap": a.fcap, "regex": a.regex, "action": a.action})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "# my router\n[system]\nhostname = \"r\" # keep me\n\n[dns]\nengine = \"octopus-dns\"\n";

    #[test]
    fn edits_keep_comments() {
        let a = apply(T, &Edit::ViewClientAdd { view: "unfiltered".into(), client: "192.168.1.11".into() }).unwrap();
        assert!(a.contains("# keep me") && a.contains("[[dns.views]]") && a.contains("\"192.168.1.11\""));
        let b =
            apply(&a, &Edit::ViewClientRemove { view: "unfiltered".into(), client: "192.168.1.11".into() }).unwrap();
        assert!(!b.contains("\"192.168.1.11\""));
        let c = apply(
            &b,
            &Edit::OverrideAdd { name: "Evil.EXAMPLE.".into(), ip: "192.168.1.250".into(), subdomains: true },
        )
        .unwrap();
        assert!(c.contains("[[dns.overrides]]") && c.contains("name = \"evil.example\""));
        assert!(
            apply(&c, &Edit::OverrideAdd { name: "evil.example".into(), ip: "192.168.1.250".into(), subdomains: true })
                .is_err()
        );
        let d = apply(&c, &Edit::SinkholeSet { ip: "192.168.1.250".into() }).unwrap();
        assert!(d.contains("sinkhole = \"192.168.1.250\""));
        assert!(apply(&d, &Edit::SinkholeSet { ip: "nope".into() }).is_err());
        assert!(apply(&d, &Edit::ViewClientAdd { view: "x".into(), client: "a\"b".into() }).is_err());
        let doc: toml::Table = toml::from_str(&d).unwrap();
        let dns: octopus_config::schema::Dns = doc["dns"].clone().try_into().unwrap();
        assert_eq!(dns.overrides.len(), 1);
        assert_eq!(dns.views[0].upstreams[0].ip.to_string(), "1.1.1.1");
    }
}
