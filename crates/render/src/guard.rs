//! /etc/octopus/guard.json for `octopus guard`: the tiers whose addresses
//! only listed devices may use (those with `macs`, sharing the house ports
//! with others). A device on such an address that isn't listed (its MAC,
//! a prefix of it, or a reservation of that address) is cut off from the
//! router by a bridge rule on the router's port.

use octopus_config::Router;
use octopus_config::ifmap::normalize_mac;
use serde_json::json;

use crate::{Generation, Service, Subsystem};

pub const GUARD_CONF: &str = "/etc/octopus/guard.json";

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let mut ports = vec![];
    for n in r.nets.iter().filter(|n| n.src.is_some()) {
        let Some(t) = r.cfg.networks.iter().find(|x| x.name == n.name) else { continue };
        if t.macs.is_empty() {
            continue;
        }
        let reserved: serde_json::Map<String, serde_json::Value> = r
            .cfg
            .hosts
            .iter()
            .filter(|h| n.prefix.contains(&h.ip))
            .filter_map(|h| Some((h.ip.to_string(), json!(normalize_mac(h.mac.as_deref()?)?))))
            .collect();
        ports.push(json!({
            "veb": n.bridge, "vport": n.ifname, "tier": n.name, "prefix": n.prefix.to_string(),
            "router": n.addr.to_string(),
            "macs": t.macs.iter().map(|m| m.to_ascii_lowercase()).collect::<Vec<_>>(),
            "reserved": reserved,
        }));
    }
    g.services.push(Service {
        name: "octopus_guard".into(),
        enabled: !ports.is_empty(),
        flags: None,
        subsystem: Subsystem::Net,
        restart: true,
    });
    if ports.is_empty() {
        return;
    }
    let s = serde_json::to_string_pretty(&json!({"restricted": ports})).unwrap_or_default() + "\n";
    g.file(GUARD_CONF, s, Subsystem::Net);
}
