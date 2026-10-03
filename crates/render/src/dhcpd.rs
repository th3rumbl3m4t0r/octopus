//! /etc/kea/kea-dhcp4.conf (Kea, the DHCP server pfSense uses too): one
//! subnet per tier with a `dhcp` block, reservations from [[hosts]] with a
//! MAC. The tiers untagged on the house ports share one interface: a Kea
//! shared network whose pools are chosen by client class, the tiers' `macs`
//! (full MACs or prefixes), and the `wired` tier for every other MAC.

use octopus_config::Router;
use octopus_config::ifmap::normalize_mac;
use octopus_config::model::Net;
use octopus_config::schema::{Dhcp, Network};
use serde_json::{Value, json};

use crate::{Generation, Subsystem};

pub const KEA_CONF: &str = "/etc/kea/kea-dhcp4.conf";
pub const LEASES: &str = "/var/lib/kea/kea-leases4.csv";

/// A tier's client class: its MACs and prefixes.
fn class_name(n: &str) -> String {
    format!("tier_{n}")
}

/// Kea's test for a list of MACs and prefixes: `substring(pkt4.mac,0,3) == 0xbc2411 or ...`.
fn mac_test(macs: &[String]) -> String {
    macs.iter()
        .map(|m| {
            let hex: String = m.split(':').collect::<Vec<_>>().concat().to_ascii_lowercase();
            format!("substring(pkt4.mac,0,{}) == 0x{hex}", hex.len() / 2)
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

fn served(r: &Router) -> Vec<(&Net, &Network, &Dhcp)> {
    r.nets
        .iter()
        .filter_map(|n| {
            let t = r.cfg.networks.iter().find(|x| x.name == n.name)?;
            Some((n, t, t.dhcp.as_ref()?))
        })
        .collect()
}

/// Subnet ids stay put when tiers are reordered: the network address.
fn subnet_id(n: &Net) -> u32 {
    u32::from(n.prefix.network())
}

fn subnet(r: &Router, n: &Net, t: &Network, d: &Dhcp, class: Option<String>) -> Value {
    let c = &r.cfg;
    let mut pools: Vec<Value> = d.all_ranges().iter().map(|[a, b]| json!({"pool": format!("{a} - {b}")})).collect();
    if let Some(cl) = &class {
        for p in &mut pools {
            p["client-class"] = json!(cl);
        }
    }
    let reservations: Vec<Value> = c
        .hosts
        .iter()
        .filter(|h| r.host_net(h).is_some_and(|x| x.name == n.name))
        .filter_map(|h| {
            let mac = normalize_mac(h.mac.as_deref()?)?;
            Some(json!({"hw-address": mac, "ip-address": h.ip.to_string(), "hostname": h.name}))
        })
        .collect();
    let mut options = vec![
        json!({"name": "routers", "data": n.addr.to_string()}),
        json!({"name": "domain-name-servers", "data": n.addr.to_string()}),
        json!({"name": "domain-name", "data": c.system.domain}),
    ];
    if c.ntp.serve {
        options.push(json!({"name": "ntp-servers", "data": n.addr.to_string()}));
    }
    json!({
        "id": subnet_id(n),
        "subnet": n.prefix.to_string(),
        "comment": t.description.clone().unwrap_or_else(|| t.name.clone()),
        "valid-lifetime": d.lease_time,
        "max-valid-lifetime": d.max_lease_time,
        "pools": pools,
        "option-data": options,
        "reservations": reservations,
    })
}

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let served = served(r);
    if served.is_empty() {
        return;
    }
    let mut classes = vec![];
    let mut alone = vec![];
    let mut shared: Vec<(String, Vec<Value>)> = vec![];
    // per interface: one tier is a subnet; several are a shared network
    let mut ifs: Vec<&str> = served.iter().map(|x| x.0.ifname.as_str()).collect();
    ifs.dedup();
    for i in &ifs {
        let here: Vec<_> = served.iter().filter(|x| x.0.ifname == *i).collect();
        if here.len() == 1 {
            let (n, t, d) = here[0];
            let mut s = subnet(r, n, t, d, None);
            s["interface"] = json!(i);
            alone.push(s);
            continue;
        }
        let listed: Vec<String> = here.iter().filter(|x| !x.1.macs.is_empty()).map(|x| class_name(&x.1.name)).collect();
        let mut subnets = vec![];
        for (n, t, d) in &here {
            let class = if !t.macs.is_empty() {
                classes.push(json!({"name": class_name(&t.name), "test": mac_test(&t.macs)}));
                Some(class_name(&t.name))
            } else if t.wired {
                let name = format!("tier_{}_others", t.name);
                let test = if listed.is_empty() {
                    "true".to_string()
                } else {
                    listed.iter().map(|l| format!("not member('{l}')")).collect::<Vec<_>>().join(" and ")
                };
                classes.push(json!({"name": name, "test": test}));
                Some(name)
            } else {
                // neither listed MACs nor the fallback: reservations only
                if !classes.iter().any(|c| c["name"] == "reservations_only") {
                    classes.push(json!({"name": "reservations_only", "test": "false"}));
                }
                Some("reservations_only".to_string())
            };
            subnets.push(subnet(r, n, t, d, class));
        }
        shared.push((i.to_string(), subnets));
    }
    let shared_networks: Vec<Value> =
        shared.into_iter().map(|(i, subnets)| json!({"name": i, "interface": i, "subnet4": subnets})).collect();
    // the classes that test "member()" come after the ones they name
    classes.sort_by_key(|c| c["test"].as_str().is_some_and(|t| t.contains("member(")));
    let conf = json!({
        "Dhcp4": {
            "interfaces-config": {"interfaces": ifs, "dhcp-socket-type": "raw"},
            "lease-database": {"type": "memfile", "persist": true, "name": LEASES, "lfc-interval": 3600},
            "client-classes": classes,
            "shared-networks": shared_networks,
            "subnet4": alone,
            "loggers": [{"name": "kea-dhcp4", "output_options": [{"output": "syslog"}], "severity": "INFO"}],
        }
    });
    let s = format!(
        "// generated by octopus from router.toml; edit that, not this file\n{}\n",
        serde_json::to_string_pretty(&conf).unwrap_or_default()
    );
    g.file(KEA_CONF, s, Subsystem::Dhcpd);
}

/// Whether anything is served (the service runs).
pub(crate) fn serving(r: &Router) -> bool {
    !served(r).is_empty()
}
