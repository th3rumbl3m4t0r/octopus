//! /etc/octopus/proxy.toml: the servers networks' egress proxy (design 13).
//!
//! pf diverts a servers network's outbound 443 and 80 to octopus-proxy on
//! loopback. It allows only the network's [[proxy.allow]] names (SNI and
//! Host), verifies every origin's real certificate, and presents leaves from
//! the interception root, which only servers trust. The services root never
//! appears here (INV-5).

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::schema::Kind;

use crate::{Generation, Service, Subsystem, header};

pub const CA_CERT: &str = "/etc/ssl/octopus-intercept.crt";
pub const CA_KEY: &str = "/etc/ssl/private/octopus-intercept.key";
pub const USER: &str = "_octoproxy";

/// Loopback ports of a servers network's listeners (https, http), by its
/// position among the servers networks.
pub fn ports(i: usize) -> (u16, u16) {
    (8444 + 2 * i as u16, 8081 + 2 * i as u16)
}

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;
    let servers: Vec<_> = r.nets.iter().filter(|n| n.kind == Kind::Servers).collect();
    let on = c.proxy.is_some() && !servers.is_empty();
    // relayd was the design's proxy; make sure an old install doesn't run it
    g.services.push(Service {
        name: "relayd".into(),
        enabled: false,
        flags: None,
        subsystem: Subsystem::Proxy,
        restart: false,
    });
    g.services.push(Service {
        name: "octopus_proxy".into(),
        enabled: on,
        flags: None,
        subsystem: Subsystem::Proxy,
        restart: true,
    });
    let Some(p) = &c.proxy else { return };
    if servers.is_empty() {
        return;
    }
    let mut s =
        header("#", &["octopus-proxy: servers' egress; the interception root is trusted by servers only (INV-5)"]);
    let _ = writeln!(s, "user = \"{USER}\"\nca_cert = \"{CA_CERT}\"\nca_key = \"{CA_KEY}\"");
    for (i, n) in servers.iter().enumerate() {
        let (https, http) = ports(i);
        let hosts: Vec<String> = p
            .allow
            .iter()
            .filter(|a| a.network == n.name)
            .flat_map(|a| a.hosts.iter().map(|h| format!("\"{h}\"")))
            .collect();
        let _ = writeln!(
            s,
            "\n[[listeners]]\nname = \"{}\"\nhttps = \"127.0.0.1:{https}\"\nhttp = \"127.0.0.1:{http}\"\nallow = [{}]",
            n.name,
            hosts.join(", ")
        );
    }
    g.file("/etc/octopus/proxy.toml", s, Subsystem::Proxy);
}
