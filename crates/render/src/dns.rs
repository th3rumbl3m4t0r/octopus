//! DNS: hickory-dns configuration (phase A) and the zone files.
//!
//! Zones: the internal zone (router, networks, hosts), reverse zones for
//! every /24 the networks cover, one-name zones for split-horizon records,
//! and an empty `use-application-dns.net` zone. That answers NODATA, which
//! turns off Firefox's built-in DoH just like NXDOMAIN would (INV-4).
//! Everything else is forwarded over DNS-over-TLS.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use octopus_config::Router;
use octopus_config::schema::{DnsEngine, Kind};
use sha2::{Digest, Sha256};

use crate::{Generation, Subsystem, header};

pub const DNS_DIR: &str = "/etc/octopus/dns";
pub const ZONE_DIR: &str = "/etc/octopus/dns/zones";
pub const DNS_USER: &str = "_octodns";
pub const CANARY: &str = "use-application-dns.net";
pub const PFHELPER_SOCKET: &str = "/var/run/octopus-pfhelper.sock";
/// octopus-collector: IPFIX from pflow, DNS answers from octopus-dns.
pub const COLLECTOR_IPFIX: &str = "127.0.0.1:2055";
pub const COLLECTOR_DNS: &str = "127.0.0.1:2056";

/// A zone serial that changes when the records do (no secondaries exist, so
/// it only has to differ, not grow).
pub fn zone_serial(body: &str) -> u32 {
    let h = Sha256::digest(body.as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & 0x7fff_ffff
}

struct Zone {
    name: String,
    records: Vec<(String, &'static str, String)>,
}

impl Zone {
    fn new(name: &str) -> Zone {
        Zone { name: name.trim_end_matches('.').to_string(), records: vec![] }
    }

    fn add(&mut self, owner: &str, rtype: &'static str, data: String) {
        self.records.push((owner.to_string(), rtype, data));
    }

    fn file_name(&self) -> String {
        format!("{}.zone", self.name)
    }

    fn text(&self, r: &Router) -> String {
        let ns = format!("{}.{}.", r.cfg.system.hostname, r.cfg.system.domain);
        let mut body = String::new();
        for (owner, t, data) in &self.records {
            let _ = writeln!(body, "{owner:<24} IN {t:<5} {data}");
        }
        let serial = zone_serial(&body);
        let mut s = header(";", &[]);
        let _ = writeln!(s, "$ORIGIN {}.", self.name);
        s += "$TTL 300\n";
        let _ = writeln!(s, "@ IN SOA {ns} hostmaster.{}. ( {serial} 3600 600 86400 300 )", r.cfg.system.domain);
        let _ = writeln!(s, "@ IN NS {ns}");
        s += &body;
        s
    }
}

/// `gw-lan-fastlane`: the router's name on one network (no underscores in DNS).
fn net_host(host: &str, net: &str) -> String {
    format!("{host}-{}", net.replace('_', "-"))
}

/// Reverse zone and owner for an address: per /24, or one zone per /16 for
/// networks that big (`wide`).
fn reverse_name(ip: Ipv4Addr, wide: bool) -> (String, String) {
    let o = ip.octets();
    if wide {
        (format!("{}.{}.in-addr.arpa", o[1], o[0]), format!("{}.{}", o[3], o[2]))
    } else {
        (format!("{}.{}.{}.in-addr.arpa", o[2], o[1], o[0]), o[3].to_string())
    }
}

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;
    let domain = &c.system.domain;
    let host = &c.system.hostname;
    let mut zones: Vec<Zone> = vec![];

    // internal zone
    let mut z = Zone::new(domain);
    let mgmt: Vec<Ipv4Addr> = r.nets.iter().filter(|n| n.kind == Kind::Mgmt).map(|n| n.addr).collect();
    let primary = mgmt.first().copied().or(r.nets.first().map(|n| n.addr));
    if let Some(a) = primary {
        z.add(host, "A", a.to_string());
    }
    if let Some(v6) = r.nets.iter().filter(|n| n.kind == Kind::Mgmt).find_map(|n| n.v6) {
        z.add(host, "AAAA", v6.ula.addr().to_string());
    }
    for n in &r.nets {
        z.add(&net_host(host, &n.name), "A", n.addr.to_string());
    }
    for h in &c.hosts {
        z.add(&h.name, "A", h.ip.to_string());
        for a in &h.aliases {
            z.add(a, "A", h.ip.to_string());
        }
    }
    // vhosts are served by the router (nginx); lan networks reach every router address
    let primary6 = r.nets.iter().filter(|n| n.kind == Kind::Mgmt).chain(r.nets.iter()).find_map(|n| n.v6);
    if let Some(a) = primary {
        for fqdn in c.vhosts.iter().flat_map(|v| v.split_names(domain).0) {
            let owner = fqdn.strip_suffix(&format!(".{domain}")).unwrap_or(&fqdn).to_string();
            z.add(&owner, "A", a.to_string());
            if let Some(v6) = primary6 {
                z.add(&owner, "AAAA", v6.ula.addr().to_string());
            }
        }
    }
    zones.push(z);

    // reverse zones: every /24 touched by a network
    let mut rev: BTreeMap<String, Zone> = BTreeMap::new();
    let wide = |ip: Ipv4Addr| r.net_of(ip).is_some_and(|n| n.prefix.prefix_len() <= 16);
    for n in &r.nets {
        let w = n.prefix.prefix_len() <= 16;
        let step: u32 = if w { 65536 } else { 256 };
        let mask: u32 = if w { 0xffff_0000 } else { 0xffff_ff00 };
        let first = u32::from(n.prefix.network()) & mask;
        let last = u32::from(n.prefix.broadcast()) & mask;
        let mut b = first;
        while b <= last {
            let (name, _) = reverse_name(Ipv4Addr::from(b), w);
            rev.entry(name.clone()).or_insert_with(|| Zone::new(&name));
            match b.checked_add(step) {
                Some(x) => b = x,
                None => break,
            }
        }
    }
    let mut ptr = |ip: Ipv4Addr, fqdn: String| {
        let (zn, owner) = reverse_name(ip, wide(ip));
        if let Some(z) = rev.get_mut(&zn) {
            z.add(&owner, "PTR", fqdn);
        }
    };
    for n in &r.nets {
        let name = if Some(n.addr) == primary { host.clone() } else { net_host(host, &n.name) };
        ptr(n.addr, format!("{name}.{domain}."));
    }
    for h in &c.hosts {
        ptr(h.ip, format!("{}.{domain}.", h.name));
    }
    zones.extend(rev.into_values());

    // split horizon: one zone per public name
    for rec in &c.dns.records {
        let mut z = Zone::new(&rec.name);
        let t = if rec.ip.is_ipv4() { "A" } else { "AAAA" };
        z.add("@", t, rec.ip.to_string());
        zones.push(z);
    }

    // public vhosts' names (design 11.1): internal clients get the router,
    // not its WAN address, so they never need hairpin NAT
    if let Some(a) = primary {
        let primary6 = r.nets.iter().filter(|n| n.kind == Kind::Mgmt).chain(r.nets.iter()).find_map(|n| n.v6);
        for name in c.vhosts.iter().filter(|v| v.public).flat_map(|v| v.split_names(domain).1) {
            if zones.iter().any(|z| z.name == name) {
                continue;
            }
            let mut z = Zone::new(&name);
            z.add("@", "A", a.to_string());
            if let Some(v6) = primary6 {
                z.add("@", "AAAA", v6.ula.addr().to_string());
            }
            zones.push(z);
        }
    }

    // overrides (blackholing): a zone each, the name and with subdomains a wildcard
    for o in &c.dns.overrides {
        let mut z = Zone::new(&o.name.to_ascii_lowercase());
        let t = if o.ip.is_ipv4() { "A" } else { "AAAA" };
        z.add("@", t, o.ip.to_string());
        if o.subdomains {
            z.add("*", t, o.ip.to_string());
        }
        zones.push(z);
    }

    // DoH canary: phase A answers it from an empty zone (NODATA); octopus-dns
    // answers NXDOMAIN itself
    let engine = c.dns.engine;
    if engine == DnsEngine::Hickory {
        zones.push(Zone::new(CANARY));
    }

    // ---- hickory config
    let mut listen: Vec<String> = vec!["127.0.0.1".into()];
    listen.extend(r.nets.iter().map(|n| n.addr.to_string()));
    let mut allow: Vec<String> = vec!["127.0.0.0/8".into()];
    allow.extend(r.nets.iter().map(|n| n.prefix.to_string()));
    if let Some(w) = &c.wireguard {
        listen.push(w.address.addr().to_string());
        allow.push(w.address.trunc().to_string());
    }
    // IPv6: the stable unique local addresses; clients come from those and
    // from the delegated (global) prefixes, which pf already limits to the inside
    let listen6: Vec<String> = r.nets.iter().filter_map(|n| n.v6).map(|v| v.ula.addr().to_string()).collect();
    if !listen6.is_empty() {
        allow.push(octopus_config::model::ula_prefix(c).to_string());
        allow.push("2000::/3".into());
        allow.push("::1/128".into());
    }
    let q = |v: &[String]| v.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ");

    for z in &zones {
        g.file(format!("{ZONE_DIR}/{}", z.file_name()), z.text(r), Subsystem::Dns);
    }
    let forward = forward_toml(&c.dns.upstreams, if engine == DnsEngine::Hickory { "zones.stores" } else { "forward" });

    if engine == DnsEngine::OctopusDns {
        let mut s = header("#", &["octopus-dns (phase B); validate with: octopus-dns --validate -c <this file>"]);
        let all: Vec<String> = listen.iter().chain(&listen6).cloned().collect();
        let _ = writeln!(s, "listen = [{}]", q(&all));
        let _ = writeln!(s, "allow = [{}]", q(&allow));
        let _ = writeln!(s, "zone_dir = \"{ZONE_DIR}\"");
        let names: Vec<String> = zones.iter().map(|z| z.name.clone()).collect();
        let _ = writeln!(s, "zones = [{}]", q(&names));
        let _ = writeln!(s, "nxdomain = [\"{CANARY}\"]");
        let _ = writeln!(s, "user = \"{DNS_USER}\"");
        let _ = writeln!(s, "pfhelper = \"{PFHELPER_SOCKET}\"");
        if let Some(sh) = c.dns.sinkhole {
            let _ = writeln!(s, "sinkhole = \"{sh}\"");
        }
        if c.logging.pflow.as_deref().is_some_and(|p| p.starts_with("127.")) {
            let _ = writeln!(s, "collector = \"{COLLECTOR_DNS}\"");
        }
        s += "min_retention = 3600\n";
        for n in &r.nets {
            let _ = writeln!(s, "\n[[networks]]\nname = \"{}\"\nprefix = \"{}\"", n.name, n.prefix);
            if let Some(v6) = n.v6 {
                let _ = writeln!(s, "\n[[networks]]\nname = \"{}\"\nprefix = \"{}\"", n.name, v6.ula.trunc());
            }
        }
        if let Some(w) = &c.wireguard {
            let _ = writeln!(s, "\n[[networks]]\nname = \"wg\"\nprefix = \"{}\"", w.address.trunc());
        }
        if let Some(t) = &c.traffic {
            for d in &t.destinations {
                let doms: Vec<String> = d.domains.clone();
                let _ = writeln!(
                    s,
                    "\n[[classes]]\nname = \"{}\"\ntable = \"cls_{}\"\ndomains = [{}]",
                    d.class.name(),
                    d.class.name(),
                    q(&doms)
                );
            }
        }
        let _ = writeln!(s, "\n[forward]\noptions = {{ cache_size = {} }}", c.dns.cache_size);
        s += &forward;
        // views: other upstreams for listed clients, own cache, no fallback
        for v in &c.dns.views {
            let clients: Vec<String> = v.clients.iter().flat_map(|cl| client_prefixes(r, cl)).collect();
            let _ = writeln!(s, "\n[[views]]\nname = \"{}\"\nclients = [{}]", v.name, q(&clients));
            let _ = writeln!(s, "[views.forward]\noptions = {{ cache_size = {} }}", c.dns.cache_size / 4);
            s += &forward_toml(&v.upstreams, "views.forward");
        }
        g.file(format!("{DNS_DIR}/octopus-dns.toml"), s, Subsystem::Dns);
        return;
    }

    let mut s = header("#", &["hickory-dns 0.26 (phase A); validate with: hickory-dns --validate -c <this file>"]);
    let _ = writeln!(s, "listen_addrs_ipv4 = [{}]", q(&listen));
    if !listen6.is_empty() {
        let _ = writeln!(s, "listen_addrs_ipv6 = [{}]", q(&listen6));
    }
    s += "listen_port = 53\n";
    let _ = writeln!(s, "directory = \"{ZONE_DIR}\"");
    let _ = writeln!(s, "user = \"{DNS_USER}\"");
    let _ = writeln!(s, "group = \"{DNS_USER}\"");
    let _ = writeln!(s, "allow_networks = [{}]", q(&allow));
    for z in &zones {
        let _ =
            writeln!(s, "\n[[zones]]\nzone = \"{}\"\nzone_type = \"Primary\"\nfile = \"{}\"", z.name, z.file_name());
    }
    s += "\n[[zones]]\nzone = \".\"\nzone_type = \"External\"\n";
    s += "[zones.stores]\ntype = \"forward\"\n";
    let _ = writeln!(s, "options = {{ cache_size = {} }}", c.dns.cache_size);
    s += &forward;
    g.file(format!("{DNS_DIR}/named.toml"), s, Subsystem::Dns);
}

/// A view client as prefixes (hosts, networks and tables expanded).
fn client_prefixes(r: &Router, cl: &str) -> Vec<String> {
    use octopus_config::Endpoint;
    match r.endpoint(cl) {
        Ok(Endpoint::Any) => vec!["0.0.0.0/0".into()],
        Ok(Endpoint::Router) => vec!["127.0.0.0/8".into()],
        Ok(Endpoint::Internal) => r.nets.iter().map(|n| n.prefix.to_string()).collect(),
        // clients ask from the inside: nothing outside is a client
        Ok(Endpoint::Internet) => vec![],
        Ok(Endpoint::Net(i)) => vec![r.nets[i].prefix.to_string()],
        Ok(Endpoint::Addr(a)) => vec![a.to_string()],
        Ok(Endpoint::Table(t)) => r
            .cfg
            .tables
            .iter()
            .find(|x| x.name == t)
            .map(|x| x.entries.iter().map(|e| e.to_string()).collect())
            .unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// DoT upstreams in hickory's forward-store syntax under `table`.
fn forward_toml(upstreams: &[octopus_config::schema::Upstream], table: &str) -> String {
    let mut s = String::new();
    for u in upstreams {
        let ip = match u.ip {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => a.to_string(),
        };
        let _ = writeln!(s, "\n[[{table}.name_servers]]\nip = \"{ip}\"");
        let _ = writeln!(
            s,
            "[[{table}.name_servers.connections]]\nport = 853\nprotocol = {{ type = \"tls\", server_name = \"{}\" }}",
            u.tls_name
        );
    }
    s
}
