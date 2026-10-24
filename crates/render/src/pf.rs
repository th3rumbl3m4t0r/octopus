//! /etc/pf.conf.
//!
//! Layout (pf is last-match, so order matters):
//!   options, macros, tables, queues
//!   `block log all`                      the first rule (INV-7)
//!   quick blocks: IPv6 off, antispoofing, martians
//!   match rules: scrub, NAT, DNS interception, classification
//!   `pass out quick`                     policy is enforced on ingress
//!   WAN inbound: WireGuard, forwards     the only inbound paths (INV-2)
//!   per network, in order: reflection, management guard (INV-1), DoT block
//!   (INV-4), explicit [[rules]] (first match), the kind policy
//!
//! Every rule after `block log all` that passes is `quick`, which makes the
//! ruleset first-match like pfSense and keeps imported rule order meaningful.

use ipnet::IpNet;
use octopus_config::check::parse_rate;
use octopus_config::model::{Endpoint, RULE_ALL, RULE_WAN, WG_IF};
use octopus_config::schema::*;
use octopus_config::{Net, Router};
use std::fmt::Write as _;

use crate::net::LAN_GROUP;
use crate::{Generation, Subsystem, header};

fn v6(r: &Router) -> bool {
    r.cfg.ipv6.mode == Ipv6Mode::Pd
}

/// The router's addresses on a network: `192.168.1.1` or `{ 192.168.1.1 fd..::1 }`.
fn router_addrs(n: &Net) -> String {
    match n.v6 {
        Some(v) => format!("{{ {} {} }}", n.addr, v.ula.addr()),
        None => n.addr.to_string(),
    }
}

const MARTIANS: &str = "0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
                        192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 \
                        198.51.100.0/24 203.0.113.0/24 224.0.0.0/3";

/// IPv6 sources that never come from the internet (link-local excluded:
/// neighbour discovery and DHCPv6 with the ISP use it).
const MARTIANS6: &str = "::/128 ::1 ::ffff:0:0/96 100::/64 2001:db8::/32 fc00::/7 fec0::/10 ff00::/8";

/// Well-known public resolvers (DoH/DoT): clients must use the router's DNS
/// and their view (INV-4), not go around it over 443.
const PUBLIC_RESOLVERS: &str = "1.1.1.1 1.0.0.1 1.1.1.2 1.0.0.2 1.1.1.3 1.0.0.3 \
    2606:4700:4700::1111 2606:4700:4700::1001 2606:4700:4700::1112 2606:4700:4700::1002 \
    2606:4700:4700::1113 2606:4700:4700::1003 8.8.8.8 8.8.4.4 2001:4860:4860::8888 \
    2001:4860:4860::8844 9.9.9.9 149.112.112.112 9.9.9.10 149.112.112.10 9.9.9.11 \
    149.112.112.11 2620:fe::fe 2620:fe::9 2620:fe::10 2620:fe::11 94.140.14.14 \
    94.140.15.15 94.140.14.140 94.140.14.141 2a10:50c0::ad1:ff 2a10:50c0::ad2:ff \
    208.67.222.222 208.67.220.220 208.67.222.123 208.67.220.123 45.90.28.0/24 45.90.30.0/24 \
    185.228.168.0/24 185.228.169.0/24 194.242.2.0/24 2a07:e340::/32";

/// pf state limiters: the internet's ways in, and every inside address.
const WAN_LIMIT: &str = "wan";
const CLIENT_LIMIT: &str = "clients";

/// Default realtime ports: SSH, WireGuard and NTP are added from the config.
const REALTIME_PORTS: &[(&str, &str, &str)] =
    &[("udp", "8801:8810", "Zoom"), ("udp", "19302:19309", "Google Meet"), ("udp", "3478:3481", "Teams / STUN")];

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;
    let mut s = header("#", &["pf is last-match; everything after the first block is quick (first-match)"]);
    let wan = r.wan.as_ref().map(|w| w.egress.as_str());
    let wg = c.wireguard.as_ref();
    let mgmt_ports = mgmt_ports(r);

    // ---- options
    s += "set skip on lo\n";
    s += "set block-policy drop\n";
    if let Some(w) = wan {
        let _ = writeln!(s, "set loginterface {w}");
    }
    let _ = writeln!(s, "set limit {{ states {}, table-entries {} }}", c.system.max_states, c.system.max_table_entries);
    s += "set syncookies adaptive (start 25%, end 12%)\n";
    // nobody fills the state table alone: the internet's ways in share a
    // fifth of it, each inside address (an IPv6 /64) a tenth; management
    // and the router's own traffic keep the rest
    let _ = writeln!(s, "state limiter \"{WAN_LIMIT}\" id 1 limit {}", (c.system.max_states / 5).max(1000));
    let _ = writeln!(
        s,
        "source limiter \"{CLIENT_LIMIT}\" id 2 entries 16384 limit {} inet6 mask 64",
        (c.system.max_states / 10).max(1000)
    );
    if c.logging.pflow.is_some() {
        s += "set state-defaults pflow\n";
    }
    s += "\n";

    // ---- macros
    if let Some(w) = wan {
        let _ = writeln!(s, "wan = \"{w}\"");
    }
    for n in &r.nets {
        let _ = writeln!(s, "if_{} = \"{}\"\t# {} {}", n.name, n.ifname, n.kind, n.prefix);
    }
    if wg.is_some() {
        let _ = writeln!(s, "if_wg = \"{WG_IF}\"");
    }
    let _ =
        writeln!(s, "mgmt_ports = \"{{ {} }}\"", mgmt_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(" "));
    s += "\n";

    // ---- tables
    // the tiers, the tunnel and the networks behind [[routes]]
    let mut internal: Vec<String> = r.internal_v4().iter().map(|p| p.to_string()).collect();
    if v6(r) {
        // the delegated prefix is dynamic: those networks are matched via ($group:network)
        internal.push(octopus_config::model::ula_prefix(c).to_string());
    }
    let _ = writeln!(s, "table <martians> const {{ {MARTIANS} }}");
    if v6(r) {
        let _ = writeln!(s, "table <martians6> const {{ {MARTIANS6} }}");
    }
    if c.dns.block_public_resolvers {
        let _ = writeln!(s, "table <public_resolvers> const {{ {PUBLIC_RESOLVERS} }}");
    }
    let _ = writeln!(s, "table <internal> const {{ {} }}", internal.join(" "));
    for t in &c.tables {
        if let Some(d) = &t.description {
            let _ = writeln!(s, "# {}", one_line(d));
        }
        let entries: Vec<String> = t.entries.iter().map(|e| host_or_net(*e)).collect();
        let _ = writeln!(s, "table <t_{}> const {{ {} }}", t.name, wrap(&entries));
    }
    if c.vhosts.iter().any(|v| v.public && v.allow_from.iter().any(|a| a == "cloudflare")) {
        let _ = writeln!(
            s,
            "table <cloudflare> const {{ {} }}",
            wrap(&octopus_config::schema::CLOUDFLARE.iter().map(|x| x.to_string()).collect::<Vec<_>>())
        );
    }
    if let Some(w) = wg {
        for k in [Kind::Mgmt, Kind::Lan] {
            let ips: Vec<String> = w.peers.iter().filter(|p| p.policy == k).map(|p| p.address.to_string()).collect();
            let _ = writeln!(s, "table <wg_{k}> const {{ {} }}", ips.join(" "));
        }
    }
    s += "# filled at runtime by octopus-pfhelper (DNS classification, lab blocks)\n";
    for t in ["cls_realtime", "cls_streaming", "cls_bulk", "lab_block"] {
        let _ = writeln!(s, "table <{t}> persist");
    }
    s += "\n";

    // ---- queues
    let qnets = queue_nets(r);
    if let Some(t) = &c.traffic {
        render_queues(&mut s, t, wan.is_some(), &qnets);
    }

    // ---- default deny
    s += "# ---- default deny (INV-7)\n";
    s += "block log all\n";
    if wan.is_some() {
        // the internet's background noise isn't logged: it would fill /var
        // (pf is last-match, and every pass below is quick)
        s += "block in on $wan label \"wan:default\"\n";
    }
    if c.ipv6.mode == Ipv6Mode::Off {
        s += "block quick inet6 all\t# IPv6 is off\n";
    }
    s += "block in quick from urpf-failed label \"urpf\"\n";
    s += "block in quick from <lab_block> label \"lab_block\"\n";
    // forwarded traffic only: the router's own (DNS upstreams, NTP) is never cut
    s += "block out quick to <lab_block> received-on any label \"lab_block\"\n";
    if wan.is_some() {
        if v6(r) {
            // the router's own DHCPv6 solicit goes to a multicast address, which <martians6> holds
            s += "pass out quick on $wan inet6 proto udp from fe80::/10 port dhcpv6-client to ff02::1:2 port dhcpv6-server label \"v6:dhcp6\"\n";
        }
        s += "block in quick on $wan from <martians> label \"martians\"\n";
        s += "block out quick on $wan to <martians> label \"martians\"\n";
        if v6(r) {
            s += "block in quick on $wan inet6 from <martians6> label \"martians\"\n";
            s += "block out quick on $wan inet6 to <martians6> label \"martians\"\n";
        }
    }
    if v6(r) {
        s += "# IPv6 on the link: neighbour discovery, router solicitations/advertisements, MLD\n";
        s += "pass quick inet6 proto icmp6 icmp6-type { neighbrsol neighbradv } label \"v6:nd\"\n";
        s += "pass quick inet6 proto icmp6 from { fe80::/10 :: } to { fe80::/10 ff02::/16 } icmp6-type { routersol routeradv 130 131 132 143 } label \"v6:link\"\n";
        if wan.is_some() {
            s += "pass in quick on $wan inet6 proto udp from fe80::/10 port dhcpv6-server to fe80::/10 port dhcpv6-client label \"v6:dhcp6\"\n";
        }
    }
    s += "\n";

    // ---- match rules
    s += "# ---- normalisation, NAT, interception, classification\n";
    s += "match in all scrub (no-df random-id)\n";
    if let (Some(_), Some(cw)) = (wan, &c.wan) {
        let mss = cw.mss.unwrap_or(cw.mtu - 40);
        let _ = writeln!(s, "match on $wan scrub (max-mss {mss})");
        let _ = writeln!(s, "match out on $wan inet from <internal> nat-to ($wan)");
        // reflection: the redirected connection must come back through us
        for (i, f) in c.forwards.iter().enumerate().filter(|(_, f)| f.reflect) {
            if let Some(n) = r.net_of(f.to) {
                let _ = writeln!(
                    s,
                    "match out on $if_{} inet{} to {}{} tagged RFL_{i} nat-to ($if_{}:0)",
                    n.name,
                    proto(f.proto),
                    f.to,
                    port_clause(&target_port(f)),
                    n.name
                );
            }
        }
    }
    // (tiers sharing an interface: each to its own router address)
    let mut ingress: Vec<(&str, String, String)> =
        r.nets.iter().map(|n| (n.name.as_str(), n.addr.to_string(), src_clause(n))).collect();
    if let Some(w) = wg {
        ingress.push(("wg", w.address.addr().to_string(), String::new()));
    }
    for (name, addr, src) in &ingress {
        let _ = writeln!(
            s,
            "match in on $if_{name} inet proto {{ tcp udp }}{src} to ! self port domain rdr-to {addr}\t# INV-4"
        );
    }
    for n in r.nets.iter().filter(|n| n.v6.is_some()) {
        let _ = writeln!(
            s,
            "match in on $if_{} inet6 proto {{ tcp udp }} to ! self port domain rdr-to {}\t# INV-4",
            n.name,
            n.v6.unwrap().ula.addr()
        );
    }
    if let Some(t) = &c.traffic {
        render_classification(&mut s, r, t, &qnets, wan.is_some());
    }
    s += "\n";

    s += "# ---- leaving: policy is enforced where traffic enters\n";
    s += "pass out quick\n\n";

    // ---- WAN inbound
    if let (Some(_), Some(cw)) = (wan, &c.wan) {
        s += "# ---- WAN inbound: default deny, declared paths only (INV-2)\n";
        if cw.allow_ping {
            let _ = writeln!(
                s,
                "pass in quick on $wan inet proto icmp to ($wan) icmp-type echoreq label \"wan:ping\" state limiter \"{WAN_LIMIT}\""
            );
            if v6(r) {
                let _ = writeln!(
                    s,
                    "pass in quick on $wan inet6 proto icmp6 to self icmp6-type echoreq label \"wan:ping\" state limiter \"{WAN_LIMIT}\""
                );
            }
        }
        // [[rules]] on the wan: blocks only (INV-2), ahead of every way in
        for (k, rule) in c.rules.iter().enumerate().filter(|(_, x)| x.network == RULE_WAN) {
            s += &explicit_rule(r, "$wan", k, rule, None);
        }
        if let Some(w) = wg {
            let _ = writeln!(
                s,
                "pass in quick on $wan proto udp to ($wan) port {} label \"wan:wireguard\" state limiter \"{WAN_LIMIT}\"",
                w.listen_port
            );
        }
        if let Some(from) = public_vhost_sources(r) {
            let _ = writeln!(
                s,
                "pass in quick on $wan proto tcp from {from} to ($wan) port {{ http https }} label \"wan:vhosts\" state limiter \"{WAN_LIMIT}\""
            );
        }
        for f in &c.forwards {
            let _ = writeln!(
                s,
                "pass in{} quick on $wan inet{} from {} to ($wan){} rdr-to {}{} label \"fwd:{}\" state limiter \"{WAN_LIMIT}\"",
                if f.log { " log" } else { "" },
                proto(f.proto),
                endpoint_str(r, &r.endpoint(&f.from).unwrap_or(Endpoint::Any)),
                port_clause(&f.port),
                f.to,
                f.to_port.map(|p| format!(" port {p}")).unwrap_or_default(),
                label(&f.name)
            );
        }
        s += "\n";
    }

    // ---- internal networks: one section per interface (tiers on the house
    // ports share one)
    let mut done = std::collections::BTreeSet::new();
    for n in &r.nets {
        if done.insert(n.ifname.clone()) {
            let here: Vec<&Net> = r.nets.iter().filter(|x| x.ifname == n.ifname).collect();
            render_interface(&mut s, r, &here);
        }
    }
    if let Some(w) = wg {
        render_wg(&mut s, r, w);
    }

    g.file("/etc/pf.conf", s, Subsystem::Pf).mode = 0o600;
}

fn mgmt_ports(r: &Router) -> Vec<u16> {
    let mut v = vec![r.cfg.ssh.port];
    if r.cfg.web.enabled {
        v.push(r.cfg.web.port);
    }
    v
}

/// ` from <prefix>` for a tier that shares its interface (told apart by
/// source address), else nothing.
fn src_clause(n: &Net) -> String {
    n.src.map(|p| format!(" from {p}")).unwrap_or_default()
}

/// The tiers on one interface, in this order: every tier's management guard
/// (fixed kinds) and DoT/DoH blocks, so no rule for one tier comes before
/// another tier's guard; then the explicit rules in file order; links;
/// reflection; each tier's kind policy; the IPv6 of a shared interface.
fn render_interface(s: &mut String, r: &Router, here: &[&Net]) {
    let c = &r.cfg;
    let first = here[0];
    let i = format!("$if_{}", first.name);
    for n in here {
        let _ = writeln!(s, "# ---- {} ({}, {}, {})", n.name, n.kind, n.ifname, n.prefix);
    }
    for n in here {
        let i = format!("$if_{}", n.name);
        let src = src_clause(n);
        // open tiers: the guard comes after the rules, which may let them in
        if !matches!(n.kind, Kind::Mgmt | Kind::Open) {
            let _ = writeln!(
                s,
                "block in log quick on {i} proto tcp{src} to self port $mgmt_ports label \"{}:guard\"\t# INV-1",
                n.name
            );
        }
        let _ = writeln!(
            s,
            "block in log quick on {i} proto {{ tcp udp }}{src} to ! self port 853 label \"{}:dot\"\t# INV-4",
            n.name
        );
        if c.dns.block_public_resolvers {
            let _ = writeln!(
                s,
                "block in log quick on {i} proto {{ tcp udp }}{src} to <public_resolvers> port {{ 443 853 }} label \"{}:doh\"\t# INV-4",
                n.name
            );
        }
    }
    let owner = r.v6_owner(&first.ifname);
    if let Some(o) = owner {
        // the shared /64: the same blocks without a source (IPv4 ranges don't cover it)
        if !matches!(o.kind, Kind::Mgmt | Kind::Open) {
            let _ = writeln!(
                s,
                "block in log quick on {i} inet6 proto tcp to self port $mgmt_ports label \"{}:guard\"\t# INV-1",
                o.name
            );
        }
        let _ = writeln!(
            s,
            "block in log quick on {i} inet6 proto {{ tcp udp }} to ! self port 853 label \"{}:dot\"\t# INV-4",
            o.name
        );
        if c.dns.block_public_resolvers {
            let _ = writeln!(
                s,
                "block in log quick on {i} inet6 proto {{ tcp udp }} to <public_resolvers> port {{ 443 853 }} label \"{}:doh\"\t# INV-4",
                o.name
            );
        }
    }

    // explicit rules in file order: the `all` ones once per interface (they
    // match by source); one tier's rules on a shared interface only from its range
    for (k, rule) in c.rules.iter().enumerate() {
        if rule.network == RULE_ALL {
            *s += &explicit_rule(r, &i, k, rule, None);
        } else if let Some(n) = here.iter().find(|n| n.name == rule.network) {
            let scope = (here.len() > 1).then_some(*n);
            *s += &explicit_rule(r, &format!("$if_{}", n.name), k, rule, scope);
        }
    }
    for n in here.iter().filter(|n| n.kind == Kind::Servers) {
        for (k, l) in c.links.iter().enumerate().filter(|(_, x)| x.network == n.name) {
            if let Ok(to) = r.endpoint(&l.to) {
                let _ = writeln!(
                    s,
                    "pass in quick on $if_{}{}{} to {}{} label \"link:{}\"{}{}",
                    n.name,
                    if l.proto == Proto::Icmp { " inet proto icmp" } else { proto(l.proto) },
                    src_clause(n),
                    endpoint_str(r, &to),
                    l.port.as_ref().map(port_clause).unwrap_or_default(),
                    k + 1,
                    limiter(n.kind),
                    l.description.as_ref().map(|d| format!("\t# {}", one_line(d))).unwrap_or_default()
                );
            }
        }
    }
    // after the rules: an explicit block inside also stops the way round through the WAN address
    reflection(s, r, &i);
    for n in here {
        let from = n.src.map(|p| p.to_string());
        kind_policy(s, r, &format!("$if_{}", n.name), &n.name, n.kind, &router_addrs(n), from.as_deref());
    }
    if let Some(o) = owner
        && o.kind == Kind::Open
    {
        // IPv6 on a shared interface: one /64 for its tiers, the policy of its owner
        let _ = writeln!(
            s,
            "block in log quick on {i} inet6 proto tcp to self port $mgmt_ports label \"{}:guard\"",
            o.name
        );
        let _ = writeln!(s, "pass in quick on {i} inet6 label \"{}:open\"{}", o.name, limiter(o.kind));
    }
    s.push('\n');
}

/// The per-address limiter on a pass rule (not for management: the way in
/// must stay open).
fn limiter(kind: Kind) -> String {
    if kind == Kind::Mgmt { String::new() } else { format!(" source limiter \"{CLIENT_LIMIT}\"") }
}

/// Router services and the default for a kind. `from` narrows the source
/// (WireGuard peers share one interface).
fn kind_policy(s: &mut String, r: &Router, i: &str, label: &str, kind: Kind, addr: &str, from: Option<&str>) {
    // pf grammar: on <if> [af] [proto] [from] [to] [options]
    let src = from.map(|f| format!(" from {f}")).unwrap_or_default();
    match kind {
        Kind::Open => {
            // everything, the router's management only by a rule above
            let _ = writeln!(
                s,
                "block in log quick on {i} proto tcp{src} to self port $mgmt_ports label \"{label}:guard\"\t# INV-1"
            );
            let _ = writeln!(s, "pass in quick on {i}{src} label \"{label}:open\"{}", limiter(kind));
            if from.is_some() {
                // DHCP comes from 0.0.0.0, not the tier's addresses
                let _ = writeln!(
                    s,
                    "pass in quick on {i} proto udp from port bootpc to {{ 255.255.255.255 self }} port bootps label \"{label}:dhcp\""
                );
            }
        }
        Kind::Mgmt => {
            let _ = writeln!(s, "pass in quick on {i}{src} label \"{label}:mgmt\"");
        }
        Kind::Lan | Kind::Servers | Kind::Guest => {
            let lim = limiter(kind);
            let _ = writeln!(
                s,
                "pass in quick on {i} proto {{ tcp udp }}{src} to {addr} port domain label \"{label}:dns\"{lim}"
            );
            if from.is_none() {
                // to the router: never a way out (INV-3) or to other hosts' port 67
                let _ = writeln!(
                    s,
                    "pass in quick on {i} proto udp from port bootpc to {{ 255.255.255.255 self }} port bootps label \"{label}:dhcp\""
                );
            }
            if r.cfg.ntp.serve {
                let _ =
                    writeln!(s, "pass in quick on {i} proto udp{src} to {addr} port ntp label \"{label}:ntp\"{lim}");
            }
            if kind == Kind::Lan && !r.cfg.vhosts.is_empty() {
                let _ = writeln!(
                    s,
                    "pass in quick on {i} proto tcp{src} to self port {{ http https }} label \"{label}:vhosts\"{lim}"
                );
            }
            let v4addr = addr.trim_matches(['{', '}', ' ']).split(' ').next().unwrap_or(addr);
            let _ = writeln!(
                s,
                "pass in quick on {i} inet proto icmp{src} to {v4addr} icmp-type echoreq label \"{label}:ping\""
            );
            if v6(r) && from.is_none() {
                let _ = writeln!(
                    s,
                    "pass in quick on {i} inet6 proto icmp6 to self icmp6-type echoreq label \"{label}:ping\""
                );
            }
            let _ = writeln!(s, "block in log quick on {i}{src} to self label \"{label}:self\"");
            if matches!(kind, Kind::Lan | Kind::Guest) {
                if v6(r) && from.is_none() {
                    // the other networks' delegated prefixes aren't in <internal>
                    let _ = writeln!(
                        s,
                        "block in log quick on {i} inet6 to ({LAN_GROUP}:network) label \"{label}:internal6\""
                    );
                }
                let _ = writeln!(s, "pass in quick on {i}{src} to ! <internal> label \"{label}:internet\"{lim}");
            } else if from.is_none() {
                // web traffic goes to octopus-proxy on loopback (allowlist, verified TLS); the
                // rest only through [[links]] (INV-3)
                if r.cfg.proxy.is_some()
                    && let Some(idx) =
                        r.nets.iter().filter(|n| n.kind == Kind::Servers).position(|n| format!("$if_{}", n.name) == i)
                {
                    let (https, http) = crate::proxy::ports(idx);
                    let _ = writeln!(
                        s,
                        "pass in quick on {i} proto tcp to ! <internal> port https divert-to 127.0.0.1 port {https} label \"{label}:proxy\"{lim}"
                    );
                    let _ = writeln!(
                        s,
                        "pass in quick on {i} proto tcp to ! <internal> port http divert-to 127.0.0.1 port {http} label \"{label}:proxy\"{lim}"
                    );
                } else {
                    let _ =
                        writeln!(s, "# servers: no direct egress; no [proxy], so web traffic is blocked too (INV-3)");
                }
            }
        }
    }
}

fn render_wg(s: &mut String, r: &Router, w: &WireGuard) {
    let _ = writeln!(s, "# ---- wireguard ({WG_IF}, {})", w.address.trunc());
    let addr = w.address.addr().to_string();
    let _ = writeln!(
        s,
        "block in log quick on $if_wg proto tcp from ! <wg_mgmt> to self port $mgmt_ports label \"wg:guard\"\t# INV-1"
    );
    let _ =
        writeln!(s, "block in log quick on $if_wg proto {{ tcp udp }} to ! self port 853 label \"wg:dot\"\t# INV-4");
    if r.cfg.dns.block_public_resolvers {
        let _ = writeln!(
            s,
            "block in log quick on $if_wg proto {{ tcp udp }} to <public_resolvers> port {{ 443 853 }} label \"wg:doh\"\t# INV-4"
        );
    }
    // rules on every internal network hold for the peers too
    for (k, rule) in r.cfg.rules.iter().enumerate().filter(|(_, x)| x.network == RULE_ALL) {
        *s += &explicit_rule(r, "$if_wg", k, rule, None);
    }
    kind_policy(s, r, "$if_wg", "wg_mgmt", Kind::Mgmt, &addr, Some("<wg_mgmt>"));
    reflection(s, r, "$if_wg");
    kind_policy(s, r, "$if_wg", "wg_lan", Kind::Lan, &addr, Some("<wg_lan>"));
    s.push('\n');
}

fn reflection(s: &mut String, r: &Router, i: &str) {
    if r.wan.is_none() {
        return;
    }
    for (k, f) in r.cfg.forwards.iter().enumerate().filter(|(_, f)| f.reflect) {
        // internal clients only; a source restriction to outside addresses
        // can never match them, so there is nothing to reflect
        let from = match r.endpoint(&f.from).unwrap_or(Endpoint::Any) {
            Endpoint::Any => "<internal>".to_string(),
            e if r.overlaps_internal(&e) => endpoint_str(r, &e),
            _ => continue,
        };
        let _ = writeln!(
            s,
            "pass in quick on {i} inet{} from {from} to ($wan){} rdr-to {}{} tag RFL_{k} label \"fwd:{}:reflect\" source limiter \"{CLIENT_LIMIT}\"",
            proto(f.proto),
            port_clause(&f.port),
            f.to,
            f.to_port.map(|p| format!(" port {p}")).unwrap_or_default(),
            label(&f.name)
        );
    }
}

/// An explicit [[rules]] entry: one pf line per address family it needs
/// (see `alternatives`). `scope`: the tier the rule is for when its
/// interface carries other tiers too; the source is narrowed to its range.
fn explicit_rule(r: &Router, i: &str, k: usize, rule: &Rule, scope: Option<&Net>) -> String {
    let action = match rule.action {
        Action::Pass => "pass",
        Action::Block => "block drop",
        Action::Reject => "block return",
    };
    let from = r.endpoint(&rule.from).unwrap_or(Endpoint::Any);
    let to = r.endpoint(&rule.to).unwrap_or(Endpoint::Any);
    let froms = match scope {
        Some(n) => narrow(r, &from, n),
        None => alternatives(r, &from),
    };
    // on the WAN pf sees the WAN address: forwards translate after this rule
    let tos = if rule.network == RULE_WAN && r.is_internal(&to) {
        vec![(Af::Any, "($wan)".to_string())]
    } else {
        alternatives(r, &to)
    };
    let icmp = rule.proto == Proto::Icmp;
    let lim = if rule.action == Action::Pass && rule.network != RULE_WAN { limiter(Kind::Open) } else { String::new() };
    let desc = rule.description.as_ref().map(|d| format!("\t# {}", one_line(d))).unwrap_or_default();
    let mut out = String::new();
    for (fa, f) in &froms {
        for (ta, t) in &tos {
            // ICMP is IPv4 only: a network that also has IPv6 would expand to both
            let Some(af) = fa.with(*ta).and_then(|a| if icmp { a.with(Af::Inet) } else { Some(a) }) else { continue };
            let _ = writeln!(
                out,
                "{action} in{} quick on {i}{}{} from {f} to {t}{} label \"rule:{}\"{lim}{desc}",
                if rule.log { " log" } else { "" },
                af.keyword(),
                proto(rule.proto),
                rule.port.as_ref().map(port_clause).unwrap_or_default(),
                k + 1,
            );
        }
    }
    if out.is_empty() {
        let _ = writeln!(out, "# rule:{} can't match on {i}{desc}", k + 1);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Af {
    Any,
    Inet,
    Inet6,
}

impl Af {
    /// Both at once, if they can be.
    fn with(self, o: Af) -> Option<Af> {
        match (self, o) {
            (Af::Any, x) | (x, Af::Any) => Some(x),
            (a, b) if a == b => Some(a),
            _ => None,
        }
    }

    fn keyword(self) -> &'static str {
        match self {
            Af::Any => "",
            Af::Inet => " inet",
            Af::Inet6 => " inet6",
        }
    }
}

/// An endpoint as pf alternatives, one rule each. IPv6 needs its own: the
/// delegated prefixes are dynamic (pf tracks them through the interface
/// group), pf can't negate a list, and a shared interface's `:network`
/// would cover every tier aliased on it.
fn alternatives(r: &Router, e: &Endpoint) -> Vec<(Af, String)> {
    match e {
        Endpoint::Internal if v6(r) => {
            vec![(Af::Any, "<internal>".into()), (Af::Inet6, format!("({LAN_GROUP}:network)"))]
        }
        Endpoint::Internet if v6(r) => {
            vec![(Af::Inet, "! <internal>".into()), (Af::Inet6, format!("! ({LAN_GROUP}:network)"))]
        }
        Endpoint::Net(i) => net_alternatives(r, &r.nets[*i]),
        // an address is of one family: never paired with the other's alternative
        Endpoint::Addr(a @ IpNet::V4(_)) if v6(r) => vec![(Af::Inet, host_or_net(*a))],
        Endpoint::Addr(a @ IpNet::V6(_)) if v6(r) => vec![(Af::Inet6, host_or_net(*a))],
        _ => vec![(Af::Any, endpoint_str(r, e))],
    }
}

/// A tier: alone on its interface, the interface's networks (its delegated
/// /64 included); sharing one, its IPv4 range, and the interface's /64 if it
/// is the tier that owns it.
fn net_alternatives(r: &Router, n: &Net) -> Vec<(Af, String)> {
    match n.src {
        None if n.v6.is_some() => vec![(Af::Any, format!("($if_{}:network)", n.name))],
        None => vec![(Af::Any, n.prefix.to_string())],
        Some(p) => {
            let mut v = vec![(Af::Inet, p.to_string())];
            if r.v6_owner(&n.ifname).is_some_and(|o| o.name == n.name) {
                v.push((Af::Inet6, format!("($if_{}:network)", n.name)));
            }
            v
        }
    }
}

/// A rule's source narrowed to tier `n`, which shares its interface: the
/// part of it that can come from the tier.
fn narrow(r: &Router, from: &Endpoint, n: &Net) -> Vec<(Af, String)> {
    let own = net_alternatives(r, n);
    let p = n.src.unwrap_or(n.prefix);
    match from {
        Endpoint::Any | Endpoint::Internal => own,
        Endpoint::Net(j) if r.nets[*j].name == n.name => own,
        Endpoint::Addr(IpNet::V4(a)) if p.contains(a) => vec![(Af::Inet, host_or_net(IpNet::V4(*a)))],
        Endpoint::Addr(IpNet::V4(a)) if a.contains(&p) => vec![(Af::Inet, p.to_string())],
        Endpoint::Addr(IpNet::V6(a)) if own.iter().any(|(af, _)| *af == Af::Inet6) => {
            vec![(Af::Inet6, host_or_net(IpNet::V6(*a)))]
        }
        // a table can't be narrowed (check refuses it); anything else is never from here
        Endpoint::Table(_) => vec![(Af::Any, endpoint_str(r, from))],
        _ => vec![],
    }
}

/// Who may reach the public vhosts on the WAN (None: no public vhost). One
/// site open to all opens the port to all: pf can't see the host name.
fn public_vhost_sources(r: &Router) -> Option<String> {
    let public: Vec<_> = r.cfg.vhosts.iter().filter(|v| v.public).collect();
    if public.is_empty() {
        return None;
    }
    if public.iter().any(|v| v.allow_from.is_empty()) {
        return Some("any".into());
    }
    let mut srcs: Vec<String> = vec![];
    for a in public.iter().flat_map(|v| &v.allow_from) {
        let s = if a == "cloudflare" {
            "<cloudflare>".to_string()
        } else {
            match r.endpoint(a) {
                Ok(e) => endpoint_str(r, &e),
                Err(_) => continue,
            }
        };
        if !srcs.contains(&s) {
            srcs.push(s);
        }
    }
    Some(if srcs.len() == 1 { srcs.remove(0) } else { format!("{{ {} }}", srcs.join(" ")) })
}

fn endpoint_str(r: &Router, e: &Endpoint) -> String {
    match e {
        Endpoint::Any => "any".into(),
        Endpoint::Router => "self".into(),
        Endpoint::Internal => "<internal>".into(),
        Endpoint::Internet => "! <internal>".into(),
        // with IPv6 the network's delegated prefix is dynamic: let pf track the
        // interface, unless other tiers share it (their aliases would count)
        Endpoint::Net(i) if r.nets[*i].v6.is_some() && r.nets[*i].src.is_none() => {
            format!("($if_{}:network)", r.nets[*i].name)
        }
        Endpoint::Net(i) => r.nets[*i].prefix.to_string(),
        Endpoint::Addr(a) => host_or_net(*a),
        Endpoint::Table(t) => format!("<t_{t}>"),
    }
}

fn host_or_net(a: IpNet) -> String {
    if a.prefix_len() == a.max_prefix_len() { a.addr().to_string() } else { a.to_string() }
}

fn proto(p: Proto) -> &'static str {
    match p {
        Proto::Any => "",
        Proto::Tcp => " proto tcp",
        Proto::Udp => " proto udp",
        Proto::TcpUdp => " proto { tcp udp }",
        // ICMP is IPv4 only (explicit rules say inet themselves)
        Proto::Icmp => " proto icmp",
        Proto::Gre => " proto gre",
        Proto::Esp => " proto esp",
    }
}

/// ` port 80`, ` port 80:90` or ` port { 80 443 }`.
fn port_clause(p: &Ports) -> String {
    let one = |(a, b): &(u16, u16)| if a == b { a.to_string() } else { format!("{a}:{b}") };
    match p.0.as_slice() {
        [x] => format!(" port {}", one(x)),
        xs => format!(" port {{ {} }}", xs.iter().map(one).collect::<Vec<_>>().join(" ")),
    }
}

/// Port(s) a forward lands on internally.
fn target_port(f: &Forward) -> Ports {
    match (f.to_port, f.port.0.as_slice()) {
        (Some(tp), [(a, b)]) => Ports(vec![(tp, tp.saturating_add(b - a))]),
        _ => f.port.clone(),
    }
}

fn one_line(s: &str) -> String {
    crate::comment(s)
}

/// Text inside a `label "..."`: names are checked, this is the second line of defence.
fn label(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.')).collect()
}

/// Long tables wrapped over several lines.
fn wrap(entries: &[String]) -> String {
    let mut out = String::new();
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out += if i % 6 == 0 { " \\\n\t" } else { " " };
        }
        out += e;
    }
    out
}

// ---- queues (phase 4)

/// Queue share of the root, in per mille, and min share: from the design's
/// starting values (upload root 22M, download root 90M).
const UP: [(&str, Class, u64, u64); 4] = [
    ("rt", Class::Realtime, 182, 91),
    ("str", Class::Streaming, 91, 0),
    ("def", Class::Default, 545, 0),
    ("bulk", Class::Bulk, 182, 45),
];
const DOWN: [(&str, Class, u64, u64); 4] = [
    ("rt", Class::Realtime, 56, 22),
    ("str", Class::Streaming, 389, 222),
    ("def", Class::Default, 389, 0),
    ("bulk", Class::Bulk, 166, 33),
];

/// Download trees live on physical ports: a VLAN's traffic is queued on its
/// parent, so every network on one trunk shares one budget, and the queue
/// interface exists before a new VLAN is created (pf rejects queues on
/// missing interfaces).
fn queue_port(n: &Net) -> &str {
    n.parent.as_deref().unwrap_or(&n.ifname)
}

fn queue_nets(r: &Router) -> Vec<&Net> {
    r.nets.iter().collect()
}

fn rate(bps: u64) -> String {
    if bps >= 1_000_000 && bps.is_multiple_of(1_000_000) {
        format!("{}M", bps / 1_000_000)
    } else {
        format!("{}K", bps / 1000)
    }
}

fn qname(prefix: &str, short: &str) -> String {
    format!("{prefix}_{short}")
}

fn render_queues(s: &mut String, t: &Traffic, wan: bool, nets: &[&Net]) {
    s.push_str("# ---- queues: root about 90 % of the measured line; children borrow when idle\n");
    let up = parse_rate(&t.upload).unwrap_or(0);
    let down = parse_rate(&t.download).unwrap_or(0);
    if wan {
        tree(s, "$wan", "up", up, &UP);
    }
    let mut ports: Vec<&str> = nets.iter().map(|n| queue_port(n)).collect();
    ports.dedup();
    ports.sort();
    ports.dedup();
    for p in ports {
        tree(s, p, &format!("dn_{p}"), down, &DOWN);
    }
    s.push('\n');
}

fn tree(s: &mut String, on: &str, root: &str, total: u64, shares: &[(&str, Class, u64, u64)]) {
    let _ = writeln!(s, "queue {root} on {on} bandwidth {} max {}", rate(total), rate(total));
    for (short, class, share, min) in shares {
        let mut line = format!("queue {} parent {root} bandwidth {}", qname(root, short), rate(total * share / 1000));
        if *min > 0 {
            let _ = write!(line, " min {}", rate(total * min / 1000));
        }
        if *class == Class::Default {
            line += " default";
        }
        line += " qlimit 128";
        let _ = writeln!(s, "{line}");
    }
}

fn short(c: Class) -> &'static str {
    match c {
        Class::Realtime => "rt",
        Class::Streaming => "str",
        Class::Default => "def",
        Class::Bulk => "bulk",
    }
}

/// `set queue` match rules in ascending class priority: the last match
/// wins, so realtime > streaming > default > bulk on shared addresses.
fn render_classification(s: &mut String, r: &Router, t: &Traffic, nets: &[&Net], wan: bool) {
    let c = &r.cfg;
    let mut ports: Vec<(String, String, Class)> =
        REALTIME_PORTS.iter().map(|(p, ports, _)| (p.to_string(), ports.to_string(), Class::Realtime)).collect();
    ports.push(("tcp".into(), c.ssh.port.to_string(), Class::Realtime));
    ports.push(("udp".into(), "ntp".into(), Class::Realtime));
    if let Some(w) = &c.wireguard {
        ports.push(("udp".into(), w.listen_port.to_string(), Class::Realtime));
    }
    for p in &t.ports {
        let proto = match p.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            _ => "{ tcp udp }",
        };
        for (a, b) in &p.port.0 {
            let ps = if a == b { a.to_string() } else { format!("{a}:{b}") };
            ports.push((proto.into(), ps, p.class));
        }
    }

    let upq = |cl: Class| format!("(up_{}, up_rt)", short(cl));
    s.push_str("# classification: where (destination) beats who (source network)\n");
    for n in nets {
        let i = format!("$if_{}", n.name);
        let root = format!("dn_{}", queue_port(n));
        let q = |cl: Class| format!("({}_{}, {}_rt)", root, short(cl), root);
        let _ = writeln!(s, "match in on {i} tag C_{} set queue {}", short(n.class), q(n.class));
        for cl in Class::ALL {
            if cl != Class::Default {
                let _ = writeln!(s, "match in on {i} to <cls_{}> set queue {}", cl.name(), q(cl));
            }
            for (p, ps, _) in ports.iter().filter(|x| x.2 == cl) {
                let _ = writeln!(s, "match in on {i} proto {p} to port {ps} set queue {}", q(cl));
            }
        }
    }
    if !wan {
        return;
    }
    s.push_str("match out on $wan set queue (up_def, up_rt)\n");
    // who first, then where: the destination class wins (last match), as on the way down
    for cl in Class::ALL.into_iter().filter(|c| *c != Class::Default) {
        let _ = writeln!(s, "match out on $wan tagged C_{} set queue {}", short(cl), upq(cl));
    }
    for cl in Class::ALL {
        if cl != Class::Default {
            let _ = writeln!(s, "match out on $wan to <cls_{}> set queue {}", cl.name(), upq(cl));
        }
        for (p, ps, _) in ports.iter().filter(|x| x.2 == cl) {
            let _ = writeln!(s, "match out on $wan proto {p} to port {ps} set queue {}", upq(cl));
        }
    }
    s.push_str("match out on $wan proto tcp to port 853 user _octodns set queue (up_rt, up_rt)\t# our DNS upstream\n");
    if r.cfg.proxy.is_some() {
        s.push_str("match out on $wan proto tcp user _octoproxy set queue (up_bulk, up_rt)\t# servers' web traffic via the proxy\n");
    }
}
