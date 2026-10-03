//! The firewall as people read it: one row per rule, source → destination,
//! allow / deny / nat. Built from the same resolved router as pf.conf;
//! every row names the pf labels of the rules it stands for (the web UI
//! shows their counters), the router.toml entry it comes from when it has
//! one (`ref`), and its source and destination as router.toml endpoints
//! (`src`, `dst`) so the UI can start a new rule from any row.

use octopus_config::model::{Endpoint, RULE_ALL, RULE_WAN};
use octopus_config::schema::*;
use octopus_config::{Net, Router};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    /// "in" (from the internet), "out" (inside to the internet), "internal"
    pub section: &'static str,
    pub source: String,
    pub destination: String,
    pub service: String,
    /// allow, deny, nat, redirect, proxy
    pub action: &'static str,
    pub labels: Vec<String>,
    pub note: String,
    /// the router.toml entry: `rules`, `forwards` or `links`, and its index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<(&'static str, usize)>,
    pub src: String,
    pub dst: String,
}

struct R {
    section: &'static str,
    source: String,
    destination: String,
    service: String,
    action: &'static str,
    labels: Vec<String>,
    note: String,
    src: String,
    dst: String,
}

impl R {
    fn new(section: &'static str, action: &'static str, src: &str, dst: &str) -> R {
        R {
            section,
            source: String::new(),
            destination: String::new(),
            service: "any".into(),
            action,
            labels: vec![],
            note: String::new(),
            src: src.into(),
            dst: dst.into(),
        }
    }
    fn words(mut self, source: impl Into<String>, destination: impl Into<String>) -> R {
        self.source = source.into();
        self.destination = destination.into();
        self
    }
    fn service(mut self, s: impl Into<String>) -> R {
        self.service = s.into();
        self
    }
    fn labels<I: IntoIterator<Item = String>>(mut self, l: I) -> R {
        self.labels = l.into_iter().collect();
        self
    }
    fn note(mut self, n: impl Into<String>) -> R {
        self.note = n.into();
        self
    }
    fn row(self, r#ref: Option<(&'static str, usize)>) -> Row {
        Row {
            section: self.section,
            source: self.source,
            destination: self.destination,
            service: self.service,
            action: self.action,
            labels: self.labels,
            note: self.note,
            r#ref,
            src: self.src,
            dst: self.dst,
        }
    }
}

fn proto_port(p: Proto, port: Option<&Ports>) -> String {
    let proto = match p {
        Proto::Any => "any",
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::TcpUdp => "tcp/udp",
        Proto::Icmp => "icmp",
        Proto::Gre => "gre",
        Proto::Esp => "esp",
    };
    match port {
        Some(p) => format!("{proto} {p}"),
        None => proto.to_string(),
    }
}

/// A rule endpoint in words: hosts by name, networks with their prefix.
fn describe(r: &Router, s: &str) -> String {
    match r.endpoint(s) {
        Ok(Endpoint::Any) => "anywhere".into(),
        Ok(Endpoint::Router) => "the router".into(),
        Ok(Endpoint::Internal) => "internal ranges".into(),
        Ok(Endpoint::Internet) => "the internet".into(),
        Ok(Endpoint::Net(i)) => net_label(&r.nets[i]),
        Ok(Endpoint::Table(t)) => format!("table {t}"),
        Ok(Endpoint::Addr(a)) => match r.cfg.hosts.iter().find(|h| ipnet::IpNet::from(std::net::IpAddr::V4(h.ip)) == a)
        {
            Some(h) => format!("{} ({})", h.name, h.ip),
            None => a.to_string(),
        },
        Err(_) => s.to_string(),
    }
}

fn host_name(r: &Router, ip: std::net::Ipv4Addr) -> String {
    match r.cfg.hosts.iter().find(|h| h.ip == ip) {
        Some(h) => format!("{} ({ip})", h.name),
        None => ip.to_string(),
    }
}

/// The endpoint token for an address: the host's name when it has one.
fn host_token(r: &Router, ip: std::net::Ipv4Addr) -> String {
    match r.cfg.hosts.iter().find(|h| h.ip == ip) {
        Some(h) => format!("host:{}", h.name),
        None => ip.to_string(),
    }
}

fn net_label(n: &Net) -> String {
    format!("{} ({})", n.name, n.prefix)
}

fn action(a: Action) -> &'static str {
    match a {
        Action::Pass => "allow",
        Action::Block | Action::Reject => "deny",
    }
}

pub fn rows(r: &Router) -> Vec<Row> {
    let c = &r.cfg;
    let mut v = vec![];

    // ---- from the internet: only what is declared (INV-2)
    if c.wan.is_some() {
        for (k, rule) in c.rules.iter().enumerate().filter(|(_, x)| x.network == RULE_WAN) {
            let from = if rule.from == "any" { "internet" } else { rule.from.as_str() };
            v.push(
                R::new("in", action(rule.action), from, &rule.to)
                    .words(describe(r, from), describe(r, &rule.to))
                    .service(proto_port(rule.proto, rule.port.as_ref()))
                    .labels([format!("rule:{}", k + 1)])
                    .note(rule.description.clone().unwrap_or_default())
                    .row(Some(("rules", k))),
            );
        }
        for (k, f) in c.forwards.iter().enumerate() {
            let to = match f.to_port {
                Some(p) => format!("{}, port {p}", host_name(r, f.to)),
                None => host_name(r, f.to),
            };
            let from = if f.from == "any" { "internet" } else { f.from.as_str() };
            v.push(
                R::new("in", "nat", from, &host_token(r, f.to))
                    .words(describe(r, from), to)
                    .service(proto_port(f.proto, Some(&f.port)))
                    .labels([format!("fwd:{}", f.name)])
                    .note(format!("{} (port forward on the WAN address)", f.name))
                    .row(Some(("forwards", k))),
            );
        }
        if let Some(w) = &c.wireguard {
            v.push(
                R::new("in", "allow", "internet", "self")
                    .words("the internet", "the router (WireGuard)")
                    .service(format!("udp {}", w.listen_port))
                    .labels(["wan:wireguard".to_string()])
                    .note("VPN")
                    .row(None),
            );
        }
        let public: Vec<String> =
            c.vhosts.iter().filter(|x| x.public).flat_map(|x| x.split_names(&c.system.domain).1).collect();
        if !public.is_empty() {
            let mut from: Vec<String> =
                c.vhosts.iter().filter(|x| x.public).flat_map(|x| x.allow_from.clone()).collect();
            from.dedup();
            let open = c.vhosts.iter().any(|x| x.public && x.allow_from.is_empty());
            v.push(
                R::new("in", "allow", "internet", "self")
                    .words(if open { "the internet".to_string() } else { from.join(", ") }, "the router (nginx)")
                    .service("tcp 80, 443")
                    .labels(["wan:vhosts".to_string()])
                    .note(format!("public sites: {} (reverse proxy page)", public.join(", ")))
                    .row(None),
            );
        }
        if c.wan.as_ref().is_some_and(|w| w.allow_ping) {
            v.push(
                R::new("in", "allow", "internet", "self")
                    .words("the internet", "the router")
                    .service("ping")
                    .labels(["wan:ping".to_string()])
                    .row(None),
            );
        }
        v.push(
            R::new("in", "deny", "internet", "any")
                .words("the internet", "anything")
                .note("everything not listed above (logged)")
                .row(None),
        );
    }

    // ---- rules on every internal network
    for (k, rule) in c.rules.iter().enumerate().filter(|(_, x)| x.network == RULE_ALL) {
        v.push(explicit(r, k, rule, "internal", "internal ranges"));
    }

    // ---- per network
    for n in &r.nets {
        let me = net_label(n);
        let tok = format!("net:{}", n.name);
        // explicit rules first: they are first-match
        for (k, rule) in c.rules.iter().enumerate().filter(|(_, x)| x.network == n.name) {
            v.push(explicit(r, k, rule, &tok, &me));
        }
        match n.kind {
            Kind::Mgmt => {
                v.push(
                    R::new("internal", "allow", &tok, "any")
                        .words(&me, "everything, the internet too")
                        .labels([format!("{}:mgmt", n.name)])
                        .note("management network: the router included")
                        .row(None),
                );
            }
            Kind::Lan => {
                v.push(
                    R::new("out", "allow", &tok, "internet")
                        .words(&me, "the internet")
                        .labels([format!("{}:internet", n.name)])
                        .note("other internal networks only by a rule")
                        .row(None),
                );
                let mut svc = vec!["dns", "ntp", "ping"];
                if !c.vhosts.is_empty() {
                    svc.push("http/https (vhosts)");
                }
                v.push(
                    R::new("internal", "allow", &tok, "self")
                        .words(&me, "the router")
                        .service(svc.join(", "))
                        .labels(["dns", "ntp", "ping", "vhosts", "dhcp"].iter().map(|s| format!("{}:{s}", n.name)))
                        .note("router services")
                        .row(None),
                );
                v.push(
                    R::new("internal", "deny", &tok, "self")
                        .words(&me, "the router")
                        .service("ssh, web UI")
                        .labels([format!("{}:guard", n.name)])
                        .note("management only from mgmt (INV-1)")
                        .row(None),
                );
            }
            Kind::Open => {
                v.push(
                    R::new("internal", "allow", &tok, "any")
                        .words(&me, "anything, the internet too")
                        .labels([format!("{}:open", n.name)])
                        .note("a tier: what the rules above don't stop")
                        .row(None),
                );
                v.push(
                    R::new("internal", "deny", &tok, "self")
                        .words(&me, "the router")
                        .service("ssh, web UI")
                        .labels([format!("{}:guard", n.name)])
                        .note("unless a rule above allows it")
                        .row(None),
                );
            }
            Kind::Guest => {
                v.push(
                    R::new("out", "allow", &tok, "internet")
                        .words(&me, "the internet")
                        .labels([format!("{}:internet", n.name)])
                        .note("guests: nothing internal")
                        .row(None),
                );
                v.push(
                    R::new("internal", "allow", &tok, "self")
                        .words(&me, "the router")
                        .service("dns, ntp, ping")
                        .labels(["dns", "ntp", "ping", "dhcp"].iter().map(|s| format!("{}:{s}", n.name)))
                        .note("router services")
                        .row(None),
                );
                v.push(
                    R::new("internal", "deny", &tok, "internal")
                        .words(&me, "internal ranges and the router")
                        .service("anything else")
                        .labels([format!("{}:self", n.name)])
                        .note("guests only get out")
                        .row(None),
                );
            }
            Kind::Servers => {
                if c.proxy.is_some() {
                    let hosts: Vec<String> = c
                        .proxy
                        .iter()
                        .flat_map(|p| &p.allow)
                        .filter(|a| a.network == n.name)
                        .flat_map(|a| a.hosts.clone())
                        .collect();
                    v.push(
                        R::new("out", "proxy", &tok, "internet")
                            .words(
                                &me,
                                if hosts.is_empty() {
                                    "nothing (empty allowlist)".to_string()
                                } else {
                                    hosts.join(", ")
                                },
                            )
                            .service("tcp 80, 443")
                            .labels([format!("{}:proxy", n.name)])
                            .note("through octopus-proxy, origins' certificates checked")
                            .row(None),
                    );
                }
                for (k, l) in c.links.iter().enumerate().filter(|(_, l)| l.network == n.name) {
                    v.push(
                        R::new("out", "allow", &tok, &l.to)
                            .words(&me, describe(r, &l.to))
                            .service(proto_port(l.proto, l.port.as_ref()))
                            .labels([format!("link:{}", k + 1)])
                            .note(l.description.clone().unwrap_or_else(|| "direct egress (a link)".into()))
                            .row(Some(("links", k))),
                    );
                }
                v.push(
                    R::new("out", "deny", &tok, "internet")
                        .words(&me, "the internet")
                        .service("anything else")
                        .note("no direct egress (INV-3)")
                        .row(None),
                );
                v.push(
                    R::new("internal", "allow", &tok, "self")
                        .words(&me, "the router")
                        .service("dns, ntp, ping")
                        .labels(["dns", "ntp", "ping", "dhcp"].iter().map(|s| format!("{}:{s}", n.name)))
                        .note("router services")
                        .row(None),
                );
                v.push(
                    R::new("internal", "deny", &tok, "self")
                        .words(&me, "the router")
                        .service("ssh, web UI")
                        .labels([format!("{}:guard", n.name)])
                        .note("management only from mgmt (INV-1)")
                        .row(None),
                );
            }
        }
        // DNS stays with the router (INV-4)
        v.push(
            R::new("out", "redirect", &tok, "internet")
                .words(&me, "any DNS server")
                .service("dns (53)")
                .note("answered by the router instead")
                .row(None),
        );
        let mut dns_block = vec![format!("{}:dot", n.name)];
        let mut what = "DoT (853)".to_string();
        if c.dns.block_public_resolvers {
            dns_block.push(format!("{}:doh", n.name));
            what = "DoT (853), public resolvers' DoH (443)".into();
        }
        v.push(
            R::new("out", "deny", &tok, "internet")
                .words(&me, "public resolvers")
                .service(what)
                .labels(dns_block)
                .note("no way around the router's DNS")
                .row(None),
        );
    }

    if let Some(w) = &c.wireguard {
        let peers =
            |k: Kind| w.peers.iter().filter(|p| p.policy == k).map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
        let m = peers(Kind::Mgmt);
        if !m.is_empty() {
            v.push(
                R::new("internal", "allow", "any", "any")
                    .words(format!("WireGuard peers {m}"), "everything, the internet too")
                    .labels(["wg_mgmt:mgmt".to_string()])
                    .note("mapped to mgmt")
                    .row(None),
            );
        }
        let l = peers(Kind::Lan);
        if !l.is_empty() {
            v.push(
                R::new("out", "allow", "any", "internet")
                    .words(format!("WireGuard peers {l}"), "the internet")
                    .labels(["wg_lan:internet".to_string()])
                    .note("mapped to lan")
                    .row(None),
            );
        }
    }
    v
}

/// An explicit [[rules]] entry; `tok` and `me` stand for its whole network.
fn explicit(r: &Router, k: usize, rule: &Rule, tok: &str, me: &str) -> Row {
    let (src, source) = if rule.from == "any" {
        (tok.to_string(), me.to_string())
    } else if rule.network == RULE_ALL {
        (rule.from.clone(), describe(r, &rule.from))
    } else {
        (rule.from.clone(), format!("{} in {}", describe(r, &rule.from), rule.network))
    };
    let to = r.endpoint(&rule.to).unwrap_or(Endpoint::Any);
    let section = if r.is_internal(&to) { "internal" } else { "out" };
    R::new(section, action(rule.action), &src, &rule.to)
        .words(source, describe(r, &rule.to))
        .service(proto_port(rule.proto, rule.port.as_ref()))
        .labels([format!("rule:{}", k + 1)])
        .note(rule.description.clone().unwrap_or_default())
        .row(Some(("rules", k)))
}
