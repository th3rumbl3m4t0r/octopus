//! ntpd, sshd, syslogd, the web UI's config, and the rcctl service plan.

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::check::parse_remote;
use octopus_config::schema::*;

use crate::dns::DNS_DIR;
use crate::{Generation, Service, Subsystem, dhcpd, header};

/// syslog.conf as shipped in OpenBSD 7.9's etc set, minus comments.
const SYSLOG_BASE: &str = "\
*.notice;auth,authpriv,cron,ftp,kern,lpr,mail,user.none\t/var/log/messages
kern.debug;syslog,user.info\t\t\t\t/var/log/messages
auth.info\t\t\t\t\t\t/var/log/authlog
authpriv.debug\t\t\t\t\t\t/var/log/secure
cron.info\t\t\t\t\t\t/var/cron/log
daemon.info\t\t\t\t\t\t/var/log/daemon
ftp.info\t\t\t\t\t\t/var/log/xferlog
lpr.debug\t\t\t\t\t\t/var/log/lpd-errs
mail.info\t\t\t\t\t\t/var/log/maillog
";

pub const WEB_CONF: &str = "/etc/octopus/web.toml";
pub const PFHELPER_CONF: &str = "/etc/octopus/pfhelper.conf";

/// octopus-pfhelper's limits for lab_block: the addresses it never takes
/// and how long an entry may live in pf.
fn pfhelper_conf(r: &Router) -> String {
    let expire = r
        .cfg
        .analyzer
        .rules
        .iter()
        .filter(|a| a.action == AnalyzerAction::Block)
        .map(|a| a.block_for)
        .max()
        .unwrap_or(3600);
    let mut s =
        header("#", &["octopus-pfhelper: lab_block never takes these; its entries end in pf after lab_block_expire"]);
    let list: Vec<String> = protected(r).iter().map(|x| format!("\"{x}\"")).collect();
    let _ = writeln!(s, "lab_block_expire = {expire}\nprotected = [{}]", list.join(", "));
    s
}

/// What lab_block may never hold: the router's own addresses, the networks
/// that manage it, the servers it depends on.
pub(crate) fn protected(r: &Router) -> Vec<String> {
    use std::net::IpAddr;
    let c = &r.cfg;
    let mut p: Vec<String> = vec![];
    // every entry a prefix: a host is /32 or /128
    let mut add = |x: String| {
        let x = if x.contains('/') {
            x
        } else if x.contains(':') {
            format!("{x}/128")
        } else {
            format!("{x}/32")
        };
        if !p.contains(&x) {
            p.push(x);
        }
    };
    for n in &r.nets {
        add(n.addr.to_string());
        if let Some(v) = n.v6 {
            add(v.ula.addr().to_string());
        }
    }
    for n in r.nets.iter().filter(|n| r.manages_router(n)) {
        add(n.prefix.to_string());
        if let Some(v) = n.v6 {
            add(v.ula.trunc().to_string());
        }
    }
    if let Some(w) = &c.wireguard {
        add(w.address.addr().to_string());
        for peer in w.peers.iter().filter(|x| x.policy == Kind::Mgmt) {
            add(peer.address.to_string());
        }
    }
    for u in c.dns.upstreams.iter().chain(c.dns.views.iter().flat_map(|v| &v.upstreams)) {
        add(u.ip.to_string());
    }
    for h in c
        .ntp
        .servers
        .iter()
        .map(String::as_str)
        .chain(c.logging.remote.iter().filter_map(|x| parse_remote(x).map(|t| t.1)))
    {
        if let Ok(ip) = h.trim_matches(['[', ']']).parse::<IpAddr>() {
            add(ip.to_string());
        }
    }
    if let Some(WanMode::Static { gateway, .. }) = c.wan.as_ref().and_then(|w| w.mode()) {
        add(gateway.to_string());
    }
    for rt in &c.routes {
        add(rt.via.to_string());
    }
    p
}

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;

    // ---- ntpd
    let mut s = header("#", &[]);
    s += "listen on 127.0.0.1\n";
    if c.ntp.serve {
        for n in &r.nets {
            let _ = writeln!(s, "listen on {}", n.addr);
        }
    }
    for srv in &c.ntp.servers {
        let _ = writeln!(s, "servers {srv}");
    }
    for k in &c.ntp.constraints {
        let k = k.trim_start_matches("https://");
        if k.parse::<std::net::IpAddr>().is_ok() {
            let _ = writeln!(s, "constraint from \"{k}\"");
        } else {
            let _ = writeln!(s, "constraints from \"{k}\"");
        }
    }
    g.file("/etc/ntpd.conf", s, Subsystem::Ntpd);

    // ---- sshd: management addresses only (INV-1)
    let mut s = header("#", &["listens on management addresses only (INV-1)"]);
    for a in r.mgmt_addrs() {
        let _ = writeln!(s, "ListenAddress {a}");
    }
    let _ = writeln!(s, "Port {}", c.ssh.port);
    let _ = writeln!(s, "PermitRootLogin {}", c.ssh.root_login.name());
    let _ = writeln!(s, "PasswordAuthentication {}", if c.ssh.password_auth { "yes" } else { "no" });
    s += "KbdInteractiveAuthentication no\n";
    s += "AuthorizedKeysFile\t.ssh/authorized_keys\n";
    s += "Subsystem\tsftp\t/usr/libexec/sftp-server\n";
    g.file("/etc/ssh/sshd_config", s, Subsystem::Sshd);

    // ---- dhcpleased: an address from the ISP, not its DNS servers
    if let (Some(w), Some(WanMode::Dhcp)) = (&r.wan, c.wan.as_ref().and_then(|w| w.mode())) {
        let s = format!("{}interface {} {{\n\tignore dns\n}}\n", header("#", &[]), w.egress);
        g.file("/etc/dhcpleased.conf", s, Subsystem::Resolv);
    }

    // ---- syslogd
    let mut s = header("#", &[]);
    s += SYSLOG_BASE;
    if c.dns.engine == DnsEngine::OctopusDns {
        s += "local5.info\t\t\t\t\t\t/var/log/octopus-dns\n";
    }
    if c.proxy.is_some() {
        s += "local3.info\t\t\t\t\t\t/var/log/octopus-proxy\n";
    }
    let collector = c.logging.pflow.as_deref().is_some_and(|p| p.starts_with("127."));
    if collector {
        s += "local2.info\t\t\t\t\t\t/var/log/octopus-flows\n";
    }
    if crate::analyzer::running(r) {
        s += "local1.info\t\t\t\t\t\t/var/log/octopus-analyzer\n";
    }
    for remote in &c.logging.remote {
        if let Some((proto, host, port)) = parse_remote(remote) {
            let target = match port {
                Some(p) => format!("@{proto}://{host}:{p}"),
                None => format!("@{proto}://{host}"),
            };
            let _ = writeln!(s, "*.*\t\t\t\t\t\t\t{target}");
        }
    }
    g.file("/etc/syslog.conf", s, Subsystem::Syslogd);

    // ---- flow collector (phase 6): pflow to loopback means it runs here
    if collector {
        let mut s = header("#", &["octopus-collector: pflow's flows, labelled with the names clients looked up"]);
        let _ = writeln!(
            s,
            "user = \"_octoflow\"\nipfix = \"{}\"\ndns = \"{}\"\ndns_from = \"{}\"",
            crate::dns::COLLECTOR_IPFIX,
            crate::dns::COLLECTOR_DNS,
            crate::dns::COLLECTOR_FEED
        );
        for n in &r.nets {
            let _ = writeln!(s, "\n[[networks]]\nname = \"{}\"\nprefix = \"{}\"", n.name, n.prefix);
        }
        g.file("/etc/octopus/collector.toml", s, Subsystem::Collector);
    }

    // ---- web UI
    if c.web.enabled {
        let mut s = header("#", &["read by octopus-web; it listens on management addresses only (INV-1)"]);
        let addrs: Vec<String> = r.mgmt_addrs().iter().map(|a| format!("\"{a}:{}\"", c.web.port)).collect();
        let _ = writeln!(s, "listen = [{}]", addrs.join(", "));
        let _ = writeln!(s, "hostname = \"{}\"", c.system.hostname);
        s += "cert = \"/etc/octopus/web/cert.pem\"\n";
        s += "key = \"/etc/octopus/web/key.pem\"\n";
        s += "users = \"/etc/octopus/web/users\"\n";
        g.file(WEB_CONF, s, Subsystem::Web);
    }

    // ---- services
    let dhcp = dhcpd::serving(r);
    let wan_dhcp = matches!(c.wan.as_ref().and_then(|w| w.mode()), Some(WanMode::Dhcp));
    if c.dns.engine == DnsEngine::OctopusDns {
        g.file(PFHELPER_CONF, pfhelper_conf(r), Subsystem::Dns);
    }
    let mut svc = |name: &str, enabled: bool, flags: Option<String>, sub: Subsystem| {
        let restart = name != "pflogd";
        g.services.push(Service { name: name.into(), enabled, flags, subsystem: sub, restart });
    };
    // Kea (its interfaces are in its config); base dhcpd is turned off by
    // apply when an older generation had it on
    svc("octopus_kea", dhcp, None, Subsystem::Dhcpd);
    svc("ntpd", true, None, Subsystem::Ntpd);
    svc("sshd", true, None, Subsystem::Sshd);
    // TLS to the log server: its CA (-C), our client certificate (-c, -k)
    let mut sflags = vec![];
    if let Some(ca) = &c.logging.tls_ca {
        sflags.push(format!("-C {ca}"));
    }
    if let (Some(cert), Some(key)) = (&c.logging.tls_cert, &c.logging.tls_key) {
        sflags.push(format!("-c {cert} -k {key}"));
    }
    svc("syslogd", true, Some(sflags.join(" ")), Subsystem::Syslogd);
    svc("octopus_filterlog", c.logging.pf, None, Subsystem::Syslogd);
    svc("pflogd", true, None, Subsystem::Pf);
    // the router resolves through its own DNS service; nothing else may
    // rewrite resolv.conf (resolvd would put the ISP's servers first)
    svc("resolvd", false, None, Subsystem::Resolv);
    if wan_dhcp {
        svc("dhcpleased", true, None, Subsystem::Resolv);
    }
    svc("unwind", false, None, Subsystem::Dns);
    let phase_b = c.dns.engine == DnsEngine::OctopusDns;
    svc("octopus_hickory", !phase_b, (!phase_b).then(|| format!("-q -c {DNS_DIR}/named.toml")), Subsystem::Dns);
    svc("octopus_pfhelper", phase_b, None, Subsystem::Dns);
    svc("octopus_dns", phase_b, phase_b.then(|| format!("-c {DNS_DIR}/octopus-dns.toml")), Subsystem::Dns);
    svc("octopus_web", c.web.enabled, None, Subsystem::Web);
    svc("octopus_collector", collector, None, Subsystem::Collector);
    let v6 = c.ipv6.mode == Ipv6Mode::Pd;
    // prefix delegation needs a WAN to ask on
    svc("dhcp6leased", v6 && c.wan.is_some(), None, Subsystem::Dhcp6);
    svc("rad", v6, None, Subsystem::Rad);
}
