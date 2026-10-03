//! /etc/nginx/nginx.conf for [[vhosts]], and /etc/acme-client.conf for the
//! public ones. Internal names are served on the router's internal
//! addresses with a leaf from the services intermediate; public names also
//! on every address (pf opens only tcp 80/443 on the WAN, INV-2) with a
//! Let's Encrypt certificate or the site's own `cert`/`key`.

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::schema::{CLOUDFLARE, Vhost};

use crate::{Generation, Service, Subsystem, header};

pub const LEAF_DIR: &str = "/etc/octopus/pki/leaf";
const SYSTEM_CA: &str = "/etc/ssl/cert.pem";
pub const ACME_CONF: &str = "/etc/acme-client.conf";
/// acme-client writes http-01 tokens here; nginx (chrooted to /var/www)
/// serves them as /acme/
pub const ACME_DIR: &str = "/var/www/acme";
const ACME_DIR_CHROOT: &str = "/acme/";

/// Certificate and key acme-client keeps for a public site (named by its
/// first outside name).
pub fn acme_paths(v: &Vhost, domain: &str) -> Option<(String, String)> {
    if !v.acme(domain) {
        return None;
    }
    let first = v.split_names(domain).1.into_iter().next()?;
    Some((format!("/etc/ssl/{first}.fullchain.pem"), format!("/etc/ssl/private/{first}.key")))
}

/// The services leaf for a site's internal names (file named by the first).
pub fn leaf_paths(v: &Vhost, domain: &str) -> Option<(String, Vec<String>)> {
    if v.cert.is_some() {
        return None;
    }
    let inside = v.split_names(domain).0;
    let first = inside.first()?.clone();
    Some((first, inside))
}

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;
    g.services.push(Service {
        name: "nginx".into(),
        enabled: !c.vhosts.is_empty(),
        flags: None,
        subsystem: Subsystem::Nginx,
        restart: true,
    });
    if c.vhosts.is_empty() {
        return;
    }
    let domain = &c.system.domain;
    let mut addrs: Vec<String> = r.nets.iter().map(|n| n.addr.to_string()).collect();
    addrs.extend(r.nets.iter().filter_map(|n| n.v6).map(|v| format!("[{}]", v.ula.addr())));
    if let Some(w) = &c.wireguard {
        addrs.push(w.address.addr().to_string());
    }
    let listen = |port: &str, extra: &str| -> String {
        addrs.iter().map(|a| format!("\t\tlisten {a}:{port}{extra};\n")).collect()
    };
    // every address: the WAN's may change (PPPoE, DHCP); pf decides who gets in
    let anywhere = |port: &str, extra: &str| format!("\t\tlisten {port}{extra};\n\t\tlisten [::]:{port}{extra};\n");
    let public = c.vhosts.iter().any(|v| v.public);

    let mut s = header(
        "#",
        &["vhosts: internal names with leaves from the services intermediate, public names on every address"],
    );
    s += "worker_processes 1;\nworker_rlimit_nofile 1024;\nerror_log logs/error.log warn;\n\n";
    s += "events {\n\tworker_connections 512;\n}\n\n";
    s += "http {\n";
    s += "\tserver_tokens off;\n\taccess_log logs/access.log;\n";
    s += "\tssl_protocols TLSv1.2 TLSv1.3;\n\tssl_session_cache shared:SSL:1m;\n\tssl_session_timeout 1h;\n";
    s += "\tclient_max_body_size 64m;\n\tproxy_read_timeout 300s;\n\n";
    s += "\tmap $http_upgrade $connection_upgrade {\n\t\tdefault upgrade;\n\t\t'' close;\n\t}\n\n";

    s += "\t# plain http: to https\n\tserver {\n";
    s += &listen("80", " default_server");
    s += "\t\treturn 301 https://$host$request_uri;\n\t}\n\n";
    s += "\t# names we don't serve: no certificate, no handshake\n\tserver {\n";
    s += &listen("443", " ssl default_server");
    s += "\t\tssl_reject_handshake on;\n\t}\n";
    if public {
        s += "\n\t# the internet side: Let's Encrypt's http-01 tokens, everything else to https\n\tserver {\n";
        s += &anywhere("80", " default_server");
        let _ = writeln!(s, "\t\tlocation ^~ /.well-known/acme-challenge/ {{\n\t\t\talias {ACME_DIR_CHROOT};\n\t\t}}");
        s += "\t\tlocation / {\n\t\t\treturn 301 https://$host$request_uri;\n\t\t}\n\t}\n";
        s += "\tserver {\n";
        s += &anywhere("443", " ssl default_server");
        s += "\t\tssl_reject_handshake on;\n\t}\n";
    }

    for v in &c.vhosts {
        let outside = v.split_names(domain).1;
        let desc = v.description.as_ref().map(|d| format!(": {}", d.replace('\n', " "))).unwrap_or_default();
        // (names, certificate, key, on every address)
        let mut blocks: Vec<(Vec<String>, String, String, bool)> = vec![];
        if let (Some(cert), Some(key)) = (&v.cert, &v.key) {
            blocks.push((v.names(domain), cert.clone(), key.clone(), v.public));
        } else {
            if let Some((first, names)) = leaf_paths(v, domain) {
                blocks.push((names, format!("{LEAF_DIR}/{first}.crt"), format!("{LEAF_DIR}/{first}.key"), false));
            }
            if let Some((cert, key)) = acme_paths(v, domain) {
                blocks.push((outside.clone(), cert, key, true));
            }
        }
        for (names, cert, key, everywhere) in blocks {
            let _ = writeln!(s, "\n\t# {} ({}){desc}", v.name, names.join(" "));
            s += "\tserver {\n";
            s += &listen("443", " ssl");
            if everywhere {
                s += &anywhere("443", " ssl");
            }
            let _ = writeln!(s, "\t\tserver_name {};", names.join(" "));
            let _ = writeln!(s, "\t\tssl_certificate {cert};");
            let _ = writeln!(s, "\t\tssl_certificate_key {key};");
            s += "\t\tadd_header Strict-Transport-Security \"max-age=31536000\" always;\n";
            if everywhere && v.allow_from.iter().any(|a| a == "cloudflare") {
                // the visitor's address instead of Cloudflare's, for the log and the upstream
                for n in CLOUDFLARE {
                    let _ = writeln!(s, "\t\tset_real_ip_from {n};");
                }
                s += "\t\treal_ip_header CF-Connecting-IP;\n";
            }
            location(&mut s, v);
            s += "\t}\n";
        }
    }
    s += "}\n";
    g.file("/etc/nginx/nginx.conf", s, Subsystem::Nginx);

    let acme: Vec<&Vhost> = c.vhosts.iter().filter(|v| v.acme(domain)).collect();
    if !acme.is_empty() {
        let mut a = header("#", &["Let's Encrypt for the public vhosts; octopus pki renew runs acme-client daily"]);
        a += "authority letsencrypt {\n\tapi url \"https://acme-v02.api.letsencrypt.org/directory\"\n";
        a += "\taccount key \"/etc/acme/letsencrypt-privkey.pem\"\n}\n";
        for v in acme {
            let outside = v.split_names(domain).1;
            let (cert, key) = acme_paths(v, domain).unwrap_or_default();
            let _ = writeln!(a, "\n# {}\ndomain {} {{", v.name, outside[0]);
            if outside.len() > 1 {
                let _ = writeln!(a, "\talternative names {{ {} }}", outside[1..].join(" "));
            }
            let _ = writeln!(a, "\tdomain key \"{key}\"\n\tdomain full chain certificate \"{cert}\"");
            let _ = writeln!(a, "\tchallengedir \"{ACME_DIR}\"\n\tsign with letsencrypt\n}}");
        }
        g.file(ACME_CONF, a, Subsystem::Nginx);
    }
}

fn location(s: &mut String, v: &Vhost) {
    *s += "\t\tlocation / {\n";
    let _ = writeln!(s, "\t\t\tproxy_pass {};", v.upstream);
    *s += "\t\t\tproxy_set_header Host $host;\n";
    *s += "\t\t\tproxy_set_header X-Real-IP $remote_addr;\n";
    *s += "\t\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n";
    *s += "\t\t\tproxy_set_header X-Forwarded-Proto https;\n";
    if v.upstream.starts_with("https://") {
        *s += "\t\t\tproxy_ssl_server_name on;\n";
        if let Some(n) = &v.upstream_name {
            let _ = writeln!(s, "\t\t\tproxy_ssl_name {n};");
        }
        if v.verify_upstream {
            let ca = v.upstream_ca.as_deref().unwrap_or(SYSTEM_CA);
            let _ = writeln!(
                s,
                "\t\t\tproxy_ssl_verify on;\n\t\t\tproxy_ssl_trusted_certificate {ca};\n\t\t\tproxy_ssl_verify_depth 3;"
            );
        } else {
            *s += "\t\t\tproxy_ssl_verify off;\t# verify_upstream = false\n";
        }
    }
    if v.websocket {
        *s += "\t\t\tproxy_http_version 1.1;\n";
        *s += "\t\t\tproxy_set_header Upgrade $http_upgrade;\n";
        *s += "\t\t\tproxy_set_header Connection $connection_upgrade;\n";
    }
    *s += "\t\t}\n";
}
