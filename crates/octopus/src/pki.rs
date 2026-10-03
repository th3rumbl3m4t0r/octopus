//! `octopus pki`: the services root on the router.
//!
//!   init   (offline, once) root + intermediate into a directory; copy
//!          root.crt, intermediate.crt and intermediate.key to /etc/octopus/pki
//!          on the router and keep root.key somewhere offline
//!   renew  (router, daily) issue or renew the web UI's and each vhost's leaf:
//!          missing, expiring within 30 days, or names changed; public vhosts'
//!          Let's Encrypt certificates through acme-client (a placeholder until
//!          the first one arrives, so nginx can start)
//!   status list the leaves

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use octopus_config::Router;
use octopus_config::schema::WebCertificate;
use octopus_pki::{Ca, Constraints};
use octopus_render::nginx::{ACME_CONF, LEAF_DIR, acme_paths, leaf_paths};
use serde::{Deserialize, Serialize};

use crate::os::{self, Res, log, now};

pub const DIR: &str = "/etc/octopus/pki";
const DAYS: i64 = 90;
const RENEW_BEFORE: i64 = 30 * 86400;

pub fn constraints(r: &Router) -> Constraints {
    let mut ips: Vec<ipnet::IpNet> = r.nets.iter().map(|n| ipnet::IpNet::V4(n.prefix)).collect();
    if let Some(w) = &r.cfg.wireguard {
        ips.push(ipnet::IpNet::V4(w.address.trunc()));
    }
    Constraints { dns: vec![r.cfg.system.domain.clone()], ips }
}

pub fn init(r: &Router, out: &Path) -> Res<()> {
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    for f in ["root.key", "intermediate.key"] {
        if out.join(f).exists() {
            return Err(format!("{} exists; refusing to overwrite a CA", out.join(f).display()));
        }
    }
    let c = constraints(r);
    let root = octopus_pki::new_root(&format!("Octopus services root ({})", r.cfg.system.domain), &c)?;
    let inter = octopus_pki::new_intermediate(
        &root,
        &format!("Octopus services intermediate ({})", r.cfg.system.hostname),
        &c,
    )?;
    let w = |n: &str, s: &str, mode: u32| os::write_atomic(&out.join(n), s.as_bytes(), mode, "root", "wheel");
    w("root.crt", &root.cert_pem, 0o644)?;
    w("root.key", &root.key_pem, 0o600)?;
    w("intermediate.crt", &inter.cert_pem, 0o644)?;
    w("intermediate.key", &inter.key_pem, 0o600)?;
    println!("services root for {} ({} address ranges) in {}", c.dns.join(", "), c.ips.len(), out.display());
    println!("router: copy root.crt, intermediate.crt, intermediate.key to {DIR}/ (key mode 0600)");
    println!("offline: keep root.key; install root.crt on the owner's devices");
    Ok(())
}

fn intermediate() -> Option<Ca> {
    let cert_pem = fs::read_to_string(format!("{DIR}/intermediate.crt")).ok()?;
    let key_pem = fs::read_to_string(format!("{DIR}/intermediate.key")).ok()?;
    Some(Ca { cert_pem, key_pem })
}

pub fn present() -> bool {
    Path::new(&format!("{DIR}/intermediate.key")).exists()
}

#[derive(Clone)]
struct Want {
    name: String,
    dns: Vec<String>,
    ips: Vec<IpAddr>,
    cert: PathBuf,
    key: PathBuf,
    group: &'static str,
    key_mode: u32,
    service: &'static str,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Meta {
    names: Vec<String>,
    not_after: i64,
}

fn wants(r: &Router) -> Vec<Want> {
    let c = &r.cfg;
    let mut v = vec![];
    if c.web.enabled && c.web.certificate == WebCertificate::Services {
        v.push(Want {
            name: "web".into(),
            dns: vec![format!("{}.{}", c.system.hostname, c.system.domain)],
            ips: r.mgmt_addrs().into_iter().map(IpAddr::V4).collect(),
            cert: "/etc/octopus/web/cert.pem".into(),
            key: "/etc/octopus/web/key.pem".into(),
            group: "_octoweb",
            key_mode: 0o640,
            service: "octopus_web",
        });
    }
    for vh in &c.vhosts {
        let Some((first, dns)) = leaf_paths(vh, &c.system.domain) else { continue };
        let fqdn = first;
        v.push(Want {
            name: fqdn.clone(),
            dns,
            ips: vec![],
            cert: format!("{LEAF_DIR}/{fqdn}.crt").into(),
            key: format!("{LEAF_DIR}/{fqdn}.key").into(),
            group: "wheel",
            key_mode: 0o600,
            service: "nginx",
        });
    }
    v
}

fn meta_path(w: &Want) -> PathBuf {
    PathBuf::from(format!("{LEAF_DIR}/{}.json", w.name))
}

fn names(w: &Want) -> Vec<String> {
    w.dns.iter().cloned().chain(w.ips.iter().map(IpAddr::to_string)).collect()
}

/// Issue what is missing (and, unless `missing_only`, what expires soon or
/// names something else). Returns the services to reload.
pub fn renew(r: &Router, force: bool, missing_only: bool) -> Res<Vec<&'static str>> {
    let ws = wants(r);
    let mut reload = acme(r, missing_only)?;
    if !present() {
        if ws.iter().any(|w| w.service == "nginx") {
            return Err(format!(
                "[[vhosts]] with internal names need the services intermediate in {DIR} (octopus pki init)"
            ));
        }
        return Ok(reload);
    }
    let inter = intermediate().ok_or("cannot read the intermediate")?;
    let permitted = octopus_pki::permitted(&inter.cert_pem)?;
    fs::create_dir_all(LEAF_DIR).map_err(|e| format!("{LEAF_DIR}: {e}"))?;
    for w in &ws {
        // only names the root may vouch for: a leaf naming anything else (an
        // address range added after `pki init`) fails verification outright,
        // and browsers don't let you click through a name-constraints error
        let covered;
        let w = match &permitted {
            Some(p) => {
                let (dns, ips, dropped) = p.vouched(&w.dns, &w.ips);
                if !dropped.is_empty() {
                    log(&format!(
                        "pki: {}: the services root doesn't cover {}; left out of its certificate (octopus pki init for a wider root)",
                        w.name,
                        dropped.join(" ")
                    ));
                }
                if dns.is_empty() && ips.is_empty() {
                    log(&format!(
                        "pki: {}: no name the services root covers; its certificate is left as it is",
                        w.name
                    ));
                    continue;
                }
                covered = Want { dns, ips, ..w.clone() };
                &covered
            }
            None => w,
        };
        let meta: Option<Meta> = fs::read_to_string(meta_path(w)).ok().and_then(|t| serde_json::from_str(&t).ok());
        let fresh = meta.as_ref().is_some_and(|m| m.names == names(w) && m.not_after - now() as i64 > RENEW_BEFORE);
        let need = force || !w.cert.exists() || !w.key.exists() || (!missing_only && !fresh) || meta.is_none();
        if !need {
            continue;
        }
        let leaf = octopus_pki::issue(&inter, &w.dns, &w.ips, DAYS)?;
        os::write_atomic(&w.key, leaf.key_pem.as_bytes(), w.key_mode, "root", w.group)?;
        os::write_atomic(&w.cert, leaf.chain_pem.as_bytes(), 0o644, "root", w.group)?;
        let m = Meta { names: names(w), not_after: leaf.not_after };
        os::write_atomic(&meta_path(w), serde_json::to_string(&m).unwrap().as_bytes(), 0o644, "root", "wheel")?;
        log(&format!("pki: issued {} for {} (90 days)", w.cert.display(), names(w).join(" ")));
        if !reload.contains(&w.service) {
            reload.push(w.service);
        }
    }
    Ok(reload)
}

/// Public vhosts' certificates. A missing one gets a self-signed placeholder
/// (nginx won't start without the file) marked for replacement; unless
/// `missing_only` (apply), acme-client then gets or renews the real one,
/// forced while the placeholder is there. A failure is logged and left for
/// the next run: the site keeps its current certificate.
fn acme(r: &Router, missing_only: bool) -> Res<Vec<&'static str>> {
    let domain = &r.cfg.system.domain;
    let mut reload = vec![];
    if !missing_only {
        // markers of sites that are gone (their files stay, unused)
        let wanted: Vec<String> = r.cfg.vhosts.iter().filter_map(|v| acme_paths(v, domain)).map(|(c, _)| c).collect();
        for e in fs::read_dir("/etc/ssl").map(|d| d.flatten().collect::<Vec<_>>()).unwrap_or_default() {
            let p = e.path().to_string_lossy().into_owned();
            if let Some(cert) = p.strip_suffix(".octopus-placeholder")
                && !wanted.iter().any(|w| w == cert)
            {
                let _ = fs::remove_file(&p);
            }
        }
    }
    for v in &r.cfg.vhosts {
        let Some((cert, key)) = acme_paths(v, domain) else { continue };
        let names = v.split_names(domain).1;
        let handle = names[0].clone();
        let marker = format!("{cert}.octopus-placeholder");
        if !Path::new(&cert).exists() || !Path::new(&key).exists() {
            let out = std::process::Command::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj"])
                // a CN holds at most 64 characters
                .arg(if handle.len() <= 64 {
                    format!("/O=octopus placeholder/CN={handle}")
                } else {
                    "/O=octopus placeholder".to_string()
                })
                // acme-client reads the names of the certificate it replaces
                .arg("-addext")
                .arg(format!(
                    "subjectAltName={}",
                    names.iter().map(|n| format!("DNS:{n}")).collect::<Vec<_>>().join(",")
                ))
                .args(["-keyout", &key, "-out", &cert])
                .output()
                .map_err(|e| format!("openssl: {e}"))?;
            if !out.status.success() {
                return Err(format!("placeholder for {handle}: {}", String::from_utf8_lossy(&out.stderr).trim()));
            }
            let _ = fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600));
            fs::write(&marker, b"").map_err(|e| format!("{marker}: {e}"))?;
            log(&format!("pki: placeholder certificate for {handle} until acme-client gets one"));
            reload.push("nginx");
        }
        if missing_only {
            continue;
        }
        let placeholder = Path::new(&marker).exists();
        let mut cmd = std::process::Command::new("acme-client");
        cmd.args(["-f", ACME_CONF]);
        if placeholder {
            cmd.arg("-F");
        }
        match cmd.arg(&handle).output() {
            Ok(o) if o.status.code() == Some(0) => {
                let _ = fs::remove_file(&marker);
                log(&format!("pki: acme-client: new certificate for {handle}"));
                if !reload.contains(&"nginx") {
                    reload.push("nginx");
                }
            }
            Ok(o) if o.status.code() == Some(2) => {}
            Ok(o) => log(&format!("pki: acme-client {handle} failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => log(&format!("pki: acme-client: {e}")),
        }
    }
    Ok(reload)
}

/// The interception root (design 14): made on the router, key readable by
/// root only. octopus-proxy reads it at start and hands it to its signer
/// process; the part that talks to servers and origins never has it. No name
/// constraints are possible (it must vouch for any allowed name), so only
/// servers may trust it.
pub fn intercept_init(r: &Router) -> Res<()> {
    use octopus_render::proxy::{CA_CERT, CA_KEY};
    r.cfg.proxy.as_ref().ok_or("router.toml has no [proxy]")?;
    if Path::new(CA_KEY).exists() {
        return Err(format!("{CA_KEY} exists; refusing to replace the interception root"));
    }
    let ca = octopus_pki::new_intercept_root()?;
    os::write_atomic(Path::new(CA_KEY), ca.key_pem.as_bytes(), 0o600, "root", "wheel")?;
    os::write_atomic(Path::new(CA_CERT), ca.cert_pem.as_bytes(), 0o644, "root", "wheel")?;
    log("pki: made the interception root (servers only)");
    println!("interception root: {CA_CERT} (give it to the servers, never to personal devices)");
    Ok(())
}

pub fn status(r: &Router) {
    if !present() {
        println!("no services intermediate in {DIR}; the web UI uses its self-signed certificate");
    } else if r.cfg.web.certificate == WebCertificate::SelfSigned {
        println!("web UI: its self-signed certificate ([web] certificate = \"self-signed\"), not issued here");
    }
    for w in wants(r) {
        let meta: Option<Meta> = fs::read_to_string(meta_path(&w)).ok().and_then(|t| serde_json::from_str(&t).ok());
        match meta {
            Some(m) => {
                println!("{:<34} {:>4} days left  {}", w.name, (m.not_after - now() as i64) / 86400, m.names.join(" "))
            }
            None => println!("{:<34} not issued", w.name),
        }
    }
}
