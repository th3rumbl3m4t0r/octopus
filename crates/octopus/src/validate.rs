//! Native validators (INV-6): each rendered file goes through its owning
//! daemon's parser before anything is applied.

use std::path::Path;

use crate::gens;
use crate::os::{Res, is_openbsd, run};

pub const HICKORY: &str = "/usr/local/sbin/hickory-dns";
pub const OCTOPUS_DNS: &str = "/usr/local/sbin/octopus-dns";

pub struct Outcome {
    pub path: String,
    pub validator: String,
    pub result: Result<(), String>,
}

/// Validate the files of a rendered tree rooted at `root` (a generation's
/// files/ directory or a `build --out` directory).
pub fn tree(root: &Path, paths: &[String], offline: bool) -> Vec<Outcome> {
    tree_with(root, paths, offline, &[])
}

/// `planned`: addresses the tree's own hostname files will create. A
/// validator that binds (nginx -t) can't bind those yet.
pub fn tree_with(root: &Path, paths: &[String], offline: bool, planned: &[String]) -> Vec<Outcome> {
    // interfaces this tree's hostname files create
    let planned_ifs: Vec<String> =
        paths.iter().filter_map(|p| p.strip_prefix("/etc/hostname.")).map(str::to_string).collect();
    let mut out = vec![];
    let at = |p: &str| root.join(p.trim_start_matches('/')).to_string_lossy().into_owned();
    for p in paths {
        let file = at(p);
        let (validator, result): (String, Res<()>) = match p.as_str() {
            "/etc/pf.conf" => pf(&file, offline, &planned_ifs),
            "/etc/dhcpd.conf" => native("dhcpd -n", &["dhcpd", "-n", "-c", &file]),
            "/etc/ntpd.conf" => native("ntpd -n", &["ntpd", "-n", "-f", &file]),
            "/etc/ssh/sshd_config" => native("sshd -t", &["/usr/sbin/sshd", "-t", "-f", &file]),
            "/etc/rad.conf" => native("rad -n", &["rad", "-n", "-f", &file]),
            "/etc/octopus/analyzer.toml" => {
                let bin =
                    std::env::var("OCTOPUS_ANALYZER").unwrap_or_else(|_| "/usr/local/sbin/octopus-analyzer".into());
                native("octopus-analyzer --validate", &[&bin, "--validate", "-c", &file])
            }
            "/etc/octopus/collector.toml" => {
                let bin =
                    std::env::var("OCTOPUS_COLLECTOR").unwrap_or_else(|_| "/usr/local/sbin/octopus-collector".into());
                native("octopus-collector --validate", &[&bin, "--validate", "-c", &file])
            }
            "/etc/octopus/proxy.toml" => {
                let bin = std::env::var("OCTOPUS_PROXY").unwrap_or_else(|_| "/usr/local/sbin/octopus-proxy".into());
                native("octopus-proxy --validate", &[&bin, "--validate", "-c", &file])
            }
            "/etc/dhcp6leased.conf" => native("dhcp6leased -n", &["dhcp6leased", "-n", "-f", &file]),
            "/etc/octopus/dns/named.toml" => {
                let zones = at("/etc/octopus/dns/zones");
                let bin = std::env::var("HICKORY").unwrap_or_else(|_| HICKORY.into());
                native("hickory-dns --validate", &[&bin, "--validate", "-c", &file, "-z", &zones])
            }
            "/etc/octopus/dns/octopus-dns.toml" => {
                let zones = at("/etc/octopus/dns/zones");
                // the build VM validates with the binary it just built
                let bin = std::env::var("OCTOPUS_DNS").unwrap_or_else(|_| OCTOPUS_DNS.into());
                native("octopus-dns --validate", &[&bin, "--validate", "-c", &file, "-z", &zones])
            }
            "/etc/nginx/nginx.conf" => nginx(&file, offline, planned),
            "/etc/acme-client.conf" => native("acme-client -n", &["acme-client", "-n", "-f", &file]),
            "/etc/kea/kea-dhcp4.conf" => kea(&file, offline, &planned_ifs),
            "/etc/octopus/web.toml" => (
                "toml".into(),
                std::fs::read_to_string(&file)
                    .map_err(|e| e.to_string())
                    .and_then(|t| t.parse::<toml::Table>().map(|_| ()).map_err(|e| e.to_string())),
            ),
            _ => continue, // hostname.*, syslog.conf, resolv.conf, zones: compiler-checked
        };
        out.push(Outcome { path: p.clone(), validator, result });
    }
    out
}

/// pfctl -nf. Off the router (`offline`) the ports a ruleset names may not
/// exist, and pf refuses queues on missing interfaces: if that is the only
/// complaint, check again without the queue definitions and say so.
fn pf(file: &str, offline: bool, planned_ifs: &[String]) -> (String, Res<()>) {
    let (name, res) = native("pfctl -nf", &["pfctl", "-nf", file]);
    let Err(e) = &res else { return (name, res) };
    let only_missing = e.lines().skip(1).chain(e.lines().take(1)).all(|l| l.contains("not an interface"));
    if !only_missing {
        return (name, res);
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => return (name, Err(e.to_string())),
    };
    // on the router: only interfaces this generation creates may be missing
    let missing = queue_ifs(&text).into_iter().filter(|i| !crate::os::ok("ifconfig", &[i])).collect::<Vec<_>>();
    if !offline && !missing.iter().all(|i| planned_ifs.contains(i)) {
        return (name, res);
    }
    let stripped: String = text
        .lines()
        .filter(|l| !l.starts_with("queue "))
        .map(|l| match l.find(" set queue ") {
            Some(i) if l.starts_with("match ") => l[..i].to_string(),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let tmp = format!("{file}.noqueue");
    if let Err(e) = std::fs::write(&tmp, stripped) {
        return (name, Err(e.to_string()));
    }
    let (_, res) = native("pfctl -nf", &["pfctl", "-nf", &tmp]);
    let _ = std::fs::remove_file(&tmp);
    let why = if offline {
        "their interfaces aren't on this machine".to_string()
    } else {
        format!("{} not created yet; loaded after netstart", missing.join(" "))
    };
    (format!("pfctl -nf (queues not checked: {why})"), res)
}

/// kea-dhcp4 -t. It refuses interfaces that don't exist; those this
/// generation creates (offline: any) are left out of a copy that is checked.
fn kea(file: &str, offline: bool, planned_ifs: &[String]) -> (String, Res<()>) {
    let (name, mut res) = native("kea-dhcp4 -t", &["kea-dhcp4", "-t", file]);
    let Ok(text) = std::fs::read_to_string(file) else { return (name, res) };
    let body = text.split_once('\n').map(|x| x.1).unwrap_or(&text);
    let Ok(mut conf) = serde_json::from_str::<serde_json::Value>(body) else { return (name, res) };
    let mut skipped: Vec<String> = vec![];
    while let Err(e) = &res {
        // Specified network interface name vport1 for subnet 10.51.3.0/24 is not present in the system
        let Some(i) = e.split("network interface name ").nth(1).and_then(|r| r.split_whitespace().next()) else {
            break;
        };
        let i = i.to_string();
        if skipped.contains(&i) || !(offline || planned_ifs.contains(&i)) {
            break;
        }
        let d = &mut conf["Dhcp4"];
        if let Some(list) = d["interfaces-config"]["interfaces"].as_array_mut() {
            list.retain(|x| x != i.as_str());
        }
        for key in ["subnet4", "shared-networks"] {
            for s in d[key].as_array_mut().into_iter().flatten() {
                if s["interface"] == i.as_str() {
                    s.as_object_mut().map(|o| o.remove("interface"));
                }
            }
        }
        skipped.push(i);
        let tmp = format!("{file}.planned");
        if let Err(e) = std::fs::write(&tmp, conf.to_string()) {
            return (name, Err(e.to_string()));
        }
        res = native("kea-dhcp4 -t", &["kea-dhcp4", "-t", &tmp]).1;
        let _ = std::fs::remove_file(&tmp);
    }
    if skipped.is_empty() {
        (name, res)
    } else {
        (format!("kea-dhcp4 -t (not there yet, created by this generation: {})", skipped.join(" ")), res)
    }
}

/// Interfaces named by `queue ... on IF` lines, macros resolved.
fn queue_ifs(text: &str) -> Vec<String> {
    let macros: std::collections::BTreeMap<&str, &str> = text
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(" = ")?;
            Some((k.trim(), v.split('#').next()?.trim().trim_matches('"')))
        })
        .collect();
    let mut v: Vec<String> = text
        .lines()
        .filter(|l| l.starts_with("queue ") && l.contains(" on "))
        .filter_map(|l| l.split(" on ").nth(1)?.split_whitespace().next())
        .map(|i| {
            i.strip_prefix('$').and_then(|m| macros.get(m)).map(|s| s.to_string()).unwrap_or_else(|| i.to_string())
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// nginx -t. Off the router the leaves don't exist yet: check a copy that
/// points at throwaway certificates instead.
fn nginx(file: &str, offline: bool, planned: &[String]) -> (String, Res<()>) {
    if !offline {
        return nginx_on_router(file, planned);
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => return ("nginx -t".into(), Err(e.to_string())),
    };
    // scratch next to the file (the generation dir or the build output), never
    // a shared /tmp where a predictable name could be planted by another user
    let tmp = std::path::PathBuf::from(format!("{file}.check"));
    let _ = std::fs::remove_dir_all(&tmp);
    if let Err(e) = std::fs::create_dir(&tmp) {
        return ("nginx -t".into(), Err(format!("{}: {e}", tmp.display())));
    }
    let c = octopus_pki::Constraints { dns: vec!["invalid".into()], ips: vec![] };
    let throwaway = octopus_pki::new_root("throwaway", &c)
        .and_then(|root| octopus_pki::issue(&root, &["x.invalid".into()], &[], 1));
    let leaf = match throwaway {
        Ok(l) => l,
        Err(e) => return ("nginx -t".into(), Err(e)),
    };
    let crt = tmp.join("leaf.crt");
    let key = tmp.join("leaf.key");
    let _ = std::fs::write(&crt, &leaf.chain_pem);
    let _ = std::fs::write(&key, &leaf.key_pem);
    let rewritten: String = text
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("ssl_certificate_key ") {
                format!("\t\tssl_certificate_key {};", key.display())
            } else if t.starts_with("ssl_certificate ") {
                format!("\t\tssl_certificate {};", crt.display())
            } else if t.starts_with("proxy_ssl_trusted_certificate ") {
                "\t\t\tproxy_ssl_trusted_certificate /etc/ssl/cert.pem;".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let conf = tmp.join("nginx.conf");
    // off the router any listen address may be missing here
    let addrs: Vec<String> = rewritten
        .lines()
        .filter_map(|l| l.trim().strip_prefix("listen "))
        .filter_map(|l| l.split_whitespace().next()?.rsplit_once(':').map(|(a, _)| a.to_string()))
        .collect();
    let _ = std::fs::write(&conf, rewritten);
    let (name, res) = nginx_on_router(&conf.to_string_lossy(), &addrs);
    let _ = std::fs::remove_dir_all(&tmp);
    (format!("{name} (with throwaway certificates)"), res)
}

/// nginx -t binds its listen sockets. Addresses this generation is about to
/// create can't be bound yet: if those are the only complaint, check a copy
/// without their listen lines (every server also listens on an address that
/// exists, so none is left without one).
fn nginx_on_router(file: &str, planned: &[String]) -> (String, Res<()>) {
    let (name, mut res) = native("nginx -t", &["nginx", "-t", "-q", "-p", "/var/www/", "-c", file]);
    let mut text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => return (name, Err(e.to_string())),
    };
    let mut skipped: Vec<String> = vec![];
    for _ in 0..planned.len() {
        let Err(e) = &res else { break };
        // nginx: [emerg] bind() to 10.99.0.1:80 failed (49: Can't assign requested address)
        let Some(addr) = e
            .split("bind() to ")
            .nth(1)
            .and_then(|r| r.split(" failed (49:").next())
            .and_then(|a| a.rsplit_once(':').map(|(ip, _)| ip.to_string()))
        else {
            break;
        };
        if !planned.contains(&addr) || skipped.contains(&addr) {
            break;
        }
        text = text
            .lines()
            .filter(|l| !l.trim_start().starts_with(&format!("listen {addr}:")))
            .collect::<Vec<_>>()
            .join("\n");
        skipped.push(addr);
        let tmp = format!("{file}.nobind");
        if let Err(e) = std::fs::write(&tmp, &text) {
            return (name, Err(e.to_string()));
        }
        res = native("nginx -t", &["nginx", "-t", "-q", "-p", "/var/www/", "-c", &tmp]).1;
        let _ = std::fs::remove_file(&tmp);
    }
    if skipped.is_empty() {
        (name, res)
    } else {
        (format!("nginx -t (not yet bindable, created by this generation: {})", skipped.join(" ")), res)
    }
}

fn native(name: &str, argv: &[&str]) -> (String, Res<()>) {
    if !is_openbsd() {
        return (format!("{name} (skipped: not OpenBSD)"), Ok(()));
    }
    (name.to_string(), run(argv[0], &argv[1..]).map(|_| ()))
}

/// Validate a stored generation; Err lists every failure.
pub fn generation(n: u32, paths: &[String], planned: &[String]) -> Res<Vec<Outcome>> {
    let root = gens::dir(n).join("files");
    let res = tree_with(&root, paths, false, planned);
    let failed: Vec<String> = res
        .iter()
        .filter_map(|o| o.result.as_ref().err().map(|e| format!("{} ({}): {e}", o.path, o.validator)))
        .collect();
    if failed.is_empty() { Ok(res) } else { Err(failed.join("\n")) }
}
