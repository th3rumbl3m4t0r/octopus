//! `octopus status --json`: a read-only snapshot for the web UI and humans.
//! Runs as root (via doas for the web UI) because pfctl needs /dev/pf.

use std::collections::BTreeMap;
use std::fs;

use serde::Serialize;
use serde_json::{Value, json};

use crate::apply::load_state;
use crate::gens;
use crate::os::{now, run};

#[derive(Serialize, Default)]
struct Iface {
    name: String,
    description: String,
    up: bool,
    status: String,
    inet: Vec<String>,
    /// global and unique local IPv6 addresses (no link-local)
    inet6: Vec<String>,
    ibytes: u64,
    obytes: u64,
    ierrs: u64,
    oerrs: u64,
}

fn ifaces() -> Vec<Iface> {
    let mut map: BTreeMap<String, Iface> = BTreeMap::new();
    let mut cur: Option<String> = None;
    for l in run("ifconfig", &["-a"]).unwrap_or_default().lines() {
        if !l.starts_with(char::is_whitespace) {
            let name = l.split(':').next().unwrap_or("").to_string();
            if name.starts_with("lo") || name.starts_with("enc") || name.starts_with("pflog") {
                cur = None;
                continue;
            }
            let up = l.contains("<UP");
            map.insert(name.clone(), Iface { name: name.clone(), up, ..Default::default() });
            cur = Some(name);
            continue;
        }
        let Some(c) = &cur else { continue };
        let i = map.get_mut(c).unwrap();
        let t = l.trim();
        if let Some(d) = t.strip_prefix("description: ") {
            i.description = d.to_string();
        } else if let Some(s) = t.strip_prefix("status: ") {
            i.status = s.to_string();
        } else if let Some(rest) = t.strip_prefix("inet ") {
            i.inet.push(rest.split_whitespace().next().unwrap_or("").to_string());
        } else if let Some(rest) = t.strip_prefix("inet6 ") {
            let mut w = rest.split_whitespace();
            let a = w.next().unwrap_or("");
            let len = w.nth(1).unwrap_or("");
            if !a.starts_with("fe80") {
                i.inet6.push(format!("{a}/{len}"));
            }
        } else if let Some(s) = t.strip_prefix("state: ") {
            // pppoe(4) session state
            i.status = s.to_string();
        }
    }
    // byte counters: netstat -ibn, first (link) line per interface
    let mut seen = std::collections::BTreeSet::new();
    for l in run("netstat", &["-ibn"]).unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 6 || !seen.insert(f[0].to_string()) {
            continue;
        }
        if let Some(i) = map.get_mut(f[0]) {
            let n = f.len();
            i.ibytes = f[n - 2].parse().unwrap_or(0);
            i.obytes = f[n - 1].parse().unwrap_or(0);
        }
    }
    for l in run("netstat", &["-in"]).unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 9
            && let Some(i) = map.get_mut(f[0])
            && f[2].starts_with("<Link")
        {
            let n = f.len();
            i.ierrs = f[n - 4].parse().unwrap_or(0);
            i.oerrs = f[n - 2].parse().unwrap_or(0);
        }
    }
    map.into_values().collect()
}

fn pf_info() -> Value {
    let si = run("pfctl", &["-si"]).unwrap_or_default();
    let mut states = 0u64;
    let mut enabled = false;
    for l in si.lines() {
        let t = l.trim();
        if t.starts_with("Status: Enabled") {
            enabled = true;
        }
        if let Some(r) = t.strip_prefix("current entries") {
            states = r.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
        }
    }
    // label counters: name evaluations packets bytes ...; pf expands lists
    // (self, port sets) into several rules with one label, so sum them.
    // 7.9 puts column headers ("ID USE/LIMIT ...") above the labels: skip them
    let mut sums: BTreeMap<String, [u64; 3]> = BTreeMap::new();
    for l in run("pfctl", &["-sl"]).unwrap_or_default().lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 4 && f[1..4].iter().all(|x| x.parse::<u64>().is_ok()) {
            let e = sums.entry(f[0].to_string()).or_default();
            for (i, x) in f[1..4].iter().enumerate() {
                e[i] += num(x);
            }
        }
    }
    let labels: Vec<Value> = sums
        .into_iter()
        .map(|(k, v)| json!({"label": k, "evaluations": v[0], "packets": v[1], "bytes": v[2]}))
        .collect();
    let mut tables = vec![];
    for t in run("pfctl", &["-sT"]).unwrap_or_default().lines() {
        let t = t.trim();
        let count = run("pfctl", &["-t", t, "-Ts"]).map(|o| o.lines().count()).unwrap_or(0);
        tables.push(json!({"name": t, "entries": count}));
    }
    let queues = run("pfctl", &["-vsq"]).unwrap_or_default();
    json!({"enabled": enabled, "states": states, "labels": labels, "tables": tables, "queues": queues})
}

fn num(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}

/// Active leases from dhcpd.leases (the last entry for an address wins).
fn leases() -> Vec<Value> {
    leases_from(&fs::read_to_string(KEA_LEASES).unwrap_or_default(), now() as i64)
}

const KEA_LEASES: &str = "/var/lib/kea/kea-leases4.csv";

/// Kea's memfile: CSV, appended to; the last line for an address wins, and
/// an expired or released one (expire in the past, state 2) is gone.
fn leases_from(text: &str, now: i64) -> Vec<Value> {
    let mut lines = text.lines();
    let head: Vec<&str> = lines.next().unwrap_or("").split(',').collect();
    let col = |name: &str| head.iter().position(|h| *h == name);
    let (Some(ia), Some(im), Some(ie)) = (col("address"), col("hwaddr"), col("expire")) else { return vec![] };
    let (ih, is) = (col("hostname"), col("state"));
    let mut by_ip: BTreeMap<String, Value> = BTreeMap::new();
    for l in lines {
        let f: Vec<&str> = l.split(',').collect();
        let Some(ip) = f.get(ia) else { continue };
        let expire: i64 = f.get(ie).and_then(|x| x.parse().ok()).unwrap_or(0);
        let state = is.and_then(|i| f.get(i)).copied().unwrap_or("0");
        if expire <= now || state == "2" {
            by_ip.remove(*ip);
            continue;
        }
        let ends = time_utc(expire);
        by_ip.insert(
            ip.to_string(),
            json!({"ip": ip, "mac": f.get(im).copied().unwrap_or(""), "hostname": ih.and_then(|i| f.get(i)).copied().unwrap_or("").trim_end_matches('.'),
                   "ends": ends, "abandoned": state == "1"}),
        );
    }
    by_ip.into_values().collect()
}

/// `2026/10/01 12:00:00`, UTC
fn time_utc(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    // civil from days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}/{m:02}/{d:02} {:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// IPv6 prefix delegation: what dhcp6leased holds for the WAN.
fn ipv6() -> Value {
    if !crate::os::ok("rcctl", &["get", "dhcp6leased", "status"]) {
        return json!({"enabled": false});
    }
    let conf = fs::read_to_string("/etc/dhcp6leased.conf").unwrap_or_default();
    let wan = conf
        .lines()
        .find_map(|l| l.trim().strip_prefix("request prefix delegation on ").and_then(|r| r.split_whitespace().next()))
        .unwrap_or("")
        .to_string();
    let lease = if wan.is_empty() {
        String::new()
    } else {
        run("dhcp6leasectl", &["show", "interface", &wan]).unwrap_or_default()
    };
    json!({"enabled": true, "wan": wan, "lease": lease.trim()})
}

fn services(names: &[&str]) -> Vec<Value> {
    names
        .iter()
        .map(|n| {
            let enabled = crate::os::ok("rcctl", &["get", n, "status"]);
            let running = enabled && crate::os::ok("rcctl", &["check", n]);
            json!({"name": n, "enabled": enabled, "running": running})
        })
        .collect()
}

/// JSON records from the tail of a log file (syslog prefix stripped).
fn tail_json(path: &str, max: u64) -> Vec<Value> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = fs::File::open(path) else { return vec![] };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(max)));
    let mut text = String::new();
    let _ = f.read_to_string(&mut text);
    text.lines().filter_map(|l| l.find('{').and_then(|i| serde_json::from_str(&l[i..]).ok())).collect()
}

fn top_by(records: &[Value], key: &str, weight: Option<&str>, n: usize) -> Vec<Value> {
    let mut m: BTreeMap<String, u64> = BTreeMap::new();
    for r in records {
        let k = match &r[key] {
            Value::String(s) => s.clone(),
            Value::Null => continue,
            v => v.to_string(),
        };
        *m.entry(k).or_default() += weight.map(|w| r[w].as_u64().unwrap_or(0)).unwrap_or(1);
    }
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.into_iter().take(n).map(|(k, c)| json!({"name": k, "count": c})).collect()
}

/// Flows from octopus-collector: top names and clients by bytes, recent flows.
fn flows() -> Value {
    if !std::path::Path::new("/var/log/octopus-flows").exists() {
        return json!(null);
    }
    let recs = tail_json("/var/log/octopus-flows", 512 * 1024);
    let labelled = recs.iter().filter(|r| r["name"].is_string()).count();
    let recent: Vec<Value> = recs.iter().rev().take(100).cloned().collect();
    json!({
        "flows": recs.len(), "labelled": labelled,
        "top_names": top_by(&recs, "name", Some("bytes"), 15),
        "top_clients": top_by(&recs, "src", Some("bytes"), 15),
        "recent": recent,
    })
}

/// octopus-proxy's decisions.
fn proxy() -> Value {
    if !std::path::Path::new("/var/log/octopus-proxy").exists() {
        return json!(null);
    }
    let recs = tail_json("/var/log/octopus-proxy", 256 * 1024);
    let blocked: Vec<&Value> = recs.iter().filter(|r| r["action"] == "block").collect();
    let recent: Vec<Value> = recs.iter().rev().take(100).cloned().collect();
    json!({
        "events": recs.len(), "blocked": blocked.len(),
        "top_hosts": top_by(&recs, "host", None, 15),
        "recent": recent,
    })
}

/// octopus-analyzer's matches and its pcap files.
fn analyzer() -> Value {
    if !std::path::Path::new("/var/log/octopus-analyzer").exists() {
        return json!(null);
    }
    let recs = tail_json("/var/log/octopus-analyzer", 256 * 1024);
    let mut pcaps = vec![];
    if let Ok(rd) = fs::read_dir("/var/octopus/pcap") {
        for e in rd.flatten() {
            let m = e.metadata().ok();
            pcaps.push(json!({
                "name": e.file_name().to_string_lossy(),
                "bytes": m.as_ref().map(|m| m.len()).unwrap_or(0),
                "modified": m.and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
            }));
        }
    }
    let rules: Vec<Value> = fs::read_to_string("/etc/octopus/analyzer.toml")
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|t| t.get("rules").and_then(|r| r.as_array()).cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|r| json!({"name": r.get("name").and_then(|x| x.as_str()), "if": r.get("interface").and_then(|x| x.as_str()),
                        "fcap": r.get("fcap").and_then(|x| x.as_str()), "regex": r.get("regex").and_then(|x| x.as_str()),
                        "action": r.get("action").and_then(|x| x.as_str())}))
        .collect();
    let recent: Vec<Value> = recs.iter().rev().take(100).cloned().collect();
    json!({"rules": rules, "matches": recs.len(), "by_rule": top_by(&recs, "rule", None, 20), "recent": recent, "pcaps": pcaps})
}

/// The tail of octopus-dns's query log: recent records and top talkers.
fn dns_log() -> Value {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = fs::File::open("/var/log/octopus-dns") else { return json!(null) };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(256 * 1024)));
    let mut text = String::new();
    let _ = f.read_to_string(&mut text);
    let mut recent: Vec<Value> = vec![];
    let mut names: BTreeMap<String, u64> = BTreeMap::new();
    let mut clients: BTreeMap<String, u64> = BTreeMap::new();
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    let mut views: BTreeMap<String, u64> = BTreeMap::new();
    let mut errors = 0u64;
    for l in text.lines() {
        let Some(i) = l.find('{') else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&l[i..]) else { continue };
        *names.entry(v["qname"].as_str().unwrap_or("").to_string()).or_default() += 1;
        *clients.entry(v["client"].as_str().unwrap_or("").to_string()).or_default() += 1;
        *views.entry(v["view"].as_str().unwrap_or("default").to_string()).or_default() += 1;
        if let Some(c) = v["class"].as_str() {
            *classes.entry(c.to_string()).or_default() += 1;
        }
        if v["rcode"].as_str().is_some_and(|r| r != "NoError" && r != "NXDomain") {
            errors += 1;
        }
        recent.push(v);
    }
    let top = |m: BTreeMap<String, u64>| -> Vec<Value> {
        let mut v: Vec<(String, u64)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.into_iter().take(15).map(|(k, n)| json!({"name": k, "count": n})).collect()
    };
    let total = recent.len();
    let recent: Vec<Value> = recent.into_iter().rev().take(100).collect();
    json!({"queries": total, "errors": errors, "recent": recent, "top_names": top(names), "top_clients": top(clients), "classes": top(classes), "views": top(views)})
}

fn octopus_log() -> Vec<String> {
    let text = fs::read_to_string("/var/log/daemon").unwrap_or_default();
    let lines: Vec<String> = text.lines().filter(|l| l.contains(" octopus")).map(str::to_string).collect();
    lines[lines.len().saturating_sub(40)..].to_vec()
}

pub fn collect() -> Value {
    let st = load_state();
    let gens: Vec<Value> = gens::list()
        .iter()
        .rev()
        .take(30)
        .filter_map(|n| gens::load(*n).ok())
        .map(|m| json!({"gen": m.generation, "created": m.created, "source": m.source, "user": m.user, "files": m.files.len(), "warnings": m.warnings}))
        .collect();
    let load = run("sysctl", &["-n", "vm.loadavg"]).unwrap_or_default();
    let boot: u64 = run("sysctl", &["-n", "kern.boottime"]).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    json!({
        "time": now(),
        "hostname": run("hostname", &[]).unwrap_or_default().trim(),
        "release": run("uname", &["-r"]).unwrap_or_default().trim(),
        "uptime": now().saturating_sub(boot),
        "load": load.trim(),
        "state": {
            "current": st.current,
            "confirmed": st.confirmed,
            "pending": st.pending.as_ref().map(|p| json!({"gen": p.generation, "previous": p.previous, "deadline": p.deadline, "remaining": p.deadline.saturating_sub(now())})),
        },
        "generations": gens,
        "interfaces": ifaces(),
        "pf": pf_info(),
        "leases": leases(),
        "services": services(&[
            "octopus_hickory",
            "octopus_dns",
            "octopus_pfhelper",
            "octopus_web",
            "octopus_filterlog",
            "octopus_proxy",
            "octopus_collector",
            "octopus_analyzer",
            "dhcpd",
            "dhcp6leased",
            "rad",
            "nginx",
            "ntpd",
            "sshd",
            "syslogd",
            "pflogd",
        ]),
        "log": octopus_log(),
        "dns": dns_log(),
        "ipv6": ipv6(),
        "flows": flows(),
        "proxy": proxy(),
        "analyzer": analyzer(),
        "aps": crate::ap::load_state(),
        "guard": crate::guard::load_state(),
        // what the access point image needs, and which passphrases exist (names only)
        "ap_key": fs::read_to_string(format!("{}.pub", crate::ap::KEY)).ok().map(|k| k.trim().to_string()),
        "wifi_secrets": wifi_secrets(),
    })
}

/// The names of the wifi_* secrets that are set (never their values).
fn wifi_secrets() -> Vec<String> {
    let text = fs::read_to_string(crate::secret::SECRETS).unwrap_or_default();
    toml::from_str::<toml::Table>(&text)
        .map(|t| t.keys().filter(|k| k.starts_with("wifi_")).cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod lease_tests {
    #[test]
    fn kea_memfile() {
        let csv = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n\
                   192.168.2.10,aa:bb:cc:00:00:01,,7200,2000,3232236032,0,0,desk.,0,,0\n\
                   192.168.2.11,aa:bb:cc:00:00:02,,7200,2000,3232236032,0,0,,0,,0\n\
                   192.168.2.11,aa:bb:cc:00:00:02,,7200,500,3232236032,0,0,,2,,0\n\
                   192.168.2.12,aa:bb:cc:00:00:03,,7200,900,3232236032,0,0,,0,,0\n";
        let l = super::leases_from(csv, 1000);
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0]["hostname"], "desk");
        assert_eq!(super::time_utc(1790859600), "2026/10/01 13:00:00");
    }
}
