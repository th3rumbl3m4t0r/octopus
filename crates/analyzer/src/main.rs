//! octopus-analyzer (phase 6): the passive lab.
//!
//! Each rule is an FCAP expression (translated to a pcap filter by the
//! compiler) on one interface, an optional payload regex, an action. For
//! every rule it opens bpf(4), installs the filter and locks it (BIOCLOCK),
//! then the whole process drops to _octoflow and pledges. Matching packets
//! are logged as JSON (syslog local1, /var/log/octopus-analyzer), kept in
//! ring-buffered pcap files, and with action = "block" their source goes into
//! pf's <lab_block> through octopus-pfhelper for block_for seconds.
//!
//! Nothing here is inline: pf forwards packets whether or not this runs.
//!
//! `--oneshot request.json` is the UI's capture window: one filter, a few
//! seconds, the packets back as JSON on stdout (see oneshot.rs).

// capturing is OpenBSD-only; elsewhere this builds for tests and fuzzing
#![cfg_attr(not(target_os = "openbsd"), allow(dead_code))]

#[cfg(target_os = "openbsd")]
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
#[cfg(target_os = "openbsd")]
use std::time::{Duration, Instant};

use serde::Deserialize;

#[cfg(target_os = "openbsd")]
mod bpf;
mod oneshot;

const LOST: &str = "pfhelper connection lost";
const RING_FILES: usize = 4;
const RING_BYTES: u64 = 16 << 20;
const LOG_PER_SEC: u32 = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    user: String,
    pcap_dir: String,
    pfhelper: Option<String>,
    rules: Vec<RuleConf>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RuleConf {
    name: String,
    interface: String,
    /// the original expression, for people reading the file
    #[allow(dead_code)]
    fcap: String,
    filter: String,
    regex: Option<String>,
    action: String,
    block_for: u64,
    pcap: bool,
}

struct Rule {
    conf: RuleConf,
    re: Option<pcre2::bytes::Regex>,
    dlt: i32,
    fd: i32,
    ring: Option<Ring>,
    matches: u64,
    logged_this_sec: (u64, u32),
}

/// Ring-buffered pcap files: name-0.pcap .. name-3.pcap, 16 MB each.
struct Ring {
    dir: String,
    name: String,
    idx: usize,
    file: Option<File>,
    size: u64,
    dlt: i32,
}

impl Ring {
    fn write(&mut self, sec: u32, usec: u32, pkt: &[u8], orig_len: u32) {
        if self.file.is_none() || self.size >= RING_BYTES {
            if self.file.is_some() {
                self.idx = (self.idx + 1) % RING_FILES;
            }
            let path = format!("{}/{}-{}.pcap", self.dir, self.name, self.idx);
            let Ok(mut f) = File::create(&path) else { return };
            let h = pcap_header(self.dlt);
            let _ = f.write_all(&h);
            self.size = h.len() as u64;
            self.file = Some(f);
        }
        if let Some(f) = &mut self.file {
            let mut r = Vec::with_capacity(16 + pkt.len());
            pcap_record(&mut r, sec, usec, pkt, orig_len);
            if f.write_all(&r).is_ok() {
                self.size += r.len() as u64;
            }
        }
    }
}

/// Classic pcap file header: magic, 2.4, tz 0, sigfigs 0, snaplen, link type.
fn pcap_header(dlt: i32) -> Vec<u8> {
    let mut h = vec![];
    h.extend(0xa1b2_c3d4u32.to_le_bytes());
    h.extend(2u16.to_le_bytes());
    h.extend(4u16.to_le_bytes());
    h.extend([0u8; 8]);
    h.extend(65535u32.to_le_bytes());
    h.extend((dlt as u32).to_le_bytes());
    h
}

fn pcap_record(out: &mut Vec<u8>, sec: u32, usec: u32, pkt: &[u8], orig_len: u32) {
    out.extend(sec.to_le_bytes());
    out.extend(usec.to_le_bytes());
    out.extend((pkt.len() as u32).to_le_bytes());
    out.extend(orig_len.to_le_bytes());
    out.extend(pkt);
}

/// Payload expressions are PCRE (lookaround, backreferences), run by the
/// interpreter with a bound on the work per packet: a pathological pattern
/// fails its match instead of stalling the capture.
fn payload_regex(pattern: &str) -> Result<pcre2::bytes::Regex, String> {
    if pattern.len() > 1000 {
        return Err("regex longer than 1000 characters".into());
    }
    pcre2::bytes::RegexBuilder::new()
        .build(&format!("(*LIMIT_MATCH=200000)(*LIMIT_DEPTH=2000){pattern}"))
        .map_err(|e| e.to_string())
}

struct Pkt {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    proto: &'static str,
    sport: u16,
    dport: u16,
    payload: Vec<u8>,
}

/// Addresses, ports and payload of a captured frame (etherparse does the parsing).
fn dissect(dlt: i32, frame: &[u8]) -> Pkt {
    use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
    let sliced = match dlt {
        1 => SlicedPacket::from_ethernet(frame),
        0 | 12 => frame.get(4..).map_or(SlicedPacket::from_ip(&[]), SlicedPacket::from_ip),
        51 => frame.get(8..).map_or(SlicedPacket::from_ip(&[]), SlicedPacket::from_ip),
        _ => SlicedPacket::from_ip(frame),
    };
    let mut p = Pkt { src: None, dst: None, proto: "-", sport: 0, dport: 0, payload: vec![] };
    let Ok(s) = sliced else { return p };
    match &s.net {
        Some(InternetSlice::Ipv4(v4)) => {
            p.src = Some(IpAddr::V4(v4.header().source_addr()));
            p.dst = Some(IpAddr::V4(v4.header().destination_addr()));
        }
        Some(InternetSlice::Ipv6(v6)) => {
            p.src = Some(IpAddr::V6(v6.header().source_addr()));
            p.dst = Some(IpAddr::V6(v6.header().destination_addr()));
        }
        _ => {}
    }
    match &s.transport {
        Some(TransportSlice::Tcp(t)) => {
            p.proto = "tcp";
            p.sport = t.source_port();
            p.dport = t.destination_port();
            p.payload = t.payload().to_vec();
        }
        Some(TransportSlice::Udp(u)) => {
            p.proto = "udp";
            p.sport = u.source_port();
            p.dport = u.destination_port();
            p.payload = u.payload().to_vec();
        }
        Some(TransportSlice::Icmpv4(_)) => p.proto = "icmp",
        Some(TransportSlice::Icmpv6(_)) => p.proto = "icmp6",
        _ => {}
    }
    p
}

fn syslog(prio: libc::c_int, msg: &str) {
    if let Ok(m) = std::ffi::CString::new(msg.replace('\0', "")) {
        unsafe { libc::syslog(prio, c"%s".as_ptr(), m.as_ptr()) };
    }
}

/// The pf helper, one request line and one reply line. Connected when
/// first needed and again after a failure: it may start after us.
struct Helper {
    path: Option<String>,
    conn: Option<(BufReader<UnixStream>, UnixStream)>,
}

impl Helper {
    /// The helper drops idle connections: on a lost one, reconnect and retry once.
    fn request(&mut self, op: &str, addr: IpAddr) -> Result<(), String> {
        match self.once(op, addr) {
            Err(e) if e == LOST => self.once(op, addr),
            r => r,
        }
    }

    fn once(&mut self, op: &str, addr: IpAddr) -> Result<(), String> {
        let path = self.path.clone().ok_or("no pfhelper configured")?;
        if self.conn.is_none() {
            let s = UnixStream::connect(&path).map_err(|e| format!("{path}: {e}"))?;
            s.set_read_timeout(Some(std::time::Duration::from_secs(3))).map_err(|e| e.to_string())?;
            self.conn = Some((BufReader::new(s.try_clone().map_err(|e| e.to_string())?), s));
        }
        let (r, w) = self.conn.as_mut().unwrap();
        let line =
            serde_json::json!({"table": "lab_block", "op": op, "addresses": [addr.to_string()]}).to_string() + "\n";
        let mut reply = String::new();
        let io = w.write_all(line.as_bytes()).and_then(|_| r.read_line(&mut reply));
        if io.is_err() || reply.is_empty() {
            self.conn = None;
            return Err(LOST.into());
        }
        let v: serde_json::Value = serde_json::from_str(&reply).map_err(|e| e.to_string())?;
        if v["ok"].as_bool() == Some(true) { Ok(()) } else { Err(v["error"].as_str().unwrap_or("refused").to_string()) }
    }
}

fn ids(name: &str, file: &str, field: usize) -> Option<u32> {
    let text = std::fs::read_to_string(file).ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > field && f[0] == name).then(|| f[field].parse().ok())?
    })
}

fn drop_privileges(user: &str, pcap_dir: &str, pfhelper: Option<&str>) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        let uid = ids(user, "/etc/passwd", 2).ok_or_else(|| format!("no user {user}"))?;
        let gid = ids(user, "/etc/passwd", 3).ok_or_else(|| format!("no user {user}"))?;
        // the pf helper's socket belongs to group _octodns
        let mut groups = vec![gid];
        groups.extend(ids("_octodns", "/etc/group", 2));
        unsafe {
            if libc::setgroups(groups.len() as _, groups.as_ptr() as *const _) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(format!("cannot drop to {user}"));
            }
        }
    }
    #[cfg(target_os = "openbsd")]
    unsafe {
        let dir = std::ffi::CString::new(pcap_dir).map_err(|_| "pcap_dir")?;
        if libc::unveil(dir.as_ptr(), c"rwc".as_ptr()) != 0 {
            return Err("unveil pcap_dir".into());
        }
        if let Some(p) = pfhelper {
            let p = std::ffi::CString::new(p).map_err(|_| "pfhelper")?;
            if libc::unveil(p.as_ptr(), c"rw".as_ptr()) != 0 {
                return Err("unveil pfhelper".into());
            }
        }
        if libc::unveil(std::ptr::null(), std::ptr::null()) != 0
            || libc::pledge(c"stdio rpath wpath cpath unix".as_ptr(), std::ptr::null()) != 0
        {
            return Err("unveil/pledge".into());
        }
    }
    let _ = (pcap_dir, pfhelper);
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut conf = "/etc/octopus/analyzer.toml".to_string();
    let mut validate = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => conf = args.next().expect("-c needs a file"),
            "--validate" => validate = true,
            "--oneshot" => {
                let req = args.next().expect("--oneshot needs a request file");
                if let Err(e) = oneshot::run(&req) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return;
            }
            _ => {
                eprintln!("usage: octopus-analyzer [-c analyzer.toml] [--validate] | --oneshot request.json");
                std::process::exit(2);
            }
        }
    }
    unsafe { libc::openlog(c"octopus-analyzer".as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_DAEMON) };
    if let Err(e) = run(&conf, validate) {
        eprintln!("octopus-analyzer: {e}");
        syslog(libc::LOG_DAEMON | libc::LOG_ERR, &format!("fatal: {e}"));
        std::process::exit(1);
    }
}

fn run(conf: &str, validate: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(conf).map_err(|e| format!("{conf}: {e}"))?;
    let cfg: Config = toml::from_str(&text).map_err(|e| format!("{conf}: {e}"))?;
    let mut rules = vec![];
    for r in &cfg.rules {
        let re = match &r.regex {
            Some(x) => Some(payload_regex(x).map_err(|e| format!("rule {}: regex: {e}", r.name))?),
            None => None,
        };
        if !matches!(r.action.as_str(), "log" | "block") {
            return Err(format!("rule {}: action must be log or block", r.name));
        }
        #[cfg(target_os = "openbsd")]
        bpf::check(&r.filter).map_err(|e| format!("rule {}: {e}", r.name))?;
        rules.push((r.clone(), re));
    }
    if validate {
        println!("{conf}: ok ({} rules)", rules.len());
        return Ok(());
    }
    run_capture(cfg, rules)
}

#[cfg(not(target_os = "openbsd"))]
fn run_capture(_: Config, _: Vec<(RuleConf, Option<pcre2::bytes::Regex>)>) -> Result<(), String> {
    Err("capturing needs OpenBSD's bpf(4)".into())
}

#[cfg(target_os = "openbsd")]
fn run_capture(cfg: Config, conf_rules: Vec<(RuleConf, Option<pcre2::bytes::Regex>)>) -> Result<(), String> {
    let mut rules = vec![];
    for (c, re) in conf_rules {
        let (fd, dlt) = bpf::open(&c.interface, &c.filter).map_err(|e| format!("rule {}: {e}", c.name))?;
        let ring =
            c.pcap.then(|| Ring { dir: cfg.pcap_dir.clone(), name: c.name.clone(), idx: 0, file: None, size: 0, dlt });
        rules.push(Rule { conf: c, re, dlt, fd, ring, matches: 0, logged_this_sec: (0, 0) });
    }
    if rules.iter().any(|r| r.conf.action == "block") && cfg.pfhelper.is_none() {
        return Err("block rules need pfhelper".into());
    }
    let mut helper = Helper { path: cfg.pfhelper.clone(), conn: None };
    drop_privileges(&cfg.user, &cfg.pcap_dir, cfg.pfhelper.as_deref())?;
    syslog(
        libc::LOG_DAEMON | libc::LOG_NOTICE,
        &format!(
            "{} rule(s): {}",
            rules.len(),
            rules.iter().map(|r| format!("{} on {}", r.conf.name, r.conf.interface)).collect::<Vec<_>>().join(", ")
        ),
    );

    let mut blocked: HashMap<IpAddr, Instant> = HashMap::new();
    let mut buf = vec![0u8; bpf::BUFLEN as usize];
    let mut last_expiry = Instant::now();
    loop {
        let mut pfds: Vec<libc::pollfd> =
            rules.iter().map(|r| libc::pollfd { fd: r.fd, events: libc::POLLIN, revents: 0 }).collect();
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, 5000) };
        if last_expiry.elapsed() > Duration::from_secs(30) {
            last_expiry = Instant::now();
            let now = Instant::now();
            let gone: Vec<IpAddr> = blocked.iter().filter(|(_, t)| **t <= now).map(|(a, _)| *a).collect();
            for a in gone {
                blocked.remove(&a);
                let r = helper.request("delete", a);
                syslog(
                    libc::LOG_LOCAL1 | libc::LOG_INFO,
                    &serde_json::json!({"unblock": a.to_string(), "ok": r.is_ok()}).to_string(),
                );
            }
        }
        if n <= 0 {
            continue;
        }
        for (i, pfd) in pfds.iter().enumerate() {
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let len = unsafe { libc::read(pfd.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if len <= 0 {
                continue;
            }
            let rule = &mut rules[i];
            for (sec, usec, datalen, frame) in bpf::records(&buf[..len as usize]) {
                let p = dissect(rule.dlt, frame);
                // a match that hits the work limit counts as no match
                let hit = match &rule.re {
                    Some(re) => re.is_match(&p.payload).unwrap_or(false),
                    None => true,
                };
                if !hit {
                    continue;
                }
                rule.matches += 1;
                if let Some(ring) = &mut rule.ring {
                    ring.write(sec, usec, frame, datalen);
                }
                let mut action = "log";
                if rule.conf.action == "block"
                    && let Some(src) = p.src
                    && !blocked.contains_key(&src)
                {
                    action = match helper.request("add", src) {
                        Ok(()) => {
                            blocked.insert(src, Instant::now() + Duration::from_secs(rule.conf.block_for));
                            "block"
                        }
                        Err(e) => {
                            syslog(libc::LOG_DAEMON | libc::LOG_WARNING, &format!("pfhelper: {e}"));
                            "block-failed"
                        }
                    };
                }
                // at most LOG_PER_SEC lines per rule and second; blocks always
                let s64 = sec as u64;
                if rule.logged_this_sec.0 != s64 {
                    rule.logged_this_sec = (s64, 0);
                }
                rule.logged_this_sec.1 += 1;
                if rule.logged_this_sec.1 <= LOG_PER_SEC || action != "log" {
                    let v = serde_json::json!({
                        "ts": sec, "rule": rule.conf.name, "if": rule.conf.interface, "action": action,
                        "src": p.src.map(|a| a.to_string()), "dst": p.dst.map(|a| a.to_string()),
                        "proto": p.proto, "sport": p.sport, "dport": p.dport, "len": datalen,
                        "matches": rule.matches,
                    });
                    syslog(libc::LOG_LOCAL1 | libc::LOG_INFO, &v.to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dissects_a_tcp_frame() {
        use etherparse::PacketBuilder;
        let b = PacketBuilder::ethernet2([1; 6], [2; 6]).ipv4([10, 0, 0, 5], [1, 1, 1, 1], 64).tcp(40000, 80, 1, 1000);
        let payload = b"GET /evil HTTP/1.1\r\n";
        let mut frame = vec![];
        b.write(&mut frame, payload).unwrap();
        let p = super::dissect(1, &frame);
        assert_eq!(p.src, Some("10.0.0.5".parse().unwrap()));
        assert_eq!((p.proto, p.sport, p.dport), ("tcp", 40000, 80));
        assert_eq!(p.payload, payload);
        // junk never panics
        for cut in 0..frame.len() {
            let _ = super::dissect(1, &frame[..cut]);
        }
    }

    #[test]
    fn payload_regex_is_pcre_and_bounded() {
        let re = super::payload_regex(r"(?i)get /(?=evil)").unwrap();
        assert!(re.is_match(b"xx GET /evil").unwrap());
        assert!(!re.is_match(b"GET /good").unwrap());
        // catastrophic backtracking stops at the limit instead of hanging
        let bad = super::payload_regex(r"(a+)+$").unwrap();
        let subject = [b"a".repeat(40), b"!".to_vec()].concat();
        assert!(bad.is_match(&subject).is_err());
        assert!(super::payload_regex("(").is_err());
    }
}
