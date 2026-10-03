//! octopus-collector (phase 6): pflow's IPFIX flows, labelled with the
//! name the client looked up.
//!
//! octopus-dns sends every answer here ({"c": client, "q": name, "a": [addresses]}
//! over UDP on loopback); pflow sends IPFIX when a pf state ends. Each flow
//! is matched to the name that (client, address) last resolved to, else to
//! any client's lookup of that address, and logged as one JSON line
//! (syslog local2, /var/log/octopus-flows). It answers "which name was this
//! connection for".
//!
//! Unprivileged (_octoflow), pledged "stdio inet"; listens on loopback only.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use octopus_collector::ipfix;

const KEEP: Duration = Duration::from_secs(6 * 3600);
const MAX_PAIRS: usize = 500_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    user: String,
    ipfix: SocketAddr,
    dns: SocketAddr,
    #[serde(default)]
    networks: Vec<NetConf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetConf {
    name: String,
    prefix: ipnet_lite::Net,
}

/// A prefix without another dependency: "a.b.c.d/n" or "x::/n".
mod ipnet_lite {
    use std::net::IpAddr;

    #[derive(Clone, Copy)]
    pub struct Net(pub IpAddr, pub u8);

    impl Net {
        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self.0, ip) {
                (IpAddr::V4(n), IpAddr::V4(a)) => {
                    let m = if self.1 == 0 { 0 } else { u32::MAX << (32 - self.1.min(32)) };
                    u32::from(n) & m == u32::from(a) & m
                }
                (IpAddr::V6(n), IpAddr::V6(a)) => {
                    let m = if self.1 == 0 { 0 } else { u128::MAX << (128 - self.1.min(128)) };
                    u128::from(n) & m == u128::from(a) & m
                }
                _ => false,
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for Net {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let s = String::deserialize(d)?;
            let (a, p) = s.split_once('/').ok_or_else(|| serde::de::Error::custom("prefix needs /len"))?;
            Ok(Net(a.parse().map_err(serde::de::Error::custom)?, p.parse().map_err(serde::de::Error::custom)?))
        }
    }
}

#[derive(Deserialize)]
struct Answer {
    c: IpAddr,
    q: String,
    a: Vec<IpAddr>,
}

#[derive(Default)]
struct Names {
    /// (client, address) -> name
    pair: HashMap<(IpAddr, IpAddr), (String, Instant)>,
    /// address -> name (any client)
    addr: HashMap<IpAddr, (String, Instant)>,
}

impl Names {
    fn learn(&mut self, a: Answer) {
        let now = Instant::now();
        if self.pair.len() > MAX_PAIRS {
            self.pair.retain(|_, (_, t)| t.elapsed() < KEEP / 4);
            self.addr.retain(|_, (_, t)| t.elapsed() < KEEP / 4);
        }
        for ip in a.a {
            self.pair.insert((a.c, ip), (a.q.clone(), now));
            self.addr.insert(ip, (a.q.clone(), now));
        }
    }

    fn label(&self, src: IpAddr, dst: IpAddr) -> Option<&str> {
        fn fresh(e: &(String, Instant)) -> Option<&str> {
            (e.1.elapsed() < KEEP).then_some(e.0.as_str())
        }
        self.pair
            .get(&(src, dst))
            .and_then(fresh)
            .or_else(|| self.pair.get(&(dst, src)).and_then(fresh))
            .or_else(|| self.addr.get(&dst).and_then(fresh))
            .or_else(|| self.addr.get(&src).and_then(fresh))
    }
}

fn syslog(prio: libc::c_int, msg: &str) {
    if let Ok(m) = std::ffi::CString::new(msg.replace('\0', "")) {
        unsafe { libc::syslog(prio, c"%s".as_ptr(), m.as_ptr()) };
    }
}

fn drop_privileges(user: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        let text = std::fs::read_to_string("/etc/passwd").map_err(|e| e.to_string())?;
        let (uid, gid): (u32, u32) = text
            .lines()
            .find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 3 && f[0] == user).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
            })
            .ok_or_else(|| format!("no user {user}"))?;
        unsafe {
            let g = [gid];
            if libc::setgroups(1, g.as_ptr() as *const _) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(format!("cannot drop to {user}"));
            }
        }
    }
    #[cfg(target_os = "openbsd")]
    unsafe {
        if libc::unveil(std::ptr::null(), std::ptr::null()) != 0
            || libc::pledge(c"stdio inet".as_ptr(), std::ptr::null()) != 0
        {
            return Err("pledge".into());
        }
    }
    Ok(())
}

fn proto_name(p: u8) -> String {
    match p {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        58 => "icmp6".into(),
        n => n.to_string(),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut conf = "/etc/octopus/collector.toml".to_string();
    let mut validate = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => conf = args.next().expect("-c needs a file"),
            "--validate" => validate = true,
            _ => {
                eprintln!("usage: octopus-collector [-c collector.toml] [--validate]");
                std::process::exit(2);
            }
        }
    }
    unsafe { libc::openlog(c"octopus-collector".as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_DAEMON) };
    if let Err(e) = run(&conf, validate) {
        eprintln!("octopus-collector: {e}");
        syslog(libc::LOG_DAEMON | libc::LOG_ERR, &format!("fatal: {e}"));
        std::process::exit(1);
    }
}

fn run(conf: &str, validate: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(conf).map_err(|e| format!("{conf}: {e}"))?;
    let cfg: Config = toml::from_str(&text).map_err(|e| format!("{conf}: {e}"))?;
    if !cfg.ipfix.ip().is_loopback() || !cfg.dns.ip().is_loopback() {
        return Err("listen on loopback only".into());
    }
    if validate {
        println!("{conf}: ok");
        return Ok(());
    }
    let ipfix = UdpSocket::bind(cfg.ipfix).map_err(|e| format!("{}: {e}", cfg.ipfix))?;
    let dns = UdpSocket::bind(cfg.dns).map_err(|e| format!("{}: {e}", cfg.dns))?;
    drop_privileges(&cfg.user)?;
    syslog(libc::LOG_DAEMON | libc::LOG_NOTICE, &format!("ipfix on {}, dns answers on {}", cfg.ipfix, cfg.dns));

    let names = Arc::new(Mutex::new(Names::default()));
    let n2 = names.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((len, _)) = dns.recv_from(&mut buf) else { continue };
            if let Ok(a) = serde_json::from_slice::<Answer>(&buf[..len]) {
                n2.lock().unwrap().learn(a);
            }
        }
    });

    let nets = cfg.networks;
    let net_of = |ip: Option<IpAddr>| -> &str {
        ip.and_then(|ip| nets.iter().find(|n| n.prefix.contains(ip)).map(|n| n.name.as_str())).unwrap_or("-")
    };
    let mut parser = ipfix::Parser::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let Ok((len, _)) = ipfix.recv_from(&mut buf) else { continue };
        for f in parser.message(&buf[..len]) {
            let (Some(src), Some(dst)) = (f.src, f.dst) else { continue };
            let name = names.lock().unwrap().label(src, dst).map(str::to_string);
            let v = serde_json::json!({
                "start": f.start_ms / 1000, "end": f.end_ms / 1000,
                "src": src.to_string(), "sport": f.sport, "dst": dst.to_string(), "dport": f.dport,
                "proto": proto_name(f.proto), "packets": f.packets, "bytes": f.bytes,
                "name": name, "net": net_of(Some(src)),
                "nat": f.nat_src.map(|a| a.to_string()),
            });
            syslog(libc::LOG_LOCAL2 | libc::LOG_INFO, &v.to_string());
        }
    }
}
