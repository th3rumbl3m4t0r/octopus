//! `octopus-analyzer --oneshot request.json`: the web UI's capture window.
//!
//! The request ({interface, fcap, pcre, seconds, max_packets}) is staged by
//! _octoweb, so it is read without following links and validated like any
//! other untrusted input. As root this only opens bpf with the translated
//! filter and locks it; then it drops to _octoflow, pledges stdio and
//! captures until the time or packet limit. Output: JSON on stdout.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use serde::Deserialize;
#[cfg(target_os = "openbsd")]
use serde_json::json;

const USER: &str = "_octoflow";
const MAX_SECONDS: u32 = 30;
const MAX_PACKETS: u32 = 500;
/// bytes of each frame shown in the viewer; the pcap keeps the whole frame
const SHOW_BYTES: usize = 2048;
const PCAP_BYTES: usize = 8 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    interface: String,
    #[serde(default)]
    fcap: String,
    #[serde(default)]
    pcre: String,
    seconds: u32,
    max_packets: u32,
}

fn read_request(path: &str) -> Result<Request, String> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    let mut text = String::new();
    f.by_ref().take(64 << 10).read_to_string(&mut text).map_err(|e| format!("{path}: {e}"))?;
    let r: Request = serde_json::from_str(&text).map_err(|e| format!("request: {e}"))?;
    if r.interface.is_empty()
        || r.interface.len() > 15
        || !r.interface.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(format!("interface {:?}: not an interface name", r.interface));
    }
    if r.seconds == 0 || r.seconds > MAX_SECONDS || r.max_packets == 0 || r.max_packets > MAX_PACKETS {
        return Err(format!("1-{MAX_SECONDS} seconds and 1-{MAX_PACKETS} packets"));
    }
    if r.fcap.len() > 1000 {
        return Err("fcap longer than 1000 characters".into());
    }
    Ok(r)
}

/// The pcap filter for an FCAP expression; empty means every packet.
pub fn filter(fcap: &str) -> Result<String, String> {
    let fcap = fcap.trim();
    if fcap.is_empty() {
        Ok(String::new())
    } else {
        octopus_config::fcap::to_pcap(fcap).map_err(|e| format!("fcap: {e}"))
    }
}

pub fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

#[cfg(not(target_os = "openbsd"))]
pub fn run(path: &str) -> Result<(), String> {
    let r = read_request(path)?;
    filter(&r.fcap)?;
    if !r.pcre.is_empty() {
        super::payload_regex(&r.pcre).map_err(|e| format!("pcre: {e}"))?;
    }
    Err("capturing needs OpenBSD's bpf(4)".into())
}

#[cfg(target_os = "openbsd")]
pub fn run(path: &str) -> Result<(), String> {
    use std::time::{Duration, Instant};

    let r = read_request(path)?;
    let filter = filter(&r.fcap)?;
    let re = match r.pcre.as_str() {
        "" => None,
        p => Some(super::payload_regex(p).map_err(|e| format!("pcre: {e}"))?),
    };
    let (fd, dlt) = super::bpf::open(&r.interface, &filter)?;
    drop_to_user()?;

    let deadline = Instant::now() + Duration::from_secs(r.seconds as u64);
    let mut buf = vec![0u8; super::bpf::BUFLEN as usize];
    let mut pcap = super::pcap_header(dlt);
    let (mut seen, mut packets, mut pcap_full) = (0u64, vec![], false);
    'capture: while packets.len() < r.max_packets as usize {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(1000) as i32 + 1) } <= 0 {
            continue;
        }
        let len = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if len <= 0 {
            continue;
        }
        for (sec, usec, datalen, frame) in super::bpf::records(&buf[..len as usize]) {
            seen += 1;
            let p = super::dissect(dlt, frame);
            let at = match &re {
                None => None,
                Some(re) => match re.find(&p.payload) {
                    Ok(Some(m)) => Some((m.start(), m.end())),
                    _ => continue,
                },
            };
            if pcap.len() + 16 + frame.len() <= PCAP_BYTES {
                super::pcap_record(&mut pcap, sec, usec, frame, datalen);
            } else {
                pcap_full = true;
            }
            packets.push(json!({
                "ts": sec, "usec": usec,
                "src": p.src.map(|a| a.to_string()), "dst": p.dst.map(|a| a.to_string()),
                "proto": p.proto, "sport": p.sport, "dport": p.dport,
                "len": datalen, "caplen": frame.len(),
                // payload offset in the frame, and the regex match inside the payload
                "payload_at": frame.len() - p.payload.len(),
                "match": at.map(|(s, e)| [s, e]),
                "data": b64(&frame[..frame.len().min(SHOW_BYTES)]),
            }));
            if packets.len() >= r.max_packets as usize {
                break 'capture;
            }
        }
    }
    let out = json!({
        "interface": r.interface, "filter": filter, "dlt": dlt, "seen": seen,
        "limit": packets.len() >= r.max_packets as usize, "pcap_truncated": pcap_full,
        "packets": packets, "pcap": b64(&pcap),
    });
    println!("{out}");
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn drop_to_user() -> Result<(), String> {
    let uid = super::ids(USER, "/etc/passwd", 2).ok_or_else(|| format!("no user {USER}"))?;
    let gid = super::ids(USER, "/etc/passwd", 3).ok_or_else(|| format!("no user {USER}"))?;
    unsafe {
        if libc::setgroups(1, &gid as *const u32 as *const _) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(format!("cannot drop to {USER}"));
        }
        if libc::unveil(c"/".as_ptr(), c"".as_ptr()) != 0
            || libc::unveil(std::ptr::null(), std::ptr::null()) != 0
            || libc::pledge(c"stdio".as_ptr(), std::ptr::null()) != 0
        {
            return Err("unveil/pledge".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64() {
        assert_eq!(super::b64(b""), "");
        assert_eq!(super::b64(b"f"), "Zg==");
        assert_eq!(super::b64(b"fo"), "Zm8=");
        assert_eq!(super::b64(b"foo"), "Zm9v");
        assert_eq!(super::b64(b"foobar\xff"), "Zm9vYmFy/w==");
    }

    #[test]
    fn requests_are_checked() {
        let dir = std::env::temp_dir().join(format!("oneshot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.json");
        let try_req = |body: &str| {
            std::fs::write(&p, body).unwrap();
            super::read_request(p.to_str().unwrap()).map(|_| ())
        };
        assert!(try_req(r#"{"interface":"vio0","seconds":5,"max_packets":100}"#).is_ok());
        assert!(try_req(r#"{"interface":"vio0; rm","seconds":5,"max_packets":100}"#).is_err());
        assert!(try_req(r#"{"interface":"vio0","seconds":31,"max_packets":100}"#).is_err());
        assert!(try_req(r#"{"interface":"vio0","seconds":5,"max_packets":100,"x":1}"#).is_err());
        let link = dir.join("link.json");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(super::read_request(link.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(super::filter("").unwrap(), "");
        assert_eq!(super::filter(" dst port 80 ").unwrap(), "dst port 80");
        assert!(super::filter("dst port banana").is_err());
    }
}
