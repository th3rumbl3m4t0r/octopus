//! octopus-pfhelper: the only path from unprivileged code (octopus-dns,
//! the lab analyzer) to pf. It listens on a Unix socket and accepts one JSON
//! request per line:
//!
//!   {"table": "cls_streaming", "op": "add", "addresses": ["192.0.2.1", "2001:db8::/64"]}
//!
//! and answers `{"ok": true, "count": N}` or `{"ok": false, "error": "..."}`.
//! Tables must be on the allowlist; every address must be one host or
//! prefix. It runs `pfctl -t TABLE -T OP -f -` and logs every action. After
//! setup it is pledged to stdio/unix/proc/exec and can only execute pfctl.
//!
//! This file is privileged code: keep it small and review every change.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::time::Duration;

use octopus_pfhelper::{DEFAULT_TABLES, parse};

const SOCKET: &str = "/var/run/octopus-pfhelper.sock";
const PFCTL: &str = "/sbin/pfctl";
/// The socket's group; its members may connect.
const CLIENT_GROUP: &str = "_octodns";
/// Who may send requests: octopus-dns (classification), octopus-analyzer (lab blocks).
const CLIENT_USERS: [&str; 2] = ["_octodns", "_octoflow"];
const MAX_LINE: usize = 1 << 20;

fn log(msg: &str) {
    eprintln!("octopus-pfhelper: {msg}");
    #[cfg(target_os = "openbsd")]
    {
        let m = std::ffi::CString::new(msg.replace('\0', "")).unwrap();
        unsafe { libc::syslog(libc::LOG_DAEMON | libc::LOG_NOTICE, c"%s".as_ptr(), m.as_ptr()) };
    }
}

fn pfctl(table: &str, op: &str, addrs: &[String]) -> Result<(), String> {
    let mut child = Command::new(PFCTL)
        .args(["-q", "-t", table, "-T", op, "-f", "-"])
        // pipes, not /dev/null: opening a file would need more pledge promises
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("pfctl: {e}"))?;
    {
        let mut stdin = child.stdin.take().unwrap();
        let mut text = addrs.join("\n");
        text.push('\n');
        stdin.write_all(text.as_bytes()).map_err(|e| format!("pfctl stdin: {e}"))?;
    }
    // pfctl -q prints nothing on success; read stderr, then drain stdout
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_end(&mut Vec::new());
    }
    let st = child.wait().map_err(|e| format!("pfctl: {e}"))?;
    if st.success() { Ok(()) } else { Err(format!("pfctl failed: {}", err.trim())) }
}

fn handle(stream: UnixStream, tables: &[String], allowed_uids: &[u32]) {
    let peer = peer_ids(&stream);
    let ok_peer = match peer {
        Some((uid, _)) => uid == 0 || allowed_uids.contains(&uid),
        None => !cfg!(target_os = "openbsd"),
    };
    let mut w = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    if !ok_peer {
        log(&format!("refused peer {peer:?}"));
        let _ = writeln!(w, "{}", serde_json::json!({"ok": false, "error": "not allowed"}));
        return;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut r = BufReader::new(stream.take(MAX_LINE as u64 * 16));
    let mut line = String::new();
    loop {
        line.clear();
        match r.by_ref().take(MAX_LINE as u64).read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if !line.ends_with('\n') {
            let _ = writeln!(w, "{}", serde_json::json!({"ok": false, "error": "line too long"}));
            return;
        }
        let reply = match parse(&line, tables) {
            Err(e) => {
                log(&format!("rejected request from {peer:?}: {e}"));
                serde_json::json!({"ok": false, "error": e})
            }
            Ok((table, op, addrs)) => match pfctl(&table, op, &addrs) {
                Ok(()) => {
                    let sample: Vec<&str> = addrs.iter().take(4).map(String::as_str).collect();
                    log(&format!(
                        "{op} {table}: {} address(es) {}{}",
                        addrs.len(),
                        sample.join(" "),
                        if addrs.len() > 4 { " ..." } else { "" }
                    ));
                    serde_json::json!({"ok": true, "count": addrs.len()})
                }
                Err(e) => {
                    log(&format!("{op} {table}: {e}"));
                    serde_json::json!({"ok": false, "error": e})
                }
            },
        };
        if writeln!(w, "{reply}").is_err() {
            return;
        }
    }
}

#[cfg(target_os = "openbsd")]
fn peer_ids(s: &UnixStream) -> Option<(u32, u32)> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    (unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some((uid, gid))
}

#[cfg(not(target_os = "openbsd"))]
fn peer_ids(_: &UnixStream) -> Option<(u32, u32)> {
    None
}

fn uid_of(user: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[0] == user).then(|| f[2].parse().ok()).flatten()
    })
}

fn gid_of(group: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[0] == group).then(|| f[2].parse().ok()).flatten()
    })
}

#[cfg(target_os = "openbsd")]
fn sandbox() {
    use std::ffi::CString;
    let path = CString::new(PFCTL).unwrap();
    unsafe {
        if libc::unveil(path.as_ptr(), c"x".as_ptr()) != 0 || libc::unveil(std::ptr::null(), std::ptr::null()) != 0 {
            log("unveil failed");
            std::process::exit(1);
        }
        if libc::pledge(c"stdio unix proc exec".as_ptr(), std::ptr::null()) != 0 {
            log("pledge failed");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "openbsd"))]
fn sandbox() {}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut socket = SOCKET.to_string();
    let mut tables: Vec<String> = DEFAULT_TABLES.iter().map(|s| s.to_string()).collect();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-s" => socket = args.next().expect("-s needs a path"),
            // -t restricts the allowlist further; it can't add tables beyond the defaults
            "-t" => {
                let want: Vec<String> = args.next().expect("-t needs a list").split(',').map(str::to_string).collect();
                tables.retain(|t| want.contains(t));
            }
            _ => {
                eprintln!("usage: octopus-pfhelper [-s socket] [-t table,table]");
                std::process::exit(2);
            }
        }
    }
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap_or_else(|e| {
        log(&format!("{socket}: {e}"));
        std::process::exit(1);
    });
    let gid = gid_of(CLIENT_GROUP);
    if let Some(g) = gid {
        let _ = std::os::unix::fs::chown(&socket, Some(0), Some(g));
    }
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660));
    // before pledge: no file access afterwards
    let uids: Vec<u32> = CLIENT_USERS.iter().filter_map(|u| uid_of(u)).collect();
    sandbox();
    log(&format!("listening on {socket}; tables {}", tables.join(",")));
    for s in listener.incoming().flatten() {
        handle(s, &tables, &uids);
    }
}
