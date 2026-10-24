//! octopus-pfhelper: the only path from unprivileged code (octopus-dns,
//! the lab analyzer) to pf. It listens on a Unix socket and accepts one JSON
//! request per line:
//!
//!   {"table": "cls_streaming", "op": "add", "addresses": ["192.0.2.1", "2001:db8::/64"]}
//!
//! and answers `{"ok": true, "count": N}` or `{"ok": false, "error": "..."}`.
//! Each client may write its own tables only (octopus-dns the cls_* ones,
//! the analyzer lab_block); every address must be one host or prefix, and
//! lab_block takes single addresses outside the protected prefixes of
//! /etc/octopus/pfhelper.conf. It runs `pfctl -t TABLE -T OP -f -` and logs
//! every action; lab_block entries also expire in pf itself. Clients are
//! served side by side, with timeouts. After setup it is pledged to
//! stdio/unix/proc/exec and can only execute pfctl.
//!
//! This file is privileged code: keep it small and review every change.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipnet::IpNet;
use octopus_pfhelper::{Config, DEFAULT_TABLES, Grant, LAB_BLOCK, parse, tables_for};

const SOCKET: &str = "/var/run/octopus-pfhelper.sock";
const CONF: &str = "/etc/octopus/pfhelper.conf";
/// Clients served at once (each is a thread).
const MAX_CLIENTS: usize = 16;
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

struct Shared {
    tables: Vec<String>,
    /// uid -> the tables it may write
    clients: Vec<(u32, Vec<String>)>,
    protected: Vec<IpNet>,
    /// one pfctl at a time
    pf: Mutex<()>,
    active: AtomicUsize,
}

fn handle(stream: UnixStream, sh: &Shared) {
    let peer = peer_ids(&stream);
    let mine: Vec<String> = match peer {
        Some((uid, _)) => sh.clients.iter().find(|(u, _)| *u == uid).map(|(_, t)| t.clone()).unwrap_or_default(),
        None if !cfg!(target_os = "openbsd") => sh.tables.clone(),
        None => vec![],
    };
    // and only those the command line left on
    let mine: Vec<String> = mine.into_iter().filter(|t| sh.tables.contains(t)).collect();
    let mut w = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    // a client that stops reading can't hold a thread forever
    let _ = w.set_write_timeout(Some(Duration::from_secs(5)));
    if mine.is_empty() {
        log(&format!("refused peer {peer:?}"));
        let _ = writeln!(w, "{}", serde_json::json!({"ok": false, "error": "not allowed"}));
        return;
    }
    let grant = Grant { tables: &mine, protected: &sh.protected };
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
        let reply = match parse(&line, &grant) {
            Err(e) => {
                log(&format!("rejected request from {peer:?}: {e}"));
                serde_json::json!({"ok": false, "error": e})
            }
            Ok((table, op, addrs)) => {
                let done = {
                    let _pf = sh.pf.lock().unwrap_or_else(|e| e.into_inner());
                    pfctl(&table, op, &addrs)
                };
                match done {
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
                }
            }
        };
        if writeln!(w, "{reply}").is_err() {
            return;
        }
    }
}

/// pfctl -T expire: lab blocks end in pf even when the analyzer that made
/// them was restarted, stopped or lost its delete.
fn expire_lab_blocks(sh: &Shared, secs: u32) {
    let _pf = sh.pf.lock().unwrap_or_else(|e| e.into_inner());
    // pipes, not /dev/null: opening a file would need more pledge promises
    let out = Command::new(PFCTL)
        .args(["-q", "-t", LAB_BLOCK, "-T", "expire", &secs.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    if let Ok(o) = out
        && !o.status.success()
    {
        log(&format!("expire {LAB_BLOCK}: {}", String::from_utf8_lossy(&o.stderr).trim()));
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
    // before pledge: no file access afterwards
    let conf: Config = match std::fs::read_to_string(CONF) {
        Ok(t) => toml::from_str(&t).unwrap_or_else(|e| {
            log(&format!("{CONF}: {e}"));
            std::process::exit(1);
        }),
        Err(_) => Config { protected: vec![], lab_block_expire: 3600 },
    };
    let mut clients: Vec<(u32, Vec<String>)> = CLIENT_USERS
        .iter()
        .filter_map(|u| uid_of(u).map(|id| (id, tables_for(u).iter().map(|t| t.to_string()).collect())))
        .collect();
    clients.push((0, tables_for("root").iter().map(|t| t.to_string()).collect()));
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
    sandbox();
    let sh = Arc::new(Shared {
        tables,
        clients,
        protected: conf.protected,
        pf: Mutex::new(()),
        active: AtomicUsize::new(0),
    });
    log(&format!("listening on {socket}; tables {}; {} protected prefix(es)", sh.tables.join(","), sh.protected.len()));
    if sh.tables.iter().any(|t| t == LAB_BLOCK) {
        let sh = sh.clone();
        let secs = conf.lab_block_expire.max(60);
        std::thread::spawn(move || {
            loop {
                expire_lab_blocks(&sh, secs);
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }
    for s in listener.incoming().flatten() {
        if sh.active.load(Ordering::SeqCst) >= MAX_CLIENTS {
            log("too many clients; refusing one");
            continue;
        }
        sh.active.fetch_add(1, Ordering::SeqCst);
        let sh = sh.clone();
        std::thread::spawn(move || {
            handle(s, &sh);
            sh.active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}
