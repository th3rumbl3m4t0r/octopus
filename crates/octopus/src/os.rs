//! Small OS helpers: running commands, atomic writes, ownership, locking.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub type Res<T> = Result<T, String>;

/// The web UI's user: it owns /var/octopus/staged.
pub const WEB_USER: &str = "_octoweb";

pub fn is_openbsd() -> bool {
    cfg!(target_os = "openbsd")
}

/// Run a command; Ok(stdout) on exit 0, Err(stderr + stdout) otherwise.
pub fn run(cmd: &str, args: &[&str]) -> Res<String> {
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).output().map_err(|e| format!("{cmd}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(format!("{cmd} {}: {}{}", args.join(" "), stderr.trim(), stdout.trim()))
    }
}

/// Run and only report whether it succeeded.
pub fn ok(cmd: &str, args: &[&str]) -> bool {
    run(cmd, args).is_ok()
}

fn lookup_id(file: &str, name: &str) -> Option<u32> {
    let text = fs::read_to_string(file).ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then_some(())?;
        f.next()?;
        f.next()?.parse().ok()
    })
}

/// A user's uid and primary gid, from /etc/passwd.
pub fn ids_of(user: &str) -> Option<(u32, u32)> {
    let text = fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 4 || f[0] != user {
            return None;
        }
        Some((f[2].parse().ok()?, f[3].parse().ok()?))
    })
}

/// Write via a temp file in the same directory, then rename. The temp file
/// is new (O_EXCL, never a symlink), gets its owner and mode before any
/// content, and the directory is synced after the rename.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32, owner: &str, group: &str) -> Res<()> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = path.parent().ok_or("no parent")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy();
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let tmp = dir.join(format!(
        ".{name}.{}.{}.{nanos:x}.octopus-tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        if unsafe { libc::geteuid() } == 0 {
            let uid = lookup_id("/etc/passwd", owner);
            let gid = lookup_id("/etc/group", group);
            std::os::unix::fs::fchown(&f, uid, gid).map_err(|e| format!("chown {}: {e}", tmp.display()))?;
        }
        f.set_permissions(fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        f.write_all(content).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("{}: {e}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
        return res;
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Several files replaced together: every one written and synced first,
/// then renamed into place one right after the other (a certificate and
/// its key never mismatch because a write failed between them).
pub fn write_atomic_all(files: &[(&Path, &[u8], u32, &str, &str)]) -> Res<()> {
    let mut temps = vec![];
    for (path, content, mode, owner, group) in files {
        let dir = path.parent().ok_or("no parent")?;
        let tmp = dir.join(format!(".{}.pair.octopus-tmp", path.file_name().ok_or("no file name")?.to_string_lossy()));
        let _ = fs::remove_file(&tmp);
        if let Err(e) = write_atomic(&tmp, content, *mode, owner, group) {
            for t in &temps {
                let _ = fs::remove_file(t);
            }
            return Err(e);
        }
        temps.push(tmp);
    }
    for (tmp, (path, ..)) in temps.iter().zip(files) {
        fs::rename(tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Read a file another user may control (the web UI's staging directory):
/// never through a symlink, only a regular file owned by `owner`, at most
/// `max` bytes.
pub fn read_owned(path: &Path, owner: &str, max: u64) -> Res<String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    let uid = lookup_id("/etc/passwd", owner).ok_or_else(|| format!("no user {owner}"))?;
    if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1 {
        return Err(format!("{}: not a plain file of {owner}", path.display()));
    }
    if meta.len() > max {
        return Err(format!("{}: larger than {max} bytes", path.display()));
    }
    let mut s = String::new();
    f.take(max).read_to_string(&mut s).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(s)
}

/// An exclusive lock held for the life of the value.
pub struct Lock(#[allow(dead_code)] fs::File);

pub fn lock(path: &Path) -> Res<Lock> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another octopus apply/rollback is running".into());
    }
    Ok(Lock(f))
}

extern "C" fn ignore(_: libc::c_int) {}

/// Keep running when the terminal or the pipe we print to goes away, and
/// on ^C. SIGHUP and SIGINT get a handler that does nothing rather than
/// SIG_IGN, so the daemons we start (which inherit ignored signals, not
/// handlers) keep their defaults; std resets SIGPIPE for children itself.
pub fn outlive_reader() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        for sig in [libc::SIGHUP, libc::SIGINT] {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = ignore as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// The lock, waiting up to `secs` for whoever holds it.
pub fn lock_wait(path: &Path, secs: u64) -> Res<Lock> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        match lock(path) {
            Ok(l) => return Ok(l),
            Err(e) if std::time::Instant::now() >= until => return Err(e),
            Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
    }
}

/// Free space (KB) for root on the filesystem holding `path`.
#[allow(clippy::unnecessary_cast)] // statvfs field types differ between systems
pub fn free_kb(path: &Path) -> Option<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| s.f_bfree as u64 * s.f_frsize as u64 / 1024)
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Log an event to syslog (daemon facility) and stderr.
pub fn log(msg: &str) {
    // syslog first: stderr may be a pipe nobody reads any more
    if is_openbsd() {
        let _ = Command::new("logger")
            .args(["-p", "daemon.notice", "-t", "octopus", "--", msg])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    err!("octopus: {msg}");
}

pub fn invoking_user() -> String {
    std::env::var("DOAS_USER")
        .or_else(|_| std::env::var("SUDO_USER"))
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "?".into())
}
