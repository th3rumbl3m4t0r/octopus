//! Small OS helpers: running commands, atomic writes, ownership, locking.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, chown};
use std::path::Path;
use std::process::{Command, Stdio};

pub type Res<T> = Result<T, String>;

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

/// Write via a temp file in the same directory, then rename.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32, owner: &str, group: &str) -> Res<()> {
    let dir = path.parent().ok_or("no parent")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.octopus-tmp", path.file_name().unwrap().to_string_lossy()));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(content).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    let uid = lookup_id("/etc/passwd", owner);
    let gid = lookup_id("/etc/group", group);
    if unsafe { libc::geteuid() } == 0 {
        chown(&tmp, uid, gid).map_err(|e| format!("chown {}: {e}", tmp.display()))?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
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

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Log an event to syslog (daemon facility) and stderr.
pub fn log(msg: &str) {
    eprintln!("octopus: {msg}");
    if is_openbsd() {
        let _ = Command::new("logger").args(["-p", "daemon.notice", "-t", "octopus", msg]).status();
    }
}

pub fn invoking_user() -> String {
    std::env::var("DOAS_USER")
        .or_else(|_| std::env::var("SUDO_USER"))
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "?".into())
}
