//! The generation store: /var/octopus/generation/<n>/ holds the router.toml it was
//! built from, every rendered file under files/, and manifest.json.
//! Generation 0 is the baseline: the files as they were before the first apply.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use octopus_render::{Generation, Service, Subsystem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::os::{Res, now, write_atomic};

pub const VAR: &str = "/var/octopus";

/// Files octopus owns even when it didn't write them: stale ones are removed.
pub fn owned_by_glob(path: &str) -> bool {
    path == "/etc/mygate" || path.strip_prefix("/etc/hostname.").is_some_and(|s| !s.is_empty() && !s.contains('/'))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub path: String,
    pub mode: u32,
    pub owner: String,
    pub group: String,
    pub subsystem: Subsystem,
    pub secret: bool,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub generation: u32,
    pub created: u64,
    /// cli, web, rollback, baseline
    pub source: String,
    pub user: String,
    pub files: Vec<FileMeta>,
    pub services: Vec<Service>,
    /// Baseline only: managed paths that didn't exist before octopus.
    #[serde(default)]
    pub absent: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

pub fn root() -> PathBuf {
    std::env::var_os("OCTOPUS_VAR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(VAR))
}

pub fn dir(n: u32) -> PathBuf {
    root().join("gen").join(n.to_string())
}

pub fn file_path(n: u32, target: &str) -> PathBuf {
    dir(n).join("files").join(target.trim_start_matches('/'))
}

pub fn sha(content: &[u8]) -> String {
    Sha256::digest(content).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn list() -> Vec<u32> {
    let mut v: Vec<u32> = fs::read_dir(root().join("gen"))
        .map(|rd| rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

pub fn next() -> u32 {
    list().last().map_or(1, |n| n + 1).max(1)
}

pub fn load(n: u32) -> Res<Manifest> {
    let p = dir(n).join("manifest.json");
    let t = fs::read_to_string(&p).map_err(|e| format!("generation {n}: {e}"))?;
    serde_json::from_str(&t).map_err(|e| format!("generation {n}: {e}"))
}

pub fn content(n: u32, target: &str) -> Res<Vec<u8>> {
    fs::read(file_path(n, target)).map_err(|e| format!("generation {n} {target}: {e}"))
}

fn mkdir(p: &Path) -> Res<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p).map_err(|e| format!("{}: {e}", p.display()))?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", p.display()))
}

/// Store a rendered generation.
pub fn store(
    n: u32,
    g: &Generation,
    router_toml: &str,
    source: &str,
    user: &str,
    warnings: Vec<String>,
) -> Res<Manifest> {
    let d = dir(n);
    if d.exists() {
        return Err(format!("generation {n} already exists"));
    }
    mkdir(&d)?;
    write_atomic(&d.join("router.toml"), router_toml.as_bytes(), 0o600, "root", "wheel")?;
    let mut files = vec![];
    for f in &g.files {
        let p = file_path(n, &f.path);
        fs::create_dir_all(p.parent().unwrap()).map_err(|e| format!("{}: {e}", p.display()))?;
        // stored copies are root-only regardless of the target mode
        write_atomic(&p, f.content.as_bytes(), 0o600, "root", "wheel")?;
        files.push(FileMeta {
            path: f.path.clone(),
            mode: f.mode,
            owner: f.owner.clone(),
            group: f.group.clone(),
            subsystem: f.subsystem,
            secret: f.secret,
            sha256: sha(f.content.as_bytes()),
        });
    }
    let m = Manifest {
        generation: n,
        created: now(),
        source: source.into(),
        user: user.into(),
        files,
        services: g.services.clone(),
        absent: vec![],
        warnings,
    };
    save(&m)?;
    Ok(m)
}

pub fn save(m: &Manifest) -> Res<()> {
    let t = serde_json::to_string_pretty(m).map_err(|e| e.to_string())?;
    write_atomic(&dir(m.generation).join("manifest.json"), t.as_bytes(), 0o600, "root", "wheel")
}

/// Generation 0: copies of every live file the first generation touches or
/// octopus owns, and the services' rc state, so rollback can return the
/// router to how it was before octopus.
pub fn baseline(paths: &[String], services: Vec<Service>) -> Res<Manifest> {
    let d = dir(0);
    if d.exists() {
        return load(0);
    }
    mkdir(&d)?;
    let mut all: Vec<String> = paths.to_vec();
    if let Ok(rd) = fs::read_dir("/etc") {
        for e in rd.flatten() {
            let p = format!("/etc/{}", e.file_name().to_string_lossy());
            if owned_by_glob(&p) && !all.contains(&p) {
                all.push(p);
            }
        }
    }
    let mut files = vec![];
    let mut absent = vec![];
    for p in all {
        match fs::read(&p) {
            Ok(c) => {
                let meta = fs::metadata(&p).map_err(|e| format!("{p}: {e}"))?;
                let target = file_path(0, &p);
                fs::create_dir_all(target.parent().unwrap()).map_err(|e| e.to_string())?;
                write_atomic(&target, &c, 0o600, "root", "wheel")?;
                use std::os::unix::fs::MetadataExt;
                files.push(FileMeta {
                    path: p.clone(),
                    mode: meta.mode() & 0o7777,
                    owner: name_of("/etc/passwd", meta.uid()).unwrap_or_else(|| "root".into()),
                    group: name_of("/etc/group", meta.gid()).unwrap_or_else(|| "wheel".into()),
                    subsystem: subsystem_of(&p),
                    // treat every baseline file as secret: we don't know what's in it
                    secret: true,
                    sha256: sha(&c),
                });
            }
            Err(_) => absent.push(p),
        }
    }
    let m = Manifest {
        generation: 0,
        created: now(),
        source: "baseline".into(),
        user: "-".into(),
        files,
        services,
        absent,
        warnings: vec![],
    };
    save(&m)?;
    Ok(m)
}

fn name_of(file: &str, id: u32) -> Option<String> {
    let text = fs::read_to_string(file).ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[2].parse() == Ok(id)).then(|| f[0].to_string())
    })
}

pub fn subsystem_of(path: &str) -> Subsystem {
    match path {
        "/etc/pf.conf" => Subsystem::Pf,
        "/etc/dhcpd.conf" => Subsystem::Dhcpd,
        "/etc/ntpd.conf" => Subsystem::Ntpd,
        "/etc/ssh/sshd_config" => Subsystem::Sshd,
        "/etc/syslog.conf" => Subsystem::Syslogd,
        "/etc/resolv.conf" => Subsystem::Resolv,
        "/etc/sysctl.conf" => Subsystem::Sysctl,
        "/etc/rad.conf" => Subsystem::Rad,
        "/etc/dhcp6leased.conf" => Subsystem::Dhcp6,
        p if p.starts_with("/etc/octopus/dns/") => Subsystem::Dns,
        p if p.starts_with("/etc/octopus/web") => Subsystem::Web,
        "/etc/nginx/nginx.conf" => Subsystem::Nginx,
        "/etc/octopus/proxy.toml" => Subsystem::Proxy,
        "/etc/octopus/collector.toml" => Subsystem::Collector,
        "/etc/octopus/analyzer.toml" => Subsystem::Analyzer,
        _ => Subsystem::Net,
    }
}

/// Drop old generations, keeping the baseline, the newest `keep`, and any in `pinned`.
pub fn prune(keep: usize, pinned: &[u32]) {
    let all = list();
    let cut = all.len().saturating_sub(keep);
    for n in &all[..cut] {
        if *n != 0 && !pinned.contains(n) {
            let _ = fs::remove_dir_all(dir(*n));
        }
    }
}
