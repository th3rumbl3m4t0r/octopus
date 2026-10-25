//! octopus: compiles router.toml into OpenBSD configuration and applies it
//! with commit-confirm. It is a compiler, not a runtime: when it isn't
//! running, the router runs on plain OpenBSD files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use octopus_config::{Diagnostics, Router, Secrets, check::check, ifmap};
use octopus_render::{Generation, SecretSource, render};

// Output never fails: the reader (the web UI's pipe, a terminal) may be
// gone halfway through an apply, and the apply has to finish or revert.
macro_rules! out {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = writeln!(std::io::stdout(), $($t)*); }};
}
macro_rules! outn {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = write!(std::io::stdout(), $($t)*); }};
}
macro_rules! err {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = writeln!(std::io::stderr(), $($t)*); }};
}
macro_rules! errn {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = write!(std::io::stderr(), $($t)*); }};
}

mod ap;
mod apply;
mod diff;
mod gens;
mod guard;
mod os;
mod pki;
mod power;
mod secret;
mod status;
mod validate;

use os::{Res, log};

const USAGE: &str = "\
usage: octopus <command> [options]

compile
  check     [-c router.toml] [-s secrets.toml]   parse, resolve, check invariants
  build     [-c ...] [-s ...] -o DIR             render into DIR (placeholders without -s)
  validate  DIR [--offline]                      run the native validators on a rendered DIR
  diff      [-c ...]                             rendered vs live files (secrets hidden)

apply (root, OpenBSD)
  apply     [-c ...] [--timeout SECS] [--no-confirm] [--staged]
            build, validate, apply; roll back unless confirmed within SECS (60)
  confirm                                        keep the pending generation
  rollback  [GEN] [--no-confirm]                 revert the pending generation, or go to GEN
  generations                                    list stored generations
  show      GEN [PATH]                           files of a generation (secrets hidden)
  status    [--json]                             router state
  boot                                           at boot: revert an unconfirmed generation, check ports and pf
  supervise                                      (cron) start enabled octopus daemons that died

services root (design 14)
  pki init  [-c ...] -o DIR                      new root + intermediate (offline; keep root.key there)
  pki renew [--force]                            issue/renew the web UI's and vhosts' leaves (daily)
  pki status                                     leaves and days left
  pki csr CN [-o DIR]                            key + certificate request (e.g. the log server's client cert)
  pki intercept-init                             the interception root for [proxy] (servers only)

access points (OpenWrt, [wifi])
  ap key                                         the router's SSH key for them (made once); prints it
  ap trust  NAME                                 pin the access point's SSH host key (check its fingerprint)
  ap push   [NAME] [--force]                     run their scripts on them now (apply does it too)
  ap status                                      the last push of each
  secret set wifi_KEY < value                    a Wi-Fi passphrase into secrets.toml

tiers
  guard run                                      (octopus_guard) cut off devices on restricted addresses
  guard status | release MAC                     the blocked devices; lift a block

power ([power])
  power run                                      (octopus_power) file systems read-only while the UPS is on battery
  power status                                   the UPS feed, what is read-only, the boot's fsck repair

pfSense migration
  import-pfsense config.xml -o router.toml --secrets-out secrets.toml [--report FILE]
  redact    config.xml                           print config.xml with secrets removed

options
  -c FILE   router.toml (default /etc/octopus/router.toml)
  -s FILE   secrets.toml (default /etc/octopus/secrets.toml when it exists)
  --no-secrets      check with placeholders, not this machine's secrets.toml
  --ifconfig FILE   resolve MACs from saved `ifconfig -a` output instead of this machine
  --offline         don't resolve MACs; use the interfaces' `name` fields (CI, build VM)
";

const STAGED: &str = "/var/octopus/staged/router.toml";

struct Args {
    cmd: String,
    pos: Vec<String>,
    opts: BTreeMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    fn parse() -> Res<Args> {
        let mut it = std::env::args().skip(1);
        let cmd = it.next().ok_or(USAGE)?;
        let mut a = Args { cmd, pos: vec![], opts: BTreeMap::new(), flags: vec![] };
        let with_value = ["-c", "-s", "-o", "--timeout", "--ifconfig", "--secrets-out", "--report"];
        while let Some(x) = it.next() {
            if with_value.contains(&x.as_str()) {
                let v = it.next().ok_or_else(|| format!("{x} needs a value"))?;
                a.opts.insert(x, v);
            } else if x.starts_with("--") {
                a.flags.push(x);
            } else {
                a.pos.push(x);
            }
        }
        Ok(a)
    }

    fn flag(&self, f: &str) -> bool {
        self.flags.iter().any(|x| x == f)
    }

    fn config_path(&self) -> PathBuf {
        if self.flag("--staged") {
            return PathBuf::from(STAGED);
        }
        PathBuf::from(self.opts.get("-c").map(String::as_str).unwrap_or("/etc/octopus/router.toml"))
    }

    fn secrets(&self) -> Res<Option<Secrets>> {
        if self.flag("--no-secrets") {
            return Ok(None);
        }
        match self.opts.get("-s") {
            Some(p) => Secrets::load(Path::new(p)).map(Some),
            None => {
                let p = Path::new("/etc/octopus/secrets.toml");
                if p.exists() { Secrets::load(p).map(Some) } else { Ok(None) }
            }
        }
    }

    fn macs(&self) -> Res<BTreeMap<String, String>> {
        if self.flag("--offline") {
            return Ok(BTreeMap::new());
        }
        if let Some(f) = self.opts.get("--ifconfig") {
            let t = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
            return Ok(ifmap::parse_ifconfig(&t));
        }
        if os::is_openbsd() {
            return Ok(ifmap::parse_ifconfig(&os::run("ifconfig", &["-a"])?));
        }
        Ok(BTreeMap::new())
    }
}

/// Load, resolve and check. Prints diagnostics; Err when there are errors.
fn compile(a: &Args, secrets: Option<&Secrets>) -> Res<(Router, String, Diagnostics)> {
    let path = a.config_path();
    // the staging directory is _octoweb's: never follow its links into root's files
    let text = if a.flag("--staged") { os::read_owned(&path, os::WEB_USER, 4 << 20)? } else { read_limited(&path)? };
    let cfg = octopus_config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let r = Router::resolve(cfg, &a.macs()?).map_err(|d| d.to_string())?;
    let d = check(&r, secrets);
    errn!("{d}");
    if d.has_errors() {
        return Err(format!("{} error(s) in {}", d.errors().count(), path.display()));
    }
    Ok((r, text, d))
}

fn read_limited(p: &Path) -> Res<String> {
    let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if meta.len() > 4 << 20 {
        return Err(format!("{}: larger than 4 MiB", p.display()));
    }
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn render_with(r: &Router, secrets: Option<&Secrets>) -> Res<Generation> {
    match secrets {
        Some(s) => render(r, &SecretSource::Real(s)),
        None => render(r, &SecretSource::Placeholder),
    }
}

/// Is this SSH session coming in through the WireGuard tunnel?
fn session_via_wg(r: &Router) -> bool {
    let Some(wg) = &r.cfg.wireguard else { return false };
    std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<std::net::Ipv4Addr>().ok())
        .is_some_and(|ip| wg.address.trunc().contains(&ip))
}

fn need_root() -> Res<()> {
    if !os::is_openbsd() {
        return Err("this command runs on the OpenBSD router".into());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("this command needs root".into());
    }
    Ok(())
}

fn cmd_build(a: &Args) -> Res<()> {
    // placeholders unless -s names the real secrets: build output goes to disk
    let secrets = match a.opts.get("-s") {
        Some(p) => Some(Secrets::load(Path::new(p))?),
        None => None,
    };
    let (r, _, _) = compile(a, secrets.as_ref())?;
    let g = render_with(&r, secrets.as_ref())?;
    let out = PathBuf::from(a.opts.get("-o").ok_or("build needs -o DIR")?);
    // with real secrets the tree is the owner's alone, and every file has its
    // mode from the moment it exists
    if secrets.is_some() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&out).map_err(|e| e.to_string())?;
    }
    for f in &g.files {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let p = out.join(f.path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&p);
        let mut w = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(f.mode & 0o600)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        w.write_all(f.content.as_bytes()).map_err(|e| format!("{}: {e}", p.display()))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(f.mode)).map_err(|e| e.to_string())?;
    }
    let plan = serde_json::to_string_pretty(&g.services).map_err(|e| e.to_string())?;
    std::fs::write(out.join("services.json"), plan).map_err(|e| e.to_string())?;
    out!("rendered {} files into {}", g.files.len(), out.display());
    Ok(())
}

fn cmd_validate(a: &Args) -> Res<()> {
    let dir = PathBuf::from(a.pos.first().ok_or("validate needs DIR")?);
    let mut paths = vec![];
    for p in walk(&dir) {
        paths.push(format!("/{}", p.strip_prefix(&dir).unwrap().display()));
    }
    let mut failed = 0;
    for o in validate::tree(&dir, &paths, a.flag("--offline")) {
        match &o.result {
            Ok(()) => out!("ok    {:<34} {}", o.path, o.validator),
            Err(e) => {
                failed += 1;
                out!("FAIL  {:<34} {}\n      {}", o.path, o.validator, e.replace('\n', "\n      "));
            }
        }
    }
    if failed > 0 { Err(format!("{failed} file(s) failed validation")) } else { Ok(()) }
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { v.extend(walk(&p)) } else { v.push(p) }
        }
    }
    v.sort();
    v
}

fn cmd_diff(a: &Args) -> Res<()> {
    let secrets = a.secrets()?;
    let (r, _, _) = compile(a, secrets.as_ref())?;
    let g = render_with(&r, secrets.as_ref())?;
    let d = diff::render_vs_live(&g);
    if d.is_empty() {
        out!("no changes");
    } else {
        outn!("{d}");
    }
    Ok(())
}

fn cmd_apply(a: &Args) -> Res<()> {
    need_root()?;
    let _l = os::lock(&apply::lock_path())?;
    on_mains()?;
    let st = apply::load_state()?;
    if let Some(p) = &st.pending {
        return Err(format!("generation {} is waiting for confirm or rollback", p.generation));
    }
    // a full /var stops everything halfway: Kea's leases, the state, the generations
    if let Some(kb) = os::free_kb(&gens::root())
        && kb < 64 * 1024
    {
        return Err(format!(
            "only {} MB free in {}: make room first (logs in /var/log)",
            kb / 1024,
            gens::root().display()
        ));
    }
    let secrets = a.secrets()?.ok_or("/etc/octopus/secrets.toml is missing")?;
    let (r, text, diags) = compile(a, Some(&secrets))?;
    let g = render(&r, &SecretSource::Real(&secrets))?;
    // leaves for new vhosts must exist before nginx -t can pass
    let reissued = pki::renew(&r, false, true)?;

    let n = gens::next();
    let source = if a.flag("--staged") { "web" } else { "cli" };
    let warnings: Vec<String> = diags.0.iter().map(|d| d.to_string()).collect();
    let user = if a.flag("--staged") {
        // the web UI names its logged-in user next to the staged file
        let actor = os::read_owned(Path::new("/var/octopus/staged/actor"), os::WEB_USER, 256).unwrap_or_default();
        let actor: String =
            actor.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
        format!("web:{actor}")
    } else {
        os::invoking_user()
    };
    let mut m = gens::store(n, &g, &text, source, &user, warnings)?;
    // the ports by MAC as this machine names them now: `octopus boot` checks it
    m.ifmap = r
        .cfg
        .interfaces
        .iter()
        .filter_map(|(role, i)| Some((ifmap::normalize_mac(&i.mac)?, r.phys.get(role)?.clone())))
        .collect();
    gens::save(&m)?;
    let paths: Vec<String> = g.files.iter().map(|f| f.path.clone()).collect();
    let mut planned: Vec<String> = r.nets.iter().map(|x| x.addr.to_string()).collect();
    // IPv6 as nginx writes it: [address]
    planned.extend(r.nets.iter().filter_map(|x| x.v6).map(|v| format!("[{}]", v.ula.addr())));
    if let Some(w) = &r.cfg.wireguard {
        planned.push(w.address.addr().to_string());
    }
    if let Err(e) = validate::generation(n, &paths, &planned) {
        let _ = std::fs::remove_dir_all(gens::dir(n));
        return Err(format!("validation failed (INV-6), nothing applied:\n{e}"));
    }
    if let Err(e) = apply::preflight(&m) {
        let _ = std::fs::remove_dir_all(gens::dir(n));
        return Err(e);
    }

    // generation 0 keeps the pre-octopus copy of every file before octopus first writes it
    let base = gens::baseline(&paths, apply::services_now(&g.services))?;
    let previous = st.confirmed.unwrap_or(0);
    let from = st.current.and_then(|c| gens::load(c).ok());

    let p = apply::plan(&m, from.as_ref());
    // "no changes" only when the live generation is also the recorded one: an
    // apply that died before it was recorded is recorded now
    if p.write.is_empty() && p.delete.is_empty() && from.as_ref().is_some_and(|f| apply::same_files(f, &m)) {
        let _ = std::fs::remove_dir_all(gens::dir(n));
        for x in restart_reissued(&reissued, &[]) {
            out!("  {x}");
        }
        if let Some(x) = apply::lift_lockdown(from.as_ref().unwrap_or(&m))? {
            out!("  {x}");
        }
        out!("no changes");
        return Ok(());
    }
    let mut secs: u64 =
        a.opts.get("--timeout").map(|t| t.parse().map_err(|_| "bad --timeout")).transpose()?.unwrap_or(60);
    // applying a WireGuard change over WireGuard drops this session: leave
    // time to reconnect and confirm
    if !a.opts.contains_key("--timeout") && p.write.iter().any(|f| f == "/etc/hostname.wg0") && session_via_wg(&r) {
        secs = secs.max(300);
        out!("note: this session runs over WireGuard, which was just reconfigured; confirm window {secs}s");
    }
    log(&format!(
        "applying generation {n} ({source} by {user}): {} file(s), {} removal(s)",
        p.write.len(),
        p.delete.len()
    ));
    let mut actions = go_live(&m, from.as_ref().or(Some(&base)), previous, secs, a.flag("--no-confirm"))?;
    actions.extend(restart_reissued(&reissued, &actions));
    actions.extend(apply::lift_lockdown(&m)?);
    for x in &actions {
        out!("  {x}");
    }
    if a.flag("--no-confirm") {
        log(&format!("generation {n} applied without confirm"));
    } else {
        out!("generation {n} is live; run `octopus confirm` within {secs}s or it is rolled back to {previous}");
    }
    gens::prune(20, &[previous, n]);
    Ok(())
}

/// Make stored generation `m` live over `from`, write-ahead: it is recorded
/// as pending and watched before the first file changes, so an apply that
/// dies anywhere (a signal, a crash, power) is reverted, by the watchdog
/// now or by `octopus boot` after a reboot. An error reverts at once.
/// Confirmed at the end when `no_confirm`, else open for `secs`.
fn go_live(
    m: &gens::Manifest,
    from: Option<&gens::Manifest>,
    previous: u32,
    secs: u64,
    no_confirm: bool,
) -> Res<Vec<String>> {
    let n = m.generation;
    let before = apply::load_state()?;
    let mut st = apply::State {
        current: Some(n),
        confirmed: Some(previous),
        pending: Some(apply::Pending {
            generation: n,
            previous,
            deadline: os::now() + secs,
            window: secs,
            applying: true,
            boot: apply::boot_id(),
            reverting: false,
            revert_failures: 0,
        }),
    };
    apply::save_state(&st)?;
    if let Err(e) = apply::spawn_watchdog(n, previous) {
        // nothing has changed yet
        apply::save_state(&before)?;
        return Err(format!("cannot start the commit-confirm watchdog ({e}); nothing applied"));
    }
    let actions = match apply::apply_manifest(m, from) {
        Ok(actions) => actions,
        Err(e) => {
            // revert first, report after: whoever reads our output may be gone
            let back = apply::revert_pending(&st);
            log(&format!("apply of generation {n} failed: {e}"));
            return Err(match back {
                Ok(()) => format!("apply failed, generation {previous} restored: {e}"),
                Err(b) => format!("apply failed: {e}\n{b}"),
            });
        }
    };
    apply::install_source(n)?;
    if no_confirm {
        st = apply::State { current: Some(n), confirmed: Some(n), pending: None };
    } else if let Some(p) = st.pending.as_mut() {
        p.applying = false;
        p.deadline = os::now() + secs;
    }
    apply::save_state(&st)?;
    Ok(actions)
}

/// Services whose certificate `pki renew` just issued and that the apply
/// didn't restart anyway: they read it at start.
fn restart_reissued(reissued: &[&str], actions: &[String]) -> Vec<String> {
    let mut done = vec![];
    for svc in reissued {
        if actions.iter().any(|a| a.contains(&format!(" {svc}"))) || !os::ok("rcctl", &["check", svc]) {
            continue;
        }
        if *svc == "octopus_web" {
            apply::restart_web_later();
            done.push(format!("restart {svc} in a few seconds (new certificate)"));
        } else {
            let action = if *svc == "nginx" { "reload" } else { "restart" };
            let _ = os::run("rcctl", &[action, svc]);
            done.push(format!("{action} {svc} (new certificate)"));
        }
    }
    done
}

fn cmd_confirm() -> Res<()> {
    need_root()?;
    let _l = os::lock(&apply::lock_path())?;
    let mut st = apply::load_state()?;
    let p = st.pending.take().ok_or("nothing to confirm")?;
    if p.reverting {
        return Err(format!("generation {} is being rolled back; too late to confirm", p.generation));
    }
    if p.applying {
        return Err(format!("generation {} is still being applied", p.generation));
    }
    st.confirmed = Some(p.generation);
    apply::save_state(&st)?;
    log(&format!("generation {} confirmed by {}", p.generation, os::invoking_user()));
    out!("generation {} confirmed", p.generation);
    // new public sites run on placeholders until acme-client has their certificates
    let placeholders = std::fs::read_dir("/etc/ssl")
        .map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".octopus-placeholder")))
        .unwrap_or(false);
    if placeholders {
        match apply::spawn_detached(&["pki", "renew"]) {
            Ok(()) => {
                out!("acme-client is getting the public sites' certificates (octopus pki status, /var/log/daemon)")
            }
            Err(e) => log(&format!("pki renew after confirm: {e}")),
        }
    }
    Ok(())
}

fn cmd_rollback(a: &Args) -> Res<()> {
    need_root()?;
    let _l = os::lock(&apply::lock_path())?;
    on_mains()?;
    let st = apply::load_state()?;
    match a.pos.first() {
        None => {
            apply::revert_pending(&st)?;
            out!("rolled back");
            Ok(())
        }
        Some(g) => {
            if st.pending.is_some() {
                return Err("a generation is pending: confirm or roll it back first".into());
            }
            let n: u32 = g.parse().map_err(|_| "GEN must be a number")?;
            let to = gens::load(n)?;
            apply::preflight(&to)?;
            let paths: Vec<String> = to.files.iter().map(|f| f.path.clone()).collect();
            gens::baseline(&paths, apply::services_now(&to.services))?;
            let from = st.current.and_then(|c| gens::load(c).ok());
            let previous = st.confirmed.unwrap_or(0);
            log(&format!("rollback to generation {n} by {}", os::invoking_user()));
            let no_confirm = a.flag("--no-confirm");
            for x in go_live(&to, from.as_ref(), previous, 60, no_confirm)? {
                out!("  {x}");
            }
            if !no_confirm {
                out!("generation {n} is live; `octopus confirm` within 60s");
            }
            Ok(())
        }
    }
}

fn cmd_generations() -> Res<()> {
    let st = apply::load_state()?;
    for n in gens::list() {
        let m = gens::load(n)?;
        let mut tags = vec![];
        if st.current == Some(n) {
            tags.push("current");
        }
        if st.confirmed == Some(n) {
            tags.push("confirmed");
        }
        if st.pending.as_ref().is_some_and(|p| p.generation == n) {
            tags.push("PENDING");
        }
        out!("{:>4}  {}  {:<9} {:<10} {:>3} files  {}", n, m.created, m.source, m.user, m.files.len(), tags.join(","));
    }
    Ok(())
}

fn cmd_show(a: &Args) -> Res<()> {
    let n: u32 = a.pos.first().ok_or("show needs GEN")?.parse().map_err(|_| "GEN must be a number")?;
    let m = gens::load(n)?;
    match a.pos.get(1) {
        None => {
            for f in &m.files {
                out!(
                    "{:o} {:<8} {:<10} {}{}",
                    f.mode,
                    f.owner,
                    f.subsystem.name(),
                    f.path,
                    if f.secret { "  (secret)" } else { "" }
                );
            }
            for s in &m.services {
                out!(
                    "service {:<14} {} {}",
                    s.name,
                    if s.enabled { "on " } else { "off" },
                    s.flags.as_deref().unwrap_or("")
                );
            }
        }
        Some(p) => {
            let f = m.files.iter().find(|f| &f.path == p).ok_or("no such file in that generation")?;
            if f.secret {
                return Err("that file contains secrets; read it on the router directly".into());
            }
            outn!("{}", String::from_utf8_lossy(&gens::content(n, p)?));
        }
    }
    Ok(())
}

fn cmd_status(a: &Args) -> Res<()> {
    let v = status::collect();
    if a.flag("--json") {
        out!("{v}");
        return Ok(());
    }
    out!(
        "{} OpenBSD {}  up {}s  load {}",
        v["hostname"].as_str().unwrap_or(""),
        v["release"].as_str().unwrap_or(""),
        v["uptime"],
        v["load"].as_str().unwrap_or("")
    );
    out!(
        "generation current={} confirmed={} pending={}",
        v["state"]["current"],
        v["state"]["confirmed"],
        v["state"]["pending"]
    );
    for i in v["interfaces"].as_array().into_iter().flatten() {
        out!(
            "  {:<10} {:<12} {:<4} {:<22} {}",
            i["name"].as_str().unwrap_or(""),
            i["description"].as_str().unwrap_or(""),
            if i["up"].as_bool() == Some(true) { "up" } else { "down" },
            i["status"].as_str().unwrap_or(""),
            i["inet"]
        );
    }
    out!("pf states {}", v["pf"]["states"]);
    Ok(())
}

fn cmd_boot() -> Res<()> {
    need_root()?;
    let _l = os::lock(&apply::lock_path())?;
    // after an upgrade /etc/rc is OpenBSD's again: the fsck repair goes back in
    power::ensure_rc();
    let st = apply::load_state().inspect_err(|e| log(&format!("boot: {e}")))?;
    let r = boot_revert(&st);
    // whatever generation is live now: are its ports where it put them, and
    // is its ruleset loaded?
    if let Ok(st) = apply::load_state()
        && let Some(m) = st.current.and_then(|c| gens::load(c).ok())
    {
        apply::boot_checks(&m);
    }
    r
}

/// Every few minutes from cron: the live generation's octopus daemons that
/// should run but don't (a crash; they abort on a panic) start again. Not
/// while an apply or rollback runs.
fn cmd_supervise() -> Res<()> {
    let Ok(_l) = os::lock(&apply::lock_path()) else { return Ok(()) };
    power::ensure_rc();
    let st = apply::load_state()?;
    let Some(m) = st.current.and_then(|c| gens::load(c).ok()) else { return Ok(()) };
    // a boot lockdown keeps DHCP off until an apply lifts it
    let locked = apply::locked_down();
    for s in m.services.iter().filter(|s| s.enabled && s.name.starts_with("octopus_")) {
        if locked && s.name == "octopus_kea" {
            continue;
        }
        if !os::ok("rcctl", &["check", &s.name]) {
            let r = os::run("rcctl", &["start", &s.name]);
            log(&format!(
                "supervise: {} wasn't running; {}",
                s.name,
                if r.is_ok() { "started" } else { "it doesn't start" }
            ));
        }
    }
    Ok(())
}

/// Applies and rollbacks write /etc: not while the power guard has it read-only.
fn on_mains() -> Res<()> {
    let ro = power::readonly_now();
    if !ro.iter().any(|m| m == "/") {
        return Ok(());
    }
    Err(format!("on battery: the power guard has {} read-only; try again once the mains is back", ro.join(" ")))
}

fn boot_revert(st: &apply::State) -> Res<()> {
    if let Some(p) = &st.pending {
        if !p.applying && !p.reverting && !p.boot.is_empty() && p.boot == apply::boot_id() {
            // applied earlier in this boot (rc.firsttime): its watchdog decides
            log(&format!("boot: generation {} is pending; confirm it or it rolls back", p.generation));
            return Ok(());
        }
        log(&format!("boot: generation {} was never confirmed; rolling back to {}", p.generation, p.previous));
        if let Err(e) = apply::revert_pending(st) {
            log(&format!("boot: {e}; trying again in the background"));
            let _ = apply::spawn_watchdog(p.generation, p.previous);
            return Err(e);
        }
    }
    Ok(())
}

fn cmd_pki(a: &Args) -> Res<()> {
    let sub = a.pos.first().map(String::as_str).unwrap_or("status");
    if sub == "csr" {
        // needs no router.toml
        let cn = a.pos.get(1).ok_or("pki csr needs a CN")?;
        let dir = PathBuf::from(a.opts.get("-o").map(String::as_str).unwrap_or("."));
        let (csr, key) = octopus_pki::csr(cn)?;
        let keyp = dir.join(format!("{cn}.key"));
        if keyp.exists() {
            return Err(format!("{} exists; not replacing a key", keyp.display()));
        }
        os::write_atomic(&keyp, key.as_bytes(), 0o600, "root", "wheel")?;
        os::write_atomic(&dir.join(format!("{cn}.csr")), csr.as_bytes(), 0o644, "root", "wheel")?;
        out!("{}", csr.trim());
        out!("key: {} (stays here); have the request signed and save the certificate as {cn}.crt", keyp.display());
        return Ok(());
    }
    let (r, _, _) = compile(a, None)?;
    match sub {
        "init" => pki::init(&r, Path::new(a.opts.get("-o").ok_or("pki init needs -o DIR")?)),
        "status" => {
            pki::status(&r);
            Ok(())
        }
        "intercept-init" => {
            need_root()?;
            pki::intercept_init(&r)
        }
        "renew" => {
            need_root()?;
            // not while an apply runs or a generation waits for its confirm:
            // the leaves would follow a configuration that may not stay
            let _l = os::lock_wait(&apply::lock_path(), 120)?;
            if let Some(p) = apply::load_state()?.pending {
                out!("generation {} is pending: not renewing now", p.generation);
                return Ok(());
            }
            let (r, _, _) = compile(a, None)?;
            for svc in pki::renew(&r, a.flag("--force"), false)? {
                if os::ok("rcctl", &["check", svc]) {
                    let action = if svc == "nginx" { "reload" } else { "restart" };
                    os::run("rcctl", &[action, svc])?;
                    out!("{action} {svc}");
                }
            }
            Ok(())
        }
        other => Err(format!("unknown pki command {other:?}")),
    }
}

fn cmd_import(a: &Args) -> Res<()> {
    let src = a.pos.first().ok_or("import-pfsense needs config.xml")?;
    let xml = std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))?;
    let out = a.opts.get("-o").ok_or("import-pfsense needs -o router.toml")?;
    let sec_out = a.opts.get("--secrets-out").ok_or("import-pfsense needs --secrets-out secrets.toml")?;
    // MACs come from the pfSense box's `ifconfig -a`; config.xml has none
    let macs: BTreeMap<String, String> = match a.opts.get("--ifconfig") {
        Some(f) => {
            let t = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
            ifmap::parse_ifconfig(&t).into_iter().map(|(mac, name)| (name, mac)).collect()
        }
        None => BTreeMap::new(),
    };
    let imp = octopus_import_pfsense::import_with(&xml, &macs)?;
    std::fs::write(out, &imp.router_toml).map_err(|e| format!("{out}: {e}"))?;
    os::write_atomic(Path::new(sec_out), imp.secrets.to_toml().as_bytes(), 0o600, "root", "wheel")?;
    let report = imp.report.join("\n") + "\n";
    match a.opts.get("--report") {
        Some(r) => std::fs::write(r, &report).map_err(|e| format!("{r}: {e}"))?,
        None => errn!("{report}"),
    }
    out!(
        "wrote {out} and {sec_out} ({} secret(s): {})",
        imp.secrets.keys().count(),
        imp.secrets.keys().collect::<Vec<_>>().join(", ")
    );
    Ok(())
}

fn cmd_redact(a: &Args) -> Res<()> {
    let src = a.pos.first().ok_or("redact needs config.xml")?;
    let xml = std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))?;
    outn!("{}", octopus_import_pfsense::redact(&xml)?);
    Ok(())
}

fn main() -> ExitCode {
    let a = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            errn!("{e}");
            return ExitCode::from(2);
        }
    };
    // Commands that change the router run to the end whoever stops reading
    // (a closed browser tab, a restarted web UI, a dropped SSH session, ^C):
    // an apply that dies halfway is what commit-confirm can't always undo.
    // Read-only ones end quietly when the reader goes (`octopus diff | head`).
    let changes = matches!(
        a.cmd.as_str(),
        "apply" | "confirm" | "rollback" | "boot" | "supervise" | "_watchdog" | "pki" | "ap" | "guard" | "secret"
    );
    if changes {
        os::outlive_reader();
    } else {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    let r = match a.cmd.as_str() {
        "check" => a.secrets().and_then(|s| compile(&a, s.as_ref())).map(|(r, _, _)| {
            out!(
                "ok: {} networks, {} hosts, {} rules, {} forwards",
                r.nets.len(),
                r.cfg.hosts.len(),
                r.cfg.rules.len(),
                r.cfg.forwards.len()
            );
        }),
        "build" => cmd_build(&a),
        "validate" => cmd_validate(&a),
        "diff" => cmd_diff(&a),
        "apply" => cmd_apply(&a),
        "confirm" => cmd_confirm(),
        "rollback" => cmd_rollback(&a),
        "generations" => cmd_generations(),
        "show" => cmd_show(&a),
        "status" => cmd_status(&a),
        "boot" => cmd_boot(),
        "supervise" => need_root().and_then(|_| cmd_supervise()),
        "import-pfsense" => cmd_import(&a),
        "pki" => cmd_pki(&a),
        // only files and ssh: root, but not necessarily the router
        "ap" => ap::root().and_then(|_| {
            ap::cmd(
                a.pos.first().map(String::as_str).unwrap_or("status"),
                a.pos.get(1).map(String::as_str),
                a.flag("--force"),
            )
        }),
        "guard" => need_root().and_then(|_| guard::cmd(&a.pos, a.flag("--staged"))),
        "power" => need_root().and_then(|_| power::cmd(&a.pos)),
        "_power-probe" => match a.pos.first() {
            Some(url) => power::probe(url),
            None => Err("usage: _power-probe URL".into()),
        },
        "secret" => need_root().and_then(|_| secret::cmd(&a.pos, a.flag("--staged"))),
        "redact" => cmd_redact(&a),
        "_watchdog" => {
            let n = a.pos.first().and_then(|x| x.parse().ok());
            let p = a.pos.get(1).and_then(|x| x.parse().ok());
            match (n, p) {
                (Some(n), Some(p)) => apply::watchdog(n, p),
                _ => Err("usage: _watchdog GEN PREVIOUS".into()),
            }
        }
        "help" | "-h" | "--help" => {
            outn!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n{USAGE}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            err!("octopus: {e}");
            ExitCode::FAILURE
        }
    }
}
