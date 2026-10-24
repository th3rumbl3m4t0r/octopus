//! router.toml from anyone who can reach the web UI's check: parse, resolve,
//! check and render must never panic, whatever the text; and what passes
//! check renders to files where no text became syntax.
#![no_main]
use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(cfg) = octopus_config::parse(text) else { return };
    let Ok(r) = octopus_config::Router::resolve(cfg, &BTreeMap::new()) else { return };
    let d = octopus_config::check::check(&r, None);
    if d.has_errors() {
        return;
    }
    let Ok(g) = octopus_render::render(&r, &octopus_render::SecretSource::Placeholder) else { return };
    let pf = &g.get("/etc/pf.conf").expect("pf.conf").content;
    // a comment never continues onto the next line, and every rule is there
    for l in pf.lines() {
        if let Some(c) = l.split_once('#').map(|x| x.1) {
            assert!(!c.ends_with('\\'), "comment continues: {l}");
        }
    }
    for k in 1..=r.cfg.rules.len() {
        let label = format!("label \"rule:{k}\"");
        let comment_only = format!("# rule:{k} can't match");
        assert!(pf.contains(&label) || pf.contains(&comment_only), "rule {k} is missing");
    }
    // every hostname.* line: no expansions outside single quotes
    for f in g.files.iter().filter(|f| f.path.starts_with("/etc/hostname.")) {
        for l in f.content.lines().filter(|l| !l.starts_with('#')) {
            let unquoted: String = l.split('\'').step_by(2).collect();
            assert!(!unquoted.contains(['$', '`', ';', '|', '&', '>', '<']), "{}: {l}", f.path);
        }
    }
    // sshd_config: exactly the lines it is made of
    let sshd = &g.get("/etc/ssh/sshd_config").expect("sshd_config").content;
    for l in sshd.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let k = l.split_whitespace().next().unwrap_or("");
        assert!(
            ["ListenAddress", "Port", "PermitRootLogin", "PasswordAuthentication", "KbdInteractiveAuthentication", "AuthorizedKeysFile", "Subsystem"].contains(&k),
            "sshd_config: {l}"
        );
    }
});
