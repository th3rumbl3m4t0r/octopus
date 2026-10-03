//! router.toml from anyone who can reach the web UI's check: parse, resolve,
//! check and render must never panic, whatever the text.
#![no_main]
use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(cfg) = octopus_config::parse(text) else { return };
    let Ok(r) = octopus_config::Router::resolve(cfg, &BTreeMap::new()) else { return };
    let d = octopus_config::check::check(&r, None);
    if !d.has_errors() {
        let _ = octopus_render::render(&r, &octopus_render::SecretSource::Placeholder);
    }
});
