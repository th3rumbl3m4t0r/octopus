//! pfSense config.xml: import and redaction must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = octopus_import_pfsense::redact(text);
    if let Ok(imp) = octopus_import_pfsense::import(text) {
        // whatever it imports must at least parse again
        let _ = octopus_config::parse(&imp.router_toml);
    }
});
