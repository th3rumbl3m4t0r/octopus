//! pfSense config.xml: import and redaction must never panic; what the
//! import writes parses again, and has no top-level part it didn't mean to.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = octopus_import_pfsense::redact(text);
    if let Ok(imp) = octopus_import_pfsense::import(text) {
        let doc: toml::Table = imp.router_toml.parse().expect("the imported router.toml parses");
        const KNOWN: [&str; 12] =
            ["system", "interfaces", "wan", "networks", "hosts", "tables", "forwards", "rules", "dns", "ntp", "ssh", "logging"];
        for k in doc.keys() {
            assert!(KNOWN.contains(&k.as_str()), "imported router.toml has a {k:?}");
        }
        // secrets never show in Debug
        let dbg = format!("{:?}", imp.secrets);
        for k in imp.secrets.keys() {
            let v = imp.secrets.resolve(&format!("secret:{k}")).unwrap_or("");
            assert!(v.len() < 4 || !dbg.contains(v), "{k} in Debug");
        }
    }
});
