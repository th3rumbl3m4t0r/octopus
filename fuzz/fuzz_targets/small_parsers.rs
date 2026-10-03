//! ifconfig output, secrets.toml, port specs.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = octopus_config::ifmap::parse_ifconfig(text);
    if let Ok(s) = octopus_config::Secrets::parse(text) {
        // values never leak through Debug
        let _ = format!("{s:?}");
    }
    let _ = text.parse::<octopus_config::schema::Ports>();
    let _ = octopus_config::check::parse_remote(text);
    let _ = octopus_config::check::parse_rate(text);
});
