//! FCAP -> pcap: never panics, and what it emits contains only the
//! characters pcap filters are made of (no ;, quotes or shell syntax).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(f) = octopus_config::fcap::to_pcap(text) {
        assert!(f.chars().all(|c| c.is_ascii_alphanumeric() || " ().:/-&=!<>[]x".contains(c)), "{f}");
    }
});
