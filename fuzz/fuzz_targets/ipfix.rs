//! pflow's IPFIX: templates then data, in any order and any shape.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut p = octopus_collector::ipfix::Parser::new();
    // the same input twice: the second pass sees the templates of the first
    let _ = p.message(data);
    let _ = p.message(data);
});
