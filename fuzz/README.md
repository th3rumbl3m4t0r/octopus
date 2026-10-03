# Fuzzing (design R8)

Every parser of outside input has a target. Needs nightly and cargo-fuzz:

```sh
rustup toolchain install nightly && cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run -O router_toml       # router.toml: parse, resolve, check, render
cargo +nightly fuzz run -O pfsense_import    # config.xml: import, redact
cargo +nightly fuzz run -O pfhelper_request  # octopus-pfhelper requests: accepted => allow-listed and canonical
cargo +nightly fuzz run -O small_parsers     # ifconfig output, secrets.toml, ports, syslog targets, rates
cargo +nightly fuzz run -O ipfix             # pflow's IPFIX messages (octopus-collector)
cargo +nightly fuzz run -O fcap              # FCAP -> pcap filter: output is filter syntax only
```

Seed `corpus/<target>/` with real inputs (redacted config.xml, the site
configs, a pflow capture). DNS wire parsing is hickory's (design R1), TLS and
HTTP in octopus-proxy are rustls's and hyper's, packet dissection in the
analyzer is etherparse's: all fuzzed upstream.

2026-10-01 on buildvm: router_toml 478 k, pfsense_import 201 k,
pfhelper_request 14.8 M, small_parsers 1.75 M (90 s each); ipfix 1.4 M,
fcap 3.8 M (60 s each). No crashes.
