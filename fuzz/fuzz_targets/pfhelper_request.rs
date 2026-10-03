//! octopus-pfhelper's request line: whatever is accepted must be a table on
//! the allowlist, a known op and canonical addresses only.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else { return };
    let tables: Vec<String> = octopus_pfhelper::DEFAULT_TABLES.iter().map(|s| s.to_string()).collect();
    if let Ok((table, op, addrs)) = octopus_pfhelper::parse(line, &tables) {
        assert!(tables.contains(&table));
        assert!(["add", "delete", "replace"].contains(&op));
        for a in addrs {
            assert!(a.parse::<std::net::IpAddr>().is_ok() || a.parse::<ipnet_like::Net>().is_ok(), "{a}");
            assert!(!a.contains(char::is_whitespace) && !a.starts_with('-'), "{a}");
        }
    }
});

mod ipnet_like {
    /// prefix syntax check without another dependency
    pub struct Net;
    impl std::str::FromStr for Net {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let (a, p) = s.split_once('/').ok_or(())?;
            a.parse::<std::net::IpAddr>().map_err(|_| ())?;
            p.parse::<u8>().map_err(|_| ())?;
            Ok(Net)
        }
    }
}
