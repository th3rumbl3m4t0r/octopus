//! Allowlist matching: exact names and `*.domain` (any name below domain,
//! not domain itself). Names are compared lowercase, without a port or a
//! trailing dot.

pub fn normalize(host: &str) -> String {
    let h = host.trim().trim_end_matches('.');
    // strip a port, but not from an IPv6 literal
    let h = match h.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => h,
    };
    h.to_ascii_lowercase()
}

/// An address the proxy may connect to for a name: on the internet, not
/// the router, the inside or anything else local.
pub fn global(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || o[0] >= 240)
        }
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => global(IpAddr::V4(v4)),
            None => {
                let s = a.segments()[0];
                !(a.is_loopback()
                    || a.is_unspecified()
                    || a.is_multicast()
                    || (s & 0xfe00) == 0xfc00
                    || (s & 0xffc0) == 0xfe80)
            }
        },
    }
}

pub fn matches(list: &[String], host: &str) -> bool {
    let h = normalize(host);
    if h.is_empty() {
        return false;
    }
    list.iter().any(|p| {
        // `deb.debian.org.` and `deb.debian.org` are one name
        let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
        match p.strip_prefix("*.") {
            Some(base) => {
                h.len() > base.len() + 1 && h.ends_with(base) && h.as_bytes()[h.len() - base.len() - 1] == b'.'
            }
            None => h == p,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let l = vec!["deb.debian.org".to_string(), "*.badssl.com".to_string()];
        assert!(matches(&l, "deb.debian.org"));
        assert!(matches(&l, "DEB.debian.org."));
        assert!(matches(&l, "deb.debian.org:443"));
        assert!(matches(&l, "expired.badssl.com"));
        assert!(!matches(&l, "badssl.com"));
        assert!(!matches(&l, "evilbadssl.com"));
        assert!(!matches(&l, "x.deb.debian.org"));
        assert!(!matches(&l, ""));
        assert!(!matches(&l, "debian.org"));
        let dotted = vec!["deb.debian.org.".to_string(), "*.example.org.".to_string()];
        assert!(matches(&dotted, "deb.debian.org") && matches(&dotted, "a.example.org."));
    }

    #[test]
    fn only_global_upstreams() {
        for ok in ["151.101.2.132", "2a04:4e42::644"] {
            assert!(global(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!global(bad.parse().unwrap()), "{bad}");
        }
    }
}
