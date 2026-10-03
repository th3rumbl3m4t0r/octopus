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

pub fn matches(list: &[String], host: &str) -> bool {
    let h = normalize(host);
    if h.is_empty() {
        return false;
    }
    list.iter().any(|p| {
        let p = p.to_ascii_lowercase();
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
    }
}
