//! MAC address to interface name, from `ifconfig -a` output.

use std::collections::BTreeMap;

/// Normalise a MAC to lowercase colon form; None if it isn't six octets.
pub fn normalize_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = Vec::with_capacity(6);
    for p in parts {
        if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(format!("{:0>2}", p.to_ascii_lowercase()));
    }
    Some(out.join(":"))
}

/// Parse `ifconfig -a` (OpenBSD or FreeBSD): physical interfaces only (those with `lladdr` that
/// aren't pseudo-devices we create ourselves).
pub fn parse_ifconfig(text: &str) -> BTreeMap<String, String> {
    const PSEUDO: [&str; 13] =
        ["vlan", "svlan", "pppoe", "wg", "pflow", "pflog", "enc", "lo", "carp", "bridge", "veb", "vport", "vether"];
    let mut map = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split(':').next().map(str::to_string);
            continue;
        }
        let Some(name) = &current else { continue };
        let stem: String = name.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        // FreeBSD names vlans parent.tag
        if PSEUDO.contains(&stem.as_str()) || name.contains('.') {
            continue;
        }
        let mut words = line.split_whitespace();
        // OpenBSD says lladdr, FreeBSD (pfSense) says ether
        if matches!(words.next(), Some("lladdr" | "ether"))
            && let Some(mac) = words.next().and_then(normalize_mac)
        {
            map.insert(mac, name.clone());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openbsd_ifconfig() {
        let text = "lo0: flags=2008049<UP,LOOPBACK,RUNNING,MULTICAST,LRO> mtu 32768\n\
                    \tinet 127.0.0.1 netmask 0xff000000\n\
                    igc1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                    \tlladdr 02:00:5e:10:00:0a\n\
                    \tindex 2 priority 0 llprio 3\n\
                    vlan848: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                    \tlladdr 02:00:5e:10:00:0b\n";
        let m = parse_ifconfig(text);
        assert_eq!(m.len(), 1);
        assert_eq!(m["02:00:5e:10:00:0a"], "igc1");
        assert_eq!(normalize_mac("02-00-5E-10-00-0B").as_deref(), Some("02:00:5e:10:00:0b"));
        assert_eq!(normalize_mac("02:00:5e:10:00"), None);
    }
}
