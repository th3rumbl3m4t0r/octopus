//! IPv6 (`[ipv6] mode = "pd"`): dhcp6leased asks the ISP for a prefix on the
//! WAN and gives every network a /64 from it; rad advertises them. Every
//! network also has a stable unique local /64 (in hostname.if) for the
//! router's DNS and NTP.
//!
//! dhcp6leased hands out the delegated prefix in list order, so the list
//! always has 2^(64 - request) entries: each network at its slot, `reserve`
//! everywhere else. Adding or removing a network never renumbers another.

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::schema::Ipv6Mode;

use crate::{Generation, Subsystem, header};

pub(crate) fn render(r: &Router, g: &mut Generation) {
    let c = &r.cfg;
    if c.ipv6.mode != Ipv6Mode::Pd {
        return;
    }
    let nets: Vec<_> = r.nets.iter().filter(|n| n.v6.is_some()).collect();

    if let Some(w) = &r.wan {
        let slots = 1usize << (64 - c.ipv6.request.clamp(48, 64) as usize);
        let mut list = vec!["reserve".to_string(); slots];
        for n in &nets {
            let slot = n.v6.unwrap().slot as usize;
            if slot < slots {
                list[slot] = n.ifname.clone();
            }
        }
        let mut s = header("#", &[&format!("a /{} from the ISP; one /64 per network at its slot", c.ipv6.request)]);
        s += "request rapid commit\n";
        let _ = writeln!(s, "request prefix delegation on {} for {{", w.egress);
        for (i, name) in list.iter().enumerate() {
            let _ = writeln!(s, "\t{name}\t# slot {i}");
        }
        s += "}\n";
        g.file("/etc/dhcp6leased.conf", s, Subsystem::Dhcp6);
    }

    let mut s = header("#", &["router advertisements: prefixes come from the interfaces' addresses"]);
    if c.ipv6.advertise_dns {
        // the unique local address is stable; the delegated one may change
        if let Some(first) = nets.first() {
            let _ =
                writeln!(s, "dns {{\n\tnameserver {}\n\tsearch {}\n}}", first.v6.unwrap().ula.addr(), c.system.domain);
        }
    }
    for n in &nets {
        let _ = writeln!(s, "interface {}\t# {}", n.ifname, n.name);
    }
    g.file("/etc/rad.conf", s, Subsystem::Rad);
}
