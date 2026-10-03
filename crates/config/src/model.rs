//! The resolved router: roles bound to interface names, networks laid out,
//! endpoint strings resolved. Renderers work from this, never from raw strings.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::diag::Diagnostics;
use crate::ifmap::normalize_mac;
use crate::schema::*;

#[derive(Debug, Clone)]
pub struct Net {
    pub name: String,
    /// Interface carrying the network: `igc1`, `vlan20`, or `vport0` for a bridge.
    pub ifname: String,
    /// Physical parent when tagged.
    pub parent: Option<String>,
    pub vlan: Option<u16>,
    /// `veb0` when the network bridges several ports.
    pub bridge: Option<String>,
    /// The bridged ports (physical names).
    pub members: Vec<String>,
    /// Set when the interface carries several tiers (the house ports,
    /// untagged): this tier is told apart by its source addresses.
    pub src: Option<Ipv4Net>,
    /// IPv6: the /64 slot and the router's ULA address in it.
    pub v6: Option<V6>,
    /// Router address.
    pub addr: Ipv4Addr,
    /// Network prefix (host bits zero).
    pub prefix: Ipv4Net,
    pub kind: Kind,
    pub class: Class,
}

#[derive(Debug, Clone, Copy)]
pub struct V6 {
    pub slot: u8,
    /// The router's unique local address, `ula:slot::1/64`.
    pub ula: Ipv6Net,
}

impl Net {
    /// Ports whose egress queue carries this network's traffic.
    pub fn ports(&self) -> Vec<&str> {
        if !self.members.is_empty() {
            self.members.iter().map(String::as_str).collect()
        } else {
            vec![self.parent.as_deref().unwrap_or(&self.ifname)]
        }
    }
}

/// The ULA /48: configured, or derived from the router's name so it stays
/// the same across reinstalls (RFC 4193 wants it random-looking, not secret).
pub fn ula_prefix(cfg: &Config) -> Ipv6Net {
    if let Some(u) = cfg.ipv6.ula {
        return u.trunc();
    }
    // FNV-1a over hostname.domain: 40 bits of global ID
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{}.{}", cfg.system.hostname, cfg.system.domain).bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let g = h & 0xff_ffff_ffff;
    let a = Ipv6Addr::new(0xfd00 | ((g >> 32) as u16 & 0xff), (g >> 16) as u16, g as u16, 0, 0, 0, 0, 0);
    Ipv6Net::new(a, 48).unwrap()
}

#[derive(Debug, Clone)]
pub struct WanIf {
    pub phys: String,
    /// `vlan848` when the WAN is tagged.
    pub vlan_if: Option<String>,
    /// Where traffic leaves: `pppoe0`, the vlan, or the port itself.
    pub egress: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Endpoint {
    Any,
    /// The router's own addresses (pf `self`).
    Router,
    /// Every internal network (`internal`: pf's `<internal>`).
    Internal,
    /// Everything outside the internal networks (`internet`: `! <internal>`).
    Internet,
    Net(usize),
    Addr(IpNet),
    Table(String),
}

/// `[[rules]] network` for a rule on every internal network.
pub const RULE_ALL: &str = "all";
/// `[[rules]] network` for a rule on traffic coming in from the internet.
pub const RULE_WAN: &str = "wan";

#[derive(Debug, Clone)]
pub struct Router {
    pub cfg: Config,
    /// role -> interface name
    pub phys: BTreeMap<String, String>,
    pub nets: Vec<Net>,
    pub wan: Option<WanIf>,
}

pub const WG_IF: &str = "wg0";
pub const PPPOE_IF: &str = "pppoe0";

impl Router {
    /// Resolve roles against `macs` (MAC -> name, from ifconfig). When the map
    /// is empty (compiling off the router) the roles' `name` fields are used.
    pub fn resolve(cfg: Config, macs: &BTreeMap<String, String>) -> Result<Router, Diagnostics> {
        let mut d = Diagnostics::default();
        let mut phys = BTreeMap::new();
        for (role, i) in &cfg.interfaces {
            let Some(mac) = normalize_mac(&i.mac) else {
                d.error("E-IF", format!("interface {role}: bad MAC {:?}", i.mac));
                continue;
            };
            match (macs.get(&mac), &i.name) {
                (Some(found), Some(want)) if found != want => d.error(
                    "E-IF",
                    format!("interface {role}: MAC {mac} is {found} on this machine, config says {want}"),
                ),
                (Some(found), _) => {
                    phys.insert(role.clone(), found.clone());
                }
                (None, Some(want)) if macs.is_empty() => {
                    phys.insert(role.clone(), want.clone());
                }
                (None, _) => d.error("E-IF", format!("interface {role}: no port with MAC {mac} on this machine")),
            }
        }
        if d.has_errors() {
            return Err(d);
        }

        let mut nets = vec![];
        // one veb per set of ports; each network on it gets its own vport,
        // except the tiers untagged on the house ports, which share one
        let mut bridges: BTreeMap<Vec<String>, String> = BTreeMap::new();
        let mut vports = 0;
        let mut lan_untagged: Option<String> = None;
        let v6_on = cfg.ipv6.mode == Ipv6Mode::Pd;
        let ula = ula_prefix(&cfg);
        for (idx, n) in cfg.networks.iter().enumerate() {
            let (ifname, parent, bridge, members) = match (&n.interface, n.bridge.as_slice()) {
                (Some(role), []) => {
                    let Some(p) = phys.get(role) else {
                        d.error("E-NET", format!("network {}: unknown interface role {role:?}", n.name));
                        continue;
                    };
                    match n.vlan {
                        Some(v) => (format!("vlan{v}"), Some(p.clone()), None, vec![]),
                        None => (p.clone(), None, None, vec![]),
                    }
                }
                (None, roles) if roles.len() >= 2 => {
                    let mut members = vec![];
                    for role in roles {
                        match phys.get(role) {
                            Some(p) => members.push(p.clone()),
                            None => d.error("E-NET", format!("network {}: unknown interface role {role:?}", n.name)),
                        }
                    }
                    let mut key = roles.to_vec();
                    key.sort();
                    let next = bridges.len();
                    let veb = bridges.entry(key).or_insert_with(|| format!("veb{next}")).clone();
                    let v = vports;
                    vports += 1;
                    (format!("vport{v}"), None, Some(veb), members)
                }
                (None, []) if cfg.lan.is_some() => {
                    let lan = cfg.lan.as_ref().unwrap();
                    let mut members = vec![];
                    for role in &lan.ports {
                        match phys.get(role) {
                            Some(p) => members.push(p.clone()),
                            None => d.error("E-LAN", format!("lan: unknown interface role {role:?}")),
                        }
                    }
                    let mut key = lan.ports.clone();
                    key.sort();
                    let next = bridges.len();
                    let veb = bridges.entry(key).or_insert_with(|| format!("veb{next}")).clone();
                    let vport = match (n.vlan, &lan_untagged) {
                        (None, Some(v)) => v.clone(),
                        _ => {
                            let v = format!("vport{vports}");
                            vports += 1;
                            if n.vlan.is_none() {
                                lan_untagged = Some(v.clone());
                            }
                            v
                        }
                    };
                    (vport, None, Some(veb), members)
                }
                _ => {
                    d.error(
                        "E-NET",
                        format!(
                            "tier {}: set interface = \"role\", bridge = [roles], or the house ports in [lan]",
                            n.name
                        ),
                    );
                    continue;
                }
            };
            let v6 = (v6_on && n.ipv6.unwrap_or(true)).then(|| {
                let slot = n.ipv6_slot.unwrap_or(idx as u8);
                let mut seg = ula.addr().segments();
                seg[3] = slot as u16;
                seg[7] = 1;
                V6 { slot, ula: Ipv6Net::new(Ipv6Addr::from(seg), 64).unwrap() }
            });
            nets.push(Net {
                name: n.name.clone(),
                ifname,
                parent,
                bridge,
                members,
                src: None,
                v6,
                vlan: n.vlan,
                addr: n.address.addr(),
                prefix: n.address.trunc(),
                kind: n.kind,
                class: n.class.unwrap_or(match n.kind {
                    Kind::Servers => Class::Bulk,
                    _ => Class::Default,
                }),
            });
        }

        // tiers sharing an interface: told apart by source address; IPv6
        // (one /64 per interface) stays with the first of them
        for i in 0..nets.len() {
            let shared = nets.iter().filter(|o| o.ifname == nets[i].ifname).count() > 1;
            if shared {
                nets[i].src = Some(nets[i].prefix);
                if nets[..i].iter().any(|o| o.ifname == nets[i].ifname) {
                    nets[i].v6 = None;
                }
            }
        }

        let wan = match &cfg.wan {
            None => None,
            Some(w) => match phys.get(&w.interface) {
                None => {
                    d.error("E-WAN", format!("wan: unknown interface role {:?}", w.interface));
                    None
                }
                Some(p) => {
                    let vlan_if = w.vlan.map(|v| format!("vlan{v}"));
                    let carrier = vlan_if.clone().unwrap_or_else(|| p.clone());
                    let egress = match w.mode() {
                        Some(WanMode::Pppoe { .. }) => PPPOE_IF.to_string(),
                        _ => carrier,
                    };
                    Some(WanIf { phys: p.clone(), vlan_if, egress })
                }
            },
        };

        if d.has_errors() {
            return Err(d);
        }
        Ok(Router { cfg, phys, nets, wan })
    }

    pub fn net(&self, name: &str) -> Option<(usize, &Net)> {
        self.nets.iter().enumerate().find(|(_, n)| n.name == name)
    }

    /// The internal networks a rule applies on: its network, or all of them
    /// for `all` (none for `wan`, whose rules sit with the WAN's inbound policy).
    pub fn rule_nets(&self, network: &str) -> Vec<&Net> {
        match network {
            RULE_ALL => self.nets.iter().collect(),
            n => self.net(n).map(|(_, n)| vec![n]).unwrap_or_default(),
        }
    }

    /// Can traffic from `e` come from network `n`?
    pub fn endpoint_in_net(&self, e: &Endpoint, n: &Net) -> bool {
        let hit = |a: &IpNet| match a {
            IpNet::V4(a) => n.prefix.contains(a) || a.contains(&n.prefix),
            IpNet::V6(_) => false,
        };
        match e {
            Endpoint::Any | Endpoint::Internal => true,
            Endpoint::Internet | Endpoint::Router => false,
            Endpoint::Net(i) => self.nets[*i].name == n.name,
            Endpoint::Addr(a) => hit(a),
            Endpoint::Table(t) => {
                self.cfg.tables.iter().find(|x| &x.name == t).is_some_and(|x| x.entries.iter().any(hit))
            }
        }
    }

    /// Guests: the old `guest` kind, or a tier the rules keep from inside
    /// (a block from it to `internal`).
    pub fn is_guest(&self, tier: &str) -> bool {
        self.net(tier).is_some_and(|(_, n)| n.kind == Kind::Guest)
            || self.cfg.rules.iter().any(|r| {
                r.action != Action::Pass && r.to == "internal" && (r.from == format!("net:{tier}") || r.from == tier)
            })
    }

    /// A host's tier: as named, else the one whose range holds its address.
    pub fn host_net(&self, h: &Host) -> Option<&Net> {
        match &h.network {
            Some(n) => self.net(n).map(|x| x.1),
            None => self.net_of(h.ip),
        }
    }

    pub fn mgmt_addrs(&self) -> Vec<Ipv4Addr> {
        let mut v: Vec<Ipv4Addr> =
            self.nets.iter().filter(|n| matches!(n.kind, Kind::Mgmt | Kind::Open)).map(|n| n.addr).collect();
        if let Some(wg) = &self.cfg.wireguard
            && wg.peers.iter().any(|p| p.policy == Kind::Mgmt)
        {
            v.push(wg.address.addr());
        }
        v
    }

    /// The network an address belongs to.
    pub fn net_of(&self, ip: Ipv4Addr) -> Option<&Net> {
        self.nets.iter().find(|n| n.prefix.contains(&ip))
    }

    /// Resolve an endpoint string: `any`, `self`, `internal`, `internet`, `net:<n>`, `host:<n>`,
    /// `table:<n>`, an address, a prefix, or a bare name that is unique across
    /// networks, hosts and tables.
    pub fn endpoint(&self, s: &str) -> Result<Endpoint, String> {
        let s = s.trim();
        match s {
            "any" => return Ok(Endpoint::Any),
            "self" => return Ok(Endpoint::Router),
            "internal" => return Ok(Endpoint::Internal),
            "internet" => return Ok(Endpoint::Internet),
            _ => {}
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Endpoint::Addr(IpNet::from(ip)));
        }
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(Endpoint::Addr(net.trunc()));
        }
        let (ns, name) = match s.split_once(':') {
            Some((ns @ ("net" | "host" | "table"), name)) => (Some(ns), name),
            _ => (None, s),
        };
        let mut found = vec![];
        if (ns.is_none() || ns == Some("net"))
            && let Some((i, _)) = self.net(name)
        {
            found.push(Endpoint::Net(i));
        }
        if (ns.is_none() || ns == Some("host"))
            && let Some(h) = self.cfg.hosts.iter().find(|h| h.name == name)
        {
            found.push(Endpoint::Addr(IpNet::from(IpAddr::V4(h.ip))));
        }
        if (ns.is_none() || ns == Some("table")) && self.cfg.tables.iter().any(|t| t.name == name) {
            found.push(Endpoint::Table(name.to_string()));
        }
        match found.len() {
            1 => Ok(found.pop().unwrap()),
            0 => Err(format!("{s:?} is not any/self, an address, or a known network, host or table")),
            _ => Err(format!("{s:?} is ambiguous; prefix it with net:, host: or table:")),
        }
    }

    /// Does `e` cover the router itself (any of its addresses)?
    pub fn covers_router(&self, e: &Endpoint) -> bool {
        match e {
            Endpoint::Any | Endpoint::Router | Endpoint::Internal | Endpoint::Net(_) => true,
            Endpoint::Internet => false,
            Endpoint::Addr(a) => self.nets.iter().any(|n| a.contains(&IpAddr::V4(n.addr))),
            Endpoint::Table(t) => {
                self.cfg.tables.iter().find(|x| &x.name == t).is_some_and(|x| {
                    x.entries.iter().any(|a| self.nets.iter().any(|n| a.contains(&IpAddr::V4(n.addr))))
                })
            }
        }
    }

    /// Can `e` contain an address of an internal network?
    pub fn overlaps_internal(&self, e: &Endpoint) -> bool {
        let hit = |a: &IpNet| match a {
            IpNet::V4(a) => self.nets.iter().any(|n| n.prefix.contains(a) || a.contains(&n.prefix)),
            IpNet::V6(_) => false,
        };
        match e {
            Endpoint::Any | Endpoint::Router | Endpoint::Internal | Endpoint::Net(_) => true,
            Endpoint::Internet => false,
            Endpoint::Addr(a) => hit(a),
            Endpoint::Table(t) => {
                self.cfg.tables.iter().find(|x| &x.name == t).is_some_and(|x| x.entries.iter().any(hit))
            }
        }
    }

    /// Is `e` entirely inside the internal networks (or the router)?
    pub fn is_internal(&self, e: &Endpoint) -> bool {
        let inside = |a: &IpNet| match a {
            IpNet::V4(a) => self.nets.iter().any(|n| n.prefix.contains(a)),
            IpNet::V6(_) => false,
        };
        match e {
            Endpoint::Any | Endpoint::Internet => false,
            Endpoint::Router | Endpoint::Internal | Endpoint::Net(_) => true,
            Endpoint::Addr(a) => inside(a),
            Endpoint::Table(t) => {
                self.cfg.tables.iter().find(|x| &x.name == t).is_some_and(|x| x.entries.iter().all(inside))
            }
        }
    }
}
