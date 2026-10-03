//! IPFIX (RFC 7011), as sent by pflow(4) with `pflowproto 10`. Template
//! driven: templates are learned per (observation domain, template id) and
//! data records are read field by field, so the exporter's exact layout
//! doesn't matter. Everything is bounds-checked; malformed input yields
//! fewer records, never a panic (fuzzed: fuzz/fuzz_targets/ipfix.rs).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Flow {
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
    /// milliseconds since the epoch
    pub start_ms: u64,
    pub end_ms: u64,
    /// after NAT (pflow exports the translated address for NATed states)
    pub nat_src: Option<IpAddr>,
    pub nat_sport: u16,
}

#[derive(Debug, Clone, Copy)]
struct Field {
    id: u16,
    len: u16,
}

#[derive(Default)]
pub struct Parser {
    templates: HashMap<(u32, u16), Vec<Field>>,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// An unsigned integer of 1..8 bytes.
fn uint(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |acc, x| (acc << 8) | *x as u64)
}

impl Parser {
    pub fn new() -> Parser {
        Parser::default()
    }

    /// Parse one IPFIX message; returns the data records it could decode.
    pub fn message(&mut self, msg: &[u8]) -> Vec<Flow> {
        let mut out = vec![];
        // header: version(2) length(2) export time(4) sequence(4) domain(4)
        if be16(msg, 0) != Some(10) {
            return out;
        }
        let Some(len) = be16(msg, 2) else { return out };
        let msg = &msg[..(len as usize).min(msg.len())];
        let Some(domain) = be32(msg, 12) else { return out };
        let mut at = 16;
        while at + 4 <= msg.len() {
            let (Some(set_id), Some(set_len)) = (be16(msg, at), be16(msg, at + 2)) else { break };
            let set_len = set_len as usize;
            if set_len < 4 || at + set_len > msg.len() {
                break;
            }
            let body = &msg[at + 4..at + set_len];
            match set_id {
                2 => self.templates_set(domain, body),
                3 => {} // options templates: not needed
                id if id >= 256 => {
                    if let Some(t) = self.templates.get(&(domain, id)) {
                        out.extend(records(t, body));
                    }
                }
                _ => {}
            }
            at += set_len;
        }
        out
    }

    fn templates_set(&mut self, domain: u32, body: &[u8]) {
        let mut at = 0;
        while at + 4 <= body.len() {
            let (Some(tid), Some(count)) = (be16(body, at), be16(body, at + 2)) else { return };
            at += 4;
            let mut fields = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let (Some(id), Some(len)) = (be16(body, at), be16(body, at + 2)) else { return };
                at += 4;
                // enterprise-specific: a 4-byte enterprise number follows
                if id & 0x8000 != 0 {
                    at += 4;
                }
                fields.push(Field { id: id & 0x7fff, len });
            }
            // variable-length fields (0xffff) aren't used by pflow; skip such templates
            if tid >= 256 && !fields.is_empty() && fields.iter().all(|f| f.len != 0xffff) {
                self.templates.insert((domain, tid), fields);
            }
        }
    }
}

fn records(t: &[Field], body: &[u8]) -> Vec<Flow> {
    let rec_len: usize = t.iter().map(|f| f.len as usize).sum();
    let mut out = vec![];
    if rec_len == 0 {
        return out;
    }
    let mut at = 0;
    while at + rec_len <= body.len() {
        let mut f = Flow::default();
        let mut p = at;
        for fld in t {
            let v = &body[p..p + fld.len as usize];
            p += fld.len as usize;
            match (fld.id, v.len()) {
                (8, 4) => f.src = Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]))),
                (12, 4) => f.dst = Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]))),
                (27, 16) => f.src = Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v).unwrap()))),
                (28, 16) => f.dst = Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v).unwrap()))),
                (225, 4) => f.nat_src = Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]))),
                (281, 16) => f.nat_src = Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v).unwrap()))),
                (227, _) => f.nat_sport = uint(v) as u16,
                (7, _) => f.sport = uint(v) as u16,
                (11, _) => f.dport = uint(v) as u16,
                (4, _) => f.proto = uint(v) as u8,
                (2, _) => f.packets = uint(v),
                (1, _) => f.bytes = uint(v),
                (152, _) => f.start_ms = uint(v),
                (153, _) => f.end_ms = uint(v),
                (150, _) => f.start_ms = uint(v) * 1000,
                (151, _) => f.end_ms = uint(v) * 1000,
                _ => {}
            }
        }
        out.push(f);
        at += rec_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message with a template (src, dst, ports, proto, packets, bytes)
    /// and one data record.
    fn sample() -> Vec<u8> {
        let mut t = vec![];
        let fields: [(u16, u16); 7] = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 8), (1, 8)];
        t.extend(256u16.to_be_bytes());
        t.extend((fields.len() as u16).to_be_bytes());
        for (id, len) in fields {
            t.extend(id.to_be_bytes());
            t.extend(len.to_be_bytes());
        }
        let mut d = vec![10, 0, 0, 5, 1, 1, 1, 1];
        d.extend(40000u16.to_be_bytes());
        d.extend(443u16.to_be_bytes());
        d.push(6);
        d.extend(12u64.to_be_bytes());
        d.extend(3400u64.to_be_bytes());
        let mut m = vec![];
        let sets = [(2u16, t), (256u16, d)];
        let total: usize = 16 + sets.iter().map(|(_, b)| 4 + b.len()).sum::<usize>();
        m.extend(10u16.to_be_bytes());
        m.extend((total as u16).to_be_bytes());
        m.extend([0u8; 8]);
        m.extend(7u32.to_be_bytes());
        for (id, b) in sets {
            m.extend(id.to_be_bytes());
            m.extend(((4 + b.len()) as u16).to_be_bytes());
            m.extend(b);
        }
        m
    }

    #[test]
    fn parses_and_survives_garbage() {
        let mut p = Parser::new();
        let f = p.message(&sample());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].src, Some("10.0.0.5".parse().unwrap()));
        assert_eq!((f[0].sport, f[0].dport, f[0].proto, f[0].packets, f[0].bytes), (40000, 443, 6, 12, 3400));
        // truncations and junk
        let s = sample();
        for cut in 0..s.len() {
            let _ = Parser::new().message(&s[..cut]);
        }
        let _ = p.message(&[0u8; 3]);
        let _ = p.message(&[0, 10, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 2]);
    }
}
