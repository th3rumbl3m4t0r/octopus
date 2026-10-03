//! Arbor-style FCAP expressions -> pcap filter syntax (for BPF).
//!
//!   expr    := term { "or" term }
//!   term    := factor { "and" factor }
//!   factor  := "not" factor | "(" expr ")" | prim
//!   prim    := [src|dst] (host ADDR | net PREFIX | ADDR | PREFIX)
//!            | [src|dst] port N[-M]
//!            | proto NAME|NUMBER
//!            | tflags FLAGS[/MASK]          FLAGS: F S R P A U E C (e.g. S/SA)
//!            | len|ttl|icmp_type OP N        OP: = != < > <= >=
//!            | frag
//!
//! FCAP's flow-level terms (bps, pps, bytes, packets) describe flows, not
//! packets: they are refused, a BPF program can't see them.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    LParen,
    RParen,
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = vec![];
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<Tok>| {
        if !cur.is_empty() {
            out.push(Tok::Word(std::mem::take(cur)));
        }
    };
    for c in s.chars() {
        match c {
            '(' | ')' => {
                flush(&mut cur, &mut out);
                out.push(if c == '(' { Tok::LParen } else { Tok::RParen });
            }
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            c if c.is_ascii_alphanumeric() || ".:/-_<>=!|".contains(c) => cur.push(c),
            c => return Err(format!("unexpected character {c:?}")),
        }
        if out.len() > 512 {
            return Err("expression too long".into());
        }
    }
    flush(&mut cur, &mut out);
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
    depth: usize,
}

impl P {
    fn peek(&self) -> Option<&str> {
        match self.t.get(self.i) {
            Some(Tok::Word(w)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn word(&mut self, what: &str) -> Result<String, String> {
        match self.t.get(self.i) {
            Some(Tok::Word(w)) => {
                self.i += 1;
                Ok(w.clone())
            }
            _ => Err(format!("expected {what}")),
        }
    }

    fn expr(&mut self) -> Result<String, String> {
        let mut parts = vec![self.term()?];
        while self.peek().is_some_and(|w| w.eq_ignore_ascii_case("or")) {
            self.i += 1;
            parts.push(self.term()?);
        }
        Ok(if parts.len() == 1 { parts.pop().unwrap() } else { format!("({})", parts.join(" or ")) })
    }

    fn term(&mut self) -> Result<String, String> {
        let mut parts = vec![self.factor()?];
        while self.peek().is_some_and(|w| w.eq_ignore_ascii_case("and")) {
            self.i += 1;
            parts.push(self.factor()?);
        }
        Ok(if parts.len() == 1 { parts.pop().unwrap() } else { format!("({})", parts.join(" and ")) })
    }

    fn factor(&mut self) -> Result<String, String> {
        self.depth += 1;
        if self.depth > 64 {
            return Err("nested too deeply".into());
        }
        let r = match self.t.get(self.i) {
            Some(Tok::LParen) => {
                self.i += 1;
                let e = self.expr()?;
                if self.t.get(self.i) != Some(&Tok::RParen) {
                    return Err("missing )".into());
                }
                self.i += 1;
                Ok(e)
            }
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case("not") => {
                self.i += 1;
                Ok(format!("not {}", self.factor()?))
            }
            Some(Tok::Word(_)) => self.prim(),
            _ => Err("expected a term".into()),
        };
        self.depth -= 1;
        r
    }

    fn prim(&mut self) -> Result<String, String> {
        let w = self.word("a term")?.to_ascii_lowercase();
        let (dir, w) = match w.as_str() {
            "src" | "dst" => (Some(w.clone()), self.word("host, net, port or an address")?.to_ascii_lowercase()),
            _ => (None, w),
        };
        let d = dir.as_ref().map(|d| format!("{d} ")).unwrap_or_default();
        match w.as_str() {
            "host" => Ok(format!("{d}host {}", addr(&self.word("an address")?)?)),
            "net" => Ok(format!("{d}net {}", prefix(&self.word("a prefix")?)?)),
            "port" => {
                let p = self.word("a port")?;
                match p.split_once('-') {
                    Some((a, b)) => Ok(format!("{d}portrange {}-{}", port(a)?, port(b)?)),
                    None => Ok(format!("{d}port {}", port(&p)?)),
                }
            }
            "proto" if dir.is_none() => {
                let p = self.word("a protocol")?.to_ascii_lowercase();
                // pcap's own keywords cover IPv4 and IPv6; the rest by number
                let n = match p.as_str() {
                    "tcp" | "udp" | "icmp" | "icmp6" => return Ok(p),
                    "igmp" => 2,
                    "gre" => 47,
                    "esp" => 50,
                    "ah" => 51,
                    n => n.parse::<u8>().map_err(|_| format!("unknown protocol {p:?}"))?,
                };
                Ok(format!("(ip proto {n} or ip6 proto {n})"))
            }
            "tflags" if dir.is_none() => {
                let f = self.word("TCP flags")?.to_ascii_uppercase();
                let (set, mask) = match f.split_once('/') {
                    Some((s, m)) => (flags(s)?, flags(m)?),
                    None => (flags(&f)?, flags(&f)?),
                };
                if set & !mask != 0 {
                    return Err(format!("tflags {f}: flags outside the mask"));
                }
                Ok(format!("(tcp and (tcp[13] & {mask:#04x}) = {set:#04x})"))
            }
            "len" | "ttl" | "icmp_type" if dir.is_none() => {
                let op = self.word("an operator")?;
                if !["=", "!=", "<", ">", "<=", ">="].contains(&op.as_str()) {
                    return Err(format!("{w}: unknown operator {op:?}"));
                }
                let n: u32 = self.word("a number")?.parse().map_err(|_| format!("{w}: not a number"))?;
                let lhs = match w.as_str() {
                    "len" => "len",
                    "ttl" => "ip[8]",
                    _ => "icmp[0]",
                };
                let guard = match w.as_str() {
                    "ttl" => "ip and ",
                    "icmp_type" => "icmp and ",
                    _ => "",
                };
                Ok(format!("({guard}{lhs} {op} {n})"))
            }
            "frag" if dir.is_none() => Ok("(ip and (ip[6:2] & 0x3fff) != 0)".into()),
            "bps" | "pps" | "bytes" | "packets" => {
                Err(format!("{w} is a flow-level FCAP term; a packet filter can't see it"))
            }
            other => {
                // a bare address or prefix
                if let Ok(a) = addr(other) {
                    Ok(format!("{d}host {a}"))
                } else if let Ok(p) = prefix(other) {
                    Ok(format!("{d}net {p}"))
                } else {
                    Err(format!("unknown term {other:?}"))
                }
            }
        }
    }
}

fn addr(s: &str) -> Result<String, String> {
    s.parse::<IpAddr>().map(|a| a.to_string()).map_err(|_| format!("{s:?} is not an address"))
}

fn prefix(s: &str) -> Result<String, String> {
    s.parse::<ipnet::IpNet>().map(|n| n.trunc().to_string()).map_err(|_| format!("{s:?} is not a prefix"))
}

fn port(s: &str) -> Result<u16, String> {
    s.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("{s:?} is not a port"))
}

fn flags(s: &str) -> Result<u8, String> {
    let mut v = 0u8;
    for c in s.chars() {
        v |= match c {
            'F' => 0x01,
            'S' => 0x02,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            'E' => 0x40,
            'C' => 0x80,
            _ => return Err(format!("unknown TCP flag {c:?} (use F S R P A U E C)")),
        };
    }
    Ok(v)
}

/// Translate an FCAP expression into pcap filter syntax.
pub fn to_pcap(fcap: &str) -> Result<String, String> {
    let t = lex(fcap)?;
    if t.is_empty() {
        return Err("empty expression".into());
    }
    let mut p = P { t, i: 0, depth: 0 };
    let e = p.expr()?;
    if p.i != p.t.len() {
        return Err(format!("unexpected {:?}", p.t[p.i]));
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::to_pcap;

    #[test]
    fn translations() {
        assert_eq!(to_pcap("src 10.0.0.0/8 and dst port 80").unwrap(), "(src net 10.0.0.0/8 and dst port 80)");
        assert_eq!(to_pcap("proto tcp and tflags S/SA").unwrap(), "(tcp and (tcp and (tcp[13] & 0x12) = 0x02))");
        assert_eq!(to_pcap("proto 47").unwrap(), "(ip proto 47 or ip6 proto 47)");
        assert_eq!(to_pcap("not (dst port 53 or dst port 853)").unwrap(), "not (dst port 53 or dst port 853)");
        assert_eq!(to_pcap("dst port 1000-2000").unwrap(), "dst portrange 1000-2000");
        assert_eq!(to_pcap("192.168.1.5").unwrap(), "host 192.168.1.5");
        assert_eq!(to_pcap("len > 1000 and ttl < 5").unwrap(), "((len > 1000) and (ip and ip[8] < 5))");
        assert!(to_pcap("bps > 1000").unwrap_err().contains("flow-level"));
        assert!(to_pcap("tflags X").is_err());
        assert!(to_pcap("dst port 0").is_err());
        assert!(to_pcap("(dst port 80").is_err());
        assert!(to_pcap("host 10.0.0.1; rm -rf /").is_err());
        assert!(to_pcap("").is_err());
    }
}
