//! Request validation for octopus-pfhelper, separate from the daemon so it
//! can be tested and fuzzed (design R8).

use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;

pub const DEFAULT_TABLES: [&str; 4] = ["cls_realtime", "cls_streaming", "cls_bulk", "lab_block"];
pub const LAB_BLOCK: &str = "lab_block";
pub const MAX_ADDRS: usize = 8192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub table: String,
    pub op: String,
    pub addresses: Vec<String>,
}

/// What one client may touch: its tables, and for lab_block never the
/// protected prefixes (the router, management, upstreams).
pub struct Grant<'a> {
    pub tables: &'a [String],
    pub protected: &'a [IpNet],
}

/// The tables each client uid may write: classification for octopus-dns,
/// lab blocks for the analyzer, all of them for root.
pub fn tables_for(user: &str) -> &'static [&'static str] {
    match user {
        "_octodns" => &DEFAULT_TABLES[..3],
        "_octoflow" => &DEFAULT_TABLES[3..],
        "root" => &DEFAULT_TABLES,
        _ => &[],
    }
}

/// Addresses lab_block never takes, whatever the configuration says: they
/// aren't anyone's, or blocking them cuts the router off from itself.
fn never_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_unspecified() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (a.segments()[0] & 0xffc0) == 0xfe80
                || a.to_ipv4_mapped().is_some()
        }
    }
}

/// Validate a request into (table, op, addresses as pfctl text).
pub fn validate(req: &Request, grant: &Grant) -> Result<(String, &'static str, Vec<String>), String> {
    if !grant.tables.iter().any(|t| t == &req.table) {
        return Err(format!("table {:?} is not allowed", req.table));
    }
    let op = match req.op.as_str() {
        "add" => "add",
        "delete" => "delete",
        "replace" => "replace",
        _ => return Err(format!("op {:?} is not add, delete or replace", req.op)),
    };
    if req.addresses.len() > MAX_ADDRS {
        return Err(format!("more than {MAX_ADDRS} addresses"));
    }
    let lab = req.table == LAB_BLOCK;
    let mut out = Vec::with_capacity(req.addresses.len());
    for a in &req.addresses {
        // reparse and print canonically: nothing but an address reaches pfctl
        let net = match a.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip),
            Err(_) => a.parse::<IpNet>().map_err(|_| format!("{a:?} is not an address or prefix"))?,
        };
        if lab {
            // one host at a time, never one the router depends on (a delete
            // of a protected address is harmless and may clean up an old entry)
            if net.prefix_len() != net.max_prefix_len() {
                return Err(format!("{a:?}: lab_block takes single addresses"));
            }
            if op != "delete" && (never_blocked(net.addr()) || grant.protected.iter().any(|p| p.contains(&net.addr())))
            {
                return Err(format!("{a:?}: protected (the router, management or an upstream)"));
            }
        } else {
            // classification: hosts and small networks, never half the internet
            let min = if net.addr().is_ipv4() { 16 } else { 32 };
            if net.prefix_len() < min {
                return Err(format!("{a:?}: shorter than /{min}"));
            }
        }
        out.push(if net.prefix_len() == net.max_prefix_len() {
            net.addr().to_string()
        } else {
            net.trunc().to_string()
        });
    }
    if out.is_empty() && op != "replace" {
        return Err("no addresses".into());
    }
    Ok((req.table.clone(), op, out))
}

/// Parse and validate one request line.
pub fn parse(line: &str, grant: &Grant) -> Result<(String, &'static str, Vec<String>), String> {
    let req: Request = serde_json::from_str(line).map_err(|e| format!("bad request: {e}"))?;
    validate(&req, grant)
}

/// /etc/octopus/pfhelper.conf, rendered by octopus.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Prefixes lab_block never takes.
    #[serde(default)]
    pub protected: Vec<IpNet>,
    /// lab_block entries older than this many seconds are dropped by pf
    /// itself (the analyzer's own expiry is in memory only).
    #[serde(default = "default_expire")]
    pub lab_block_expire: u32,
}

fn default_expire() -> u32 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(table: &str, op: &str, a: &[&str]) -> Request {
        Request { table: table.into(), op: op.into(), addresses: a.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn validation() {
        let t: Vec<String> = DEFAULT_TABLES.iter().map(|s| s.to_string()).collect();
        let protected: Vec<IpNet> = vec!["10.10.0.0/24".parse().unwrap(), "1.1.1.2/32".parse().unwrap()];
        let g = Grant { tables: &t, protected: &protected };
        assert!(validate(&req("cls_bulk", "add", &["192.0.2.1", "2001:db8::/32"]), &g).is_ok());
        assert!(validate(&req("internal", "add", &["192.0.2.1"]), &g).is_err());
        assert!(validate(&req("cls_bulk", "flush", &["192.0.2.1"]), &g).is_err());
        assert!(validate(&req("cls_bulk", "add", &["192.0.2.1 -F all"]), &g).is_err());
        assert!(validate(&req("cls_bulk", "add", &["0.0.0.0/0"]), &g).is_err());
        assert!(validate(&req("cls_bulk", "add", &["-f/etc/pf.conf"]), &g).is_err());
        let (_, _, a) = validate(&req("cls_bulk", "add", &["10.1.2.3/16"]), &g).unwrap();
        assert_eq!(a, ["10.1.0.0/16"]);
        assert!(validate(&req("cls_bulk", "replace", &[]), &g).is_ok());
        // no halves of the internet anywhere
        assert!(validate(&req("cls_bulk", "add", &["0.0.0.0/1"]), &g).is_err());
        assert!(validate(&req("lab_block", "add", &["0.0.0.0/1"]), &g).is_err());
        // lab_block: hosts, never the router's, management or upstreams
        assert!(validate(&req("lab_block", "add", &["203.0.113.9"]), &g).is_ok());
        for bad in ["10.10.0.5", "1.1.1.2", "127.0.0.1", "fe80::1", "224.0.0.1", "255.255.255.255", "::ffff:1.2.3.4"] {
            assert!(validate(&req("lab_block", "add", &[bad]), &g).is_err(), "{bad}");
        }
        assert!(validate(&req("lab_block", "delete", &["10.10.0.5"]), &g).is_ok());
        assert!(validate(&req("lab_block", "replace", &[]), &g).is_ok());
    }

    #[test]
    fn each_client_its_tables() {
        assert_eq!(tables_for("_octodns"), ["cls_realtime", "cls_streaming", "cls_bulk"]);
        assert_eq!(tables_for("_octoflow"), ["lab_block"]);
        assert!(tables_for("_octoweb").is_empty());
    }
}
