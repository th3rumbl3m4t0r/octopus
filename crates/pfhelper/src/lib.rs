//! Request validation for octopus-pfhelper, separate from the daemon so it
//! can be tested and fuzzed (design R8).

use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;

pub const DEFAULT_TABLES: [&str; 4] = ["cls_realtime", "cls_streaming", "cls_bulk", "lab_block"];
pub const MAX_ADDRS: usize = 8192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub table: String,
    pub op: String,
    pub addresses: Vec<String>,
}

/// Validate a request into (table, op, addresses as pfctl text).
pub fn validate(req: &Request, tables: &[String]) -> Result<(String, &'static str, Vec<String>), String> {
    if !tables.iter().any(|t| t == &req.table) {
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
    let mut out = Vec::with_capacity(req.addresses.len());
    for a in &req.addresses {
        // reparse and print canonically: nothing but an address reaches pfctl
        let net = match a.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip),
            Err(_) => a.parse::<IpNet>().map_err(|_| format!("{a:?} is not an address or prefix"))?,
        };
        if net.prefix_len() == 0 {
            return Err(format!("{a:?}: refusing a default route prefix"));
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
pub fn parse(line: &str, tables: &[String]) -> Result<(String, &'static str, Vec<String>), String> {
    let req: Request = serde_json::from_str(line).map_err(|e| format!("bad request: {e}"))?;
    validate(&req, tables)
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
        assert!(validate(&req("cls_bulk", "add", &["192.0.2.1", "2001:db8::/32"]), &t).is_ok());
        assert!(validate(&req("internal", "add", &["192.0.2.1"]), &t).is_err());
        assert!(validate(&req("cls_bulk", "flush", &["192.0.2.1"]), &t).is_err());
        assert!(validate(&req("cls_bulk", "add", &["192.0.2.1 -F all"]), &t).is_err());
        assert!(validate(&req("cls_bulk", "add", &["0.0.0.0/0"]), &t).is_err());
        assert!(validate(&req("cls_bulk", "add", &["-f/etc/pf.conf"]), &t).is_err());
        let (_, _, a) = validate(&req("cls_bulk", "add", &["10.1.2.3/8"]), &t).unwrap();
        assert_eq!(a, ["10.0.0.0/8"]);
        assert!(validate(&req("cls_bulk", "replace", &[]), &t).is_ok());
    }
}
