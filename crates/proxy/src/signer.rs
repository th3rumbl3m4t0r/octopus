//! The signer: a separate process that holds the interception root's key
//! and mints short-lived leaves, for allowlisted names only. The proxy,
//! which parses everything servers and origins send, never sees the key
//! (relayd's privilege separation, kept).
//!
//! Protocol on a socketpair, one JSON line each way:
//!   {"host": "deb.debian.org"}  ->  {"chain": "...PEM...", "key": "...PEM..."} | {"error": "..."}

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use octopus_pki::Ca;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::allow;

const LEAF_DAYS: i64 = 7;
const REFRESH: Duration = Duration::from_secs(24 * 3600);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Req {
    host: String,
}

/// The signer's loop (blocking; the process is pledged "stdio").
pub fn run(sock: StdUnixStream, ca: Ca, allowed: Vec<String>) -> ! {
    let mut w = sock.try_clone().expect("socket");
    let r = BufReader::new(sock);
    for line in r.lines() {
        let Ok(line) = line else { break };
        let reply = match serde_json::from_str::<Req>(&line) {
            Err(e) => serde_json::json!({"error": format!("bad request: {e}")}),
            Ok(req) => {
                let host = allow::normalize(&req.host);
                if !allow::matches(&allowed, &host) {
                    serde_json::json!({"error": format!("{host} is not on any allowlist")})
                } else {
                    match octopus_pki::issue(&ca, std::slice::from_ref(&host), &[], LEAF_DAYS) {
                        Ok(leaf) => serde_json::json!({"chain": leaf.chain_pem, "key": leaf.key_pem}),
                        Err(e) => serde_json::json!({"error": e}),
                    }
                }
            }
        };
        if writeln!(w, "{reply}").is_err() {
            break;
        }
    }
    std::process::exit(0);
}

pub struct Signer {
    conn: tokio::sync::Mutex<(TokioBufReader<OwnedReadHalf>, OwnedWriteHalf)>,
    cache: std::sync::Mutex<HashMap<String, (Arc<CertifiedKey>, Instant)>>,
}

impl Signer {
    pub fn new(sock: StdUnixStream) -> std::io::Result<Signer> {
        sock.set_nonblocking(true)?;
        let (r, w) = UnixStream::from_std(sock)?.into_split();
        Ok(Signer { conn: tokio::sync::Mutex::new((TokioBufReader::new(r), w)), cache: Default::default() })
    }

    /// A leaf for `host`, minted once a day at most.
    pub async fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        if let Some((k, t)) = self.cache.lock().unwrap().get(host)
            && t.elapsed() < REFRESH
        {
            return Ok(k.clone());
        }
        let line = serde_json::json!({"host": host}).to_string() + "\n";
        let reply = {
            let mut c = self.conn.lock().await;
            c.1.write_all(line.as_bytes()).await.map_err(|e| format!("signer: {e}"))?;
            let mut s = String::new();
            c.0.read_line(&mut s).await.map_err(|e| format!("signer: {e}"))?;
            s
        };
        let v: serde_json::Value = serde_json::from_str(&reply).map_err(|e| format!("signer: {e}"))?;
        if let Some(e) = v["error"].as_str() {
            return Err(e.to_string());
        }
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(v["chain"].as_str().unwrap_or("").as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| format!("signer chain: {e}"))?;
        let key = PrivateKeyDer::from_pem_slice(v["key"].as_str().unwrap_or("").as_bytes())
            .map_err(|e| format!("signer key: {e}"))?;
        let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| format!("signer key: {e}"))?;
        let ck = Arc::new(CertifiedKey::new(chain, signing));
        self.cache.lock().unwrap().insert(host.to_string(), (ck.clone(), Instant::now()));
        Ok(ck)
    }
}
