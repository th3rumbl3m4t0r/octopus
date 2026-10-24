//! Client for octopus-pfhelper: one JSON request per line on a Unix
//! socket, one reply per line. One connection, reopened on failure.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

pub struct Helper {
    path: String,
    conn: Mutex<Option<BufReader<UnixStream>>>,
}

impl Helper {
    pub fn new(path: &str) -> Helper {
        Helper { path: path.to_string(), conn: Mutex::new(None) }
    }

    /// One request, all of it (waiting for the connection included) within `wait`.
    pub async fn request(&self, table: &str, op: &str, addresses: &[String], wait: Duration) -> Result<(), String> {
        let line = serde_json::json!({"table": table, "op": op, "addresses": addresses}).to_string() + "\n";
        tokio::time::timeout(wait, self.exchange(&line)).await.unwrap_or_else(|_| Err("timed out".into()))
    }

    async fn exchange(&self, line: &str) -> Result<(), String> {
        // dropped halfway (the caller's deadline), the connection may still get
        // this reply: it goes with the guard, before the next request has it
        let mut guard = Reset(self.conn.lock().await, false);
        let r = self.exchange_on(&mut guard.0, line).await;
        guard.1 = true;
        r
    }

    async fn exchange_on(&self, guard: &mut Option<BufReader<UnixStream>>, line: &str) -> Result<(), String> {
        for attempt in 0..2 {
            if guard.is_none() {
                let s = UnixStream::connect(&self.path).await.map_err(|e| format!("{}: {e}", self.path))?;
                *guard = Some(BufReader::new(s));
            }
            let conn = guard.as_mut().unwrap();
            let mut reply = String::new();
            let ok = conn.get_mut().write_all(line.as_bytes()).await.is_ok()
                && conn.read_line(&mut reply).await.is_ok_and(|n| n > 0);
            if !ok {
                *guard = None;
                if attempt == 0 {
                    continue;
                }
                return Err("connection lost".into());
            }
            let v: serde_json::Value = serde_json::from_str(&reply).map_err(|e| format!("bad reply: {e}"))?;
            return if v["ok"].as_bool() == Some(true) {
                Ok(())
            } else {
                Err(v["error"].as_str().unwrap_or("refused").to_string())
            };
        }
        Err("unreachable".into())
    }
}

/// The connection, reset unless the exchange that holds it finished.
struct Reset<'a>(tokio::sync::MutexGuard<'a, Option<BufReader<UnixStream>>>, bool);

impl Drop for Reset<'_> {
    fn drop(&mut self) {
        if !self.1 {
            *self.0 = None;
        }
    }
}
