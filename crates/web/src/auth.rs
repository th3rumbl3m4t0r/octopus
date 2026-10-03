//! Logins: a users file of `name:bcrypt-hash` lines (make hashes with
//! `encrypt(1)` or `octopus-web --hash`), sessions in memory, and a small
//! per-address failure limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const COOKIE: &str = "octopus_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_FAILS: u32 = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(300);

pub struct Auth {
    users: HashMap<String, String>,
    /// verified against for unknown users, so timing doesn't reveal names
    dummy: String,
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Auth {
    pub fn load(path: &str) -> Result<Auth, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let mut users = HashMap::new();
        for (i, l) in text.lines().enumerate() {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let (name, hash) = l.split_once(':').ok_or_else(|| format!("{path}:{}: expected name:hash", i + 1))?;
            if !hash.starts_with("$2") {
                return Err(format!("{path}:{}: hash for {name} is not bcrypt", i + 1));
            }
            users.insert(name.to_string(), hash.to_string());
        }
        if users.is_empty() {
            return Err(format!("{path}: no users"));
        }
        let cost = users.values().next().and_then(|h| h.get(4..6)?.parse().ok()).unwrap_or(10);
        let dummy = bcrypt::hash("octopus-dummy", cost).map_err(|e| e.to_string())?;
        Ok(Auth { users, dummy, sessions: Mutex::new(HashMap::new()), fails: Mutex::new(HashMap::new()) })
    }

    /// Ok(session token) or Err(message for the login page).
    pub fn login(&self, ip: IpAddr, user: &str, password: &str) -> Result<String, &'static str> {
        {
            let mut f = self.fails.lock().unwrap();
            f.retain(|_, (_, t)| t.elapsed() < FAIL_WINDOW);
            if f.get(&ip).is_some_and(|(n, _)| *n >= MAX_FAILS) {
                return Err("too many failed logins; wait five minutes");
            }
        }
        let hash = self.users.get(user).unwrap_or(&self.dummy);
        let ok = bcrypt::verify(password, hash).unwrap_or(false) && self.users.contains_key(user);
        if !ok {
            let mut f = self.fails.lock().unwrap();
            let e = f.entry(ip).or_insert((0, Instant::now()));
            e.0 += 1;
            e.1 = Instant::now();
            return Err("wrong user or password");
        }
        self.fails.lock().unwrap().remove(&ip);
        let token = token();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, (_, t)| t.elapsed() < SESSION_TTL);
        s.insert(token.clone(), (user.to_string(), Instant::now()));
        Ok(token)
    }

    pub fn user(&self, token: &str) -> Option<String> {
        let s = self.sessions.lock().unwrap();
        s.get(token).filter(|(_, t)| t.elapsed() < SESSION_TTL).map(|(u, _)| u.clone())
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

fn token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("getrandom");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The session token from a Cookie header.
pub fn cookie(header: Option<&str>) -> Option<String> {
    header?.split(';').map(str::trim).find_map(|c| c.strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions() {
        let hash = bcrypt::hash("pw", 4).unwrap();
        let path = std::env::temp_dir().join(format!("octopus-users-{}", std::process::id()));
        std::fs::write(&path, format!("admin:{hash}\n")).unwrap();
        let a = Auth::load(path.to_str().unwrap()).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(a.login(ip, "admin", "nope").is_err());
        assert!(a.login(ip, "ghost", "pw").is_err());
        let t = a.login(ip, "admin", "pw").unwrap();
        assert_eq!(a.user(&t).as_deref(), Some("admin"));
        a.logout(&t);
        assert!(a.user(&t).is_none());
        for _ in 0..MAX_FAILS {
            let _ = a.login(ip, "admin", "x");
        }
        assert!(a.login(ip, "admin", "pw").is_err(), "locked out after failures");
        assert_eq!(cookie(Some("a=b; octopus_session=abc")).as_deref(), Some("abc"));
        let _ = std::fs::remove_file(path);
    }
}
