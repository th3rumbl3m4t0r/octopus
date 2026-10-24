//! Logins: a users file of `name:bcrypt-hash` lines (make hashes with
//! `encrypt(1)` or `octopus-web --hash`), `:ro` after the hash for a user
//! who may look but not change anything; sessions in memory; a small
//! per-address failure limit, counted before the password is checked, and
//! a few password checks at a time.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const COOKIE: &str = "octopus_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_FAILS: u32 = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(300);
/// bcrypt runs at once: a flood of logins can't take every CPU.
const MAX_CHECKING: usize = 4;

pub struct Auth {
    /// name -> (hash, read-only)
    users: HashMap<String, (String, bool)>,
    /// verified against for unknown users, so timing doesn't reveal names
    dummy: String,
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    checking: std::sync::atomic::AtomicUsize,
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
            let (name, rest) = l.split_once(':').ok_or_else(|| format!("{path}:{}: expected name:hash", i + 1))?;
            let (hash, ro) = match rest.rsplit_once(':') {
                Some((h, "ro")) => (h, true),
                _ => (rest, false),
            };
            if !hash.starts_with("$2") {
                return Err(format!("{path}:{}: hash for {name} is not bcrypt", i + 1));
            }
            users.insert(name.to_string(), (hash.to_string(), ro));
        }
        if users.is_empty() {
            return Err(format!("{path}: no users"));
        }
        let cost = users.values().next().and_then(|(h, _)| h.get(4..6)?.parse().ok()).unwrap_or(10);
        let dummy = bcrypt::hash("octopus-dummy", cost).map_err(|e| e.to_string())?;
        Ok(Auth {
            users,
            dummy,
            sessions: Mutex::new(HashMap::new()),
            fails: Mutex::new(HashMap::new()),
            checking: Default::default(),
        })
    }

    /// Ok(session token) or Err(message for the login page).
    pub fn login(&self, ip: IpAddr, user: &str, password: &str) -> Result<String, &'static str> {
        use std::sync::atomic::Ordering;
        // every attempt counts as a failure until it succeeds: attempts at
        // the same moment can't all slip under the limit
        {
            let mut f = self.fails.lock().unwrap();
            f.retain(|_, (_, t)| t.elapsed() < FAIL_WINDOW);
            let e = f.entry(ip).or_insert((0, Instant::now()));
            if e.0 >= MAX_FAILS {
                return Err("too many failed logins; wait five minutes");
            }
            e.0 += 1;
            e.1 = Instant::now();
        }
        if self.checking.fetch_add(1, Ordering::SeqCst) >= MAX_CHECKING {
            self.checking.fetch_sub(1, Ordering::SeqCst);
            return Err("too many logins at once; try again");
        }
        let hash = self.users.get(user).map(|(h, _)| h).unwrap_or(&self.dummy);
        let ok = bcrypt::verify(password, hash).unwrap_or(false) && self.users.contains_key(user);
        self.checking.fetch_sub(1, Ordering::SeqCst);
        if !ok {
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

    /// May this user only look?
    pub fn read_only(&self, user: &str) -> bool {
        self.users.get(user).is_none_or(|(_, ro)| *ro)
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
        // a burst from one address: no more than MAX_FAILS get a password check
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let checked = std::sync::atomic::AtomicU32::new(0);
        std::thread::scope(|sc| {
            for _ in 0..40 {
                sc.spawn(|| {
                    if a.login(other, "admin", "x") == Err("wrong user or password") {
                        checked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert!(checked.into_inner() <= MAX_FAILS);
        assert!(!a.read_only("admin"));
        assert_eq!(cookie(Some("a=b; octopus_session=abc")).as_deref(), Some("abc"));
        let _ = std::fs::remove_file(path);
    }
}
