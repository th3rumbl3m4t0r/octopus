//! secrets.toml: a flat table of strings, referenced from router.toml as
//! `secret:<key>`. Values never appear in Debug output or error messages.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

pub const PREFIX: &str = "secret:";

#[derive(Default, Clone)]
pub struct Secrets {
    values: BTreeMap<String, String>,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets").field("keys", &self.values.keys().collect::<Vec<_>>()).finish()
    }
}

/// The key of a `secret:<key>` reference, or None if `s` isn't one.
pub fn key_of(s: &str) -> Option<&str> {
    let k = s.strip_prefix(PREFIX)?;
    let ok = !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then_some(k)
}

impl Secrets {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let table: toml::Table = text.parse().map_err(|e: toml::de::Error| {
            // the parser quotes the offending line; keep only the position
            match e.span() {
                Some(span) => format!("syntax error at byte {}", span.start),
                None => "syntax error".to_string(),
            }
        })?;
        let mut values = BTreeMap::new();
        for (k, v) in table {
            match v {
                toml::Value::String(s) => {
                    values.insert(k, s);
                }
                _ => return Err(format!("secret {k:?} must be a string")),
            }
        }
        Ok(Secrets { values })
    }

    pub fn insert(&mut self, key: &str, value: String) {
        self.values.insert(key.to_string(), value);
    }

    pub fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Resolve a `secret:<key>` reference.
    pub fn resolve(&self, reference: &str) -> Result<&str, String> {
        let key = key_of(reference).ok_or_else(|| format!("{reference:?} is not a secret:<key> reference"))?;
        self.values.get(key).map(String::as_str).ok_or_else(|| format!("secret {key:?} is not in secrets.toml"))
    }

    /// TOML text for writing a secrets.toml (mode 0600 is the caller's job).
    pub fn to_toml(&self) -> String {
        let mut t = toml::Table::new();
        for (k, v) in &self.values {
            t.insert(k.clone(), toml::Value::String(v.clone()));
        }
        toml::to_string(&t).unwrap_or_default()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs() {
        assert_eq!(key_of("secret:pppoe_user"), Some("pppoe_user"));
        assert_eq!(key_of("secret:"), None);
        assert_eq!(key_of("pppoe_user"), None);
        assert_eq!(key_of("secret:a b"), None);
    }

    #[test]
    fn errors_hide_values() {
        let e = Secrets::parse("k = \"hunter2\"\nbad line hunter2").unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
        let s = Secrets::parse("k = \"hunter2\"").unwrap();
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(s.resolve("secret:k").unwrap(), "hunter2");
        assert!(s.resolve("secret:x").unwrap_err().contains("not in secrets.toml"));
    }
}
