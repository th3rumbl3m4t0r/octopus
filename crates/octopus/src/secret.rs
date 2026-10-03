//! `octopus secret set KEY` (value on stdin) and `octopus secret --staged`
//! (the web UI's Wi-Fi passwords, staged by _octoweb as JSON). Only
//! `wifi_*` keys: the web UI can set a Wi-Fi passphrase, never read one,
//! and never touch the other secrets.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::os::{self, Res, log};

pub const SECRETS: &str = "/etc/octopus/secrets.toml";
const STAGED: &str = "/var/octopus/staged/secret.json";

fn valid(key: &str, value: &str) -> Res<()> {
    let k = key.strip_prefix("wifi_").ok_or("only wifi_* secrets can be set this way")?;
    if k.is_empty() || k.len() > 40 || !k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err(format!("{key:?}: wifi_ then a-z, 0-9, _"));
    }
    let hex = value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex && (value.len() < 8 || value.len() > 63) {
        return Err("a Wi-Fi passphrase is 8 to 63 characters".into());
    }
    if !value.bytes().all(|b| (0x20..0x7f).contains(&b)) || value.contains(['\'', '\\']) {
        return Err("printable characters only, no ' or \\".into());
    }
    Ok(())
}

/// Set `key` in secrets.toml (0600), keeping the rest of the file.
fn set(key: &str, value: &str) -> Res<()> {
    valid(key, value)?;
    let text = std::fs::read_to_string(SECRETS).unwrap_or_default();
    let mut t: toml::Table = toml::from_str(&text).map_err(|e| format!("{SECRETS}: {e}"))?;
    let changed = t.get(key).and_then(|v| v.as_str()) != Some(value);
    t.insert(key.to_string(), toml::Value::String(value.to_string()));
    if changed {
        // the file is flat key = "value" lines; comments at the top survive
        let comments: String = text.lines().take_while(|l| l.starts_with('#')).map(|l| format!("{l}\n")).collect();
        let body = toml::to_string(&t).map_err(|e| e.to_string())?;
        os::write_atomic(Path::new(SECRETS), format!("{comments}{body}").as_bytes(), 0o600, "root", "wheel")?;
        log(&format!("secret {key} set"));
    }
    println!("secret {key} {}", if changed { "set" } else { "unchanged" });
    Ok(())
}

pub fn cmd(args: &[String], staged: bool) -> Res<()> {
    if staged {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(STAGED)
            .map_err(|e| format!("{STAGED}: {e}"))?;
        let mut text = String::new();
        f.by_ref().take(4096).read_to_string(&mut text).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(STAGED);
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("staged secret: {e}"))?;
        let (Some(k), Some(val)) = (v["key"].as_str(), v["value"].as_str()) else {
            return Err("staged secret: {key, value}".into());
        };
        return set(k, val);
    }
    match args {
        [s, key] if s == "set" => {
            let mut val = String::new();
            std::io::stdin().read_to_string(&mut val).map_err(|e| e.to_string())?;
            set(key, val.trim_end_matches(['\n', '\r']))
        }
        _ => Err("usage: octopus secret set wifi_KEY < value | secret --staged".into()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_wifi_passphrases() {
        assert!(super::valid("wifi_home", "correct horse").is_ok());
        assert!(super::valid("pppoe_pass", "correct horse").is_err());
        assert!(super::valid("wifi_home", "short").is_err());
        assert!(super::valid("wifi_Home", "correct horse").is_err());
        assert!(super::valid("wifi_home", "it's mine!").is_err());
        assert!(super::valid("wifi_home", &"a".repeat(64)).is_ok());
    }
}
