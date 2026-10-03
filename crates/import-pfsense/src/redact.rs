//! Remove secrets from a pfSense config.xml before anyone (or any agent)
//! reads it (design rule R7). Element names decide what is secret; unknown
//! long base64 blobs are removed too, in case a package stores keys we
//! don't know about.

use sha2::{Digest, Sha256};

fn secret_tag(tag: &str, path: &[&str]) -> bool {
    let t = tag.to_ascii_lowercase();
    const PARTS: [&str; 13] = [
        "prv",
        "pass",
        "secret",
        "community",
        "device_key",
        "hash",
        "psk",
        "privatekey",
        "presharedkey",
        "apikey",
        "token",
        "bindpw",
        "shared_key",
    ];
    PARTS.iter().any(|p| t.contains(p))
        || t == "key"
        || t == "tls"
        || t.ends_with("domainkey")
        || (t == "username" && path.contains(&"ppp"))
        || t == "custom_options"
}

fn looks_like_blob(s: &str) -> bool {
    s.len() >= 40 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=\r\n \t".contains(&b))
}

pub fn redact(xml: &str) -> Result<String, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("config.xml: {e}"))?;
    let mut edits: Vec<(std::ops::Range<usize>, String)> = vec![];
    for n in doc.descendants().filter(|n| n.is_text()) {
        let Some(parent) = n.parent_element() else { continue };
        let text = n.text().unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        let path: Vec<&str> = parent.ancestors().filter(|a| a.is_element()).map(|a| a.tag_name().name()).collect();
        let tag = parent.tag_name().name();
        let replacement = if secret_tag(tag, &path) {
            "REDACTED".to_string()
        } else if tag == "crt" {
            let h = Sha256::digest(text.as_bytes());
            format!("CERT sha256:{}", h.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>())
        } else if looks_like_blob(text) && tag != "publickey" {
            format!("REDACTED(blob, {} bytes)", text.len())
        } else {
            continue;
        };
        edits.push((n.range(), replacement));
    }
    let mut out = String::with_capacity(xml.len());
    let mut at = 0;
    for (r, rep) in edits {
        out.push_str(&xml[at..r.start]);
        out.push_str(&rep);
        at = r.end;
    }
    out.push_str(&xml[at..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn removes_secrets() {
        let xml = "<pfsense><ppps><ppp><username>u@isp</username><password>aHVudGVyMg==</password></ppp></ppps>\
                   <system><user><name>admin</name><sha512-hash>$6$x</sha512-hash></user></system>\
                   <cert><prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVND</prv></cert>\
                   <interfaces><lan><descr>LAN</descr></lan></interfaces></pfsense>";
        let r = super::redact(xml).unwrap();
        for s in ["u@isp", "aHVudGVyMg==", "$6$x", "LS0tLS1CRUdJTi"] {
            assert!(!r.contains(s), "{s} leaked: {r}");
        }
        assert!(r.contains("<descr>LAN</descr>"));
        assert!(r.contains("<name>admin</name>"));
    }
}
