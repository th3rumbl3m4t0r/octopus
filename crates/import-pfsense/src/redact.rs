//! Remove secrets from a pfSense config.xml before anyone (or any agent)
//! reads it (design rule R7). Element names decide what is secret; unknown
//! long base64 blobs are removed too, in case a package stores keys we
//! don't know about.

use sha2::{Digest, Sha256};

fn secret_tag(tag: &str, path: &[&str]) -> bool {
    let t = tag.to_ascii_lowercase();
    // keys that aren't secret
    const PUBLIC: [&str; 6] = ["publickey", "keyname", "keyalgorithm", "keytype", "keylen", "pubkey"];
    if PUBLIC.contains(&t.as_str()) {
        return false;
    }
    // sections where most values are credentials: everything but plain names
    const SECRET_SECTIONS: [&str; 2] = ["notifications", "pppoes"];
    let inside = |s: &str| path.contains(&s);
    if SECRET_SECTIONS.iter().any(|s| inside(s))
        && !matches!(t.as_str(), "enable" | "descr" | "name" | "port" | "ipaddr")
    {
        return true;
    }
    const PARTS: [&str; 22] = [
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
        "pre-shared-key",
        "radiuskey",
        "keydata",
        "authkey",
        "userkey",
        "trapstring",
        "omapi_key",
        "maxmind",
        "api",
    ];
    PARTS.iter().any(|p| t.contains(p))
        || t == "key"
        || t.ends_with("_key")
        || t.ends_with("-key")
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
        // an element that only holds text: replace all of its content (text,
        // CDATA and text again are several pieces in the file, one node here)
        let range = match (parent.children().all(|c| c.is_text()), content_range(xml, parent)) {
            (true, Some(r)) => r,
            _ => n.range(),
        };
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
        edits.push((range, replacement));
    }
    edits.sort_by_key(|(r, _)| r.start);
    edits.dedup_by_key(|(r, _)| r.start);
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

/// The bytes between an element's start tag and its end tag.
fn content_range(xml: &str, e: roxmltree::Node) -> Option<std::ops::Range<usize>> {
    let r = e.range();
    let raw = &xml[r.clone()];
    if raw.ends_with("/>") {
        return None;
    }
    let start = r.start + raw.find('>')? + 1;
    let end = r.start + raw.rfind("</")?;
    (start <= end).then_some(start..end)
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

    #[test]
    fn removes_the_less_common_secrets_too() {
        let secrets = [
            ("<ipsec><phase1><pre-shared-key>ipsecpsk1</pre-shared-key></phase1></ipsec>", "ipsecpsk1"),
            ("<ipsec><mobilekey><pre-shared-key>mobpsk2</pre-shared-key></mobilekey></ipsec>", "mobpsk2"),
            ("<captiveportal><z><radiuskey>rad3</radiuskey><radiuskey2>rad4</radiuskey2></z></captiveportal>", "rad4"),
            (
                "<notifications><telegram><api>12345:tgtoken5</api><chatid>99</chatid></telegram></notifications>",
                "tgtoken5",
            ),
            ("<notifications><slack><api>xoxb-slack6</api></slack></notifications>", "xoxb-slack6"),
            ("<notifications><pushover><userkey>pushkey7</userkey></pushover></notifications>", "pushkey7"),
            ("<snmpd><trapstring>trap8</trapstring></snmpd>", "trap8"),
            ("<dnsupdates><dnsupdate><keydata>tsig9short==</keydata></dnsupdate></dnsupdates>", "tsig9short"),
            ("<ntpd><serverauthkey>ntpkey10</serverauthkey></ntpd>", "ntpkey10"),
            ("<dhcpd><lan><omapi_key>omapi11</omapi_key></lan></dhcpd>", "omapi11"),
            ("<pppoes><pppoe><username>bob:cGFzcw==:10.0.0.2</username></pppoe></pppoes>", "cGFzcw=="),
            ("<installedpackages><tailscale><authkey>tskey-12</authkey></tailscale></installedpackages>", "tskey-12"),
            ("<a><password>pre<![CDATA[cdatasecret13]]>post14</password></a>", "secret13"),
        ];
        for (x, leak) in secrets {
            let r = super::redact(&format!("<pfsense>{x}</pfsense>")).unwrap();
            assert!(!r.contains(leak), "{leak} leaked: {r}");
        }
        let r = super::redact("<pfsense><a><password>pre<![CDATA[x]]>post14</password></a></pfsense>").unwrap();
        assert!(!r.contains("post14"), "{r}");
        // public material stays
        let r = super::redact("<pfsense><wg><publickey>pubkey15</publickey><keyname>kn16</keyname></wg></pfsense>")
            .unwrap();
        assert!(r.contains("pubkey15") && r.contains("kn16"), "{r}");
    }
}
