//! The services root (design 14): certificates for internal services and
//! nginx's internal vhosts. Both CA levels carry a critical nameConstraints
//! extension (permitted: the internal zone and the internal address
//! ranges), so even a stolen intermediate can't vouch for any other name.
//!
//!   root          ECDSA P-256, 10 years, kept offline
//!   intermediate  pathlen:0, 3 years, its key on the router (0600)
//!   leaves        90 days, renewed by `octopus pki renew`
//!
//! This is the PKI code the owner reviews (R8).

use std::net::IpAddr;

use ipnet::IpNet;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256, SanType,
    SerialNumber,
};
use time::{Duration, OffsetDateTime};

pub type Res<T> = Result<T, String>;

/// A CA certificate and its private key, both PEM.
pub struct Ca {
    pub cert_pem: String,
    pub key_pem: String,
}

/// What the CAs may vouch for.
pub struct Constraints {
    pub dns: Vec<String>,
    pub ips: Vec<IpNet>,
}

pub struct Leaf {
    /// The leaf followed by the intermediate.
    pub chain_pem: String,
    pub key_pem: String,
    /// Unix seconds.
    pub not_after: i64,
}

fn serial() -> SerialNumber {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom");
    b[0] &= 0x7f; // positive
    SerialNumber::from_slice(&b)
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "Octopus");
    d.push(DnType::CommonName, cn);
    d
}

fn name_constraints(c: &Constraints) -> NameConstraints {
    let mut permitted: Vec<GeneralSubtree> = c.dns.iter().map(|d| GeneralSubtree::DnsName(d.clone())).collect();
    permitted.extend(
        c.ips.iter().map(|n| GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(n.network(), n.prefix_len()))),
    );
    NameConstraints { permitted_subtrees: permitted, excluded_subtrees: vec![] }
}

fn ca_params(cn: &str, c: &Constraints, years: i64, path_len: Option<u8>) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(match path_len {
        Some(n) => BasicConstraints::Constrained(n),
        None => BasicConstraints::Unconstrained,
    });
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.name_constraints = Some(name_constraints(c));
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::days(365 * years);
    p.serial_number = Some(serial());
    p
}

fn check(c: &Constraints) -> Res<()> {
    if c.dns.is_empty() {
        return Err("a services root needs at least one permitted DNS name (the internal zone)".into());
    }
    Ok(())
}

/// A new root, self-signed. Keep its key offline.
pub fn new_root(cn: &str, c: &Constraints) -> Res<Ca> {
    check(c)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    // pathlen 1: exactly one intermediate below it
    let cert = ca_params(cn, c, 10, Some(1)).self_signed(&key).map_err(|e| e.to_string())?;
    Ok(Ca { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
}

/// A new intermediate signed by `root`: pathlen 0, the same constraints.
pub fn new_intermediate(root: &Ca, cn: &str, c: &Constraints) -> Res<Ca> {
    check(c)?;
    let root_key = KeyPair::from_pem(&root.key_pem).map_err(|e| format!("root key: {e}"))?;
    let issuer = Issuer::from_ca_cert_pem(&root.cert_pem, root_key).map_err(|e| format!("root certificate: {e}"))?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let cert = ca_params(cn, c, 3, Some(0)).signed_by(&key, &issuer).map_err(|e| e.to_string())?;
    Ok(Ca { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
}

/// The permitted names of a CA certificate (None: it has no constraints).
pub fn permitted(ca_pem: &str) -> Res<Option<Constraints>> {
    use x509_parser::extensions::GeneralName;
    let (_, pem) = x509_parser::pem::parse_x509_pem(ca_pem.as_bytes()).map_err(|e| format!("CA certificate: {e}"))?;
    let cert = pem.parse_x509().map_err(|e| format!("CA certificate: {e}"))?;
    let Some(nc) = cert.name_constraints().map_err(|e| format!("CA certificate: {e}"))? else { return Ok(None) };
    let mut c = Constraints { dns: vec![], ips: vec![] };
    for t in nc.value.permitted_subtrees.iter().flatten() {
        match t.base {
            GeneralName::DNSName(d) => c.dns.push(d.to_string()),
            // address then mask, 4 + 4 or 16 + 16 bytes
            GeneralName::IPAddress(b) => {
                let (a, m) = b.split_at(b.len() / 2);
                let len = m.iter().map(|x| x.count_ones() as u8).sum();
                let net = match a.len() {
                    4 => IpNet::new(IpAddr::from(<[u8; 4]>::try_from(a).unwrap()), len),
                    16 => IpNet::new(IpAddr::from(<[u8; 16]>::try_from(a).unwrap()), len),
                    _ => continue,
                };
                c.ips.extend(net.ok());
            }
            _ => {}
        }
    }
    Ok(Some(c))
}

impl Constraints {
    /// Whether a DNS name is inside a permitted zone (the zone itself or below it).
    pub fn allows_dns(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.dns.iter().any(|z| {
            let z = z.trim_start_matches('.').to_ascii_lowercase();
            name == z || name.ends_with(&format!(".{z}"))
        })
    }

    pub fn allows_ip(&self, ip: &IpAddr) -> bool {
        self.ips.iter().any(|n| n.contains(ip))
    }

    /// Of `dns` and `ips`, what a CA so constrained may vouch for, and what
    /// it can't (as strings, for the log). A name type the constraints don't
    /// mention at all is unconstrained (RFC 5280 4.2.1.10).
    pub fn vouched(&self, dns: &[String], ips: &[IpAddr]) -> (Vec<String>, Vec<IpAddr>, Vec<String>) {
        let mut dropped = vec![];
        let d = dns
            .iter()
            .filter(|n| {
                let ok = self.dns.is_empty() || self.allows_dns(n);
                if !ok {
                    dropped.push((*n).clone());
                }
                ok
            })
            .cloned()
            .collect();
        let i = ips
            .iter()
            .copied()
            .filter(|a| {
                let ok = self.ips.is_empty() || self.allows_ip(a);
                if !ok {
                    dropped.push(a.to_string());
                }
                ok
            })
            .collect();
        (d, i, dropped)
    }
}

/// A server certificate for `dns` names and `ips`, valid for `days`.
pub fn issue(inter: &Ca, dns: &[String], ips: &[IpAddr], days: i64) -> Res<Leaf> {
    if dns.is_empty() && ips.is_empty() {
        return Err("a certificate needs at least one name or address".into());
    }
    let inter_key = KeyPair::from_pem(&inter.key_pem).map_err(|e| format!("intermediate key: {e}"))?;
    let issuer =
        Issuer::from_ca_cert_pem(&inter.cert_pem, inter_key).map_err(|e| format!("intermediate certificate: {e}"))?;
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(dns.first().map(String::as_str).unwrap_or("octopus"));
    let mut sans = vec![];
    for d in dns {
        sans.push(SanType::DnsName(d.clone().try_into().map_err(|e| format!("{d}: {e}"))?));
    }
    sans.extend(ips.iter().map(|ip| SanType::IpAddress(*ip)));
    p.subject_alt_names = sans;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::days(days);
    p.serial_number = Some(serial());
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let cert = p.signed_by(&key, &issuer).map_err(|e| e.to_string())?;
    Ok(Leaf {
        chain_pem: format!("{}{}", cert.pem(), inter.cert_pem),
        key_pem: key.serialize_pem(),
        not_after: p.not_after.unix_timestamp(),
    })
}

/// The interception root (design 14): pathlen 0, 2 years, no name
/// constraints (it has to vouch for any name a server asks for). Trusted by
/// servers only, never by personal devices.
pub fn new_intercept_root() -> Res<Ca> {
    let mut p = CertificateParams::default();
    p.distinguished_name = dn("Octopus interception root (servers only)");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::days(730);
    p.serial_number = Some(serial());
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let cert = p.self_signed(&key).map_err(|e| e.to_string())?;
    Ok(Ca { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
}

/// A key and a certificate request with CN=`cn` (for CAs elsewhere, like
/// the log server's). Returns (csr_pem, key_pem).
pub fn csr(cn: &str) -> Res<(String, String)> {
    let mut p = CertificateParams::default();
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    p.distinguished_name = d;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let req = p.serialize_request(&key).map_err(|e| e.to_string())?;
    Ok((req.pem().map_err(|e| e.to_string())?, key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain() {
        let c = Constraints { dns: vec!["home.arpa".into()], ips: vec!["10.0.0.0/8".parse().unwrap()] };
        let root = new_root("Octopus services root", &c).unwrap();
        let inter = new_intermediate(&root, "Octopus services intermediate", &c).unwrap();
        let leaf = issue(&inter, &["nas.home.arpa".into()], &["10.20.0.1".parse().unwrap()], 90).unwrap();
        assert!(leaf.chain_pem.matches("BEGIN CERTIFICATE").count() == 2);
        assert!(leaf.not_after > OffsetDateTime::now_utc().unix_timestamp() + 89 * 86400);
        assert!(new_root("x", &Constraints { dns: vec![], ips: vec![] }).is_err());
        let p = permitted(&inter.cert_pem).unwrap().unwrap();
        assert_eq!(p.dns, ["home.arpa"]);
        assert_eq!(p.ips, ["10.0.0.0/8".parse::<IpNet>().unwrap()]);
        assert!(p.allows_dns("nas.home.arpa") && p.allows_dns("home.arpa") && !p.allows_dns("evilhome.arpa"));
        assert!(p.allows_ip(&"10.20.0.1".parse().unwrap()) && !p.allows_ip(&"192.168.1.1".parse().unwrap()));
        // a leaf for a lab that outgrew its root: only the covered names, the rest reported
        let (d, i, dropped) = p.vouched(
            &["rt.home.arpa".to_string(), "rt.example.org".to_string()],
            &["10.51.1.1".parse().unwrap(), "192.168.1.41".parse().unwrap()],
        );
        assert_eq!(d, ["rt.home.arpa"]);
        assert_eq!(i, ["10.51.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(dropped, ["rt.example.org", "192.168.1.41"]);
        // constraints on DNS names only leave addresses alone
        let dns_only = Constraints { dns: vec!["home.arpa".into()], ips: vec![] };
        assert_eq!(dns_only.vouched(&[], &["192.168.1.41".parse().unwrap()]).1.len(), 1);
    }
}
