//! Writes a root, an intermediate, a leaf inside the constraints and one
//! outside them into DIR, for checking with `openssl verify`.
fn main() {
    let dir = std::env::args().nth(1).expect("usage: constraints-demo DIR");
    let c = octopus_pki::Constraints { dns: vec!["home.arpa".into()], ips: vec!["10.0.0.0/8".parse().unwrap()] };
    let root = octopus_pki::new_root("demo root", &c).unwrap();
    let inter = octopus_pki::new_intermediate(&root, "demo intermediate", &c).unwrap();
    let good = octopus_pki::issue(&inter, &["nas.home.arpa".into()], &["10.1.2.3".parse().unwrap()], 90).unwrap();
    let bad = octopus_pki::issue(&inter, &["www.example.com".into()], &[], 90).unwrap();
    let badip = octopus_pki::issue(&inter, &["x.home.arpa".into()], &["192.0.2.1".parse().unwrap()], 90).unwrap();
    let w = |n: &str, s: &str| std::fs::write(format!("{dir}/{n}"), s).unwrap();
    w("root.pem", &root.cert_pem);
    w("inter.pem", &inter.cert_pem);
    let leaf = |chain: &str| chain.split_inclusive("-----END CERTIFICATE-----\n").next().unwrap().to_string();
    w("good.pem", &leaf(&good.chain_pem));
    w("bad.pem", &leaf(&bad.chain_pem));
    w("badip.pem", &leaf(&badip.chain_pem));
}
