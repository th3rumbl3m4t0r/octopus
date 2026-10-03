use std::collections::BTreeMap;

use octopus_config::{Router, Secrets, check::check, parse};

use crate::{SecretSource, render};

const EXAMPLE: &str = include_str!("../../../examples/vlans.toml");

fn router(text: &str) -> Router {
    let cfg = parse(text).expect("parse");
    let r = Router::resolve(cfg, &BTreeMap::new()).expect("resolve");
    let d = check(&r, None);
    assert!(!d.has_errors(), "{d}");
    r
}

/// The Kea config, without its comment line.
fn kea(g: &crate::Generation) -> serde_json::Value {
    let text = &g.get("/etc/kea/kea-dhcp4.conf").unwrap().content;
    serde_json::from_str(text.split_once('\n').unwrap().1).unwrap()
}

fn secrets() -> Secrets {
    Secrets::parse("pppoe_user = \"user@isp\"\npppoe_pass = \"s3cr3t-pw\"\nwg_key = \"WGKEYWGKEYWGKEYWGKEYWGKEYWGKEYWGKEYWGKEY0=\"").unwrap()
}

#[test]
fn pf_starts_with_default_block() {
    // INV-7: `set skip on lo`, and the first rule is the default block
    let g = render(&router(EXAMPLE), &SecretSource::Placeholder).unwrap();
    let pf = &g.get("/etc/pf.conf").unwrap().content;
    assert!(pf.contains("set skip on lo\n"));
    let first_rule =
        pf.lines().map(str::trim).find(|l| ["pass", "block", "match"].iter().any(|k| l.starts_with(k))).unwrap();
    assert_eq!(first_rule, "block log all");
}

#[test]
fn secrets_only_in_0600_files() {
    // INV-8
    let g = render(&router(EXAMPLE), &SecretSource::Real(&secrets())).unwrap();
    for f in &g.files {
        let has = ["user@isp", "s3cr3t-pw", "WGKEYWGKEY"].iter().any(|v| f.content.contains(v));
        if has {
            assert!(f.secret && f.mode == 0o600, "{} has a secret but mode {:o}", f.path, f.mode);
        }
    }
    assert!(g.get("/etc/hostname.pppoe0").unwrap().content.contains("authkey 's3cr3t-pw'"));
}

#[test]
fn sshd_and_web_only_on_mgmt() {
    // INV-1
    let g = render(&router(EXAMPLE), &SecretSource::Placeholder).unwrap();
    let sshd = &g.get("/etc/ssh/sshd_config").unwrap().content;
    let listens: Vec<&str> = sshd.lines().filter(|l| l.starts_with("ListenAddress")).collect();
    // mgmt network plus the WireGuard address (a peer is mapped to mgmt)
    assert_eq!(listens, ["ListenAddress 10.10.0.1", "ListenAddress 10.99.0.1"]);
    let pf = &g.get("/etc/pf.conf").unwrap().content;
    assert!(pf.contains("block in log quick on $if_lan proto tcp to self port $mgmt_ports"));
    assert!(pf.contains("block in log quick on $if_servers proto tcp to self port $mgmt_ports"));
    assert!(!pf.contains("block in log quick on $if_mgmt proto tcp to self port $mgmt_ports"));
}

#[test]
fn rejects_bad_secret_values() {
    let s = Secrets::parse("pppoe_user = \"a'b\"\npppoe_pass = \"x\"\nwg_key = \"k\"").unwrap();
    assert!(render(&router(EXAMPLE), &SecretSource::Real(&s)).is_err());
}

#[test]
fn invariants_catch_violations() {
    let bad = format!(
        "{EXAMPLE}\n[[rules]]\nnetwork = \"lan\"\naction = \"pass\"\nto = \"self\"\nproto = \"tcp\"\nport = 22\n\n\
         [[rules]]\nnetwork = \"servers\"\naction = \"pass\"\nto = \"any\"\nproto = \"tcp\"\nport = 443\n"
    );
    let r = Router::resolve(parse(&bad).unwrap(), &BTreeMap::new()).unwrap();
    let d = check(&r, None);
    let codes: Vec<&str> = d.errors().map(|e| e.code).collect();
    assert!(codes.contains(&"INV-1"), "{d}");
    assert!(codes.contains(&"INV-3"), "{d}");
}

#[test]
fn dhcp_reservations_and_dns() {
    let g = render(&router(EXAMPLE), &SecretSource::Placeholder).unwrap();
    let dhcp = kea(&g);
    let tv = dhcp["Dhcp4"]["subnet4"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["reservations"].as_array().unwrap().clone())
        .find(|r| r["hostname"] == "tv")
        .unwrap();
    assert_eq!((tv["hw-address"].as_str(), tv["ip-address"].as_str()), (Some("aa:bb:cc:dd:ee:ff"), Some("10.20.0.50")));
    let zone = &g.get("/etc/octopus/dns/zones/home.arpa.zone").unwrap().content;
    assert!(zone.contains("files"));
    assert!(g.get("/etc/octopus/dns/zones/use-application-dns.net.zone").is_some());
    assert!(g.get("/etc/octopus/dns/zones/0.20.10.in-addr.arpa.zone").unwrap().content.contains("PTR   tv.home.arpa."));
    let named = &g.get("/etc/octopus/dns/named.toml").unwrap().content;
    assert!(named.contains("server_name = \"dns.quad9.net\""));
    assert!(!named.contains("port = 53\n[[zones.stores"), "no plaintext upstreams");
}

#[test]
fn phase_b_dns() {
    let text = EXAMPLE.replace("[dns]\n", "[dns]\nengine = \"octopus-dns\"\n");
    let g = render(&router(&text), &SecretSource::Placeholder).unwrap();
    assert!(g.get("/etc/octopus/dns/named.toml").is_none());
    let conf = &g.get("/etc/octopus/dns/octopus-dns.toml").unwrap().content;
    assert!(conf.contains("nxdomain = [\"use-application-dns.net\"]"));
    assert!(conf.contains("table = \"cls_streaming\""));
    assert!(conf.contains("[[forward.name_servers]]"));
    // the canary is answered by the daemon, not a zone
    assert!(g.get("/etc/octopus/dns/zones/use-application-dns.net.zone").is_none());
    let on: Vec<&str> = g.services.iter().filter(|s| s.enabled).map(|s| s.name.as_str()).collect();
    assert!(on.contains(&"octopus_dns") && on.contains(&"octopus_pfhelper") && !on.contains(&"octopus_hickory"));
}

const BRIDGED: &str = r#"
[system]
hostname = "rt"
domain = "home.arpa"
openbsd_release = "7.9"

[interfaces.wan]
mac = "00:00:00:00:00:01"
name = "igc0"
[interfaces.fast]
mac = "00:00:00:00:00:02"
name = "igc1"
[interfaces.slow]
mac = "00:00:00:00:00:03"
name = "igc2"
[interfaces.vast]
mac = "00:00:00:00:00:04"
name = "igc3"

[wan]
interface = "wan"
vlan = 848
pppoe = { user = "secret:u", password = "secret:p" }
mtu = 1492

[[networks]]
name = "lan"
bridge = ["fast", "vast"]
address = "192.168.1.1/16"
kind = "mgmt"
dhcp = { ranges = [["192.168.0.10", "192.168.0.254"], ["192.168.2.10", "192.168.2.254"]] }

[[networks]]
name = "slow"
interface = "slow"
address = "172.16.2.1/24"
kind = "lan"
ipv6_slot = 3

[[hosts]]
name = "pc"
network = "lan"
ip = "192.168.1.11"

[ipv6]
mode = "pd"

[dns]
engine = "octopus-dns"
upstreams = [{ ip = "1.1.1.2", tls_name = "security.cloudflare-dns.com" }]
views = [{ name = "unfiltered", upstreams = [{ ip = "1.1.1.1", tls_name = "cloudflare-dns.com" }], clients = ["pc"] }]

[logging]
remote = ["tls://192.168.1.21:514"]
tls_ca = "/etc/octopus/syslog/ca.crt"
tls_cert = "/etc/octopus/syslog/router.crt"
tls_key = "/etc/octopus/syslog/router.key"
pf = true
"#;

#[test]
fn bridge_ipv6_views_syslog() {
    let g = render(&router(BRIDGED), &SecretSource::Placeholder).unwrap();
    let veb = &g.get("/etc/hostname.veb0").unwrap().content;
    assert!(veb.contains("!ifconfig vport0 create\nadd igc1\nadd igc3\nadd vport0\n"), "{veb}");
    let vport = &g.get("/etc/hostname.vport0").unwrap().content;
    assert!(vport.contains("inet 192.168.1.1 255.255.0.0"));
    assert!(vport.contains("inet6 fd") && vport.contains("group octolan"));
    assert!(!g.get("/etc/hostname.igc1").unwrap().content.contains("inet "), "a bridge port has no address");
    let dhcp = kea(&g);
    let lan =
        dhcp["Dhcp4"]["subnet4"].as_array().unwrap().iter().find(|s| s["subnet"] == "192.168.0.0/16").unwrap().clone();
    let pools: Vec<&str> = lan["pools"].as_array().unwrap().iter().map(|p| p["pool"].as_str().unwrap()).collect();
    assert_eq!(pools, ["192.168.0.10 - 192.168.0.254", "192.168.2.10 - 192.168.2.254"]);
    assert_eq!(lan["interface"], "vport0");

    // IPv6: 16 slots (/60), lan at 0, slow at its fixed slot 3
    let pd = &g.get("/etc/dhcp6leased.conf").unwrap().content;
    let slots: Vec<&str> =
        pd.lines().filter(|l| l.starts_with('\t')).map(|l| l.trim().split('\t').next().unwrap()).collect();
    assert_eq!(slots.len(), 16);
    assert_eq!(slots[0], "vport0");
    assert_eq!(slots[3], "igc2");
    assert!(pd.contains("on pppoe0"));
    assert!(g.get("/etc/rad.conf").unwrap().content.contains("interface vport0"));
    let pf = &g.get("/etc/pf.conf").unwrap().content;
    assert!(!pf.contains("block quick inet6 all"));
    assert!(pf.contains("inet6 to (octolan:network)"));
    assert!(pf.contains("to <public_resolvers> port { 443 853 }"));
    assert!(g.get("/etc/hostname.pppoe0").unwrap().content.contains("inet6 eui64"));

    // DNS: the view has its own upstreams; the client is the host's address
    let dns = &g.get("/etc/octopus/dns/octopus-dns.toml").unwrap().content;
    assert!(dns.contains("[[views]]\nname = \"unfiltered\"\nclients = [\"192.168.1.11/32\"]"), "{dns}");
    assert!(dns.contains("[[views.forward.name_servers]]\nip = \"1.1.1.1\""));
    assert!(dns.contains("[[forward.name_servers]]\nip = \"1.1.1.2\""));

    // syslog over TLS with a client certificate; pf log forwarded
    let svc = |n: &str| g.services.iter().find(|s| s.name == n).unwrap().clone();
    assert_eq!(
        svc("syslogd").flags.as_deref(),
        Some("-C /etc/octopus/syslog/ca.crt -c /etc/octopus/syslog/router.crt -k /etc/octopus/syslog/router.key")
    );
    assert!(svc("octopus_filterlog").enabled && svc("dhcp6leased").enabled && svc("rad").enabled);
    assert!(g.get("/etc/syslog.conf").unwrap().content.contains("@tls://192.168.1.21:514"));
}

#[test]
fn dns_overrides_and_sinkhole() {
    let text = BRIDGED.replace("[dns]\n", "[dns]\nsinkhole = \"192.168.1.250\"\n")
        + "\n[[dns.overrides]]\nname = \"Ads.Example.com.\"\nip = \"192.168.1.250\"\n\n\
           [[dns.overrides]]\nname = \"exact.example.net\"\nip = \"fd00::1\"\nsubdomains = false\n";
    let g = render(&router(&text), &SecretSource::Placeholder).unwrap();
    let zone = |n: &str| g.get(&format!("/etc/octopus/dns/zones/{n}.zone")).map(|f| f.content.clone());
    // the name lowercased, and with subdomains (the default) a wildcard too
    let ads = zone("ads.example.com").expect("override zone");
    let a: Vec<Vec<&str>> =
        ads.lines().map(|l| l.split_whitespace().collect::<Vec<_>>()).filter(|f| f.get(2) == Some(&"A")).collect();
    assert_eq!(a, [["@", "IN", "A", "192.168.1.250"], ["*", "IN", "A", "192.168.1.250"]], "{ads}");
    let exact = zone("exact.example.net").expect("override zone");
    assert!(
        exact.contains("fd00::1") && exact.contains("AAAA") && !exact.lines().any(|l| l.starts_with('*')),
        "{exact}"
    );
    let conf = &g.get("/etc/octopus/dns/octopus-dns.toml").unwrap().content;
    assert!(conf.contains("\"ads.example.com\"") && conf.contains("\"exact.example.net\""), "{conf}");
    assert!(conf.contains("sinkhole = \"192.168.1.250\"\n"));
    // without one, octopus-dns gets no sinkhole line
    let plain = render(&router(BRIDGED), &SecretSource::Placeholder).unwrap();
    assert!(!plain.get("/etc/octopus/dns/octopus-dns.toml").unwrap().content.contains("sinkhole"));

    let errors = |t: &str| {
        let r = Router::resolve(parse(t).unwrap(), &BTreeMap::new()).unwrap();
        check(&r, None).errors().map(|e| e.msg.clone()).collect::<Vec<_>>()
    };
    // the sinkhole is octopus-dns's; hickory can't do it
    let hickory = EXAMPLE.replace("[dns]\n", "[dns]\nsinkhole = \"10.10.0.250\"\n");
    assert!(errors(&hickory).iter().any(|m| m.contains("sinkhole")), "{:?}", errors(&hickory));
    // names in the internal zone are [[hosts]], not overrides
    let internal = format!("{BRIDGED}\n[[dns.overrides]]\nname = \"nas.home.arpa\"\nip = \"192.168.1.5\"\n");
    assert!(errors(&internal).iter().any(|m| m.contains("internal zone")), "{:?}", errors(&internal));
}

#[test]
fn public_vhosts_and_rule_scopes() {
    let text = format!(
        "{BRIDGED}
[[tables]]
name = \"bad\"
entries = [\"198.51.100.0/24\"]

[[rules]]
network = \"all\"
action = \"pass\"
to = \"host:pc\"
proto = \"tcp\"
port = 8006

[[rules]]
network = \"wan\"
action = \"block\"
from = \"table:bad\"

[[forwards]]
name = \"web\"
proto = \"tcp\"
port = 8443
to = \"192.168.1.11\"

[[vhosts]]
name = \"blog\"
hostnames = [\"blog.example.com\", \"www.example.com\"]
public = true
allow_from = [\"cloudflare\"]
upstream = \"http://192.168.1.11:8080\"

[[vhosts]]
name = \"git\"
hostnames = [\"git.example.org\"]
public = true
cert = \"/etc/ssl/origin.pem\"
key = \"/etc/ssl/private/origin.key\"
allow_from = [\"cloudflare\"]
upstream = \"http://192.168.1.11:3000\"
"
    );
    let r = router(&text);
    let g = render(&r, &SecretSource::Placeholder).unwrap();
    let pf = &g.get("/etc/pf.conf").unwrap().content;
    assert!(pf.contains("table <cloudflare> const { 173.245.48.0/20"), "{pf}");
    assert!(pf.contains(
        "pass in quick on $wan proto tcp from <cloudflare> to ($wan) port { http https } label \"wan:vhosts\""
    ));
    // a wan rule blocks ahead of every way in
    let block = pf.find("block drop in quick on $wan from <t_bad> to any label \"rule:2\"").expect("wan rule");
    assert!(block < pf.find("label \"fwd:web\"").unwrap() && block < pf.find("wan:vhosts").unwrap());
    // an `all` rule on every network
    assert_eq!(pf.matches("proto tcp from any to 192.168.1.11 port 8006 label \"rule:1\"").count(), 2, "{pf}");

    let nginx = &g.get("/etc/nginx/nginx.conf").unwrap().content;
    assert!(nginx.contains("server_name blog.example.com www.example.com;"), "{nginx}");
    assert!(nginx.contains("ssl_certificate /etc/ssl/blog.example.com.fullchain.pem;"));
    assert!(
        nginx.contains("ssl_certificate /etc/ssl/origin.pem;") && nginx.contains("set_real_ip_from 173.245.48.0/20;")
    );
    assert!(nginx.contains("\t\tlisten 443 ssl;\n\t\tlisten [::]:443 ssl;") && nginx.contains("alias /acme/;"));
    let acme = &g.get("/etc/acme-client.conf").unwrap().content;
    assert!(acme.contains("domain blog.example.com {\n\talternative names { www.example.com }"), "{acme}");
    assert!(!acme.contains("git.example.org"), "own certificate: no acme");
    // inside, the public names are the router (split horizon)
    let z = &g.get("/etc/octopus/dns/zones/www.example.com.zone").unwrap().content;
    assert!(z.lines().any(|l| l.split_whitespace().collect::<Vec<_>>() == ["@", "IN", "A", "192.168.1.1"]), "{z}");

    let rows = crate::policy::rows(&r);
    let all = rows.iter().find(|x| x.r#ref == Some(("rules", 0))).unwrap();
    assert_eq!((all.source.as_str(), all.action), ("internal ranges", "allow"));
    let wan = rows.iter().find(|x| x.r#ref == Some(("rules", 1))).unwrap();
    assert_eq!((wan.section, wan.source.as_str(), wan.action), ("in", "table bad", "deny"));
    let fwd = rows.iter().find(|x| x.r#ref == Some(("forwards", 0))).unwrap();
    assert_eq!((fwd.action, fwd.src.as_str(), fwd.dst.as_str()), ("nat", "internet", "host:pc"));
    assert!(rows.iter().any(|x| x.labels == ["wan:vhosts"]));

    let errors = |t: &str| {
        let r = Router::resolve(parse(t).unwrap(), &BTreeMap::new()).unwrap();
        check(&r, None).errors().map(|e| e.msg.clone()).collect::<Vec<_>>()
    };
    let site =
        |extra: &str| format!("{BRIDGED}\n[[vhosts]]\nname = \"x\"\nupstream = \"http://192.168.1.11:80\"\n{extra}\n");
    assert!(errors(&site("hostnames = [\"a.example.com\"]")).iter().any(|m| m.contains("need public")));
    assert!(errors(&site("public = true")).iter().any(|m| m.contains("public needs hostnames")));
    assert!(
        errors(&site("hostnames = [\"a.example.com\"]\npublic = true\ncert = \"/x.pem\""))
            .iter()
            .any(|m| m.contains("go together"))
    );
    let pass_in = format!("{BRIDGED}\n[[rules]]\nnetwork = \"wan\"\naction = \"pass\"\n");
    assert!(errors(&pass_in).iter().any(|m| m.contains("make it a forward")));
}

const WIFI: &str = r#"
[[networks]]
name = "guest"
bridge = ["fast", "vast"]
vlan = 30
address = "10.60.0.1/24"
kind = "guest"
dhcp = { range = ["10.60.0.10", "10.60.0.200"] }

[[hosts]]
name = "ap-hall"
network = "lan"
ip = "192.168.1.5"
mac = "02:00:00:00:00:05"

[wifi]
country = "CZ"

[[wifi.networks]]
ssid = "home"
network = "lan"
password = "secret:wifi_home"

[[wifi.networks]]
ssid = "guests 'n friends"
network = "guest"
password = "secret:wifi_guest"
bands = ["5g"]

[[wifi.aps]]
name = "hall"
host = "ap-hall"
channel_5g = "36"
"#;

#[test]
fn guest_vlan_on_the_bridge_and_access_points() {
    let text = format!("{BRIDGED}{WIFI}");
    let r = router(&text);
    let s = Secrets::parse("u = \"x\"\np = \"y\"\nwifi_home = \"correct horse\"\nwifi_guest = \"it is the guests\"")
        .unwrap();
    let g = render(&r, &SecretSource::Real(&s)).unwrap();
    // one veb, two vports: lan untagged, guest in VLAN 30, the ports carry it tagged
    let veb = &g.get("/etc/hostname.veb0").unwrap().content;
    assert!(veb.contains("add vport0") && veb.contains("add vport1") && veb.contains("untagged vport1 30"), "{veb}");
    assert!(veb.contains("tagged igc1 +30") && veb.contains("tagged igc3 +30"), "{veb}");
    assert_eq!(veb.matches("add igc1").count(), 1, "{veb}");
    assert!(g.get("/etc/hostname.vport1").unwrap().content.contains("inet 10.60.0.1 255.255.255.0"));
    // guests: the internet and router services, no vhosts, nothing internal
    let pf = &g.get("/etc/pf.conf").unwrap().content;
    assert!(pf.contains("pass in quick on $if_guest to ! <internal> label \"guest:internet\""), "{pf}");
    assert!(pf.contains("block in log quick on $if_guest to self label \"guest:self\""));
    assert!(pf.contains("block in log quick on $if_guest proto tcp to self port $mgmt_ports"));

    let ap = g.get("/etc/octopus/ap/hall.sh").unwrap();
    assert!(ap.secret && ap.mode == 0o600);
    let sh = &ap.content;
    assert!(sh.starts_with("#!/bin/sh\n# octopus-ap name=hall address=192.168.1.5\n"), "{sh}");
    assert!(sh.contains("list ports '$PORT.30'") && sh.contains("config interface 'v30'"), "{sh}");
    // the port keeps the board's MAC (else a random one on ipq807x, and a new lease)
    assert!(sh.contains("MAC=$(jsonfilter -i /etc/board.json -e '@.network.lan.macaddr'"), "{sh}");
    assert!(sh.contains("\tlist ports '$PORT'\n$BRMAC\n"), "{sh}");
    assert!(sh.contains("[ -n \"$MAC\" ] && printf \"config device\\n\\toption name '%s'\\n\\toption macaddr '%s'\\n\\n\" \"$PORT\" \"$MAC\" >> /etc/config/network"), "{sh}");
    assert!(sh.contains("add \"$r\" lan 'home' sae-mixed 'correct horse' 0 0"), "{sh}");
    // guests isolated, quoted, on 5 GHz only
    assert!(sh.contains("add \"$r\" v30 'guests '\\''n friends' sae-mixed 'it is the guests' 1 0"), "{sh}");
    let g2 = sh.split("\t2g)").nth(1).unwrap().split(";;").next().unwrap();
    assert!(!g2.contains("guests"), "{g2}");
    assert!(sh.contains("uci set wireless.$r.channel='36'") && sh.contains("country='CZ'"));
    // the script is sh
    let out = std::process::Command::new("sh").arg("-n").arg("-c").arg(sh).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let errors = |t: &str| {
        let r = Router::resolve(parse(t).unwrap(), &BTreeMap::new()).unwrap();
        check(&r, None).errors().map(|e| e.msg.clone()).collect::<Vec<_>>()
    };
    // an SSID onto a network the AP can't reach tagged
    let untagged = text.replace("ssid = \"home\"\nnetwork = \"lan\"", "ssid = \"home\"\nnetwork = \"slow\"");
    assert!(errors(&untagged).iter().any(|m| m.contains("has no vlan")), "{:?}", errors(&untagged));
    let nopw = text.replace("password = \"secret:wifi_home\"\n", "");
    assert!(errors(&nopw).iter().any(|m| m.contains("needs password")));
    let plain = text.replace("\"secret:wifi_home\"", "\"hunter2hunter2\"");
    assert!(errors(&plain).iter().any(|m| m.contains("secret:<key>")));
    // a VLAN on a single port of the bridge is refused, with the way to do it
    let wrong = format!(
        "{BRIDGED}\n[[networks]]\nname = \"g2\"\ninterface = \"fast\"\nvlan = 40\naddress = \"10.70.0.1/24\"\nkind = \"guest\"\n"
    );
    assert!(errors(&wrong).iter().any(|m| m.contains("put the VLAN on the bridge")), "{:?}", errors(&wrong));
    // a short passphrase fails at render time (real secrets)
    let s2 = Secrets::parse("u = \"x\"\np = \"y\"\nwifi_home = \"short\"\nwifi_guest = \"it is the guests\"").unwrap();
    assert!(render(&r, &SecretSource::Real(&s2)).unwrap_err().contains("8 to 63"));
}

/// The owner's tiers: every house port one bridge; CD by MAC, DD for the
/// other cables, Wi-Fi and guests by VLAN; the policy is the rules.
pub(crate) const TIERS: &str = r#"
[system]
hostname = "rt"
domain = "home.arpa"
openbsd_release = "7.9"
timezone = "Europe/Prague"

[interfaces.wan]
mac = "00:00:00:00:00:01"
name = "igc0"
[interfaces.fast]
mac = "00:00:00:00:00:02"
name = "igc1"
[interfaces.slow]
mac = "00:00:00:00:00:03"
name = "igc2"
[interfaces.vast]
mac = "00:00:00:00:00:04"
name = "igc3"

[wan]
interface = "wan"
dhcp = true

[lan]
ports = ["fast", "slow", "vast"]

[[tiers]]
name = "cd"
address = "192.168.1.1/24"
macs = ["bc:24:11", "02:00:5e:10:00:0a"]
dhcp = { range = ["192.168.1.100", "192.168.1.199"] }

[[tiers]]
name = "dd"
address = "192.168.2.1/24"
wired = true
dhcp = { range = ["192.168.2.10", "192.168.2.250"] }

[[tiers]]
name = "wifi"
address = "192.168.3.1/24"
vlan = 3
dhcp = { range = ["192.168.3.10", "192.168.3.250"] }

[[tiers]]
name = "guest"
address = "192.168.4.1/23"
vlan = 4
dhcp = { range = ["192.168.4.10", "192.168.5.250"] }

[[hosts]]
name = "nas"
ip = "192.168.1.20"
mac = "02:00:00:00:00:20"

[[rules]]
network = "all"
action = "pass"
from = "net:guest"
to = "self"
proto = "tcp/udp"
port = "53,123"
description = "guests: the router's DNS and NTP"

[[rules]]
network = "all"
action = "pass"
from = "net:guest"
to = "self"
proto = "icmp"
description = "guests: ping the router"

[[rules]]
network = "all"
action = "block"
from = "net:guest"
to = "internal"
description = "guests: nothing else inside"

[[rules]]
network = "all"
action = "pass"
from = "internal"
to = "self"
proto = "tcp"
port = "22,8443"
description = "managing the router"
"#;

#[test]
fn tiers_on_the_house_ports() {
    let r = router(TIERS);
    let g = render(&r, &SecretSource::Placeholder).unwrap();
    // one bridge of every house port; CD and DD untagged on one vport, Wi-Fi and guests their VLANs
    let veb = &g.get("/etc/hostname.veb0").unwrap().content;
    for l in [
        "add igc1",
        "add igc2",
        "add igc3",
        "add vport0",
        "untagged vport1 3",
        "untagged vport2 4",
        "tagged igc2 +3",
        "tagged igc3 +4",
    ] {
        assert!(veb.contains(l), "{l}: {veb}");
    }
    assert_eq!(veb.matches("add vport0").count(), 1);
    let vport0 = &g.get("/etc/hostname.vport0").unwrap().content;
    assert!(
        vport0.contains("inet 192.168.1.1 255.255.255.0") && vport0.contains("inet alias 192.168.2.1 255.255.255.0"),
        "{vport0}"
    );

    let pf = &g.get("/etc/pf.conf").unwrap().content;
    // DNS to the tier's own router address
    assert!(
        pf.contains(
            "match in on $if_dd inet proto { tcp udp } from 192.168.2.0/24 to ! self port domain rdr-to 192.168.2.1"
        ),
        "{pf}"
    );
    // rules once per interface, before the open policy; the guard after them
    let guest = pf.find("# ---- guest").unwrap();
    let at = |needle: &str| pf[guest..].find(needle).map(|i| i + guest).unwrap_or_else(|| panic!("{needle}: {pf}"));
    assert!(
        at("from 192.168.4.0/23 to self port { 53 123 } label \"rule:1\"")
            < at("from 192.168.4.0/23 to <internal> label \"rule:3\"")
    );
    assert!(
        at("label \"rule:4\"") < at("label \"guest:guard\"")
            && at("label \"guest:guard\"") < at("label \"guest:open\"")
    );
    assert_eq!(pf.matches("label \"rule:4\"").count(), 3, "once on each interface (vport0 carries two tiers)");
    assert!(pf.contains("pass in quick on $if_cd from 192.168.1.0/24 label \"cd:open\""));
    assert!(pf.contains("pass in quick on $if_dd proto udp from port bootpc to port bootps label \"dd:dhcp\""));

    // Kea: CD by MAC class, DD for the rest, on one shared network; Wi-Fi and guests alone
    let k = kea(&g);
    let classes = k["Dhcp4"]["client-classes"].as_array().unwrap();
    assert_eq!(classes[0]["test"], "substring(pkt4.mac,0,3) == 0xbc2411 or substring(pkt4.mac,0,6) == 0x02005e10000a");
    assert_eq!(classes[1]["test"], "not member('tier_cd')");
    let sh = &k["Dhcp4"]["shared-networks"][0];
    assert_eq!(sh["interface"], "vport0");
    assert_eq!(sh["subnet4"][0]["pools"][0]["client-class"], "tier_cd");
    assert_eq!(sh["subnet4"][1]["pools"][0]["client-class"], "tier_dd_others");
    assert_eq!(sh["subnet4"][0]["reservations"][0]["ip-address"], "192.168.1.20", "the host's tier from its address");
    let alone: Vec<&str> =
        k["Dhcp4"]["subnet4"].as_array().unwrap().iter().map(|s| s["interface"].as_str().unwrap()).collect();
    assert_eq!(alone, ["vport1", "vport2"]);
    assert!(
        g.services.iter().any(|s| s.name == "octopus_kea" && s.enabled)
            && !g.services.iter().any(|s| s.name == "dhcpd" && s.enabled)
    );

    // the guard: CD addresses for listed devices only
    let gd: serde_json::Value = serde_json::from_str(&g.get("/etc/octopus/guard.json").unwrap().content).unwrap();
    assert_eq!(gd["restricted"][0]["tier"], "cd");
    assert_eq!(gd["restricted"][0]["reserved"]["192.168.1.20"], "02:00:00:00:00:20");

    let errors = |t: &str| {
        let r = Router::resolve(parse(t).unwrap(), &BTreeMap::new()).unwrap();
        check(&r, None).errors().map(|e| e.msg.clone()).collect::<Vec<_>>()
    };
    // without a rule to the router's management nobody could manage it
    let locked = TIERS.replace("port = \"22,8443\"", "port = \"80\"");
    assert!(errors(&locked).iter().any(|m| m.contains("nobody can manage")), "{:?}", errors(&locked));
    let stray = format!("{TIERS}\n[[hosts]]\nname = \"far\"\nip = \"10.9.9.9\"\n");
    assert!(errors(&stray).iter().any(|m| m.contains("in no tier's range")));
    let two = TIERS.replace("macs = [\"bc:24:11\", \"02:00:5e:10:00:0a\"]", "wired = true");
    assert!(errors(&two).iter().any(|m| m.contains("one fallback")));
}

#[test]
fn analyzer_off_by_default() {
    let rule = "\n[[analyzer.rules]]\nname = \"ssh\"\nnetwork = \"slow\"\nfcap = \"proto tcp and dst port 22\"\nregex = \"(?i)ssh-\"\n";
    let on = |g: &crate::Generation| g.services.iter().any(|s| s.name == "octopus_analyzer" && s.enabled);
    let off = render(&router(&format!("{BRIDGED}{rule}")), &SecretSource::Placeholder).unwrap();
    assert!(!on(&off) && off.get("/etc/octopus/analyzer.toml").is_none());
    let text = format!("{BRIDGED}\n[analyzer]\nenabled = true\n{rule}");
    let g = render(&router(&text), &SecretSource::Placeholder).unwrap();
    assert!(on(&g));
    let conf = &g.get("/etc/octopus/analyzer.toml").unwrap().content;
    assert!(conf.contains("name = \"ssh\"") && conf.contains("filter = \"(tcp and dst port 22)\""), "{conf}");
}

#[test]
fn ipv6_slots_stay_put() {
    // moving a network in the file must not move its prefix (slots are fixed)
    let slow = "[[networks]]\nname = \"slow\"\ninterface = \"slow\"\naddress = \"172.16.2.1/24\"\nkind = \"lan\"\nipv6_slot = 3\n";
    assert!(BRIDGED.contains(slow));
    let moved = BRIDGED
        .replace(slow, "")
        .replace("[[networks]]\nname = \"lan\"", &format!("{slow}\n[[networks]]\nname = \"lan\"\nipv6_slot = 0"));
    let a = render(&router(BRIDGED), &SecretSource::Placeholder).unwrap();
    let b = render(&router(&moved), &SecretSource::Placeholder).unwrap();
    let slot_of = |g: &crate::Generation, ifname: &str| {
        g.get("/etc/dhcp6leased.conf").unwrap().content.lines().position(|l| l.trim_start().starts_with(ifname))
    };
    assert_eq!(slot_of(&a, "igc2"), slot_of(&b, "igc2"));
    assert_eq!(slot_of(&a, "vport0"), slot_of(&b, "vport0"));
}

#[test]
fn old_generations_stay_readable() {
    // a manifest written by an older version must still load (rollback)
    let s: crate::Subsystem = serde_json::from_str("\"relayd\"").unwrap();
    assert_eq!(s, crate::Subsystem::Proxy);
    let s: crate::Subsystem = serde_json::from_str("\"something-new\"").unwrap();
    assert_eq!(s, crate::Subsystem::Other);
}
