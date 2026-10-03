//! /etc/octopus/ap/<name>.sh: each OpenWrt access point's settings as a
//! script `octopus ap push` runs on it over SSH. The access point becomes a
//! plain bridge: its own network untagged (address by DHCP, a reservation),
//! every other network as a VLAN on its port, no DHCP server, DNS or
//! firewall of its own; the radios carry the SSIDs onto those networks.
//! Mode 0600: the passphrases are in it.

use std::fmt::Write as _;

use octopus_config::Router;
use octopus_config::schema::{AccessPoint, Band, Wifi, WifiSecurity};

use crate::{Generation, SecretSource, Subsystem, header};

pub const AP_DIR: &str = "/etc/octopus/ap";

/// Single-quoted for sh.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub(crate) fn render(r: &Router, secrets: &SecretSource, g: &mut Generation) -> Result<(), String> {
    let Some(w) = &r.cfg.wifi else { return Ok(()) };
    for ap in &w.aps {
        let s = script(r, w, ap, secrets)?;
        let f = g.file(format!("{AP_DIR}/{}.sh", ap.name), s, Subsystem::Ap);
        f.mode = 0o600;
        f.secret = true;
    }
    Ok(())
}

fn passphrase(secrets: &SecretSource, reference: &str) -> Result<String, String> {
    let p = secrets.get(reference)?;
    let hex = p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex && (p.len() < 8 || p.len() > 63 || !p.bytes().all(|b| (0x20..0x7f).contains(&b))) {
        return Err(format!("{reference}: a Wi-Fi passphrase is 8 to 63 printable characters"));
    }
    Ok(p)
}

fn script(r: &Router, w: &Wifi, ap: &AccessPoint, secrets: &SecretSource) -> Result<String, String> {
    let c = &r.cfg;
    let host =
        c.hosts.iter().find(|h| h.name == ap.host).ok_or(format!("access point {}: no host {}", ap.name, ap.host))?;
    let home = r
        .host_net(host)
        .map(|n| n.name.clone())
        .ok_or(format!("access point {}: {} is in no tier", ap.name, host.ip))?;
    let nets: Vec<_> = w.networks.iter().filter(|n| n.on(&ap.name)).collect();
    // the VLANs this AP carries, and the OpenWrt interface each SSID joins
    let mut vlans: Vec<u16> = vec![];
    let mut ifaces = vec![];
    for n in &nets {
        let net = r.net(&n.network).map(|x| x.1).ok_or(format!("wifi {:?}: unknown network", n.ssid))?;
        let iface = if net.name == home {
            "lan".to_string()
        } else {
            let v = net.vlan.ok_or(format!("wifi {:?}: {} has no vlan", n.ssid, net.name))?;
            if !vlans.contains(&v) {
                vlans.push(v);
            }
            format!("v{v}")
        };
        let (enc, key) = match n.security {
            WifiSecurity::Open => ("none", String::new()),
            sec => {
                let p = passphrase(secrets, n.password.as_deref().unwrap_or(""))?;
                let enc = match sec {
                    WifiSecurity::Wpa2Wpa3 => "sae-mixed",
                    WifiSecurity::Wpa3 => "sae",
                    _ => "psk2",
                };
                (enc, p)
            }
        };
        ifaces.push((n, iface, enc, key, n.isolate.unwrap_or(r.is_guest(&net.name))));
    }
    vlans.sort();

    let mut s = String::from("#!/bin/sh\n");
    let _ = writeln!(s, "# octopus-ap name={} address={}", ap.name, host.ip);
    s += &header("#", &["run on the access point by `octopus ap push` (over SSH, with the router's key)"]);
    s += "set -e\n";
    // SHA (of this script) comes first from `octopus ap push`; FORCE=1 pushes anyway
    s += "if [ -z \"$FORCE\" ] && [ -n \"$SHA\" ] && [ \"$(cat /etc/octopus-ap.sha 2>/dev/null)\" = \"$SHA\" ]; then echo unchanged; exit 0; fi\n\n";
    s += "# the uplink: the board's lan port, and the MAC the board gives it\n";
    s += "PORT=$(jsonfilter -i /etc/board.json -e '@.network.lan.ports[0]' 2>/dev/null || true)\n";
    s += "[ -n \"$PORT\" ] || PORT=$(jsonfilter -i /etc/board.json -e '@.network.lan.device' 2>/dev/null || true)\n";
    s += "[ -n \"$PORT\" ] || PORT=eth0\n";
    s += "MAC=$(jsonfilter -i /etc/board.json -e '@.network.lan.macaddr' 2>/dev/null || true)\n";
    s += "BRMAC=; [ -n \"$MAC\" ] && BRMAC=\"\toption macaddr '$MAC'\"\n\n";

    s += "cat > /etc/config/network <<EOF\n";
    s += "config interface 'loopback'\n\toption device 'lo'\n\toption proto 'static'\n\toption ipaddr '127.0.0.1'\n\toption netmask '255.0.0.0'\n\n";
    // the bridge's MAC pinned too: it takes its first port's only when it is made
    s += "config device\n\toption name 'br-lan'\n\toption type 'bridge'\n\tlist ports '$PORT'\n$BRMAC\n\n";
    let _ = writeln!(
        s,
        "config interface 'lan'\n\toption device 'br-lan'\n\toption proto 'dhcp'\n\toption hostname {}\n",
        sq(&ap.name)
    );
    for v in &vlans {
        let _ =
            writeln!(s, "config device\n\toption name 'br-v{v}'\n\toption type 'bridge'\n\tlist ports '$PORT.{v}'\n");
        let _ = writeln!(s, "config interface 'v{v}'\n\toption device 'br-v{v}'\n\toption proto 'none'\n");
    }
    s += "EOF\n";
    // without it the port keeps the kernel's MAC, random on boards whose
    // factory MAC OpenWrt sets from its calibration data (ipq807x): a new
    // lease, and the router loses the AP
    s += "[ -n \"$MAC\" ] && printf \"config device\\n\\toption name '%s'\\n\\toption macaddr '%s'\\n\\n\" \"$PORT\" \"$MAC\" >> /etc/config/network\n\n";

    s += "# a plain access point: the router does DHCP, DNS and filtering\n";
    s += "for svc in dnsmasq odhcpd firewall; do\n\t[ -x /etc/init.d/$svc ] && { /etc/init.d/$svc disable; /etc/init.d/$svc stop; } >/dev/null 2>&1 || true\ndone\n";
    s += "uci -q get system.@system[0] >/dev/null || { touch /etc/config/system; uci add system system >/dev/null; }\n";
    let _ = writeln!(s, "uci set system.@system[0].hostname={}", sq(&ap.name));
    s += "\n# radios as the hardware has them, then ours\n";
    s += "rm -f /etc/config/wireless\nwifi config >/dev/null 2>&1 || true\n";
    s += "while uci -q delete wireless.@wifi-iface[0]; do :; done\n";
    s += "add() { # radio interface ssid encryption key isolate hidden\n";
    s += "\ti=$(uci add wireless wifi-iface)\n";
    s += "\tuci set wireless.$i.device=\"$1\"; uci set wireless.$i.mode=ap; uci set wireless.$i.network=\"$2\"\n";
    s += "\tuci set wireless.$i.ssid=\"$3\"; uci set wireless.$i.encryption=\"$4\"\n";
    s += "\t[ -n \"$5\" ] && uci set wireless.$i.key=\"$5\"\n";
    s += "\tuci set wireless.$i.isolate=\"$6\"; uci set wireless.$i.hidden=\"$7\"\n}\n";
    s += "for r in $(uci -q show wireless | sed -n 's/^wireless\\.\\([^.=]*\\)=wifi-device$/\\1/p'); do\n";
    s += "\tband=$(uci -q get wireless.$r.band || true)\n";
    let country = w.country(&c.system.timezone).ok_or("wifi: no country")?;
    let _ = writeln!(s, "\tuci set wireless.$r.country={}", sq(&country));
    s += "\tuci set wireless.$r.disabled=0\n\tcase \"$band\" in\n";
    for band in [Band::G2, Band::G5] {
        let ch = if band == Band::G2 { &ap.channel_2g } else { &ap.channel_5g };
        let _ = writeln!(s, "\t{})\n\t\tuci set wireless.$r.channel={}", band.name(), sq(ch));
        for (n, iface, enc, key, iso) in ifaces.iter().filter(|x| x.0.bands.contains(&band)) {
            let _ = writeln!(
                s,
                "\t\tadd \"$r\" {iface} {} {enc} {} {} {}",
                sq(&n.ssid),
                sq(key),
                u8::from(*iso),
                u8::from(n.hidden)
            );
        }
        s += "\t\t;;\n";
    }
    s += "\t*) uci set wireless.$r.disabled=1 ;;\n\tesac\ndone\n\n";
    s += "uci commit\n[ -n \"$SHA\" ] && echo \"$SHA\" > /etc/octopus-ap.sha\n";
    s += "# after we've answered: the new network may move this very connection\n";
    s += "( set +e; sleep 1; /etc/init.d/system reload; /etc/init.d/network reload; sleep 2; wifi reload ) >/dev/null 2>&1 </dev/null &\n";
    s += "echo applied\n";
    Ok(s)
}
