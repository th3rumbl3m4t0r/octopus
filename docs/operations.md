# Operating Octopus

## Build VM

OpenBSD 7.9 amd64, the router's release (design R9: rebuild per release,
never copy binaries across releases).

```sh
pkg_add rust git nginx
git clone git@192.168.1.31:/srv/git/octopus.git && cd octopus
deploy/build-hickory.sh          # hickory-dns 0.26.3 -> /usr/local/sbin
cargo build --release
```

Users the validators need (`install.site` creates them on the router):
`_octodns` (860) and `_octoweb` (861).

## The site set

`SITEDIR` holds `router.toml`, and optionally `secrets.toml`,
`authorized_keys` (root's SSH keys) and `web-users`.

```sh
deploy/mksite.sh SITEDIR OUTDIR    # check, build, validate, then OUTDIR/site79.tgz
```

The set contains the binaries, rc.d scripts, doas rules, nginx and its
dependencies (signed packages), the configuration, and `install.site`. With
`secrets.toml` in SITEDIR it contains secrets: keep it on removable media.

`install.site` creates the users and directories, a self-signed web UI
certificate (replaced by a services-root leaf once `octopus pki` is set up),
an initial web login (`/root/octopus-web-password`), the doas rules, the
boot hook (`octopus boot` in rc.local), daily certificate renewal, and the
first-boot apply (rc.firsttime).

## Install (design 8)

Build a site set with `deploy/mksite.sh`, an install stick with
`deploy/mkinstall-img.sh` and `deploy/install.conf.example`, and boot the
router from it; `rc.firsttime` applies router.toml.

1. Fill `deploy/install.conf.example` → `auto_install.conf` (root password
   hash from `encrypt -b a`, SSH key). The partitioning question is left
   out so the installer picks MBR or GPT by how the stick was booted.
2. `deploy/mkinstall-img.sh install79.img site79.tgz auto_install.conf
   OUT.img` on the build VM: OpenBSD's installer image (signify-verified)
   with the site set added and the answers in the ramdisk, console on com0.
   `dd` it to a stick.
3. Boot the stick: it erases sd0 (the box's disk) and installs without
   asking. First boot applies `router.toml` from rc.firsttime
   (`logger -t octopus-firstboot`).
4. `octopus status`, `octopus generations`; generation 0 is the installer's
   files, generation 1 the configuration.

(NICs: the pfSense box has 4× Intel I225-V, `igc(4)`; CPU J4125 has AES-NI.)

## Daily operations

```sh
vi /etc/octopus/router.toml     # or the web UI's config page
octopus check && octopus diff
octopus apply                   # pending; watchdog armed
octopus confirm                 # within 60 s
```

* Something wrong after apply: do nothing; it rolls back at the deadline.
  Or `octopus rollback` now.
* Lost the session: the watchdog doesn't need it. After a reboot an
  unconfirmed generation is reverted by `octopus boot`.
* Applying a change to `[wireguard]` over the WireGuard tunnel reconnects
  `wg0` and drops your session; `octopus apply` notices (SSH_CONNECTION) and
  gives 300 s to come back and confirm. Pass `--timeout` for more.
* Every file octopus renders is compared against the live one on each
  apply, and `/etc/hostname.*` files it doesn't render are removed: the
  router is exactly router.toml, hand edits don't survive (design R3). The
  pre-octopus state is generation 0.
* Older configuration: `octopus generations`, `octopus rollback N`
  (also commit-confirmed; `--no-confirm` to skip).
* `/etc/octopus/router.toml` always matches the live generation (rollbacks
  restore it too). Copy it back into git after changes made in the web UI.
* Log: `grep octopus /var/log/daemon`.

## Services root (design 14)

On an offline machine (or the build VM, then move the key off it):

```sh
octopus pki init -c router.toml -o /secure/pki
```

Copy `root.crt`, `intermediate.crt`, `intermediate.key` (0600) to
`/etc/octopus/pki/` on the router; keep `root.key` offline; install
`root.crt` on the owner's devices (Firefox has its own store; Android apps
ignore user CAs by default). Both CAs are constrained to the internal zone
and the internal ranges, so leaves for any other name fail verification.

`octopus pki renew` (daily from `/etc/daily.local`) issues the web UI's and
each vhost's leaf (90 days; renewed 30 days before expiry or when names
change) and reloads nginx / restarts the web UI. `octopus pki status` lists
them. `octopus apply` issues missing leaves before validating.

A name the root doesn't cover (an address range added after `pki init`) is
left out of the leaf and logged: a leaf outside the constraints fails
verification outright, and browsers don't let you click through that
(Firefox: `SEC_ERROR_CERT_NOT_IN_NAME_SPACE`). Either make a wider root or,
for a lab, set `[web] certificate = "self-signed"` and the web UI keeps the
self-signed certificate from the install.

## Logs over TLS to a log host

The log host's syslog-ng wants a client certificate from its own CA (`tls-ca.sh`);
the certificate's CN is the source name there, so the router's is `router`:

```sh
octopus pki csr router -o /etc/octopus/syslog      # key stays on the router; prints the request
# on the log host: tls-ca.sh sign router < router.csr > router.crt
# copy router.crt and the log host's /etc/syslog-ng/tls/ca.crt to /etc/octopus/syslog/
```

With `[logging] remote = ["tls://192.168.1.21:514"]` and the three `tls_*`
paths, syslogd sends everything there (RFC 5425 framing), including pf's
log as `filterlog` lines (`pf = true`). pfSense's plaintext UDP stops.

## Servers' proxy and the interception root

```sh
octopus pki intercept-init     # /etc/ssl/octopus-intercept.crt, key in /etc/ssl/private (0600)
```

Install the certificate on the servers only (`AWS_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, Java keystores: design 13).
Never on personal devices. `octopus-proxy` reads the key at start and hands
it to its signer process; the process that talks to servers and origins
never has it. Leaves last 7 days and are minted per allowed name.

## Analyzer and flows

`[analyzer]` with `enabled = true` runs the standing rules
(`[[analyzer.rules]]`): matches in `/var/log/octopus-analyzer` (JSON), pcaps in
`/var/octopus/pcap`. A `block` rule's sources sit in `<lab_block>` for
`block_for` seconds (`pfctl -t lab_block -T show`). With
`pflow = "127.0.0.1:2055"`, `/var/log/octopus-flows` has every finished
flow with the name the client looked up before it. The web UI's flows,
proxy and analyzer pages read those logs.

The analyzer page's ad hoc window captures on demand, with the standing
rules on or off: an interface, an FCAP filter and a PCRE on the payload, for
up to 30 s and 500 packets, one capture at a time; the matched packets are
listed with a hex view and a "download pcap" button.
`octopus-web` stages the request in `/var/octopus/staged/capture.json` and
runs `octopus-analyzer --oneshot` through doas; it opens and locks bpf as
root, then captures as `_octoflow` with `pledge("stdio")`. The packets come
back as JSON with a pcap to download; nothing is written on the router.

## Editing from the web UI

Every page edits router.toml with comments and layout kept. Edits collect in
the browser's "unapplied changes" window at the top of every page and go
through the same check, diff and apply (with the confirm window) as the
config page; until then nothing on the router changes. They are dropped if
router.toml changes underneath them (an apply from elsewhere, a rollback).

* **firewall**: a rule is source, destination and allow / deny / nat, with
  aliases for internal ranges, the internet, the router, networks, hosts and
  tables, or an address. Clicking a row starts a new rule from it; rows from
  router.toml (marked ✎) are edited or deleted in place. Where it lands in
  router.toml is described in router-toml.md ([[rules]]).
* **dns**: views, the sinkhole, and overrides (a list above the query log;
  clicking a name in the log or in top names starts an override for it).
* **wifi**: SSIDs (each onto a router network, passphrases write-only) and
  the access points, with their last push and "push now".
* **dhcp**: reservations (`[[hosts]]` with a mac); a lease's "reserve" fills
  one in.
* **reverse proxy**: `[[vhosts]]`, internal and public sites.
* **analyzer**: ad hoc FCAP + PCRE captures in one window (matched packets,
  hex view, download pcap), and the standing rules with their on/off switch
  (off by default).
* **settings**: every section of router.toml as forms, built from the
  schema (the Rust types: their doc comments are the help texts, their
  defaults the placeholders; `octopus-web --schema` prints it). Lists can be
  reordered, which matters for rules (first match wins).

Secrets stay out of the web UI: fields such as `pppoe.password` hold
`secret:<key>` references, and the values live in secrets.toml on the router.

The status page graphs each interface's traffic from `netstat -ibn`, kept
in octopus-web's memory: an hour at 5 s and a day at 1 min, started over
when it restarts. The firewall page's overview lists the policy as rules
(source, destination, service, action) built from router.toml, with the
counters of the pf rules behind each.

## Public sites (reverse proxy on the WAN)

A `[[vhosts]]` entry with `public = true` and `hostnames` outside the
internal zone is served on the internet: pf opens tcp 80 and 443 on the WAN
(to `allow_from`, or everyone), nginx answers on every address, and inside
the names resolve to the router. Certificates come from Let's Encrypt through
acme-client (http-01 on port 80; a self-signed placeholder until the first
one arrives: `octopus confirm` starts acme-client, `octopus pki renew` renews
daily, both log to /var/log/daemon), or from `cert`/`key` files placed on the
router (a Cloudflare origin certificate, say). With Cloudflare in front:
proxied names, SSL mode Full (strict), `allow_from = ["cloudflare"]`.

## Tiers, DHCP and the guard

DHCP is Kea (`octopus_kea`, the kea package in the site set; pfSense uses it
too): `/etc/kea/kea-dhcp4.conf`, leases in `/var/lib/kea/kea-leases4.csv`,
logs in /var/log/daemon. On the house ports the tiers without a VLAN share
one interface, and Kea chooses by client class: a tier's `macs`, else the
`wired` tier. Reservations (`[[hosts]]` with a mac) win.

`octopus guard` (`octopus_guard`) reads the ARP table every 5 s. A device
on an address of a tier with `macs` that isn't listed (MAC, prefix, or a
reservation of that address) gets `rule block out on <vport> src <mac>` on
the bridge: it can't reach the router any more, wherever it is plugged in.
`octopus guard status` lists them; `octopus guard release MAC` or the
firewall page's "blocked devices" lifts it. The blocks survive restarts and
are put back if the bridge is recreated.

Before switching gw to tiers: every device that keeps a static CD address
must be listed (its MAC prefix in `macs`, or a reservation), or the guard
cuts it off. gw.toml lists today's (pfSense's ARP table, 2026-10-02).

## Access points (OpenWrt)

Octopus owns the Wi-Fi and network settings of OpenWrt access points
(`[wifi]` in router-toml.md): it pushes a script to each over SSH, with a
key only the router has, on every apply that changes it. An access point
joins in four steps:

1. **The key.** `install.site` made it; `octopus ap key` prints it (the wifi
   page shows it too).
2. **The image**, on a Linux x86_64 machine, with OpenWrt's Image Builder:

   ```sh
   deploy/ap-image.sh 25.12.5 qualcommax/ipq807x tplink_eap620hd-v1 ap.key.pub
   ```

   Stock OpenWrt for the device plus that key (SSH by key only), lan by DHCP
   instead of 192.168.1.1 (which is the router's), no DHCP server, DNS or
   firewall of its own, no LuCI. Profile names are OpenWrt's
   (firmware-selector.openwrt.org); the EAP620 HD is `tplink_eap620hd-v1`
   (25.12) or `tplink_eap620-hd-v2` / `-v3` (`snapshot`,
   qualcommax/ipq60xx) — check the label, each version has its own image.
   On Rocky Linux the Image Builder needs: `dnf install zstd unzip bzip2
   wget patch ncurses-devel zlib-devel perl-FindBin perl-Data-Dumper
   perl-File-Copy perl-File-Compare perl-Thread-Queue perl-Time-Piece
   perl-IPC-Cmd perl-JSON-PP squashfs-tools`.
3. **Flash** it the way OpenWrt documents for the device. TP-Link's EAP6xx
   with stock firmware: set it up standalone in its web UI, Management →
   SSH on, `ssh -o hostkeyalgorithms=ssh-rsa <ip>`, `cliclientd stopcs`,
   then System → Firmware Update with the `*web-ui-factory.bin` (renamed to
   under 63 characters).
4. **Register** it: a reservation on the dhcp page (its mac, the address it
   should have), then the access point on the wifi page, and apply.

Only OpenWrt access points can be managed this way. OpenWrt covers the
EAP620 HD v1 (and v2/v3 in snapshots), the EAP610 v3 (as `tplink_eap613-v1`,
ramips/mt7621) and the EAP610-Outdoor; not the EAP610 v1/v2 or the EAP110.

The access point's SSH host key is pinned on first contact
(`/etc/octopus/ap.known_hosts`); after reflashing one, delete its line.
`octopus ap status` shows the last push of each.

## Web UI users

`/etc/octopus/web/users`: `name:bcrypt-hash` lines (mode 0640 root:_octoweb).
Make a hash with `octopus-web --hash` (password on stdin) or `encrypt -b a`.
Restart `octopus_web` after editing. Sessions last 12 hours; five failed
logins from one address lock it out for five minutes.

## Testing the web UI before a rollout

`tests/web-ui/run.sh` (Linux, as root, Playwright with Chromium) runs
octopus-web with `examples/lab.toml` in a throwaway mount namespace, with a
stateful stand-in for `octopus` (apply, confirm, rollback, access point
pushes, Wi-Fi passwords), and drives every page in a browser: firewall rules
from a row, edited, deleted and nat; DNS overrides, views and the sinkhole;
DHCP reservations from a lease; Wi-Fi networks with passwords, a guest
network, an access point, apply and push; reverse-proxy sites; ad hoc
captures and analyzer rules; every settings section; the config page's
check, diff, apply and rollback; the unapplied-changes window; layout at
1400 and 760 px; no script errors or CSP violations anywhere. Then the
`tests/web-smoke/lab-*.js` scripts against the lab, where the real octopus
runs.

## Upgrades

| what | how |
|---|---|
| errata | `syspatch`; kernel errata need a reboot |
| nginx | `pkg_add -u nginx` |
| OpenBSD release | upgrade the build VM, rebuild (`cargo build --release`, `deploy/build-hickory.sh`), run the validators against the router's config, build a new site set; `sysupgrade` the router, then `deploy/install-live.sh site80.tgz`, reboot |
| Octopus | build a site set, `deploy/install-live.sh siteXY.tgz` on the router (keeps router.toml, secrets and web users), then `octopus apply` |

## Lab results

On the OpenBSD 7.9 sandbox VM (`examples/lab.toml`), 2026-10-01:

| test | result |
|---|---|
| imported pfSense config and the example: pfctl -nf, dhcpd -n, ntpd -n, sshd -t, hickory-dns --validate, nginx -t | pass |
| apply; failure during apply (a daemon not starting) | previous generation restored automatically |
| apply, no confirm | watchdog rolled back at the deadline |
| apply, reboot while pending | `octopus boot` rolled back |
| rollback to generation 0 | pre-Octopus files, interfaces, services, hostname restored |
| apply from the web UI, confirm from the web UI | generation attributed `web:<user>` |
| sshd and web UI listen on mgmt only | yes |
| client in a lan network (rdomain 1 over pair(4)): DNS to router; DNS to 8.8.8.8 intercepted; DoT blocked; sshd/web UI blocked; lan→mgmt host blocked; ping/NTP | as designed |
| upstream DNS only DoT; wrong TLS name → SERVFAIL; platform verifier finds /etc/ssl/cert.pem | yes |
| octopus-dns: JSON log per query, NXDOMAIN canary, answer IPs in cls_* before the reply | yes |
| octopus-pfhelper: allow-listed tables only, injection attempts rejected | yes |
| queue trees on the VLAN parent load, counters move | yes (full test needs client traffic) |
| WireGuard peer (wg1 in rdomain 1): mgmt policy reaches sshd/web UI; lan policy doesn't | yes |
| vhosts: chain verifies with the services root; unknown names refused; https upstream verified | yes |
| bridge of two ports, one /16, DHCP from two ranges over both ports, a reservation | yes |
| IPv6: ULA on every network, SLAAC clients, DNS/vhosts/ping over v6, sshd and web UI refused over v6 (INV-1) | yes (prefix delegation itself needs a real WAN) |
| DNS views: default client gets `0.0.0.0` for Cloudflare's malware test name, listed client gets the real address; direct 1.1.1.1 intercepted; DoH/DoT to public resolvers blocked | yes |
| syslog over TLS to a receiver that requires a client certificate; `filterlog` lines arrive | yes |
| proxy (server in rdomain 3): allowed host and an SNI CDN fetched; expired, wrong.host, self-signed, untrusted-root refused with the reason; unlisted host refused / 403; no direct egress; without the interception root the server can't connect | yes |
| collector: flows labelled with the looked-up name | yes |
| analyzer: SYN to 2222 blocks its source for `block_for`, then unblocks; `GET /evil` matched by regex and kept in a pcap, `GET /fine` not | yes |
| leaves outside the name constraints | rejected by OpenSSL 3 and LibreSSL |
| web UI pages with live data (jsdom), CSRF/Origin checks, login lockout | pass |
| web UI in Chromium (Playwright): traffic graph from netstat, firewall overview with counters, a DNS override edited and diffed through doas (then discarded), no CSP violations | pass |
| one-shot capture through doas: UDP probes captured on vio0 through the locked BPF filter, PCRE2 lookahead marked in the hex view, pcap downloads; `(a+)+$` hits the match limit and the capture still ends on time; a second capture at once refused; a bad interface name refused | pass |
| `octopus-analyzer --oneshot` captures as `_octoflow`; PCRE2 linked statically (no libpcre2 in `ldd`); `cargo test` on OpenBSD | yes |
| editing through the web UI, applied and confirmed there (`tests/web-smoke/lab-edit.js`): a deny on lan, an `all` allow (on every network in pf), a DNS override (and its subdomains), a public site with its own certificate and one with Let's Encrypt, an analyzer rule with a PCRE, a DHCP reservation, [ntp] | all live as written |
| public sites: both names of a site proxied with its certificate, unknown names refused at the handshake, the acme-client token served on port 80 (nginx chrooted: `/acme/`), the placeholder accepted by acme-client up to Let's Encrypt's order (which refuses example.com) | yes |
| public site, `wan` and `all` rules in gw.toml: pfctl -nf, nginx -t, acme-client -n | pass |
| guest network as VLAN 30 on the lan bridge (veb0: ports tagged 30, vport1 untagged 30): a client tagging VLAN 30 gets a lease, reaches the router's DNS and ping; the router's other addresses, ssh, a lan host are blocked | yes |
| access point script pushed by `octopus ap push` to OpenWrt 25.12.5 (x86 rootfs over SSH, radios stubbed): network with the guest VLAN on the port, radios (country, channels), SSIDs per band, guests isolated; unchanged on a second push, again with --force | yes |
| apply with an unreachable access point: applied and confirmed, the access point marked "NOT updated" | yes |
| wifi page (`tests/web-smoke/lab-wifi.js`): passphrase only to /api/secret, router.toml holds the reference; push now | pass |
| EAP620 HD v1 image from `deploy/ap-image.sh`: key and first-boot settings inside, no LuCI | yes |
| the EAP620 HD v1 flashed from its stock UI (SSH on, `cliclientd stopcs`, the web-ui-factory image), registered as `ap620` in lab.toml, the script pushed by apply: both radios up with the lab SSID, key-only SSH, lan by DHCP; the port and bridge keep the factory MAC (without it the AP took a random one and a new lease) | yes (2026-10-02) |
| tiers (examples/lab.toml): one bridge of the lab ports, CD and DD on one vport (two addresses), Wi-Fi and guests VLAN 3/4; Kea: the listed MAC gets CD, testbox its DD reservation, VLAN clients Wi-Fi and guest addresses | yes |
| tier policy: CD↔DD, Wi-Fi↔everyone, management from CD/DD/Wi-Fi; guests: the router's DNS and ping, not hosts inside (buildvm behind the lab's mgmt port), not ssh or the web UI | yes (a client on the router's own host matches `self` and floating states: tested with interface-bound states and a host outside) |
| guard: a DD device giving itself a CD address is cut off from the router within 5 s (its DD address too), released by `octopus guard release` | yes |
| editing, applying and confirming through the web UI on tiers (`tests/web-smoke/lab-edit.js`) | yes |

Bugs the lab found and that are fixed: the site set packed `.` (would have
made `/` mode 0700 on install), `current_exe()` failing on OpenBSD (no
watchdog), pf syntax order in WireGuard rules, pfhelper aborted by pledge
when opening /dev/null, mygate ignored when any interface uses DHCP,
nginx -t binding addresses that don't exist yet, relayd's TLS inspection
connecting upstream without SNI (replaced by octopus-proxy), an old
generation's manifest failing to load after a subsystem was renamed
(rollback must never depend on names), pfhelper reading /etc/passwd after
pledge, `pfctl -sl`'s column headers on 7.9 counted as a rule called `ID`,
a placeholder certificate subject longer than X.509's 64 characters, and a
placeholder without the names acme-client checks, nginx -t refusing a new
network's IPv6 address it couldn't bind yet, `proto icmp` rules on networks
with IPv6 (now `inet proto icmp`), Kea refusing interfaces the generation
creates (checked without them).
