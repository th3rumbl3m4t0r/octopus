# router.toml reference

Every table rejects unknown keys. `octopus check` reports errors (which stop a
build) and warnings; codes `INV-n` are the design invariants, `E-*` structural.
Examples: `examples/vlans.toml` (the design's VLAN layout), `examples/lab.toml`
(a lab VM with paired interfaces).

## [system]

| key | default | |
|---|---|---|
| `hostname` | — | DNS label |
| `domain` | — | internal zone, e.g. `home.arpa` |
| `openbsd_release` | — | `7.9`; binaries are built per release |
| `timezone` | `UTC` | |
| `max_states` | 100000 | pf state limit |
| `max_table_entries` | 400000 | pf table entry limit |

## [interfaces.ROLE]

Physical ports by role, bound to MAC addresses so the same file works on the
VM (`vio0`) and the hardware (`igc0`).

| key | |
|---|---|
| `mac` | resolved against `ifconfig -a` on the machine |
| `name` | only used off the router (`--offline`): CI, the build VM |
| `description` | |

## [wan]

| key | default | |
|---|---|---|
| `interface` | — | role |
| `vlan` | none | tag on the WAN port, if the ISP requires one (e.g. 848) |
| `vlan_prio` | none | 802.1p priority (`txprio`) |
| `pppoe` | — | `{ user = "secret:k", password = "secret:k", auth = "chap" }` |
| `dhcp` | false | |
| `static` | — | `{ address = "a.b.c.d/nn", gateway = "a.b.c.d" }` |
| `mtu` | 1500 | PPPoE: 1492 |
| `mss` | mtu − 40 | TCP MSS clamp on the WAN |
| `allow_ping` | false | answer ICMP echo on the WAN address |

Exactly one of `pppoe`, `dhcp`, `static`. No `[wan]` at all is allowed (lab).

## [lan] and [[tiers]]

The house ports are one bridge, and any device can go in any port. Address
ranges are **tiers**; a device lands in one by its MAC, by the cable, or by
the VLAN its Wi-Fi access point tags it with. A tier is open: it reaches
everything, and the policy is the `[[rules]]`, which match by source address,
the same address everywhere.

```toml
[lan]
ports = ["fastlane", "slowlane", "vast"]   # roles in [interfaces]

[[tiers]]
name = "cd"                                # core distribution
address = "192.168.1.1/24"
macs = ["bc:24:11", "90:9a:4a"]            # MACs and prefixes that get this tier
dhcp = { range = ["192.168.1.200", "192.168.1.250"] }

[[tiers]]
name = "dd"                                # every other cable
address = "192.168.2.1/24"
wired = true
dhcp = { range = ["192.168.2.10", "192.168.2.250"] }

[[tiers]]
name = "wifi"
address = "192.168.3.1/24"
vlan = 3                                   # tagged by the access points
dhcp = { range = ["192.168.3.10", "192.168.3.250"] }

[[tiers]]
name = "guest"
address = "192.168.4.1/23"
vlan = 4
dhcp = { range = ["192.168.4.10", "192.168.5.250"] }
```

| key | |
|---|---|
| `name` | a-z0-9_, max 15 |
| `address` | router address and prefix |
| `macs` | MACs and MAC prefixes (`bc:24:11`) whose devices get this tier's addresses; on the house ports, untagged tiers only |
| `wired` | every other device on a cable gets this tier (one tier) |
| `vlan` | the tier travels tagged on every house port (veb(4) is VLAN-aware since 7.9): for Wi-Fi tiers; VLAN 1 is the bridge's own |
| `kind` | `open` (the default: everything allowed, the router managed only where a rule allows it) or the older fixed policies `mgmt`, `lan`, `servers`, `guest` |
| `dhcp` | `{ range = ["first", "last"], lease_time = 7200, max_lease_time = 86400 }`, or `ranges = [[…], […]]` |
| `interface`, `bridge` | instead of the house ports: a port of its own, or a bridge of roles (older layout; `[[networks]]` in older files still reads) |
| `ipv6`, `ipv6_slot` | as before; tiers sharing the house ports untagged share one /64 (the first of them carries it) |
| `description` | |

The untagged tiers share one interface: the router has an address in each,
DHCP (Kea) picks the tier by MAC class, and pf tells them apart by source
address. Wi-Fi and guest tiers come in on their own VLAN interface, where
uRPF drops any address outside the tier's range. A tier with `macs` is for
listed devices only: a device that takes one of its addresses itself (not by
DHCP, not reserved for it) is cut off from the router by `octopus guard`
(a bridge rule on the router's port; the firewall page lists it with a
release button).

Guests are a tier the rules keep from inside. The wifi page writes these
when it makes a guest tier; exceptions go above the block:

```toml
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

[[rules]]
network = "all"
action = "block"
from = "net:guest"
to = "internal"
```

Who manages the router (ssh, web UI) is a rule too, per tier, e.g.
`from = "net:cd"`, `to = "self"`, `proto = "tcp"`, `port = "22,8443"`. A
configuration where no rule lets any tier in is refused (it would lock
everyone out).

The older fixed policies (`kind`), for tiers on ports of their own:

| kind | router services | elsewhere |
|---|---|---|
| `mgmt` | everything, including sshd and the web UI | everything |
| `lan` | DNS, DHCP, NTP, ping, nginx vhosts | the internet; other internal networks only by `[[rules]]` |
| `servers` | DNS, DHCP, NTP, ping | nothing directly: `[[links]]`; 80/443 through octopus-proxy |
| `guest` | DNS, DHCP, NTP, ping | the internet only; no internal network, no vhosts |

## [[hosts]]

A name in the internal zone (A + PTR) and, with `mac`, a DHCP reservation.
`name`, `ip`, `mac`, `aliases = []`, `description`; its tier follows from
`ip` (`tier` names it, `network` in older files). A reservation also lets
the device use that address in a tier kept for listed devices.

## [[tables]]

`name`, `entries = ["prefix" | "address", ...]`, `description`. Referenced as
`table:NAME` (or just `NAME`) in rules and forwards. Rendered as `<t_NAME>`.

## [[forwards]] (INV-2: the only inbound paths)

| key | |
|---|---|
| `name` | |
| `proto` | `tcp`, `udp`, `tcp/udp` |
| `port` | `8080`, `"8000-8100"` or `"80,443"` |
| `from` | `any` (warned), `internet`, a table, an address or prefix |
| `to` | an address on an internal network (not the router) |
| `to_port` | target port (start of the range) |
| `reflect` | NAT reflection for internal clients (only works when `from` can match them) |
| `log` | |

## [[rules]]

Explicit first-match rules for traffic **entering** from `network`, before its
kind policy. `network` is a network, `all` (the rule on every internal
network) or `wan` (from the internet: `block` and `reject` only, ahead of the
forwards and every other way in; an inside `to` means the WAN address, since
pf sees it before a forward translates it). `action` = `pass` / `block` /
`reject`; `from`, `to` = `any`, `self`, `internal` (every internal network),
`internet` (everything outside them), a network, host or table name (`net:`,
`host:`, `table:` to disambiguate), an address or prefix; `proto`; `port`;
`log`; `description`. The management guard (INV-1) and the DoT block (INV-4)
come before them.

The web UI's firewall page writes these for you: a rule there is source,
destination and allow / deny / nat. Allow and deny become a `[[rules]]` entry
on the source's network (`all` for internal ranges, `wan` for a deny from
outside), or a `[[links]]` entry for a servers network's way out; nat becomes
a `[[forwards]]` entry, which also allows the traffic.

## [[links]] (INV-3)

Direct egress for a `servers` network: `network`, `to` (not `any`), `proto`,
`port`, `description`.

## [[routes]]

`to = "prefix" | "default"`, `via = "address on an internal network"`. A
default route conflicts with a WAN; with a DHCP WAN OpenBSD ignores it.

## [dns]

| key | default | |
|---|---|---|
| `engine` | `hickory` | `hickory` (phase A, stock binary) or `octopus-dns` (phase B) |
| `upstreams` | Cloudflare + Quad9 | `[{ ip, tls_name }]`; DNS-over-TLS only, certificates checked |
| `cache_size` | 50000 | |
| `records` | `[]` | `[{ name, ip }]` names outside the zone answered locally (split horizon) |
| `block_public_resolvers` | true | block 443/853 to well-known public resolvers (Cloudflare, Google, Quad9, AdGuard, OpenDNS, NextDNS, …): no way around the router's DNS and its views |
| `sinkhole` | — | octopus-dns: names an upstream blocks (Cloudflare's security resolvers answer `0.0.0.0`) get this IPv4 address instead, AAAA gets no answer; logged as `blocked` either way. Best an internal host that logs who asked |

Phase B also needs `[traffic].destinations` for classification. The DoH
canary `use-application-dns.net` is NODATA in phase A, NXDOMAIN in phase B.

### [[dns.overrides]]

A name, and by default every name below it, answered with one address for
every client and view: blackholing, or sending a public name to an internal
host. Names in the internal zone are `[[hosts]]` instead.

| key | default | |
|---|---|---|
| `name` | — | fully qualified; lowercased, trailing dot dropped |
| `ip` | — | IPv4 (A) or IPv6 (AAAA) |
| `subdomains` | true | also `*.name` |
| `description` | | |

```toml
[[dns.overrides]]
name = "ads.example.com"
ip = "192.168.1.250"
```

### [[dns.views]] (octopus-dns)

Other upstreams for listed clients. Each view has its own forwarder and
cache; it never falls back to another view's upstreams, so a client whose
view's resolver blocks a name gets no answer from anywhere else.

| key | |
|---|---|
| `name` | a-z0-9_ (not `default`) |
| `upstreams` | `[{ ip, tls_name }]` |
| `clients` | host names, addresses, prefixes, networks or tables; told apart by IPv4 source address |
| `description` | |

```toml
[dns]
engine = "octopus-dns"
upstreams = [{ ip = "1.1.1.2", tls_name = "security.cloudflare-dns.com" }]   # everyone

[[dns.views]]
name = "unfiltered"
upstreams = [{ ip = "1.1.1.1", tls_name = "cloudflare-dns.com" }]
clients = ["pc", "192.168.1.11"]
```

## [ntp], [ssh], [logging], [web]

* `[ntp]`: `servers = []`, `constraints = ["9.9.9.9", "www.google.com"]`, `serve = true`.
* `[ssh]`: `port = 22`, `password_auth = false`, `root_login = "prohibit-password"`.
  sshd listens only on mgmt addresses (and the WireGuard address when a peer is mgmt).
* `[logging]`: `remote = ["tls://host:514" | "tcp://…" | "udp://…"]`; for TLS `tls_ca` (the server's CA file) and, when it requires a client certificate, `tls_cert` + `tls_key` (`octopus pki csr` makes the key and request); `pf = true` sends pf's log to syslog as program `filterlog`; `pflow = "ip:port"` exports IPFIX, and `"127.0.0.1:2055"` runs octopus-collector on the router (flows labelled with names in `/var/log/octopus-flows`).
* `[web]`: `enabled = true`, `port = 8443`, `certificate = "services"`: a leaf from
  the services root once it is set up (`octopus pki renew` keeps it current), or
  `"self-signed"`: the certificate install.site made stays, for a lab whose addresses
  the root doesn't cover.

## [ipv6]

| key | default | |
|---|---|---|
| `mode` | `off` | `off`: IPv6 blocked completely. `pd`: a prefix from the ISP on the WAN (dhcp6leased), one /64 per network, router advertisements (rad), IPv6 policy mirroring IPv4 |
| `request` | 60 | prefix length asked for; 2^(64 − request) network slots |
| `ula` | derived from the hostname | a unique local /48 (`fdxx::/48`): every network also gets a stable `ula:slot::/64` with the router at `::1`, used for DNS and NTP |
| `advertise_dns` | false | RDNSS in router advertisements. Off: clients keep asking over IPv4, where views can tell them apart |

The router's own services listen on the ULA; the WAN's delegated prefix is
only ever handled by interface references in pf, so it may change freely.

## [traffic] (phase 4)

| key | |
|---|---|
| `upload`, `download` | root rates, about 90 % of the **measured** line: `"22M"`, `"90M"` |
| `destinations` | `[{ class, domains = [suffixes] }]` → `cls_<class>` tables (octopus-dns) |
| `ports` | `[{ class, proto, port, description }]` extra port classification |

Upload tree on the WAN, download trees on each physical port (VLANs share
their parent's). Precedence: realtime > streaming > default > bulk; a
destination class beats the source network's class.

## [wireguard]

`listen_port`, `address` (router, with prefix), `private_key = "secret:k"`,
`peers = [{ name, public_key, address, policy = "mgmt" | "lan", preshared_key = "secret:k" }]`.
A peer gets its policy's access; mgmt peers are the only remote path to sshd.

## [[vhosts]] (phase 2)

| key | default | |
|---|---|---|
| `name` | — | label (`omada`) or name inside the internal zone; with `hostnames`, only the site's name |
| `hostnames` | `[name]` | the names served: inside the internal zone they share one services leaf; outside it (`app.example.com`) they need `public` or `cert` |
| `public` | false | serve the outside names on the internet too: nginx on every address, pf opens tcp 80/443 on the WAN (INV-2), and inside they resolve to the router (split horizon) |
| `cert`, `key` | — | certificate (full chain) and key files on the router for the outside names, e.g. a Cloudflare origin certificate; without them a public site gets Let's Encrypt (acme-client, http-01) |
| `allow_from` | anyone | public sites: `cloudflare` (its published ranges; nginx logs and forwards the visitor's address from `CF-Connecting-IP`), tables, addresses or prefixes. pf opens the WAN to the union of all public sites' lists |
| `upstream` | — | `http://host:port` or `https://host:port` |
| `verify_upstream` | true | check an https upstream's certificate |
| `upstream_ca` | system store | CA file on the router |
| `upstream_name` | — | name to verify; required for an address (nginx checks DNS names only) |
| `websocket` | false | |
| `description` | | |

Internal names need the services intermediate (`octopus pki init`); they get
an A record to the router. Several subdomains to different inside hosts are
several sites:

```toml
[[vhosts]]
name = "blog"
hostnames = ["blog.example.com", "www.example.com"]
public = true
allow_from = ["cloudflare"]
upstream = "http://192.168.1.30:8080"

[[vhosts]]
name = "git"
hostnames = ["git.example.com"]
public = true
allow_from = ["cloudflare"]
upstream = "http://192.168.1.32:3000"
```

Let's Encrypt: until acme-client has a site's certificate, nginx serves a
self-signed placeholder (one day, so acme-client replaces it). `octopus
confirm` starts acme-client in the background when there are placeholders,
and `octopus pki renew` (daily) renews. Behind Cloudflare, proxy the names
(orange cloud) and use SSL mode Full (strict); Cloudflare passes
`/.well-known/acme-challenge/` through on port 80.

## [proxy] (phase 5, servers networks)

Servers' outbound 443 and 80 are diverted to octopus-proxy. It allows only
listed names (TLS SNI, then every request's Host, which must match the SNI),
connects to the original destination with that name and verifies the
origin's certificate against `/etc/ssl/cert.pem`, and presents a leaf from
the interception root (`octopus pki intercept-init`; servers trust it,
nothing else does). Decisions: `/var/log/octopus-proxy`.

```toml
[proxy]
[[proxy.allow]]
network = "servers"
hosts = ["deb.debian.org", "*.s3.eu-central-1.amazonaws.com"]   # *.x = below x, not x
```

Clients that pin certificates or need mutual TLS go through `[[links]]` instead.

## [analyzer] (phase 6)

Standing passive rules, run by octopus-analyzer only with `enabled = true`
(default off; the rules are kept either way). pf forwards regardless. Each
rule's FCAP expression becomes a pcap filter installed as a locked BPF
program (BIOCLOCK) before the daemon drops privileges. The web UI's ad hoc
captures (FCAP + PCRE on demand) need none of this.

```toml
[analyzer]
enabled = true

[[analyzer.rules]]
name = "ssh_probes"
network = "wan"
fcap = "proto tcp and dst port 22 and tflags S/SA"
```

`[[analyzer.rules]]`:

| key | default | |
|---|---|---|
| `name` | — | a-z0-9_ |
| `network` | — | a network, or `wan` |
| `fcap` | — | `[src|dst] host A / net P / port N[-M]`, `proto tcp|udp|icmp|icmp6|N`, `tflags S/SA`, `len|ttl|icmp_type OP N`, `frag`, with `and`, `or`, `not`, parentheses. Flow-level terms (bps, pps) are refused |
| `regex` | — | PCRE2 on the payload (TCP/UDP): lookaround and backreferences work; a match that takes too much work (`(a+)+$`) fails instead of stalling |
| `action` | `log` | `log`, or `block`: the source goes into pf's `<lab_block>` through the pf helper |
| `block_for` | 3600 | seconds in `lab_block` |
| `pcap` | true | matching packets kept in `/var/octopus/pcap/<name>-N.pcap` (4 × 16 MB ring) |

Matches: `/var/log/octopus-analyzer`.

## [wifi]

Wi-Fi on OpenWrt access points that octopus sets up over SSH: the SSIDs,
the router network each one joins, and the access points that broadcast
them. `apply` pushes each access point's settings (and rollback the previous
ones); one that can't be reached doesn't fail the apply, it is marked and
`octopus ap push` (or the wifi page) catches up. Assimilating an access
point: docs/operations.md.

```toml
[wifi]
# country = "CZ"             # default: from system.timezone (Europe/Prague: CZ)

[[wifi.networks]]
ssid = "home"
tier = "wifi"
password = "secret:wifi_home"

[[wifi.networks]]
ssid = "guests"
tier = "guest"               # guests: clients isolated
password = "secret:wifi_guests"
bands = ["5g"]

[[wifi.aps]]
name = "hall"
host = "ap-hall"             # a [[hosts]] entry with its mac: the reservation
```

`country` is the regulatory domain: which channels and how much transmit
power are legal (in the EU, 5 GHz 36–64 indoors only, 100–140 with radar
detection). Without it OpenWrt uses the "world" domain, where many 5 GHz
channels may not be used to start a network. It defaults to the country of
`system.timezone`; set it when the time zone doesn't say (UTC) or the
access points are elsewhere.

`[[wifi.networks]]`:

| key | default | |
|---|---|---|
| `ssid` | — | 1 to 32 bytes |
| `network` | — | the router network its clients join: the access point's own network (untagged), or one with a `vlan`, which the access point carries tagged |
| `security` | `wpa2-wpa3` | `wpa2-wpa3` (WPA2 and WPA3 together), `wpa3`, `wpa2`, `open` |
| `password` | — | `secret:wifi_NAME`; the wifi page sets it (write-only), or `octopus secret set wifi_NAME < file` |
| `bands` | `["2g", "5g"]` | |
| `hidden` | false | |
| `isolate` | guest tiers | clients can't reach each other (a guest tier: the `guest` kind, or a rule blocking it from `internal`) |
| `aps` | all | only on these access points |
| `description` | | |

`[[wifi.aps]]`: `name`, `host` (its `[[hosts]]` entry: the address octopus
reaches it on), `channel_2g` / `channel_5g` (`auto` or a number),
`description`.

## secrets.toml

A flat table of strings, mode 0600, never committed:

```toml
pppoe_user = "..."
pppoe_pass = "..."
wg_key = "..."      # openssl rand -base64 32
```
