# Octopus

An OpenBSD router configured from one file. `router.toml` describes the
networks, hosts, firewall policy, port forwards, DNS, VPN and reverse proxy;
the `octopus` compiler turns it into plain OpenBSD configuration (`pf.conf`,
`hostname.*`, Kea's DHCP config, ...), checks it against the design's invariants,
validates every file with its own daemon's parser, and applies it with
commit-confirm: if you don't confirm within 60 seconds, the previous
configuration comes back by itself.

Octopus is a compiler, not a runtime. Packets are forwarded, filtered and
NATed by OpenBSD's kernel and base daemons. When no Octopus process is
running, the router keeps running on the files it was given.

Design: [docs/design.md](docs/design.md) (the original document, with
Octopus's deviations at the top). Operations and cutover:
[docs/operations.md](docs/operations.md). Configuration reference:
[docs/router-toml.md](docs/router-toml.md).

## Pieces

| Binary | Runs as | What it does |
|---|---|---|
| `octopus` | root (CLI) | compile, check, diff, apply / confirm / rollback, generations, PKI, pfSense import |
| `octopus-web` | `_octoweb` | web UI on the management addresses (x11 look); privileged actions only through six exact `doas` rules |
| `octopus-dns` | root → `_octodns` | DNS phase B: hickory-server with JSON query log, NXDOMAIN DoH canary, DNS-driven traffic classification |
| `octopus-pfhelper` | root | the only path from unprivileged code to pf: add/delete/replace on allow-listed tables |
| `octopus-proxy` | root → `_octoproxy` | servers' egress: SNI/Host allowlist, origins' certificates verified, leaves from the interception root minted by a separate signer process |
| `octopus-collector` | root → `_octoflow` | pflow's IPFIX flows labelled with the names clients looked up |
| `octopus-analyzer` | root → `_octoflow` | FCAP rules as locked BPF filters, payload regex, ring-buffered pcaps, `lab_block` through the pf helper |
| `hickory-dns` | root → `_octodns` | DNS phase A: the stock Hickory binary (0.26.3) |

Everything else is OpenBSD 7.9 base (pf, ntpd, sshd, syslogd, wg,
pppoe, vlan, veb) plus two packages from the site set: Kea (DHCP) and nginx (vhosts).

| Crate | |
|---|---|
| `crates/config` | schema, secrets, MAC → interface resolution, invariants INV-1..4, 8 |
| `crates/render` | one module per output: pf, hostname.*, Kea, DNS, ntpd/sshd/syslog, nginx, access points, the guard |
| `crates/import-pfsense` | pfSense `config.xml` → `router.toml` + `secrets.toml` + report; redaction |
| `crates/octopus` | the CLI: generations, apply, validators, status, PKI commands |
| `crates/pki` | services root: name-constrained root + intermediate, 90-day leaves (rcgen) |
| `crates/dns` | `octopus-dns` |
| `crates/pfhelper` | `octopus-pfhelper` |
| `crates/web` | `octopus-web` |
| `crates/proxy`, `crates/collector`, `crates/analyzer` | the phase 5 and 6 daemons |
| `deploy/` | rc.d scripts, doas rules, `install.site`, site set builder, autoinstall template |
| `examples/` | a sample `router.toml` (VLAN tiers, Wi-Fi, DNS views, a reverse-proxy site) |

## Working with it

On the build VM (OpenBSD 7.9, same release as the router; Rust from packages):

```sh
pkg_add rust nginx
deploy/build-hickory.sh                     # stock hickory-dns into /usr/local/sbin
cargo build --release
target/release/octopus check --offline -c examples/vlans.toml
target/release/octopus build --offline -c examples/vlans.toml -o /tmp/out
target/release/octopus validate --offline /tmp/out    # pfctl -nf, kea-dhcp4 -t, sshd -t, nginx -t, ...
deploy/mksite.sh SITEDIR OUTDIR             # siteXY.tgz for autoinstall(8)
```

On the router:

```sh
octopus diff                # what would change (files with secrets are not shown)
octopus apply               # build, validate, apply; prints what it did
octopus confirm             # within 60 s, or it rolls back
octopus rollback [GEN]      # revert the pending generation, or go to an older one
octopus generations         # every applied configuration, plus the pre-Octopus baseline (0)
octopus status              # interfaces, pf, services
```

The web UI (`https://<mgmt address>:8443`) does the same through
check → diff → apply → confirm, shows live status, traffic graphs, the
firewall policy with its counters, DNS queries and DHCP leases, and edits
all of router.toml (through the same diff and apply): firewall rules as
source, destination and allow / deny / nat, DNS overrides and views, DHCP
reservations, Wi-Fi networks and access points, reverse-proxy sites (public ones with Let's Encrypt), analyzer
rules, and every other section on a settings page built from the schema. It
captures packets on demand.

## Safety model

* **Commit-confirm.** An applied generation is pending until confirmed. A
  detached watchdog reverts it at the deadline; `octopus boot` (from
  `rc.local`) reverts it after a reboot; any error during apply reverts
  immediately. Generation 0 is a copy of the files as they were before
  Octopus, so even the first apply can be undone.
* **Invariants** fail the compile: management only from mgmt networks
  (INV-1), WAN default-deny with declared forwards only (INV-2), servers
  without direct egress (INV-3), clients can't reach outside DNS (INV-4),
  ruleset starts with `block` (INV-7), secrets only in 0600 files (INV-8).
* **Native validation** (INV-6) of every file before anything is touched.
* **Least privilege.** Network-facing code runs unprivileged and pledged
  (`octopus-web`, `octopus-dns`, `octopus-proxy`, the collector and analyzer);
  root helpers are small and narrow (`octopus-pfhelper`: tables only;
  `octopus` via doas: five fixed commands, plus the analyzer's one-shot
  capture).
* **Management is internal.** The web UI listens on management addresses
  only and is not meant to be exposed: it has sessions, bcrypt logins and a
  lockout, and its state-changing API needs a header only its own script
  sets, but no Origin checks and no HSTS.
* **Secrets** live in `/etc/octopus/secrets.toml` (0600) and are referenced
  as `secret:<key>`; they never appear in diffs, the web UI or the repository.

## Status

| Phase | | State |
|---|---|---|
| 1 | compiler, importer, apply/rollback, WAN/VLANs/NAT/pf, dhcpd, DNS phase A, sshd, ntpd, deploy | done, lab-tested |
| 2 | WireGuard, nginx vhosts, services PKI | done, lab-tested |
| 3 | pf helper, octopus-dns: query log, classification, NXDOMAIN canary, DNS views | done, lab-tested |
| 4 | queue trees and classification rules | rendered and loading; rates need the line measurement |
| 5 | interception root, servers' egress proxy (octopus-proxy, not relayd: see docs/design.md) | done, lab-tested |
| 6 | IPFIX collector with DNS join, FCAP analyzer, `lab_block` | done, lab-tested |
| — | IPv6: prefix delegation, router advertisements, v6 policy | done; lab-tested with unique local addresses (the lab has no WAN) |
| — | bridged networks (several ports, one network, no VLANs), DNS views, syslog over TLS with a client certificate, pf log to syslog | done, lab-tested |
| — | tiers on one house bridge (MAC classes in Kea, wired fallback, Wi-Fi/guest VLANs), rules by source address, the MAC guard | done, lab-tested with clients in each tier |
| — | Wi-Fi: OpenWrt access points configured over SSH (`[wifi]`), guest networks as VLANs on a bridge | done; guest VLAN tested on the lab with a client; pushes tested against OpenWrt 25.12.5 (x86 rootfs, radios stubbed); not yet on a real access point |
| — | public vhosts (WAN, Let's Encrypt or own certificate, Cloudflare-only), web UI editing of all of router.toml | done; public sites validated (pfctl, nginx -t, acme-client -n) and served on the lab, but the lab has no WAN for a real Let's Encrypt run |

The lab is an OpenBSD 7.9 VM with paired interfaces standing in for clients. What was tested
there, and how, is in [docs/operations.md](docs/operations.md#lab-results).

## License

Copyright (C) 2026 th3rumbl3m4t0r

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).
