#!/bin/ksh
#
# Install a site set onto a running OpenBSD system (the build VM, a lab VM,
# or an upgrade of the binaries on the router), then show what applying
# router.toml would change. It does not apply: run `octopus apply` yourself.
#
#   deploy/install-live.sh siteXY.tgz

set -eu
[ $# -eq 1 ] || { echo "usage: $0 siteXY.tgz" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# keep a router.toml / secrets.toml that is already there
keep=$(mktemp -d)
trap 'rm -rf "$keep"' EXIT
for f in router.toml secrets.toml web/users; do
	[ -f "/etc/octopus/$f" ] && { mkdir -p "$keep/$(dirname $f)"; cp -p "/etc/octopus/$f" "$keep/$f"; }
done

if tar -tzf "$1" | grep -qxE '\.?/?'; then
	echo "$1 contains an entry for / (built by an old mksite.sh): refusing" >&2
	exit 1
fi
# stop our daemons with the scripts that started them (names can change)
for s in octopus_web octopus_hickory octopus_dns octopus_pfhelper octopus_filterlog octopus_proxy octopus_collector octopus_analyzer octopus_kea octopus_guard; do
	[ -f /etc/rc.d/$s ] && rcctl stop "$s" >/dev/null 2>&1 || true
done
tar -C / -xzpf "$1"
for f in router.toml secrets.toml web/users; do
	[ -f "$keep/$f" ] && cp -p "$keep/$f" "/etc/octopus/$f"
done

OCTOPUS_LIVE=1 ksh /install.site
rm -f /install.site

for s in octopus_pfhelper octopus_hickory octopus_dns octopus_web octopus_filterlog octopus_proxy octopus_collector octopus_analyzer octopus_kea octopus_guard; do
	rcctl get "$s" status >/dev/null 2>&1 && rcctl start "$s" >/dev/null 2>&1 || true
done

/usr/local/sbin/octopus check
echo
echo "next: octopus diff | less; octopus apply   (then octopus confirm within 60 s)"
