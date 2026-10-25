#!/bin/ksh
#
# Install a site set onto a running OpenBSD system (the build VM, a lab VM,
# or an upgrade of the binaries on the router), then show what applying
# router.toml would change. It does not apply: run `octopus apply` yourself.
#
#   deploy/install-live.sh siteXY.tgz
#
# Keeps what the router has: router.toml, secrets.toml, the web users and
# root's authorized_keys (OCTOPUS_REPLACE_KEYS=1 takes the set's keys).
# The whole set is checked and unpacked aside before any daemon stops; if
# anything fails after that, the kept files go back, the daemons start
# again and the copies stay where it says.

set -eu
[ $# -eq 1 ] || { echo "usage: $0 siteXY.tgz" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
daemons="octopus_pfhelper octopus_hickory octopus_dns octopus_web octopus_filterlog octopus_proxy octopus_collector octopus_analyzer octopus_kea octopus_guard octopus_power"

# all of it readable, nothing that would replace a directory
gzip -t "$1" || { echo "$1 is damaged" >&2; exit 1; }
if tar -tzf "$1" | grep -qxE '\.?/?|.*/'; then
	echo "$1 has directory entries (built by an old mksite.sh): refusing" >&2
	exit 1
fi
stage=$(mktemp -d /var/tmp/octopus-site.XXXXXX)
keep=$(mktemp -d /var/tmp/octopus-keep.XXXXXX)
tar -C "$stage" -xzpf "$1" || { rm -rf "$stage" "$keep"; echo "$1 doesn't unpack" >&2; exit 1; }

keepers="etc/octopus/router.toml etc/octopus/secrets.toml etc/octopus/web/users"
[ "${OCTOPUS_REPLACE_KEYS:-0}" = 1 ] || keepers="$keepers root/.ssh/authorized_keys"
for f in $keepers; do
	if [ -f "/$f" ]; then
		mkdir -p "$keep/$(dirname $f)"
		cp -p "/$f" "$keep/$f"
		rm -f "$stage/$f"
	fi
done

stopped=""
done_ok=0
finish() {
	if [ "$done_ok" != 1 ]; then
		echo "install-live: FAILED; putting back what was kept and starting the daemons again" >&2
		(cd "$keep" && find . -type f) | while read -r f; do cp -p "$keep/$f" "/$f"; done
		echo "install-live: the kept files stay in $keep" >&2
	else
		rm -rf "$keep"
	fi
	for s in $stopped; do
		rcctl get "$s" status >/dev/null 2>&1 && rcctl start "$s" >/dev/null 2>&1 || true
	done
	rm -rf "$stage"
}
trap finish EXIT

# stop our daemons with the scripts that started them (names can change)
for s in $daemons; do
	if [ -f /etc/rc.d/$s ] && rcctl check "$s" >/dev/null 2>&1; then
		rcctl stop "$s" >/dev/null 2>&1 || true
		stopped="$stopped $s"
	fi
done
# daemons enabled but down (a new one) start too
for s in $daemons; do
	case " $stopped " in *" $s "*) ;; *) stopped="$stopped $s" ;; esac
done

(cd "$stage" && find . -type f) > "$stage.list"
tar -C "$stage" -cf - -I "$stage.list" | tar -C / -xpf -
rm -f "$stage.list"

OCTOPUS_LIVE=1 ksh /install.site
rm -f /install.site
done_ok=1

/usr/local/sbin/octopus check || true
echo
echo "next: octopus diff | less; octopus apply   (then octopus confirm within 60 s)"
