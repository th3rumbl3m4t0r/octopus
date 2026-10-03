#!/bin/ksh
#
# Build the Octopus site set on the build VM (same OpenBSD release as the
# router; design R9: never copy binaries between releases).
#
#   deploy/mksite.sh SITEDIR OUTDIR
#
# SITEDIR holds router.toml and optionally secrets.toml, authorized_keys
# and web-users. The result is OUTDIR/siteXY.tgz; put it next to the base
# sets (and in their index.txt) for autoinstall(8). It contains secrets when
# SITEDIR does: treat the file and the medium it is on accordingly.

set -eu
[ $# -eq 2 ] || { echo "usage: $0 SITEDIR OUTDIR" >&2; exit 2; }
site=$(cd "$1" && pwd)
out=$(cd "$2" && pwd)
top=$(cd "$(dirname "$0")/.." && pwd)
rel=$(uname -r | tr -d .)
hickory=${HICKORY:-/usr/local/sbin/hickory-dns}

[ -x "$hickory" ] || { echo "hickory-dns not found at $hickory: run deploy/build-hickory.sh" >&2; exit 1; }
[ -f "$site/router.toml" ] || { echo "$site/router.toml is missing" >&2; exit 1; }

cd "$top"
cargo build --release --locked

# compile + validate before packing anything (INV-6)
chk=$(mktemp -d)
trap 'rm -rf "$chk" ${stage:-}' EXIT
sec=""
[ -f "$site/secrets.toml" ] && sec="-s $site/secrets.toml"
target/release/octopus check --offline -c "$site/router.toml" $sec
target/release/octopus build --offline -c "$site/router.toml" -o "$chk"
HICKORY="$hickory" OCTOPUS_DNS="$top/target/release/octopus-dns" OCTOPUS_PROXY="$top/target/release/octopus-proxy" \
    OCTOPUS_COLLECTOR="$top/target/release/octopus-collector" OCTOPUS_ANALYZER="$top/target/release/octopus-analyzer" \
    target/release/octopus validate --offline "$chk"

stage=$(mktemp -d)
install -d -m 755 "$stage/usr/local/sbin" "$stage/etc/rc.d" "$stage/etc/octopus"
install -m 555 target/release/octopus target/release/octopus-web target/release/octopus-pfhelper \
    target/release/octopus-dns target/release/octopus-proxy target/release/octopus-collector \
    target/release/octopus-analyzer "$hickory" "$stage/usr/local/sbin/"
install -m 555 deploy/rc.d/octopus_hickory deploy/rc.d/octopus_dns deploy/rc.d/octopus_web \
    deploy/rc.d/octopus_pfhelper deploy/rc.d/octopus_filterlog deploy/rc.d/octopus_proxy \
    deploy/rc.d/octopus_collector deploy/rc.d/octopus_analyzer deploy/rc.d/octopus_kea deploy/rc.d/octopus_guard \
    "$stage/etc/rc.d/"
install -m 644 deploy/doas.conf "$stage/etc/octopus/doas.conf"
install -m 644 "$site/router.toml" "$stage/etc/octopus/router.toml"
[ -f "$site/secrets.toml" ] && install -m 600 "$site/secrets.toml" "$stage/etc/octopus/secrets.toml"
if [ -f "$site/web-users" ]; then
	install -d -m 750 "$stage/etc/octopus/web"
	install -m 640 "$site/web-users" "$stage/etc/octopus/web/users"
fi
if [ -f "$site/authorized_keys" ]; then
	install -d -m 700 "$stage/root/.ssh"
	install -m 600 "$site/authorized_keys" "$stage/root/.ssh/authorized_keys"
fi
install -m 555 deploy/install.site "$stage/install.site"

# the packages and their dependencies: nginx for [[vhosts]], Kea for DHCP;
# pkg_add checks their signatures at install time
pkgs="${OCTOPUS_PACKAGES:-nginx pcre2 bzip2 kea log4cplus}"
install -d -m 755 "$stage/var/octopus/packages"
# the versions installed here (pkg_add -u keeps them current), from
# packages-stable (errata updates) or the release's packages
base="$(cat /etc/installurl)/$(uname -r)"
arch=$(machine -a)
for p in $pkgs; do
	f=$(pkg_info | awk '{print $1}' | grep -E "^$p-[0-9]" | head -1 || true)
	[ -n "$f" ] || { echo "package $p is not installed on this build VM: pkg_add $p" >&2; exit 1; }
	ftp -V -o "$stage/var/octopus/packages/$f.tgz" "$base/packages-stable/$arch/$f.tgz" 2>/dev/null ||
	    ftp -V -o "$stage/var/octopus/packages/$f.tgz" "$base/packages/$arch/$f.tgz" ||
	    { echo "cannot download $f" >&2; exit 1; }
done

# Pack the top-level entries, never "." itself: the installer extracts with
# tar -p, and a "./" entry would give the new system's / the staging
# directory's mode (mktemp -d makes it 0700, which breaks every daemon).
chmod 755 "$stage"
entries=$(cd "$stage" && ls -A | sed 's|^|./|')
tar -C "$stage" -czf "$out/site$rel.tgz" $entries
if tar -tzf "$out/site$rel.tgz" | grep -qxE '\.?/?'; then
	echo "BUG: site set contains an entry for /" >&2
	exit 1
fi
echo "wrote $out/site$rel.tgz ($(du -h "$out/site$rel.tgz" | cut -f1))"
[ -f "$site/secrets.toml" ] && echo "NOTE: it contains secrets.toml"
