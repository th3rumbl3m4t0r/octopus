#!/bin/sh
#
# OpenWrt for an access point octopus manages, built with OpenWrt's own
# Image Builder (on Linux x86_64): the stock image for the device plus
#   * the router's key for root (`octopus ap key` on the router prints it);
#     SSH by key only, no password logins
#   * lan by DHCP instead of 192.168.1.1, so it never fights the router
#     for that address
#   * no DHCP server, DNS or firewall of its own: a plain access point
# Wi-Fi stays off until the router pushes its settings.
#
#   deploy/ap-image.sh RELEASE|snapshot TARGET/SUBTARGET PROFILE KEYFILE [OUTDIR]
#   deploy/ap-image.sh 25.12.5 qualcommax/ipq807x tplink_eap620hd-v1 ap.key.pub
#
# The profile names are OpenWrt's (firmware-selector.openwrt.org shows them).

set -eu
[ $# -ge 4 ] || { sed -n '3,17p' "$0" >&2; exit 2; }
rel=$1; target=$2; profile=$3; keyfile=$4; out=${5:-$PWD/ap-images}
grep -q '^ssh-' "$keyfile" || { echo "$keyfile: not an SSH public key" >&2; exit 1; }

if [ "$rel" = snapshot ]; then
	base=https://downloads.openwrt.org/snapshots/targets/$target
else
	base=https://downloads.openwrt.org/releases/$rel/targets/$target
fi
work=${AP_IMAGE_CACHE:-$HOME/.cache/octopus-ap-image}/$rel-$(echo "$target" | tr / -)
mkdir -p "$work" "$out"
cd "$work"

# the Image Builder, checked against OpenWrt's sha256sums
curl -fsS -o sha256sums "$base/sha256sums"
ib=$(awk '/imagebuilder.*Linux-x86_64\.tar/ {sub(/^\*/, "", $2); print $2}' sha256sums)
[ -n "$ib" ] || { echo "no Image Builder in $base" >&2; exit 1; }
if ! grep " \*\?$ib\$" sha256sums | sed 's/ \*/  /' | sha256sum -c --status 2>/dev/null; then
	echo "downloading $ib"
	curl -fS -o "$ib" "$base/$ib"
	grep " \*\?$ib\$" sha256sums | sed 's/ \*/  /' | sha256sum -c --quiet
fi
dir=${ib%.tar.*}
[ -d "$dir" ] || tar -xf "$ib"

# what goes into the image on top of the stock one
files=$work/files-$profile
rm -rf "$files"
mkdir -p "$files/etc/dropbear" "$files/etc/uci-defaults"
cp "$keyfile" "$files/etc/dropbear/authorized_keys"
chmod 600 "$files/etc/dropbear/authorized_keys"
cat > "$files/etc/uci-defaults/90-octopus" <<'EOF'
# octopus access point: lan by DHCP, key-only SSH, no services of a router
uci -q batch <<UCI
set network.lan.proto='dhcp'
delete network.lan.ipaddr
delete network.lan.netmask
delete network.lan.ip6assign
delete network.wan
delete network.wan6
set dropbear.@dropbear[0].PasswordAuth='off'
set dropbear.@dropbear[0].RootPasswordAuth='off'
commit
UCI
for s in dnsmasq odhcpd firewall; do [ -x /etc/init.d/$s ] && /etc/init.d/$s disable; done
exit 0
EOF

cd "$dir"
# no LuCI: the router manages it, and it would log in without a password
mkdir -p tmp
make image PROFILE="$profile" FILES="$files" PACKAGES="-luci" BIN_DIR="$out/$profile" >"$work/build-$profile.log" 2>&1 || {
	tail -30 "$work/build-$profile.log" >&2
	# a failed first run leaves an empty profile list behind
	rm -f .profiles.mk
	exit 1
}
ls -l "$out/$profile"
echo "flash the *web-ui-factory* image (stock TP-Link UI) or *sysupgrade* (from OpenWrt)"
