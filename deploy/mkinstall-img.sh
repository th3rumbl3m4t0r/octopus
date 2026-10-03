#!/bin/ksh
#
# A USB stick image that installs OpenBSD + Octopus on the router without
# questions: OpenBSD's installXY.img plus the site set, with the autoinstall
# response file inside the ramdisk kernel (autoinstall(8), rdsetroot(8)) and
# the console on com0 at 115200 (the router box has no monitor).
#
#   deploy/mkinstall-img.sh installXY.img siteXY.tgz auto_install.conf OUT.img
#
# Run on the build VM as root (vnconfig). Verify installXY.img against
# OpenBSD's SHA256.sig with signify first; this script doesn't. The X and
# game sets are dropped from the image to make room; the site set is added
# to SHA256 so its checksum passes (it still counts as unverified: the
# response file answers that question).
#
# Everything the autoinstall needs is on the stick: no network, no server.
# Booting it in a machine erases the disk the response file names as the
# root disk (sd0): read deploy/install.conf.example and docs/operations.md.

set -eu
[ $# -eq 4 ] || { sed -n '3,19p' "$0" >&2; exit 2; }
img=$1; site=$2; resp=$3; out=$4
for f in "$img" "$site" "$resp"; do [ -f "$f" ] || { echo "$f: not a file" >&2; exit 1; }; done
[ "$(id -u)" = 0 ] || { echo "run as root (vnconfig)" >&2; exit 1; }
grep -q '^Which disk is the root disk' "$resp" || { echo "$resp: no root disk answer" >&2; exit 1; }
set=$(basename "$site")
case "$set" in site[0-9][0-9].tgz) ;; *) echo "$site: expected siteXY.tgz" >&2; exit 1 ;; esac
rel=${set#site}; rel=${rel%.tgz}; relp="${rel%?}.${rel#?}"	# 79 -> 7.9

for v in vnd0 vnd1; do
	vnconfig -l 2>/dev/null | grep -q "^$v: covering" && { echo "$v is in use" >&2; exit 1; }
done
work=$(mktemp -d)
m1=$work/img; m2=$work/rd
mkdir -p "$m1" "$m2"
cleanup() {
	umount "$m2" 2>/dev/null || true
	vnconfig -u vnd1 2>/dev/null || true
	umount "$m1" 2>/dev/null || true
	vnconfig -u vnd0 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

cp "$img" "$out"
vnconfig vnd0 "$out"
mount /dev/vnd0a "$m1"
sets=$m1/$relp/amd64
[ -d "$sets" ] || { echo "$img: no $relp/amd64 in it" >&2; exit 1; }

# the ramdisk: /auto_install.conf makes the installer start by itself
gunzip -c "$sets/bsd.rd" > "$work/bsd.rd"
rdsetroot -x "$work/bsd.rd" "$work/disk.fs"
vnconfig vnd1 "$work/disk.fs"
mount /dev/vnd1a "$m2"
install -m 644 "$resp" "$m2/auto_install.conf"
umount "$m2"
vnconfig -u vnd1
rdsetroot "$work/bsd.rd" "$work/disk.fs"
gzip -9n -c "$work/bsd.rd" > "$work/bsd.rd.gz"
# /bsd and /bsd.rd on the stick are one file; cp keeps that
cp "$work/bsd.rd.gz" "$sets/bsd.rd"
cp "$work/bsd.rd.gz" "$m1/bsd.rd"

# room for the site set; the installer is told -x* -game* anyway
rm -f "$sets"/x*"$rel".tgz "$sets/game$rel.tgz"
install -m 644 "$site" "$sets/$set"
(cd "$sets" && sha256 "$set" >> SHA256 && grep -v -E "x(base|font|serv|share)$rel|game$rel" SHA256 > SHA256.new && mv SHA256.new SHA256)

# serial console for the bootloader and the installer
cat > "$m1/etc/boot.conf" <<EOF
stty com0 115200
set tty com0
set image /$relp/amd64/bsd.rd
EOF

df -h "$m1" | tail -1
umount "$m1"
vnconfig -u vnd0
sha256 "$out" | tee "$out.sha256"
echo "wrote $out: dd it to a USB stick (dd if=$out of=/dev/sdX bs=1M conv=fsync); it installs onto sd0 without asking"
