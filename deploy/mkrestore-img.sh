#!/bin/ksh
#
# A USB stick image that puts the pfSense disk image back on the router box
# without a keyboard or a second machine: OpenBSD's ramdisk kernel (from
# installXY.img) with deploy/restore-pfsense.sh as its only program, the
# gzip'd disk image on the stick. The console is the screen and keyboard;
# CONSOLE=com0 puts it on the serial port at 115200 instead.
#
#   deploy/mkrestore-img.sh installXY.img disk.img.gz disk.img.sha256 OUT.img
#   cat disk.img.gz | deploy/mkrestore-img.sh installXY.img size:BYTES disk.img.sha256 OUT.img
#
# disk.img.sha256 holds "<sha256 hex> <bytes>" of the UNCOMPRESSED image
# (gzip -l can't tell: it stores the size modulo 4 GB). With size:BYTES the
# gzip'd image comes on stdin (its compressed size in bytes), so it never
# has to fit on the build VM's disk next to the result. Run on the build VM
# as root (vnconfig, installboot). The image boots via BIOS and UEFI like
# OpenBSD's own, and is about 8 % bigger than the compressed image.

set -eu
[ $# -eq 4 ] || { sed -n '3,17p' "$0" >&2; exit 2; }
img=$1; gz=$2; sum=$3; out=$4
exec 3<&0 </dev/null	# the gzip'd image, when it comes on stdin
case "$gz" in
size:*) gzbytes=${gz#size:} ;;
*) [ -f "$gz" ] || { echo "$gz: not a file" >&2; exit 1; }; gzbytes=$(ls -l "$gz" | awk '{print $5}') ;;
esac
for f in "$img" "$sum"; do [ -f "$f" ] || { echo "$f: not a file" >&2; exit 1; }; done
set -- $(cat "$sum"); [ ${#1} -eq 64 ] && [ "${2:-0}" -gt 0 ] || { echo "$sum: expected '<sha256> <bytes>'" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
top=$(cd "$(dirname "$0")/.." && pwd)
restore=$top/deploy/restore-pfsense.sh
[ -f "$restore" ] || { echo "$restore missing" >&2; exit 1; }
for v in vnd0 vnd1 vnd2; do
	vnconfig -l 2>/dev/null | grep -q "^$v: covering" && { echo "$v is in use" >&2; exit 1; }
done

work=$(mktemp -d)
m0=$work/src; m1=$work/img; m2=$work/rd
mkdir -p "$m0" "$m1" "$m2"
cleanup() {
	for m in "$m2" "$m1" "$m0"; do umount "$m" 2>/dev/null || true; done
	for v in vnd2 vnd1 vnd0; do vnconfig -u $v 2>/dev/null || true; done
	rm -rf "$work"
}
trap cleanup EXIT

# the ramdisk kernel from the install image, with our program in it
vnconfig vnd0 "$img"
mount -r /dev/vnd0a "$m0"
rel=$(ls "$m0" | sed -n 's/^\([0-9]\.[0-9]\)$/\1/p' | head -1)
gunzip -c "$m0/$rel/amd64/bsd.rd" > "$work/bsd.rd"
umount "$m0"
vnconfig -u vnd0
rdsetroot -x "$work/bsd.rd" "$work/disk.fs"
vnconfig vnd1 "$work/disk.fs"
mount /dev/vnd1a "$m2"
# the installer and its data make room (the ramdisk has ~250 KB free)
rm -f "$m2/install.sub" "$m2/install" "$m2/upgrade" "$m2/autoinstall" "$m2/install.md"
install -m 755 "$restore" "$m2/restore"
# .profile: the stock prologue (mount root rw, make /tmp, set the tty) and then ours
awk '/^	echo .erase/ {exit} {print}' "$m2/.profile" > "$work/profile"
cat >> "$work/profile" <<'EOF'
	stty newcrt werase ^W intr ^C kill ^U erase ^? status ^T
	exec /restore
fi
EOF
install -m 644 "$work/profile" "$m2/.profile"
umount "$m2"
vnconfig -u vnd1
rdsetroot "$work/bsd.rd" "$work/disk.fs"
gzip -9n -c "$work/bsd.rd" > "$work/bsd.rd.gz"

# the stick: MBR with an EFI system partition (960 sectors at 64, as
# OpenBSD's images) and an OpenBSD partition with one FFS2 filesystem
# FFS needs room of its own (cylinder groups, inodes): 8 % plus 96 MB
sectors=$(( (gzbytes + gzbytes / 12 + 96 * 1024 * 1024) / 512 ))
sectors=$(( (sectors / 2048 + 1) * 2048 ))
rm -f "$out"
dd if=/dev/zero of="$out" bs=512 count=1 seek=$((sectors - 1)) 2>/dev/null
vnconfig vnd2 "$out"
fdisk -iy -b 960 vnd2 >/dev/null
# the label: a = everything after the EFI partition
disklabel vnd2 > "$work/label" 2>/dev/null
asize=$((sectors - 1024))
printf 'a: %d 1024 4.2BSD 2048 16384 1\n' "$asize" >> "$work/label"
disklabel -R vnd2 "$work/label"
# one big file: no free-space reserve, few inodes
newfs -q -O 2 -m 0 -i 1048576 /dev/rvnd2a >/dev/null
newfs_msdos /dev/rvnd2i >/dev/null
mount /dev/vnd2a "$m1"
mkdir -p "$m1/etc" "$m1/pfsense"
install -m 644 "$work/bsd.rd.gz" "$m1/bsd.rd"
{
	[ "${CONSOLE:-}" = com0 ] && printf 'stty com0 115200\nset tty com0\n'
	echo "set image /bsd.rd"
} > "$m1/etc/boot.conf"
case "$gz" in
size:*) cat <&3 > "$m1/pfsense/disk.img.gz" ;;
*) cp "$gz" "$m1/pfsense/disk.img.gz" ;;
esac
got=$(ls -l "$m1/pfsense/disk.img.gz" | awk '{print $5}')
[ "$got" -eq "$gzbytes" ] || { echo "disk.img.gz: $got bytes, expected $gzbytes" >&2; exit 1; }
# (gunzip -t would take as long as a restore: compare this with the source's sha256 instead)
sha256 "$m1/pfsense/disk.img.gz" | sed 's|(.*)|(disk.img.gz on the stick)|'
awk '{print $1, $2; exit}' "$sum" > "$m1/pfsense/disk.img.sha256"
cat > "$m1/pfsense/README" <<EOF
pfSense disk image of the router, gzip'd.
Written back by /restore on this stick's ramdisk; by hand:
  gunzip -c /mnt/stick/pfsense/disk.img.gz | dd of=/dev/rsdXc bs=1m
EOF
# bootloaders: biosboot + /boot for BIOS, BOOTX64.EFI on the ESP for UEFI.
# With -r, installboot takes them from ROOT/usr/mdec; stage them there.
install -d "$m1/usr/mdec"
install -m 644 /usr/mdec/biosboot /usr/mdec/boot /usr/mdec/BOOTX64.EFI /usr/mdec/BOOTIA32.EFI "$m1/usr/mdec/"
installboot -r "$m1" vnd2 >/dev/null
rm -rf "$m1/usr"
# installboot fills the ESP only on GPT disks: on this MBR stick, by hand
mkdir -p "$work/esp"
mount -t msdos /dev/vnd2i "$work/esp"
mkdir -p "$work/esp/EFI/BOOT"
cp /usr/mdec/BOOTX64.EFI /usr/mdec/BOOTIA32.EFI "$work/esp/EFI/BOOT/"
umount "$work/esp"
df -h "$m1" | tail -1
umount "$m1"
vnconfig -u vnd2
sha256 "$out" | tee "$out.sha256"
echo "wrote $out: dd it to a stick (>= $((sectors / 2048)) MB); boot it, type 'revert'"
