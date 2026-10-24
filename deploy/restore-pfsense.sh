#!/bin/ksh
#
# Runs inside the OpenBSD ramdisk of the restore stick (deploy/mkrestore-img.sh
# puts it there as /restore and makes .profile run it). Finds the stick (the
# disk with /pfsense/disk.img.gz on it) and the box's own disk (the other
# one), asks once, writes the image back, checks the sha256 of what was
# written, reboots. Everything on the console (the screen, or com0 at
# 115200 for a stick made with CONSOLE=com0).

PATH=/sbin:/bin:/usr/bin:/usr/sbin
IMG=pfsense/disk.img.gz
SUM=pfsense/disk.img.sha256	# sha256 of the uncompressed image
INFO=pfsense/README

say() { print -r -- "$*"; }
die() { say ""; say "*** $*"; say "A shell follows; 'reboot' when done."; exec ksh; }

# the ramdisk has no awk, tr, tail or head: ksh and sed only
mkdir -p /mnt/stick
say ""
say "========== pfSense restore stick =========="
say ""

# the disks, sd0 sd1 ... (hw.disknames is "sd0:uuid,sd1:uuid,cd0:")
disks=
IFS=, ; set -- $(sysctl -n hw.disknames); IFS=' 	
'
for d; do
	d=${d%%:*}
	[[ $d == sd* || $d == wd* ]] && disks="$disks $d"
done

# the stick: whichever disk has the image
stick=
for d in $disks; do
	if mount -r /dev/${d}a /mnt/stick 2>/dev/null; then
		[[ -f /mnt/stick/$IMG ]] && { stick=$d; break; }
		umount /mnt/stick
	fi
done
[[ -n $stick ]] || die "no disk with /$IMG found (disks:$disks); is the stick's partition readable?"
set -- $(cat /mnt/stick/$SUM)
want=$1	# sha256 of the uncompressed image
size=$2	# its bytes
[[ -f /mnt/stick/$INFO ]] && cat /mnt/stick/$INFO

# the target: the one other disk
targets=
for d in $disks; do
	[[ $d == $stick ]] || targets="$targets $d"
done
set -- $targets
(($# == 1)) || die "expected exactly one disk besides the stick ($stick), found: ${targets:-none}. Unplug extra disks or restore by hand: gunzip -c /mnt/stick/$IMG | dd of=/dev/rsdXc bs=1m"
target=$1

set -- $(ls -l /mnt/stick/$IMG)
say ""
say "stick:  $stick"
say "target: $target  $(dmesg | grep "^$target at" | sed -n '$p' | sed 's/.*: //')"
dmesg | grep "^$target: " | sed -n '$p'
say "image:  $5 bytes compressed, $size bytes to write"
say "        the pfSense disk as it was imaged"
say ""
say "EVERYTHING ON $target WILL BE OVERWRITTEN."
say ""
print -n "Type  revert  to write pfSense back to $target, anything else for a shell: "
read answer
[[ $answer == revert ]] || die "not confirmed; nothing was written."

say ""
say "$(date) writing (about 10 to 40 minutes for a 240 GB disk; a line every minute) ..."
# $! of a background pipeline is its last command: dd. It reports on SIGINFO.
gunzip -c /mnt/stick/$IMG | dd of=/dev/r${target}c bs=1m 2>/tmp/dd.err &
job=$!
while kill -0 $job 2>/dev/null; do
	sleep 60
	kill -INFO $job 2>/dev/null
	sleep 1
	grep "bytes transferred" /tmp/dd.err | sed -n '$p'
done
wait $job
rc=$?
sed -n '$p' /tmp/dd.err
((rc == 0)) || die "write failed (exit $rc). The disk may be smaller than the image or faulty."
sync

say ""
say "$(date) write done; reading back $size bytes to check the sha256 (as long again) ..."
print -n "Check now? [yes] "
read answer
if [[ -z $answer || $answer == y* ]]; then
	mb=$((size / 1048576)); rem=$((size % 1048576))
	got=$( { dd if=/dev/r${target}c bs=1m count=$mb 2>/dev/null
		((rem > 0)) && dd if=/dev/r${target}c bs=512 skip=$((mb * 2048)) count=$((rem / 512)) 2>/dev/null; } | sha256)
	if [[ $got == $want ]]; then
		say "$(date) sha256 OK: $got"
	else
		die "sha256 MISMATCH: wrote $got, expected $want. Don't boot from $target; retry or restore from another copy."
	fi
else
	say "not checked."
fi

umount /mnt/stick
say ""
say "pfSense is back on $target. Remove the stick; rebooting in 15 seconds (Ctrl-C for a shell)."
sleep 15
reboot
