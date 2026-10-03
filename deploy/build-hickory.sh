#!/bin/ksh
#
# Build the stock hickory-dns (DNS phase A) on the build VM, with the
# features from the design (11.2): forwarding over DNS-over-TLS (ring),
# certificates checked by the platform verifier. No sqlite, no blocklist.

set -eu
version=${HICKORY_VERSION:-0.26.3}
root=${1:-/usr/local}
cargo install --locked hickory-dns --version "$version" --no-default-features \
    --features resolver,tls-ring,rustls-platform-verifier --root "$root/hickory-build"
install -m 555 "$root/hickory-build/bin/hickory-dns" "$root/sbin/hickory-dns"
rm -rf "$root/hickory-build"
"$root/sbin/hickory-dns" --version
