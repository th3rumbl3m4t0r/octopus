#!/bin/sh
# Fetch every page and /api/status from a running octopus-web for run.js.
#   tests/web-smoke/fetch.sh https://192.168.1.41:8443 USER PASSWORD_FILE
# then: (cd tests/web-smoke && npm install jsdom@24 && node run.js)
set -eu
B=$1; U=$2; P=$3
cd "$(dirname "$0")"
C=$(mktemp)
trap 'rm -f "$C"' EXIT
curl -sk -c "$C" -o /dev/null --data-urlencode "user=$U" --data-urlencode "password@$P" "$B/login"
for p in status firewall dns flows proxy analyzer dhcp config generations; do curl -sfk -b "$C" "$B/$p" > "page-$p.html"; done
for f in nav.js x11.js octopus.js; do curl -sfk -b "$C" "$B/$f" > "$f"; done
curl -sfk -b "$C" "$B/api/status" > status.json
echo "fetched; run: node run.js"
