#!/bin/sh
#
# The web UI in a real browser, every page and feature, before a rollout:
# octopus-web (development mode) on 127.0.0.1:18443 with examples/lab.toml and
# stand-ins for octopus, octopus-analyzer and netstat (this directory), in a
# private mount namespace whose /etc, /var and /usr/bin are throwaway
# overlays. Linux, as root; Playwright with Chromium (NODE_PATH, or
# tests/web-smoke/node_modules).
#
#   tests/web-ui/run.sh [suite.js arguments]

set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)
[ "$(id -u)" = 0 ] || { echo "run as root (mount namespace)" >&2; exit 1; }
export NODE_PATH=${NODE_PATH:-$top/tests/web-smoke/node_modules}

(cd "$top" && cargo build -q -p octopus-web)
T=$(mktemp -d /tmp/octopus-web-ui.XXXXXX)
trap 'kill $(cat "$T/pid" 2>/dev/null) 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/eu" "$T/ew" "$T/vu" "$T/vw" "$T/bu" "$T/bw"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=localhost \
	-keyout "$T/key.pem" -out "$T/cert.pem" 2>/dev/null
printf testpass > "$T/pw"
echo "admin:$("$top/target/debug/octopus-web" --hash < "$T/pw")" > "$T/users"
cat > "$T/web.toml" <<EOF
listen = ["127.0.0.1:18443"]
hostname = "web-ui-test"
cert = "$T/cert.pem"
key = "$T/key.pem"
users = "$T/users"
EOF

unshare -m --propagation private sh -c "
	mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/eu,workdir=$T/ew /etc
	mount -t overlay overlay -o lowerdir=/var,upperdir=$T/vu,workdir=$T/vw /var
	mount -t overlay overlay -o lowerdir=/usr/bin,upperdir=$T/bu,workdir=$T/bw /usr/bin
	mkdir -p /etc/octopus /var/octopus/staged
	cp '$top/examples/lab.toml' /etc/octopus/router.toml
	cp '$here/fake-netstat.sh' /usr/bin/netstat
	echo \$\$ > '$T/pid'
	export OCTOPUS_WEB_DEV=1 OCTOPUS_BIN='$here/fake-octopus.py' OCTOPUS_ANALYZER_BIN='$here/fake-analyzer.py'
	export OCTOPUS_CAPTURE=/var/octopus/staged/capture.json OCTOPUS_STAGED=/var/octopus/staged FAKE_STATE=/var/octopus/fake-state.json
	exec '$top/target/debug/octopus-web' -f '$T/web.toml'
" > "$T/web.log" 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
	grep -q listening "$T/web.log" && break
	sleep 0.5
done
grep -q listening "$T/web.log" || { cat "$T/web.log" >&2; exit 1; }
node "$here/suite.js" https://127.0.0.1:18443 admin "$T/pw" "$@"
