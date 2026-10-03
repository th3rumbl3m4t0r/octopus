#!/bin/sh
# netstat -ibn in OpenBSD's shape for tests/web-ui/run.sh, counters growing with the clock
echo "Name    Mtu   Network     Address              Ibytes       Obytes"
echo "vio0    1500  <Link>      02:00:5e:10:00:21    $((t * 150000 + r))  $((t * 30000))"
echo "pair0   1500  <Link>      02:00:00:00:99:00    $((t * 2000))  $((t * 9000 + r))"
echo "lo0     32768 <Link>                           5            5"
