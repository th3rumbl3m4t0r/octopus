#!/usr/bin/env python3
# stands in for octopus-analyzer --oneshot (tests/web-ui/run.sh): three ethernet/IPv4/TCP frames
import base64, json, re, struct, sys, time
req = json.load(open(sys.argv[2]))
if 'banana' in req.get('fcap', ''):
    sys.exit(print('fcap: line 1: expected a number', file=sys.stderr) or 1)
def frame(src, dst, sport, dport, payload):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    return b'\x02' * 6 + b'\x04' * 6 + b'\x08\x00' + ip + tcp + payload, 54
pk, pcap = [], struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
now = int(time.time())
for i, (s, d, sp, dp, pl) in enumerate([('10.50.2.150', '93.184.216.34', 40001, 80, b'GET /evil.php HTTP/1.1\r\nHost: example.com\r\n\r\n'),
                                        ('93.184.216.34', '10.50.2.150', 80, 40001, b'HTTP/1.1 404 Not Found\r\n\r\n'),
                                        ('10.50.2.150', '1.1.1.1', 40002, 443, bytes(range(256)) * 3)]):
    f, at = frame(s, d, sp, dp, pl)
    m = None
    if req.get('pcre'):
        r = re.search(req['pcre'].encode(), pl)
        if not r: continue
        m = [r.start(), r.end()]
    pcap += struct.pack('<IIII', now, i * 1000, len(f), len(f)) + f
    pk.append({'ts': now, 'usec': i * 1000, 'src': s, 'dst': d, 'proto': 'tcp', 'sport': sp, 'dport': dp, 'len': len(f),
               'caplen': len(f), 'payload_at': at, 'match': m, 'data': base64.b64encode(f[:2048]).decode()})
print(json.dumps({'interface': req['interface'], 'filter': req.get('fcap', ''), 'dlt': 1, 'seen': 40, 'limit': False,
                  'pcap_truncated': False, 'packets': pk, 'pcap': base64.b64encode(pcap).decode()}))
