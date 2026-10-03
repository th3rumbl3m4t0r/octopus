#!/usr/bin/env python3
"""Stands in for `doas octopus ...` when tests/web-ui/run.sh runs octopus-web
in its development mode: the commands the web UI may run, with enough state
(generations, a pending one, access points, stored Wi-Fi passwords) for the
UI to be driven through everything. Status comes from router.toml plus
made-up counters, leases and logs. State lives in $FAKE_STATE."""

import difflib
import json
import os
import shutil
import sys
import time
import tomllib

ROUTER = "/etc/octopus/router.toml"
STAGED = "/var/octopus/staged/router.toml"
STATE = os.environ.get("FAKE_STATE", "/var/octopus/fake-state.json")
SECRET_STAGED = os.path.join(os.environ.get("OCTOPUS_STAGED", "/tmp"), "secret.json")


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        now = int(time.time())
        return {"gens": [{"gen": 0, "created": now - 86400, "source": "baseline", "user": "-", "files": 9},
                         {"gen": 1, "created": now - 3600, "source": "cli", "user": "root", "files": 29}],
                "current": 1, "confirmed": 1, "pending": None, "aps": {}, "secrets": {},
                "guard": {"02:00:00:00:77:66": {"ip": "10.51.1.66", "tier": "cd", "veb": "veb0", "vport": "vport0", "at": now - 600}}}


def save(st):
    with open(STATE, "w") as f:
        json.dump(st, f)


def cfg():
    with open(ROUTER, "rb") as f:
        return tomllib.load(f)


def status(st):
    c = cfg()
    now = int(time.time())
    nets = c.get("tiers", c.get("networks", []))
    ifaces = [{"name": i.get("name", r), "description": i.get("description", r), "up": True, "status": "active",
               "inet": [], "inet6": [], "ibytes": 10_000_000, "obytes": 5_000_000, "ierrs": 0, "oerrs": 0}
              for r, i in c.get("interfaces", {}).items()]
    for k, n in enumerate([n for n in nets if n.get("bridge")]):
        ifaces.append({"name": f"vport{k}", "description": n["name"], "up": True, "status": "active",
                       "inet": [n["address"].split("/")[0]], "inet6": [], "ibytes": 1000, "obytes": 1000, "ierrs": 0, "oerrs": 0})
    labels = []
    for n in nets:
        for s in ["dns", "dhcp", "ntp", "ping", "internet", "guard", "self", "dot", "doh", "mgmt", "proxy"]:
            labels.append({"label": f"{n['name']}:{s}", "evaluations": 100, "packets": 42, "bytes": 4200})
    for i, _ in enumerate(c.get("rules", [])):
        labels.append({"label": f"rule:{i + 1}", "evaluations": 10, "packets": 3, "bytes": 300})
    tables = [{"name": t, "entries": e} for t, e in
              [("internal", len(nets)), ("martians", 14), ("public_resolvers", 40), ("cls_bulk", 3), ("lab_block", 0)]]
    tables += [{"name": "t_" + t["name"], "entries": len(t.get("entries", []))} for t in c.get("tables", [])]
    first = nets[0]["address"].split("/")[0].rsplit(".", 1)[0] if nets else "10.0.0"
    leases = [{"ip": f"{first}.77", "mac": "02:00:00:00:77:01", "hostname": "Phone Of Guest", "ends": "2026-12-01 10:00:00"},
              {"ip": f"{first}.78", "mac": "02:00:00:00:77:02", "hostname": "", "ends": "2026-12-01 11:00:00"}]
    queries = [{"ts": now - i * 7, "client": f"{first}.77", "net": nets[0]["name"] if nets else "lan", "view": "default",
                "qname": q, "qtype": "A", "rcode": "NoError", "answers": ["203.0.113.5"], "ms": 3, "class": ""}
               for i, q in enumerate(["ads.example.com.", "www.example.org.", "telemetry.example.net."] * 3)]
    dns = {"queries": len(queries), "errors": 0, "recent": queries,
           "top_names": [{"name": "ads.example.com.", "count": 3}, {"name": "www.example.org.", "count": 3}],
           "top_clients": [{"name": f"{first}.77", "count": 9}], "classes": [], "views": [{"name": "default", "count": 9}]}
    an = c.get("analyzer", {})
    analyzer = {"rules": [{"name": r["name"], "if": "vport0", "fcap": r["fcap"], "regex": r.get("regex"), "action": r.get("action", "log")}
                          for r in an.get("rules", [])],
                "matches": 1, "recent": [{"ts": now - 60, "rule": "x", "src": "10.0.0.5", "sport": 1234, "dst": "10.0.0.1",
                                         "dport": 80, "proto": "tcp", "len": 60, "action": "log"}],
                "pcaps": [{"name": "x-0.pcap", "modified": now - 60, "bytes": 2048}]}
    services = [{"name": n, "enabled": True, "running": True} for n in ["pf", "dhcpd", "octopus_dns", "octopus_web", "sshd"]]
    pend = st["pending"]
    return {
        "hostname": c["system"]["hostname"], "release": "7.9", "uptime": 86400, "load": "0.10", "time": now,
        "interfaces": ifaces, "pf": {"enabled": True, "states": 123, "labels": labels, "tables": tables, "queues": ""},
        "services": services, "leases": leases, "dns": dns, "flows": None, "proxy": None, "analyzer": analyzer,
        "ipv6": {"enabled": False}, "log": ["fake octopus"], "generations": st["gens"],
        "state": {"current": st["current"], "confirmed": st["confirmed"],
                  "pending": None if not pend else {"gen": pend["gen"], "previous": pend["previous"],
                                                    "remaining": max(0, 60 - (now - pend["at"]))}},
        "aps": st["aps"], "ap_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE octopus-ap",
        "wifi_secrets": sorted(st["secrets"]),
        "guard": st.get("guard", {}),
    }


def main(args):
    st = load()
    cmd = " ".join(args)
    if cmd == "status --json":
        print(json.dumps(status(st)))
    elif cmd == "diff --staged":
        a = open(ROUTER).read().splitlines(keepends=True)
        b = open(STAGED).read().splitlines(keepends=True)
        sys.stdout.writelines(difflib.unified_diff(a, b, "a/etc/octopus/router.toml", "b/etc/octopus/router.toml"))
        if a == b:
            print("no changes")
    elif cmd == "apply --staged":
        if st["pending"]:
            print(f"octopus: generation {st['pending']['gen']} is waiting for confirm or rollback", file=sys.stderr)
            return 1
        tomllib.loads(open(STAGED).read())
        shutil.copy(ROUTER, ROUTER + ".prev")
        shutil.copy(STAGED, ROUTER)
        gen = max(g["gen"] for g in st["gens"]) + 1
        st["gens"].append({"gen": gen, "created": int(time.time()), "source": "web", "user": "web:admin", "files": 30})
        st["pending"] = {"gen": gen, "previous": st["current"], "at": int(time.time())}
        st["current"] = gen
        # apply pushes the access points (all of them, here)
        for ap in cfg().get("wifi", {}).get("aps", []):
            st["aps"][ap["name"]] = {"address": "192.0.2.1", "ok": True, "result": "applied", "at": int(time.time())}
        save(st)
        print(f"generation {gen} is live; run `octopus confirm` within 60s or it is rolled back to {st['pending']['previous']}")
    elif cmd == "confirm":
        if not st["pending"]:
            print("octopus: nothing to confirm", file=sys.stderr)
            return 1
        st["confirmed"] = st["pending"]["gen"]
        st["pending"] = None
        save(st)
        print(f"generation {st['confirmed']} confirmed")
    elif cmd == "rollback":
        if not st["pending"]:
            print("octopus: nothing to roll back", file=sys.stderr)
            return 1
        shutil.copy(ROUTER + ".prev", ROUTER)
        st["current"] = st["pending"]["previous"]
        st["pending"] = None
        save(st)
        print("rolled back")
    elif cmd in ("ap push", "ap push --force"):
        aps = cfg().get("wifi", {}).get("aps", [])
        for ap in aps:
            st["aps"][ap["name"]] = {"address": "192.0.2.1", "ok": True, "result": "applied" if "--force" in cmd else "unchanged", "at": int(time.time())}
            print(f"{ap['name']:<16} 192.0.2.1       ok {st['aps'][ap['name']]['result']}")
        save(st)
    elif cmd == "guard release --staged":
        with open(os.path.join(os.environ.get("OCTOPUS_STAGED", "/tmp"), "guard.json")) as f:
            mac = json.load(f)["mac"]
        if mac not in st.get("guard", {}):
            print(f"octopus: {mac} is not blocked", file=sys.stderr)
            return 1
        del st["guard"][mac]
        save(st)
        print(f"{mac} released")
    elif cmd == "secret --staged":
        with open(SECRET_STAGED) as f:
            s = json.load(f)
        os.remove(SECRET_STAGED)
        k, v = s["key"], s["value"]
        if not k.startswith("wifi_"):
            print("octopus: only wifi_* secrets can be set this way", file=sys.stderr)
            return 1
        if not 8 <= len(v) <= 63:
            print("octopus: a Wi-Fi passphrase is 8 to 63 characters", file=sys.stderr)
            return 1
        st["secrets"][k] = True
        save(st)
        print(f"secret {k} set")
    else:
        print(f"fake octopus: {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
