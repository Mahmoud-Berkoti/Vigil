#!/usr/bin/env python3
"""Cross-validate vigil's RFC 6811 classification against the RIPEstat
rpki-validation API (which fronts a reference validator), using the
real global VRP set.

Usage:
  curl -s https://rpki.cloudflare.com/rpki.json -o data/vrp/rpki.json
  tools/rpki_crosscheck.py [N_SAMPLES]

Samples (prefix, origin) pairs from the checked-in MRT fixture, asks
vigil (`./vigil rov`) and RIPEstat for each, and exits 1 on any
disagreement.
"""
import json
import subprocess
import sys
import time

import mrtparse

VRP = "data/vrp/rpki.json"
FIXTURE = "data/fixtures/updates-sample.mrt"


def sample_routes(n):
    seen = {}
    for entry in mrtparse.Reader(FIXTURE):
        d = entry.data
        if list(d["type"].keys())[0] not in (16, 17):
            continue
        msg = d.get("bgp_message", {})
        if list(msg.get("type", {0: None}).keys())[0] != 2:
            continue
        aspath = []
        for attr in msg.get("path_attributes", []) or []:
            if list(attr["type"].keys())[0] == 2:
                for seg in attr["value"]:
                    aspath.extend(int(a) for a in seg["value"])
        if not aspath:
            continue
        for p in msg.get("nlri", []) or []:
            pfx = f"{p['prefix']}/{p['length']}"
            seen.setdefault(pfx, aspath[-1])
        if len(seen) >= n:
            break
    return list(seen.items())[:n]


def ripestat(prefix, asn):
    url = (f"https://stat.ripe.net/data/rpki-validation/data.json"
           f"?resource=AS{asn}&prefix={prefix}")
    out = subprocess.run(["curl", "-s", "--max-time", "30", url],
                         capture_output=True, text=True, check=True)
    d = json.loads(out.stdout)
    status = d["data"]["status"].lower()  # valid | invalid | unknown
    return "notfound" if status.startswith("unknown") else \
           ("invalid" if status.startswith("invalid") else "valid")


def vigil_rov(prefix, asn):
    out = subprocess.run(["./vigil", "rov", VRP, prefix, str(asn)],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    routes = sample_routes(n)
    bad = 0
    for prefix, asn in routes:
        got = vigil_rov(prefix, asn)
        want = ripestat(prefix, asn)
        mark = "OK " if got == want else "MISMATCH"
        if got != want:
            bad += 1
        print(f"{mark} AS{asn:<10} {prefix:<22} vigil={got:<9} ripestat={want}")
        time.sleep(0.4)  # be polite to RIPEstat
    if bad:
        print(f"{bad}/{len(routes)} mismatches")
        sys.exit(1)
    print(f"RPKI CROSSCHECK OK ({len(routes)} routes)")


if __name__ == "__main__":
    main()
