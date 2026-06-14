#!/usr/bin/env python3
"""Cross-validate vigil's MRT replay counts against mrtparse.

Usage: tools/crosscheck.py FILE.mrt
Prints reference counts in the same key=value format as `vigil -r` and
exits 1 if vigil's output (run via ./vigil -r) disagrees.
"""
import subprocess
import sys

import mrtparse


def reference_counts(path):
    updates = announces = withdraws = rib_entries = records = 0
    skipped = 0
    prefixes = set()
    origins = set()

    for entry in mrtparse.Reader(path):
        d = entry.data
        records += 1
        mtype = list(d["type"].keys())[0]
        if mtype in (16, 17):  # BGP4MP / BGP4MP_ET
            subtype = list(d["subtype"].keys())[0]
            if subtype not in (1, 4, 6, 7):
                skipped += 1
                continue
            msg = d.get("bgp_message", {})
            bt = list(msg.get("type", {0: None}).keys())[0]
            if bt != 2:  # not UPDATE
                skipped += 1
                continue
            updates += 1
            for w in msg.get("withdrawn_routes", []) or []:
                withdraws += 1
                prefixes.add((w["prefix"], w["length"]))
            nlri = list(msg.get("nlri", []) or [])
            aspath = []
            as4path = []
            for attr in msg.get("path_attributes", []) or []:
                at = list(attr["type"].keys())[0]
                if at == 2:  # AS_PATH
                    for seg in attr["value"]:
                        aspath.extend(int(a) for a in seg["value"])
                elif at == 17:  # AS4_PATH
                    for seg in attr["value"]:
                        as4path.extend(int(a) for a in seg["value"])
                elif at == 14:  # MP_REACH
                    nlri.extend(attr["value"].get("nlri", []))
                elif at == 15:  # MP_UNREACH
                    for w in attr["value"].get("withdrawn_routes", []):
                        withdraws += 1
                        prefixes.add((w["prefix"], w["length"]))
            # RFC 6793 AS4_PATH reconstruction (matches vigil)
            if as4path and len(as4path) <= len(aspath):
                aspath = aspath[:len(aspath) - len(as4path)] + as4path
            for p in nlri:
                announces += 1
                prefixes.add((p["prefix"], p["length"]))
                if aspath:
                    origins.add(aspath[-1])
        elif mtype == 13:  # TABLE_DUMP_V2
            subtype = list(d["subtype"].keys())[0]
            if subtype in (2, 4):
                pfx = (d["prefix"], d["length"])
                for e in d["rib_entries"]:
                    rib_entries += 1
                    announces += 1
                    prefixes.add(pfx)
                    for attr in e.get("path_attributes", []) or []:
                        if list(attr["type"].keys())[0] == 2:
                            path = [int(a) for seg in attr["value"]
                                    for a in seg["value"]]
                            if path:
                                origins.add(path[-1])
            elif subtype != 1:
                skipped += 1
        else:
            skipped += 1

    return dict(records=records, updates=updates, rib_entries=rib_entries,
                announces=announces, withdraws=withdraws,
                prefixes=len(prefixes), origins=len(origins))


def main():
    path = sys.argv[1]
    ref = reference_counts(path)
    print("reference:", " ".join(f"{k}={v}" for k, v in ref.items()))

    out = subprocess.check_output(["./vigil", "-r", path], text=True)
    first_line = out.splitlines()[0]
    print("vigil:    ", first_line)
    got = dict(kv.split("=") for kv in first_line.split())

    mismatches = []
    for key in ("updates", "rib_entries", "announces", "withdraws",
                "prefixes", "origins"):
        if int(got[key]) != ref[key]:
            mismatches.append(f"{key}: vigil={got[key]} reference={ref[key]}")
    if mismatches:
        print("MISMATCH:\n  " + "\n  ".join(mismatches))
        sys.exit(1)
    print("CROSSCHECK OK")


if __name__ == "__main__":
    main()
