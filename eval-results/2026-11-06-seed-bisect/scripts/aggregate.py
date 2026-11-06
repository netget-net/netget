#!/usr/bin/env python3
"""Aggregate per-seed harness outputs under ROOT/seed-*/latest.json into a table."""
import collections
import glob
import json
import sys

root = sys.argv[1]
tot = collections.OrderedDict()
fails = collections.defaultdict(collections.Counter)
for f in sorted(glob.glob(root + "/seed-*/latest.json")):
    j = json.load(open(f))
    cases = j["cases"] if isinstance(j, dict) and "cases" in j else j
    for c in cases:
        p, a = tot.get(c["id"], (0, 0))
        tot[c["id"]] = (p + c["passes"], a + c["attempts"])
        for r in c["runs"]:
            if r["verdict"] != "pass":
                fails[c["id"]][r["failure_mode"] or r["verdict"]] += 1
P = A = 0
for k, (p, a) in tot.items():
    P += p
    A += a
    print(f"{k:45s} {p:3d}/{a:<3d} {dict(fails[k]) if fails[k] else ''}")
print(f"{'TOTAL':45s} {P:3d}/{A}")
