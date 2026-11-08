#!/usr/bin/env python3
"""usage: lane3-compare.py <before latest.json> <after latest.json> — per-case pass counts."""
import json
import sys

a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
for n, d in (("before", a), ("after", b)):
    t = d["totals"]
    print(f"{n}: {t['runs_passed']}/{t['runs_total']} ({100 * t['runs_passed'] / t['runs_total']:.1f}%)")
A = {c["id"]: c for c in a["cases"]}
B = {c["id"]: c for c in b["cases"]}
for k in sorted(A):
    x, y = A[k], B.get(k)
    if y is None or not x["attempts"]:
        continue
    if x["passes"] != y["passes"] or x["passes"] < x["attempts"] or y["passes"] < y["attempts"]:
        fails = [(r["seed"], r["failure_mode"]) for r in y["runs"] if r["verdict"] != "pass"]
        print(f"| `{k}` | {x['passes']}/{x['attempts']} | {y['passes']}/{y['attempts']} | {fails}")
