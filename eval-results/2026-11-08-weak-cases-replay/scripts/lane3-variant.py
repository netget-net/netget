#!/usr/bin/env python3
"""Derive a variant prompt from a captured one by exact string replacements.

usage: lane3-variant.py <in_prompt> <out_prompt> <spec.json>
spec.json: [["old text", "new text"], ...]; every old text must occur exactly once.
"""
import json
import sys

src, dst, spec = sys.argv[1:4]
p = open(src).read()
for old, new in json.load(open(spec)):
    n = p.count(old)
    if n != 1:
        raise SystemExit(f"{spec}: expected exactly one occurrence, found {n}: {old[:80]!r}")
    p = p.replace(old, new)
open(dst, "w").write(p)
print(f"wrote {dst} ({len(p)} chars)")
