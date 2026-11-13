#!/usr/bin/env python3
"""List captured requests whose prompt contains every needle, with seed and reply.

usage: lane3-caps.py <capture_dir> [--dump N] [--full] needle [needle ...]
--dump N writes the Nth match's prompt to stdout instead of listing.
"""
import glob
import json
import os
import sys

args = sys.argv[1:]
d = args.pop(0)
dump = None
full = False
if "--dump" in args:
    i = args.index("--dump")
    dump = int(args[i + 1])
    del args[i:i + 2]
if "--full" in args:
    args.remove("--full")
    full = True
needles = args


def reply(base):
    raw = open(base + ".resp.json").read()
    out = ""
    for line in raw.splitlines():
        try:
            out += json.loads(line).get("response", "")
        except Exception:
            pass
    return out


matches = []
for f in sorted(glob.glob(os.path.join(d, "*.req.json"))):
    req = json.load(open(f))
    p = req.get("prompt", "")
    if all(n in p for n in needles):
        matches.append((f, req))

if dump is not None:
    sys.stdout.write(matches[dump][1]["prompt"])
    sys.exit(0)

for i, (f, req) in enumerate(matches):
    base = f[: -len(".req.json")]
    r = reply(base) if os.path.exists(base + ".resp.json") else "<no resp>"
    r = r if full else r[:260].replace("\n", " ")
    print(f"[{i}] {os.path.basename(base)} seed={req.get('options', {}).get('seed')} len={len(req['prompt'])} :: {r}")
