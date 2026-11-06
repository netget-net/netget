#!/usr/bin/env python3
"""Simulate NetGet's correction round for a notes-only answer.

usage: retry_sim.py <req.json> <resp.ndjson> <correction.txt> <pass_regex> <seeds>

Builds the prompt the way ConversationHandler flattens it for /api/generate
(system + user, then "Your previous response:\n<reply>", then the correction) and
replays it over the seeds.
"""
import json
import re
import sys
import urllib.request

req = json.load(open(sys.argv[1]))
reply = "".join(json.loads(l).get("response", "") for l in open(sys.argv[2]) if l.strip())
correction = open(sys.argv[3]).read().strip()
rx = re.compile(sys.argv[4], re.S)
seeds = []
for part in sys.argv[5].split(","):
    a, _, b = part.partition("-")
    seeds.extend(range(int(a), int(b or a) + 1))

base = req["prompt"]
if not base.endswith("\n\n"):
    base = base.rstrip("\n") + "\n\n"
req["prompt"] = base + "Your previous response:\n" + reply + "\n\n" + correction + "\n\n"
req["stream"] = False
ok_n = 0
for s in seeds:
    req["options"]["seed"] = s
    req["options"]["num_predict"] = 2048
    r = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=json.dumps(req).encode(),
                               headers={"Content-Type": "application/json"})
    out = json.load(urllib.request.urlopen(r, timeout=900)).get("response", "")
    ok = bool(rx.search(out))
    ok_n += ok
    print(f"seed {s:3d} {'PASS' if ok else 'fail'} {re.sub(chr(10), ' ', out)[:240]}", flush=True)
print(f"TALLY {ok_n}/{len(seeds)}")
