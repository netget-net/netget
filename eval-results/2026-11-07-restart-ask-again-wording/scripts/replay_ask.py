#!/usr/bin/env python3
"""Replay a captured ask-again request over seeds and tally the shapes of the answers.

usage: replay_ask.py <req.json> <variant.py|-> <seeds a-b>

An answer's shape is its actions with memory/notes dropped, e.g.
`send_command "Paris"` or `execute_redis_command "GET mykey"` or `(none)`.
"""
import collections, json, runpy, sys, urllib.request
sys.path.insert(0, "/tmp/telnet-line")
from replay import first_json, acts

SKIP = {"set_memory", "append_memory", "notify_operator", "show_message", "provide_feedback"}


def shape(actions):
    parts = []
    for a in actions:
        t = a.get("type")
        if t in SKIP:
            continue
        vals = [v for k, v in a.items() if k != "type" and isinstance(v, str)]
        parts.append(f"{t} {json.dumps(' '.join(vals))}" if vals else str(t))
    return "; ".join(parts) or "(none)"


req = json.load(open(sys.argv[1]))
if sys.argv[2] != "-":
    req["prompt"] = runpy.run_path(sys.argv[2])["transform"](req["prompt"])
a, b = sys.argv[3].split("-")
req["stream"] = False
tally = collections.Counter()
for s in range(int(a), int(b) + 1):
    req.setdefault("options", {})["seed"] = s
    r = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=json.dumps(req).encode(),
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=900) as resp:
        content = json.load(resp).get("response", "")
    v = first_json(content)
    sh = shape(acts(v)) if v is not None else "(unparseable)"
    tally[sh] += 1
    print(f"seed {s:3d} {sh[:160]}", flush=True)
print(f"TALLY {sys.argv[1].split('/')[-1]} {sys.argv[2].split('/')[-1]} {dict(tally.most_common())}", flush=True)
