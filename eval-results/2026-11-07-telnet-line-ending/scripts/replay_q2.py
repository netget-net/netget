#!/usr/bin/env python3
"""Replay a captured Q2 prompt ("what is 2 plus 2?") and score whether the answer sent says 4.

usage: replay_q2.py <req.json> <variant.py|-> <seeds a-b>
"""
import json, runpy, sys, urllib.request
sys.path.insert(0, "/tmp/telnet-line")
from replay import first_json, acts, classify

req = json.load(open(sys.argv[1]))
if sys.argv[2] != "-":
    req["prompt"] = runpy.run_path(sys.argv[2])["transform"](req["prompt"])
a, b = sys.argv[3].split("-")
req["stream"] = False
tally = {"says4": 0, "other_answer": 0, "no_send": 0, "TEXT": 0}
for s in range(int(a), int(b) + 1):
    req.setdefault("options", {})["seed"] = s
    r = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=json.dumps(req).encode(),
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=900) as resp:
        content = json.load(resp).get("response", "")
    ac = acts(first_json(content))
    c = classify(ac)
    sent = [x for x in ac if x.get("type") in ("send_command", "send_text", "send_line")]
    if c == "TEXT":
        k = "TEXT"
    elif not sent:
        k = "no_send"
    elif any("4" in json.dumps(x) or "four" in json.dumps(x).lower() for x in sent):
        k = "says4"
    else:
        k = "other_answer"
    tally[k] += 1
    print(f"seed {s:3d} {k:12s} {json.dumps(sent)[:160]}", flush=True)
print(f"TALLY {sys.argv[1].split('/')[-1]} {sys.argv[2]} {tally}", flush=True)
