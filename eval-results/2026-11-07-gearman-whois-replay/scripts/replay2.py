#!/usr/bin/env python3
"""Replay a captured NetGet -> Ollama /api/generate request over seeds and score the actions.

usage: replay2.py <req.json> <prompt.txt> <mode> <seeds a-b> [--show]

Modes score the first JSON value in the reply (what NetGet's parser executes):
  gearman_fail   pass when the first outcome action is fail_gearman_job or
                 send_gearman_exception (both reach the client as WORK_FAIL -> "Job failed")
  gearman_rev    pass when complete_gearman_job's result contains "desserts"
  whois_nomatch  pass when the text the wire actions would print matches the eval's regex
  whois_record   pass when a send_whois_record/response for the domain is sent (no error)
"""
import json
import re
import sys
import urllib.request

UP = "http://127.0.0.1:11434"


def first_json(text):
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "{[":
            try:
                v, _ = dec.raw_decode(text[i:])
                return v
            except ValueError:
                continue
    return None


def actions_of(v):
    if isinstance(v, dict) and isinstance(v.get("actions"), list):
        return v["actions"]
    if isinstance(v, dict) and "type" in v:
        return [v]
    if isinstance(v, list):
        return [a for a in v if isinstance(a, dict)]
    return []


def strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            if k != "type":
                yield from strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from strings(v)


def score(mode, acts):
    types = [a.get("type") for a in acts]
    if mode == "gearman_fail":
        for t in types:
            if t in ("fail_gearman_job", "send_gearman_exception"):
                return True
            if t in ("complete_gearman_job", "send_gearman_error"):
                return False
        return False
    if mode == "gearman_rev":
        for a in acts:
            if a.get("type") == "complete_gearman_job":
                return "desserts" in str(a.get("result", ""))
            if a.get("type") in ("fail_gearman_job", "send_gearman_exception", "send_gearman_error"):
                return False
        return False
    wire = [a for a in acts if a.get("type") in ("send_error", "send_whois_record", "send_whois_response")]
    text = "\n".join(s for a in wire for s in strings(a))
    if mode == "whois_nomatch":
        return bool(re.search(r"(?i)no match|not found|no entries|no data found", text))
    if mode == "whois_record":
        return bool(wire) and wire[0].get("type") != "send_error"
    raise SystemExit(f"unknown mode {mode}")


def main():
    req = json.load(open(sys.argv[1]))
    req["prompt"] = open(sys.argv[2]).read()
    mode = sys.argv[3]
    a, b = sys.argv[4].split("-")
    show = "--show" in sys.argv
    req["stream"] = False
    passes = 0
    seeds = range(int(a), int(b) + 1)
    for s in seeds:
        req.setdefault("options", {})["seed"] = s
        req["options"]["num_predict"] = 2048
        r = urllib.request.Request(UP + "/api/generate", data=json.dumps(req).encode(),
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=900) as resp:
            content = json.load(resp).get("response", "")
        acts = actions_of(first_json(content))
        ok = score(mode, acts)
        passes += ok
        one = json.dumps(acts)[:240]
        print(f"seed {s:3d} {'PASS' if ok else 'fail'} {one if show or not ok else ''}", flush=True)
    print(f"TALLY {sys.argv[2]} {mode} {passes}/{len(seeds)}", flush=True)


if __name__ == "__main__":
    main()
