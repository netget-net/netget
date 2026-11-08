#!/usr/bin/env python3
"""Replay a captured NetGet -> Ollama /api/generate request over seeds and score the actions.

usage: lane3-replay.py <req.json> <prompt.txt|-> <scorer> <seeds a-b> [--show] [--par N]

<prompt.txt> replaces the request's prompt ('-' keeps the captured one). <scorer> names a
function in lane3_scorers.py taking the list of actions in the first JSON value of the reply
(what NetGet's parser executes) and returning True/False. Prints one line per seed and a TALLY.
"""
import concurrent.futures
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lane3_scorers  # noqa: E402

UP = os.environ.get("REPLAY_UPSTREAM", "http://127.0.0.1:11434")


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
        return [a for a in v["actions"] if isinstance(a, dict)]
    if isinstance(v, dict) and "type" in v:
        return [v]
    if isinstance(v, list):
        return [a for a in v if isinstance(a, dict)]
    return []


def one(req, s):
    r = dict(req)
    r["options"] = dict(req.get("options") or {})
    r["options"]["seed"] = s
    r["stream"] = False
    rq = urllib.request.Request(UP + "/api/generate", data=json.dumps(r).encode(),
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(rq, timeout=900) as resp:
        content = json.load(resp).get("response", "")
    return actions_of(first_json(content)), content


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show = "--show" in sys.argv
    par = 1
    if "--par" in sys.argv:
        par = int(sys.argv[sys.argv.index("--par") + 1])
        args = [a for a in args if a != str(par)]
    req = json.load(open(args[0]))
    if args[1] != "-":
        req["prompt"] = open(args[1]).read()
    scorer = getattr(lane3_scorers, args[2])
    a, b = args[3].split("-")
    seeds = list(range(int(a), int(b) + 1))
    passes = 0
    with concurrent.futures.ThreadPoolExecutor(par) as ex:
        for s, (acts, content) in zip(seeds, ex.map(lambda s: one(req, s), seeds)):
            ok = bool(scorer(acts))
            passes += ok
            desc = json.dumps(acts)[:300] if acts else ("NOJSON " + content[:200].replace("\n", " "))
            print(f"seed {s:3d} {'PASS' if ok else 'fail'} {desc if show or not ok else ''}", flush=True)
    print(f"TALLY {args[1]} {args[2]} {passes}/{len(seeds)}", flush=True)


if __name__ == "__main__":
    main()
