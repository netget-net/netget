#!/usr/bin/env python3
"""Replay a captured NetGet -> Ollama request over seeds, with the prompt optionally rewritten.

usage: replay.py <req.json> <variant.py|-> <seeds a-b> [--show]

<variant.py> defines `transform(prompt: str) -> str`; "-" replays unchanged.
Each reply's first JSON value is scored by the first action that sends anything:
  LINE  send_command / send_line with no line_ending "none" (a CRLF-terminated line)
  TEXT  send_text, or a line action with line_ending "none" (no line ending)
  other anything else (wait_for_more first, nothing parseable, ...)
"""
import json, runpy, sys, urllib.request

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


def acts(v):
    if isinstance(v, dict) and isinstance(v.get("actions"), list):
        return [a for a in v["actions"] if isinstance(a, dict)]
    if isinstance(v, dict) and "type" in v:
        return [v]
    if isinstance(v, list):
        return [a for a in v if isinstance(a, dict)]
    return []


def classify(actions):
    for a in actions:
        t = a.get("type")
        if t == "send_text":
            return "TEXT"
        if t in ("send_line", "send_command"):
            if str(a.get("line_ending", "")).lower() == "none":
                return "TEXT"
            return "LINE"
    return "other"


def main():
    req = json.load(open(sys.argv[1]))
    key = "prompt" if "prompt" in req else None
    if sys.argv[2] != "-":
        transform = runpy.run_path(sys.argv[2])["transform"]
        if key:
            req[key] = transform(req[key])
        else:
            for m in req["messages"]:
                m["content"] = transform(m["content"])
    a, b = sys.argv[3].split("-")
    show = "--show" in sys.argv
    path = "/api/generate" if key else "/api/chat"
    req["stream"] = False
    tally = {"LINE": 0, "TEXT": 0, "other": 0}
    for s in range(int(a), int(b) + 1):
        req.setdefault("options", {})["seed"] = s
        r = urllib.request.Request(UP + path, data=json.dumps(req).encode(),
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=900) as resp:
            body = json.load(resp)
        content = body.get("response") if key else body.get("message", {}).get("content", "")
        ac = acts(first_json(content or ""))
        c = classify(ac)
        tally[c] += 1
        print(f"seed {s:3d} {c:5s} {json.dumps(ac)[:200] if show or c != 'LINE' else ''}", flush=True)
    print(f"TALLY {sys.argv[1].split('/')[-1]} {sys.argv[2]} {tally}", flush=True)


if __name__ == "__main__":
    main()
