#!/usr/bin/env python3
"""Replay a recorded NetGet -> Ollama /api/chat request over many seeds.

usage: replay.py <req.json> <pass_regex> <seeds e.g. 1-20> [--variant name] [--show]

The request body is sent unchanged except for options.seed (and whatever the
variant does to the messages). Each reply's message content is tested against
pass_regex (Python re, DOTALL). Prints one line per seed and a tally.

Variants (applied to the system prompt, messages[0]):
  none                 unchanged
  no_conn_mem          remove the set_connection_memory / append_connection_memory
                       action blocks and the memory-partial bullet about them
  conn_mem_last        move the two connection-memory action blocks to the end of the list
"""
import json
import re
import sys
import urllib.request

UP = "http://127.0.0.1:11434"


def parse_seeds(s):
    out = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def action_blocks(text):
    """Split the Available Actions section into (prefix, [blocks], suffix).

    Each action block in NetGet's prompt starts with a line '### <n>. <name>' or
    similar; we find them by a heading regex and fall back to no-op."""
    m = list(re.finditer(r"(?m)^(#{2,4} *\d+\. *`?([a-z_0-9]+)`?.*)$", text))
    return m


def drop_action(text, name):
    ms = action_blocks(text)
    for i, m in enumerate(ms):
        if m.group(2) == name:
            end = ms[i + 1].start() if i + 1 < len(ms) else None
            if end is None:
                # last block: cut to the next top-level heading
                nxt = re.search(r"(?m)^#{1,2} [^#]", text[m.end():])
                end = m.end() + nxt.start() if nxt else len(text)
            return text[: m.start()] + text[end:], text[m.start():end]
    return text, None


VARIANTS = {}


def variant(fn):
    VARIANTS[fn.__name__] = fn
    return fn


@variant
def none(msgs):
    return msgs


def _sys(msgs):
    return msgs[0]["content"]


@variant
def no_conn_mem(msgs):
    t = _sys(msgs)
    for n in ("set_connection_memory", "append_connection_memory"):
        t, _ = drop_action(t, n)
    t = re.sub(r"(?m)^- \*\*Facts about the peer on this connection\*\*.*\n", "", t)
    msgs[0]["content"] = t
    return msgs


@variant
def no_conn_mem_actions_only(msgs):
    t = _sys(msgs)
    for n in ("set_connection_memory", "append_connection_memory"):
        t, _ = drop_action(t, n)
    msgs[0]["content"] = t
    return msgs


def main():
    req_path, pass_re, seeds = sys.argv[1], sys.argv[2], parse_seeds(sys.argv[3])
    vname = "none"
    show = "--show" in sys.argv
    if "--variant" in sys.argv:
        vname = sys.argv[sys.argv.index("--variant") + 1]
    dump = None
    if "--dump" in sys.argv:
        dump = sys.argv[sys.argv.index("--dump") + 1]
    req = json.load(open(req_path))
    if "--prompt-file" in sys.argv:
        req["prompt"] = open(sys.argv[sys.argv.index("--prompt-file") + 1]).read()
        vname = "file:" + sys.argv[sys.argv.index("--prompt-file") + 1]
    if dump:
        open(dump, "w").write(req["prompt"])
    req["stream"] = False
    rx = re.compile(pass_re, re.S)
    passes = 0
    for s in seeds:
        req.setdefault("options", {})["seed"] = s
        # A reply that runs past 2048 tokens is a regurgitated prompt, never an answer; the
        # cap only cuts generation short and does not change the tokens drawn before it.
        req["options"]["num_predict"] = 2048
        body = json.dumps(req).encode()
        r = urllib.request.Request(UP + "/api/generate", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=900) as resp:
            out = json.load(resp)
        content = out.get("response", "")
        ok = bool(rx.search(content))
        passes += ok
        one = re.sub(r"\s+", " ", content)[:300]
        print(f"seed {s:3d} {'PASS' if ok else 'fail'} {one if show or not ok else ''}", flush=True)
    print(f"TALLY variant={vname} {passes}/{len(seeds)}", flush=True)


if __name__ == "__main__":
    main()
