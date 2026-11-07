#!/usr/bin/env python3
"""Quiz stats for the telnet line-ending measurement.

q1_line      : the server received a complete line containing "paris"
q1_clean     : ... and that line is not merged with a following "hello"
unterminated : model answer actions that send no line ending (send_text / line_ending none)
"""
import json, re, sys
ANSI = re.compile(r"\x1b\[[0-9;]*m")


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


SENDS = ("send_text", "send_line", "send_command")
for path in sys.argv[1:]:
    rows = json.load(open(path))
    T = dict(q1_line=0, q1_clean=0, end=0, hello_extra=0, unterminated=0, line_acts=0, model_q1=0)
    for r in rows:
        low = [l.lower() for l in r["lines"]]
        text = ANSI.sub("", open(r["dir"] + "/stdout.txt").read())
        answers = re.findall(r"Response \(normalized\): (.*)", text)
        unterm = line = 0
        mq1 = False
        for a in answers:
            for x in acts(first_json(a)):
                t = x.get("type")
                none_end = str(x.get("line_ending", "")).lower() == "none"
                if t == "send_text" or (t in ("send_line", "send_command") and none_end):
                    unterm += 1
                elif t in ("send_line", "send_command"):
                    line += 1
                if t in SENDS and "paris" in json.dumps(x).lower():
                    mq1 = True
        q1 = any("paris" in l for l in low)
        clean = any("paris" in l and "hello" not in l for l in low)
        hellos = sum(1 for l in low if "hello" in l)
        end = any("blue" in l for l in low)
        T["q1_line"] += q1
        T["q1_clean"] += clean
        T["end"] += end
        T["hello_extra"] += max(0, hellos - 1)
        T["unterminated"] += unterm
        T["line_acts"] += line
        T["model_q1"] += mq1
        print(f"  seed {r['seed']}: q1_line={q1} clean={clean} model_sent_paris={mq1} end={end} "
              f"hellos={hellos} line_acts={line} unterminated_acts={unterm} wire={r['lines'][:6]}")
    print(path, T, f"n={len(rows)}")
