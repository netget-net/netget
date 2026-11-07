"""Per run: did the client hang up itself (the telnet client logs "disconnecting" on a model disconnect)?"""
import json, re, sys
ANSI = re.compile(r"\x1b\[[0-9;]*m")
for path in sys.argv[1:]:
    rows = json.load(open(path))
    n = 0
    out = []
    for r in rows:
        t = ANSI.sub("", open(r["dir"] + "/stdout.txt").read())
        hung = bool(re.search(r"client client-\d+ disconnecting|Action: disconnect", t, re.I))
        n += hung
        out.append(f"{r['seed']}:{'Y' if hung else '-'}")
    print(path.split('/')[-1], "hung up:", n, "of", len(rows), " ".join(out))
