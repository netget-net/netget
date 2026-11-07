#!/usr/bin/env python3
"""Seeded real-model measurement of client plan-following.

Usage: harness.py <netget-binary> <case> <label> [seeds...]
Cases: redis (scripted), quiz (conversational telnet), again (legitimate repeats).
"""
import json, os, subprocess, sys, tempfile, time

BIN = sys.argv[1]
CASE = sys.argv[2]
LABEL = sys.argv[3]
SEEDS = [int(s) for s in sys.argv[4:]] or list(range(42, 50))
RUN_FOR = int(os.environ.get("RUN_FOR", "60"))
MODEL = os.environ.get("MODEL", "llama3.1:8b")

REDIS_SCRIPT = r'''import json, sys
data = json.load(sys.stdin)
event = data["event"]
args = event.get("args", [])
with open(LOGPATH, "a") as f:
    f.write(" ".join(str(a) for a in args) + "\n")
verb = args[0].upper() if args else ""
if verb == "PING":
    actions = [{"type": "redis_simple_string", "value": "PONG"}]
elif verb == "GET":
    actions = [{"type": "redis_bulk_string", "value": "hello"}]
else:
    actions = [{"type": "redis_simple_string", "value": "OK"}]
print(json.dumps({"actions": actions}))'''

QUIZ_SCRIPT = r'''import json, sys
data = json.load(sys.stdin)
event = data["event"]
m = str(event.get("message", "")).strip()
with open(LOGPATH, "a") as f:
    f.write(m + "\n")
l = m.lower()
if "paris" in l:
    reply = "Correct. Question 2: what is 2 plus 2?"
elif "4" in l or "four" in l:
    reply = "Correct. Question 3: what colour is a clear daytime sky?"
elif "blue" in l:
    reply = "Correct. That was the last question. BYE"
elif "hello" in l or "hi" in l:
    reply = "Welcome to the quiz. Question 1: what is the capital of France?"
else:
    reply = "Please answer the question."
print(json.dumps({"actions": [{"type": "send_telnet_line", "line": reply}]}))'''

AGAIN_SCRIPT = r'''import json, sys
data = json.load(sys.stdin)
event = data["event"]
m = str(event.get("message", "")).strip()
with open(LOGPATH, "a") as f:
    f.write(m + "\n")
with open(LOGPATH) as f:
    pings = sum(1 for line in f if line.strip().upper() == "PING")
reply = "AGAIN" if pings < 3 else "DONE"
print(json.dumps({"actions": [{"type": "send_telnet_line", "line": reply}]}))'''

CASES = {
    "redis": dict(server="redis", client="redis", pattern="redis_command", script=REDIS_SCRIPT,
                  instruction="Send PING, then GET mykey, then stop sending commands."),
    "quiz": dict(server="telnet", client="telnet", pattern="telnet_message_received",
                 script=QUIZ_SCRIPT,
                 instruction="Say hello to the server, then answer each question it asks with a "
                             "short answer. When it says BYE, disconnect."),
    "again": dict(server="telnet", client="telnet", pattern="telnet_message_received",
                  script=AGAIN_SCRIPT,
                  instruction="Send the command PING. Each time the server answers AGAIN, send "
                              "PING again. When it answers DONE, disconnect."),
}


def judge(case, lines):
    if case == "redis":
        ok = lines == ["PING", "GET mykey"]
        return ok, ("ok" if ok else "restart" if len(lines) > 2 else "short")
    if case == "quiz":
        low = [l.lower() for l in lines]
        reached = any("blue" in l for l in low)
        hello = sum(1 for l in low if "hello" in l)
        return reached and hello == 1, f"reached_end={reached} hellos={hello} lines={len(lines)}"
    if case == "again":
        pings = sum(1 for l in lines if l.upper() == "PING")
        return pings == 3 and len(lines) == 3, f"pings={pings} lines={len(lines)}"


def run(seed):
    c = CASES[CASE]
    d = tempfile.mkdtemp(prefix=f"tl-{CASE}-{LABEL}-{seed}-")
    logpath = os.path.join(d, "server.log")
    port = 21000 + {"redis": 0, "quiz": 100, "again": 200}[CASE] + (seed - 42)
    script = c["script"].replace("LOGPATH", repr(logpath))
    cfg = {"actions": [
        {"type": "open_server", "port": port, "host": "127.0.0.1", "base_stack": c["server"],
         "instruction": "",
         "event_handlers": [{"event_pattern": c["pattern"],
                             "handler": {"type": "script", "language": "python",
                                         "code": script}},
                            {"event_pattern": "*",
                             "handler": {"type": "static", "actions": []}}]},
        {"type": "open_client", "protocol": c["client"], "remote_addr": f"127.0.0.1:{port}",
         "instruction": c["instruction"], "batching": False},
    ]}
    if os.environ.get("RESTART_CHECK") in ("0", "false"):
        cfg["actions"][1]["restart_check"] = False
    cfgpath = os.path.join(d, "run.netget")
    with open(cfgpath, "w") as f:
        json.dump(cfg, f)
    t0 = time.time()
    out = open(os.path.join(d, "stdout.txt"), "w")
    proc = subprocess.Popen([BIN, "--load", cfgpath, "--model", MODEL, "--llm-seed", str(seed),
                             "--run-for", str(RUN_FOR)] + (["--ollama-url", os.environ["OLLAMA_URL"]] if os.environ.get("OLLAMA_URL") else []), cwd=d, stdout=out,
                            stderr=subprocess.STDOUT)
    try:
        rc = proc.wait(timeout=RUN_FOR + 90)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        rc = "HUNG"
    out.close()
    class P: pass
    p = P(); p.returncode = rc
    lines = []
    if os.path.exists(logpath):
        lines = [l.rstrip("\n") for l in open(logpath) if l.strip()]
    ok, detail = judge(CASE, lines)
    return dict(seed=seed, ok=ok, detail=detail, lines=lines, secs=round(time.time() - t0),
                dir=d, rc=p.returncode)


results = []
for s in SEEDS:
    r = run(s)
    results.append(r)
    print(f"seed {r['seed']}: {'OK ' if r['ok'] else 'BAD'} {r['detail']} rc={r['rc']} "
          f"{r['secs']}s lines={r['lines'][:14]} dir={r['dir']}", flush=True)
out = f"/tmp/telnet-line/results-{CASE}-{LABEL}.json"
json.dump(results, open(out, "w"), indent=1)
print(f"{CASE}/{LABEL}: {sum(r['ok'] for r in results)}/{len(results)} ok")
