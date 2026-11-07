"""List captured ask-again requests: seed, done list, the latest event data, and the recorded answer."""
import glob, json, re, sys
for case in sys.argv[1:]:
    print("==", case)
    for f in sorted(glob.glob(f"/tmp/telnet-line/rec-m2-{case}/*.req.json")):
        d = json.load(open(f))
        p = d["prompt"]
        m = re.search(r"Already done at the start of this session, and not to be sent again: (.*?)\. Answer", p)
        if not m:
            continue
        data = p.rsplit("Data:", 1)[-1].strip().replace("\n", " ")[:90]
        try:
            resp = json.load(open(f.replace(".req.json", ".resp.json")))["response"]
        except Exception:
            resp = open(f.replace(".req.json", ".resp.json")).read()
        resp = re.sub(r"\s+", " ", resp)[:110]
        print(f"{f.split('/')[-1][:5]} seed={d['options']['seed']} done={m.group(1)[:70]} | {data} | {resp}")
