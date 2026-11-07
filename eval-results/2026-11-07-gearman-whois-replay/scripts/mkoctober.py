"""Rebuild the gearman prompt as the October (3e2d24bd) shared prompt would have framed it.

Takes the October http capture's shared sections and the current capture's gearman actions,
state and event. usage: mkoctober.py <oct_http_prompt> <current_req.json> <out.txt>
"""
import json
import re
import sys

oct_t = open(sys.argv[1]).read()
cur = json.load(open(sys.argv[2]))["prompt"]

# October: everything before the http action block, minus the instruction text.
pre = oct_t[: oct_t.index("## 4. send_http_response")]
oct_instr = re.search(r"## Event-Specific Instructions\n(.*?)\n\n## Network", oct_t, re.S).group(1)
cur_instr = re.search(r"## Server Instruction\n(.*?)\n\n## Network", cur, re.S).group(1)
pre = pre.replace(oct_instr, cur_instr)

# Current gearman actions: from "## 5. complete_gearman_job" to "## Understanding Memory".
acts = cur[cur.index("## 5. complete_gearman_job") : cur.index("## Understanding Memory")]
acts = re.sub(r"(?m)^## (\d+)\. ", lambda m: f"## {int(m.group(1)) - 1}. ", acts)

# October memory + response format sections, then the current state and event.
mid = oct_t[oct_t.index("## Understanding Memory") : oct_t.index("# Current State")]
tail = cur[cur.index("# Current State") :]
open(sys.argv[3], "w").write(pre + acts + mid + tail)
