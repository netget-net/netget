#!/usr/bin/env python3
"""Build named prompt variants of a W3 prompt for one case.

usage: variants.py <pre.txt> <w3.txt> <outdir> <case>

Writes <outdir>/<case>-<variant>.txt for:
  pre          the prompt before W3
  w3           the prompt with W3
  w3-rev-instr     W3 with the network-instruction wording reverted (hunk group A)
  w3-rev-memdesc   W3 with set/append_memory descriptions and examples reverted (B)
  w3-rev-actions   W3 with the action list reverted: show_message back, no
                   connection-memory actions (C)
  w3-rev-partial   W3 with the memory partial reverted (D)
  w3-noconn        W3 without the two connection-memory actions and their bullet
                   (notify_operator stays withheld)
  w3-notify        W3 with notify_operator listed again (connection memory kept)
  w3-protofirst    W3 with the protocol's own actions listed before the common ones
  w3-noconn-protofirst
"""
import difflib
import os
import re
import sys

pre_path, w3_path, outdir, case = sys.argv[1:5]
pre = open(pre_path).read()
w3 = open(w3_path).read()
os.makedirs(outdir, exist_ok=True)

COMMON = {
    "set_memory", "append_memory", "set_connection_memory", "append_connection_memory",
    "notify_operator", "show_message", "append_to_log", "provide_feedback",
}


def write(name, text):
    open(os.path.join(outdir, f"{case}-{name}.txt"), "w").write(text)


def classify(old_lines, new_lines):
    text = "".join(old_lines + new_lines)
    if "Maintain state if needed" in text or "reach the peer" in text or "only notifies the NetGet operator" in text:
        return "A"
    if re.search(r"^## \d+\. ", text, re.M) or "connection_memory" in text or "show_message" in text \
            or "Display a message" in text or "Message to display" in text \
            or "connection's new notes" in text or "THIS connection" in text:
        # the memory partial bullet mentions connection memory too
        if "**Facts about the peer" in text or "Add to existing memory" in text:
            return "D"
        return "C"
    if "Memory is a **string**" in text or "**Example:**" in text or "Add to existing memory" in text:
        return "D"
    return "B"


def revert(groups):
    old = pre.splitlines(keepends=True)
    new = w3.splitlines(keepends=True)
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    res = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            res.extend(new[j1:j2])
            continue
        g = classify(old[i1:i2], new[j1:j2])
        res.extend(old[i1:i2] if g in groups else new[j1:j2])
    return "".join(res)


def split_actions(text):
    """Return (head, [(name, block)], tail) for the '# Available Actions' list."""
    start = text.index("# Available Actions")
    first = re.search(r"(?m)^## \d+\. ", text[start:])
    a = start + first.start()
    end_m = re.search(r"(?m)^(# |## Understanding Memory)", text[a:])
    b = a + end_m.start() if end_m else len(text)
    body = text[a:b]
    parts = re.split(r"(?m)^(?=## \d+\. )", body)
    blocks = []
    for p in parts:
        if not p:
            continue
        name = re.match(r"## \d+\. (\S+)", p).group(1)
        blocks.append((name, p))
    return text[:a], blocks, text[b:]


def join_actions(head, blocks, tail):
    out = []
    for i, (name, p) in enumerate(blocks):
        out.append(re.sub(r"^## \d+\. ", f"## {i}. ", p, count=1))
    return head + "".join(out) + tail


def noconn(text):
    h, bl, t = split_actions(text)
    bl = [b for b in bl if b[0] not in ("set_connection_memory", "append_connection_memory")]
    return re.sub(r"(?m)^- \*\*Facts about the peer on this connection\*\*.*\n", "", join_actions(h, bl, t))


def protofirst(text):
    h, bl, t = split_actions(text)
    proto = [b for b in bl if b[0] not in COMMON]
    common = [b for b in bl if b[0] in COMMON]
    return join_actions(h, proto + common, t)


NOTIFY_BLOCK = """## 0. notify_operator

Show a note to the person operating NetGet, on their own screen. It is NOT sent over the network: the peer, client or server on the other end never sees it. To say anything to them, use this protocol's own send or response action.

Parameters:
- `message` (string, required): The note for the operator (never transmitted)

Example:
```json
{"type":"notify_operator","message":"Server #1 is listening on port 8080"}
```

"""


def notify(text):
    h, bl, t = split_actions(text)
    idx = next(i for i, b in enumerate(bl) if b[0] == "append_to_log")
    bl.insert(idx, ("notify_operator", NOTIFY_BLOCK))
    return join_actions(h, bl, t)


write("pre", pre)
write("w3", w3)
write("w3-rev-instr", revert({"A"}))
write("w3-rev-memdesc", revert({"B"}))
write("w3-rev-actions", revert({"C"}))
write("w3-rev-partial", revert({"D"}))
write("w3-noconn", noconn(w3))
write("w3-notify", notify(w3))
write("w3-protofirst", protofirst(w3))
write("w3-noconn-protofirst", protofirst(noconn(w3)))
write("pre-protofirst", protofirst(pre))
