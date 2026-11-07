"""Variants of the restart check's ask-again sentence (`client::restart_check::continue_instruction`).

The master sentence is
  "Already done at the start of this session, and not to be sent again: {done}. Answer the
   latest message with what your instruction calls for next; if nothing is left to do, answer
   with no actions."
where {done} is `name {json}; name {json}` for each opening action.
"""
import json
import re
import sys

PAT = re.compile(r"Already done at the start of this session, and not to be sent again: (.*?)\. "
                 r"Answer the latest message with what your instruction calls for next; if nothing "
                 r"is left to do, answer with no actions\.", re.S)


def parse_done(done):
    """[(name, fields)] from `name {json}; name {json}`."""
    out, i, dec = [], 0, json.JSONDecoder()
    while i < len(done):
        m = re.match(r"\s*([A-Za-z0-9_]+)", done[i:])
        if not m:
            break
        name = m.group(1)
        i += m.end()
        fields = {}
        if done[i:i + 1] == " " and done[i + 1:i + 2] == "{":
            fields, end = dec.raw_decode(done[i + 1:])
            i += 1 + end
        out.append((name, fields))
        if done[i:i + 2] == "; ":
            i += 2
        else:
            break
    return out


def describe(name, fields):
    return f"{name} {json.dumps(fields, separators=(',', ':'))}" if fields else name


def content(fields):
    vals = [v for v in fields.values() if isinstance(v, str)]
    return " ".join(vals)


def names_of(items):
    seen = []
    for n, _ in items:
        if n not in seen:
            seen.append(n)
    return ", ".join(seen)


def W1(items):
    done = "; ".join(describe(n, f) for n, f in items)
    return (f"Already sent at the start of this session: {done}. That content is done: do not "
            f"send it again. The action is not used up: {names_of(items)} is still how you send "
            f"anything new, including your answer to the latest message. Answer the latest "
            f"message with what your instruction calls for next; if nothing is left to do, "
            f"answer with no actions.")


def W2(items):
    said = "; ".join(f'"{content(f)}"' if content(f) else n for n, f in items)
    return (f"Already sent at the start of this session, and not to be sent again: {said}. "
            f"Answer the latest message with what your instruction calls for next, with the "
            f"same actions as always ({names_of(items)} included); if nothing is left to do, "
            f"answer with no actions.")


def W3(items):
    done = "; ".join(describe(n, f) for n, f in items)
    return (f"Already done at the start of this session: {done}. Do not send that content "
            f"again; {names_of(items)} is still the way to send anything new. Answer the latest "
            f"message with what your instruction calls for next; if nothing is left to do, "
            f"answer with no actions.")


def W4(items):
    done = "; ".join(describe(n, f) for n, f in items)
    return (f"Already sent at the start of this session: {done}. That content is done: do not "
            f"send it again. The action is not used up: {names_of(items)} is still how you send "
            f"anything new. Answer the latest message with what your instruction calls for next; "
            f"if nothing is left to do, answer with no actions.")


def W5(items):
    done = "; ".join(describe(n, f) for n, f in items)
    return (f"Already done at the start of this session: {done}. Those lines or commands must "
            f"not be sent again; {names_of(items)} is still the way to send anything new. Answer "
            f"the latest message with what your instruction calls for next; if nothing is left to "
            f"do, answer with no actions.")


def make(fn):
    def transform(p):
        m = PAT.search(p)
        assert m, "no ask-again sentence"
        return p[:m.start()] + fn(parse_done(m.group(1))) + p[m.end():]
    return transform


V = {"W1": make(W1), "W2": make(W2), "W3": make(W3), "W4": make(W4), "W5": make(W5)}

if __name__ == "__main__":
    for name in V:
        with open(f"/tmp/telnet-line/variants/ask_{name}.py", "w") as out:
            out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                      f"from ask import V\ntransform = V[{name!r}]\n")
        print(name)
    sample = ("X\n\nAlready done at the start of this session, and not to be sent again: "
              'execute_redis_command {"command":"PING"}; execute_redis_command {"command":"GET mykey"}. '
              "Answer the latest message with what your instruction calls for next; if nothing is "
              "left to do, answer with no actions.\n")
    for name, f in V.items():
        print(f(sample))
