"""Changes that should not matter, on the plain-history Q2 prompt: how much does Q2 move by itself?"""
import sys
sys.path.insert(0, '/tmp/telnet-line/variants')
from common import CMD_BLOCK, TEXT_BLOCK, EVENT_DESC, sub
from all import TEXT_B, block, ev

PLAIN = lambda p: p.replace('"command":"answer: Paris"', '"command":"Paris"')
EV_NEUTRAL = ev("Reply with send_command, which sends one line,")
EV_NEUTRAL2 = ev("Reply with send_command (it sends one line ending in CRLF),")
CMD_C = block("send_command",
              "Send one line to the Telnet server (CRLF is appended). Use it for commands and "
              "for replies to the server's prompts and questions.",
              ["command: string (required) - The text of the line, without a line ending"],
              [("type", "send_command"), ("command", "ls -la")])

P = {
    # null edits
    "null_server": lambda p: PLAIN(p).replace("Send a text command to the Telnet server", "Send a text command to the telnet server"),
    "null_example": lambda p: PLAIN(p).replace('"text": "yes"', '"text": "y"'),
    # candidate event wordings without the word "answer"
    "ev_neutral": lambda p: sub(PLAIN(p), EVENT_DESC, EV_NEUTRAL),
    "ev_neutral2": lambda p: sub(PLAIN(p), EVENT_DESC, EV_NEUTRAL2),
    "C_full": lambda p: sub(sub(sub(PLAIN(p), CMD_BLOCK, CMD_C), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_NEUTRAL),
}
Q1 = {
    "C_full": lambda p: sub(sub(sub(p, CMD_BLOCK, CMD_C), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_NEUTRAL),
}

if __name__ == "__main__":
    for d, prefix in ((P, "q2n"), (Q1, "q1n")):
        for name in d:
            with open(f'/tmp/telnet-line/variants/{prefix}_{name}.py', 'w') as out:
                out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                          f"from q2null import {'P' if prefix == 'q2n' else 'Q1'} as D\ntransform = D[{name!r}]\n")
            print(prefix, name)
