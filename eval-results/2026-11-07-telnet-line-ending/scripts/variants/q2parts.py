"""Which part of the shipped wording changes the Q2 answer? Each applies one part to the plain-history Q2 prompt."""
import sys
sys.path.insert(0, '/tmp/telnet-line/variants')
from common import CMD_BLOCK, TEXT_BLOCK, EVENT_DESC, sub
from all import CMD_B, TEXT_B, ev, block

PLAIN = lambda p: p.replace('"command":"answer: Paris"', '"command":"Paris"')
EV_B = ev("Reply with send_command (one line, the usual answer),")

# Alternative send_command wordings.
CMD_ALT1 = block("send_command",
                 "Send one line to the Telnet server, with the line ending (CRLF) added for you. "
                 "Use it for anything the server should read as a line: a command, a reply, a "
                 "login name.",
                 ["command: string (required) - The line to send, without a line ending"],
                 [("type", "send_command"), ("command", "ls -la")])
CMD_ALT2 = block("send_command",
                 "Send a line of text to the Telnet server (CRLF is appended). Use it for commands "
                 "and for answers to the server's prompts and questions.",
                 ["command: string (required) - The text of the line (CRLF will be appended)"],
                 [("type", "send_command"), ("command", "ls -la")])

P = {
    "cmd_only": lambda p: sub(PLAIN(p), CMD_BLOCK, CMD_B),
    "text_only": lambda p: sub(PLAIN(p), TEXT_BLOCK, TEXT_B),
    "ev_only": lambda p: sub(PLAIN(p), EVENT_DESC, EV_B),
    "alt1_full": lambda p: sub(sub(sub(PLAIN(p), CMD_BLOCK, CMD_ALT1), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_B),
    "alt2_full": lambda p: sub(sub(sub(PLAIN(p), CMD_BLOCK, CMD_ALT2), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_B),
}
# The same alternatives without the plain-history rewrite, for the Q1 prompts.
Q1 = {
    "alt1_full": lambda p: sub(sub(sub(p, CMD_BLOCK, CMD_ALT1), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_B),
    "alt2_full": lambda p: sub(sub(sub(p, CMD_BLOCK, CMD_ALT2), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_B),
}

if __name__ == "__main__":
    for d, prefix in ((P, "q2p"), (Q1, "q1p")):
        for name in d:
            with open(f'/tmp/telnet-line/variants/{prefix}_{name}.py', 'w') as out:
                out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                          f"from q2parts import {'P' if prefix == 'q2p' else 'Q1'} as D\ntransform = D[{name!r}]\n")
            print(prefix, name)
