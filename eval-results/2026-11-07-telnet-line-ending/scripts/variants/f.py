"""Shipped action wording with an event description that does not say "answer"."""
import sys
sys.path.insert(0, '/tmp/telnet-line/variants')
from common import CMD_BLOCK, TEXT_BLOCK, EVENT_DESC, sub
from all import CMD_B, TEXT_B, ev

PLAIN = lambda p: p.replace('"command":"answer: Paris"', '"command":"Paris"')
EV_F = ev("Reply with send_command, which sends one line,")
F = lambda p: sub(sub(sub(p, CMD_BLOCK, CMD_B), TEXT_BLOCK, TEXT_B), EVENT_DESC, EV_F)
F2 = lambda p: sub(sub(p, CMD_BLOCK, CMD_B), TEXT_BLOCK, TEXT_B)
V = {
    "F": F,
    "F2": F2,
    "F_plain": lambda p: F(PLAIN(p)),
    "F2_plain": lambda p: F2(PLAIN(p)),
}

if __name__ == "__main__":
    for name in V:
        with open(f'/tmp/telnet-line/variants/f_{name}.py', 'w') as out:
            out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                      f"from f import V\ntransform = V[{name!r}]\n")
        print(name)
