"""Q2 variants: master or shipped wording, with the history's Q1 answer as master or fix ran it."""
import sys
sys.path.insert(0, '/tmp/telnet-line/variants')
from all import VARIANTS

PLAIN = lambda p: p.replace('"command":"answer: Paris"', '"command":"Paris"')
Q2 = {
    "master_plain": PLAIN,
    "B_plain": lambda p: VARIANTS["B_wording"](PLAIN(p)),
    "B": VARIANTS["B_wording"],
}

if __name__ == "__main__":
    for name in Q2:
        with open(f'/tmp/telnet-line/variants/q2_{name}.py', 'w') as out:
            out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                      f"from q2 import Q2\ntransform = Q2[{name!r}]\n")
        print(name)
