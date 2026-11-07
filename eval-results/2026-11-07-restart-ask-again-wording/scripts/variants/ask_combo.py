"""The old quiz ask-again prompt (rec-master/00004) brought up to the current telnet wording, then
optionally with an ask-again variant on top."""
import sys
sys.path.insert(0, '/tmp/telnet-line/variants')
from f import V as FV
from ask import V as AV

C = {"cur": FV["F2"]}
for k, f in AV.items():
    C[f"cur_{k}"] = (lambda f: lambda p: f(FV["F2"](p)))(f)

if __name__ == "__main__":
    for name in C:
        with open(f"/tmp/telnet-line/variants/combo_{name}.py", "w") as out:
            out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                      f"from ask_combo import C\ntransform = C[{name!r}]\n")
        print(name)
