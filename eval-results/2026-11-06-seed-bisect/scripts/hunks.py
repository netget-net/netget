#!/usr/bin/env python3
"""Line-level hunks between two system prompts, and hybrids built from them.

usage:
  hunks.py list <old.txt> <new.txt>
      print each hunk with its index
  hunks.py build <old.txt> <new.txt> <out.txt> <indices>
      write NEW with the listed hunks reverted to OLD (indices comma-separated,
      'none' for none)
"""
import difflib
import sys


def hunks(a, b):
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return [op for op in sm.get_opcodes() if op[0] != "equal"]


def main():
    cmd = sys.argv[1]
    old = open(sys.argv[2]).read().splitlines(keepends=True)
    new = open(sys.argv[3]).read().splitlines(keepends=True)
    hs = hunks(old, new)
    if cmd == "list":
        for i, (tag, i1, i2, j1, j2) in enumerate(hs):
            print(f"=== hunk {i} {tag} old[{i1}:{i2}] new[{j1}:{j2}]")
            for line in old[i1:i2]:
                print("- " + line.rstrip("\n")[:160])
            for line in new[j1:j2]:
                print("+ " + line.rstrip("\n")[:160])
        return
    out, idx = sys.argv[4], sys.argv[5]
    revert = set() if idx == "none" else {int(x) for x in idx.split(",")}
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    res = []
    k = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            res.extend(new[j1:j2])
            continue
        res.extend(old[i1:i2] if k in revert else new[j1:j2])
        k += 1
    open(out, "w").write("".join(res))


if __name__ == "__main__":
    main()
