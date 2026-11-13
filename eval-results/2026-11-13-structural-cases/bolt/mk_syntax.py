#!/usr/bin/env python3
"""The bolt/syntax-error case's login prompt, from the count case's captured prompts (the
instruction is the only per-case text in a login prompt)."""
old = ("Act as a Neo4j graph database that accepts any login. It holds exactly 42 Movie nodes and "
       "nothing else.")
new = ("Act as a Neo4j graph database that accepts any login. Reject any query that is not valid "
       "Cypher with Neo4j's syntax error.")
for src, dst in (("login-master.txt", "login-syntax-master.txt"),
                 ("login-branch.txt", "login-syntax-branch.txt")):
    p = open("/tmp/netget-r3-l4/work/bolt/" + src).read()
    assert p.count(old) == 2, (src, p.count(old))
    open("/tmp/netget-r3-l4/work/bolt/" + dst, "w").write(p.replace(old, new))
print("ok")
