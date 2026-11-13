#!/usr/bin/env python3
"""Make bolt login prompt variants from a captured master prompt.

usage: bolt_variants.py <master.txt> <outprefix> <login sentence>
"""
import sys

src, prefix, sentence = sys.argv[1:4]
p = open(src).read()


def narrow(t):
    # Drop the memory/log action sections and close_connection, keep accept/reject.
    start = t.index("## 0. set_memory")
    acc = t.index("## 5. accept_bolt_login")
    t = t[:start] + t[acc:]
    t = t.replace("## 5. accept_bolt_login", "## 0. accept_bolt_login")
    t = t.replace("## 6. reject_bolt_login", "## 1. reject_bolt_login")
    c0 = t.index("## 7. close_connection")
    c1 = t.index("## Understanding Memory")
    t = t[:c0] + t[c1:]
    return t


def policy(t):
    old = ('may log in. accept_bolt_login unless your instructions refuse this user, this scheme, '
           'or a login without a credential.')
    assert t.count(old) == 1, old
    new = ('may log in. Your instructions say about logins: \\"' + sentence + '\\" '
           'accept_bolt_login unless that refuses this user, this scheme, or a login without a '
           'credential.')
    return t.replace(old, new)


open(prefix + "-n1.txt", "w").write(narrow(p))
open(prefix + "-p1.txt", "w").write(policy(p))
open(prefix + "-np1.txt", "w").write(policy(narrow(p)))
print("ok")
