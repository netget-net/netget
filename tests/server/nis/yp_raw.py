"""A NIS (YP v2) caller written from yp.x with python's struct module, independent of
NetGet's encoder and decoder: it assembles each call and decodes each result itself.

usage: python3 yp_raw.py HOST PORT tcp|udp CALLS_JSON

CALLS_JSON is a list of calls:
  {"proc": 3, "args": [["s", "netget.test"], ["s", "passwd.byname"], ["o", "alice"]],
   "decode": "val", "prog": 100004, "vers": 2, "rpcvers": 2}
args: "s" an XDR string, "o" an opaque, "u" an unsigned int, "raw" hex bytes as given.
decode: void, bool, val, key_val, all, master, order, maplist, or words (the reply as
32-bit words, for RPC-level errors).

Prints one JSON list: per call {"reply": [...words of the RPC header...], "accept_stat": n,
"result": ...} or {"timeout": true}. Over TCP every call shares one connection.
"""
import json
import socket
import struct
import sys

host, port, transport, calls = sys.argv[1], int(sys.argv[2]), sys.argv[3], json.loads(sys.argv[4])


def pad(b):
    return b + b"\0" * ((4 - len(b) % 4) % 4)


def opaque(b):
    return struct.pack(">I", len(b)) + pad(b)


def encode_args(args):
    out = b""
    for kind, v in args:
        if kind == "s":
            out += opaque(v.encode())
        elif kind == "o":
            out += opaque(v.encode())
        elif kind == "u":
            out += struct.pack(">I", v)
        elif kind == "raw":
            out += bytes.fromhex(v)
    return out


class R:
    def __init__(self, b):
        self.b, self.p = b, 0

    def u(self):
        v = struct.unpack(">I", self.b[self.p:self.p + 4])[0]
        self.p += 4
        return v

    def i(self):
        v = struct.unpack(">i", self.b[self.p:self.p + 4])[0]
        self.p += 4
        return v

    def o(self):
        n = self.u()
        v = self.b[self.p:self.p + n]
        assert len(v) == n, "opaque runs past the reply"
        self.p += n + (4 - n % 4) % 4
        return v.decode("utf-8", "replace")


STAT = {1: "YP_TRUE", 2: "YP_NOMORE", 0: "YP_FALSE", -1: "YP_NOMAP", -2: "YP_NODOM",
        -3: "YP_NOKEY", -4: "YP_BADOP", -5: "YP_BADDB", -6: "YP_YPERR", -7: "YP_BADARGS",
        -8: "YP_VERS"}


def decode(kind, r):
    if kind == "void":
        return None
    if kind == "bool":
        return r.u()
    if kind == "val":
        s = STAT[r.i()]
        return {"stat": s, "val": r.o()}
    if kind == "key_val":
        s = STAT[r.i()]
        val = r.o()
        return {"stat": s, "key": r.o(), "val": val}
    if kind == "all":
        out, records = [], 0
        while r.u() == 1:
            records += 1
            s = STAT[r.i()]
            val = r.o()
            key = r.o()
            out.append({"stat": s, "key": key, "val": val})
        assert r.p == len(r.b), "bytes after more=FALSE"
        return out
    if kind == "master":
        s = STAT[r.i()]
        return {"stat": s, "peer": r.o()}
    if kind == "order":
        s = STAT[r.i()]
        return {"stat": s, "order": r.u()}
    if kind == "maplist":
        s = STAT[r.i()]
        maps = []
        while r.u() == 1:
            maps.append(r.o())
        return {"stat": s, "maps": maps}
    raise ValueError(kind)


def recv_exact(s, n):
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            raise EOFError
        d += c
    return d


def read_record(s):
    out = b""
    fragments = 0
    while True:
        h = struct.unpack(">I", recv_exact(s, 4))[0]
        fragments += 1
        out += recv_exact(s, h & 0x7FFFFFFF)
        if h & 0x80000000:
            return out, fragments


if transport == "tcp":
    sock = socket.create_connection((host, port), timeout=20)
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(calls[0].get("udp_timeout", 20)) if calls else 20)

results = []
for n, c in enumerate(calls):
    xid = 0x4E490000 + n
    body = struct.pack(">IIIIII", xid, 0, c.get("rpcvers", 2), c.get("prog", 100004),
                       c.get("vers", 2), c["proc"])
    body += struct.pack(">IIII", 0, 0, 0, 0) + encode_args(c.get("args", []))
    try:
        if transport == "tcp":
            sock.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
            msg, fragments = read_record(sock)
        else:
            sock.settimeout(float(c.get("udp_timeout", 20)))
            sock.sendto(body, (host, port))
            msg, fragments = sock.recv(70000), 1
    except (socket.timeout, EOFError) as e:
        results.append({"timeout": True, "why": type(e).__name__})
        if transport == "tcp":
            break
        continue
    r = R(msg)
    got_xid, mtype, reply_stat = r.u(), r.u(), r.u()
    assert got_xid == xid and mtype == 1, (got_xid, xid, mtype)
    res = {"reply_stat": reply_stat, "fragments": fragments, "length": len(msg)}
    if reply_stat == 0:
        r.u()
        r.o()
        res["accept_stat"] = r.u()
        if res["accept_stat"] == 0:
            res["result"] = decode(c.get("decode", "void"), r)
            if c.get("decode") not in ("all",):
                assert r.p == len(r.b), "trailing bytes in the result"
        elif res["accept_stat"] == 2:
            res["low_high"] = [r.u(), r.u()]
    else:
        res["words"] = [r.u() for _ in range((len(msg) - r.p) // 4)]
    results.append(res)
print(json.dumps(results))
