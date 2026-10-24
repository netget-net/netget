# A second, independent GRE implementation for tests/server/gre/scapy_peer_test.rs: scapy builds
# GRE packets (key, checksum and sequence number as each case asks) and sends them to NetGet from
# inside a network namespace, then reads what comes back. Its own GRE layer parses the replies,
# and the checksum is recomputed here over the bytes as they crossed the wire.
#
# argv[1] is JSON: {"netget", "me", "iface", "wait", "packets": [spec, ...]}. Each spec:
#   proto, key, csum, seq          the GRE header (key/seq absent or null for none)
#   version, flags_or              forbidden header values to write anyway
#   bad_csum, truncate             corruptions applied to the encoded GRE bytes
#   inner: {"kind": "arp"|"ping"|"udp"|"keepalive"|"short", ...}, "pad": bytes of padding
# Prints one JSON object: {"replies": [...]}, each reply what scapy read from one GRE packet.
import json
import sys
import threading

from scapy.all import ARP, GRE, ICMP, IP, UDP, AsyncSniffer, Ether, Raw, conf, fragment, send
from scapy.utils import checksum

conf.verb = 0
cfg = json.loads(sys.argv[1])
NETGET, ME, IFACE = cfg["netget"], cfg["me"], cfg["iface"]
PEER_MAC = "02:00:00:00:00:01"


def inner(spec, proto):
    i = spec["inner"]
    kind = i["kind"]
    if kind == "arp":
        p = Ether(src=PEER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=PEER_MAC, psrc="10.99.0.1", pdst=i.get("target", "10.99.0.2"))
    elif kind == "ping":
        p = IP(src="10.99.0.1", dst=i.get("dst", "10.99.0.2")) / ICMP(
            type=8, id=i.get("id", 0x1234), seq=i.get("seq", 1)) / Raw(i.get("data", "abc").encode())
        if proto == 0x6558:
            p = Ether(src=PEER_MAC, dst="02:4e:47:00:00:02") / p
    elif kind == "udp":
        p = IP(src="10.99.0.1", dst=i.get("dst", "10.99.0.2")) / UDP(
            sport=5000, dport=i.get("port", 7777)) / Raw(i.get("data", "hi").encode())
        if proto == 0x6558:
            p = Ether(src=PEER_MAC, dst="02:4e:47:00:00:02") / p
    elif kind == "keepalive":
        # Cisco: an IPv4 packet from the far end (NetGet) back to us, carrying a bare GRE
        # header. NetGet should send it on to its destination, which is us.
        p = IP(src=i.get("src", NETGET), dst=i.get("dst", ME), proto=47) / GRE(proto=0)
    elif kind == "short":
        p = Raw(b"\x02\x00\x00\x00\x00")  # an Ethernet frame cut off after five bytes
    else:
        raise SystemExit("unknown inner kind " + kind)
    b = bytes(p)
    return b + b"\x00" * spec.get("pad", 0)


def gre_bytes(spec):
    proto = spec.get("proto", 0x6558)
    g = GRE(proto=proto, version=spec.get("version", 0))
    if spec.get("csum"):
        g.chksum_present = 1
    if spec.get("key") is not None:
        g.key_present = 1
        g.key = spec["key"]
    if spec.get("seq") is not None:
        g.seqnum_present = 1
        g.sequence_number = spec["seq"]
    b = bytearray(bytes(g / Raw(inner(spec, proto))))
    b[0] |= spec.get("flags_or", 0)
    if spec.get("bad_csum"):
        b[5] ^= 0x01
    if spec.get("truncate"):
        b = b[: spec["truncate"]]
    return bytes(b)


def describe(p):
    ip = p[IP]
    wire = bytes(ip)[ip.ihl * 4 :]
    g = GRE(wire)
    r = {
        "proto": g.proto,
        "key": g.key if g.key_present else None,
        "seq": g.sequence_number if g.seqnum_present else None,
        "csum": bool(g.chksum_present),
        "csum_ok": (checksum(wire) == 0) if g.chksum_present else None,
        "len": len(wire),
    }
    if ARP in g:
        a = g[ARP]
        r["arp"] = {"op": a.op, "hwsrc": a.hwsrc, "psrc": a.psrc, "hwdst": a.hwdst, "pdst": a.pdst}
    if ICMP in g:
        c = g[ICMP]
        r["icmp"] = {"type": c.type, "id": c.id, "seq": c.seq, "load": bytes(c.payload).decode("latin-1"),
                     "src": g[IP].src, "dst": g[IP].dst,
                     "ok": checksum(bytes(c)) == 0}
    if UDP in g:
        u = g[UDP]
        r["udp"] = {"sport": u.sport, "dport": u.dport, "load": bytes(u.payload).decode("latin-1"),
                    "src": g[IP].src, "dst": g[IP].dst}
    return r


started = threading.Event()
sniffer = AsyncSniffer(
    iface=IFACE,
    lfilter=lambda p: IP in p and p[IP].src == NETGET and p[IP].proto == 47,
    started_callback=started.set,
    store=True,
)
sniffer.start()
started.wait(10)
outgoing = []
for spec in cfg["packets"]:
    packet = IP(src=ME, dst=NETGET, proto=47) / Raw(gre_bytes(spec))
    # A jumbo GRE packet does not fit the veth's 1500-byte MTU: fragment it, as a router
    # would, and the receiving kernel reassembles it before NetGet's socket sees it.
    outgoing.extend(fragment(packet, fragsize=1400) if len(packet) > 1500 else [packet])
# One call, so a burst leaves as a burst (the rate bound is measured against it).
send(outgoing)
threading.Event().wait(cfg.get("wait", 2.0))
sniffer.stop()
print(json.dumps({"replies": [describe(p) for p in sniffer.results or []]}))
