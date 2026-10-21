#!/usr/bin/env python3
"""Regenerate `fuzz/corpus/` — the committed seed inputs for every fuzz target.

Run as: `python3 fuzz/seed_corpus.py .` from the repository root.

Two kinds of seed live here, and the second is the one worth understanding.

**Valid messages.** A fuzzer that starts from random bytes spends its whole budget
rediscovering the header of every protocol. These are the shapes the real decoders
accept, from the protocols' own tests and their RFCs, so libFuzzer starts at the edges
that matter instead of at byte zero.

**Depth bombs**, for the decoders that have a nesting guard. Coverage-guided
fuzzing gives *no gradient toward depth*: a value nested 10,000 deep executes exactly
the same basic blocks as one nested 3 deep, so libFuzzer scores it as uninteresting and
throws it away. It will not grow one on its own. This was measured, not assumed — with
`utils::bencode`'s guard removed and no deep seed, 300 seconds and 15.5M executions
found nothing; with the bomb seeded, the same build died in 2.8 seconds. Every one of
this repository's eight stack overflows is in that class, so a corpus without depth in it
cannot find the next one.

With the guards in place the bombs are refused in microseconds and nothing downstream
sees them, so they cost the running fuzzer nothing. They exist for the day a guard
regresses.

This file is the provenance for 136 otherwise-opaque binary blobs; edit it rather than
the blobs.
"""
import os
import struct
import sys

ROOT = sys.argv[1]
CORPUS = os.path.join(ROOT, "fuzz", "corpus")


def write(target, name, data):
    d = os.path.join(CORPUS, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


# --- bencode: KRPC ping, and the shapes the guard has to get right ---------
write("bencode_structure", "krpc_ping",
      b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
write("bencode_structure", "krpc_find_node",
      b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e"
      b"1:q9:find_node1:t2:aa1:y1:qe")
write("bencode_structure", "int", b"i42e")
write("bencode_structure", "negative_int", b"i-1e")
write("bencode_structure", "list", b"l4:spam4:eggse")
write("bencode_structure", "nested", b"lli1eeli2eee")
write("bencode_structure", "empty_string", b"0:")
write("bencode_structure", "at_depth_limit", b"l" * 32 + b"e" * 32)

# A depth bomb, deliberately committed as a seed. With the guard in place it is refused
# in microseconds and nothing downstream sees it, so it costs the fuzzer nothing. Its
# purpose is the day the guard regresses: coverage-guided fuzzing gives **no gradient
# toward nesting depth** — a deeper value exercises exactly the same basic blocks, so
# libFuzzer discards it as uninteresting and will not grow one on its own. Measured here:
# with the guard removed and no deep seed, 300 seconds and 15.5M executions found nothing;
# with this seed present the crash is immediate. A depth-class bug is found only if the
# corpus already contains depth.
#
# It also sets libFuzzer's default -max_len (which it infers from the largest corpus
# entry), so the depth needed to overflow an 8 MiB main thread is reachable at all —
# under the 4096-byte default it is not. Note the module doc's "9,215 levels" figure is
# from a debug build; measured against this optimised fuzz build 12,000 levels survived
# and 20,000 died, so the bomb is sized well past either.
write("bencode_structure", "depth_bomb", b"l" * 32768)

# --- SNMP: v2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0) --------------
def ber(tag, payload):
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    ln = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + payload


oid_sysdescr = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])  # 1.3 packed, then the rest
varbind = ber(0x30, ber(0x06, oid_sysdescr) + ber(0x05, b""))
varbinds = ber(0x30, varbind)
pdu = ber(0xA0, ber(0x02, b"\x00\x00\x00\x01") + ber(0x02, b"\x00") +
          ber(0x02, b"\x00") + varbinds)
for community in (b"public", b"private"):
    msg = ber(0x30, ber(0x02, b"\x01") + ber(0x04, community) + pdu)
    write("snmp_ber", "getrequest_" + community.decode(), msg)
write("snmp_ber", "at_depth_limit", b"".join(bytes([0x30, 0x80]) for _ in range(15)) +
      b"\x05\x00" + b"\x00\x00" * 15)
write("snmp_ber", "depth_bomb",
      b"".join(bytes([0x30, 0x80]) for _ in range(16384)))

# --- AMQP field table: {"product": S"NetGet", "copy": t True} -------------
def amqp_shortstr(s):
    return bytes([len(s)]) + s


def amqp_longstr(s):
    return struct.pack(">I", len(s)) + s


entries = (amqp_shortstr(b"product") + b"S" + amqp_longstr(b"NetGet") +
           amqp_shortstr(b"copy") + b"t" + b"\x01" +
           amqp_shortstr(b"count") + b"I" + struct.pack(">i", 7))
write("amqp_field_table", "client_properties", struct.pack(">I", len(entries)) + entries)
nested_inner = amqp_shortstr(b"a") + b"s" + amqp_shortstr(b"b")
nested = amqp_shortstr(b"caps") + b"F" + struct.pack(">I", len(nested_inner)) + nested_inner
write("amqp_field_table", "nested_table", struct.pack(">I", len(nested)) + nested)
write("amqp_field_table", "empty", struct.pack(">I", 0))

# Nested AMQP field tables cost the peer five bytes per level, which is what made one
# 128 KiB frame worth ~26,000 levels before MAX_FIELD_TABLE_DEPTH existed.
def amqp_nest(levels):
    inner = struct.pack(">I", 0)
    for _ in range(levels):
        body = amqp_shortstr(b"n") + b"F" + inner
        inner = struct.pack(">I", len(body)) + body
    return inner


write("amqp_field_table", "depth_bomb", amqp_nest(6000))

# --- NATS: the target's first byte is max_payload, the rest is the wire ----
NATS_PREFIX = b"\x40"  # 0x40 << 24 = 1 GiB payload bound
for name, frame in [
    ("connect", b"CONNECT {\"verbose\":false}\r\n"),
    ("ping", b"PING\r\n"),
    ("sub", b"SUB foo.bar 1\r\n"),
    ("pub", b"PUB foo.bar 5\r\nhello\r\n"),
    ("hpub", b"HPUB foo 22 27\r\nNATS/1.0\r\nX-A: b\r\n\r\nhello\r\n"),
    ("unsub", b"UNSUB 1 5\r\n"),
]:
    write("nats_frame", name, NATS_PREFIX + frame)
# NATS does not nest either. Its stack overflow was `parse_frame` recursing once per blank line
# (8 KB of newlines, one `read`, killed the process); `blank_line_prefix_len` is now a loop.
# The blank-line run is that class's depth bomb: 32 Ki of them ahead of a PING.
write("nats_frame", "blank_line_bomb", NATS_PREFIX + b"\r\n" * 32768 + b"PING\r\n")

# --- STOMP ----------------------------------------------------------------
write("stomp_frame", "connect",
      b"CONNECT\naccept-version:1.2\nhost:localhost\n\n\x00")
write("stomp_frame", "send_with_len",
      b"SEND\ndestination:/queue/a\ncontent-length:5\n\nhello\x00")
write("stomp_frame", "send_no_len", b"SEND\ndestination:/queue/a\n\nhello\x00")
write("stomp_frame", "subscribe",
      b"SUBSCRIBE\nid:0\ndestination:/queue/a\nack:client\n\n\x00")
write("stomp_frame", "escaped_header",
      b"SEND\ndestination:/queue/a\nx\\ckey:v\\nal\n\n\x00")
write("stomp_frame", "heartbeat", b"\n")
# STOMP does not nest: headers are a flat, MAX_HEADERS-bounded list and the inter-frame EOL
# drain is a loop. The recursion this framer once had was per blank line, so the equivalent of
# a depth bomb is a long run of them — 32 Ki heart-beats ahead of one frame. It costs the
# iterative drain nothing and is here for the day someone makes it recursive again.
write("stomp_frame", "blank_line_bomb", b"\r\n" * 32768 + b"SEND\ndestination:/q\n\nx\x00")

# --- RADIUS: Access-Request with User-Name and User-Password --------------
attrs = (bytes([1, 2 + 5]) + b"alice" +
         bytes([2, 2 + 16]) + bytes(range(16)) +
         bytes([4, 6]) + bytes([127, 0, 0, 1]) +
         bytes([5, 6]) + struct.pack(">I", 1))
pkt = bytes([1, 42]) + struct.pack(">H", 20 + len(attrs)) + bytes(range(16, 32)) + attrs
write("radius_packet", "access_request", pkt)
acct = (bytes([40, 6]) + struct.pack(">I", 1) + bytes([1, 2 + 5]) + b"alice")
write("radius_packet", "accounting_request",
      bytes([4, 7]) + struct.pack(">H", 20 + len(acct)) + bytes(16) + acct)

# --- DNS: a standard A query for example.com ------------------------------
def dns_name(host):
    out = b""
    for label in host.split(b"."):
        out += bytes([len(label)]) + label
    return out + b"\x00"


q = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
     dns_name(b"example.com") + struct.pack(">HH", 1, 1))
write("dns_message", "a_query", q)
resp = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) +
        dns_name(b"example.com") + struct.pack(">HH", 1, 1) +
        b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34]))
write("dns_message", "a_response", resp)
write("dns_message", "compression_pointer_loop",
      struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" +
      struct.pack(">HH", 1, 1))

# --- LLDP: chassis id + port id + TTL + end ------------------------------
def lldp_tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


lldpdu = (lldp_tlv(1, b"\x04" + bytes([0, 0x0C, 0x29, 1, 2, 3])) +
          lldp_tlv(2, b"\x05" + b"eth0") +
          lldp_tlv(3, struct.pack(">H", 120)) +
          lldp_tlv(5, b"netget") +
          lldp_tlv(0, b""))
write("lldp_frame", "lldpdu", lldpdu)
write("lldp_frame", "full_frame",
      b"\x01\x80\xc2\x00\x00\x0e" + bytes([0, 0x0C, 0x29, 1, 2, 3]) +
      b"\x88\xcc" + lldpdu)

# --- CDP: version/ttl/checksum + device-id TLV ---------------------------
def cdp_tlv(t, v):
    return struct.pack(">HH", t, len(v) + 4) + v


cdp_body = cdp_tlv(1, b"switch1") + cdp_tlv(3, b"Ethernet0/1") + cdp_tlv(5, b"IOS")
cdp_payload = bytes([2, 180]) + b"\x00\x00" + cdp_body
write("cdp_frame", "payload", cdp_payload)
write("cdp_frame", "full_frame",
      b"\x01\x00\x0c\xcc\xcc\xcc" + bytes([0, 0x0C, 0x29, 1, 2, 3]) +
      struct.pack(">H", len(cdp_payload) + 8) +
      b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp_payload)

# --- Modbus: MBAP + read holding registers / write single ---------------
def mbap(tid, unit, pdu):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


write("modbus_adu", "read_holding", mbap(1, 1, bytes([3]) + struct.pack(">HH", 0, 10)))
write("modbus_adu", "read_coils", mbap(2, 1, bytes([1]) + struct.pack(">HH", 0, 8)))
write("modbus_adu", "write_single", mbap(3, 1, bytes([6]) + struct.pack(">HH", 1, 0xABCD)))
write("modbus_adu", "two_adus",
      mbap(4, 1, bytes([3]) + struct.pack(">HH", 0, 1)) +
      mbap(5, 1, bytes([3]) + struct.pack(">HH", 1, 1)))
# Modbus has no nesting — an ADU is a flat header and a flat PDU, and no decoder here calls
# itself — so there is no depth bomb to plant. What a peer controls instead is every length
# it declares, and these seeds sit on each one. `max_adu` is exactly MAX_ADU_LEN (MBAP length
# 254); `over_max_adu` is the same frame one octet longer (length 255, refused);
# `declared_longer_than_sent` announces 254 and carries 5 (must ask for more, never read past
# the end); `zero_length` and `not_modbus` are the two framing refusals.
write("modbus_adu", "max_adu", mbap(6, 1, bytes([0x41]) + b"\xaa" * 252))
write("modbus_adu", "over_max_adu", mbap(7, 1, bytes([0x41]) + b"\xaa" * 253))
write("modbus_adu", "declared_longer_than_sent",
      struct.pack(">HHHB", 8, 0, 254, 1) + bytes([3]) + struct.pack(">HH", 0, 1))
write("modbus_adu", "zero_length", struct.pack(">HHHB", 9, 0, 0, 1))
write("modbus_adu", "not_modbus", struct.pack(">HHHB", 10, 7, 6, 1) + bytes([3, 0, 0, 0, 1]))
# The PDU-level lengths: each quantity limit at its maximum, and a write whose byte count
# disagrees with its quantity.
write("modbus_adu", "read_coils_max", mbap(11, 1, bytes([1]) + struct.pack(">HH", 0, 2000)))
write("modbus_adu", "read_registers_max",
      mbap(12, 1, bytes([3]) + struct.pack(">HH", 0xFFFF - 124, 125)))
write("modbus_adu", "write_coils_max",
      mbap(13, 1, bytes([0x0F]) + struct.pack(">HHB", 0, 1968, 246) + b"\x55" * 246))
write("modbus_adu", "write_registers_max",
      mbap(14, 1, bytes([0x10]) + struct.pack(">HHB", 0, 123, 246) + b"\x00\x01" * 123))
write("modbus_adu", "byte_count_mismatch",
      mbap(15, 1, bytes([0x10]) + struct.pack(">HHB", 0, 2, 3) + b"\x00\x0a\x01"))

# --- CoAP: confirmable GET /.well-known/core ----------------------------
def coap_opt(delta, value):
    ln = len(value)
    assert delta < 13 and ln < 13
    return bytes([(delta << 4) | ln]) + value


get = (bytes([0x40 | 0x02, 0x01]) + struct.pack(">H", 0x1234) + b"\xab\xcd" +
       coap_opt(11, b".well-known") + coap_opt(0, b"core"))
write("coap_message", "get_wellknown", get)
write("coap_message", "empty_ack", bytes([0x60, 0x00]) + struct.pack(">H", 0x1234))
post = (bytes([0x40 | 0x02, 0x02]) + struct.pack(">H", 1) + b"\x01\x02" +
        coap_opt(11, b"sensor") + b"\xff" + b"23.5")
write("coap_message", "post_payload", post)

# CoAP has no nesting, so it has no depth bomb — the equivalent blind spot is the
# option delta/length *extension* encodings, and none of the three seeds above reaches
# one. Nibble 13 means "one more byte, +13"; nibble 14 means "two more bytes, +269", and
# `read_extended` saturates that addition. Every length a peer can state that the walker
# must then not run past lives behind those two nibbles, so without a seed here a
# coverage-guided run explores only the 0-12 forms and reports clean for the encoding
# that actually carries the arithmetic.
def coap_opt_ext(delta, value):
    """One option using the 13 form for the delta and, past 12 octets, for the length."""
    ln = len(value)
    assert 13 <= delta < 269 and 13 <= ln < 269
    return bytes([(13 << 4) | 13, delta - 13, ln - 13]) + value


ext13 = (bytes([0x40 | 0x02, 0x01]) + struct.pack(">H", 0x4711) + b"\xde\xad\xbe\xef" +
         coap_opt_ext(60, b"x" * 40))
write("coap_message", "option_delta_ext13", ext13)
# The 14 form on both nibbles: delta 600 (-> 331 in two bytes) and a 300-octet value.
ext14 = (bytes([0x40 | 0x02, 0x01]) + struct.pack(">H", 0x4712) + b"\xde\xad\xbe\xef" +
         bytes([(14 << 4) | 14]) + struct.pack(">H", 600 - 269) +
         struct.pack(">H", 300 - 269) + b"y" * 300)
write("coap_message", "option_delta_ext14", ext14)

# --- HSRP v1 hello and a v2 TLV ----------------------------------------
v1 = (bytes([0, 0, 3, 1, 100, 1, 10]) + b"cisco\x00\x00\x00" +
      bytes([192, 168, 1, 1]))
write("hsrp_message", "v1_hello", v1)
v2_body = (bytes([4, 0]) + bytes([1, 100, 1, 10]) + struct.pack(">H", 1) +
           bytes([0, 0x0C, 0x29, 1, 2, 3]) + bytes([192, 168, 1, 1]))
write("hsrp_message", "v2_hello", bytes([1, len(v2_body)]) + v2_body)

# --- M3UA: DATA and ASPUP ----------------------------------------------
def m3ua_param(tag, value):
    pad = (-len(value)) % 4
    return struct.pack(">HH", tag, len(value) + 4) + value + b"\x00" * pad


protocol_data = (struct.pack(">II", 1, 2) + bytes([3, 0, 0, 0]) + b"payload")
data_params = m3ua_param(0x0210, protocol_data)
write("m3ua_message", "data",
      bytes([1, 0, 1, 1]) + struct.pack(">I", 8 + len(data_params)) + data_params)
aspup = m3ua_param(0x0011, struct.pack(">I", 1))
write("m3ua_message", "aspup",
      bytes([1, 0, 3, 1]) + struct.pack(">I", 8 + len(aspup)) + aspup)

# --- BGP: first byte is asn4, then marker+length+type -------------------
MARKER = b"\xff" * 16
keepalive = MARKER + struct.pack(">HB", 19, 4)
write("bgp_message", "keepalive", b"\x01" + keepalive)
open_body = (bytes([4]) + struct.pack(">HH", 65001, 180) +
             bytes([192, 168, 1, 1]) + bytes([0]))
write("bgp_message", "open",
      b"\x01" + MARKER + struct.pack(">HB", 19 + len(open_body), 1) + open_body)
notification = MARKER + struct.pack(">HB", 21, 3) + bytes([6, 0])
write("bgp_message", "notification", b"\x00" + notification)


# BGP path attributes do not nest in anything netgauze 0.7 decodes: every PathAttributeValue
# variant is a flat value or a flat list, and ATTR_SET (RFC 6368), the one attribute that would
# contain attributes, is not implemented. So there is no depth bomb; the lengths are what a
# peer controls, and the corpus had no UPDATE at all. These seed one ordinary UPDATE and one at
# BGP's 4096-octet maximum, carried by a long AS_PATH.
def bgp_attr(flags, code, value):
    if len(value) > 255:
        return bytes([flags | 0x10, code]) + struct.pack(">H", len(value)) + value
    return bytes([flags, code, len(value)]) + value


def bgp_update(attrs, nlri):
    body = struct.pack(">H", 0) + struct.pack(">H", len(attrs)) + attrs + nlri
    return MARKER + struct.pack(">HB", 19 + len(body), 2) + body


update_attrs = (bgp_attr(0x40, 1, b"\x00") +
                bgp_attr(0x40, 2, bytes([2, 2]) + struct.pack(">II", 65001, 65002)) +
                bgp_attr(0x40, 3, bytes([192, 0, 2, 1])))
write("bgp_message", "update_ipv4",
      b"\x01" + bgp_update(update_attrs, bytes([24, 198, 51, 100])))
# 4096 = header 19 + two length fields 4 + ORIGIN 4 + AS_PATH (4-byte extended header + P) +
# NEXT_HOP 7 + NLRI 4, so the AS_PATH value is P = 4054 octets: five AS_SEQUENCE segments
# (a segment holds at most 255 four-byte ASNs, and 2k + 4N = 4054 needs k odd) of 1011 ASNs.
as_path = b""
for n in (255, 255, 255, 245, 1):
    as_path += bytes([2, n]) + b"".join(struct.pack(">I", 64512 + i) for i in range(n))
assert len(as_path) == 4054
max_attrs = (bgp_attr(0x40, 1, b"\x00") + bgp_attr(0x40, 2, as_path) +
             bgp_attr(0x40, 3, bytes([192, 0, 2, 1])))
max_update = bgp_update(max_attrs, bytes([24, 198, 51, 100]))
assert len(max_update) == 4096
write("bgp_message", "update_max_len", b"\x01" + max_update)

# --- NDEF: a text record and a URI record ------------------------------
text_payload = bytes([2]) + b"en" + b"hello"
write("ndef_message", "text_record",
      bytes([0xD1, 1, len(text_payload)]) + b"T" + text_payload)
uri_payload = bytes([0x03]) + b"netget.net"
write("ndef_message", "uri_record",
      bytes([0xD1, 1, len(uri_payload)]) + b"U" + uri_payload)
write("ndef_message", "two_records",
      bytes([0x91, 1, len(text_payload)]) + b"T" + text_payload +
      bytes([0x51, 1, len(uri_payload)]) + b"U" + uri_payload)

# --- ISO 7816 APDUs ----------------------------------------------------
write("nfc_apdu", "select_ndef", bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) +
      bytes([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]) + bytes([0x00]))
write("nfc_apdu", "read_binary", bytes([0x00, 0xB0, 0x00, 0x00, 0x0F]))
write("nfc_apdu", "case1", bytes([0x00, 0x20, 0x00, 0x00]))
write("nfc_apdu", "extended",
      bytes([0x00, 0xB0, 0x00, 0x00, 0x00, 0x01, 0x00]) + bytes(256))

# --- NFS record markers: last-fragment bit is the high bit --------------
LAST = 0x80000000
write("nfs_record_guard", "single_small", struct.pack(">I", LAST | 100))
write("nfs_record_guard", "two_fragments",
      struct.pack(">I", 1024) + struct.pack(">I", LAST | 1024))
write("nfs_record_guard", "many_fragments",
      b"".join(struct.pack(">I", 512) for _ in range(8)) +
      struct.pack(">I", LAST | 512))
write("nfs_record_guard", "oversized_announce", struct.pack(">I", LAST | 0x7FFFFFFF))


# --- RESP2: what redis-cli and redis-rs send, and the shapes utils::resp refuses ---
def resp_command(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


write("resp_frame", "ping", resp_command(b"PING"))
write("resp_frame", "set", resp_command(b"SET", b"key", b"value"))
write("resp_frame", "pipelined", resp_command(b"PING") + resp_command(b"GET", b"k"))
write("resp_frame", "reply_shapes",
      b"*5\r\n+OK\r\n:42\r\n$-1\r\n*-1\r\n*2\r\n$0\r\n\r\n-ERR no\r\n")
write("resp_frame", "incomplete_bulk", b"*1\r\n$10\r\nabc")
write("resp_frame", "at_depth_limit", b"*1\r\n" * 32 + b":1\r\n")
# A declared length the 64 MiB buffer can never satisfy, refused on the header line.
write("resp_frame", "huge_declared_len", b"*4000000000\r\n")
write("resp_frame", "huge_declared_bulk", b"*1\r\n$4000000000\r\n")
# 65,536 levels at four bytes each: enough to overflow the fuzzer's 8 MiB main thread
# when the guard is removed (verified), and the input that sets libFuzzer's -max_len.
write("resp_frame", "depth_bomb", b"*1\r\n" * 65536 + b":1\r\n")


# --- BSON: MongoDB command documents, and the shapes utils::bson_depth refuses ---
def bson_doc(elements):
    return struct.pack("<i", 4 + len(elements) + 1) + elements + b"\x00"


def bson_el(kind, key, value):
    return bytes([kind]) + key + b"\x00" + value


def bson_str(s):
    return struct.pack("<i", len(s) + 1) + s + b"\x00"


def bson_nested(levels):
    """`levels` documents in all, `{a: {a: ... {} ...}}`, built without quadratic copying."""
    sizes = [5 + 8 * i for i in range(levels)]  # innermost first
    head = b"".join(struct.pack("<i", sizes[i]) + b"\x03a\x00"
                    for i in range(levels - 1, 0, -1))
    return head + bson_doc(b"") + b"\x00" * (levels - 1)


write("bson_document", "hello", bson_doc(
    bson_el(0x10, b"hello", struct.pack("<i", 1)) + bson_el(0x02, b"$db", bson_str(b"admin"))))
write("bson_document", "find_with_filter", bson_doc(
    bson_el(0x02, b"find", bson_str(b"users")) +
    bson_el(0x03, b"filter", bson_doc(bson_el(0x03, b"age", bson_doc(
        bson_el(0x10, b"$gte", struct.pack("<i", 25)))))) +
    bson_el(0x02, b"$db", bson_str(b"test"))))
write("bson_document", "insert_array", bson_doc(
    bson_el(0x02, b"insert", bson_str(b"users")) +
    bson_el(0x04, b"documents", bson_doc(
        bson_el(0x03, b"0", bson_doc(bson_el(0x02, b"name", bson_str(b"Alice")))) +
        bson_el(0x03, b"1", bson_doc(bson_el(0x02, b"name", bson_str(b"Bob")))))) +
    bson_el(0x02, b"$db", bson_str(b"test"))))
write("bson_document", "every_type", bson_doc(
    bson_el(0x01, b"d", struct.pack("<d", 1.5)) +
    bson_el(0x05, b"bin", struct.pack("<i", 3) + b"\x00abc") +
    bson_el(0x06, b"u", b"") +
    bson_el(0x07, b"oid", bytes(range(12))) +
    bson_el(0x08, b"t", b"\x01") +
    bson_el(0x09, b"dt", struct.pack("<q", 0)) +
    bson_el(0x0A, b"n", b"") +
    bson_el(0x0B, b"re", b"^a\x00i\x00") +
    bson_el(0x0C, b"ptr", bson_str(b"db.c") + bytes(12)) +
    bson_el(0x0D, b"js", bson_str(b"x")) +
    bson_el(0x0E, b"sym", bson_str(b"s")) +
    bson_el(0x11, b"ts", struct.pack("<q", 1)) +
    bson_el(0x12, b"i64", struct.pack("<q", -1)) +
    bson_el(0x13, b"dec", bytes(16)) +
    bson_el(0x7F, b"max", b"") +
    bson_el(0xFF, b"min", b"")))
code = bson_str(b"f()")
scope = bson_doc(bson_el(0x10, b"x", struct.pack("<i", 1)))
write("bson_document", "code_with_scope", bson_doc(
    bson_el(0x0F, b"cws", struct.pack("<i", 4 + len(code) + len(scope)) + code + scope)))
write("bson_document", "at_depth_limit", bson_nested(64))
# A document declaring 2 GiB: bson's reader_to_vec would reserve that before finding out.
write("bson_document", "huge_declared_len", struct.pack("<i", 0x7FFFFFFF) + b"\x00")
# 16,384 levels at eight bytes each (~128 KiB): past the 4,861 that overflow the fuzzer's
# 8 MiB main thread in a release build when the guard is removed (verified).
write("bson_document", "depth_bomb", bson_nested(16384))


# --- LDAP: SearchRequests, and the filter nesting MAX_FILTER_DEPTH bounds ---
def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return b"\x82" + struct.pack(">H", n)
    return b"\x83" + n.to_bytes(3, "big")


def tlv(tag, value):
    return bytes([tag]) + ber_len(len(value)) + value


def ldap_search(filter_bytes, msg_id=1):
    body = (tlv(0x04, b"dc=example,dc=com") + tlv(0x0A, b"\x02") + tlv(0x0A, b"\x00") +
            tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x01, b"\x00") +
            filter_bytes + tlv(0x30, tlv(0x04, b"cn") + tlv(0x04, b"mail")))
    return tlv(0x30, tlv(0x02, bytes([msg_id])) + tlv(0x63, body))


def ldap_nested_and(levels, inner):
    """`levels` nested `&` filters around `inner`, built without quadratic copying."""
    headers = []
    size = len(inner)
    for _ in range(levels):
        header = b"\xa0" + ber_len(size)
        headers.append(header)
        size += len(header)
    return b"".join(reversed(headers)) + inner


ldap_eq = tlv(0xA3, tlv(0x04, b"uid") + tlv(0x04, b"alice"))
write("ldap_filter", "search_equality", ldap_search(ldap_eq))
write("ldap_filter", "search_present", ldap_search(tlv(0x87, b"objectClass")))
write("ldap_filter", "search_and_or_not", ldap_search(tlv(0xA0,
      ldap_eq + tlv(0xA1, tlv(0xA3, tlv(0x04, b"ou") + tlv(0x04, b"eng")) +
                    tlv(0xA2, tlv(0x87, b"disabled"))))))
write("ldap_filter", "search_substrings", ldap_search(tlv(0xA4,
      tlv(0x04, b"cn") + tlv(0x30, tlv(0x80, b"al") + tlv(0x81, b"ic") + tlv(0x82, b"e")))))
write("ldap_filter", "bind_simple",
      tlv(0x30, tlv(0x02, b"\x01") + tlv(0x60, tlv(0x02, b"\x03") + tlv(0x04, b"cn=admin") +
                                         tlv(0x80, b"secret"))))
# render_filter stops at depth 32: the equality inside 32 `&`s is the first thing it elides.
write("ldap_filter", "at_depth_limit", ldap_search(ldap_nested_and(32, ldap_eq)))
# 60,000 levels at ~5 bytes each (~300 KiB, under the 1 MiB MAX_LDAP_MESSAGE, so it is framed
# and reaches the renderer): with the depth check removed this overflows the fuzzer's 8 MiB
# main thread (verified).
write("ldap_filter", "depth_bomb", ldap_search(ldap_nested_and(60000, ldap_eq)))


# --- ra_svn: tuples, and the nesting MAX_TUPLE_DEPTH bounds ---
write("svn_tuple", "client_greeting",
      b"( 2 ( edit-pipeline svndiff1 accepts-svndiff2 absent-entries depth mergeinfo log-revprops"
      b" ) 32:svn://127.0.0.1/repo/trunk/proj 10:SVN/1.14.2 ( ) ) ")
write("svn_tuple", "auth_anonymous", b"( ANONYMOUS ( 0: ) ) ")
write("svn_tuple", "get_latest_rev", b"( get-latest-rev ( ) ) ")
write("svn_tuple", "get_dir", b"( get-dir ( 0: ( ) true false ( kind size ) ) ) ")
write("svn_tuple", "counted_string_with_newline", b"( check-path ( 5:a\nb c ( 12 ) ) ) ")
write("svn_tuple", "two_commands", b"( get-latest-rev ( ) ) ( stat ( 0: ( ) ) ) ")
# The reader refuses a 65th open list, so 64 closed lists is the deepest item it accepts.
write("svn_tuple", "at_depth_limit", b"(" * 64 + b")" * 64)
# 32,000 closed lists: two bytes a level, so it fits MAX_COMMAND_BYTES (64 KiB) and is a size
# the server really admits. The reader is iterative, but the Item it builds is walked
# recursively (Display, to_json, Drop); with MAX_TUPLE_DEPTH removed this overflows the
# fuzzer's 8 MiB main thread (verified).
write("svn_tuple", "depth_bomb", b"(" * 32000 + b")" * 32000)


# --- XML-RPC: methodCalls, and the nesting MAX_VALUE_DEPTH bounds ---
def xmlrpc_call(params):
    return (b'<?xml version="1.0"?><methodCall><methodName>examples.getStateName</methodName>'
            b"<params>" + b"".join(b"<param>" + p + b"</param>" for p in params) +
            b"</params></methodCall>")


def xmlrpc_nested_array(levels, inner):
    return (b"<value><array><data>" * levels + inner +
            b"</data></array></value>" * levels)


write("xmlrpc_value", "int_param", xmlrpc_call([b"<value><i4>41</i4></value>"]))
write("xmlrpc_value", "every_scalar", xmlrpc_call([
    b"<value><int>-7</int></value>", b"<value><i8>9007199254740993</i8></value>",
    b"<value><boolean>1</boolean></value>", b"<value><string>a &amp; b</string></value>",
    b"<value><double>2.5</double></value>",
    b"<value><dateTime.iso8601>19980717T14:08:55</dateTime.iso8601></value>",
    b"<value><base64>aGVsbG8=</base64></value>", b"<value><nil/></value>",
    b"<value>untyped</value>", b"<value/>"]))
write("xmlrpc_value", "struct_and_array", xmlrpc_call([
    b"<value><struct><member><name>id</name><value><int>1</int></value></member>"
    b"<member><name>tags</name><value><array><data><value>a</value><value>b</value>"
    b"</data></array></value></member></struct></value>"]))
# 31 levels of <value><array> plus the innermost <value> is 63 frames, one under the guard.
write("xmlrpc_value", "at_depth_limit",
      xmlrpc_call([xmlrpc_nested_array(31, b"<value><i4>1</i4></value>")]))
# 20,000 closed levels at 42 bytes each (~860 KB): the parser is iterative, but the
# XmlRpcValue it builds is walked recursively (to JSON, and on drop); with MAX_VALUE_DEPTH
# removed this overflows the fuzzer's 8 MiB main thread (verified; 16,000 already does).
# It must stay under 1 MiB: libFuzzer caps the -max_len it infers from a corpus at 1 MiB and
# silently TRUNCATES larger seeds, so a 40,000-level bomb (1.7 MB) arrived as malformed XML,
# never reached the recursion, and ran 60 seconds "clean" with the guard removed.
write("xmlrpc_value", "depth_bomb",
      xmlrpc_call([xmlrpc_nested_array(20000, b"<value><i4>1</i4></value>")]))

# --- Bolt: PackStream message bodies and chunked streams ----------------------
# The shapes are what cypher-shell 2026.09 (neo4j-java-driver 6.2) was recorded sending; see
# src/server/bolt/CLAUDE.md. The target decodes every input both as one message body and as a
# chunked stream, so each message is seeded in both forms.
def ps(v):
    """A minimal PackStream encoder: None, bool, int, str, list, dict, and (tag, [fields])."""
    if v is None:
        return b"\xC0"
    if v is True:
        return b"\xC3"
    if v is False:
        return b"\xC2"
    if isinstance(v, int):
        if -16 <= v < 128:
            return struct.pack(">b", v)
        if -128 <= v < 128:
            return b"\xC8" + struct.pack(">b", v)
        if -32768 <= v < 32768:
            return b"\xC9" + struct.pack(">h", v)
        if -2**31 <= v < 2**31:
            return b"\xCA" + struct.pack(">i", v)
        return b"\xCB" + struct.pack(">q", v)
    if isinstance(v, str):
        b = v.encode()
        if len(b) < 16:
            return bytes([0x80 | len(b)]) + b
        if len(b) < 256:
            return b"\xD0" + bytes([len(b)]) + b
        return b"\xD1" + struct.pack(">H", len(b)) + b
    if isinstance(v, list):
        head = bytes([0x90 | len(v)]) if len(v) < 16 else b"\xD4" + bytes([len(v)])
        return head + b"".join(ps(x) for x in v)
    if isinstance(v, dict):
        head = bytes([0xA0 | len(v)]) if len(v) < 16 else b"\xD8" + bytes([len(v)])
        return head + b"".join(ps(k) + ps(x) for k, x in v.items())
    tag, fields = v
    return bytes([0xB0 | len(fields), tag]) + b"".join(ps(f) for f in fields)


def bolt_chunk(body):
    out = b""
    for i in range(0, len(body), 65535):
        piece = body[i:i + 65535]
        out += struct.pack(">H", len(piece)) + piece
    return out + b"\x00\x00"


BOLT_MESSAGES = {
    "hello": (0x01, [{
        "bolt_agent": {"product": "neo4j-java/6.2.1", "language": "Java/21",
                       "platform": "Mac OS X; 27.0; aarch64"},
        "user_agent": "neo4j-cypher-shell/v2026.09.0",
        "routing": {"address": "127.0.0.1:7687"}}]),
    "logon": (0x6A, [{"principal": "neo4j", "scheme": "basic", "credentials": "pw"}]),
    "run": (0x10, ["MATCH (n:Person {name: $name}) RETURN n", {"name": "Alice", "n": [1, -2, 300]},
                   {"tx_metadata": {"type": "user-direct", "app": "cypher-shell_v2026.09.0"},
                    "db": "neo4j", "mode": "r"}]),
    "pull": (0x3F, [{"n": 1000}]),
    "pull_qid": (0x3F, [{"n": -1, "qid": 3}]),
    "begin": (0x11, [{"mode": "r", "db": "movies", "tx_metadata": {"type": "user-direct"}}]),
    "route": (0x66, [{"address": "127.0.0.1:7687"}, [], {}]),
    "reset": (0x0F, []),
    "goodbye": (0x02, []),
}
for name, message in BOLT_MESSAGES.items():
    body = ps(message)
    write("packstream_message", name, body)
    write("packstream_message", name + "_chunked", bolt_chunk(body))
write("packstream_message", "pipelined_run_pull",
      bolt_chunk(ps(BOLT_MESSAGES["run"])) + b"\x00\x00" + bolt_chunk(ps(BOLT_MESSAGES["pull"])))
# Parameters exactly at MAX_PACKSTREAM_DEPTH (message struct 1, parameter map 2, 30 lists).
write("packstream_message", "at_depth_limit",
      b"\xB3\x10\x81q\xA1\x81p" + b"\x91" * 30 + b"\x01\xA0")
# 100,000 one-element lists (100 KB, under libFuzzer's 1 MiB inferred -max_len), as a bare body
# and chunked: with the depth checks removed this overflows the fuzzer's 8 MiB main thread.
BOLT_BOMB = b"\xB3\x10\x81q\xA1\x81p" + b"\x91" * 100000 + b"\xC0\xA0"
write("packstream_message", "depth_bomb", BOLT_BOMB)
write("packstream_message", "depth_bomb_chunked", bolt_chunk(BOLT_BOMB))
write("packstream_message", "map_depth_bomb", b"\xA1\x81k" * 60000 + b"\xC0")
write("packstream_message", "struct_depth_bomb", b"\xB1\x4E" * 60000 + b"\xC0")
# Declared lengths four billion strong in five bytes: refused on the count, never allocated.
for name, header in [("list32_huge", b"\xD6\xFF\xFF\xFF\xFF"),
                     ("map32_huge", b"\xDA\xFF\xFF\xFF\xFF"),
                     ("string32_huge", b"\xD2\xFF\xFF\xFF\xFF"),
                     ("bytes32_huge", b"\xCE\xFF\xFF\xFF\xFF"),
                     ("struct16_huge", b"\xDD\xFF\xFF\x4E")]:
    write("packstream_message", name, header)
    write("packstream_message", name + "_chunked", bolt_chunk(header))
# A chunk stream that never sends its terminating zero chunk.
write("packstream_message", "unterminated_chunks", (b"\xFF\xFF" + b"\x00" * 65535) * 3)


total =sum(len(files) for _, _, files in os.walk(CORPUS))
# --- zabbix: the ZBXD framing and the sender-data request ------------------
def zbxd(payload, flags=0x01, declared=None, reserved=0):
    n = len(payload) if declared is None else declared
    if flags & 0x04:
        return b"ZBXD" + bytes([flags]) + struct.pack("<QQ", n, reserved) + payload
    return b"ZBXD" + bytes([flags]) + struct.pack("<II", n, reserved) + payload


# Byte for byte what zabbix_sender 7.4 sent to a capture listener.
write("zabbix_packet", "sender_one_value", zbxd(
    b'{"request":"sender data","data":[{"host":"host1","key":"key1","value":"42"}],'
    b'"clock":1790403191,"ns":583083000}'))
write("zabbix_packet", "sender_batch", zbxd(
    b'{"request":"sender data","data":[{"host":"host1","key":"key1","value":"1"},'
    b'{"host":"host1","key":"key2","value":"two words"},{"host":"dflt","key":"key3","value":"3"}],'
    b'"clock":1790403284,"ns":288425000}'))
write("zabbix_packet", "large_header", zbxd(b'{"request":"sender data","data":[]}', flags=0x05))
write("zabbix_packet", "response", zbxd(
    b'{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.000055"}'))
write("zabbix_packet", "other_request", zbxd(b'{"request":"active checks","host":"web1"}'))
write("zabbix_packet", "compressed", zbxd(b"x\x9c\x03\x00\x00\x00\x00\x01", flags=0x03))
# Declared lengths past the 1 MiB bound, in both header forms: refused from the header alone.
write("zabbix_packet", "huge_declared_len", zbxd(b"", declared=0xFFFFFFFF))
write("zabbix_packet", "huge_declared_large", zbxd(b"", flags=0x05, declared=1 << 62))
# A JSON nesting bomb in the body: serde_json's own recursion limit (128) must turn it into a
# parse error. 65,536 levels overflow any stack if that limit is ever switched off.
write("zabbix_packet", "depth_bomb", zbxd(b"[" * 65536 + b"]" * 65536))

# --- gearman: the binary packet protocol and the admin lines ---------------
def gearman(magic, ptype, *args, declared=None):
    data = b"\0".join(args)
    n = len(data) if declared is None else declared
    return magic + struct.pack(">II", ptype, n) + data


REQ = b"\0REQ"
# Byte for byte what the gearman(1) CLI sent to a capture listener.
write("gearman_packet", "submit_job", gearman(
    REQ, 7, b"reverse", b"BE19BA24-7778-4CF6-BBFB-04CA7A3789E9", b"hello world"))
write("gearman_packet", "submit_job_bg", gearman(
    REQ, 18, b"reverse", b"CC4564F0-40CE-4753-A20D-75856AF9B5ED", b"bg job"))
write("gearman_packet", "submit_job_high", gearman(REQ, 21, b"reverse", b"", b"high"))
write("gearman_packet", "echo_req", gearman(REQ, 16, b"ping"))
write("gearman_packet", "can_do", gearman(REQ, 1, b"reverse"))
write("gearman_packet", "grab_job_all", gearman(REQ, 39))
write("gearman_packet", "option_exceptions", gearman(REQ, 26, b"exceptions"))
write("gearman_packet", "work_complete_res", gearman(b"\0RES", 13, b"H:netget:1", b"dlrow olleh"))
write("gearman_packet", "admin_status", b"status\r\n")
# A declared size past the 1 MiB bound: refused from the header alone.
write("gearman_packet", "huge_declared_size", gearman(REQ, 7, declared=0xFFFFFFFF))
# 65,536 NULs as a SUBMIT_JOB body: split_args splits only on the first two.
write("gearman_packet", "nul_bomb", gearman(REQ, 7, b"\0" * 65536))

# --- nsq: nsqd's TCP protocol (V2) -------------------------------------------
def nsq_body(line, body, declared=None):
    n = len(body) if declared is None else declared
    return line + struct.pack(">I", n & 0xFFFFFFFF) + body


def nsq_mpub(topic, *messages, count=None):
    n = len(messages) if count is None else count
    body = struct.pack(">I", n & 0xFFFFFFFF) + b"".join(
        struct.pack(">I", len(m)) + m for m in messages)
    return nsq_body(b"MPUB " + topic + b"\n", body)


V2 = b"  V2"
IDENTIFY = b'{"client_id":"fuzz","hostname":"fuzz","feature_negotiation":true,' \
    b'"heartbeat_interval":30000,"user_agent":"go-nsq/1.1.0"}'
# What go-nsq sends at connect, then a consumer's SUB and RDY.
write("nsq_frame", "consumer_session", V2 + nsq_body(b"IDENTIFY\n", IDENTIFY)
      + b"SUB orders workers#ephemeral\nRDY 200\n")
write("nsq_frame", "pub", V2 + nsq_body(b"PUB orders\n", b"order 1 shipped"))
write("nsq_frame", "dpub", nsq_body(b"DPUB orders 1500\n", b"later"))
write("nsq_frame", "mpub", nsq_mpub(b"orders", b"a", b"bb", b"ccc"))
write("nsq_frame", "fin_req_touch", b"FIN 0000000000000001\nREQ 0000000000000002 5000\n"
      b"TOUCH 0000000000000003\nNOP\nCLS\r\n")
write("nsq_frame", "auth", nsq_body(b"AUTH\n", b"secret"))
# The server's frames, for parse_frame / parse_message.
write("nsq_frame", "response_frame", struct.pack(">II", 6, 0) + b"OK")
write("nsq_frame", "message_frame", struct.pack(">II", 4 + 26 + 5, 2)
      + struct.pack(">qH", 1700000000000000000, 1) + b"0000000000000001" + b"hello")
# Oversize declarations, refused from the size field alone.
write("nsq_frame", "pub_declared_huge", nsq_body(b"PUB t\n", b"", declared=0x7FFFFFFF))
write("nsq_frame", "pub_declared_negative", nsq_body(b"PUB t\n", b"", declared=0xFFFFFFFF))
write("nsq_frame", "pub_one_past_the_limit", nsq_body(b"PUB t\n", b"", declared=1024 * 1024 + 1))
write("nsq_frame", "mpub_declared_huge", nsq_body(b"MPUB t\n", b"", declared=5 * 1024 * 1024 + 1))
write("nsq_frame", "mpub_count_bomb", nsq_mpub(b"t", b"x", count=0x7FFFFFFF))
write("nsq_frame", "line_bomb", b"x" * 65536)
# A JSON nesting bomb as the IDENTIFY body: serde_json's recursion limit (128) must refuse it.
write("nsq_frame", "identify_depth_bomb", nsq_body(b"IDENTIFY\n", b"[" * 65536 + b"]" * 65536))


# --- nostr: NIP-01 client messages, as a relay reads them -------------------
# The EVENTs were signed by nak 0.20.7 (go-nostr); the second carries every escape class,
# including the C0 controls the three id serialisations in use disagree about.
NAK_EVENT = (
    b'{"kind":1,"id":"4601ba921e79b93ee9610fc66536bcab72e34da88d62bf03c662440682a45033",'
    b'"pubkey":"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",'
    b'"created_at":1700000000,"tags":[],"content":"hello","sig":"5faead673a8e534c473d951da9726ce7'
    b'263b38c4d77c525eeb7e6ad06b48a0000edda8f74706fdb3ed88c826925a21e028f2ad558633d815e60ac4c40384'
    b'00ee"}')
NAK_CONTESTED = (
    b'{"kind":1,"id":"ede3685aa62627e9a0246c0709c4167017ced5cb79b663245cab1b17afc05955",'
    b'"pubkey":"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",'
    b'"created_at":1700000001,"tags":[["t","nostr"],["e","5c83da77af1dec6d7289834998ad7aafbd9e2191'
    b'396d75ec3cc27f5a77226f36"]],"content":"line1\\nline2 \\"quoted\\" back\\\\slash\\ttab\\rcr'
    b'\\u0008bs\\u000cfeed\\u0001ctl\\u001fus \xe2\x9c\x93 \xf0\x9f\x98\x80 \\u2028 / end",'
    b'"sig":"580226f6414004a05ae24b7c0d0c7e5f1f83333b81556f7c836d51bae94aa30a175ed6a24f7c7d53dddd'
    b'bf3e17ed4ef57d6d64838ec111e77e54a1a40f38170c"}')
write("nostr_message", "event_nak", b'["EVENT",' + NAK_EVENT + b']')
write("nostr_message", "event_contested_escapes", b'["EVENT",' + NAK_CONTESTED + b']')
write("nostr_message", "event_tampered",
      b'["EVENT",' + NAK_EVENT.replace(b'"hello"', b'"hellO"') + b']')
write("nostr_message", "req", b'["REQ","sub1",{"kinds":[1],"limit":10}]')
write("nostr_message", "req_tags_and_times",
      b'["REQ","s",{"#t":["film"],"since":1,"until":2000000000},'
      b'{"authors":["17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"],'
      b'"search":"x"}]')
write("nostr_message", "close", b'["CLOSE","sub1"]')
write("nostr_message", "count_unsupported", b'["COUNT","c",{}]')
write("nostr_message", "too_many_filters", b'["REQ","s"' + b',{}' * 11 + b']')
write("nostr_message", "long_subscription_id", b'["REQ","' + b's' * 65 + b'",{}]')
# serde_json's recursion limit (128) is the depth guard; this is ~65 000 levels, inside the
# 128 KiB message bound.
write("nostr_message", "depth_bomb", b'["REQ","s",' + b'[' * 65000 + b']' * 65000 + b']')
# The largest message the framing admits, as a REQ whose ids list fills it.
ids = b','.join([b'"' + b'0' * 64 + b'"'] * 1900)
body = b'["REQ","s",{"ids":[' + ids + b']}]'
write("nostr_message", "at_message_bound", body + b' ' * (131072 - len(body)))

# --- SMB2: requests as smbclient and smbprotocol send them, compounds, and lengths --------
# `smb2_request` walks a frame as the server does and hands every request to every parser;
# `ntlmssp_token` is the SESSION_SETUP security buffer. See both targets' module docs.
def smb2_header(cmd, mid, tid=0, sid=0, flags=0, next_command=0):
    return (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, cmd, 8, flags, next_command,
                                     mid, 0, tid, sid) + b"\x00" * 16)

def utf16(s):
    return s.encode("utf-16-le")

FID = bytes(range(16))

def smb2_negotiate(mid=0, dialects=(0x0202, 0x0210), count=None):
    n = len(dialects) if count is None else count
    return (smb2_header(0, mid) + struct.pack("<HHHHI", 36, n, 1, 0, 0) + b"\x11" * 16 +
            b"\x00" * 8 + b"".join(struct.pack("<H", d) for d in dialects))

def smb2_session_setup(mid, sid, blob, blob_len=None, blob_off=88):
    n = len(blob) if blob_len is None else blob_len
    return (smb2_header(1, mid, 0, sid) + struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, blob_off, n, 0)
            + blob)

def smb2_tree_connect(mid, sid, unc, path_len=None):
    path = utf16(unc)
    n = len(path) if path_len is None else path_len
    return smb2_header(3, mid, 0, sid) + struct.pack("<HHHH", 9, 0, 72, n) + path

def smb2_create(mid, tid, sid, name, options=0, disposition=1, name_len=None, flags=0,
                next_command=0):
    nm = utf16(name)
    n = len(nm) if name_len is None else name_len
    body = (struct.pack("<HBBI", 57, 0, 0, 2) + b"\x00" * 16 +
            struct.pack("<IIIIIHHII", 0x00120089, 0, 7, disposition, options, 120, n, 0, 0))
    return smb2_header(5, mid, tid, sid, flags, next_command) + body + (nm or b"\x00")

def smb2_file_id_request(cmd, mid, tid, sid, fid=FID, flags=0, next_command=0):
    # CLOSE and FLUSH: StructureSize 24, a 16-bit field, 4 reserved, the FileId.
    return smb2_header(cmd, mid, tid, sid, flags, next_command) + struct.pack("<HHI", 24, 0, 0) + fid

def smb2_read(mid, tid, sid, length=65536, offset=0, fid=FID):
    return (smb2_header(8, mid, tid, sid) + struct.pack("<HBBIQ", 49, 0x50, 0, length, offset) +
            fid + struct.pack("<IIIHH", 0, 0, 0, 0, 0) + b"\x00")

def smb2_write(mid, tid, sid, data, length=None, data_offset=112, offset=0, fid=FID):
    n = len(data) if length is None else length
    return (smb2_header(9, mid, tid, sid) + struct.pack("<HHIQ", 49, data_offset, n, offset) +
            fid + struct.pack("<IIHHI", 0, 0, 0, 0, 0) + data)

def smb2_query_info(mid, tid, sid, info_type=1, cls=18, out_len=0xFFFF, fid=FID, flags=0,
                    next_command=0):
    return (smb2_header(0x10, mid, tid, sid, flags, next_command) +
            struct.pack("<HBBIHHIII", 41, info_type, cls, out_len, 0, 0, 0, 0, 0) + fid + b"\x00")

def smb2_query_directory(mid, tid, sid, pattern="*", cls=37, name_len=None, out_len=0xFFFF):
    nm = utf16(pattern)
    n = len(nm) if name_len is None else name_len
    return (smb2_header(0x0E, mid, tid, sid) + struct.pack("<HBBI", 33, cls, 0, 0) + FID +
            struct.pack("<HHI", 96, n, out_len) + nm)

def smb2_simple(cmd, mid, tid=0, sid=0):
    return smb2_header(cmd, mid, tid, sid) + b"\x04\x00\x00\x00"

def smb2_compound(msgs):
    out = b""
    for i, m in enumerate(msgs):
        if i + 1 < len(msgs):
            m = m + b"\x00" * (-len(m) % 8)
            m = m[:20] + struct.pack("<I", len(m)) + m[24:]
        out += m
    return out

RELATED = 0x4
NTLM_NEGOTIATE = b"NTLMSSP\x00" + struct.pack("<II", 1, 0x62088215) + b"\x00" * 16

def ntlm_authenticate(user, domain="", workstation="WS", lm=b"", nt=b"", flags=0x62088215):
    fields = [lm, nt, utf16(domain), utf16(user), utf16(workstation), b""]
    off = 64
    fixed = b"NTLMSSP\x00" + struct.pack("<I", 3)
    payload = b""
    for f in fields:
        fixed += struct.pack("<HHI", len(f), len(f), off + len(payload))
        payload += f
    fixed += struct.pack("<I", flags)
    return fixed + payload

def der(tag, content):
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    if n <= 0xFF:
        return bytes([tag, 0x81, n]) + content
    return bytes([tag, 0x82, n >> 8, n & 0xFF]) + content

NTLMSSP_OID = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
SPNEGO_OID = bytes([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])

def spnego_init(token):
    init = der(0x30, der(0xa0, der(0x30, NTLMSSP_OID)) + der(0xa2, der(0x04, token)))
    return der(0x60, SPNEGO_OID + der(0xa0, init))

def spnego_resp(token):
    return der(0xa1, der(0x30, der(0xa2, der(0x04, token))))

ANON_AUTH = ntlm_authenticate("", lm=b"\x00", flags=0x62088A15)
GUEST_AUTH = ntlm_authenticate("guest", "WORKGROUP", nt=b"\x00" * 24)

write("smb2_request", "negotiate", smb2_negotiate())
write("smb2_request", "session_setup_spnego_negotiate",
      smb2_session_setup(1, 0, spnego_init(NTLM_NEGOTIATE)))
write("smb2_request", "session_setup_spnego_authenticate",
      smb2_session_setup(2, 7, spnego_resp(ANON_AUTH)))
write("smb2_request", "session_setup_guest", smb2_session_setup(1, 0, b""))
write("smb2_request", "tree_connect", smb2_tree_connect(3, 1, r"\\127.0.0.1\share"))
write("smb2_request", "create_root", smb2_create(4, 1, 1, "", options=1))
write("smb2_request", "create_file", smb2_create(5, 1, 1, r"dir\report.bin", options=0x40))
write("smb2_request", "create_delete_on_close",
      smb2_create(5, 1, 1, "upload.bin", options=0x1040))
write("smb2_request", "close", smb2_file_id_request(6, 6, 1, 1))
write("smb2_request", "flush", smb2_file_id_request(7, 7, 1, 1))
write("smb2_request", "read", smb2_read(8, 1, 1))
write("smb2_request", "write", smb2_write(9, 1, 1, b"hello world"))
write("smb2_request", "query_info_all", smb2_query_info(10, 1, 1))
write("smb2_request", "query_info_fs", smb2_query_info(11, 1, 1, info_type=2, cls=7))
write("smb2_request", "query_directory", smb2_query_directory(12, 1, 1, "*.bin"))
write("smb2_request", "echo", smb2_simple(0x0D, 13))
write("smb2_request", "logoff", smb2_simple(0x02, 14, 0, 1))
# smbprotocol's stat: CREATE, five QUERY_INFOs and CLOSE, all but the first RELATED_OPERATIONS
# with the all-ones "the handle just opened" FileId.
ONES = b"\xff" * 16
write("smb2_request", "compound_stat", smb2_compound(
    [smb2_create(20, 1, 1, "report.bin")] +
    [smb2_query_info(21 + i, 1, 1, cls=c, fid=ONES, flags=RELATED)
     for i, c in enumerate((4, 5, 6, 35))] +
    [smb2_query_info(25, 1, 1, info_type=2, cls=1, fid=ONES, flags=RELATED),
     smb2_file_id_request(6, 26, 1, 1, fid=ONES, flags=RELATED)]))
# Lengths a peer declares, each at and past what the message holds.
write("smb2_request", "negotiate_dialect_count_bomb", smb2_negotiate(count=0xFFFF))
write("smb2_request", "session_setup_blob_past_end",
      smb2_session_setup(1, 0, b"NTLMSSP\x00", blob_len=0xFFFF))
write("smb2_request", "session_setup_blob_offset_past_end",
      smb2_session_setup(1, 0, b"x", blob_off=0xFFFF))
write("smb2_request", "tree_connect_path_past_end",
      smb2_tree_connect(3, 1, r"\\a\b", path_len=0xFFFF))
write("smb2_request", "create_name_past_end", smb2_create(4, 1, 1, "x", name_len=0xFFFF))
write("smb2_request", "create_odd_name_len", smb2_create(4, 1, 1, "xy", name_len=3))
write("smb2_request", "write_length_bomb", smb2_write(9, 1, 1, b"x", length=0xFFFFFFFF))
write("smb2_request", "write_offset_bomb", smb2_write(9, 1, 1, b"x", data_offset=0xFFFF))
write("smb2_request", "read_length_bomb", smb2_read(8, 1, 1, length=0xFFFFFFFF,
                                                    offset=0xFFFFFFFFFFFFFFFF))
write("smb2_request", "query_directory_name_past_end",
      smb2_query_directory(12, 1, 1, "*", name_len=0xFFFF, out_len=0xFFFFFFFF))
write("smb2_request", "query_info_out_len_bomb", smb2_query_info(10, 1, 1, out_len=0xFFFFFFFF))
write("smb2_request", "next_command_past_end",
      smb2_header(0x0D, 1, next_command=0xFFFFFFF8) + b"\x04\x00\x00\x00")
write("smb2_request", "next_command_unaligned",
      smb2_compound([smb2_simple(0x0D, 1), smb2_simple(0x0D, 2)])[:20] + struct.pack("<I", 68)
      + smb2_compound([smb2_simple(0x0D, 1), smb2_simple(0x0D, 2)])[24:])
write("smb2_request", "next_command_short", smb2_header(0x0D, 1, next_command=8) + b"\x04\x00\x00\x00")
write("smb2_request", "smb1_negotiate", b"\xffSMBr" + b"\x00" * 60)
# SMB2 has no nesting; a compound chain is its long axis. 14 000 minimal ECHOs, each 72 bytes
# padded: ~1 MB, under both the server's frame bound and the 1 MiB at which libFuzzer silently
# truncates a seed (fuzz/README.md).
write("smb2_request", "chain_length_bomb",
      smb2_compound([smb2_simple(0x0D, i) for i in range(14000)]))

write("ntlmssp_token", "bare_negotiate", NTLM_NEGOTIATE)
write("ntlmssp_token", "spnego_negotiate", spnego_init(NTLM_NEGOTIATE))
write("ntlmssp_token", "spnego_authenticate_anonymous", spnego_resp(ANON_AUTH))
write("ntlmssp_token", "bare_authenticate_guest", GUEST_AUTH)
write("ntlmssp_token", "authenticate_oem", ntlm_authenticate("bob", flags=0x62088202)[:64] +
      b"bob")
write("ntlmssp_token", "authenticate_truncated", b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 20)
write("ntlmssp_token", "authenticate_field_past_end",
      b"NTLMSSP\x00" + struct.pack("<I", 3) +
      struct.pack("<HHI", 0xFFFF, 0xFFFF, 0xFFFFFFF0) * 6 + struct.pack("<I", 1))
write("ntlmssp_token", "authenticate_odd_utf16",
      ntlm_authenticate("x")[:36] + struct.pack("<HHI", 3, 3, 64) + ntlm_authenticate("x")[44:])
write("ntlmssp_token", "kerberos_only", der(0x60, SPNEGO_OID + der(0xa0, der(0x30, b""))))
# The depth bomb. SPNEGO is ASN.1, and a DER walker recurses once per constructed TLV. The
# server does not walk the DER — it scans for the NTLMSSP signature — so this is refused by
# nothing and costs a linear scan. It is here for the day a real DER parser replaces the scan:
# 20 000 nested SEQUENCEs (indefinite-length form, two bytes a level) with a token at the bottom,
# inside the 16-bit SecurityBufferLength.
write("ntlmssp_token", "der_depth_bomb",
      b"\x30\x80" * 20000 + NTLM_NEGOTIATE + b"\x00\x00" * 8000)

# ---------------------------------------------------------------------------------- hdfs_wire
# Hadoop IPC frame bodies (what follows the four-byte length) and DataTransferProtocol packets,
# encoded here field by field from the .proto files in proto/hadoop rather than by NetGet.

def pb_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb_key(num, wire):
    return pb_varint(num << 3 | wire)


def pb_ld(num, payload):
    return pb_key(num, 2) + pb_varint(len(payload)) + payload


def pb_int(num, n):
    return pb_key(num, 0) + pb_varint(n)


def pb_sint(num, n):
    return pb_int(num, (n << 1) ^ (n >> 31))


def pb_delimited(msg):
    return pb_varint(len(msg)) + msg


CLIENT_ID = bytes(range(16))


def rpc_header(call_id):
    return pb_int(1, 2) + pb_int(2, 0) + pb_sint(3, call_id) + pb_ld(4, CLIENT_ID) + pb_sint(5, 0)


def rpc_call(call_id, method, body):
    method_header = (pb_ld(1, method.encode()) +
                     pb_ld(2, b"org.apache.hadoop.hdfs.protocol.ClientProtocol") + pb_int(3, 1))
    return (pb_delimited(rpc_header(call_id)) + pb_delimited(method_header) +
            pb_delimited(body))


def packet(offset, seqno, last, data, sums):
    header = (pb_key(1, 1) + struct.pack("<q", offset) + pb_key(2, 1) + struct.pack("<q", seqno) +
              pb_int(3, 1 if last else 0) + pb_key(4, 5) + struct.pack("<i", len(data)))
    return struct.pack(">IH", 4 + len(sums) + len(data), len(header)) + header + sums + data


def crc32c_py(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


def chunk_sums(data):
    return b"".join(struct.pack(">I", crc32c_py(data[i:i + 512])) for i in range(0, len(data), 512))


write("hdfs_wire", "connection_context",
      pb_delimited(rpc_header(-3)) +
      pb_delimited(pb_ld(2, pb_ld(1, b"alice")) +
                   pb_ld(3, b"org.apache.hadoop.hdfs.protocol.ClientProtocol")))
write("hdfs_wire", "sasl_negotiate", pb_delimited(rpc_header(-33)) + pb_delimited(pb_int(2, 1)))
write("hdfs_wire", "get_file_info", rpc_call(0, "getFileInfo", pb_ld(1, b"/user/alice")))
write("hdfs_wire", "get_listing",
      rpc_call(1, "getListing", pb_ld(1, b"/") + pb_ld(2, b"") + pb_int(3, 0)))
write("hdfs_wire", "create",
      rpc_call(2, "create", pb_ld(1, b"/tmp/a") + pb_ld(2, pb_int(1, 0o644)) +
               pb_ld(3, b"DFSClient_1") + pb_int(4, 1) + pb_int(5, 1) + pb_int(6, 1) +
               pb_int(7, 134217728)))
write("hdfs_wire", "response_success",
      pb_delimited(pb_int(1, 0) + pb_int(2, 0) + pb_int(3, 9)) +
      pb_delimited(pb_ld(1, pb_ld(1, b""))))
write("hdfs_wire", "response_error",
      pb_delimited(pb_int(1, 7) + pb_int(2, 1) + pb_ld(4, b"java.io.FileNotFoundException") +
                   pb_ld(5, b"File does not exist: /x") + pb_int(6, 1)))
DATA = b"hello from netget\n" * 40
write("hdfs_wire", "packet", packet(0, 0, False, DATA, chunk_sums(DATA)))
write("hdfs_wire", "packet_train",
      b"".join(packet(i * 512, i, False, b"x" * 512, chunk_sums(b"x" * 512)) for i in range(64)) +
      packet(64 * 512, 64, True, b"", b""))
write("hdfs_wire", "packet_bad_checksum", packet(0, 0, False, DATA, b"\x00" * len(chunk_sums(DATA))))
write("hdfs_wire", "oversize_plen", struct.pack(">IH", 0xFFFFFFF0, 25) + b"\x00" * 25)
write("hdfs_wire", "acks_and_responses",
      pb_delimited(pb_int(1, 0)) + pb_delimited(pb_key(1, 0) + pb_varint(2) + pb_int(2, 0)) +
      pb_delimited(pb_int(1, 6)))
# The depth bomb. None of Hadoop's messages nests itself, but prost skips an unknown group by
# recursing into it, one level per start-group key: 10 000 of them (field 15, wire type 3) in
# a create request's body. prost stops at 100 levels; a decoder without that counter would
# overflow the stack.
write("hdfs_wire", "depth_bomb",
      rpc_call(3, "create", pb_ld(1, b"/tmp/a") + pb_key(15, 3) * 10000 + pb_key(15, 4) * 10000))

total = sum(len(files) for _, _, files in os.walk(CORPUS))
print("seeded %d corpus files across %d targets" %
      (total, len(os.listdir(CORPUS))))
