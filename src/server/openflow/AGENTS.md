# OpenFlow controller (server)

An OpenFlow 1.3 controller on TCP 6653 (IANA). A switch connects; Rust runs the session and
the model decides the network. The switch side lives in `src/client/openflow/` and shares this
directory's codec.

## Files

| File | What it is |
|---|---|
| `wire.rs` | The OpenFlow 1.3 codec, hand-written from the 1.3.5 spec: header and framing, HELLO bitmap negotiation, ERROR, FEATURES, switch config, role, async config, ports, OXM matches, the six instruction types and the 1.3 action set, PACKET_IN / PACKET_OUT, FLOW_MOD, FLOW_REMOVED, PORT_STATUS, the multipart requests and replies. Pure, no sockets. |
| `fields.rs` | The JSON vocabulary the model reads and writes: matches as `{"field": value}` (CIDR strings and `{"value", "mask"}` for maskable fields), actions and instructions as typed objects, ports as numbers or reserved names. Prerequisite completion and checking (Table 12). |
| `packet.rs` | `describe` turns a packet into headers (Ethernet, ≤2 VLAN tags, ARP, IPv4, IPv6 with ≤8 extension headers, TCP/UDP/SCTP/ICMP/ICMPv6, payload length and text when printable). `build` makes a frame from the model's description with every checksum computed. Reuses VXLAN's RFC 1071 checksum, Ethernet and ICMP echo builders, which is one reason it is native-only like VXLAN. |
| `actions.rs` | Protocol metadata, startup parameter, the five actions and six events, and the JSON → wire conversions the executor validates with. |
| `mod.rs` | The accept loop and the per-switch session. |

No crate: `rust_ofp` is unmaintained and OpenFlow 1.0 only; nothing current covers 1.3.

## The session (`mod.rs`)

1. Both sides send HELLO. The controller offers only 1.3 in its bitmap; a switch offering 1.4/1.5
   negotiates down, one offering only 1.0–1.2 gets `HELLO_FAILED/INCOMPATIBLE` with a text reason
   and is closed (`decision=protocol_reject_version`).
2. FEATURES_REQUEST, SET_CONFIG (`miss_send_len = OFPCML_NO_BUFFER`, so packets arrive whole),
   DESC and PORT_DESC multipart queries. When FEATURES and both replies are in (or after 30 s
   with FEATURES alone) `openflow_switch_connected` is raised.
3. From then on the loop answers ECHO, sends its own ECHO to a switch silent for
   `echo_interval_secs` (default 15) and closes one that does not answer within the same time,
   matches every reply by xid, reassembles multipart replies, and refuses what a switch must not
   send with an ERROR echoing the message.

Two tasks per connection besides the reader: the loop never waits on the model, which runs in a
worker fed through a bounded queue, one event at a time in arrival order. Open vSwitch's own
inactivity probe is five seconds; a model call can take thirty.

## Events and actions

Events: `openflow_switch_connected`, `openflow_packet_in`, `openflow_flow_removed`,
`openflow_port_status`, `openflow_stats_reply`, `openflow_error`. Actions:
`openflow_flow_mod`, `openflow_packet_out`, `openflow_drop_packet`, `openflow_request_stats`,
`openflow_disconnect_switch`. All are also accepted through `send_to_peer`.

A PACKET_IN is stored under a `packet_in_id` (the last 128 per switch). `openflow_packet_out`
sends the packet being answered by default, another one by `packet_in_id`, or a new one built
from `packet`. A buffered packet (when a switch buffers despite SET_CONFIG) is sent by buffer id.
An ERROR from the switch is traced to what it refused through the xid of the last 64 messages
sent, and the model sees the message type, xid and NetGet's own description of it.

## Bounds

| Bound | Value | Where |
|---|---|---|
| Message length | 8–65 535 (the 16-bit field); a shorter claim closes the connection | `wire::read_message` |
| OXMs per match / actions per list / instructions per entry | 64 / 64 / 8 (each type once) | `wire` |
| HELLO elements | 16 | `wire::parse_hello_bitmap` |
| Entries decoded per multipart part | 1 024 | `wire` |
| Outstanding requests / multipart in flight | 256 / 16 | `mod.rs` |
| Multipart reassembly | 1 MiB and 512 parts, then discarded (`decision=fail_closed_multipart_too_large`) and the model told | `mod.rs` |
| Stored packets | 128 | `mod.rs` |
| Events waiting for the model | 64, then dropped (`decision=fail_closed_queue_full`) | `mod.rs` |
| Follow-up chain | 8 turns (`decision=followup_depth`) | `mod.rs` |
| Reported statistics entries | 256, `truncated: true` beyond | `mod.rs` |
| First HELLO / handshake / stats reply | 30 s / 30 s / 60 s | `mod.rs` |
| Connections | 256 (`accept_bounded`, refused with HELLO_FAILED/EPERM) | `mod.rs` |

Nothing recurses: an instruction holds an action list, a set-field action holds one OXM.

## Failing closed

Declared `.deliberately_silent()`: every controller message is an instruction, so with no usable
answer nothing is sent — no PACKET_OUT, no FLOW_MOD — and the packet stays unforwarded, which is
what the switch's own table miss does. There is no default flood. Each event the model is asked
about logs exactly one `decision=`: `model_answer`, `model_reject` (explicit drop or disconnect),
`model_silent`, `fail_closed_bad_action`, `fail_closed_llm_error` / `fail_closed_llm_overloaded`.

## Not implemented

OpenFlow 1.0–1.2 (POX/NOX-era switches), TLS (`ssl:`), auxiliary connections, GROUP_MOD,
METER_MOD, TABLE_MOD and PORT_MOD for the model, role management, table-features queries.

## Maturity

Experimental. One independent switch (Open vSwitch, `tests/server/openflow/real_peer_test.rs`)
with tshark's `openflow_v4` dissector over both directions; no second switch implementation is
packaged for Ubuntu or Homebrew (CPqD's ofsoftswitch13 is source-only and was not attempted), and
the fuzz target has only had short runs.
