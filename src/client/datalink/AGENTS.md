# DataLink Client Implementation

## Overview

The DataLink client provides LLM-controlled raw frame injection and capture through libpcap, framed for
the interface's link type, plus structured IPv4/TCP crafting (`send_ipv4_tcp`) and a one-shot probe
(`probe_tcp`) that sends a crafted segment and returns the decoded replies on its flow. This enables
custom protocol testing, ARP spoofing detection, network monitoring, TCP option / MPTCP handshake probing,
and frame analysis.

## Link types (read this first)

libpcap's frames are in the interface's **link-layer format**, which is not always Ethernet.
macOS `lo0` — the most common interface to point this at, and the DataLink *server*'s default —
is `DLT_NULL`: every frame starts with a 4-byte address family **in host byte order**, and there
are no MACs. Until November 2026 the client assumed Ethernet everywhere, so a structured
`inject_frame` on `lo0` put a 14-byte MAC header where the family belongs, and every captured
frame was decoded into invented `dst_mac` / `src_mac` / `ethertype` read out of the family word
and the IP header.

The handle's DLT is read when it opens (`Capture::get_datalink`, `packet::LinkType::from_dlt`)
and reported as `link_type` in `datalink_connected` and in every frame event. Everything that
builds or decodes a frame takes it (`src/client/datalink/packet.rs`):

| `link_type` | Header | Structured `inject_frame` | Captured frame event |
|---|---|---|---|
| `EN10MB` | dst MAC, src MAC, EtherType | `dst_mac`, `src_mac`, `ethertype` | MACs and EtherType |
| `NULL` | 4-byte family, **host** order | `ethertype` ipv4/ipv6 only → AF_INET / AF_INET6; MACs **refused** | `dst_mac`/`src_mac` null, `family` set, `ethertype` derived from it |
| `LOOP` | 4-byte family, **network** order | as NULL | as NULL |
| `RAW` / `IPV4` / `IPV6` | none | just `payload` (the IP packet) | `ethertype` from the version nibble |
| `LINUX_SLL` | 16-byte cooked | refused (libpcap cannot inject into `any`) | EtherType decoded |

`AF_INET6` is the platform's own value when building (30 on macOS, 28 FreeBSD, 24
OpenBSD/NetBSD); when decoding all three BSD values are accepted, as libpcap's own `DLT_NULL`
documentation says a reader must. `frame_hex` passes through untouched on every link type.

The registry's `DataLinkClientProtocol::new()` has no handle behind it (`LinkSession::default`,
`link_type: None`): it only validates, and its structured `inject_frame` assumes Ethernet. A
connected client executes with `DataLinkClientProtocol::with_session(..)`, built from the open
handle.

## Architecture

### Library Choice

**Primary Library:** `pcap` crate (v2.2)

- **Rationale:** Industry-standard libpcap wrapper for packet capture/injection
- **Capabilities:**
    - Raw frame injection via `sendpacket()`
    - Promiscuous mode frame capture
    - BPF (Berkeley Packet Filter) filtering
    - Cross-platform (Linux, macOS, Windows)
- **Limitations:**
    - Requires root/CAP_NET_RAW privileges
    - Blocking I/O (requires `spawn_blocking`)
    - Platform-specific behavior differences

### Connection Model

Unlike TCP/UDP clients, the DataLink client:

1. **Interface-based**: Opens a network interface (e.g., `eth0`, `en0`) instead of connecting to a remote address
2. **Bidirectional**: Can both inject frames and capture frames in promiscuous mode
3. **Blocking Operations**: pcap is blocking, so we use `tokio::spawn_blocking` for the capture/injection loop
4. **Channel-based Injection**: Uses `mpsc::unbounded_channel` to send injection commands from async context to blocking
   pcap thread

### Lifecycle: `connect()` awaits the capture handle

`connect_with_llm_actions` does **not** return until the blocking pcap task has reported, over a
oneshot, that it found the device and opened a handle. A failure — no such interface, or no BPF
access — comes back as `Err`, and `client_startup` puts the client in `ClientStatus::Error`.

This was the capture family's signature bug and this client had it: the pcap work was
fire-and-forget, so `connect` returned `Ok` before anything was known, and on a host without
capture access the client sat in `Connected` unable to inject a byte. `[ send ]` was live and
answered every frame with an explanation. `datalink_client_refuses_an_interface_it_cannot_open`
and `connect_outcome_on_loopback_matches_capture_privilege` assert both branches, and the second
has teeth on either kind of host.

### Shutdown: the pcap loop can be stopped

`JoinHandle::abort()` cannot interrupt a thread parked in `next_packet()`, so the loop polls a
[`StopSignal`](../../utils/shutdown.rs) it gets through `register_client_task` — the same
mechanism the four capture *servers* use. `remove_client` aborts that parked task, the guard
trips the flag, and the loop exits within one poll (≤10ms in injection-only mode, ≤100ms while
in `next_packet`). An injected or model-issued `disconnect` trips it directly.

Before this the loop had no exit at all. It held the capture handle after the client was gone
and kept calling the model, and it did something worse in tests: the runtime could not shut
down, because `BlockingPool::shutdown` waits for blocking tasks and this one was
`loop { … thread::sleep(10ms) }`. `injected_frame_is_transmitted` did not fail, it **hung the
whole test binary** — which is why nobody had noticed the loop was unstoppable.

### State Management

- **ConnectionState**: `Idle` / `Processing` — one model turn per client at a time
- **ClientData**: that state, plus a **count** of frames dropped because a turn was running.
  It used to hold a `Vec<Vec<u8>>` of those frames that was only ever `clear()`ed — unbounded
  growth (up to 64 KiB a frame) in exchange for nothing — and a second copy of the client's
  memory that diverged from the one in `AppState` every other path reads.
- **InjectionCommand**: channel message for a frame injection, carrying the frame, an optional
  acknowledgement channel, and `llm_depth` (see **Bounds** below)

### Capture, promiscuous mode, filter, remote_addr

These used to be one knob: `promiscuous: true` was the only way to capture, and capture was
tied to it, so a client on loopback (where promiscuous mode means nothing) had to ask for it to
see a reply, and one that wanted to inject and see the answer without the NIC in promiscuous mode
could not. They are now separate:

- **`promiscuous`** — the NIC setting only.
- **`capture`** — whether frames are read and delivered as `datalink_frame_captured`. **Defaults
  to the value of `promiscuous`**, so every existing client behaves exactly as it did, and a
  client that sets neither only injects. That default is deliberate rather than `true`: every
  captured frame is a model call (or a handler run), and an unfiltered capture on a busy
  interface would turn a client created to send one frame into a stream of model calls.
- **`filter`** — a BPF expression applied to the capture handle (invalid → `connect` fails with
  `invalid BPF filter`). Without one, a `remote_addr` that is an address implies
  `host X and port Y` (or `host X`; port 0 counts as none); `""` means no filter at all; a
  `remote_addr` that is not an address (`"lo0"`, `"eth0"` — what the startup examples pass)
  implies nothing. `resolve_capture_filter` is the pure function.
- **`remote_addr`** is now meaningful rather than ignored: an IPv4 `host:port` is the default
  `dst_ip` / `dst_port` for `send_ipv4_tcp` and `probe_tcp`, and the default capture filter.
  MCP `start_client` requires it, so it stays required; what it was taken to mean is stated in
  the connect message — the client stores a `connect_note` in its `protocol_data`, which the MCP
  `start_client` result and the client's own status line print (e.g. `interface lo0, link_type
  NULL (loopback); capture off: frames are injected, not delivered to the model (probe_tcp still
  returns its replies); send_ipv4_tcp / probe_tcp default to 127.0.0.1:3333`).

The capture handle opens with `immediate_mode(true)`, so a captured frame is delivered as it
arrives rather than when the BPF buffer's timeout rotates it.

## LLM Integration

### Events

The full list, what raises each, and the depth rules are under **Events, and the chain between
them** at the foot of this file. Both frame-carrying events use the same payload, built by the
public, pure `frame_event_fields_for_link(frame, link_type, loopback)` (`frame_event_fields()`
is the Ethernet, non-loopback case):

| field | meaning |
|---|---|
| `link_type` | the handle's link type, `"EN10MB"`, `"NULL"`, `"LOOP"`, `"RAW"`, … — always present |
| `dst_mac` | destination MAC, `"ff:ff:ff:ff:ff:ff"` — the spelling `inject_frame` accepts back; `null` on a link with no MACs |
| `src_mac` | source MAC, same spelling, same `null` |
| `ethertype` | `"0x0806"`, likewise accepted back unchanged; on NULL/LOOP the one the family means |
| `family` | NULL/LOOP only: `"AF_INET"` / `"AF_INET6"` (a number when unknown) |
| `ip` | IPv4 header decoded (src, dst, protocol, ttl, id, DF, total_length, checksum, `checksum_ok`) — absent when not IPv4 |
| `tcp` / `udp` / `icmp` | the transport header decoded — absent when not present; see below |
| `payload` | everything after the link header (14 bytes Ethernet, 4 NULL/LOOP, 0 RAW), read per `payload_encoding` |
| `payload_encoding` | `"utf8"` when the payload is all printable ASCII, else `"hex"` |
| `frame_hex` | hex of the **first 2048 bytes** (`MAX_HEX_BYTES_TO_MODEL`), for exact replay |
| `frame_length` | the frame's true length, always |
| `captured_length` | how many bytes `frame_hex` covers |
| `truncated` | whether `frame_hex` (and `payload`) is a prefix |

The header fields exist because the payload used to be `frame_hex` and nothing else, so a
model that wanted to know who a frame was addressed to had to slice hex in its head. They are
spelled exactly as `inject_frame` accepts them, so answering a captured frame is copying
fields rather than re-deriving them, and `frame_hex` stays beside them for replaying one
verbatim. `dst_mac`, `src_mac` and `ethertype` are `null` for a frame shorter than 14 bytes —
a real Ethernet frame cannot be, but libpcap can hand back a runt and inventing a header for
one would be worse than saying there is none.

A frame can be 65535 bytes and all of it as hex is 131070 characters of prompt. The length and
the prefix are reported separately so a model is never told a 9000-byte frame was 2048 bytes
long. `tests/client/datalink/action_test.rs` asserts all of this against literal bytes,
including the exact boundary, the runt, and that every field the payload carries is one the
events declare; `packet_test.rs` asserts the link-type and IP/TCP decoding.

**The `tcp` object** carries `src_port`, `dst_port`, `seq`, `ack`, `flags` (names: `syn`, `ack`,
`fin`, `rst`, `psh`, `urg`, `ece`, `cwr`), `window`, `urgent`, `header_length`, `options`,
`checksum` / `checksum_ok` / `checksum_note`, `payload_length` (and `payload` +
`payload_encoding` when there is data). `options` is a list in **exactly the spelling
`send_ipv4_tcp` accepts**: `{"kind":"mss","value":16344}`, `{"kind":"wscale","shift":7}`,
`{"kind":"sack_perm"}`, `{"kind":"sack","blocks":[[l,r]]}`,
`{"kind":"timestamps","tsval":…,"tsecr":…}`, `{"kind":"nop"}`, MPTCP MP_CAPABLE as
`{"kind":"mp_capable","version":1,"flags":1,"flag_names":["hmac_sha256"],"sender_key":"0x…"}`,
other MPTCP subtypes as `{"kind":"mptcp","subtype":"mp_join","subtype_number":1,"data_hex":"…"}`
(re-encodable), anything else as `{"kind": n, "data_hex": "…"}`, and an impossible length as
`{"kind": n, "malformed": true}`. EOL ends the list and is not reported (it is padding).

**Checksums on loopback.** The kernel leaves TCP/UDP checksums for offload on loopback, because
the packet never crosses a wire, so a macOS `lo0` SYN-ACK or RST carries `0x0000` — which looks
like a broken packet to a reader. On a loopback interface (`Device::flags.is_loopback()`) a zero
checksum is reported as `checksum_ok: null` with a `checksum_note` saying exactly that; any other
mismatch is `checksum_ok: false` with a note (on a non-loopback interface: usually transmit
offload for a frame this host sent). A checksum over bytes the capture did not cover is
`checksum_ok: null`, "not verified".

### Actions

#### Async Actions (User-triggered)

1. **inject_frame**: Inject a raw frame, built from fields for the interface's link type
   ```json
   {
     "type": "inject_frame",
     "dst_mac": "ff:ff:ff:ff:ff:ff",
     "src_mac": "00:11:22:33:44:55",
     "ethertype": "arp",
     "payload": "0001080006040001001122334455 0a000001 000000000000 0a000002",
     "payload_encoding": "hex"
   }
   ```
   The escape hatch is still there for a frame you already have whole — typically one a
   `datalink_frame_captured` event just handed you:
   ```json
   {"type": "inject_frame", "frame_hex": "ffffffffffff0011223344550806…"}
   ```

   On a loopback link (`NULL`/`LOOP`) the same action is `{"type":"inject_frame",
   "ethertype":"ipv4","payload":"4500…","payload_encoding":"hex"}` — no MACs, which are refused.

2. **send_ipv4_tcp**: one IPv4 TCP segment from fields; both checksums and the link header are
   built for you
   ```json
   {
     "type": "send_ipv4_tcp",
     "dst_ip": "127.0.0.1", "dst_port": 3333, "src_port": 40000,
     "flags": ["syn"],
     "options": [{"kind": "mss", "value": 16344}, {"kind": "mp_capable", "version": 1, "flags": 1}]
   }
   ```
   Defaults: `dst_ip`/`dst_port` from `remote_addr`; `src_ip` = `dst_ip` when that is loopback
   (required otherwise — a source is never guessed); `src_port` random ephemeral; `flags`
   `["syn"]`; `seq` random; `ack` 0; `window` 65535; `ttl` 64; `ip_id` random; DF set; `tos` 0.
   `payload` takes the usual required `payload_encoding`. On Ethernet `dst_mac` and `src_mac`
   are required (no ARP is done); elsewhere they are refused. Options: the list above, plus the
   escape hatch `{"kind": <n>, "data_hex": "…"}`; padded with EOL to 4 bytes, refused past 40.
   MP_CAPABLE `flags` is the byte or names (`checksum_required`, `extensibility`,
   `no_new_subflows_to_source`, `hmac_sha256`; default `0x01`), with optional `sender_key` /
   `receiver_key` (64-bit, number or `0x` string), `data_level_length`, `checksum`.

3. **probe_tcp**: `send_ipv4_tcp` plus `timeout_ms` (default 1000, max 10000) and
   `max_replies` (default 1, max 16). Sends the segment and returns the replies on its flow,
   decoded — see **One-shot probe** below.

4. **disconnect**: Close the DataLink client and release interface
   ```json
   {
     "type": "disconnect"
   }
   ```

#### Sync Actions (Response to captured frames)

1. **inject_frame**: Inject frame in response to captured frame
    - Same parameters as async version
2. **send_ipv4_tcp**: as above

3. **wait_for_more**: Wait for more frames before responding
   ```json
   {
     "type": "wait_for_more"
   }
   ```

### Frame Format

An Ethernet frame is structured, so the model writes it as fields rather than as a blob. That
is the whole change: `inject_frame` used to take one parameter, `frame_hex`, and its example
was a 42-byte ARP request written out as 84 hex characters — on the action and on two event
types — which a model cannot proofread and nothing downstream checks.

This section describes the Ethernet spelling; see **Link types** at the top for what changes on
`NULL` / `LOOP` / `RAW` (`build_frame_for_link`).

- **`dst_mac`** / **`src_mac`**: `"00:11:22:33:44:55"`, `"00-11-…"`, `"001122334455"` or the
  uppercase of any of them; `"ff:ff:ff:ff:ff:ff"` to broadcast. Exactly six bytes, refused by
  name with the length it decoded to. Ethernet only — refused on a link without MACs rather
  than silently dropped, because a caller who gives them has misread which interface they are
  on.
- **`ethertype`**: a name (`ipv4`, `arp`, `vlan`, `ipv6` — `ETHERTYPE_NAMES`), a number
  (`2054`), or a `0x`-prefixed hex string (`"0x0806"`). **A bare `"0806"` is refused**: it is
  2054 read as hex and 806 read as decimal, and only the caller knows which. That is the same
  ambiguity the encoding fields exist for, given the same treatment — say which, do not guess.
- **`payload`** with **`payload_encoding`**: everything after the link header.
  `payload_encoding` is **required whenever `payload` is present** and has *no* default,
  unlike `send_tcp_data`'s `encoding`. An Ethernet payload is binary far more often than it is
  text — ARP, IPv4 and IPv6 are the three a model will build — so a `utf8` default would put
  the ASCII characters of an ARP body on the wire for exactly the frames most likely to be
  written. `"deadbeef"` is four bytes as hex and eight characters as text; the field says
  which, and `a_utf8_payload_that_looks_like_hex_goes_out_as_those_characters` asserts both
  readings of the same string produce different frames.
- **`frame_hex`**: the escape hatch, a complete frame including its header. It stays because
  `datalink_frame_captured` hands the model exactly that and replaying or amending a captured
  frame is a real thing to want. **The two spellings cannot be combined** — supplying
  `frame_hex` together with any of `dst_mac` / `src_mac` / `ethertype` is refused rather than
  resolved by precedence, and a structured frame missing one of its three required fields is
  refused by the name of what is missing rather than completed with zeros.
- **No FCS.** `pcap::sendpacket` puts exactly the bytes it is given on the wire and the
  interface computes the frame check sequence itself, so four bytes of model-computed FCS
  would go out as payload. The `inject_frame` definition used to say "including dst MAC, src
  MAC, ethertype, payload, **FCS**"; a model that followed it corrupted every frame it sent.
  `inject_frame_does_not_ask_the_model_for_an_fcs` keeps that wording from coming back. For
  the same reason the link header is assembled from the fields and must not be repeated in
  `payload`.

`build_frame_for_link` bounds the assembled frame before libpcap sees it: at least
`MIN_ETHERNET_FRAME_BYTES` (14 — a runt has no EtherType) on Ethernet, the link header's length
elsewhere, and at most
`MAX_ETHERNET_FRAME_BYTES` (65535), each refused with a message naming the actual length so
the model can correct it. Octet separators (`:`, `-`, ` `, `.`) are stripped from `frame_hex`,
from a hex `payload` and from a MAC before decoding, because a model writing hex out of a
packet dump writes them and they carry no information.

Example ARP request frame:

```
ff ff ff ff ff ff  // Destination MAC (broadcast)
00 11 22 33 44 55  // Source MAC
08 06              // EtherType (ARP)
00 01              // Hardware type (Ethernet)
08 00              // Protocol type (IPv4)
06                 // Hardware address length
04                 // Protocol address length
00 01              // Operation (ARP request)
00 11 22 33 44 55  // Sender MAC
0a 00 00 01        // Sender IP (10.0.0.1)
00 00 00 00 00 00  // Target MAC (unknown)
0a 00 00 02        // Target IP (10.0.0.2)
```

## Use Cases

1. **ARP Testing**: Inject ARP requests/replies for network discovery
2. **Custom L2 Protocols**: Test proprietary Ethernet protocols
3. **Network Monitoring**: Capture and analyze Ethernet traffic
4. **ARP Spoofing Detection**: Monitor for duplicate ARP replies
5. **MAC Address Analysis**: Track MAC address usage on network
6. **Frame Timing Analysis**: Measure frame arrival times

### Dashboard injection (`[ send ]`)

`connect_with_llm_actions` registers a command channel
(`client::command_support::register_command_channel`) before the pcap task starts and spawns
a `command_loop` task (registered with `register_client_task`), so `[ send ]` is live from
the moment the client exists — including while the connected-event call below is parked on a
manual routing rule.

There is no `AsyncWrite` half here, so the generic `handle_stream_client_command` cannot be
used. An injected `inject_frame` goes through the protocol's own `execute_action` and lands
in the same `InjectionCommand` queue the LLM path uses. That command now carries an optional
`oneshot` acknowledgement, which the pcap loop fills with the result of `sendpacket` - that
is what makes a truthful outcome possible:

| Outcome | When |
|---|---|
| `Sent { bytes_sent }` | the pcap loop acknowledged a successful `sendpacket` for that many bytes |
| `Probed { bytes_sent, report }` | a `probe_tcp` was sent and its replies collected — see below |
| `Executed { detail }` | the frame could not be handed over, or was not acknowledged - `detail` names the reason and the frame size |
| `Rejected { error }` | unknown verb, bad fields, a field the link cannot carry (MACs on `lo0`), or a frame too short/too long |
| `Disconnected` | an injected `disconnect` |

### One-shot probe (`probe_tcp`)

The thing a person hand-crafting a SYN wants is the answer on that flow, not "sent 52 bytes".
`probe_tcp` builds the segment like `send_ipv4_tcp`, then:

1. the probe worker task (one probe at a time, `probe_worker`) opens a **second, short-lived
   pcap handle** on the same interface — `immediate_mode`, 20ms read timeout, kernel filter
   `TcpFlow::reply_filter()` = `(tcp and src host D and src port DP and dst host S and dst port
   SP) or (icmp and dst host S)` — *before* anything is sent, so a fast reply cannot be missed;
2. the segment goes out through the main handle's injection queue (acknowledged, and flagged
   `report: false`, so it does not also raise `datalink_frame_injected`);
3. replies are read until `timeout_ms` after the send or `max_replies`, each re-checked in user
   space (`reply_matches`: the reversed 4-tuple, or an ICMP error whose quoted header is ours —
   on `lo0` our own SYN is on the wire too and must not count);
4. the report is `{flow, sent: {ip, tcp, summary}, reply_count, replies: [frame event fields +
   after_ms + options_echoed + options_not_echoed], waited_ms, summary: ["+0ms tcp
   127.0.0.1:3333 -> 127.0.0.1:40000 [syn, ack] options: mss; echoed: mss; not echoed:
   mp_capable"]}`.

It needs neither `capture` nor `promiscuous`, and is unaffected by `filter`. From
`send_to_client` the report is the result — `ClientSendOutcome::Probed`, which
`mcp_stdio::control::describe_outcome` prints as pretty JSON and the dashboard as the summary
lines; the access log keeps only `reply_count` and `summary`. From the model it arrives as
`datalink_probe_completed`. `run_probe_on` is public.

**There is no unprivileged path into this any more.** It used to be reachable — `connect`
returned `Ok` without a capture handle, so the dashboard offered `[ send ]` on a client that
could never send, and every injection came back `Executed` with an explanation. Now `connect`
fails instead, so the client does not exist to be sent to. The `Executed` branch survives for
the one case that remains real: the pcap loop has exited (a `disconnect`, or a capture error)
while the handle has not yet been dropped.

**Known gap**: with capture off the pcap loop polls the queue every 10ms and with capture on
it can sit up to 100ms in `next_packet`, so an injected frame is put on the
wire with up to that much latency. The acknowledgement wait is bounded at 5s.

Tests: `tests/client/datalink/action_test.rs` (no privilege — the whole model-facing surface),
`packet_test.rs` (no privilege — builder and decoder against literal bytes) and
`command_channel_test.rs` (the lifecycle; its privileged half asserts a real acknowledged
`sendpacket`, a real `disconnect`, that the capture loop actually stops, and a `probe_tcp` SYN
with MP_CAPABLE on loopback answered by a decoded SYN-ACK from a listener and a RST from a
closed port).

## Limitations

1. **Privilege Requirement**: layer-2 capture access — `/dev/bpf*` on macOS/BSD, root or
   `CAP_NET_RAW` on Linux. Declared as `PrivilegeRequirement::PacketCapture`, matching the
   DataLink *server*. It said `RawSockets` until this pass, which is a **different** capability
   in `SystemCapabilities`: a macOS user in the ChmodBPF group has capture and not raw sockets,
   and would have been refused a client that works on their machine.
2. **Blocking I/O**: pcap is blocking, so operations run in `spawn_blocking`
3. **No FCS**: the interface computes it; do not put one in `payload` or `frame_hex`
4. **Platform Differences**: libpcap behavior varies across OS
5. **IPv4 TCP only**: `send_ipv4_tcp` / `probe_tcp` build IPv4 TCP; there is no structured
   builder for UDP, ICMP or IPv6 (decode covers IPv4 TCP, UDP and ICMP; IPv6 frames are reported
   with their link fields and `frame_hex` only). Use `inject_frame` with a hex payload for those.
6. **Performance**: capture can outrun the model. One model turn runs at a time per client;
   frames that arrive during it are **dropped and counted**, not queued
7. **Dummy SocketAddr**: Returns `127.0.0.1:0` since DataLink doesn't use sockets. The kernel
   knows nothing of a flow a probe opens, so it answers the far end's SYN-ACK with its own RST;
   that is expected, and the probe's reply filter only sees the far end's side.
8. **Unproven except by privileged tests**: injection has been exercised end to end on macOS
   (2026-09-08), but only by tests that need capture access. Nothing an unprivileged run
   executes has ever put a frame on a wire. `Experimental`, and for that reason.

## Startup Parameters

- **interface** (required, string): Network interface name (e.g., `eth0`, `en0`, `wlan0`)
- **promiscuous** (optional, boolean): the NIC's promiscuous mode (default: `false`)
- **capture** (optional, boolean): deliver captured frames as `datalink_frame_captured`
  (default: the value of `promiscuous`)
- **filter** (optional, string): BPF filter for the capture (default: from an address
  `remote_addr`, else none; `""` for none)

Example:

```json
{
  "interface": "lo0",
  "capture": true,
  "filter": "tcp port 3333"
}
```

## Testing Strategy

See `tests/client/datalink/AGENTS.md` for E2E testing approach.

## Security Considerations

**CRITICAL**: Raw frame injection can disrupt networks and violate regulations. Only use on authorized test networks:

- ✅ Isolated lab environments
- ✅ Virtual networks (VMs, containers)
- ✅ Personal test setups
- ❌ Production networks
- ❌ Public networks
- ❌ Networks you don't own

ARP spoofing and MAC address manipulation can be malicious - use responsibly.

## Implementation Notes

1. **Channel-based Injection**: The async LLM code sends injection commands via `mpsc::unbounded_channel` to the
   blocking pcap thread
2. **State Machine**: Prevents concurrent LLM calls (Idle → Processing → Accumulating)
3. **Dual Logging**: Uses both `tracing` macros and `status_tx` for TUI updates
4. **Error Handling**: Injection failures are logged but don't crash the client
5. **Graceful Shutdown**: Client tracks disconnection via `ClientStatus::Disconnected`

## Future Enhancements

- Structured UDP / ICMP / IPv6 builders
- `probe_tcp` replies for IPv6
- Multiple interface support
- Frame statistics (capture rate, injection rate)
- Frame timing control (scheduled injection)
- VLAN tag support
- Jumbo frame support


## Events, and the chain between them

Three, all raised by this client and all returned from `get_event_types()` as clones of the
same statics, so a declaration cannot drift from what is emitted:

- **`datalink_connected`** — the capture handle is open. This is what lets the model act on
  its instruction; before it existed the client opened the interface and asked the model
  nothing, so a client created with "inject an ARP request for 10.0.0.2" opened `lo0` and
  then sat there having done nothing at all.
- **`datalink_frame_injected`** — a frame really went out (`sendpacket` returned Ok). It was
  declared and raised nowhere, so a model that injected a frame was never told it had worked
  and could not follow it with anything.
- **`datalink_frame_captured`** — with `capture` on only (whose default is `promiscuous`).
- **`datalink_probe_completed`** — a `probe_tcp` *the model* issued has finished; the payload is
  the probe report (`flow`, `sent`, `replies`, `reply_count`, `waited_ms`, `summary`). Bounded by
  the same depth as the injection chain: a model probe at depth `MAX_INJECTION_FOLLOWUPS` is not
  run. A probe from `send_to_client` returns its report to the caller instead and raises
  nothing.

All four carry `.with_actions(...)` — `inject_frame` and `wait_for_more`, plus `send_ipv4_tcp` and
`probe_tcp` on `datalink_connected` and `datalink_probe_completed`. A client's tool list
is async ∪ sync ∪ the firing event's actions, so this is belt and braces rather than load
bearing, but an event that declares no vocabulary is a declaration that means nothing.

### Bounds

**The chain runs through the injection queue, not the stack.** `run_llm_turn` raises one event,
queues whatever frames the model asks for, and returns. Injecting raises
`datalink_frame_injected` from the pcap loop, which calls `run_llm_turn` again — so
inject → report → inject continues with no recursion to box.

**It is still a cycle, and it is bounded.** The earlier version of this note treated "no
recursion" as the end of the argument and said in as many words that the chain "continues
without any recursion to bound" — but a model that answers every injection with another
injection then loops forever at one LLM call per hop, which is precisely what the repo's
`MAX_FOLLOWUP_DEPTH` rule exists to prevent. `InjectionCommand::llm_depth` carries the hop
count through the queue: the pcap loop raises `datalink_frame_injected` only while it is below
`MAX_INJECTION_FOLLOWUPS` (4), and past that the frame still goes out, the model is simply not
asked again (`decision=followup_depth_capped`). A frame the operator injects from the dashboard
always starts a fresh chain at depth 0 — the cap is on the model's runaway, not on the human.

**One model turn per client.** A captured frame arriving while a turn is running is dropped and
counted (WARN on the first and every hundredth), never queued.

The injected-frame event is raised with `runtime.spawn` from inside the blocking pcap thread
rather than awaited there. That thread owns the libpcap handle and is the only thing that can
call `sendpacket`; blocking it on an LLM call that a manual rule can park for minutes would
stop every other injection, including the dashboard's.

### Failure semantics: nothing is injected, and the log says which nothing

DataLink is one of the deliberately silent protocols — a fabricated frame on a real network is
worse than no frame — so every outcome below looks identical on the wire and is distinguished
in the log. Grep `decision=`:

| tag | meaning |
|---|---|
| `decision=model_inject` | the model answered with at least one frame, which was queued |
| `decision=model_silent` | the model was asked and returned no actions |
| `decision=model_reject` | every action the model returned was refused by the executor |
| `decision=model_no_frame` | actions ran but none injected anything (`wait_for_more`) |
| `decision=model_disconnect` | the model closed the client |
| `decision=fail_closed_llm_error` | the LLM call errored; `category=overloaded` vs `unavailable` from `WireFailure::classify`, plus the full error |
| `decision=followup_depth_capped` | the frame went out; the chain hit `MAX_INJECTION_FOLLOWUPS` |
