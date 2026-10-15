# GTP-C / GTP-U Server (3GPP TS 29.060, TS 29.274)

An LLM-driven **mobile-core node**. The model plays a GGSN/PGW: it decides whether a
subscriber's session is created, what IP address the device is given, which DNS servers it is
told about, and what happens to the user traffic that arrives through the tunnel. NetGet owns
the sockets, the version demultiplex and every octet of encoding.

**Status**: Experimental — see "Maturity" below, which is the honest part.
**Specs**: TS 29.060 (GTPv1-C / GTPv1-U), TS 29.274 (GTPv2-C).
**Ports**: UDP 2123 (control) and UDP 2152 (user), both declared `PrivilegeRequirement::None`.
**Feature**: `gtp` — no optional dependencies; the codec is hand-rolled.

Files: `codec.rs` (pure, no I/O), `actions.rs` (LLM vocabulary + executor), `mod.rs` (two
sockets + the fail-closed rule).

The requesting side (an SGSN, SGW or MME) is the GTP client, `src/client/gtp/`, which
builds its requests on this codec.

## Subscriber identifiers are personal data

IMSI and MSISDN identify a **person's SIM and phone number**. Two rules follow, and they are
structural rather than aspirational:

- **NetGet reads no subscriber source of any kind.** There is no HSS, no HLR, no subscriber
  file, no lookup, no cache. Every identifier this server ever sees arrives in a datagram from
  the peer, and every identifier it ever emits was invented by the model.
- **There is no PDP context table.** Nothing is stored between requests — see "No storage"
  below. That is a consequence of the codebase's own rule, and it happens to be the right
  privacy posture too: this server cannot accumulate a subscriber database because it has
  nowhere to put one.

The model is told in the `imsi` parameter's own description to treat the value as an
identifier and not as something it can look anything up by.

## Privilege: none, and that is the interesting part

2123 and 2152 are both above 1023, so no privilege is required and none is declared. Declaring
`PrivilegedPort(2123)` would be dead code — the `svn`/`PrivilegedPort(3690)` mistake recorded
in the root `AGENTS.md`.

The practical consequence is that **the transport really executes in the test suite**. Unlike
every raw-socket protocol in the same wave, `tests/server/gtp/e2e_test.rs` binds real UDP
sockets, sends real GTP datagrams and decodes real replies. Nothing is simulated except the
model.

## The two encoding rules this protocol is famous for getting wrong

Both are pinned against literal octets in `tests/server/gtp/codec_test.rs`.

### 1. The GTPv1 E/S/PN flags are all-or-nothing

If **any** of the extension-header (E), sequence-number (S) or N-PDU-number (PN) flags is set,
**all four optional octets are present** — two for the sequence number, one for the N-PDU
number, one for the next extension header type — and each field is only *meaningful* when its
own flag is set. The common bug is to consume only the flagged field, which desynchronises
every octet after it: a message with S set and PN clear is then read with the N-PDU octet as
the first byte of the body.

`GtpV1Header::optional_present()` is the rule, applied on both the encode and the decode side.
Note the second consequence: the header's Length field counts those four octets, so a
sequenced Echo Request is 12 octets with `Length = 4`, not 10 with `Length = 2`.

### 2. GTPv1 information elements split at type 128

Types 1..=127 are **fixed-length (TV)**: a type octet followed immediately by a value whose
length is known only from the specification. Types 128..=255 are **TLV** with a two-octet
big-endian length. A parser that assumes TLV throughout reads a Cause IE's value (`0x80`) as
the first octet of a length and gives up 32 kilobytes later.

`v1_fixed_ie_len()` is the table. A fixed-length type it does not know **stops the parse**
(`DecodeError::UnknownFixedIe`) rather than guessing: there is no length on the wire, so there
is no safe way to skip it, and guessing would misread everything after it.

GTPv2-C has neither problem — one flag decides the header length, and every IE is TLIV with an
instance nibble.

## GTPv2-C is implemented, not skipped

Both versions are served on the control port and told apart by the first three bits.

| | GTPv1-C | GTPv2-C |
|---|---|---|
| Version bits | `001` | `010` |
| TEID | always present | conditional on the **T** flag |
| Sequence | 16 bits, in the optional block | 24 bits, always |
| IEs | fixed below 128, TLV at 128+ | TLIV throughout, with an instance nibble |
| Session creation | Create PDP Context Request (16) | Create Session Request (32) |
| Session update | Update PDP Context Request (18) | Modify Bearer Request (34) |
| Session deletion | Delete PDP Context Request (20) | Delete Session Request (36) |

The events are named for the concept rather than the version — `gtp_create_session_request`
fires for both — and every event carries a `version` field. The server replies in whichever
version the request used, and `send_gtp_create_session_response` names its cause
symbolically (`"request_accepted"`) precisely so one action works for both numbering schemes.

GTPv1-U (G-PDU, Error Indication, End Marker) is the only user plane there is; GTPv2 has no
user plane, and a GTPv2 datagram arriving on the GTP-U socket is dropped with a warning.

## Fail closed

`FailureMode` is `Answers`, declared with `.answers_on_failure()` in `metadata()`: a
session-management request is answered with a **refusing** cause. Echo Requests and G-PDUs are
the declared exceptions and stay silent — an Echo Response asserts this node is healthy, and the
only user-plane reply (Error Indication) asserts a tunnel does not exist, which tears the peer's
session down.

A subscriber session is network access, so the OAuth2 post-mortem in the root `AGENTS.md`
applies at full force. `GtpServer::decide` is where it lives.

| Situation | Wire result | Logged decision |
|---|---|---|
| Model returns an accepting cause | the response it asked for | `decision=model_accept` |
| Model returns a refusing cause | the response it asked for | `decision=model_reject` |
| Model returns `no_response` | **nothing** | `decision=model_silent` |
| Model answers an Echo Request | Echo Response | `decision=model_echo` |
| Model returns no usable action | **refusal** (session requests) / **nothing** (echo, G-PDU) | `decision=fail_closed_no_action` |
| Model's action cannot be encoded | same | `decision=fail_closed_action_error` |
| LLM call fails or times out | same | `decision=fail_closed_llm_error` |

Four things make this structural:

1. **Nothing in `actions.rs` can synthesise an acceptance.** `cause` is required with no
   default, and an *accepting* cause additionally requires `assigned_address`, `control_teid`
   and `data_teid` — so a session cannot be granted by leaving fields out. `execute_action`
   returns an error naming the missing field instead.
2. **The synthesised refusal is a different shape.** It carries a Cause IE and nothing else: no
   address, no TEIDs, no PCO. A model refusal and a server refusal therefore differ on the wire
   as well as in the log, which is exactly what OAuth2 lost.
3. **The refusal cause is chosen by category, never by rendering the error.**
   `WireFailure::classify` maps an overloaded backend to **No resources available** (v1 199 /
   v2 73, which a peer may retry) and anything else to **System failure** (v1 204 / v2 72,
   which it should not). The error itself is logged and never reaches the wire — the peer gets
   a category, the log gets the error. `codec_test.rs` asserts both causes are outside the
   acceptance ranges in both versions.
4. **Echo Requests and G-PDUs get silence, not a fabricated reply.** This is the one place GTP
   joins the "deliberately silent" family, and the reason is the `openvpn` one: an Echo
   Response is a *positive assertion* that this node is alive and healthy, so emitting one
   during a backend outage would be inventing a fact. A peer that gets no echo retransmits and
   then tears its tunnels down, which is the correct outcome for a node that genuinely cannot
   serve. The decision token still records what happened.

## No storage — and what that costs

Per the root `AGENTS.md`, protocols must not implement storage. There is **no PDP context
table**: no map of TEIDs to sessions, no subscriber records, no bearer state. The model answers
every request, and continuity across requests comes from server memory (`set_memory`) or the
generic SQLite facility if the operator wants it.

The visible cost is in Delete and Update: a real GGSN answering a Delete PDP Context Request
looks the peer's control TEID up in the context it created earlier. This server cannot, so the
response header echoes the request's own header TEID unless the model supplies `teid`. That is
a documented consequence of the rule, not an oversight — the model can carry the value in
memory across the session if it wants the fully correct behaviour.

## Sequence numbers and TEIDs

`sequence` and `teid` are **optional** action parameters that override server-computed
defaults:

- `sequence` defaults to the request's own sequence number. A GTP peer matches a response to
  its request by this number. **It is range-checked against the header field it is going
  into, not against `u32`** — 16 bits in GTPv1, 24 in GTPv2 — and an over-wide value fails
  closed rather than wrapping. `optional_u32` in `actions.rs` cannot do this check, because
  only `mod.rs` knows which version is being answered; `render` calls `checked_sequence`
  instead. The defect this closes is a nasty one to debug: `70000 as u16` is `4464`, the peer
  cannot match it to any outstanding request, and the symptom is a request that times out —
  which reads as a lost packet and sends you to the network rather than to the field.
  `tests/server/gtp/e2e_test.rs::test_a_sequence_wider_than_the_header_field_fails_closed`
  pins it, and is also the only test of the `synthesised_refusal` path.
- `teid` defaults to the peer's own control TEID — taken from IE 17 (GTPv1) or the Sender
  F-TEID (GTPv2) — falling back to the request header's TEID. On a first contact the request
  header carries 0, so the IE is the only source.

Making them optional is what lets **static and script handlers work**: a static handler cannot
see the request, so if the echo were mandatory it could never answer. Making them *available*
is what lets a test drive the echo explicitly, which
`tests/server/gtp/e2e_test.rs` does throughout via `respond_with_actions_from_event`.

The addresses this node advertises for itself (GSN Address IEs, the F-TEID address) are **not**
model-controlled: they come from the sockets' own local addresses. A wildcard bind yields an
unspecified address, which would be useless inside an F-TEID, so `concrete_ip` substitutes the
loopback.

## Startup parameters

| Parameter | Type | Default | Effect |
|---|---|---|---|
| `user_plane_port` | number | 2152 when the control port is 2123, otherwise **ephemeral** | UDP port for GTP-U |
| `enable_user_plane` | boolean | `true` | Bind the GTP-U socket at all |

Both are read in `spawn_with_llm_actions`, through `get_optional_u64` / `get_optional_bool`
with `?` propagation — never `unwrap()`, because an undeclared key over MCP used to kill the
task before it could report the error.

The `user_plane_port` default deserves its rationale: a fixed 2152 would collide whenever the
control plane is *not* on its own standard port — two instances side by side, or an e2e test on
an ephemeral port. So the standard pair is used only when the control plane is standard.

## Events and actions

Five events, all emitted by `mod.rs`, all carrying `.with_actions(...)`:

| Event | Raised when | Actions offered |
|---|---|---|
| `gtp_echo_request` | Echo Request (v1 or v2, either plane) | echo response / no_response |
| `gtp_create_session_request` | Create PDP Context Request / Create Session Request | create session response / no_response |
| `gtp_update_context_request` | Update PDP Context Request / Modify Bearer Request | update response / no_response |
| `gtp_delete_session_request` | Delete PDP Context Request / Delete Session Request | delete response / no_response |
| `gtp_gpdu_received` | a G-PDU on the user plane | send G-PDU / error indication / no_response |

Everything else is noted and not answered: responses (a server must not answer a response),
End Marker, Error Indication, and Supported Extension Headers Notification. A datagram with an
unsupported version is answered **Version Not Supported** mechanically, with no LLM call —
there is nothing to decide.

`get_async_actions()` is empty. A GTP node has nothing to say to a peer it has not heard from,
and unsolicited traffic would need the peer table this protocol deliberately does not keep.

### Structured everywhere except one field

Event data is structured throughout: the inner packet of a G-PDU is handed to the model as
`inner_ip: {version, source, destination, protocol, protocol_name, ttl, length, source_port,
destination_port}`, not as a blob to parse. Subscriber identifiers arrive as decimal digits,
the APN as a dotted string, the RAT type as a name.

The one genuinely opaque field is `send_gtp_gpdu`'s `payload` — a G-PDU *is* an encapsulated
packet, so there is nothing to structure. It therefore carries an explicit `encoding` of
`"utf8"` (default) or `"hex"`, and `decode_payload()` **really decodes the hex**. There is no
sniffing: `"48656c6c6f"` is simultaneously valid text and valid hex and only the sender knows
which it means. That is the `send_tcp_data` lesson (`d70bb5b5`) applied up front rather than
after the fact, and `test_gtpv1_session_lifecycle_over_real_udp` asserts the decode by sending
a hex payload and checking the literal octets that reach the wire.

### `encode_apn` refuses an over-long label rather than cutting it

`encode_apn` returns `Result<Vec<u8>, EncodeError>` and refuses any DNS label past
[`MAX_APN_LABEL_LEN`] (63 octets, TS 23.003 §9.1). It used to write `bytes.len().min(63)`, so a
64-character label reached the wire as its first 63 characters — and that is the worst shape a
truncation can take: the result is a *valid* label naming a **different access point**, so
nothing downstream, not `decode_apn` and not a real PGW, could tell it was not the one that was
meant. The length prefix is one octet and the limit is a hard format rule, so there is no
recovery later either. `netbios_ns::encode_name_field` faces the identical situation for its
scope labels and bails; this is the same shape.

Latent rather than reachable: nothing in `src/` calls `encode_apn` today — it exists for the
encode half of the codec tests and for anything building a Create Session Request — so this was
an unguarded `pub fn`, which is the class the codec property tests
(`tests/codec_property_test.rs`) exist to find.

## Maturity: Experimental, and precisely why

The transport **is** exercised — real UDP sockets, real datagrams, real replies, fourteen
passing tests. What is missing is the one thing that would make it Beta: **no third-party GTP
implementation has ever accepted a packet this server produced.**

The peer in `tests/server/gtp/e2e_test.rs` is hand-written from TS 29.060 and TS 29.274 and
shares no code with `codec.rs`. That makes it an independent *reading* of the specification,
which is worth something and is the same evidence `dhcp` and the USB/IP family rest on — but
the root `AGENTS.md` is explicit that it is not an independent *implementation*.

**What was looked for, and not found, on this machine** (nothing was installed):

- `open5gs` — not installed, and no Homebrew formula. Its `open5gs-smfd` / `open5gs-upfd` would
  be the ideal peer.
- `osmo-ggsn` (Osmocom OpenGGSN) — not installed. Its `libgtp` also ships a `sgsnemu` test
  client, which would be a genuine third-party peer and is the single best target for anyone
  who wants to promote this protocol.
- Rust GTP crates — nothing in this tree, and adding a dependency was out of scope.

**What WAS found, and used: Wireshark.** `tshark` 4.x is installed here and registers three
independent dissectors — `gtp`, `gtpv2` and `gtpprime`. Four of this server's own outbound
packets were rebuilt octet-for-octet from the e2e assertions, wrapped in UDP with `text2pcap`
and dissected. All four parse with **zero expert warnings**:

| Packet | What the dissector agreed to |
|---|---|
| GTPv1 Create PDP Context Response | `Cause: Request accepted (128)`, Reordering Required, both TEIDs, Charging ID, `End user address (IETF/IPv4): 10.45.0.2`, both PCO `DNS Server IPv4 Address` containers, both GSN addresses |
| GTPv2-C Create Session Response | `Cause: Request accepted (16)` with its CS/BCE/PCE bits, PAA `IPv4 10.45.0.7`, PCO, `F-TEID … S5/S8 PGW GTP-C interface` at instance 1, and the grouped Bearer Context with EBI 5 and an `S5/S8 PGW GTP-U interface` F-TEID at instance 2 |
| GTPv1 Echo Response | flags 0x32, `Recovery: 3`, `Length: 6` — the optional block counted correctly |
| GTPv1 G-PDU with **PN set and S/E clear** | `N-PDU Number: 0x07`, `Length: 36`, and the inner IPv4/UDP packet found starting after **all four** optional octets |

The last row is the important one: it is third-party confirmation of the E/S/PN all-or-nothing
rule, from an implementation that has never seen this code.

Reproduce it with `text2pcap -u 2123,2123 <hexdump> out.pcap && tshark -r out.pcap -V` plus
`tshark -r out.pcap -q -z expert`. It is deliberately **not** wired into the suite: a test that
needs `tshark` installed would have to skip when it is missing, and the root `AGENTS.md` is
explicit that a real tool behind a skip-when-missing gate is not evidence at all.

**This still does not earn Beta.** It validates the *encoding*; Beta wants a peer that
completed a real exchange. Do not promote this protocol on the strength of the test count or of
the dissector. Promote it when `sgsnemu`, an open5gs node, or an equivalent completes a real
session against it.

## Known limitations

1. **No QoS Profile IE.** A Create PDP Context Response should carry one when it accepts.
   Building a valid TS 24.008 profile would mean inventing spec compliance that has not been
   checked against anything, so it is omitted and said so here rather than fabricated.
2. **No GTP' (TS 32.295) charging protocol**, and no GTPv0. The PT bit is decoded and a GTP'
   message is not served; version 0 gets Version Not Supported.
3. **No retransmission, no duplicate detection, no N3/T3 timers.** A retransmitted request is a
   second event and a second LLM call.
4. **No secondary PDP contexts, no MBMS, no S1/S4 handover signalling** beyond Modify Bearer.
5. **Error Indication and End Marker are received and logged, never acted on.** The model can
   *send* an Error Indication; it is not told when one arrives, because there is no session
   state for it to act on.
6. **IPv6 is encoded but untested end to end.** The PAA, End User Address and F-TEID encoders
   handle it; the tests are IPv4.
7. **The advertised GSN/F-TEID address is the socket's own.** Behind NAT, or on a wildcard
   bind, it will not be the address a peer should actually use.

## Example prompts

```
listen on port 2123 via gtp
You are a PGW for a private LTE network. Accept Create Session Requests whose APN
is "internet", assigning addresses from 10.45.0.0/16 in order and handing out
8.8.8.8 and 1.1.1.1 for DNS. Refuse any other APN with missing_or_unknown_apn.
Refuse any IMSI that does not start with 26201 with apn_access_denied_no_subscription.
Answer Echo Requests.
```

```
listen on port 2123 via gtp
Impersonate a GGSN under load: accept the first two sessions, then refuse every
further Create PDP Context Request with no_resources_available until an Echo
Request arrives, at which point start accepting again. Use memory to count.
```

## References

- [3GPP TS 29.060](https://www.3gpp.org/DynaReport/29060.htm) — GPRS Tunnelling Protocol across
  the Gn and Gp interface (GTPv1-C and GTPv1-U)
- [3GPP TS 29.274](https://www.3gpp.org/DynaReport/29274.htm) — Evolved GPRS Tunnelling
  Protocol for Control plane (GTPv2-C)
- [3GPP TS 23.003](https://www.3gpp.org/DynaReport/23003.htm) — numbering, addressing and
  identification (IMSI, MSISDN, APN)
- [3GPP TS 24.008](https://www.3gpp.org/DynaReport/24008.htm) — Protocol Configuration Options
