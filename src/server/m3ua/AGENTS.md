# M3UA / SIGTRAN Server Implementation

MTP3 User Adaptation Layer, [RFC 4666](https://datatracker.ietf.org/doc/html/rfc4666). NetGet
plays the **SGP** (signalling gateway process); the peer is an **ASP** (application server
process). Rust owns the association and the state machine's mechanics; the model owns the two
admission decisions and the SS7 traffic. Service-indicator-3 traffic is decoded through **SCCP,
TCAP, MAP and CAMEL** (see [The SS7 upper stack](#the-ss7-upper-stack-sccp-tcap-map-camel)), and
the ASP role — NetGet originating MAP and CAP dialogues — is `src/client/m3ua/`, which shares
everything here except `mod.rs` and `actions.rs`.

**Status**: `Experimental` — see [Maturity](#maturity). It runs over real SCTP against two
independent peers (Restcomm jSS7 and osmo-stp) on Linux; macOS has no SCTP and gets the
labelled lab transport only.

**Port**: SCTP 2905 (IANA). Above 1023, so `PrivilegeRequirement::None` — SCTP is an ordinary
kernel transport like TCP, not a raw socket.

## Layout

| File | Role |
|---|---|
| `codec.rs` | Common header, TLV parameters, Protocol Data, message builders (SGP and ASP side). Pure functions, `pub`, asserted against literal RFC octets. |
| `transport.rs` | The association: SCTP probe and connect, `sendmsg` with PPID 3 and stream selection, the lab TCP transport. Shared with the client. |
| `mod.rs` | Listener, association loop, ASP state machine, LLM dispatch, SS7 event dispatch and its fail-closed rule. |
| `actions.rs` | M3UA action definitions and validation, event types, metadata, startup parameters. |
| `ber.rs` | Bounded BER (X.690) reader and writer: depth, element and length bounds; high tag numbers; indefinite lengths. |
| `gsm.rs` | TBCD, AddressString, GSM 7-bit and USSD packing, SMS-SUBMIT/DELIVER TPDUs, CGI, ISUP numbers and Q.850 cause. |
| `sccp.rs` | SCCP UDT/XUDT/UDTS/XUDTS, Called/Calling Party Address (PC, SSN, GT indicators 1-4), SCMG. |
| `tcap.rs` | ITU TCAP messages, the dialogue portion (AARQ/AARE/ABRT, MAP-OpenInfo), components. |
| `map.rs` / `cap.rs` | MAP and CAMEL application contexts, operation codes, and argument/result/error mappings to structured JSON. |
| `ss7.rs` | The dialogue engine: transaction table, routing, Rust-side answers, intents to TCAP, bounds. Shared with the client. |
| `ss7_actions.rs` | The model's SS7 vocabulary and the `m3ua_map_received` / `m3ua_cap_received` events, for both roles. |

## The transport problem (read this first)

**M3UA runs over SCTP.** RFC 4666 section 1.4.1 requires it and IANA assigns SCTP port 2905.
**macOS has no SCTP stack at all** — no kernel support, no headers — and macOS is the machine
this was written and tested on. `PROTOCOL_ROADMAP.md` records three ways out; two are
implemented and the third is recorded rather than pretended.

### 1. SCTP is the default, and a host without it is refused by name

`bind_listener` asks the kernel for a `SOCK_STREAM` / `IPPROTO_SCTP` (132) socket through
`socket2`. Where that fails, `spawn()` returns an `Err` and `server_startup` puts the server in
`ServerStatus::Error`. The message names SCTP, names RFC 4666, and names the escape hatch,
because an errno alone (`Protocol not supported`) tells an operator nothing about what to do
next.

This is the `bluetooth_ble_beacon` precedent from the root `AGENTS.md`: **hiding a protocol is
not the same as refusing to start it.** Hidden, nobody learns why; refused, the reason is on
the screen.

It is a **probe, not a `cfg`**. The socket is genuinely requested, so a Linux kernel with the
`sctp` module unloaded is diagnosed exactly like macOS, and a Linux kernel that has it gets a
real SCTP listener with no code change. That choice follows the privilege model's own lesson:
`SystemCapabilities` used to *infer* raw-socket access and the check therefore never fired.

Compiling the SCTP path unconditionally (rather than behind `#[cfg(target_os = "linux")]`) is
also deliberate. Code that only compiles on a platform nobody builds for is code nobody
compiles; this way the macOS build type-checks every line of it, and the only thing that
differs at runtime is whether `socket(2)` succeeds.

### 2. `transport: "tcp"` is a lab affordance, labelled as one everywhere

The startup parameter accepts `"tcp"`. **No real SIGTRAN peer speaks M3UA over TCP.** It exists
so the layers above the transport can be exercised on this machine at all.

Because a label like that is only useful if it travels, `M3uaTransport::label()` returns
`"tcp (NON-STANDARD lab transport, not SIGTRAN)"` and that string appears in:

- the startup parameter's description, which is what the model reads;
- `metadata().notes`;
- the startup log line, plus a separate WARN saying it in full;
- the connection's `protocol_info`, so the dashboard rail shows it on the row;
- **every event's `transport` field**, so a handler and the model see it too.

`transport_test.rs` asserts each of those, including that the declared example is `"sctp"` — if
the default ever flipped, an operator on a host *with* SCTP would silently get the lab framing.

Everything above the socket is transport-agnostic: M3UA is length-delimited, so the framing does
not change. That is what makes the lab transport useful, and exactly why it must be labelled —
the code being exercised is real and the transport under it is not.

### 3. Userspace SCTP — the real fix, not done here

`webrtc-rs` is already in the tree and carries an SCTP implementation, so a userspace
association is not far-fetched. It is a project of its own: association setup, path management,
multi-streaming and multi-homing, none of which falls out of the M3UA work. Recorded so it is
not re-litigated from scratch.

### 4. On Linux it is the real thing

On a kernel with the `sctp` module the default path is a real association, and that is where the
evidence lives: `tests/server/m3ua/real_peer_test.rs` and `osmo_stp_test.rs` (and the client's
pair) run there, in the `m3ua` job of `.github/workflows/protocol-pairs.yml`, against Restcomm
jSS7 and osmo-stp. Writes go through `sendmsg` with an `SCTP_SNDRCV` control message so every
DATA chunk carries **PPID 3** and management (ASPSM, ASPTM, MGMT, RKM) rides **stream 0** while
Transfer rides **stream 1** (RFC 4666 section 1.4.7; a single-stream association falls back to 0).
Neither peer checks either, but with PPID 0 tshark stops dissecting NetGet's frames as M3UA and
the capture assertion fails (mutation-checked, as is DATA on stream 0).

## Codec: the two rules that are usually got wrong

**Parameter padding is excluded from the Parameter Length** (RFC 4666 section 3.2). A parameter
whose value is the two octets `"ok"` declares length **6** and occupies **8** octets. This is the
single most common M3UA implementation error, and it is invisible to a round-trip test: an
implementation that writes 8 into the length field decodes its own messages perfectly and
corrupts every real peer's. `tests/server/m3ua/codec_test.rs` therefore asserts **literal octets
written by hand from the RFC**, never `encode(decode(x)) == x`.

The consequential case is Protocol Data. A 15-octet value (12 of routing label plus 3 of user
part) declares 19 and occupies 20. Get it wrong by one and the far end reads a padding octet as
the last byte of an ISUP message.

**Both length fields are bounded on the encode side as well as the decode side, and the bound
is enforced by the codec rather than only by the action.** `MAX_MESSAGE_LEN` (65535) guards
`parse_header`, where a hostile peer chooses the number and the risk is an allocation. The
mirror image had no guard at all: `Parameter::write_into` wrote `declared_len()` as a `u16`, so
a user part the *model* supplied at 65520 octets or more wrapped the Parameter Length field —
and wrapped it to **0**, below the 4-octet TLV header, so the parameter became unparseable and
took every parameter after it with it. Both `Message::encode` and `Parameter::write_into` now
return `Result<_, WireError>` and refuse; `write_into` checks before it writes anything, since
a half-written TLV corrupts the body just as surely as a wrong length. Every builder
(`aspup_ack`, `beat_ack`, `data`, …) propagates that, and `mod.rs::send_encoded` answers a
refusal with `decision=fail_closed_encode` and sends nothing.

`decode_payload` refuses past `codec::MAX_USER_DATA_LEN`, counting decoded octets so declaring
`hex` buys no extra budget. **The constant is 65508, and the three octets that changed are the
interesting part**: it used to be `65535 − 8 − 4 − 12 = 65511`, which forgot that a body is
always a whole number of 4-octet words. A payload at exactly the documented limit therefore
encoded to 65536 octets — one past the ceiling — which is the "padding is not in the length"
trap above, met from the encode side by the very code that documents it. The derivation is now
`((65535 − 8) / 4) * 4 − 4 − 12`. It is also a *per-parameter* guide rather than the message
bound: a DATA that also carries Network Appearance, Routing Context and Correlation ID has 24
fewer octets to spend, and `Message::encode` is what enforces the real ceiling.

For scale, a real MSU carries at most 272 octets of user part, so anything near the limit means
the field has been misunderstood rather than a legitimate ceiling reached.
`codec_test.rs::a_user_part_too_large_to_frame_is_refused_rather_than_wrapped` pins it, asserts
the constant is derived from the format rather than picked (including that one more word does
*not* fit, so the bound is exact rather than merely safe), and that a DATA carrying the optional
parameters as well is refused at the message level.

**The one wire-reachable case is BEAT.** Heartbeat Data is echoed verbatim, and the peer chooses
it — so a BEAT carrying a maximal Heartbeat Data parameter cannot be echoed inside a 65535-octet
message. That is answered with ERR `0x07 Protocol Error` rather than silence, so the ASP learns
its keepalive was rejected instead of watching it disappear.

**Message Length covers the whole message including the common header.** NetGet *includes* the
parameters' padding in it, which is what the reference stacks do. A peer that excludes the final
parameter's padding produces a length that is not a multiple of four while still writing the
padding octets, so `read_message` drains `codec::alignment_slack(length)` octets afterwards —
otherwise the next header starts mid-word. NetGet's own messages always leave zero slack.

## Session

```text
accept                       -> ASP-DOWN
ASPUP  -> m3ua_asp_up_received     -> ASPUP ACK  -> ASP-INACTIVE  (or ERR, stay DOWN)
ASPAC  -> m3ua_asp_active_received -> ASPAC ACK  -> ASP-ACTIVE    (or ERR, stay INACTIVE)
DATA   -> m3ua_data_received       -> optional DATA back
BEAT   -> BEAT ACK                                (Rust, no LLM call)
ASPIA  -> ASPIA ACK                -> ASP-INACTIVE (Rust, no LLM call)
ASPDN  -> ASPDN ACK, then m3ua_asp_down_received  -> ASP-DOWN
ERR    -> m3ua_error_received                     (observational)
```

### What is answered in Rust, and why

- **BEAT → BEAT ACK.** A keepalive is not a decision. Routing it through the model would spend a
  request per heartbeat per association to decide nothing; routing it through a *parked manual
  handler* would drop the association while a human read the question. The Heartbeat Data is
  echoed verbatim — that opaque token is the entire point of the parameter.
- **ASPDN → ASPDN ACK** and **ASPIA → ASPIA ACK.** Taking a peer *out* of service is the safe
  direction and needs no permission. An ASP that cannot leave cleanly is a worse failure than one
  that cannot join.
- **Every protocol-validity refusal**: a bad version, a length below the header, a malformed TLV,
  ASPAC while ASP-DOWN, DATA while not ASP-ACTIVE, a routing context or network appearance that
  does not match the configured one. These follow from the protocol, not from policy, so the
  model is never consulted about them.
- **A duplicate ASPUP or ASPAC** for a peer already in that state is re-acknowledged without
  asking again (RFC 4666 section 4.3.4.3). It is not a new admission — this ASP was admitted
  already.

### Concurrency

The stream is split by `transport::split` (one socket, two `Arc` handles: a reader and a
message writer); the write half lives behind an `Arc<Mutex<..>>`
shared with the dashboard's peer command task. The mutex is held only for the duration of a
socket write and **never across an LLM call** — the model round-trip happens with nothing
locked, and the resulting bytes are written afterwards. There is no keepalive ticker, so no
writer task is needed (BGP needs one because its timers must keep sending while the read loop is
inside an LLM call).

## Fail closed: the whole point

An ASPUP is a request to join a **signalling network**. There is no safe default answer, so
every path that is not an explicit acknowledgement ends in `ERR` and leaves the ASP where it
was. The four non-answers are kept apart in the log because collapsing any two of them is a bug:

| Situation | Wire | Log tag |
|---|---|---|
| `send_m3ua_asp_up_ack` / `send_m3ua_asp_active_ack` | that ACK, ASP advances | — |
| Policy refused with `send_m3ua_error` | that ERR, ASP unchanged | `decision=model_reject` |
| Policy ran and produced no ACK (`wait_for_more`, empty handler, a NTFY and nothing else) | ERR `0x0d` | `decision=model_silent` |
| Policy could not be run (backend error, timeout, saturation) | ERR `0x0d` | `decision=fail_closed_llm_error` |
| No policy exists at all | ERR `0x0d` | `decision=no_policy_configured` |

**This is where M3UA deliberately parts company with BGP.** BGP treats "no instruction and no
handler" as a static default and completes the handshake, reasoning that the operator opened the
port with that ASN. M3UA does not: `operator_wants_dynamic() == false` is a refusal, because
"who may join this signalling gateway" has no configuration-free answer that is not a guess. The
log line names what is missing rather than leaving an operator to wonder why nothing works.

In practice every instance created through the dashboard has a policy — `ServerForm::create`
substitutes an instruction and adds a `*` → manual rule — so the refusal is reached only by a
programmatic `open_server` that supplied neither.

**On `m3ua_data_received` the mapping is different**, and the difference is the point: a policy
that ran and chose to say nothing sends nothing (`decision=model_silent`), because M3UA needs no
reply to a DATA. But a policy that could not be *run* answers ERR, because staying silent would
tell the ASP its MSU reached the SS7 network. A fabricated delivery confirmation is worse than a
refusal.

**Nothing derived from an error reaches the peer.** ERR carries a numeric Error Code and the
optional Diagnostic Information parameter is left empty — it is the one field in M3UA where an
internal string could leak, and `codec::error` never populates it. The category comes from
`crate::utils::WireFailure`; M3UA's error code registry has no resource-exhaustion code, so both
categories map onto `0x0d Refused - Management Blocking` on the wire and are separated in the
log instead. That is the rule the root `AGENTS.md` states for exactly this case.

## What is deliberately not implemented

- **Routing key management (RKM).** REG REQ / DEREG REQ are decoded and named, and answered with
  ERR `0x04 Unsupported Message Type` plus a log line saying why. Dynamic registration means
  keeping a routing key table, and a routing key table is **storage**, which the root `AGENTS.md`
  forbids a protocol from implementing. Accepting and forgetting would be worse than refusing:
  an ASP that believes it registered a key will send traffic for it. Configure `routing_context`
  instead, or use the generic SQLite facility from a handler.
- **SSNM generation.** NetGet never emits DUNA/DAVA/SCON/DUPU — there is no MTP3 network
  underneath to report on. An SSNM message *arriving* is an ASP speaking out of turn and earns
  ERR `0x06`.
- **Multi-homing, multi-streaming, stream identifier selection.** These are SCTP properties; the
  one-to-one socket API exposes none of them, and none can be exercised here anyway.
- **Application Server state, and load-sharing across ASPs.** Each association is independent.
  Traffic Mode Type is echoed as the handler chooses; nothing balances anything.

## Events and actions

| Event | Fires | Useful reply |
|---|---|---|
| `m3ua_asp_up_received` | ASPUP from an ASP-DOWN peer | `send_m3ua_asp_up_ack` to admit, `send_m3ua_error` to refuse |
| `m3ua_asp_active_received` | ASPAC from an admitted peer | `send_m3ua_asp_active_ack` to activate, `send_m3ua_error` to refuse |
| `m3ua_data_received` | an MSU from an active peer | `send_m3ua_data` or `wait_for_more` |
| `m3ua_asp_down_received` | ASPDN, already acknowledged | `send_m3ua_notify` or `wait_for_more` |
| `m3ua_error_received` | the ASP reported an error | observational |

Every event carries the full action list (`call_llm` builds the model's tools from
`EventType::actions`, not from `get_sync_actions()`), and every one has a real emit site.
`get_async_actions` is empty: an async action carries no connection, and every M3UA verb is
addressed to one association. The dashboard's `[ message this peer ]` reaches a live ASP through
the generic peer command channel, which runs exactly the same sync actions.

Actions return `ActionResult::Output` with the fully encoded message, and the session reads the
class and type back off those octets with `codec::peek_class_type` to drive the state machine.
That is deliberate: the state machine follows what is actually on the wire rather than a
parallel bookkeeping that could drift from it. (BGP needs the `Custom` intent indirection because
its encoding depends on the negotiated AS width; nothing in M3UA depends on the session.)

`close_connection` is executable but **not** advertised to the model — refusing an ASP is
`send_m3ua_error`, which leaves the association up so the peer can retry. The dashboard's
`[ disconnect this peer ]` injects it.

### Structured fields, and the one opaque one

The routing label reaches the model as `opc`, `dpc`, `si`, `si_name`, `ni`, `mp`, `sls` — never
as a blob. The SS7 user part is the one legitimately opaque field, and it carries an explicit
`encoding` (`"utf8"` / `"hex"`) in both directions, which `send_m3ua_data`'s executor really
decodes. It is **declared, never sniffed**: `"48656c6c6f"` is simultaneously valid text and
valid hex and only the sender knows which it meant. This is the `send_tcp_data` lesson from the
root `AGENTS.md` — documenting hex and then calling `as_bytes()` puts literal ASCII on the wire.

Error codes, traffic modes and NTFY status values are accepted by **name**
(`refused_management_blocking`, `loadshare`, `as_active`) as well as by number, and an
undefined numeric value is rejected as a failed action naming the allowed set rather than put on
the wire where no peer can interpret it. Status Information is validated *against its Status
Type*, since type 1 / info 3 is `AS-ACTIVE` and type 2 / info 3 is `ASP Failure`.

## Startup parameters

| Name | Default | Notes |
|---|---|---|
| `transport` | `"sctp"` | `"tcp"` is non-standard and for lab use only. |
| `routing_context` | none | If set, ASPAC/DATA naming a different one is refused with ERR `0x19` before the model is consulted. |
| `network_appearance` | none | If set, DATA naming a different one is refused with ERR `0x15`. |

All three are read; all three are validated in `M3uaConfig::from_params` before anything binds,
with `?` rather than `unwrap()`, so a bad value fails startup naming the parameter.

## Verification

The SS7 evidence (real peers, captured third-party bytes, tshark) is described in
[The SS7 upper stack](#the-ss7-upper-stack-sccp-tcap-map-camel) and in
`tests/server/m3ua/AGENTS.md`. The M3UA-only suites in `tests/server/m3ua/`:

1. **`codec_test.rs` — literal RFC octets, both directions.** Every expected vector is written
   by hand from RFC 4666 with the field decode in the comment, so it comes from the spec rather
   than from this implementation. Covers the padding rule at 1, 2 and 3 octets of padding, the
   Message Length's coverage of it, DATA's routing label, ERR, NTFY's packed Status field, ASPAC
   ACK's parameter order, and the receive direction on hand-written ASPUP and DATA messages
   NetGet did not encode. Plus the rejections: bad version, undersized and oversized lengths, a
   TLV shorter than its own header, a TLV running past the end, and a short Protocol Data.
2. **`transport_test.rs` — the refusal.** That SCTP is refused on macOS, that the refusal names
   SCTP / RFC 4666 / the escape hatch / its non-standardness, that a host *with* SCTP would get a
   real listener, that the lab transport binds, that its label warns, and that the declared
   default is `"sctp"`.
3. **`e2e_test.rs` — the whole path over the lab transport**, against a mocked model: an ASP
   comes up, is activated, exchanges an MSU with the point codes swapped and the SLS echoed, and
   BEAT and ASPIA are answered with **no** model call (which `verify_mocks` is what proves).
   Then the fail-closed pair: `wait_for_more` on an ASPUP produces ERR `0x0d` and leaves the ASP
   DOWN (and the following ASPAC earns ERR `0x06` with no second opinion), and a server with no
   policy at all refuses with `decision=no_policy_configured` in the log.

Not covered: multi-ASP behaviour, AS state, load sharing, routing key management, SSNM, and
multi-homing. SCTP itself, PPID and stream selection are covered on Linux only.

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/m3ua/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_MESSAGE_READ_TIMEOUT` | 30s | RFC 4666 has the ASP send ASPUP as soon as the association is established; the SG says nothing first and nothing legitimate precedes it. |
| `IDLE_BETWEEN_MESSAGES_TIMEOUT` | 900s | Deliberately long: a signalling link with no traffic is the normal case, not a suspicious one, so this must not be a traffic timer. The protocol's own answer to "is this quiet link alive" is BEAT (RFC 4666 §3.5.5), configured at tens of seconds in deployments — so fifteen minutes is on the order of thirty missed beats. Over TCP there is no SCTP heartbeat underneath to tell the difference. |
| `MAX_CONNECTIONS` | 256 | Refusal: **an M3UA ERR carrying `Refused - Management Blocking`** (error code 0x0d), which is what that code is for and what this server already sends when it declines an ASP. ERR is a Management-class message either end may send unsolicited, so unlike most protocols here there is a genuinely *correct* thing to say to a peer that has not spoken yet. |

NetGet's own M3UA client (`src/client/m3ua`) refused this way fails its connect with the SGP's
error code named (`tests/client/m3ua/bounds_test.rs::an_sgp_that_refuses_aspup_fails_the_connect`),
so the refusal strands nobody silently.

**The deadline covers the read and nothing else.** The deadline wraps the `read()` call in this protocol's own loop, and everything that can legitimately take minutes happens after it returns. `read_message` bounds the header, the announced body and the alignment padding. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.

## The SS7 upper stack (SCCP, TCAP, MAP, CAMEL)

### Why it is part of `m3ua` rather than a new protocol

Before this layer the SGP handed the model every MSU as an opaque user part (`payload` +
`encoding`). SCCP is simply what service indicator 3 carries on the same association, alongside
ISUP or anything else, so a separate `ss7-map` protocol would have had to duplicate the ASP state
machine, admission policy, transport and bounds — or share them across features — and would
split one SIGTRAN association into two NetGet instances. So the `m3ua` feature grew: a DATA with
SI 3 that decodes as SCCP unitdata goes through the engine, and everything else still raises
`m3ua_data_received` (an SCCP message the engine cannot decode is passed there with
`sccp_note` saying why). The ASP role is a new client under the same feature.

### Why BER is hand-written

The subset is about forty ASN.1 types out of 3GPP TS 29.002 and 29.078, all SEQUENCEs of tagged
OCTET STRINGs, INTEGERs, ENUMERATEDs and NULLs. A generic bounded TLV tree (`ber.rs`) plus
per-operation field mappings (`map.rs`, `cap.rs`) is small and fully bounded; `rasn` with the
3GPP modules would mean thousands of generated types and a second `rasn` beside SNMP's.
`asn1-codecs`/`hampi` is a compiler, not a crate.

The rule that keeps it honest: **MAP answers must equal jSS7's own answers octet for octet.**
`tests/server/m3ua/ss7_codec_test.rs` feeds the engine requests jSS7 8.0.112 put on the wire and
compares NetGet's answer for the same fields with jSS7's server's answer — SCCP addresses, AARE,
components and all.

### Bounds (all refused before the model)

| Bound | Value | Breach |
|---|---|---|
| BER nesting | `ber::MAX_BER_DEPTH` 16 | P-Abort `badlyFormattedTransactionPortion` (the transaction id is recovered without recursion) |
| BER elements per decode | `ber::MAX_BER_ELEMENTS` 1024 | same |
| BER lengths | checked against the octets present; at most 4 length octets | same |
| Components per TCAP message | `tcap::MAX_COMPONENTS` 16 | P-Abort `resourceLimitation` |
| Open dialogues per association | `ss7::MAX_OPEN_DIALOGUES` 1024 | P-Abort `resourceLimitation` |
| Dialogue idle | `ss7::DIALOGUE_IDLE_TIMEOUT` 60s, swept on every message (and on a timer in the client) | TC-U-ABORT, dialogue forgotten |
| SCCP data | 255 octets (UDT/XUDT length field) | an outgoing answer that does not fit fails the action; NetGet never segments |
| Segmented XUDT | refused | XUDTS `segmentation not supported` when the sender asked for errors |
| USSD string / SMS user data | 160 / 140 octets | refused at decode and encode |

Without the depth bound a 4 KB indefinite-length bomb overflows the stack and aborts the process
(mutation-checked: the test binary dies with `stack overflow`).

### What Rust answers without the model

SCCP SST (subsystem status test) with SSA; a TC-CONTINUE/END/ABORT for a transaction no dialogue
owns (Continue gets P-Abort `unrecognizedTransactionID`, End/Abort are discarded per Q.774); a
Continue from the wrong peer transaction (P-Abort `incorrectTransactionPortion`); an application
context that is neither a known MAP context nor CAP v2/v3/v4 gsmSSF-to-gsmSCF (TC-U-ABORT with an
AARE reject, `application-context-name-not-supported`); an operation NetGet does not implement or
an argument that does not decode (TC-END with Reject `unrecognizedOperation` /
`mistypedParameter`); CAP activityTest (its empty result). MAP v1 (no dialogue portion) is
recognised by operation code.

### The model's side

Events `m3ua_map_received` and `m3ua_cap_received` carry the decoded TCAP message: `dialogue_id`
(NetGet's transaction id), `tcap` (begin / continue / end / abort / timeout), the application
context by name and version, the dialogue portion (with MAP-OpenInfo references), each component
decoded (invoke with operation and argument fields, result, error by name, reject), the invokes
`awaiting_answer_to`, and the route (both SCCP addresses, OPC/DPC/SLS). Actions are intents —
`send_map_result`, `send_map_error`, `send_map_request`, `send_cap_operations`, `send_tcap_end`,
`send_tcap_abort` — validated against the encoders in `execute_action` and turned into TCAP by
the engine, which alone knows the transaction ids, whether an AARE is still owed, which invoke an
answer is for, and the swapped addresses. A MAP result ends the dialogue once nothing else is
pending; CAP instructions end it unless they arm events with requestReportBCSMEvent.

### Fail closed

| Situation | MAP | CAP | Log tag |
|---|---|---|---|
| model answered | its result / error | its instructions | — |
| model said nothing for an invoke that needs an answer | TC-U-ABORT (AARE reject before the dialogue was accepted) | TC-U-ABORT | `decision=model_silent` |
| model could not be asked | TC-END: AARE accepted + ReturnError `systemFailure` per pending invoke | TC-U-ABORT | `decision=fail_closed_llm_error` |
| no policy | as above | as above | `decision=no_policy_configured` |
| an intent that cannot be honoured (unknown dialogue, wrong invoke, does not fit) | nothing for it; the row above then applies | same | `decision=action_refused` |

Never a fabricated success: jSS7 receives error 34 when the model is unreachable
(`real_peer_test.rs::jss7_sees_netgets_fail_closed_answers_never_a_fabricated_success`).

### Not implemented

sendAuthenticationInfo (authentication vectors are key material the model would have to invent),
insertSubscriberData (so updateLocation is answered without the ISD exchange a real HLR performs),
MAP v1 origination, MAP-OpenInfo beyond its references, CAP charging, SRF and SMS operations, SCCP
segmentation/reassembly, LUDT, connection-oriented SCCP, global title translation (NetGet answers
whatever reaches it and replies to the calling address), ANSI TCAP and 24-bit ANSI point codes in
SCCP addresses. The dashboard's "message this peer" runs M3UA actions; SS7 intents need the
session's dialogue state and are refused there.

## Maturity

`Experimental`. Two independent peers exercise it over real SCTP — Restcomm jSS7 8.0.112 (M3UA,
SCCP, TCAP, MAP, CAP; Java) in both roles, and osmo-stp 1.6 (libosmo-sigtran; C) as an ASP of the
SGP and as the SGP of the client — with tshark's dissectors reading a live capture, tests that
fail rather than skip, and nothing `#[ignore]`d. What keeps it from Beta: that evidence runs only
in the protocol-pairs `m3ua` job, which has not run in CI yet, and the code has had no human
review. Mutation-checked: the BER depth and length bounds, the dialogue and component caps,
segmentation refusal, transaction matching, the fail-closed answer, TBCD digit order, the
sendRoutingInfoForSM operation code, PPID 3, DATA off stream 0, and dropping the model's intents
(server and client).
