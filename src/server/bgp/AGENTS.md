# BGP Server Implementation

Border Gateway Protocol 4 (RFC 4271) over TCP. Rust owns the session; the LLM decides whether to
peer and which routes to advertise.

**Status**: `Experimental`. Promoted from `Incomplete` once the session was completed and the
wire format validated. `Experimental` here means "the bytes were checked against the RFC and the
session works end to end against a scripted peer", not "peered with a production router" — see
[Verification](#verification) for exactly what was and was not done.

**Port**: TCP 179 (`PrivilegeRequirement::PrivilegedPort(179)`). Any other port needs no
privilege; the requirement is checked against the *configured* port by `server_startup`.

**Spec**: [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271),
[RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793) (four-octet AS).

## Layout

| File | Role |
|---|---|
| `wire.rs` | Encode, decode, header framing, model-facing JSON. Pure functions, `pub`, directly tested. |
| `mod.rs` | Listener, session FSM, timers, LLM dispatch. |
| `actions.rs` | Action definitions, parameter validation, event types, metadata. |

## Library choice: netgauze

All parsing and the structurally interesting encodings (OPEN, UPDATE) go through
`netgauze-bgp-pkt`.

That crate was **already the `bgp` feature's only declared dependency and had never been used**:
`grep -rn netgauze src/` returned nothing while the protocol hand-rolled its own wire format.
The hand-rolled code understood two-octet ASNs and nothing else — no capability parsing at all,
`local_as as u16` on the send path, and a path-attribute parser that handled five attribute
types. Everything on this path is attacker-controlled, and capability TLVs, attribute flags,
extended lengths, the RFC 6793 AS_PATH width ambiguity and the RFC 4760 multiprotocol attributes
are exactly where a plausible hand-rolled parser silently disagrees with a real router. The
precedent is OSPF, which used the wrong checksum algorithm for years while its docs claimed
interoperability.

Access is through `netgauze_bgp_pkt::codec::BgpCodec`, which implements `tokio_util`'s
`Encoder`/`Decoder`. **This is a dependency constraint, not a preference.** netgauze's direct
`WritablePdu`/`ReadablePduWithOneInput` traits live in `netgauze-parse-utils`, and `Ipv4Unicast`
wraps `ipnet::Ipv4Net`; neither crate is declared in NetGet's `Cargo.toml`. The codec route needs
only `netgauze-bgp-pkt`, `tokio-util` and `bytes`, all already present. Two workarounds follow
from that and **both would disappear if `netgauze-parse-utils` and `ipnet` were added**:

- `wire::ipv4_unicast` builds an `Ipv4Unicast` by deserialising the string `"10.0.0.0/24"`
  through serde rather than constructing an `Ipv4Net`. That path also bypasses netgauze's own
  unicast check, so the multicast/broadcast rejection is done locally.
- A fresh codec is constructed per message instead of one being reused.

### What is deliberately not netgauze

KEEPALIVE and NOTIFICATION are hand-encoded. KEEPALIVE is a bare 19-octet header. NOTIFICATION is
a header plus two octets, and netgauze models it as a closed enum of the `(code, subcode)` pairs
it knows — it cannot represent an arbitrary subcode, which `send_bgp_notification` accepts by
design. Neither message has structure to get wrong.

## Session

```text
TCP accept                        -> Connect
peer OPEN, validated + negotiated -> bgp_open -> our OPEN + KEEPALIVE -> OpenConfirm
peer KEEPALIVE                    -> Established -> bgp_established
peer UPDATE                       -> bgp_update
peer NOTIFICATION                 -> bgp_notification, close (never answered)
hold timer expires                -> NOTIFICATION 4/0, close
```

`BgpSessionState` (`state/server.rs`) has six variants; this server is passive, so `Idle` and
`Active` never occur — there is no outbound connect and no reconnection.

**Concurrency**: the stream is split with `tokio::io::split`. The write half is owned by a
dedicated task fed by a bounded outbox (`utils::outbox`: 4096 messages or 8 MiB, past which a
peer that is not reading is cut off), so the keepalive ticker keeps sending while the read
loop is blocked in an LLM call. Sharing the stream behind a lock would have meant holding that
lock across the LLM await, which the root CLAUDE.md forbids.

**Framing** is hand-rolled on top of netgauze's decoder, deliberately: `wire::parse_header`
validates the marker and bounds the length to `[19, 4096]` (plus the per-type minimum) *before*
any allocation, so a peer cannot choose the buffer size and `len - 19` cannot underflow. Only
then is the complete message handed to netgauze.

**The pre-OPEN phase has its own deadline** (`OPEN_HOLD_TIME`, 240s). RFC 4271 section 8.2.2
sets the Hold Timer to "a large value" on entering OpenSent precisely because the *negotiated*
timer cannot start until an OPEN has been exchanged. Without it a peer that completed the TCP
handshake and then said nothing — or sent a valid header and stopped mid-body — parked
`read_exact` for the life of the process, holding a task, a socket and a connection row. The
negotiated timers were already enforced; this closes the window before them. After the OPEN the
deadline is dropped and `spawn_timers` owns the schedule, signalling expiry through `Shutdown`,
which the read loop selects on.

**Every session task is registered** with `register_server_task`, not just the accept loop.
Aborting the accept loop closes the listener and does nothing to sessions already running: each
owns its own socket and goes on sending keepalives — and spending LLM budget — after
`stop_server` reported the server gone. `register_server_task` prunes finished handles on every
call, so a long-lived listener does not accumulate them.

### What was broken before

- **No KEEPALIVE after our OPEN.** RFC 4271 section 8.2.2 requires it to reach OpenConfirm. The
  old code sent a KEEPALIVE only in reply to one, so a peer that waits for ours before sending
  its own deadlocks. This is the single most likely reason a real daemon never came up.
- **No keepalive cadence.** Nothing was sent unless the peer spoke first.
- **No hold-timer enforcement.** A peer that went silent held the socket forever.
- **AS truncation.** `local_as as u16` turned AS 4200000000 into AS 60416 — a different, entirely
  valid-looking ASN, with no capability and no diagnostic.
- **No capability handling.** A peer in a four-octet ASN was recorded as AS 23456 (AS_TRANS),
  and AS_PATH was always read as two-octet.
- **ROUTE-REFRESH tore down the session.** Any message type outside 1-4 earned a Bad Message
  Type NOTIFICATION. It is now ignored with a warning; NetGet does not advertise the capability,
  so a conforming peer will not send it, and there is no RIB to re-advertise from anyway.
- **UPDATE bodies reached the model as `hex::encode(body)`** at one point, which no model can act
  on. They are now decoded field by field.
- **Silent close on FSM violations.** Unexpected messages now earn NOTIFICATION 5/1, 5/2 or 5/3.

### Negotiation

- **Hold time**: `min(what we put in our OPEN, what the peer put in theirs)`; zero on either side
  disables both timers. Our proposal is the handler's `hold_time` if it sent an OPEN, otherwise
  the `hold_time` startup parameter. Deriving the timers from the startup parameter when a
  handler proposed something else would make NetGet keep a schedule its peer never agreed to.
  Keepalives go at `ceil(hold/3)` seconds, minimum one.
- **Four-octet AS**: NetGet always advertises capability 65 with its real ASN, and puts AS_TRANS
  (23456) in the two-octet `My Autonomous System` field when the ASN does not fit. The peer's
  real ASN is read from *its* capability when present.
- **AS_PATH width follows the negotiation.** A peer that advertised the capability gets
  four-octet ASNs; one that did not gets two-octet ASNs, with AS_TRANS substituted and the true
  path added as the optional-transitive AS4_PATH attribute for ASNs that do not fit. Sending
  four-octet ASNs to a two-octet peer earns NOTIFICATION 3/11 from a real router.

The width cannot be decided in `execute_action`, because `Protocol::execute_action` is a pure
function of the action JSON with no session access. So actions return
`ActionResult::Custom { name: "bgp_message", data: <validated intent> }` and the session encodes
with `wire::encode_intent(&intent, peer_asn4)`. Validating in the action rather than at encode
time means a malformed action is reported as a failed action naming the field, instead of
silently producing nothing.

## Dashboard injection: peer handle and counters

Every session registers a peer handle (`peer_support::register_peer_channel`) before its first
read, so `[ message this peer ]` / `[ disconnect this peer ]` work even while a manual rule parks
`bgp_open`, and removes it on every exit path (one cleanup point in `run_session`). Byte and
packet counters are updated on every framed read and in the writer task, which sees every
outbound message — keepalives, NOTIFICATIONs and injected ones included.

The generic `spawn_peer_command_task` is **not** used, because every BGP wire verb returns
`ActionResult::Custom { "bgp_message" }` rather than bytes: the generic task would report it as
executed and write nothing. `spawn_peer_command_task` in `mod.rs` mirrors it instead — same
central executor, same `injected_action` access-log entry, same reply — and encodes the intent
through `wire::encode_intent` at the width the session negotiated (an `AtomicBool` mirror of
`peer_asn4`), then pushes the bytes down the session's write channel. An executor-level
rejection (bad prefix, AS 0, unknown verb) is reported as `Rejected` rather than swallowed.

`close_connection` is accepted by `execute_action` (`ActionResult::CloseConnection`) but is not
offered to the model; injected, it writes NOTIFICATION 6/2 (Cease / Administrative Shutdown)
and raises the session's `Shutdown`, so the read loop exits even if the peer never speaks again.

## No RIB, by design

The root CLAUDE.md forbids protocols from implementing storage, and a RIB is storage. Nothing is
stored, so there is no best-path selection, no re-advertisement, no propagation between peers and
no AS_PATH loop prevention. Routes are exactly what a handler puts in `send_bgp_update`. A
deployment that wants route state should use the generic SQLite facility or server memory.

This is a scope decision, not a missing feature — but it does mean **NetGet is not a router**.
Use BIRD or FRR for anything that forwards packets.

## Events and actions

| Event | Fires | Useful reply |
|---|---|---|
| `bgp_open` | peer's OPEN passed validation | `send_bgp_open` to accept, `send_bgp_notification` to refuse |
| `bgp_established` | session reached Established | `send_bgp_update` to advertise |
| `bgp_update` | peer sent routes | `send_bgp_update` or `wait_for_more` |
| `bgp_notification` | peer is tearing down | informational only; nothing is written back |

`bgp_notification` declares **only `wait_for_more`**. It used to declare all four `send_bgp_*`
verbs, which was a lie the model could act on: `on_notification` discards whatever comes back —
it has to, since RFC 4271 section 4.5 forbids answering a NOTIFICATION — so those verbs could
never reach the socket. `.with_no_actions()` would be wrong here rather than merely unnecessary:
a **server** narrows, so `call_llm` builds its tool list from this list alone, and dropping
`wait_for_more` would leave the event's own response example teaching an action the model was
never offered. (A **client** unions async ∪ sync ∪ event actions, which is why the client half
can use `with_no_actions()` for the same situation.) The common actions — `set_memory`,
`append_to_log` — are added by `call_llm` regardless, so a handler can still record what it saw.

`bgp_established` replaced a declared-but-never-emitted `bgp_keepalive` event. Emitting one per
KEEPALIVE would have cost a model call every `hold/3` seconds per peer, forever, to decide
nothing.

`get_async_actions` is empty. It previously offered `announce_route` and `withdraw_route`, whose
own descriptions said "NOT IMPLEMENTED — logs the prefix and returns NoAction", plus `reset_peer`.
None could reach a peer: an async action carries no connection, and this server never consumed
async action results. `transition_state` is gone for the same reason — it returned `NoAction` and
changed nothing.

### Static default when no operator policy is configured

The OPEN handshake is mechanical (fully determined by the configured ASN/router-id/hold-time and a
validated peer). So with **no operator policy** — no server instruction and no per-event handler
(`operator_wants_dynamic` in `mod.rs` = `has_instruction || has_handler`) — the session completes on the
configured OPEN with **no LLM round-trip at all**; `established`/`update` then advertise nothing,
which is correct with no routing policy. KEEPALIVE cadence never consulted the LLM. The model is
consulted **only when the operator opts in**.

### Three outcomes on `bgp_open`, and they are not interchangeable

`SendOutcome` keeps them apart, because collapsing any two of them is a bug:

| Outcome | Wire | Log tag |
|---|---|---|
| `SentOpen` | the handler's OPEN, then KEEPALIVE -> OpenConfirm | — |
| `Refused` — `send_bgp_notification` ran | that NOTIFICATION, session ends | `decision=model_reject` |
| `Nothing` — policy ran, produced no message (`wait_for_more`, empty handler) | the **configured** OPEN, session proceeds | `decision=model_silent` |
| `Failed(WireFailure)` — the policy could **not be run** (backend error/timeout/saturation) | NOTIFICATION Cease, session ends | `decision=fail_closed_llm_error` |

The `Nothing` fallback is deliberate and is not the fail-open pattern: peering is not an
authorisation decision when the policy was actually consulted and chose to say nothing. The
operator opened this port with this ASN and the peer has already completed a TCP handshake, so
refusing on silence would drop sessions the policy never objected to.

`Failed` is a different matter and used to share the `Nothing` path, which *was* fail-open: with
an admission policy in the instruction ("peer only with AS 65000-65535"), a backend outage
admitted every neighbour the policy would have refused. It now refuses.

**The refusal carries a category and nothing else.** A BGP NOTIFICATION has no free-text field,
so there is structurally nowhere for an internal error to leak; the `data` octets are left empty
and the category rides in the subcode, per RFC 4486:

- `WireFailure::Overloaded` -> Cease / **8, Out of Resources** — a transient resource condition
  a conforming peer damps and retries.
- `WireFailure::Unavailable` -> Cease / **5, Connection Rejected**.

The full error goes to `tracing::error!` and the operator's status stream, never to the peer.

`bgp_established` and `bgp_update` answer **nothing** on any of the four outcomes, including
`Failed`, and that is correct rather than an oversight: RFC 4271 defines no reply to a session
coming up or to an inbound UPDATE, advertising no routes is already the fail-closed answer, and
tearing down an Established session over one failed model call would be worse than advertising
nothing. The keepalive ticker runs in its own task, so the peer never hangs. The three cases are
still tagged in the log by `log_advertisement_outcome`. `bgp_notification` is never answered at
all (RFC 4271), so its handler is pure observation.

Protocol validity, by contrast, is decided in Rust and never delegated: a bad version, an
unacceptable hold time, a zero BGP identifier or AS 0 earn a NOTIFICATION before the model is
consulted at all.

## Startup parameters

| Name | Default | Notes |
|---|---|---|
| `as_number` | 65000 | 1-4294967295. Above 65535 goes out via the four-octet AS capability. |
| `router_id` | 192.168.1.1 | IPv4 dotted quad, not 0.0.0.0. |
| `hold_time` | 180 | 0 (timers off) or >= 3. |

All three are validated in `BgpConfig::from_params` at spawn time, so a bad value fails startup
with a message naming the parameter instead of becoming a different valid-looking value.

## Verification

**No BGP daemon (`bgpd`, `bird`, `bird2`, `frr`, `gobgp`) is installed on the development
machine, so this has never been peered against a real implementation.** That is the honest
limitation and it is why the state is `Experimental` and not `Beta`.

What was done instead, in `tests/server/bgp/`:

1. **`test.rs` — RFC-derived literal bytes.** Every expected vector is written octet by octet
   from RFC 4271 sections 4.1-4.5 and RFC 6793 section 4, with the field decode in the comment.
   These come from neither implementation, so they would still fail if NetGet and netgauze were
   wrong in the same way. Covers OPEN with and without AS_TRANS, KEEPALIVE, NOTIFICATION with hex
   data, UPDATE in both AS_PATH widths, AS4_PATH, withdrawal-only UPDATE, prefix bit-length
   encoding, and the 4096-octet cap.
2. **`test.rs` — inbound parsing of hand-written messages.** The same hand-derived vectors are
   fed into the receive path and the decoded fields checked, including that the peer's real ASN
   comes from its capability and that AS_PATH width follows negotiation. This direction is a
   genuine cross-implementation check, since the input is not NetGet's output.
3. **`e2e_test.rs` — full socket path** against a mocked model: session reaches Established,
   routes are delivered as an UPDATE whose exact bytes are asserted, the two-octet peer gets a
   two-octet AS_PATH, an invalid OPEN is refused without a model call, the model's refusal is
   honoured, a peer UPDATE arrives as structured event data, and keepalives plus hold-timer
   expiry are observed on a 3-second hold time.

4. **`llm_failure_test.rs`** — with a peering *policy* in the instruction and no mock rule for
   `bgp_open` (so the harness answers HTTP 500), the peer must get NOTIFICATION Cease / 5 and
   not the configured OPEN. Asserts the message is exactly 21 octets, which is what makes
   "nothing derived from the error reached the wire" a measurement rather than a claim.
5. **`static_default_test.rs`** — the no-policy path: the handshake completes on the configured
   OPEN with the mock recording **zero** event calls.
6. **`peer_inject_test.rs`** — the dashboard's `[ message this peer ]` / `[ disconnect this
   peer ]` through the session's own command task.

The suite was mutation-checked: removing the post-OPEN KEEPALIVE, disabling hold-timer expiry and
forcing four-octet AS_PATH each made the corresponding tests fail.

Not covered: interoperability with a live daemon, IPv6 and MP-BGP on the send path (inbound
MP_REACH/MP_UNREACH parse but are reported by name only), route refresh, graceful restart, add-
path, multi-peer behaviour of any kind, and the pre-OPEN `OPEN_HOLD_TIME` deadline — at 240s it
is too long to assert against in a suite that has to stay under ten seconds, so it is verified by
inspection only.
