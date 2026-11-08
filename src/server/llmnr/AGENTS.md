# LLMNR Protocol Implementation

LLMNR (RFC 4795) responder: a host on a link answers name queries **for the names it owns**,
and says nothing for everything else. The model owns every name — nothing here stores one.

**State**: Experimental. Not because the code is unfinished, but because no independent
client can be run against it here; see [Maturity](#maturity-why-experimental-and-not-beta).
**Privilege**: `PrivilegeRequirement::None` — port 5355 is unprivileged and joining a
multicast group needs no elevation. **Stack**: `ETH>IP>UDP>LLMNR`.
**Connectionless**: yes, declared. Every query becomes a connection entry that nothing ever
closes, so the 10-second idle sweep is what reaps them.

## Protocol

1. A querier multicasts a query to `224.0.0.252:5355` (or `[FF02::1:3]:5355`).
2. Every host on the link that is authoritative for the queried name answers, **unicast**,
   with the query's transaction ID and question echoed.
3. Every host that is not authoritative answers **nothing at all**.

LLMNR reuses the DNS message format verbatim. What is different is worth having in one place,
because all of it is load-bearing:

### The header

```
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID                       |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   Opcode  | C|TC| T| Z| Z| Z| Z|   RCODE   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Lined up against RFC 1035's `QR|Opcode|AA|TC|RD|RA|Z|Z|Z|RCODE`, the two words are bit-for-bit
identical; LLMNR only renames three flags:

| bit | DNS | LLMNR | meaning here |
|---|---|---|---|
| byte 2, bit 2 (`0x04`) | `AA` | `C` | Conflict: the querier already got multiple answers |
| byte 2, bit 1 (`0x02`) | `TC` | `TC` | unchanged |
| byte 2, bit 0 (`0x01`) | `RD` | `T` | Tentative: authoritative, uniqueness not yet verified |
| byte 3, bit 7 | `RA` | `Z` | must be zero |

`hickory-proto` has no LLMNR mode, so this is the aliasing the implementation actually uses:
`conflict_bit()` reads `metadata.authoritative`, `tentative_bit()` reads
`metadata.recursion_desired`, and `new_response()` writes them back the same way. **Those two
helpers in `actions.rs` are the only place the aliasing happens** — nowhere else should a reader
have to remember that `recursion_desired` means "tentative".

The trap this creates is worth naming: every other DNS builder in this repo calls
`metadata.authoritative = true` on an authoritative answer. Doing that here sets `C`, i.e. tells the
querier a name conflict was detected on the link. `new_response()` clears it explicitly, and
`tests/server/llmnr/e2e_test.rs` asserts `buf[2] & 0x04 == 0` at the byte level so a copied
line from `dns/actions.rs` fails rather than silently changing the meaning of every answer.

### Silence is the protocol

RFC 4795 §2.1.1: *"Since LLMNR responders only respond to LLMNR queries for names for which
they are authoritative, LLMNR responders MUST NOT respond with an RCODE of 3; instead, they
should not respond at all."* And §2.3: *"Responders MUST NOT respond to LLMNR queries for
names for which they are not authoritative."*

This is not politeness. On a shared link the host that *does* own the name still has to be
able to answer, and a negative answer from a bystander would race it. So NXDOMAIN is not
merely unused here — `send_llmnr_error` **refuses** it, naming `no_response` as the way to
express "not mine".

### Discard rules

Silently dropped, before the model is ever asked, with a `debug!` line and no packet:

* anything that is not a query (`QR=1`);
* `OPCODE != 0` (RFC 4795: *"LLMNR queries with unsupported OPCODE values MUST be silently
  discarded by responders"*);
* `QDCOUNT != 1` (*"LLMNR responders MUST silently discard LLMNR queries with QDCOUNT not
  equal to one"*);
* anything `hickory-proto` cannot parse — on a multicast group that is background noise, not
  an error worth the status stream.

## What the model sees and controls

**Event**: `llmnr_query`, one per query, carrying `transaction_id`, `name`, `query_type`,
`query_class`, `source_address`, `transport` (`"udp"`/`"tcp"`), `conflict` (the `C` bit as it
arrived) and `tentative` (the `T` bit). Structured fields only — the model never sees or
produces a packet.

**Actions**

| Action | Effect |
|---|---|
| `send_llmnr_response` | A / AAAA / PTR answer, unicast, ID + question echoed, `ttl` default 30, optional `tentative` sets `T` |
| `no_response` | **Say nothing.** The correct answer for a name this host does not own |
| `send_llmnr_error` | Non-zero RCODE (`SERVFAIL`/`NOTIMP`/`REFUSED`). TCP only — see below. `NXDOMAIN` is rejected |

No async actions: a responder says nothing until it is asked.

`send_llmnr_response` is deliberately limited to A, AAAA and PTR. LLMNR answers for a *host's
own* names; anything richer would be asserting authority over a zone, which a link-local
responder does not have.

## Fail-closed: an LLM failure produces silence

**This protocol is in the deliberately-silent class the root `AGENTS.md` catalogues, and its
case is the strongest one in it.** `metadata()` declares it with `.deliberately_silent()`, which
`tests/failure_mode_declaration_test.rs` checks.

Every other UDP protocol in NetGet answers a backend failure with an error frame, because
silence costs the client its own timeout. Here that trade inverts twice over:

* An LLMNR response is not a message the peer reads and discards. It is a **name-to-address
  binding written straight into the querier's resolver cache**, for the TTL. A fabricated
  answer during a backend outage is cache poisoning — handed to every querier on the link,
  for a name no host actually claims.
* The only error frame LLMNR has is a non-zero RCODE, and RFC 4795 §2.1.1 forbids that in
  response to a multicast query: *"The response to a multicast LLMNR query MUST have RCODE set
  to zero. A sender MUST silently discard an LLMNR response with a non-zero RCODE sent in
  response to a multicast query."* There is nothing legal to send.

A querier that hears nothing simply asks the next responder, which is exactly what the
protocol is built for. So: **nothing is written, ever, on any failure path.**

### The log carries the distinction instead

Copied from `src/server/radius/`, for the reason that file gives: *the model said no* and *the
model was never reached* produce identical bytes here — none — and must never be identical in
the log. That collapse is the OAuth2 defect the root `AGENTS.md` records, and here it would
hide a total backend outage as protocol-correct silence, indefinitely.

`Decision` in `mod.rs` is logged as `decision=<token>` on every query:

| token | meaning | bytes sent |
|---|---|---|
| `model_response` | the model answered with a record | yes |
| `model_silent` | the model chose `no_response` — this host does not own the name | none |
| `model_reject` | the model chose `send_llmnr_error`, over TCP | yes |
| `model_reject_suppressed_udp` | it chose an RCODE, but the query came over UDP | none |
| `fail_closed_no_action` | the model returned nothing usable | none |
| `fail_closed_action_error` | the model produced actions, none encoded | none |
| `fail_closed_llm_error` | the LLM call failed — outage, overload, unusable output | none |

Every `fail_closed_*` is logged at ERROR on both channels; the rest at INFO. `grep
'decision=fail_closed_'` finds every query the model did not actually answer. The LLM error is
classified through `WireFailure` (`overloaded` vs `unavailable`) **for the log only** — there
is no wire text here at all, so nothing can leak, but the category is still what tells an
operator whether to wait or to look.

## Transports, and the one RFC deviation

**UDP on the port** is the main path, and the multicast group join is best-effort:
`join_llmnr_group` logs a failure on both channels and carries on. On macOS a join on loopback
fails routinely, and a responder that refused to start because of it would be unusable for
exactly the local testing this repo does — while still being perfectly able to answer a query
sent straight to its port.

**TCP on the same port** is bound too. RFC 4795 §2.4 requires it (*"Senders MUST support
sending TCP queries, and responders MUST support listening for TCP queries"*), framed with the
RFC 1035 §4.2.2 two-byte length prefix, response on the same connection. It is the only
transport on which a non-zero RCODE may be returned. The bind is **best-effort**: the port is
whatever the UDP socket was given, and if some other process already holds it for TCP, losing
the TCP half is better than failing the whole server. The failure is logged at WARN, not
hidden.

Every TCP read is bounded by `TCP_IDLE_TIMEOUT` (30s), on the length prefix and on the body
alike. The exchange is one question and one answer — there is no session to keep alive — so a
peer that connects and says nothing, or announces a length and never sends it, would otherwise
park a task that `register_server_task` can never prune, since it never finishes. That is a
task and a file descriptor per idle connection, on a protocol with no idle connections.

### Deviation: unicast UDP queries are answered

RFC 4795 §2.4 ends with *"Unicast UDP queries MUST be silently discarded."* **This server
answers them anyway**, and that is a deliberate, knowing deviation:

* A plain `UdpSocket` cannot tell a datagram addressed to `224.0.0.252` from one addressed to
  the interface — that needs `IP_PKTINFO`/`IPV6_PKTINFO` and a recvmsg path neither tokio nor
  this codebase has. So the rule is not merely unimplemented; it is **unimplementable at this
  layer as written**.
* Discarding *all* UDP would mean discarding multicast too, i.e. the protocol's main path.
* NetGet's whole model is "point a client at this port", and every e2e test in the repo binds
  loopback. Refusing direct queries would make the responder untestable and unusable.

The consequence is confined and handled: because a UDP datagram *might* be multicast, the
stricter RCODE rule is applied to **all** UDP. A `send_llmnr_error` produced for a UDP query is
dropped with `decision=model_reject_suppressed_udp` and a WARN naming §2.1.1, rather than
risking an illegal response. Errors are delivered only over TCP, where the RFC allows them.

## Startup parameters

| Parameter | Default | Effect |
|---|---|---|
| `join_multicast` | `true` | Join `224.0.0.252` / `FF02::1:3`. A failure is logged, never fatal |
| `multicast_interface` | host's choice | Local **IPv4** address to join on. No effect on an IPv6 socket — IPv6 joins select by interface index, not address |
| `enable_tcp` | `true` | Bind the TCP listener on the same port |

All three are read in `mod.rs`; all three are accessed with `?`, never `unwrap()`.

## Not implemented

* **Name defence.** A real responder verifies a name's uniqueness on the link and defends it
  (RFC 4795 §4), which is what the `C` and `T` bits exist for. This server holds no names —
  the model does — so it has no uniqueness state to verify. `tentative` is therefore something
  the model *asserts*, not something the server *knows*, and `C` is read from queries but never
  set on responses: setting it would claim a conflict this server has no way to have detected.
* **NBT-NS fallback**, LLMNR's Windows companion. Separate protocol, separate port.
* **Storage of any kind.** No zone, no host table, no cache. The model answers every query.
* **Rate limiting and the security considerations of RFC 4795 §5.** LLMNR is trivially
  spoofable by design and this responder does nothing to mitigate that; it is a test tool.

## Example prompts

```json
{"type": "open_server", "port": 5355, "base_stack": "llmnr",
 "event_handlers": [{"event_pattern": "llmnr_query", "handler": {"type": "script",
   "language": "python",
   "code": "name = event.get('name', '').rstrip('.').lower()\nif name == 'printer.local' and event.get('query_type') == 'A':\n    respond([{'type': 'send_llmnr_response', 'transaction_id': event['transaction_id'], 'name': event['name'], 'record_type': 'A', 'address': '192.168.1.42', 'ttl': 30}])\nelse:\n    respond([{'type': 'no_response'}])"}}]}
```

```
LLMNR responder on port 5355. Answer A queries for printer.local with 192.168.1.42
and AAAA with fd00::42. Say nothing for any other name.
```

**Static mode can only express silence here.** A static handler has no access to the event, so
it cannot echo the querier's random transaction ID or the queried name — and a response
carrying neither is discarded by the querier, which is silence with extra steps. That is why
`get_startup_examples()`'s static example is `{"type": "no_response"}`, and why script mode is
the deterministic option. Same shape as DNS, for the same reason.

## Maturity: why Experimental, and not Beta

The bar for Beta in this repo is *works against real clients*, evidenced by a test an
independent implementation actually passes. That evidence cannot be produced here:

* The real LLMNR clients are the **Windows resolver** and **systemd-resolved**
  (`resolvectl query --protocol=llmnr`). Neither exists on macOS; `resolvectl`,
  `systemd-resolve` and `avahi-resolve` are all absent on this machine.
* **No Rust crate issues LLMNR queries.** A crates.io search finds `llmnr-poison`, which is a
  Responder-style *responder* — the same role as this server, not a querier — and nothing
  else. `hickory-resolver` does DNS, not LLMNR; `mdns-sd`/`simple-mdns` do mDNS, a different
  protocol on a different group and port.
* So the e2e test builds its queries with **`hickory-proto`, which is the crate this server
  encodes with**. That is exactly the circular-evidence failure the root `AGENTS.md` names for
  `webrtc_signaling`/`websocket`: the "independent peer" is the library the server itself
  frames with, so the test proves the codec round-trips through itself, not that anything else
  would accept the result. `tests/server/websocket/e2e_test.rs` escapes this by hand-writing a
  raw RFC 6455 client; a hand-written client would not help here either, since the root
  `AGENTS.md` is explicit that an in-test hand-rolled client is not a third-party client (the
  `dhcp` and `usb/serial` cases).

What the test *does* prove is still worth having: NetGet's own wiring is correct end to end —
the event fires with the right fields, routing reaches it, the actions execute, the transaction
ID and question survive the round trip, the `C` bit stays clear, silence really is silent on
three different paths, and TCP framing works.

**Unverified, and named in `metadata().notes`:** multicast reception on a real link (the test
is unicast to loopback), interoperability with a Windows or systemd-resolved querier, the TCP
transport against anything but itself, and IPv6 entirely.

## No peer handle — `[ message this peer ]` / `[ disconnect this peer ]` stay disabled

LLMNR declares `.connectionless()` — correctly: one query, one answer, no session. That makes
`AppState::cleanup_old_connections` evict its connection rows after ten seconds of silence **by
design** (the sweep is what reaps them; see the comment on `serve_tcp_connection`). A peer handle
would be registered against a row the sweep is about to remove, so the affordance would appear
and vanish rather than being reliably there when a parked query needs answering.

The TCP reply is also length-prefixed by the session (RFC 4795 §2.4 inherits RFC 1035 §4.2.2),
exactly as `dot`'s is, so an injected `ActionResult::Output` would be written without its prefix
and desynchronise the connection. And an LLMNR response carries the querier's transaction id, so
there is no unsolicited message worth sending.

**Worth knowing rather than fixing here:** a TCP querier whose event is parked for a human is
swept out of `AppState` after ten seconds while its socket is alive, because `connectionless` is
declared per protocol and LLMNR serves both transports from one declaration. The project
`AGENTS.md` describes exactly this hazard for the general case.

The dashboard renders that as a dim button reading "this protocol cannot message a peer from
here yet", which is the honest rendering. `tests/peer_handle_coverage_ratchet_test.rs` carries
this protocol on its shrink-only baseline with the reason above, and re-derives the reason from
source on every run, so if the mechanism changes the build fails rather than the file going
quietly stale.
