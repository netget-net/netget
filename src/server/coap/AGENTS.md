# CoAP Protocol Implementation

## Overview

CoAP (RFC 7252) server over UDP. The LLM plays a constrained device: it decides what a resource
*is* — its representation and media type — and which response code the request deserves. NetGet
owns the message layer: types, message ids, tokens, options and the replies the specification
leaves no room to decide.

**Status**: **Stable**, set 16 September 2026. See "Maturity: the six conditions" at the foot
of this file for what was checked, what failed when it was checked, and what the rating does
*not* cover.

This line used to name only `test_coap_get_post_and_not_found_with_coap_client` and
`test_coap_message_layer_echo_and_ping`, the two Rust-crate tests, and say nothing about
`real_client_test.rs`. That omitted the strongest evidence the protocol has: libcoap's own
`coap-client`, a C implementation, has driven this server since September 2026. Three peers,
none of which shares a line with `codec.rs`:

| peer | what it is | test |
|---|---|---|
| `coap-client` | libcoap 4.3.5, C, a different project | `real_client_test.rs` |
| `coap-client` again | Observe, Block2 and Block1 | `observe_blockwise_test.rs` |
| aiocoap 0.4 | Python, its own codec and observation/block-wise state machines (`peer/aiocoap_peer.py`) | `observe_blockwise_test.rs` |
| `coap` 0.27 | a full Rust UDP client | `e2e_test.rs` |
| `coap-lite` 0.13 | an independent Rust codec (`coap` is built on it) | `e2e_test.rs`, `bounds_test.rs` |

None is `#[ignore]`d, none has a skip-when-missing gate — `real_client_test.rs::require_coap_client`
**fails** when libcoap is absent, and `observe_blockwise_test.rs` fails without `coap-client` or
`NETGET_AIOCOAP_PYTHON` — and both crates are **unconditional** dev-dependencies
(`[dev-dependencies] coap-lite = "0.13"`, `coap = "0.27"`; neither is `optional = true`), so the
evidence compiles wherever the suite does. (The line also said "Experimental" once while the
code said `Beta` — the code was right.) The blocking CI `test` job runs
`tcp,http,dns,udp,redis,mcp-stdio` only and so does not execute any of it; run it yourself.

**RFC**: RFC 7252 (Constrained Application Protocol)
**Port**: 5683, declared as `PrivilegeRequirement::None`
**Feature**: `coap` (no optional dependencies — the codec is hand-rolled)

5683 is above 1023, so a `PrivilegedPort` declaration here could never fire and would read as
protection that is really dead code. `None` is the honest declaration.

## Library choice

**Hand-rolled**, in `codec.rs` (~650 lines; this said "~470" when the file was already 560, and
line counts in prose are worth distrusting for exactly that reason). `coap-lite` is a good codec
and would have worked,
but the test peer is `coap-lite` (and the `coap` crate on top of it). Using it on both sides
would make the round-trip tests a tautology: a shared encoder cannot disagree with itself. With
a hand-rolled server, "coap-lite decoded our ACK and found the right token" is real evidence.

Both test crates are dev-dependencies only: `coap-lite` 0.13 (MIT OR Apache-2.0) and `coap` 0.27
(MIT).

## What is implemented

- The 4-byte header: version, type, token length, code, message id.
- All four message types: CON, NON, ACK, RST.
- Tokens, 0-8 bytes, echoed verbatim on every response.
- Option encoding and decoding including **both** extension forms — nibble 13 (one extra byte,
  values 13-268) and nibble 14 (two extra bytes, 269+) — for delta and for length.
- Uri-Path, Uri-Query, Content-Format and Accept surfaced to the model; every other option is
  decoded and preserved in the message but not interpreted.
- The payload marker `0xFF`.
- The request codes GET/POST/PUT/DELETE and the full `class.detail` response code space.
- Piggybacked responses: CON → ACK with the request's message id; NON → NON with a fresh one.
- CoAP ping (RFC 7252 §4.3): an empty CON is answered with RST.
- RST in reply to a malformed CON (§4.2).
- 4.13 Request Entity Too Large (§5.9.2.9) for a datagram over `codec::MAX_MESSAGE_LEN` — see
  decision 6b.
- **Observe** (RFC 7641, `observe.rs`, decision 8): registration by a GET with Observe 0 that
  the model answers 2.xx, deregistration by Observe 1 on the same token, notifications pushed
  with `coap_notify` (NON, or CON with retransmission), and removal on a RST or on a CON
  notification never acknowledged.
- **Block-wise transfer** (RFC 7959, `blockwise.rs`, decision 9): Block2 for a representation
  over 1024 bytes or whenever the client asks for blocks, every block served from one cached
  answer with ETag and Size2; Block1 reassembled with 2.31 Continue, refused 4.08 out of order,
  4.13 with Size1 over `MAX_REPRESENTATION_LEN`, 5.03 when `MAX_UPLOADS` are in progress.

**Not implemented**: DTLS / CoAPS on 5684, separate (delayed, non-piggybacked) responses,
retransmission of Confirmable responses, and multicast. `.well-known/core` is not special-cased: the model can serve it, but nothing
generates a link-format listing automatically, because there is no resource registry to list.

## Architecture decisions

### 1. No resource database — the model answers every request

No filesystem, no map of paths to representations, no persistence. `coap_request` fires and the
model decides. Continuity across requests comes from server memory (`set_memory`,
`append_memory`) or the generic SQLite facility, never from protocol-local storage.

### 2. Message ids and tokens are server-side, deliberately

`codec::response_to` takes the type, message id and token from the request. The model does not
see the token at all and sees the message id only as an informational event field it is told to
ignore.

This is the opposite of what DNS does (where `query_id` is an action parameter the model must
echo), and it is a deliberate improvement:

- Reliability matching is not a decision. Getting it wrong means the peer retransmits forever;
  there is no interesting way to be creative about it.
- It removes the failure mode where a static handler is useless because it cannot echo a random
  identifier. Static and script handlers work fine for CoAP.

The consequence for tests is spelled out in `tests/server/coap/AGENTS.md`: the mocks still use
`respond_with_actions_from_event()`, but what they derive dynamically is the **path**, and the
message-id/token echo is asserted directly against `coap-lite`-decoded replies instead.

### 3. Mechanical replies never reach the model

Answered in `mod.rs` with no LLM call:

- Empty CON (a ping) → RST.
- Malformed datagram that was Confirmable → RST for its message id.
- Empty NON/ACK/RST → ignored.
- A message carrying a *response* code, arriving at a server → ignored.
- A class-0 code that is not 1-4 → 4.05 Method Not Allowed (RFC 7252 §5.8 defines only four).

### 4. Payload encoding is explicit and actually decoded

`send_coap_response` takes `payload` plus an optional `encoding` of `"utf8"` (default) or
`"hex"`, and `decode_payload()` really decodes the hex — tolerating whitespace, `:` separators
and a leading `0x`, and erroring with a legible message otherwise. There is no sniffing:
`"48656c6c6f"` is simultaneously valid text and valid hex and only the sender knows which it
means. This is the `send_tcp_data` lesson applied up front rather than after the fact.

`content_format` accepts a media type name (`"application/json"`, `"application/cbor"`, ...) or
the numeric identifier. When a payload is present and `content_format` is omitted it defaults to
`text/plain;charset=utf-8` (identifier 0), so a client is never handed bytes with no media type;
when there is no payload, no Content-Format option is emitted.

### 5. Fail closed

`outcome_from_results` answers **5.03 Service Unavailable** with an ERROR log when the LLM call
failed or when no usable action came back. It never invents an empty 2.05, which the client
would believe.

Note the three outcomes are structurally distinct: a response, a Reset, and deliberate silence
(`ignore_coap_request`). "The model said nothing" and "the model chose to say nothing" are
different code paths.

### 5b. `decision=` separates a backend outage from the model choosing 5.03

5.03 is what both fail-closed paths put on the wire *and* a code the model may legitimately
pick itself, so the peer cannot tell them apart. The log carries a stable token per request,
as `src/server/radius/` does:

| token | meaning | level |
|---|---|---|
| `model_answer` | the model served the resource (class 2) | DEBUG |
| `model_reject` | the model refused, class 4 or 5 | DEBUG |
| `model_reset` | the model chose RST | DEBUG |
| `model_silent` | the model chose `ignore_coap_request` — a decision, not an absence | DEBUG |
| `spec_reply` | ping → RST, or unrecognised method → 4.05; the model was never asked | DEBUG/WARN |
| `refused_too_large` | over `MAX_MESSAGE_LEN`; refused unread, never a prompt (decision 6b) | WARN |
| `fail_closed_llm_error` | the LLM backend failed | **ERROR** |
| `fail_closed_no_action` | the model was asked and returned nothing usable | **ERROR** |

`grep 'decision=fail_closed_'` finds every request the model did not actually answer. The
error text stays in the log and never reaches the wire — only the code does.

`tests/server/coap/llm_failure_test.rs` drives both fail-closed rows from a socket and asserts
that the two tags are **different**, which is the whole claim: the peer receives the same five
bytes either way, and a backend outage and a model answering badly are opposite problems with
opposite fixes. It also asserts the refusal is *matchable* — ACK, the request's message id, the
request's token — because a 5.03 a client discards as unsolicited is the silence this path
exists to replace. Until September 2026 this table was seven rows that nothing checked.

### 6. A representation has a ceiling, and the bound is on the model's side

`codec::MAX_REPRESENTATION_LEN` is **64 KiB** and `decode_payload` enforces it, counting decoded
bytes so a `hex` payload gets no extra budget. Until October 2026 this was
`codec::MAX_PAYLOAD_LEN`, 1024 bytes — RFC 7252 §4.6's payload for an unknown path MTU — because
without Block-wise transfer a response had to fit one datagram. Block2 now splits anything
larger (decision 9), so 1024 is the size of one block and the bound is on what the server holds
while it serves the blocks.

The limitation was documented and unenforced, which is the worse combination. Nothing stopped
the model returning a 100 KB representation; the oversize datagram then reached `send_to`,
failed with `EMSGSIZE`, was logged, and **nothing was sent** — so a CON client retransmitted
four times and gave up with no diagnostic on its side. Refusing at `execute_action` instead
turns it into a legible error the model can act on (return less), and the existing fail-closed
path answers 5.03 if it does not.
`tests/server/coap/e2e_test.rs::test_oversize_payload_is_refused_rather_than_silently_dropped`
pins the limit, the message, and that exactly `MAX_REPRESENTATION_LEN` bytes is still accepted.

### 6b. …and a request has to fit one too, which is the bound `max_inbound_bytes` declares

`codec::MAX_MESSAGE_LEN` is **1152 bytes** — RFC 7252 §4.6's `MAX_MESSAGE_SIZE`, the number
1024 is derived *from*. `handle_datagram` refuses a larger datagram **before decoding it and
before any model call**, answering 4.13 Request Entity Too Large (§5.9.2.9) for a request and a
Reset for a Confirmable non-request. The refusal carries the request's own message id and token,
read out of `codec::message_prefix` — a fixed-offset read that walks no options — because CoAP
matches a reply to its request by token equality and a refusal the client discards is silence
wearing a response code.

**This is a correction, not a feature.** `metadata()` declared
`.max_inbound_bytes(MAX_PAYLOAD_LEN)`, i.e. 1024 — and `MAX_PAYLOAD_LEN` bounds what the server
*writes*. Nothing on the inbound path checked it or anything else: a 2000-byte request was
decoded, turned into an event and handed to the model. The declaration named a number the code
never enforced, which is precisely what `max_inbound_bytes`' own doc comment warns against
("the number must be the one the code enforces, at the point the length is decided"). Nothing
caught it because `tests/max_inbound_bytes_bound_plus_one_test.rs`, the generic `bound + 1`
probe, reaches servers over `TcpStream::connect` and skips every UDP protocol.

Two details that look like slack and are not:

- **The receive buffer stays at 2048, deliberately larger than the bound.** `recv_from`
  discards whatever does not fit, so a buffer sized *at* 1152 would deliver a 5000-byte
  datagram as a legal-looking 1152-byte one and the guard could never fire.
- **`decision=refused_too_large`** is its own log token, not `fail_closed_`: nothing failed,
  the server decided. What it marks is a request that never became a prompt.

`tests/server/coap/bounds_test.rs::test_inbound_message_bound_refuses_one_byte_over_without_asking_the_model`
drives it from a socket — 1152 bytes served, 1153 refused 4.13 — and asserts the model-call
count directly, so the zero is the bound's and not the routing table's.

### 7. `encode` refuses what `decode` would refuse, instead of truncating

`CoapMessage::encode` returns `Result<Vec<u8>, EncodeError>`. It used to return `Vec<u8>` and
write `self.token.len().min(8)` as the TKL while copying only those eight octets, so a token
longer than the format allows reached the wire *shortened* — a perfectly parseable message
carrying a token that is not the one that was asked for. `decode` refuses `tkl > 8`, so the two
directions disagreed about what is legal, silently.

Truncation is the worst available outcome on this protocol specifically. **CoAP's whole
request/response matching is token equality** (RFC 7252 §5.3.2): a client that sent a 9-octet
token and receives an 8-octet one discards the reply as unsolicited, so the server logs a
successful send, the client logs nothing at all, and the request times out. The same change
bounds an option value at [`MAX_OPTION_LEN`], which was narrowed by an `as u16`.

Nothing in NetGet could reach either today — a response's token is echoed from the request and
`decode` has already bounded that at 8, and the model never sees the token — so both were
latent in a `pub fn` rather than reachable from the wire. `mod.rs::send` answers the refusal
with `decision=fail_closed_encode` and sends nothing, which is the same fail-closed vocabulary
the rest of the protocol uses.

### 8. Observe: the model decides what is observable and when it changed

A GET with Observe 0 reaches the model as `coap_request {observe: "register"}`. A 2.xx answer
registers the client (`observe::Observers`, keyed by endpoint and token, RFC 7641 §3.1) unless
the answer says `observable: false`; the response then carries an Observe sequence number. A
4.xx/5.xx registers nobody, which is the RFC's own "this resource cannot be observed". Observe
1 on the same token deregisters before the model is asked, and the model still answers the GET.

The model pushes state with **`coap_notify {path, payload, …}`** — an async action (an operator
asks for an update) *and* a sync one (a PUT changes what others observe). It reaches the live
socket through `CoapServerHandle`, registered with `AppState::register_server_handle`, because
the registry's protocol object is stateless; the stateless `execute_action` validates and then
refuses, naming `execute_action_with_state`. A 2.xx keeps the observations; any other code goes
out without Observe and ends them all (§4.2).

An observation also ends on the message layer:

- **RST** in reply to a notification (§3.6). `Observers::record` keeps the last
  `RECENT_NOTIFICATIONS` (256) message ids so a RST can be matched back to its observer.
- **A Confirmable notification never acknowledged.** It is resent after
  `notification_ack_timeout_ms` (default `DEFAULT_NOTIFICATION_ACK_TIMEOUT_MS`, 2000, randomised
  up to 1.5×, doubling) at most `NOTIFICATION_MAX_RETRANSMIT` (4) times, then the observer is
  removed (§4.5), `decision=observer_timeout`. The resend task is registered with the server, so
  stopping the server stops it.

`MAX_OBSERVERS` (64) bounds the registry. A registration past it is *served* — the client asked
for the representation too — without Observe, which tells it it is not registered rather than
leaving it waiting for notifications that never come (`decision=observe_cap_reached`).

### 9. Block-wise: the model answers once, whatever the block count

**Block2.** A representation over one block — 1024 bytes, or the smaller size the client asked
for in its own Block2 — goes out as block 0 with Size2 and an ETag (an FNV-1a hash of format and
payload, so two answers never share one), and is cached in `blockwise::Transfers` under (peer,
path, query). Later blocks are served from the cache with no model call
(`decision=block_cache`); a 64-block transfer costs one turn, and every block comes from the
same answer. A miss — evicted, expired, or a client that starts at block 3 — is not an error: the
request goes to the model again as RFC 7959 §2.4's stateless server would, and its answer is
sliced the same way. A block past the end is 4.02. The cache holds `MAX_TRANSFERS` (32) entries
for `TRANSFER_TTL` (60 s) and evicts the least recently used: eviction costs a model call, never a
refusal.

**Block1.** Blocks are matched by (peer, path, query, method) — not token, which a client may
change per block — and appended only at the exact offset the body has reached, which is also what
lets a client lower the block size mid-upload (§2.3). Every block but the last is answered 2.31
Continue echoing its Block1, with no model call (`decision=upload_continue`); the last carries the
whole body on to the model as one `coap_request` with `payload_size` and `blocks`, and the answer
echoes the final Block1. Refusals, each a `decision=refused_upload_*` and none reaching the model:
4.08 out of order or with no upload in progress, 4.00 for a block whose length is not its size
while it says more follow, 4.13 with Size1 when Size1 or the body passes
`MAX_REPRESENTATION_LEN`, 5.03 when `MAX_UPLOADS` (16) are in progress. Unlike a cached
representation, an upload cannot be evicted without losing blocks already acknowledged, hence the
refusal.

The tables are `std::sync::Mutex`es in `CoapServerHandle`, none held across an `.await`.
`blockwise.rs` and `observe.rs` are pure and take `now`, so their rules need no clock to test.

## LLM integration

### Events

One event, `coap_request`, emitted for every well-formed GET/POST/PUT/DELETE. Its data:

| Field | Notes |
|---|---|
| `method` | GET / POST / PUT / DELETE |
| `path` | assembled from Uri-Path options, always leading-slashed; `/` when absent |
| `path_segments` | the same, unjoined |
| `query` | Uri-Query options joined with `&`; absent when there was none |
| `message_type` | `CON` or `NON` — informational; the reply is matched automatically |
| `message_id` | informational; echoed automatically |
| `content_format` | media type of the request body, when declared |
| `accept` | media type the client asked for, when it sent an Accept option |
| `payload` / `payload_encoding` | request body, `utf8` when all bytes are printable, otherwise `hex`; a Block1 upload arrives here whole |
| `payload_size` | body length in bytes, when there is a body |
| `blocks` | how many Block1 blocks the body came in; absent for a single message |
| `observe` | `register` (a GET with Observe 0: a 2.xx answer registers the client) or `deregister` (Observe 1: already removed); absent otherwise |
| `answer_with` | the answer this request takes (`actions::answer_with_for_request`): look the path up in the instructions; if they give the device nothing there, the literal `{"type": "send_coap_response", "code": "4.04"}`; if they do, the method's success code and, for a GET, the representation character for character |

**Why `answer_with` exists, and why it is worded the way it is.** The code table in
`send_coap_response`'s description did not carry a small model on its own. In the real-model
eval (llama3.1:8b, seed 42), told "you are a greenhouse sensor whose only resource is
/temperature", the model answered a GET of /humidity with an invented 2.05 `{"humidity": 41.2}`
five runs in five — 41.2 was the value in the action's example. Three things were measured, one
eval run each:

- A hint naming the success case first and the 4.04 second: not-found 0/5 → 0/5 passes, but
  3 of the 5 were now 4.04 carrying `"content_format": ""`, which the executor refused as an
  unknown media type (fixed: an empty `content_format` reads as absent), and 2 were still an
  invented 2.05.
- The lookup first, the 4.04 as a literal action: not-found 4/5, and **text-resource fell from
  5/5 to 0/5** — "the representation your instructions give for it" read as licence to reshape
  "the text 19.5 C" into `{"temperature": 19.5}`.
- The same, with the found case saying "exactly what they say {path} returns, character for
  character - text stays text, never rewritten as JSON": text-resource 5/5, not-found 5/5.

The action and event examples are placeholders (`"<the resource's representation>"`, text/plain)
rather than a plausible reading, and the description says so.

### Actions

- `send_coap_response { code, payload?, encoding?, content_format?, observable? }` — `code` is
  written `class.detail` (`"2.05"`, `"4.04"`, `"5.03"`); class must be 2, 4 or 5. The decoded
  payload must be at most `MAX_REPRESENTATION_LEN` (64 KiB); over 1024 bytes it goes out in
  Block2 blocks. `content_format` absent, `null` or `""` means none for an empty payload and
  text/plain for a non-empty one; any other unrecognised media type is refused. `observable`
  (default true) only matters for an `observe: register` request: false serves it without
  registering.
- `coap_notify { path, payload?, encoding?, content_format?, code?, confirmable? }` — sync and
  async. Pushes to every observer of `path`; `code` defaults to 2.05 and a 4.xx/5.xx ends the
  observations; `confirmable` (default false) sends CON with retransmission. Validated by the
  same helpers as `send_coap_response`, executed only through `execute_action_with_state`.
  Answers `coap_notified {observers_notified, observations_ended}`.
- `send_coap_reset {}` — RST. For a message the device cannot make sense of at all, not for
  "not found".
- `ignore_coap_request {}` — send nothing, modelling a sleeping or unreachable node.

## Startup parameters

One: `notification_ack_timeout_ms` (default `DEFAULT_NOTIFICATION_ACK_TIMEOUT_MS`, 2000, range
100-60000) — RFC 7252's ACK_TIMEOUT for Confirmable notifications. Read in `spawn`, refused
outside its range, and declared with the constant as its default.

## Why `.connectionless()` is still right here

The test is not "is it UDP" but "has it a connection concept" — declaring `.connectionless()`
on a UDP protocol that carries a *transfer* is actively harmful, because the 10-second idle
sweep then evicts a live transfer that is merely waiting on an LLM call (TFTP had exactly
that). Observe and Block-wise *do* give CoAP state that outlives a datagram, and that is
exactly why none of it lives in a connection entry: observers, cached representations and
uploads are tables in `CoapServerHandle`, keyed by the peer's address and the resource, with
their own caps and TTLs (decisions 8 and 9). Every datagram still gets a fresh, disposable
connection entry, and the sweep removing one touches none of the tables — an observer keeps
the id of the entry its registration made only to attribute byte counts. The one visible consequence is that a
request parked longer than 10 seconds can have its sent-byte counter land on an entry the
sweep already removed; nothing about the reply itself depends on it.

## Known limitations

1. **One datagram is still at most 1152 bytes** (decision 6b); a body larger than a block has to
   come as Block1 blocks, and a client that sends one oversize datagram instead gets 4.13. This
   entry used to say Observe and Block-wise were missing; both were added in October 2026.
2. **No DTLS**, so no CoAPS on 5684.
3. **Only piggybacked responses.** A slow model still answers in the ACK rather than sending an
   empty ACK followed by a separate CON, so a client with a short ACK_TIMEOUT (2s by default)
   may retransmit while an LLM call is in flight. Use script or static handlers when that
   matters.
4. **No deduplication cache.** A retransmitted CON produces a second event and a second LLM
   call. RFC 7252 §4.5 permits re-processing an idempotent request; it is still a cost.
5. **Notifications match the observed path only.** An observer registered on `/temp?unit=C`
   gets every `coap_notify` for `/temp`; the query is kept only to find its cached Block2
   representation. Accept is not compared either — the model is told what each observer asked
   for at registration and is trusted to notify in that format.
6. **Observe sequence numbers are one counter for the whole server.** RFC 7641 §4.4 needs only
   that one observer's notifications increase, which a shared 24-bit counter gives.

## Example prompts

```
listen on port 5683 via coap
You are a soil moisture sensor.
GET /sensors/moisture returns 2.05 with JSON {"pct": <0-100>, "ts": <unix seconds>}.
GET /sensors/temp returns 2.05 with plain text degrees Celsius.
PUT /config/interval accepts an integer number of seconds and returns 2.04.
Everything else is 4.04.
```

```
listen on port 5683 via coap
Impersonate a smart lock. GET /lock/state returns "locked" or "unlocked" as
text/plain. POST /lock/actuate with body "unlock" returns 2.04 only if memory
says a valid PIN was presented in the last 30 seconds; otherwise 4.01.
```

## Maturity: the six conditions

The root `AGENTS.md` defines `Stable` as six conditions. Re-derived against source on
16 September 2026 rather than inherited. All six hold, one of them only after a repair:

| # | condition | holds? |
|---|---|---|
| 1 | two independent third-party clients, no skip, no `#[ignore]` | **yes** — libcoap's `coap-client` (C) and the `coap`/`coap-lite` crates; `require_coap_client` hard-fails |
| 2 | the pcap oracle is green over its wire traffic | **yes** — `e2e_test.rs::exchange` runs `PcapOracle::udp("coap")` over every datagram in both directions |
| 3 | a fuzz target exists and has run clean, with a corpus | **yes, as of this pass** — 292,391 runs in 91s, clean; see below |
| 4 | every declared bound has a test | **yes, as of this pass** — `bounds_test.rs`, each verified by removal |
| 5 | both `AGENTS.md` files verified against source in this pass | **yes** — this file and `tests/server/coap/AGENTS.md` |
| 6 | no `#[ignore]`, no skip-when-missing gate | **yes** — `grep -rn '#\[ignore\]' tests/server/coap/` is empty |

**Condition 3 was false until this pass, and how it broke is the useful part.**
`fuzz/fuzz_targets/coap_message.rs` was written on 15 September 2026 against an `encode` that
returned `Vec<u8>`; `0996d00f`, the same day, made it return `Result<Vec<u8>, EncodeError>` so
an over-long token is refused rather than truncated. The target's
`CoapMessage::decode(&reencoded)` has been an `E0308` ever since. Nothing noticed: `fuzz/` is
deliberately its own workspace (it needs nightly and links libFuzzer's runtime), so `cargo
check` at the repository root never compiles it and **no CI job builds it at all**. A fuzz
target that does not compile has not run, so "a fuzz target exists and has run clean" was a
claim about a file rather than about an execution. Rebuild the targets when you change any
decoder they touch:

```bash
cd fuzz && rustup run nightly-2025-12-04 cargo fuzz build coap_message
```

(`cargo +nightly fuzz` does not work on this machine — asdf's shims sit ahead of
`~/.cargo/bin` on `PATH`, so `cargo` is not the rustup proxy and `+toolchain` is read as a
subcommand name. `rustup run <toolchain> cargo fuzz …` is the form that works.)

The corpus has **no depth bomb**, and that is deliberate rather than a gap: `CoapMessage::decode`
is a `while` loop and `read_extended` does not recurse, so there is no nesting class for one to
reach. The equivalent blind spot is the option delta/length *extension* encodings — where every
length a peer can state lives — and `option_delta_ext13` / `option_delta_ext14` seed those. The
condition's letter is inapplicable; its reason is satisfied.

### What Stable does *not* mean here

It means the evidence for the surface this server implements is complete. The surface is
RFC 7252 with Observe (RFC 7641) and Block-wise transfer (RFC 7959), and without DTLS/CoAPS,
separate responses or a deduplication cache.

**Observe and Block-wise were added in October 2026 and carry the six conditions on their own
surface**, not the original evidence stretched over them:

| # | condition | for Observe and Block-wise |
|---|---|---|
| 1 | two independent clients | libcoap's `coap-client` and **aiocoap** 0.4 (Python, its own codec and state machines) each observe and receive `coap_notify` pushes, reassemble a 3000-byte Block2 representation byte for byte, and upload 3000 bytes as Block1 — `observe_blockwise_test.rs`, neither able to skip |
| 2 | pcap oracle | every exchange in `observe_blockwise_bounds_test.rs` — Observe, Block1, Block2, Size1, Size2, ETag, 2.31, 4.08, 4.13, RST — is read by tshark's dissector |
| 3 | fuzz target | `coap_message.rs` reads Observe, Block1 and Block2 from every decoded message and requires a parsed Block value to survive its own encoder; the corpus seeds a registration, a Block1 PUT, a Block2 GET and the reserved SZX 7 |
| 4 | every bound tested | `MAX_OBSERVERS`, `MAX_UPLOADS`, `MAX_TRANSFERS`, `MAX_REPRESENTATION_LEN` both directions, Block1 order and size, Block2 past the end, RST removal, `NOTIFICATION_MAX_RETRANSMIT` — `observe_blockwise_bounds_test.rs`; the cache, the upload cap and the registration's Observe option were each removed and the tests failed |
| 5 | both `AGENTS.md` re-verified | this file and `tests/server/coap/AGENTS.md`, rewritten with the code |
| 6 | no `#[ignore]`, no skip gate | unchanged |

The `openvpn` precedent is the one to check this against, and it does not apply: openvpn stays
Experimental because it implements only the front of the protocol, so *no client can use it for
what the protocol is for*. A CoAP client can use this for what CoAP is for — libcoap did, in
both directions, with the bytes asserted.

## NetGet's CoAP client shares `codec.rs`

`src/client/coap/` encodes and decodes with this module's `CoapMessage`, and since October 2026
with its option numbers and `BlockValue` too. The client also implements what this server does
not — Confirmable retransmission, separate responses and deduplication. Its evidence is
libcoap's `coap-server` and aiocoap, never this server; see `tests/client/coap/AGENTS.md`.

## References

- [RFC 7252: The Constrained Application Protocol (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252)
- [RFC 7641: Observing Resources in CoAP](https://datatracker.ietf.org/doc/html/rfc7641)
- [RFC 7959: Block-Wise Transfers in CoAP](https://datatracker.ietf.org/doc/html/rfc7959)
- [coap-lite](https://docs.rs/coap-lite) / [coap](https://docs.rs/coap) / [aiocoap](https://aiocoap.readthedocs.io) — the test peers, not runtime dependencies
