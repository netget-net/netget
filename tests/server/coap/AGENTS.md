# CoAP E2E Tests

## Strategy

**Three** peers, none of which shares a line of code with `src/server/coap/codec.rs` (which is
hand-rolled precisely so this is true). This section said "two" and described only the Rust
crates for as long as `real_client_test.rs` has existed, which had the effect of omitting the
one peer that is a different language and a different project:

1. **libcoap 4.3.5's `coap-client`** — a C implementation, run as a subprocess and never
   linked. `real_client_test.rs`; see "The binary peer" below. It is the peer that makes the
   two Rust crates a cross-check rather than the whole case.

2. **`coap` 0.27 (`UdpCoAPClient`)** — a real CoAP client. It does its own CON/ACK matching, so
   a wrong message id or a dropped token shows up as a *timeout*, not as a passing test. It is
   used for the resource-layer assertions: 2.05 Content with a JSON body, 2.04 Changed after a
   POST, 4.04 Not Found, and the Content-Format option.

3. **`coap-lite` 0.13** — an independent codec, used directly over a raw `UdpSocket` to build
   requests with a *chosen* token and message id and to decode the replies field by field. This
   is where the message layer is pinned: ACK type, message-id echo, 8-byte token echo, NON
   answered by NON with a fresh message id, and the RST reply to a CoAP ping. `coap` 0.27 is
   built on it, so these two are one implementation family and count as **one** independent
   peer for the Beta/Stable bar, not two.

4. **aiocoap 0.4** (Python) — for Observe and Block-wise only, `peer/aiocoap_peer.py`. Its own
   codec, its own observation and block-wise state machines; shares nothing with libcoap or
   coap-lite. The container this was written in has no IPv6 at all, and aiocoap's default
   transports open AF_INET6 sockets, so the script selects `simple6` (client) and
   `simplesocketserver` (server), which take the family from the address.

### Observe and Block-wise (October 2026)

`observe_blockwise_test.rs` drives libcoap's `coap-client` and aiocoap through the same three
things — observe `/temp` and receive the two notifications a script handler pushes with
`coap_notify` when another request PUTs, GET a 3000-byte `/big` as Block2 and reassemble it,
PUT 3000 bytes as Block1 — and asserts from the server's side that `/big` was asked **once**
and the upload reached the handler **once, whole**, with its block count. libcoap does it twice
for Block2, once at its default size and once with `-b 64` (47 blocks).

`observe_blockwise_bounds_test.rs` holds every new bound at its edge over a raw socket with
coap-lite (Block values packed by hand from RFC 7959 §2.2, not with the server's encoder), and
hands every exchange to the pcap oracle. See the table in its header.

Both run **in-process with no model**: `observe_support.rs` starts the server through
`ServerForm` with a script handler playing a device, so every count is exact and no mock is
involved. The handler issues `coap_notify` from a PUT, which is the sync path; the bounds tests
also call `CoapServerHandle::notify` directly to control the code and message type.

Plus **the pcap oracle** (`tests/helpers/pcap_oracle.rs`) on every datagram `e2e_test::exchange`
and `llm_failure_test::exchange` send or receive — Wireshark's own CoAP dissector as a third, unrelated reading of RFC 7252.
CoAP's option encoding is delta-and-length nibbles with extension bytes, so an option that runs
past the end of a datagram is a silent off-by-one in any codec that trusts its own writer, and
that is the class the oracle catches ("option longer than the package").

Plus codec assertions against literal RFC bytes: the four header bits
(`0x40 0x01 0x00 0x01` is Ver=1/CON/TKL=0/GET/MID=1), the code arithmetic (2.05 = 0x45,
4.04 = 0x84), and an option round trip that exercises **both** delta extension forms — nibble
13 (one extra byte) and nibble 14 (two extra bytes) — with coap-lite asked to confirm it can
read what we wrote.

**Nothing here asserts that a datagram arrived.** Every assertion is on a decoded response code,
option, token or payload — or, in `bounds_test.rs`, on a count of model calls, which is the same
rule applied to cost rather than to bytes.

## LLM call budget

| Test | Startup | Events | Total |
|---|---|---|---|
| `e2e_test::test_coap_get_post_and_not_found_with_coap_client` | 1 | 3 | **4** |
| `e2e_test::test_coap_message_layer_echo_and_ping` | 1 | 2 | **3** |
| `e2e_test::test_codec_*`, `test_oversize_payload_*` (three tests) | 0 | 0 | **0** |
| `real_client_test::…_against_libcoap_client` | 1 | ≥3 | **≥4** |
| `bounds_test::test_inbound_message_bound_…` | 1 | 1 | **2** |
| `bounds_test::test_reserved_token_length_…` | 1 | 0 | **1** |
| `bounds_test::test_encode_…`, `test_message_prefix_…` | 0 | 0 | **0** |
| `llm_failure_test::…_says_which_path_it_took` | 1 | 2 (one answered 500) | **3** |
| `answer_with_test::*` (two tests) | 0 | 0 | **0** |
| `observe_blockwise_test::*`, `observe_blockwise_bounds_test::*` (thirteen tests) | 0 | 0 (script handler) | **0** |

**Total: 17** across six files, for 13 tests. This table used to read "Total: 7" and list only
`e2e_test.rs`, which was true when that was the whole suite — derive it rather than reading it,
because it goes stale the moment a file is added. The libcoap test uses `expect_at_least` rather
than `expect_calls` because libcoap retransmits a CON whose ACK is slow and this server has no
deduplication cache, so its event count is a floor.

The two zeros in `bounds_test` are the assertion, not an economy: a CoAP ping and an oversize
or malformed datagram must all be answered without consulting the model, and both tests read
the model-call count off the mock to say so.

## The UDP rule, and how it applies here

`AGENTS.md` requires UDP-style protocols to use `.respond_with_actions_from_event()` so the
client's random transaction id is echoed dynamically — a static mock with a hardcoded id causes
client timeouts, and the usual "fix" is to weaken the assertion until it passes.

**Every rule that answers a request dynamically uses `respond_with_actions_from_event()`.** But
the thing being derived is the **request path and query**, not the message id — because this
server does not make the model handle the message id at all. `codec::response_to` takes the
type, message id and token from the request the server itself parsed; no action parameter
carries any of them. See decision 2 in `src/server/coap/AGENTS.md` for why.

(This line said "every rule in these tests", which stopped being true with `llm_failure_test.rs`
and the 4.04 rule in `e2e_test.rs`: a rule whose answer carries nothing derived from the request
— a bare 4.04, a `show_message` — is correctly static. The rule is about what the answer needs,
not about which file it is in.)

That removes the hazard the rule exists to prevent (a static mock *cannot* desynchronise an
identifier here) but it also removes the natural assertion, so the echo is pinned explicitly
instead: `test_coap_message_layer_echo_and_ping` builds a request with message id `0x4711` and
token `DE AD BE EF 01 02 03 04` using coap-lite, and asserts both come back byte for byte in an
`Acknowledgement`. A regression that broke the echo would fail that test loudly, and would also
hang the `coap` client in the first test.

## Mock expectations

Four rules in the first `e2e_test` (startup plus one per path), two in the second (startup plus
one rule matched twice, once by the CON request and once by the NON one). `bounds_test`'s two
socket-driven tests carry two rules and one rule respectively, and both additionally read
`server.llm_call_count()` — `verify_mocks` asserts against *rule* expectations, so it catches a
second call that matched a rule and not one that reached the model by some other route.

The response generators echo the request's own view of itself — `"{path}?{query} via {mtype}"` —
so the assertion `"/status?verbose=1 via CON"` can only hold if the Uri-Path options, the
Uri-Query option and the message type all decoded correctly and reached the model. A literal
payload would pass just as well against a correct server and would keep passing after a
regression in option parsing.

Every test with a mock ends with `server.verify_mocks().await?`; the four pure-codec tests have
no mock and no server.

## Client libraries

Two crates, both **unconditional** dev-dependencies — neither is `optional = true`, so the
evidence compiles wherever the suite does:

- `coap-lite = "0.13"` — MIT OR Apache-2.0, codec only.
- `coap = "0.27"` — MIT, full UDP client (built on coap-lite).

The third peer is not a dependency at all: libcoap's `coap-client` is a binary that has to be
on `PATH`, and `real_client_test.rs` **fails** rather than skipping when it is not. That is a
standing requirement on any machine the suite runs on, by design.

`UdpCoAPClient::get_with_timeout` / `post_with_timeout` are used rather than the untimed
variants so a broken server fails the test in ten seconds instead of hanging it.

## What is covered

- GET → 2.05 Content with an `application/json` Content-Format, payload intact
- POST with a body → 2.04 Changed; the request body reaches the model and returns in the answer
- GET of an absent resource → 4.04 Not Found, and it does **not** acquire a payload. Its mock
  rule also requires the event's `answer_with` to name the path, so it only matches when the
  per-request hint reached the model
- The `answer_with` sentence itself (`answer_with_test.rs`): the lookup first, the 4.04 as a
  literal action, each method's success code. The wording is measured by the real-model eval
  (`src/server/coap/AGENTS.md`, "Why `answer_with` exists"), not by these tests — they pin it
  so a rewording has to be a decision
- CON → piggybacked ACK carrying the request's message id and full 8-byte token
- NON → NON reply with a *different* message id and the same token
- Uri-Path and Uri-Query options decoded and surfaced to the model
- Content-Format encoded as a minimum-length unsigned option and decoded by coap-lite
- Empty CON (CoAP ping) → RST with the ping's message id, with no LLM call
- Header bit layout, code arithmetic, `parse_code_string` including the `"2.05 Content"` form
- Option delta extension forms 13 and 14, round-tripped and confirmed by coap-lite
- Rejection of a short datagram, a wrong version, and a reserved token length
- **Every declared bound** (`bounds_test.rs`), each verified by removing it and watching the
  test fail — see the next section
- **Both 5.03 fail-closed paths** (`llm_failure_test.rs`): a backend that fails and a model
  answer made only of common actions. Asserted as a *matchable* refusal — ACK, the request's
  message id, the request's token — and on the log distinguishing
  `decision=fail_closed_llm_error` from `decision=fail_closed_no_action`, since the peer gets
  the same five bytes either way

## Bounds (`bounds_test.rs`)

| bound | value | where it is declared | how it is driven |
|---|---|---|---|
| `MAX_MESSAGE_LEN` / `max_inbound_bytes` | 1152 | `codec.rs`, `actions.rs::metadata` | a socket: 1152 served, 1153 refused 4.13, model-call count asserted |
| `MAX_TOKEN_LEN` (decode) | 8 | `codec.rs` | a socket: TKL=9 → RST for a CON, silence for a NON, zero model calls |
| `MAX_TOKEN_LEN` (encode) | 8 | `codec.rs` | `encode()` directly — unreachable from the wire today, which is itself pinned |
| `MAX_OPTION_LEN` (encode) | 65535 | `codec.rs` | `encode()` directly |
| `MAX_REPRESENTATION_LEN` (outbound) | 65536 | `codec.rs`, enforced in `actions.rs::decode_payload` | `e2e_test::test_oversize_payload_is_refused_rather_than_silently_dropped` (it was `MAX_PAYLOAD_LEN`, 1024, until Block2 existed) |
| receive buffer | 2048 | `mod.rs` | implicitly, by the 1153-byte probe arriving intact |

The Observe and Block-wise bounds — `MAX_OBSERVERS`, `MAX_UPLOADS`, `MAX_TRANSFERS`,
`MAX_REPRESENTATION_LEN` inbound, Block1 order and size, Block2 past the end, RST removal,
`NOTIFICATION_MAX_RETRANSMIT` — are in `observe_blockwise_bounds_test.rs`, tabulated in its
header. Three were checked by removal: with the Block2 cache never storing, four tests fail
(the handler is asked once per block); with the upload cap or the registration's Observe
option removed, eight do.

Each has an **at-limit** half as well as an over-limit half, because a guard that refused
everything would satisfy the over-limit assertion for the wrong reason. Each doc comment
records what the failure looked like with the bound removed; the tkl one is worth reading,
because the observed failure is a *timeout* rather than a wrong reply — the encode-side guard
catches what the decode-side guard stopped catching, and the server writes nothing at all.

## Coverage gaps

- ~~**No external binary peer.**~~ Closed September 2026: `real_client_test.rs` drives
  libcoap 4.3.5's own `coap-client`, a C implementation — see below. aiocoap is now a fourth,
  for Observe and Block-wise.
- ~~**Observe and Block-wise are not implemented and not tested.**~~ Both implemented and
  driven by two clients in October 2026, above. DTLS/CoAPS is still neither.
- A CON notification that is never acknowledged is tested; one that is acknowledged only after
  a retransmission is not.
- No test for `send_coap_reset` or `ignore_coap_request` as *model* choices — the RST path is
  covered only via the ping, which the server answers itself.
- No test for a retransmitted CON (there is no deduplication cache; a retransmission would
  produce a second LLM call).
- ~~No test for the `"encoding": "hex"` payload path.~~ **That was false** — it was never true
  of `test_oversize_payload_is_refused_rather_than_silently_dropped`, which drives
  `{"encoding": "hex"}` twice, at the limit and one byte over, specifically to prove the bound
  counts *decoded* bytes so a hex payload does not get twice the budget. Worth noting as a
  gap-list failure mode: a gap entry is only as current as the last person who re-read the
  tests, and an entry claiming something is untested is the kind nobody re-checks.
- ~~No test of the 5.03 fail-closed path (LLM error / no usable action).~~ **Closed** by
  `llm_failure_test.rs`, which drives both paths and asserts the `decision=` tags apart. It was
  a real gap while it stood: `src/server/coap/AGENTS.md` carried a seven-row decision table
  that nothing checked.
- **No test for the model choosing 5.03 itself**, which is the third occupant of that code and
  the reason the log tags exist at all. A test would be cheap and would make the table's whole
  premise — three causes, one wire representation — visible in one place.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features coap \
    --test server -- --test-threads=100 coap
```

About twelve seconds for all 26 tests at `--test-threads=8`, measured 11 October 2026 — the
retransmission test alone waits ~3.5 s for four resends at a 100 ms ACK timeout. Everything is
loopback UDP and an in-process mock or script, except `real_client_test.rs` and
`observe_blockwise_test.rs`, which spawn `coap-client` and aiocoap.
`observe_blockwise_test.rs` needs `NETGET_AIOCOAP_PYTHON` pointing at a python with
aiocoap 0.4.12 installed.

## Failure modes seen so far

None across repeated runs. The realistic future flake is the `coap` client's own retransmission
timer firing on a loaded machine while an LLM call is in flight — this server only sends
piggybacked responses, so a slow answer looks like a lost ACK. With mocked LLM calls the answer
is immediate, so it does not arise here; with `--use-ollama` it could.

## The binary peer: libcoap's `coap-client`

`real_client_test.rs::test_coap_get_post_and_not_found_against_libcoap_client` drives
libcoap 4.3.5's `coap-client` — C, by a different project, sharing nothing with this server's
hand-rolled codec or with `coap-lite`. It is **not** `#[ignore]`d and it **fails** rather than
skipping when libcoap is absent.

Three exchanges, each asserted on what libcoap parsed and printed:

| request | answer | asserted |
|---|---|---|
| `GET /sensors/moisture` | 2.05 Content, `application/json` | the exact body, printed on stdout |
| `POST /actuators/valve` with `-e open` | 2.04 Changed | `valve=open` — so the request payload reached the model *and* the response payload came back |
| `GET /nope` | 4.04 Not Found | libcoap reports `4.04`, and the body is asserted **not** to be the moisture representation |

libcoap prints a payload only after accepting version, type, token length, code, message id,
option deltas and the payload marker, and only when the token and message id match the request
it sent. That is what a raw-socket assertion cannot reach.

Two things about driving it:

- **Every invocation passes `-B`,** which bounds libcoap's own retransmission window. The
  server has no deduplication cache, so a retransmitted CON produces a *second* event and a
  second handler call; the mock rules use `expect_at_least` rather than `expect_calls` for
  exactly that reason, and under a loaded runner that is not hypothetical.
- **The 4.04 case is what keeps the other two honest.** Without a negative path, a server that
  answered 2.05 to every request would satisfy both positive assertions.
