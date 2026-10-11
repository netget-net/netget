# CoAP client

NetGet sends CoAP (RFC 7252) requests over UDP and the model decides what to ask. What the
model never sees is the transport: message ids, tokens, retransmission, acknowledgements,
Block2 continuations and Observe bookkeeping all happen in Rust.

## Codec: the server's, shared

Encoding and decoding are `src/server/coap/codec.rs` (`CoapMessage::encode` / `decode`, the
option constants, `content_format_id` / `content_format_name`, `MAX_MESSAGE_LEN`,
`MAX_REPRESENTATION_LEN`, `BlockValue`). The option numbers and the Block value layout lived in
this module while the server implemented neither Observe nor Block-wise; since October 2026 the
server does, and they are the codec's, re-exported here (`OPT_OBSERVE`, `OPT_BLOCK1`,
`OPT_BLOCK2`, `OPT_SIZE1`, `OPT_SIZE2`).
The peer that makes the evidence count is libcoap, a C implementation — not this codec and not
the `coap` / `coap-lite` crates, which are dev-dependencies used as independent peers in the
*server's* tests.

## Tasks

| task | owns | never waits on |
|---|---|---|
| transport | the connected UDP socket, every exchange: message ids, tokens, retransmission timers, Block1 uploads, Block2 reassembly, observations | the model |
| turns | the model calls, one queued event at a time | the socket |
| commands | injected actions (`[ send ]`, MCP `send_to_client`) | the model |

The socket is `connect`ed to the server, so the kernel delivers only the server's datagrams.
The chain request → response → model → request passes through the turn queue, so it needs no
recursion and no `MAX_FOLLOWUP_DEPTH`.

## Reliability (RFC 7252 §4)

- A Confirmable request is retransmitted with the same message id after a random interval in
  `[ACK_TIMEOUT, 1.5 × ACK_TIMEOUT]`, doubling, at most `MAX_RETRANSMIT` times; then the model
  gets `coap_error {kind: timeout}`. Both are startup parameters (`ack_timeout_ms`, default
  2000, 10-60000; `max_retransmit`, default 4, at most 8), declared with their defaults from
  `DEFAULT_ACK_TIMEOUT_MS` / `DEFAULT_MAX_RETRANSMIT`.
- An empty ACK means a separate response is coming: the exchange then waits
  `RESPONSE_TIMEOUT` (30s). A Non-confirmable request waits the same.
- A Confirmable response or notification is acknowledged with an empty ACK — every copy of it,
  since the server resends when an ACK is lost — and a repeated message id (the last 64 are
  remembered) is not shown to the model twice.
- A response or notification carrying a token no exchange owns (a notification after a
  cancellation, an answer to a forgotten request) is answered with RST, as are requests and CoAP
  pings from the server.
- RST from the server ends the exchange: `coap_error {kind: reset}`.

## Observe (RFC 7641)

`coap_observe` sends GET with Observe 0. A response carrying Observe confirms the registration:
`coap_response {observing: true}` and the exchange stays open with no deadline; every later
message on that token is a `coap_notification {sequence}`. A response without Observe means the
resource is not observable: `coap_response {observing: false}` and the exchange closes.
`coap_observe_cancel` sends GET with Observe 1 on the **same token**; notifications still in
flight are ignored, and the cancellation's own response arrives as `coap_response
{observing: false}`. Cancelling a path with no observation is `coap_error {kind:
not_observing}`. A notification whose Block2 says "more" is reported with `truncated: true`
rather than fetched.

## Block2 (RFC 7959)

A response with Block2 M=1 is continued by the transport with the next block number and the
server's block size, on the same token, without Observe (§2.6). Blocks must arrive in order
(`bad_block` otherwise) and the body is capped at `MAX_BODY` (64 KiB, `body_too_large`
otherwise). The model sees **one** `coap_response` with the whole body and `blocks: N`.


## Block1 (RFC 7959 §2.3)

A request body over `block_size` (startup parameter, default `DEFAULT_BLOCK_SIZE` 1024, a power
of two from 16) goes out as Block1 blocks; block 0 carries Size1 with the whole length. Each 2.31
Continue whose Block1 echoes the block on the wire sends the next one; a smaller SZX in that echo
is adopted, and the next block is numbered from the bytes already acknowledged at the new size.
The answer to the last block — or any non-2.31 part way, such as 4.13 or 4.08 — ends the upload
and reaches the model as one `coap_response` with `blocks_sent`. A 2.31 echoing a different
block number, or asking for more after the last block, is `coap_error {kind: bad_block}`. The
body is capped at `MAX_REPRESENTATION_LEN` (64 KiB), refused before the wire.

## Events

`coap_connected {remote_addr}` (the connect event; UDP has no handshake, nothing is sent),
`coap_response`, `coap_notification`, `coap_error {kind, message, method, path}`. Responses and
notifications carry `method`, `path`, `code` (`2.05`), `status` (`Content`), `content_format`,
`payload` (text; absent when empty or not UTF-8 — never re-encoded), `payload_json` (when the
format is `application/json` and it parses), `payload_size`, and `options` (`max_age`, `etag`
as hex, `location_path`, `observe`, `size2`).

## Actions

`coap_get` / `coap_delete` / `coap_observe` `{path, query?, accept?, confirmable?}`,
`coap_post` / `coap_put` `{path, query?, payload, content_format?, confirmable?}` (a string is
sent as text/plain, an object or array as JSON), `coap_observe_cancel {path}`, `disconnect`.
Refused before the wire: a Uri-Path segment or Uri-Query item over 255 bytes, a payload over
64 KiB, an unknown media type, a non-boolean `confirmable`.

## Bounds

| bound | value | test (`tests/client/coap/`) |
|---|---|---|
| inbound datagram | 1152 bytes (`MAX_MESSAGE_LEN`); a larger one is dropped unread, `decision=oversize` | `transport_test::an_oversize_datagram_is_dropped` |
| retransmissions | `max_retransmit` (default 4) | `transport_test::an_unanswered_confirmable_request_…` |
| reassembled body | 64 KiB (`MAX_BODY`) | `transport_test::a_block2_transfer_that_never_ends_is_cut_off` |
| block order | the expected number only | `transport_test::an_out_of_order_block_is_refused` |
| open exchanges | 32 (`MAX_EXCHANGES`), observations included | `transport_test::requests_past_the_exchange_cap_are_refused` |
| request body | 64 KiB (`MAX_REPRESENTATION_LEN`), refused before the wire | `request_test::what_cannot_be_sent_is_refused` (at the limit and one over), `real_server_test::injected_coap_put_reaches_libcoap` |
| Block1 block size | `block_size`, power of two 16-1024; a server's smaller SZX adopted | `blockwise_upload_test::the_client_continues_at_the_smaller_block_size_…` |
| events waiting for the model | 256, `decision=turn_queue_full` past that | — |

CoAP has no nesting, so there is no depth to bound.

## Logging

`decision=model_actions` / `model_silent` / `llm_error` per model turn; `decision=timeout`,
`oversize`, `undecodable`, `body_too_large`, `turn_queue_full` from the transport.

## Limitations

No DTLS (`coaps`), no CoAP over TCP or WebSocket, no multicast, no reordering check on
notification sequence numbers (they are reported, not compared). A notification over one block
is reported `truncated: true` rather than fetched.

## Maturity: Beta

All four conditions of the client bar hold, on `tests/client/coap/real_server_test.rs`:

1. the peer is libcoap's `coap-server` (C), and libcoap's `coap-client` writes and reads back —
   nothing this client is built on;
2. a missing `coap-server` or `coap-client` fails the test, never skips it;
3. a real session: a Block2 GET, a PUT, and an Observe registration, notifications and
   cancellation, all answered by the server;
4. the client acts on the model's answer, asserted from the server's side by `coap-client` —
   and emptying the loop over `result.actions` fails it.

Passed three consecutive runs at `--test-threads=100` before promotion, against libcoap 4.3.5.
