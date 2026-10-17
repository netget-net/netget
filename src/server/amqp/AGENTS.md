# AMQP 0-9-1 Broker Implementation

AMQP 0-9-1 (the RabbitMQ wire protocol) broker. Frames and methods are encoded and
decoded by hand in `codec.rs`; the LLM (or a script / static handler) decides whether a
connection is accepted, what a queue declaration reports, whether a consumer is
registered, and **every message a consumer receives**.

**State**: **Beta**, which is what `actions.rs` declares. This line used to say
"Experimental — LLM-authored, not human-reviewed", contradicting the code with no way to tell
which was current; the evidence supports Beta and the code was right.

The evidence: `test_amqp_publish_is_delivered_to_consumer` drives `lapin`, a genuinely
independent client — it parses the wire with the generated `amq-protocol` parsers, and this
broker is hand-written, so it is not the circular case `websocket`/`webrtc_signaling` are. The
test is not `#[ignore]`d and cannot silently skip. It covers handshake, channel open, queue
declare, consume, publish, and a delivery whose body is asserted out of lapin's own consumer
stream (`tests/server/amqp/e2e_test.rs`).

Not Stable: `lapin` is not an unconditional dev-dependency (`amqp = ["dep:lapin"]`), so the
blocking CI job — six protocols, none of them this one — never runs it. The evidence exists and
is real, but it rests on a locally-run test.
**Port**: 5672 by default. **Privilege**: `None` (5672 > 1024).
**Stack**: `ETH>IP>TCP>AMQP`. **Spec**: AMQP 0-9-1 (the RabbitMQ dialect).

This replaces a stub that was `DevelopmentState::Incomplete` for good reason: it declared
zero actions and zero events, never called the LLM at all, and answered the protocol
header with a `Connection.Start` frame whose declared payload length (20) did not match
the 31 bytes it wrote — so no conforming client ever got past the first frame.

## Why not lapin

The `amqp` Cargo feature declares `lapin`, and it must stay: **`src/client/amqp` uses it**
(`lapin::Connection::connect`), and the E2E tests use it as the driving client. But
`lapin` is an AMQP *client* library. It parses and generates the same frames, yet every
type is wired into a client-side connection state machine — `ConnectionStatus`,
`ConnectionStep::ProtocolHeader`, `Reply::QueueDeclareOk` resolvers — with no seam where a
broker could answer a method. It could never have implemented this server, which is why
`lapin` appeared exactly once in the old `src/server/amqp/`, inside a doc comment.

The subset below is roughly 400 lines of codec. Hand-writing it also keeps every byte
inspectable, which matters for a protocol whose whole attack surface is length prefixes.

## Implemented subset

Everything here is exercised by a real `lapin` client. Anything not in this list is
answered with `Channel.Close` 540 NOT_IMPLEMENTED (or `Connection.Close` 540 on channel 0)
rather than being silently ignored, so a client gets an error instead of a hang.

| Phase | Methods |
|---|---|
| Handshake | protocol header `AMQP\0\0\x09\x01`, `Connection.Start`/`Start-Ok`, `Tune`/`Tune-Ok`, `Open`/`Open-Ok` |
| Teardown | `Connection.Close`/`Close-Ok` in both directions, `Channel.Close`/`Close-Ok` |
| Channels | `Channel.Open`/`Open-Ok` |
| Topology | `Exchange.Declare`, `Queue.Declare`/`Declare-Ok`, `Queue.Bind`/`Bind-Ok` |
| Messaging | `Basic.Qos`/`Qos-Ok`, `Basic.Consume`/`Consume-Ok`, `Basic.Cancel`/`Cancel-Ok`, `Basic.Publish` + content header + body frames, `Basic.Deliver` + content, `Basic.Return` + content, `Basic.Ack`/`Nack`/`Reject` (logged only) |
| Keepalive | heartbeat frames sent at half the negotiated interval; a peer silent for two intervals is disconnected, or for `IDLE_READ_TIMEOUT_SECS` where it negotiated heartbeating off. Answered in Rust before any dispatch, so a heartbeat can never cost a model call or park in a manual handler |

Also implemented: the field-table codec (RabbitMQ type ids, so `s` is a signed 16-bit
integer and `l`/`L` are both signed 64-bit), the Basic property list with its 16-bit flag
word and continuation words, and SASL PLAIN response splitting.

**Not implemented**: TLS (5671), SASL beyond PLAIN, publisher confirms (`Confirm.Select`),
transactions (the `Tx` class), `Basic.Get`, `Queue.Purge`/`Delete`/`Unbind`,
`Exchange.Delete`/`Bind`/`Unbind`, `Connection.Secure`/`Blocked`, AMQP 1.0, prefetch
enforcement (`Basic.Qos` is acknowledged and then ignored), and consumer cancel
notification.

## What the model sees

| Event | Fires when | Must be answered with |
|---|---|---|
| `amqp_connection_open` | handshake finished, client asked for a vhost | `amqp_connection_open_ok` or `amqp_connection_close` |
| `amqp_queue_declare` | `Queue.Declare` without no-wait | `amqp_queue_declare_ok` (or `amqp_channel_close` to refuse) |
| `amqp_basic_consume` | `Basic.Consume` without no-wait | `amqp_basic_consume_ok` (or `amqp_channel_close`) |
| `amqp_basic_publish` | publish method **and** its full content arrived | nothing is owed; `amqp_basic_deliver` is how the message reaches anyone |

Four events for a whole session is deliberate. `Channel.Open`, `Exchange.Declare`,
`Queue.Bind`, `Basic.Qos`, `Basic.Cancel`, client-initiated `Connection.Close` and
heartbeats are answered by the broker without a model call, because none of them has a
decision in it — the broker keeps no exchange or binding table, so there is nothing for a
model to decide about a binding. `Basic.Ack`/`Nack`/`Reject` are logged and dropped for
the same reason: there is no stored message to acknowledge or requeue.

### Correlation identifiers

AMQP correlates by **channel number** and by **consumer tag**, and both must be echoed.

- Every event carries `channel`. Every action defaults to the channel of the method it is
  answering, so a handler normally never sets it. `{{event.channel}}` is available for the
  rare case that it must.
- `amqp_basic_consume` carries the `consumer_tag`, already generated as
  `amq.ctag-<connection>-<n>` when the client sent an empty one. `amqp_basic_consume_ok`
  must echo it, and every later `amqp_basic_deliver` addresses the consumer by it.
- `amqp_queue_declare_ok` echoes the queue name; a client that declared with an empty name
  expects the broker to invent one.
- `delivery_tag` on `amqp_basic_deliver` is optional: omitted, the broker allocates the
  next unused number for that consumer, which is what you want unless you are deliberately
  reusing one.

### Bodies are text, never bytes

`amqp_basic_publish` reports `body` as UTF-8 text. When the bytes are not valid UTF-8,
`body_is_text` is false, `body` holds a lossy rendering and `body_size` gives the true byte
count. `amqp_basic_deliver` takes `body` as text and sends it as UTF-8. Nothing hex or
base64 encoded appears in any event or action.

Message properties travel as a JSON object (`properties` inbound, individual named
parameters outbound), and headers as a flat JSON object — the field-table codec converts
in both directions. Exotic field-table types (decimals, arrays, nested tables) decode to
their nearest JSON shape and re-encode as strings/numbers/booleans, so a decode → encode
round trip is lossy for those.

## Actions

**Sync** (in response to a client method):

| Action | Parameters |
|---|---|
| `amqp_connection_open_ok` | — |
| `amqp_connection_close` | `reply_code` (default 403), `reply_text` |
| `amqp_channel_close` | `reply_code` (default 404), `reply_text`, `channel` |
| `amqp_queue_declare_ok` | `queue`, `message_count`, `consumer_count`, `channel` |
| `amqp_basic_consume_ok` | `consumer_tag`, `queue`, `channel` |
| `amqp_basic_deliver` | `consumer_tag`, `body`, `routing_key`, `exchange`, `delivery_tag`, `redelivered`, `content_type`, `headers`, `correlation_id`, `reply_to` |
| `amqp_basic_return` | `reply_code` (default 312), `reply_text`, `routing_key`, `exchange`, `body`, `content_type`, `channel` |

**Async** (user-triggered, no connection context):

| Action | Parameters |
|---|---|
| `amqp_deliver_to_consumer` | `server_id` plus the `amqp_basic_deliver` parameters |
| `list_amqp_consumers` | `server_id` |

Every declared parameter is read by `execute_action`, and there are no dead parameters. There
is one undeclared executor branch, `close_connection`, which the "Custom-result note" below
explains; the sentence here used to claim there were none.

## Routing: the model does it, not the broker

**There is no queue, no exchange table, no binding table and no message store.** After a
client publishes, nothing is delivered automatically. `amqp_basic_publish` carries
`active_consumers` — every consumer currently attached to this server, with the queue it
subscribed to — and the handler issues `amqp_basic_deliver` for each recipient it chooses.

The only cross-request state the broker keeps is `AMQP_CONSUMERS` in `actions.rs`: a
directory of **live sockets**, keyed by `(server id, consumer tag)`, holding the writer
channel, the channel number a delivery must carry, the queue name and a delivery-tag
counter. It exists because `Basic.Deliver` has to be written on the *consumer's* channel
of the *consumer's* connection, which may not be the connection the publish arrived on —
there is no way to deliver at all without it. Entries are removed when the consumer is
cancelled, when its channel closes and when its connection ends; nothing survives a
disconnect, and no message is ever held.

## Dashboard injection (peer handle + counters)

Every connection registers a peer handle (`server::peer_support`) right after it is
tracked and before the first read, so `[ message this peer ]` / `[ disconnect this peer ]`
work even while a manual rule parks `connection.open`; the handle is removed on every exit
of `handle_connection`. Inbound bytes/packets are counted per frame (and for the protocol
header) in `Session::read_next_frame`; outbound ones in the writer task, which every frame
passes through — including cross-connection deliveries and injected actions.

**Custom-result note**: every AMQP wire action (`amqp_connection_close`,
`amqp_basic_deliver`, …) writes its frames through the connection's `out_tx` itself and
returns `ActionResult::Custom`, never `Output`. An injected action therefore *does* reach
the socket, but `send_to_peer` reports it as `Executed { detail }` rather than
`Sent { bytes_sent }`. Injected actions default `channel` to whatever method the handler
chain last answered (usually 0) — pass `channel` explicitly. `close_connection` half-closes
the shared write half and is the one thing that touches it outside the writer task.
`tests/server/amqp/peer_inject_test.rs` covers this with zero LLM calls.

## Batching (on by default, publishes only)

`Basic.Publish` owes nothing on the wire outside confirm mode, so completed publishes on one
channel that are already waiting behind the one being answered are handed to the model in one
call (`collect_publishes` / `flush_publishes` in `mod.rs`). The read half is buffered
(`READ_BUFFER_BYTES`) so collection can see whole frames without waiting; it takes only
`Basic.Publish` methods, content headers and body frames on that channel, and heartbeats, and
stops at anything else — every synchronous method (`Queue.Declare`, `Basic.Consume`, the
handshake) owes its own `-Ok` and is never batched. A publish whose content is still arriving
stays pending on its channel. Publishes before a frame that breaks the protocol are answered
before the connection exception. `tests/server/amqp/batching_test.rs` drives it with `lapin`
against a batching-off control and asserts the deliveries arrive in order.

## Failure behaviour

| Event | If the handler produces no usable action | Rationale |
|---|---|---|
| `amqp_connection_open` | **refused**: `Connection.Close` 403 "ACCESS_REFUSED - the broker's handler made no decision about this connection", logged at WARN | this is the broker's only authorisation decision, and a fail-open default would let an LLM outage silently admit every client |
| `amqp_queue_declare` | `Queue.Declare-Ok` reporting an empty queue, logged at WARN | mandatory reply, and no security decision is involved; the client would otherwise block forever |
| `amqp_basic_consume` | `Basic.Consume-Ok` with the requested tag, consumer registered, logged at WARN | mandatory reply |
| `amqp_basic_publish` | nothing; the message is dropped | outside confirm mode the spec owes the publisher no reply |

The refusal a handler asks for and the refusal caused by silence are textually distinct
(`reply_text` is the handler's own, versus "made no decision"), so an explicit denial can
never be confused with an outage. `tests/server/amqp/e2e_test.rs` asserts both paths.

"Produces no usable action" is checked per **response kind** (the `RESP_*` bitmask in
`actions.rs`), not "wrote anything": a handler that answers a `basic.consume` with only a
delivery still gets the Consume-Ok default, instead of leaving the client blocked.

Errors that close the connection: an unsupported protocol header (the broker replies with
its own header first), a handshake method out of sequence, a frame whose end marker is not
`0xCE`, a frame larger than the negotiated `frame_max`, content frames without a publish in
progress, a body longer than its content header declared, and any method on channel 0 that
is not implemented.

**A decode error tells the peer a category and tells the log the error.** All of the above
produce `Connection.Close` with reply code 505 (`UNEXPECTED_FRAME`) and the fixed
`reply_text` in `UNEXPECTED_FRAME_REPLY_TEXT` — *"UNEXPECTED_FRAME - frame could not be
decoded or was not expected here"* — while the decoder's own message goes to the WARN line
tagged `decision=fail_closed_decode_error`.

It used to build that `reply_text` as `format!("UNEXPECTED_FRAME - {}", e)`, so the peer got
netget's internal diagnostics: `"AMQP payload truncated: 24 bytes wanted at offset 6, only 2
available"` hands an unauthenticated stranger our buffer offsets, and an `anyhow` context
chain reaches further than that. That is the leak class the project `AGENTS.md` records
across ~25 protocols, arriving here by a different door — this is a *decode* failure, so
`crate::utils::WireFailure` is not the tool (neither `Overloaded` nor `Unavailable`
describes it), but the rule it encodes is the same one. The reply text is a `&'static str`
for the same reason `WireFailure::text` returns one: a value that *can* be a `String` is one
`format!` away from leaking again.
`tests/server/amqp/wire_text_test.rs` drives a truncated `connection.start-ok` from a raw
socket and asserts both halves — that the fixed category arrives, and that none of the
decoder's vocabulary does.

## Limits and parsing safety

Everything read off the wire is length-prefixed, so the parser is the attack surface.
`codec::Decoder` never indexes without `get`, offsets use `checked_add`, and the declared
length of every field is validated against the bytes remaining before any slice is taken —
so no frame, however malformed, can panic a connection task. There is no `unwrap()` on
parsed bytes anywhere in this module.

**That paragraph was true and still not enough, which is the lesson worth keeping.** It argued
entirely about *bounds* and said nothing about *depth*, and field tables are recursive: a value
may be a nested table (`F`) or a nested array (`A`). Each level cost a peer five bytes on the
wire, so the default 128 KiB `frame_max` bought ~26 000 levels in one frame and the permitted
1 MiB maximum bought ~210 000 — far past a 2 MiB tokio worker stack. The result is not a panic
a connection task absorbs: a Rust stack overflow is a `SIGSEGV` against a guard page, so
`tokio::spawn` could not contain it and the whole NetGet process aborted with every other
server and client in it. It was reachable in **two writes, before authentication** — the
protocol header, then one `Connection.Start-Ok` whose `client-properties` table is decoded in
`Phase::AwaitStartOk`, before any credential is examined and before any model decision is
asked for. A safety argument that reads as complete and covers only one axis is worse than
none.

- Frame payloads are rejected before allocation if larger than the negotiated `frame_max`
  (default 128 KiB, hard maximum 1 MiB).
- Content bodies are capped at 8 MiB, checked against the content header's 64-bit
  `body-size` — and only `BODY_RESERVE_CHUNK` of that is reserved up front. Reserving the full
  declared size bounded *one channel* while a connection may open 256 of them: ~256 small
  frames carrying no body bytes at all bought an immediate 2 GiB allocation, held until the
  connection dropped. `Vec` grows as the body frames actually arrive, so a real publisher pays
  at most one extra reallocation and an attacker pays for every byte it claims.
- A connection may hold at most 256 channels open.
- Field tables are consumed by their declared byte length before their entries are parsed,
  so a value of an unknown type costs only the rest of that table — the outer payload
  stays in sync and the entries decoded so far are still reported.
- Field-table **nesting** is capped at `MAX_FIELD_TABLE_DEPTH` (32). Real tables are one or two
  deep; `client-properties` with its nested `capabilities` is depth 2, and `amq-protocol`
  produces nothing deeper. An over-deep value is dropped and what was decoded so far is
  returned, keeping the lenient behaviour above.
- **Short strings are refused past 255 octets, not truncated.** `Encoder::short_string`
  returns `Result` and names the length and the bound.

  It used to shorten, and that was a finding rather than a feature. shortstr carries a queue
  name, an exchange name, a routing key, a consumer tag and every field-table key, so a
  256-octet name cut to 255 reached the wire as a perfectly well-formed shortstr naming a
  *different* queue, which nothing at either end reports: the publisher publishes into one and
  the consumer waits on the other. Two field-table keys differing only past octet 255 collapsed
  into one entry and the first value written was lost — measured, not theorised. It was the
  `gtp::encode_apn` shape the codec property tests exist to find, never reachable from the wire
  (`Decoder::short_string` reads a one-octet length), so the source was the model or NetGet
  itself — both of which want to be told. `tests/codec_property_test.rs`'s `amqp_props` holds
  both counterexamples as live regression tests, each asserting that the value **at** 255 still
  encodes and round-trips, because a guard that refused everything would pass the other half.

  The one exception is `Encoder::reply_text`, used only for AMQP's `reply-text` field in
  `connection.close` and `channel.close`. That field is free-form prose rather than an
  identifier, and a handler may supply its own refusal text of any length, so refusing would
  mean not sending the close frame at all and leaving the peer waiting. A shortened sentence is
  the same sentence with less of it; a shortened name is a different name. The method is
  named after the field so that reaching for it anywhere else reads wrong.

  This entry used to justify that exception by saying "one of its callers interpolates a
  decoder error message". It did, and that was the defect below rather than a reason.

- **The encoder is depth-bounded too**, by the same `MAX_FIELD_TABLE_DEPTH` (32) and with the
  same accounting as the decoder, so it accepts exactly the tables the decoder yields — which
  matters because the broker really does echo a peer's `client-properties`. It was previously
  unbounded under the argument that every table reaching it had come through the bounded
  decoder or through `serde_json`'s 128-level parser cap. That argument is about the callers,
  not the function, and would have expired silently the first time a `Value` was built in a
  loop. A refusal at any level leaves the encoder's buffer untouched: a half-written table is
  length-prefixed to describe bytes that are not there, which desynchronises every argument
  after it in the same frame.

  Worth knowing while you are here: `serde_json::Value` has no manual `Drop`, so **dropping** a
  deeply nested value recurses once per level and overflows the stack on its own. The property
  test that tries to feed the encoder 50 000 levels aborts in the harness before the encoder is
  reached. Nothing in NetGet can build one — the decoder stops at 32 — but do not raise either
  cap on the assumption that holding the value is free.

### Timeouts

There is always a read deadline. `Session::heartbeat` is zero until the client's `Tune-Ok`, and
AMQP lets a client answer `Tune-Ok` with zero to switch heartbeating off entirely, so reading
"no heartbeat, no deadline" literally left the **whole handshake** untimed and handed an
uncooperative peer a permanently untimed session — a peer that connected and said nothing held
four tasks and an `AppState` row for as long as it liked. The protocol-header read is bounded by
`HANDSHAKE_TIMEOUT_SECS` (30) and every later read by two heartbeat intervals, or
`IDLE_READ_TIMEOUT_SECS` (600) where the peer declined to heartbeat.

### Consumer tags are per connection; the directory is per server

`AMQP_CONSUMERS` is keyed `(server_id, consumer_tag)`, but a consumer tag is chosen by the
client and is unique only *within* a connection. Two things follow, and both were bugs:

- `Basic.Consume` with a tag another connection already holds is refused with a channel error
  (405 `RESOURCE_LOCKED`), before any model call. Letting it through overwrote the first
  connection's socket handle, so every later `amqp_basic_deliver` for that tag went to the
  wrong client — and the tags are not secret, `list_consumers` hands every connection's tags to
  the model on each publish event.
- `Basic.Cancel` only cancels a consumer this connection registered. Without the check one
  client could cancel another's consumer by naming its tag, after which that client silently
  stopped receiving deliveries with no `Basic.Cancel` to explain it.

### Failure semantics

An LLM failure logs `decision=fail_closed_llm_error class=overloaded|unavailable` and a handler
that ran and decided nothing logs `decision=fail_closed_no_answer`, as `src/server/radius/`
does. The distinction has to live in the log because the wire cannot carry it: a
`Connection.Close 403` looks the same whether the model refused or the backend was down.
Nothing derived from an internal error reaches the wire.

## Startup parameters

- `frame_max` (integer, optional, default 131072, clamped to 4096..=1048576)
- `heartbeat_secs` (integer, optional, default 60; 0 disables heartbeats)

Both are read in `spawn_with_llm_actions`; neither is declared and unused.

## Testing

`tests/server/amqp/e2e_test.rs` (declared in `tests/server/mod.rs`), four tests, five LLM
calls in the round-trip test and two in each refusal test. See
`tests/server/amqp/AGENTS.md`.

## References

- [AMQP 0-9-1 specification](https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf)
- [AMQP 0-9-1 protocol reference](https://www.rabbitmq.com/amqp-0-9-1-reference.html)
- [lapin](https://docs.rs/lapin/) — client used by the E2E tests and by `src/client/amqp`
- Testing notes: `tests/server/amqp/AGENTS.md`
