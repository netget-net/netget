# WebSocket (RFC 6455) Server

**Status**: Beta (see [Validation](#validation) for exactly what was checked)

Beta rests on **websocat 1.14.1**, which links `websocket-0.27.1` / `websocket-base-0.26.5`
(rust-websocket) and **not** `tungstenite` — read out of the installed binary's embedded crate
paths. That matters: this server frames with `tokio-tungstenite`, so a tungstenite-based peer
would be the circular-evidence case, and rust-websocket is a separate RFC 6455 implementation.
`test_websocket_with_websocat` is not `#[ignore]`d and **fails** rather than skips when the
binary is absent; it printed `skipping: websocat is not installed` and returned `Ok(())` until
September 2026, which is a silent pass and is what held this at Experimental.

Still unproven, and what a human should check before this goes further: `wss://`,
and any browser.
**Spec**: RFC 6455, and RFC 7692 (permessage-deflate) — see "permessage-deflate" below.
**Feature**: `websocket` · **Privilege**: `None` · **System libraries**: none

## Why this protocol is a good fit for NetGet

Almost every other protocol here is request/response: a peer asks, the model answers, the
exchange ends. WebSocket is a long-lived bidirectional session, so the model gets two things it
does not get elsewhere:

1. **It can speak unprompted.** `websocket_connection_opened` fires before the client has said
   anything, and `push_websocket_text` / `push_websocket_binary` address any open connection by
   id (or `"*"` for a broadcast) from a user command or a scheduled task. A ticker that emits a
   price every two seconds is a scheduled task plus one action.
2. **The handshake is a real decision.** `Sec-WebSocket-Protocol` negotiation is a genuine
   choice — the client offers a preference list, the server picks at most one, and RFC 6455
   §4.2.2 forbids naming one that was not offered.

## Library choice

`tokio-tungstenite` **0.21**, which was already an optional dependency in the tree (pulled in by
the `webrtc` feature). Deliberately **not bumped to 0.30**: the version is shared with
`webrtc_signaling` and has to agree with whatever the `webrtc` crate itself pins, so bumping it
is a `webrtc`-wide decision and not this protocol's to make. 0.21 is fully RFC 6455 for
everything below §5, which is all that is needed here.

`fastwebsockets` was the alternative. It was rejected for one reason: adding a second WebSocket
implementation to a tree that already contains one, for a protocol the existing one covers, is
a dependency the project would then carry forever.

### The handshake is hand-written; the framing is not

`accept_hdr_async` takes a **synchronous** callback to shape the 101 response. Choosing a
subprotocol needs a model call, which is `async`. So `src/server/websocket/mod.rs` does §4.2 of
the RFC itself:

- `parse_request_head` — request line + headers, hand-parsed (obsolete line folding rejected)
- `validate_upgrade` — method/version/`Upgrade`/`Connection`/`Sec-WebSocket-Version: 13`, and
  that `Sec-WebSocket-Key` really is a base64-encoded 16-byte nonce
- `build_accept_response` — `Sec-WebSocket-Accept` via `tungstenite::handshake::derive_accept_key`
  (`base64(SHA-1(key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))`), so there is exactly one
  implementation of the GUID concatenation in the tree
- the upgraded socket then goes to `WebSocketStream::from_partially_read(.., Role::Server, ..)`

`from_partially_read` rather than `from_raw_socket` on purpose: a pipelined client can put frames
in the same TCP segment as the request head, and those bytes would otherwise be dropped.

Everything from §5 onwards is the library's: frame parsing, the mandatory client-to-server mask
check (`accept_unmasked_frames` stays `false`, so an unmasked client frame fails the connection
per §5.1), continuation-frame reassembly, automatic pongs, and the closing handshake.

## Events

Every event below is emitted, and every one declares actions. Verify both directions with:

```bash
grep -c "with_actions\|with_no_actions" src/server/websocket/actions.rs
grep -n "_EVENT," src/server/websocket/mod.rs   # the emit side
```

| Event | When | Actions offered |
|---|---|---|
| `websocket_handshake` | every well-formed upgrade request, **before** any 101 | `accept_websocket`, `reject_websocket` |
| `websocket_connection_opened` | immediately after the 101 is written | send text/binary/ping, close |
| `websocket_text_message` | a reassembled text message | send text/binary/ping, close, `wait_for_websocket_data` |
| `websocket_binary_message` | a reassembled binary message | same |
| `websocket_ping` | a ping control frame (the pong is already on its way) | send text/binary/ping, close |
| `websocket_close` | the client started the closing handshake | send text, close |

**Pong frames are deliberately not an event.** A keepalive pong would otherwise cost a model
call per heartbeat. They are logged at DEBUG, and they count as activity for the idle bound
below — that is what they are for.

**`websocket_handshake` carries `answer_with`** (`actions::handshake_answer_with`): whether the
client offered any subprotocol, that none is normal and never a reason to refuse, the offered
list when there is one, and that `reject_websocket` needs a reason from the instructions. It
exists because, with instructions that said nothing about the handshake ("echo every message",
"greet every client"), llama3.1:8b answered websocat's upgrade — which offers no subprotocol —
with the example's `"subprotocol": "chat"` five runs in five, and with `reject_websocket` 403 "no
subprotocols offered" five runs in five (real-model eval, seed 42). The action and event examples
accept without a subprotocol. The hint also says a greeting belongs to the opened connection,
never to the handshake: told to greet every client, the model answered the handshake with
`show_message` and no accept, which is the fail-closed 503.

**`websocket_connection_opened` and `websocket_text_message` carry `answer_with` too**
(`actions::OPENED_ANSWER_WITH`, `actions::TEXT_MESSAGE_ANSWER_WITH`). Speaking first is the
instruction's call: the opened event says to send something only when the instructions say to
greet on connect, with their exact words, and otherwise to return no action. With the old
`{"event":"welcome"}` example the model greeted on every connection — an echo server announced
itself, which also ended the eval's echo probe before the echo arrived — and a server told to
greet with "Welcome to NetGet Eval" sent the example's `{"event":"welcome"}` instead. The text
message hint says an echo's text is the message's own `text`. `send_websocket_text`'s example is
now a placeholder (`"<the message, word for word>"`).

**An empty text message on connection open is dropped** (WARN `decision=empty_greeting_dropped`).
Told to stay silent on connect, the model answers `send_websocket_text` with `"text": ""` rather
than no action, every run, whatever the hint says. That is valid RFC 6455 and carries nothing —
and websocat treats a zero-length message as end of stream: against a Python `websockets` server
that sends `""` and then echoes, websocat printed nothing at all, and without the empty message
it printed the echo. In the eval the echo was sent and never shown, 5 runs in 5. The executor
knows it is answering `websocket_connection_opened` because `run_connection` brackets that call
with `WebSocketProtocol::set_speaking_first`; a reply to the client's own empty message is still
sent.

Measured with the real-model eval (5 runs each, seed 42): echo 0/5 and greeting 0/5 before;
subprotocol drop + handshake hint → echo 0/5 (an empty greeting, or the model greeting on every
connection with the old `{"event":"welcome"}` example), greeting 0/5 (`show_message` answering
the handshake); + opened/message hints and placeholder examples → echo 0/5, greeting 2/5 and then
4/5 once the handshake hint gave the accept as a literal action; + the empty-greeting drop → echo
5/5, greeting 3/5. The greeting misses are the model answering the handshake with `show_message`
or with nothing, which is the fail-closed 503.

**An accept naming a subprotocol the client did not offer is accepted without one.** RFC 6455
§4.2.2 forbids echoing a subprotocol the client did not offer, and websocat fails the connection
if the server does — but what it forbids is the echo, not the connection. The executor drops only
the subprotocol, logs WARN `decision=subprotocol_dropped` naming what was dropped and what was
offered, and the connection opens with a 101 that carries no `Sec-WebSocket-Protocol`. Refusing
the whole action instead made every such accept the fail-closed 503, because the network path
does not re-prompt the model with the executor's error.

**Every connection costs two model calls before the first message** (`websocket_handshake`, then
`websocket_connection_opened`). For a deterministic endpoint use script or static handlers, which
cost none — that is how `tests/server/websocket/e2e_test.rs` runs a whole conversation on a
single `open_server` call.

## Data format — symmetric in both directions

Text frames carry a plain `text` field; there is nothing to encode, a text frame is UTF-8 by
definition.

Binary frames use the `data` + `encoding` pair, and **the two directions are inverses**:

| Direction | Field values |
|---|---|
| inbound (`websocket_binary_message`) | `encoding: "utf8"` and `data` as literal text when every byte is printable ASCII; otherwise `encoding: "base64"` and `data` base64-encoded |
| outbound (`send_websocket_binary`, `push_websocket_binary`) | `"utf8"` (default) sends the characters of `data` unchanged; `"base64"` and `"hex"` decode it |

So echoing a binary frame back unchanged is passing the event's `data` **and** its `encoding`
straight through, and the bytes on the wire are identical. This is the `send_tcp_data` bug
(`d70bb5b5`) in a protocol that would have shipped with it: there, inbound was encoded and
outbound was not, so an echo server could not echo. `test_binary_payload_encoding_is_symmetric`
and the byte-for-byte assertion in `test_websocket_wire_protocol_against_raw_client` exist
specifically to fail if that ever drifts.

There is **no auto-detection**: `"48656c6c6f"` is simultaneously valid text, valid hex and
nearly valid base64, and only the sender knows which it means.

## Fail-closed handshake

A `websocket_handshake` answered with neither `accept_websocket` nor `reject_websocket` is
**refused with HTTP 503**, and the refusal is logged at ERROR with wording distinct from an
explicit rejection. An LLM outage, a handler that returns only `show_message`, and a model that
means to deny all end at the same place, and none of them can be mistaken for consent. This is
the OAuth2 post-mortem in CLAUDE.md applied ahead of time rather than after.

A request that is not a WebSocket upgrade at all never reaches the model — there is no decision
in "this is not a handshake". It gets 400/405/426/505 directly, and a 426 carries
`Sec-WebSocket-Version: 13` as §4.4 requires.

On a **handler failure mid-session** the connection is closed with code **1011** (internal
error), or **1013** (try again later) when the failure is a saturated backend, rather than being
reset to Idle in silence — so the peer is not left waiting for a reply that is never coming, and
a client backs off rather than recording a permanent fault. The close *reason* is the fixed
string `handler failed` in both cases: a close reason is peer-visible, so the backend's error
text belongs in the log line beside it and nowhere else.

## Failure behaviour

Every LLM call site emits one `decision=` line. The important one is `websocket_text_message` /
`websocket_binary_message` / `websocket_ping`: a handler that answers with nothing sends no
frame at all and the connection simply goes quiet, which used to be logged nowhere — so a model
that deliberately said nothing and a rule that never matched were the same silence.

| Outcome | On the wire | Log |
|---|---|---|
| `websocket_handshake` → `accept_websocket` | 101, with the agreed subprotocol | INFO `decision=model_answer` |
| `websocket_handshake` → `accept_websocket` naming an unoffered subprotocol | 101 with no subprotocol | WARN `decision=subprotocol_dropped`, then INFO `decision=model_answer` |
| `websocket_handshake` → `reject_websocket` | the handler's own status (default 403) | INFO `decision=model_reject` |
| `websocket_handshake` → neither, no action at all | **503**, fixed reason | ERROR `decision=fail_closed_no_action` |
| `websocket_handshake` → neither, but actions ran | **503**, fixed reason | ERROR `decision=fail_closed_bad_action` |
| `websocket_handshake` → backend failed | **503**, fixed reason | ERROR `decision=fail_closed_llm_error` / `..._overloaded` |
| message → frames sent, or `wait_for_websocket_data` | those frames, or the message is held | INFO `decision=model_answer` |
| message → `close_websocket` | close frame with the model's code and reason | INFO `decision=model_reject` |
| message → no action | **nothing**; the connection stays open | WARN `decision=model_silent` |
| message → every action refused by the executor | **nothing**; the connection stays open | ERROR `decision=fail_closed_bad_action` |
| message → backend failed | close **1011** / **1013**, reason `handler failed` | ERROR `decision=fail_closed_llm_error` / `..._overloaded` |
| `websocket_connection_opened` → backend failed | nothing; the connection stays open | WARN `decision=llm_error_notice_only` |
| `websocket_close` → backend failed | nothing; the peer has already closed | WARN `decision=llm_error_notice_only` |

`llm_error_notice_only` is this protocol's own token and is deliberately **not** `fail_closed_*`.
Both events it covers fire when nothing is pending: the upgrade was already decided by
`websocket_handshake`, and `websocket_close` fires because the peer has gone. Tagging them
`fail_closed_` would put lines that refused nothing in front of every
`grep decision=fail_closed`.

`tests/server/websocket/e2e_test.rs::test_websocket_handshake_backend_failure_is_tagged_fail_closed`
asserts both halves of the handshake row: the 503 on the wire, and
`decision=fail_closed_llm_error` in the log with no `decision=model_reject` anywhere.

## Connection state machine

Per connection: **Idle → Processing → Accumulating**, in `ConnData`.

- messages arriving while the model is thinking go on `queued` (no concurrent model call on one
  connection, no lost message)
- `wait_for_websocket_data` moves to `Accumulating` and parks the message in `pending`; the next
  message of the same kind is joined onto it (text concatenated, binary appended) and the pair is
  delivered as one event. Different kinds are processed in arrival order instead.
- **Batching (`BatchingMode::On`).** When the handler comes back for the next queued message
  and the instance batches, it drains every consecutive text/binary message at the front of
  `queued` (up to `MAX_BATCH_EVENTS`) into one `call_llm_batch`, newest as trigger; off, one
  queued message per call. A ping is a control frame and is always answered alone, and a
  batch stops at one. `wait_for_websocket_data` on a batch parks the trigger (newest) message
  in `pending`. Test: `tests/server/websocket/batching_test.rs`.
- **Messages are queued by the read loop itself** (`enqueue_inbound`), and a handler task is
  spawned only when none is running. Each message used to spawn a task that took the lock on
  its own, so two messages read during one call could be queued in either order — the test's
  control caught `third` answered before `second`.

`tokio::io::split` is not used directly: the socket becomes a `WebSocketStream`, which is split
with `futures::StreamExt::split()` into a `SplitSink` and a `SplitStream` — the same "one owner
per direction, never clone" shape one level up. A single **writer task** owns the sink and every
producer (message handlers, async push actions, scheduled tasks) sends `WsOut` down an
`mpsc::UnboundedSender`, so no lock is ever held across an `.await` that performs I/O.

The auto-pong is flushed by the *next* read, which the frame loop performs immediately, so a
ping is answered even when the handler produces no frame of its own.

## Startup parameters

Every one is declared and read; nothing is declared and unused.

| Parameter | Effect |
|---|---|
| `path` | only this exact path is upgraded; anything else gets 404 without a model call |
| `max_message_size` | reassembled-message ceiling, default 1 MiB, clamped to 64 MiB |
| `max_frame_size` | single-frame ceiling, same default and clamp |
| `idle_timeout_secs` | how long an upgraded connection may send no frame at all, default 600 |

## Connection bounds

| Bound | Default | Mechanism |
|---|---|---|
| Request head | 15s (`HANDSHAKE_TIMEOUT_SECS`) | `timeout` around reading the HTTP head, before the upgrade |
| Upgraded, no frame from the peer | 600s (`idle_timeout_secs`) | `accept_bounded::watch_idle_with_probe` over a `ConnectionActivity`, the probe a Ping, raced against the frame loop |
| Connections | 256 | `accept_bounded`; the peer over the cap reads `503` + `Retry-After` |

**The upgraded bound is on liveness, not on conversation.** A WebSocket client is entitled to
hold a session open with nothing to say, so at half the bound the server sends a Ping (payload
`netget-keepalive`), and every RFC 6455 endpoint answers a Ping with a Pong by itself (§5.5.2)
— browsers, tungstenite, websocat, NetGet's own client — with no application code. Any inbound
frame counts: text, binary, Ping, Pong, Close. What reaches the bound is a peer that has stopped
reading or vanished without a FIN. It is closed with **1001** ("going away", §7.4.1) and the log
says `decision=idle_timeout`.

**Why 600 and not 300: clients that stop reading while they think.** tungstenite, like most
WebSocket libraries, flushes the Pong for a Ping from inside a *read*, so a client whose
application stops reading while it decides what to say — a model turn, or a person answering a
`manual` rule's 300-second window — answers late. At twice that window a Ping sent at the worst
moment is still answered inside the bound. NetGet's own client does not need the margin: it
reads on a task of its own while turns run on another, and
`tests/client/websocket/keepalive_test.rs` holds it to a 2-second bound through two ten-second
parked turns.

**Busy is not idle.** Handlers run on their own tasks while the frame loop keeps reading, so each
holds `ConnectionActivity` busy for the whole of its answer; a message waiting on the model or
parked for a human by a `manual` rule is neither pinged nor closed, however long it takes.

`tests/server/websocket/connection_bounds_test.rs` drives all of it from the wire.

## Connection directory (not storage)

`WS_CONNECTIONS` maps connection id → live `mpsc` sender, remote address, path and negotiated
subprotocol. It exists so `push_websocket_text` can name a recipient, and an entry lives exactly
as long as its socket. No message log, no rooms, no subscriptions — the model tracks all of that
in its memory, per the no-storage rule.

## Keyword and stack-name notes

`stack_name()` is `ETH>IP>TCP>HTTP>WebSocket`, **not** `ETH>IP>TCP>WebSocket` — WebRTC Signaling
already claims that string, and stack names are registered as parser keywords, so a duplicate
would make `parse_from_str` resolve by HashMap iteration order. The HTTP hop is also more
accurate.

Claiming the keyword `websocket` would have shadowed WebRTC Signaling's longer
`websocket signaling` in the same arbitrary-order loop, so `server_registry.rs` gained a
priority check for `"WebRTC Signaling"` ahead of the generic keyword loop, in the same shape as
the existing mDNS-before-DNS and Proxy-before-HTTP entries. No bare `ws` keyword: it would match
`aws`, `wsdl` and more.

## Validation

Checked against **three peers, two of them not this repository's code**:

1. **A hand-written raw TCP client** (`tests/server/websocket/e2e_test.rs`) that composes the
   upgrade itself, recomputes `Sec-WebSocket-Accept` from the RFC algorithm with `sha1` +
   `base64` directly, masks its own frames, and decodes the server's frame headers byte by byte.
   It asserts: the 101 headers, that the server **never masks** (§5.1), a text round-trip
   including multi-byte UTF-8, a **byte-for-byte binary round-trip** of
   `00 ff fe 01 80 7f c3 28 0d 0a` (not valid UTF-8, not printable), that a ping is answered by a
   pong with the same payload, that two continuation frames are reassembled into one message
   before the handler runs, and that a close frame is echoed with the same big-endian status code.
2. **`websocat` 1.14.1**, a separately built binary, driving the same server end to end — it
   completes the handshake, receives the server's unprompted greeting and gets its own message
   echoed back. Its RFC 6455 implementation is `websocket`/`websocket-base` (rust-websocket),
   which shares no code with the `tokio-tungstenite` this server frames with. **Fails, never
   skips, when websocat is missing.**
3. **RFC 6455 §1.3's published worked example** — key `dGhlIHNhbXBsZSBub25jZQ==` must produce
   `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.

## Not implemented

- **TLS (`wss://`)** — put a TLS terminator in front, or use the `tls` protocol.
- **Every extension except permessage-deflate.** Any other `Sec-WebSocket-Extensions` offer is
  declined (the response simply names none), which RFC 6455 allows.
- **Autobahn test suite conformance.** Not run. The framing is `tungstenite`'s, which does pass
  it, but that is an inherited claim and not one this protocol has checked.

## permessage-deflate (RFC 7692)

tungstenite 0.21 — and every published version, 0.30 included — has no extension hook and
refuses any frame with RSV1 set (`ProtocolError::NonZeroReservedBits`). So the extension lives
**beneath** it: `src/server/websocket/deflate.rs`'s `DeflateStream` wraps the socket, reads
and writes frames itself and shows tungstenite only uncompressed ones. The rest of this
protocol — handlers, events, actions — never sees compression.

- **Negotiation** (`deflate::negotiate`) is mechanical, not a model decision: the first offer
  this server can honour is accepted, with its `server_no_context_takeover`,
  `client_no_context_takeover` and `*_max_window_bits` (9-15) echoed; an offer with an
  unknown or repeated parameter, or a window of 8 (zlib cannot make one for raw deflate), is
  skipped; none acceptable means uncompressed, which is always allowed. The startup parameter
  `permessage_deflate` (default `true`, `DEFAULT_PERMESSAGE_DEFLATE`) turns it off.
- **Inbound**: a message whose first frame has RSV1 is collected across its continuations,
  inflated as one (with `00 00 ff ff` appended, §7.2.2) and handed up re-fragmented at
  `max_frame_size`, keeping the client's masking key so tungstenite still sees a masked frame.
  Inflation stops at `max_message_size + 1` bytes of output — the bound is enforced while
  inflating, so a 1 KB frame cannot allocate a gigabyte — and the connection closes with 1009
  and `decision=permessage_deflate_refused`.
- **Outbound**: every data message tungstenite writes is deflated with a sync flush, the tail
  removed (§7.2.1), and sent as one frame with RSV1.
- **Backend**: flate2's `zlib-rs` (pure Rust, so no system library), because the default miniz
  backend cannot use a window smaller than 15 bits and Python websockets asks for 12.

The handshake's leftover bytes go to the deflate layer, not tungstenite: with compression on,
a pipelined client's first message may be compressed. `websocket_connection_opened` carries
`permessage_deflate` (the agreed parameters, or null).

Evidence: `tests/server/websocket/deflate_real_client_test.rs` — see the tests' AGENTS.md.
