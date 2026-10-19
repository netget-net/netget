# WebSocket (RFC 6455) Client

**Status**: Experimental · **Feature**: `websocket` · **Privilege**: `None`
**Scheme**: `ws://` only — see [Not implemented](#not-implemented)

## Library choice

`tokio-tungstenite` **0.21** `connect_async`, the same version the server side uses and the same
one already in the tree for `webrtc`. It performs the whole upgrade: generating the 16-byte
`Sec-WebSocket-Key` nonce, verifying the server's `Sec-WebSocket-Accept`, and — the part a client
can get wrong invisibly — masking every outgoing frame with a fresh 32-bit key as RFC 6455 §5.3
requires. Many servers tolerate unmasked client frames, so a bug there would not surface against
a lenient peer; `tests/client/websocket/e2e_test.rs` therefore asserts the mask bit explicitly.

What this module owns is the NetGet-shaped part: turning startup parameters into the request, and
turning received frames into events the model answers with actions.

## Vocabulary mirrors the server

`send_websocket_text`, `send_websocket_binary` (same `data` + `encoding` pair),
`send_websocket_ping` and `close_websocket` mean the same thing on both sides, so a prompt
written for one reads correctly on the other. `decode_outbound_payload` and
`encode_inbound_payload` are imported from `crate::server::websocket::actions` rather than
duplicated — one implementation, one behaviour, and the symmetry cannot drift between the two
sides.

## Events

| Event | When | Actions |
|---|---|---|
| `websocket_client_connected` | handshake done; carries the negotiated subprotocol | send text/binary/ping, close, disconnect |
| `websocket_client_text_message` | a text message from the server | the above plus `wait_for_websocket_data` |
| `websocket_client_binary_message` | a binary message; `data` + `encoding` round-trip | same |
| `websocket_client_closed` | the server closed | **`with_no_actions()`** — nothing can go on the wire after the closing handshake, so the common actions (`show_message`, `set_memory`, `append_to_log`) are the only honest vocabulary |

Pings from the server are answered automatically — by the read loop, which keeps polling while a
turn runs — and pongs are logged; neither raises an event.

## Startup parameters

All three are declared and read.

| Parameter | Effect |
|---|---|
| `path` | request path (and query string), default `/`. A leading `/` is added if missing. |
| `subprotocols` | array offered in `Sec-WebSocket-Protocol`, most preferred first |
| `headers` | extra request headers. `Sec-WebSocket-Key`/`-Version`/`-Accept`, `Connection`, `Upgrade` and `Host` are **ignored with a WARN** if supplied — the library computes them, and overwriting the key would break the accept-key check it then performs. |

`remote_addr` accepts `host:port` (combined with `path`) or a full `ws://…` URL. A `wss://` or
`https://` address fails immediately with an explanatory error rather than being silently
downgraded.

## Two tasks: the read loop and the model

A model turn can take minutes — a `manual` rule parks it for a human for up to 300s by default —
and tungstenite answers a server's Ping only when the stream is polled: reading a Ping queues the
Pong, and the *next* read flushes it. A server with a liveness bound (NetGet's own closes a peer
that sends no frame, not even a Pong, for `idle_timeout_secs`) hangs up on a client that stops
reading while it thinks. So `connect_with_llm_actions` returns as soon as the handshake is done,
and the connection runs on two tasks, both registered with `spawn_client_task`:

1. **The read loop** only reads. Text and binary messages go onto the turn queue; a Close frame
   queues `websocket_client_closed` behind them and ends the loop; a socket error ends it and
   aborts the turn task, since there is nothing left to answer on.
2. **`run_model_turns`** answers the queue one turn at a time, in order:
   `websocket_client_connected` first (queued before either task starts), then each message,
   then the close.

One consumer is what keeps two turns from overlapping on a connection. Messages that arrive
during a turn wait in the queue. With batching off each is its own turn; with batching on (the
declared default) the turn task takes every message already waiting (up to `MAX_BATCH_EVENTS`)
and answers them in one call through `call_llm_for_client_batch`, one event per message, the
newest the trigger; a close found while sweeping is answered after them.
`wait_for_websocket_data` holds the newest message of the turn and joins the next of the same
kind onto it. `tests/client/websocket/batching_test.rs` drives both against a tokio-tungstenite
server that sends during a slow call, batching off as the control. (An Idle → Processing →
Accumulating machine used to sit here too; with one consumer it never left `Idle` except for
the `wait_for_websocket_data` hold, which is all that remains of it.)

**The queue is bounded two ways and never blocks the read loop**, because a read loop that
waits for room stops answering Pings again: 256 messages (`TURN_QUEUE_CAPACITY`) and 16 MiB of
queued payload (`TURN_QUEUE_MAX_BYTES` — the count alone is no memory bound when tungstenite's
default message limit is 64 MiB). A message that does not fit is dropped with a WARN carrying
`decision=turn_queue_full`. One message larger than 16 MiB is still accepted into an empty
queue, so the byte bound never acts as a second, undeclared message-size limit.

The `SplitSink` lives behind an `Arc<Mutex<_>>`. LLM-produced actions send a `WsOut` down an
`mpsc` channel that a single writer task drains, so no lock is held across an LLM call; injected
commands write through the same sink themselves (see below). A frame is written under the lock,
so the two producers can never interleave halves of a frame.

`tests/client/websocket/keepalive_test.rs` holds this against a NetGet WebSocket server with a
2-second liveness bound: the connected turn and a message turn are each parked for ten seconds,
and the server still holds the connection and receives each answer.

## Validation

Against a **hand-written WebSocket server in `tests/client/websocket/e2e_test.rs`** that parses
the upgrade itself and recomputes `Sec-WebSocket-Accept` with `sha1` + `base64` directly. It
asserts that the client sends a 16-byte base64 nonce and `Sec-WebSocket-Version: 13`, that the
`path` and `subprotocols` startup parameters reach the wire in order, that **every** client frame
carries the mask bit, and that a binary message whose bytes are neither valid UTF-8 nor printable
comes back byte-for-byte when the event's `data` and `encoding` are fed straight into
`send_websocket_binary`.

## Not implemented

- **`wss://`.** The `tokio-tungstenite` dependency is built without a TLS backend (no
  `native-tls` / `rustls-tls` feature), and enabling one is a `webrtc`-wide dependency decision.
- **Every extension except permessage-deflate.**
- **Reconnection.** A closed connection stays closed; the model must open a new client.
- The repo-wide client limitation applies: `remove_client()` does not stop the network loop
  (`register_client_task` is called, so `stop_client` aborts it, but see
  `CLIENT_PROTOCOL_FEASIBILITY.md` for the general state of clients).

## Command channel — the dashboard's `[ send ]`

Adopted. `AppState::send_to_client(client_id, action, timeout)` executes an action inside the
running client and answers with a `ClientSendOutcome`.

- The channel is registered **before** the turn task starts, and so before the
  `websocket_client_connected` LLM call, which a manual `*` rule parks until a human answers it.
  `tests/client/websocket/command_channel_test.rs` guards that with `wait_for_client_handle`
  before it sends anything.
- `command_loop` (in `mod.rs`) executes the action through
  `WebSocketClientProtocol::for_connection` against a **private** frame channel it drains
  synchronously, then writes those frames itself through the shared sink. So the frame encoding,
  the hex decoding and the RFC 6455 validation are the protocol's own — there is no second
  implementation — while the write result is still this loop's to report.

| Outcome | When |
|---|---|
| `Sent { bytes_sent }` | frames written **and flushed** (`SinkExt::send` flushes). The count is the frame **payload** — the RFC 6455 header and the 4-byte client mask are added by the framing layer and are not counted |
| `Executed { detail }` | the action ran but the payload was empty (a bare ping), or it was `wait_for_websocket_data` |
| `Rejected { error }` | `execute_action` refused it: unknown name, a reserved close code, a ping payload over 125 bytes |
| `Disconnected` | `close_websocket` (the closing frame goes out first) or `disconnect` |

On disconnect — and on a write error — the loop closes the sink and drops the command handle
itself rather than waiting for the read loop to see the connection end.

## permessage-deflate (RFC 7692)

The client offers `permessage-deflate; client_max_window_bits` unless `permessage_deflate` is
false. To put the server's `deflate::DeflateStream` beneath tungstenite on this side too, the
client dials the TCP socket itself and hands it to `client_async_with_config` instead of
`connect_async`; the stream starts in pass-through, reads the 101 response head itself, and
switches to frame mode at the exact byte the head ends, with whatever the server accepted
(including a `client_max_window_bits` it imposed — Python websockets imposes 12). A response
naming an extension that was not offered fails the handshake. `websocket_client_connected`
carries `permessage_deflate`. The message limits are tungstenite's defaults (64 MiB per
message, 16 MiB per frame), which is what the client used before it dialled its own socket;
an inflated message is bounded by the first.
