# STOMP Protocol Implementation

STOMP 1.2 (Simple Text Oriented Messaging Protocol) broker. A client opens a session with
`CONNECT`, then publishes with `SEND` and receives with `SUBSCRIBE`/`MESSAGE`. The model decides
whether to admit a session and what every message carries; there is no broker behind it.

**State**: Beta. **Privilege**: `None` — the default port is 61613, which is
unprivileged, so declaring `PrivilegedPort` would be dead code (the `svn` mistake).
**Stack**: `ETH>IP>TCP>STOMP`. **Library**: none on the server side — the codec is `frame.rs`.
`async-stomp` is a **dev-dependency only**, used as the test peer.

## Why the rating is Beta, precisely

**A real third-party client completes a real session.** `async-stomp` 0.6.3 — an independent
STOMP 1.2 implementation, not a codec driven frame by frame — runs
CONNECT → CONNECTED → SUBSCRIBE → MESSAGE → SEND → MESSAGE → DISCONNECT → RECEIPT → close
against this server in `tests/server/stomp/e2e_test.rs`, decoding every frame with its own
parser. A second test has it decode a refusal as an `ERROR` frame with the `message` header and
body intact.

It satisfies every clause of the bar the root `AGENTS.md` sets:

- **Not `#[ignore]`d.** It runs in the default suite.
- **Cannot skip.** `async-stomp` is a compiled-in crate dependency, so there is no "is it
  installed?" question and no `SKIP: … not installed` branch to take. This is the failure mode
  that keeps `kubernetes`, `oci_registry`, `maven` and `websocket` out of Beta.
- **Not circular.** Nothing in that file touches `netget::server::stomp::frame`. The peer is a
  different implementation by a different author, which is what `rss` had to fix with `feed-rs`
  and what `webrtc_signaling` structurally cannot have.
- **Not vacuous.** A negative control was run: deleting the `version` header from `CONNECTED`
  makes `async-stomp`'s handshake fail and the test fail. Notably `raw_socket_test.rs` still
  passed under that mutation — the hand-written peer never checked `version`. That is the
  concrete demonstration that a real client is strictly stronger evidence, and the reason the
  rating rests on `e2e_test.rs` alone.

Two `async-stomp` requirements were checked against this implementation before relying on it,
and both hold: it hard-errors if `CONNECTED` carries no `version` header (this server always
sends one), and if `MESSAGE` lacks any of `destination`, `message-id`, `subscription`
(`send_stomp_message` requires all three).

**What Beta still does not claim.** Interop with the brokers' own client stacks
(ActiveMQ/RabbitMQ STOMP) is unproven, as is behaviour under concurrent sessions. Those are what
a human should check before this goes past Beta. See also *Not implemented* below — none of it
is hidden from the peer.

### Two `async-stomp` deviations worth knowing

Neither affects the tests, and neither is a defect on our side, but they will bite whoever
extends this:

- **It escapes `CONNECT` headers.** STOMP 1.2 exempts `CONNECT`/`STOMP`/`CONNECTED` from
  escaping for 1.0/1.1 compatibility, and this server implements that exemption; `async-stomp`
  escapes and unescapes unconditionally. It only matters for a value containing `:` `\r` `\n`
  or `\`, so a `virtualhost` of `localhost` is unaffected but `example.com:61613` would arrive
  as the literal `example.com\c61613`. The spec is on our side here; do not "fix" it.
- **It never writes `content-length`.** `ToServer::Send` builds its frame without one, so it
  physically cannot publish a body containing NUL. That is why the `content-length` path has to
  be exercised from `raw_socket_test.rs` instead.

There is **no** command-line STOMP client on macOS and none in Homebrew, so the `npm`/`git`
"real binary" route was never available; `stomp.py` would have been a skip-when-missing gate,
which the root `AGENTS.md` rejects. An in-process crate dependency avoids that problem entirely.

## Where the work is divided

Everything mechanical is Rust and is never asked of the model:

| Done in Rust | Why |
|---|---|
| frame boundaries, NUL terminator, `content-length` | a model that gets framing wrong produces a stream no client can resynchronise from |
| header escaping (`\r` `\n` `\c` `\\`) and its `CONNECT`/`CONNECTED` exemption | same, and an unescaped `:` forges a header |
| the `receipt` handshake | a property of the frame, not of what it means |
| heart-beat negotiation (always `0,0`) | see below |
| refusing a frame that violates the spec | a stranger must not be able to provoke an LLM round trip with a malformed frame |

The model decides content: admit this `CONNECT` or refuse it, what a `MESSAGE` carries.

### No per-connection state machine, deliberately

`src/server/tcp/mod.rs` carries Idle/Processing/Accumulating because raw TCP has no frame
boundaries: a second read arriving mid-LLM-call has to be queued. STOMP *has* frame boundaries,
so this connection reads, parses out whole frames, and handles them one at a time in the same
task. Bytes arriving during an LLM call sit in the socket buffer — TCP's own backpressure — and
are read on the next pass. There is no window in which two LLM calls could run for one
connection, so there is no state to track. Copying TCP's machine here would be dead code.

### Heart-beating is negotiated off and there is no parameter for it

`CONNECTED` always carries `heart-beat:0,0`, and `send_stomp_connected` has **no** heart-beat
parameter. The server implements no heart-beat timer, so any other value would be a promise it
does not keep, and a client that believes it will hear from us every N ms tears the connection
down when it does not. Per the spec's negotiation formula, `0,0` from the server makes both
directions zero whatever the client asked for, so a compliant client stops expecting them.
`raw_socket_test.rs` asks for `10000,10000` and asserts it gets `0,0` back; `async-stomp` sends
no heart-beat header at all, so it is content either way.

## What the model sees and controls

### Events

| Event | Fields |
|---|---|
| `stomp_connect` | `accept_version`, `host`, `login`, `passcode`, `heart_beat` |
| `stomp_send` | `destination`, `body`, `body_encoding`, `headers` |
| `stomp_subscribe` | `destination`, `id`, `ack_mode` |
| `stomp_unsubscribe` | `id` |
| `stomp_ack` / `stomp_nack` | `id` |
| `stomp_disconnect` | `receipt` |

`passcode` is carried so the model can make an authentication decision, the same way
`ssh_auth` sees what it is deciding about. `heart_beat` is informational: the answer is always
`0,0`.

### Actions

| Action | Effect |
|---|---|
| `send_stomp_connected` | `CONNECTED` with `version` (1.2 only), optional `session`/`server`, and `heart-beat:0,0` |
| `send_stomp_message` | `MESSAGE`; requires `destination`, `subscription`, `message_id`; optional `body` + `encoding`, `content_type`, `headers` |
| `send_stomp_receipt` | `RECEIPT`. Rarely needed — receipts are automatic. Only one carrying the *same* `receipt_id` the client asked for suppresses the automatic one |
| `send_stomp_error` | `ERROR`; the connection is closed afterwards, as the spec requires |
| `close_connection` | hangs up |

No async actions: STOMP here is purely reactive — every frame the server writes answers one the
client sent.

### Body encoding — explicit, never sniffed

A STOMP body may be binary, so `body` always travels with an encoding field and the executor
**decodes** it:

- inbound (`stomp_send`): `body` is text when every byte is ASCII graphic/whitespace, otherwise
  hex; `body_encoding` says which.
- outbound (`send_stomp_message`): `encoding` is `"utf8"` (default) or `"hex"`; anything else
  is an error naming the valid values.

There is no sniffing, deliberately — `"48656c6c6f"` is simultaneously valid text and valid hex,
and only the sender knows which it means (the `send_tcp_data` bug, `d70bb5b5`). Passing the
event's `body` and `body_encoding` straight into `send_stomp_message` therefore reproduces the
exact bytes. `raw_socket_test.rs` asserts that with a body containing NUL and 0xFF — it has to
be the raw peer, because `async-stomp` writes no `content-length` and so cannot send one.

`content-length` supplied through the `headers` map is dropped and recomputed: a wrong one
truncates the frame or makes the peer wait for bytes that never arrive.

## Receipts, and their ordering

Any client frame carrying a `receipt` header is answered with `RECEIPT` **after** the frame has
been processed — after the handler's own output. That is what the spec says, and it is the only
order in which a handler can answer before the acknowledgement.

`CONNECT` is exempt: `CONNECTED` is its acknowledgement and a receipt on it is not defined.

If the handler's output already begins with a `RECEIPT` frame, the automatic one is suppressed,
so a model that answers with `send_stomp_receipt` does not produce a duplicate the client would
have to reconcile.

## Batching (on by default)

Frames already waiting behind the one being answered — typically what the client sent while
the model answered the last — are answered in one call (`frames_already_here` in `mod.rs`
collects complete frames from the buffer and whatever is readable without waiting, up to
`MAX_BATCH_EVENTS`). Only `SEND`, `SUBSCRIBE`, `UNSUBSCRIBE`, `ACK` and `NACK` carrying their
required headers are batched; collection stops at the first other frame (`CONNECT`,
`DISCONNECT`, `BEGIN`/`COMMIT`/`ABORT`, a malformed frame), which is then handled alone, in
order. Receipts stay Rust's job per frame: after the batch's output, every frame whose
`receipt` the model did not write itself gets its `RECEIPT`, in arrival order, and none twice.
`tests/server/stomp/batching_test.rs` drives it with `async-stomp` against a batching-off
control.

## Failure behaviour

STOMP has an `ERROR` frame, so this server is **never silent** on failure. Two distinct paths:

- **The peer got it wrong** (unknown command, a frame before `CONNECT`, a missing `destination`
  or `id`, a version this server does not speak, unrecoverable framing). Rust decides, the
  `ERROR` names the peer's own mistake — which is theirs to read — and the connection closes.
  No LLM call is made.
  `tests/server/stomp/raw_socket_test.rs::test_stomp_protocol_errors_never_reach_the_model`
  pins this: framing must not be a question the model gets asked, or a stranger can provoke an
  LLM round trip at will.
- **netget failed.** The peer gets a `crate::utils::WireFailure` **category** (`Overloaded` vs
  `Unavailable`), never the error text; the error goes to the log and the status stream, tagged
  `decision=fail_closed_llm_error class=overloaded|unavailable`.

`stomp_connect` is the one event where model silence is not a valid answer: STOMP defines
exactly two replies to `CONNECT`, and a client that gets neither blocks forever. A connect event
that produces no bytes is answered with `ERROR` and closed, logged
`decision=fail_closed_no_answer`. Everywhere else silence is legitimate — a broker that accepts
a `SEND` and says nothing is behaving normally — and logs `decision=model_no_actions`.

Log decisions in one place: `model_reject` (the model refused), `model_close` (the model hung
up), `model_no_actions`, `fail_closed_no_answer`, `fail_closed_llm_error`, `protocol_error`,
`version_refused`.

## Dashboard injection (peer handle)

Every connection registers a peer handle (`server::peer_support`) before its first read — a
STOMP server says nothing until the client sends `CONNECT`, and a manual `*` rule can park that
frame for minutes, so the operator has to be able to reach the connection while it waits. The
write half is an `Arc<Mutex<WriteHalf>>` shared by the session and the peer command task, so
`[ message this peer ]` runs any of the actions above through the same executor the model's go
through, and `[ disconnect this peer ]` is `close_connection`.

The accept loop *and* each connection task are registered with
`AppState::register_server_task`. Aborting a parent does not abort what it spawned, so an
unregistered connection task keeps its socket alive after `stop_server` has released the
listener (the BGP keepalive bug). The one task not registered is the peer-injection task from
`server/peer_support.rs`, which is shared infrastructure and self-terminating — it ends when
`remove_peer_handle` drops its sender. This section used to claim *every* task was registered,
which read as a stronger guarantee than the code gives.

## What bounds the codec

Four things, and each was added because the absence of it was reachable from one frame:

- `MAX_FRAME_BYTES` (1 MiB) bounds a frame that is never terminated.
- A `content-length` above that is refused **on sight** rather than buffered toward, and the
  index that reads it is bounded before the addition. `content-length:18446744073709551615`
  parses cleanly into a `usize` and `pos + len` overflowed — a panic in debug and test builds,
  a wrap in release, so the bug was invisible in the shipped profile while live in every test
  run. The panic was inside the connection's `tokio::spawn`, so it was swallowed and the
  connection's cleanup never ran: the peer handle and the `AppState` row leaked with the
  connection stuck `Active`. Reachable before the CONNECT gate.
- `MAX_HEADERS` (1024) bounds the *work*, which `MAX_FRAME_BYTES` does not. The session loop
  re-parses the whole pending buffer after every read, allocating two `String`s per header
  line, so a megabyte of `a:\n` lines is ~350k headers re-parsed ~128 times as the 8 KB reads
  arrive.
- A `FrameError` quotes at most 120 characters of the peer's own input, via
  `crate::utils::truncate_for_log`. It reaches the `ERROR` frame, `netget.log` *and* the
  unbounded TUI status channel, so an unbounded quote let the peer choose how much memory
  NetGet spent on its behalf, three times over.

## Header injection on the exempt commands

STOMP 1.2 exempts `CONNECT`, `STOMP` and `CONNECTED` from header escaping so a 1.2 endpoint can
read a 1.0/1.1 peer's handshake. That means `encode()` writes those three commands' header
values **raw**, and it is the one place in this protocol where a string reaches the wire with
no escaper in front of it. `send_stomp_connected` therefore *rejects* a `session` or `server`
containing `\r`, `\n`, `:` or NUL, and the client rejects the same in `host`/`login`/`passcode`
before building its `CONNECT`. Rejecting rather than escaping is the point: escaping is exactly
what those commands cannot do, and a 1.0/1.1 peer would read the sequence literally.

This is worth stating plainly because the prose elsewhere — "framing is never the model's to
get wrong" — was not true here. The protocol's own startup example builds the session out of
peer input (`'session-' + login`), so the injection was reachable from a script handler as
readily as from the model.

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` row forever —
before `CONNECT`, so before the model had decided anything about it — on a server that would
happily accept a hundred more. It now declares both halves; the constants and the reasoning live
beside them in `src/server/stomp/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_FRAME_READ_TIMEOUT` | 30s | STOMP is client-speaks-first and the spec makes `CONNECT`/`STOMP` the *only* legal first frame, so a peer that has sent nothing has begun no session. Which bound applies is the protocol's own distinction: the flag is `connected`, set by that frame. |
| `IDLE_BETWEEN_FRAMES_TIMEOUT` | 1800s (30 min) | **The one bound here that can close a well-behaved client, stated rather than hidden.** A subscriber sends `SUBSCRIBE` once and then only receives, and this server negotiates heart-beating off unconditionally (`STOMP_HEARTBEAT` is `0,0`, because there is no timer here and promising one would be a lie), so there is no keepalive interval to sit above and no traffic from an idle subscriber at all. A finite bound is still required. Thirty minutes is measured against what a real broker does: ActiveMQ and RabbitMQ negotiate heart-beats at 10–60s and cut a peer at twice the interval, so this is 30–180× more patient. A client that wants longer has a cheap way to say so — a bare EOL is a STOMP heart-beat, the parser drains it as one, and it counts as inbound activity. |
| `MAX_CONNECTIONS` | 256 | Refusal: a well-formed **`ERROR` frame** with `message:too many connections`, built through `frame::error_frame` rather than as a byte literal so escaping and the `content-length`/NUL rules stay the encoder's job. The spec has the server close after an `ERROR`, which is exactly the shape of a refusal. |

**NetGet's own STOMP client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `src/client/stomp/mod.rs` writes its `CONNECT` frame and waits for `CONNECTED`
before returning — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline wraps the `read()` and nothing else**, and here that is stronger than it sounds:
`handle_frame` is awaited in the same task, so while the model is answering — or a `manual` rule
is parked for a human — nothing is being read and no clock is running. What the bound measures is
the peer's own silence. An idle close writes `ERROR` with `message:idle timeout` and logs
`decision=fail_closed_idle_timeout`.

`tests/server/stomp/connection_bounds_test.rs` drives all three from the wire against a
model-free server: the refusal is checked for its `message` header *and* its NUL terminator, and
releasing one admitted connection is checked to free exactly one slot. Replacing the
`tokio::time::timeout` around the read with the bare call makes the first test hang for its whole
70-second window and fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if either
bound is removed, and `tests/accept_bounded_test.rs` covers the shared helper.

## Not implemented

- **Heart-beating.** Negotiated `0,0`; see above.
- **Transactions.** `BEGIN`/`COMMIT`/`ABORT` are acknowledged (a receipt if asked for, a log
  line either way) and otherwise ignored. Holding a `SEND` until `COMMIT` means queueing
  messages inside the protocol, which is storage, and protocols must not implement storage. The
  `transaction` header still reaches the model in the `stomp_send` event's `headers`, so a
  handler can do whatever it likes with it.
- **Subscription bookkeeping.** The server does not remember who subscribed to what. A
  `send_stomp_message` goes to the connection whose event is being answered, and the model
  supplies the `subscription` id (the `stomp_subscribe` event gave it one). Remembering
  subscriptions would be broker state.
- **STOMP 1.0 / 1.1.** A `CONNECT` whose `accept-version` does not include `1.2` — including
  one with no `accept-version` at all, which means 1.0 — is refused with an `ERROR` naming
  `version:1.2`, as the spec asks. Answering a dialect this server does not implement would be
  the same class of lie as advertising heart-beats.
- **TLS.** Plain TCP only.

## Example prompts

```
STOMP broker on port 61613 - accept every CONNECT, and when a client subscribes to a
destination send it one MESSAGE welcoming it to that destination.
```

```json
{"type": "open_server", "port": 61613, "base_stack": "stomp",
 "event_handlers": [{"event_pattern": "stomp_connect", "handler": {"type": "static",
   "actions": [{"type": "send_stomp_connected", "session": "session-1", "server": "netget/stomp"}]}}]}
```

```json
{"type": "open_server", "port": 61613, "base_stack": "stomp",
 "event_handlers": [{"event_pattern": "stomp_subscribe", "handler": {"type": "script",
   "language": "python",
   "code": "respond([{'type': 'send_stomp_message', 'destination': event['destination'], 'subscription': event['id'], 'message_id': 'msg-1', 'body': 'welcome', 'encoding': 'utf8'}])"}}]}
```

## Verified

`tests/server/stomp/` is declared in `tests/server/mod.rs` and runs. **22 tests, 10 LLM calls**,
green on repeated runs at `--test-threads=100`:

```bash
./cargo-isolated.sh test --no-default-features --features stomp \
    --test server -- --test-threads=100 stomp
```

| File | Tests | LLM calls | Peer |
|---|---|---|---|
| `e2e_test.rs` | 2 | 7 | `async-stomp` 0.6.3 — **the Beta evidence** |
| `raw_socket_test.rs` | 2 | 3 | raw socket, for what a client cannot express |
| `codec_test.rs` | 18 | 0 | none — spec byte literals |
