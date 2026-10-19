# NATS Client Implementation

NetGet dials a NATS broker (TCP 4222 by convention) and **joins the fabric as a peer**. The
model decides what to subscribe to and what to say in reply to what arrives; NetGet owns the
socket, the framing and the keepalive.

**State**: `Beta` — verified against the official `nats-server` binary in a test that is not
`#[ignore]`d and cannot skip. See [Maturity](#maturity-what-beta-rests-on).
**Privilege**: `None`. Port 4222 is a destination here, not a bind, so nothing is privileged.
**Stack**: `ETH>IP>TCP>NATS`. **Library**: none — the codec is hand-written on `tokio`.
**Feature**: `nats`, shared with the server half.

## Protocol

1. The broker writes `INFO {json}\r\n` immediately on accept. Nothing may be sent before it
   arrives, and this client refuses the connection if the first frame is anything else.
2. NetGet writes `CONNECT {json}\r\n`, then any `subscribe_subjects` as `SUB` lines, then
   `PING\r\n` — one write, in that order. The `PING` is how a real client learns that `CONNECT`
   was accepted.
3. Then, in any order: `PUB`/`HPUB`, `SUB`, `UNSUB`, `PONG` out; `MSG`, `HMSG`, `INFO`, `+OK`,
   `-ERR`, `PING`, `PONG` in.

`MSG <subject> <sid> [reply-to] <#bytes>\r\n<payload>\r\n` — the payload is byte-counted, not
delimited, so it may contain anything including CRLF. `HMSG` adds a `<#header bytes>` count and
a `NATS/1.0\r\n…\r\n\r\n` block in front of the payload.

`parse_server_frame` decodes the **broker → client** direction. It is a different grammar from
`crate::server::nats::parse_frame`, which decodes client → server; they share no verbs except
`PING`/`PONG`, which is why they are two functions rather than one with a mode flag.

## Two tasks per connection

- **Reader** — owns the read half, frames the stream, answers `PING` with `PONG` itself, logs
  `PONG`/`+OK`/mid-session `INFO`, and forwards `MSG`/`HMSG`/`-ERR` over a **bounded** channel
  (256).
- **Dispatcher** — owns the model. One LLM call at a time, in arrival order, plus the
  injected-command channel behind the dashboard's `[ send ]`.

**Batching (`BatchingMode::On`).** Frames the broker sends while the model is answering wait on
the reader→dispatcher channel. With the client's batching on, the dispatcher takes every frame
already waiting into one `call_llm_for_client_batch` call, one event per message (at most
`MAX_BATCH_EVENTS`); off, one per call. Each event keeps its own `reply_to` and, for JetStream,
its `ack_subject`, so the model can still answer or acknowledge each delivery separately.
`tests/client/nats/batching_test.rs` holds it against a hand-written broker, off and on in one
test.

**The split exists so the keepalive cannot be blocked by a decision.** Answering `PING` in
Rust is not an optimisation: a broker that gets no `PONG` within two ping intervals declares
the connection stale and drops it, and a dashboard-created instance defaults to a `*` → manual
rule — so a single-task client would need a human to answer the keepalive, in seconds, forever.
The same reasoning is why the `nats_connected` event is dispatched *after* the reader is
running: that event can park for minutes and the connection survives it.

This is the `Idle → Processing → Accumulating` machine of `src/server/tcp/mod.rs` in a
different shape. The dispatcher being busy *is* `Processing`, the channel *is* `queued_data`,
and there is no `Accumulating` state because NATS frames are self-delimiting — so
`wait_for_more` here means "say nothing", not "the response was cut short".

Both tasks are registered with `AppState::register_client_task`, not just the reader: aborting
a task does not abort tasks it spawned. The command channel is registered **before** the
`nats_connected` event, so `[ send ]` works during a park rather than reading "no command
channel" for its duration.

### The action → event → action cycle

A `MSG` arrives, the model answers with `send_nats_publish`, the bytes go on the wire, and
whatever comes back reaches the reader as another frame and raises another event. The cycle
passes through the socket and the reader task, so **nothing recurses** and there is no
self-referential future to box — this is the `datalink` case the root `AGENTS.md` describes,
where the chain continues by itself. What bounds it is `client/llm_budget.rs`'s per-client call
budget. Do not add a `MAX_FOLLOWUP_DEPTH` here; there is no recursion to bound.

## What the model sees and controls

**Events**

| Event | Carries |
|---|---|
| `nats_connected` | `remote_addr`, `server_name`, `server_id`, `version`, `max_payload`, `headers`, `auth_required`, `tls_required`, `subscriptions` (from the startup parameter), `info` (the full INFO document) |
| `nats_message_received` | `subject`, `sid`, `reply_to`, `payload`, `payload_encoding`, `headers` |
| `nats_error_received` | `message`, `fatal` |
| `nats_permission_error` | `message`, `operation` (`publish`/`subscription`/`unknown`), `subject` |

**Actions**

| Action | Frames written |
|---|---|
| `send_nats_publish` | `PUB`, or `HPUB` when `headers` is given |
| `send_nats_subscribe` | `SUB <subject> [queue] <sid>` |
| `send_nats_unsubscribe` | `UNSUB <sid> [max]` |
| `send_nats_request` | `SUB <reply> <sid>` + `UNSUB <sid> 1` + `PUB <subject> <reply> …`, as one write |
| `wait_for_more` | nothing (a real answer: most traffic needs no reply) |
| `disconnect` | half-close |

Everything is declared in `get_async_actions()` and `get_sync_actions()` is empty. That is
deliberate: `client_llm_action_set` is the union of async ∪ sync ∪ the firing event's actions,
so a client cannot express a narrowing, and duplicating the list into both — which ~40 clients
did — buys nothing.

`-ERR` is split into two events because only one of them is actionable. A permissions
violation leaves the connection open and names the subject that was denied, so the model can
pick another; every other `-ERR` is fatal and the broker hangs up straight after.

### Payload encoding

Inbound `payload` is the text itself when every byte is printable and hex otherwise;
`payload_encoding` says which. Outbound takes the same pair (`payload` + `encoding`, `"utf8"`
default, `"hex"`), decoded **explicitly**. There is no sniffing: `"48656c6c6f"` is
simultaneously valid text and valid hex and only the sender knows which it means — the bug
`send_tcp_data` had. Echo an event's `payload` **and** its `payload_encoding` and the exact
received bytes go back out.

### Injection guards

`subject`, `sid`, `reply_to` and `queue_group` are rejected if they contain whitespace or a
control character, and header names/values are rejected for `:`/space/CR/LF. A NATS control
line is space-delimited and CRLF-terminated, so an unchecked token would forge a second frame
— a publish on a subject nobody asked for. Rejecting is louder than stripping, which is why it
rejects.

### Failure behaviour

An LLM failure writes **nothing** to the broker, and this is one of the deliberate-silence
cases. Every frame this client can send is a positive assertion — a publish, a subscription —
so inventing one because the backend was down would put fabricated traffic on somebody's
message bus. The log carries the error and tags it `decision=fail_closed_llm_error`; the wire
carries nothing. The model answering with no actions is a legitimate and distinct outcome,
logged as `decision=model_no_actions`.

## Startup parameters

| Parameter | Effect |
|---|---|
| `client_name` | `name` in the CONNECT document (default `"netget"`). Display only. |
| `verbose` | Ask for `+OK` after every command (default false). Logged at trace, never shown to the model — it is bookkeeping, not a decision. |
| `subscribe_subjects` | Subjects `SUB`bed immediately after CONNECT, sids `1..n`, reported in `nats_connected`. |

`subscribe_subjects` is not a convenience. A subscriber that waits for the model — or, on a
dashboard-created instance, for a **human** — before subscribing misses everything published in
the meantime. This is the deterministic way to be listening from the first byte.

## Not implemented

- **No TLS and no authentication.** `CONNECT` carries no credentials, and a broker with
  `auth_required: true` answers `-ERR 'Authorization Violation'` and hangs up. The
  `nats_connected` event reports `auth_required`/`tls_required` so the model knows why.
- **No reconnect and no cluster failover.** `connect_urls` from `INFO` is handed to the model
  and otherwise ignored; a mid-session `INFO` is logged, not raised as a second
  `nats_connected`.
- **JetStream** (`jetstream.rs`), when the server's `INFO` advertises it: the client
  subscribes once to its own inbox (`<inbox>.>`, sid `js`) and addresses each request's reply
  under it by what was asked, so replies become typed events with no request table —
  `nats_js_api` → `nats_js_response {operation, stream, consumer, response, error}`,
  `nats_js_publish` → `nats_js_publish_ack {stream, seq, error}`, `nats_js_fetch` → one
  `nats_js_message {…, stream_seq, consumer_seq, ack_subject}` per delivery and
  `nats_js_fetch_done {status}` when a batch ends short, `nats_js_ack` on the ack subject. A
  status line (`NATS/1.0 404 No Messages`) is exposed as `Status`/`Description` headers, as
  nats.go does. Evidence: `tests/client/nats/jetstream_test.rs` against `nats-server -js`.
- **No client-side subscription table.** `sid`s are the model's to choose and track; nothing
  here validates that a `MSG`'s sid was ever subscribed to, and `UNSUB … <max>` is sent as the
  protocol defines it and honoured by the broker, not counted here.
- **No storage.** Nothing is retained across the session or across restarts.
- **Backpressure stops the keepalive, eventually.** The reader→dispatcher channel holds 256
  frames; if the model stays slower than the fabric long enough to fill it, the reader blocks
  on `send` and stops answering `PING`. That is the deliberate trade against an unbounded queue
  that grows until the process dies, and it is the same limitation the server half documents.

## Maturity: what Beta rests on

`tests/client/nats/e2e_test.rs::test_nats_client_round_trips_through_the_official_nats_server`.
The official Go **`nats-server` 2.14**, spawned on an ephemeral loopback port, routes the
traffic; **`async-nats` 0.50** is the peer that asks the question and reads the answer. Neither
end is ours, and the reply quotes the request, so nothing canned can satisfy it.

What it proves, in order — none of which a same-project peer can show:

1. `nats-server` accepted our `CONNECT` document. It parses that document strictly, so a
   wrongly-typed field fails the session here and nowhere else.
2. We parsed a real `INFO` — one carrying a `server_id`, a `max_payload` and fields nothing in
   this project wrote.
3. `nats-server`'s own routing table matched our `SUB` and delivered to it. The subject match
   is Go's, not ours.
4. We framed the inbound `MSG`, asked the model, and published its answer on the reply subject.
5. `nats-server` routed that answer back to `async-nats`, which read it as a reply to its own
   request — so our `PUB` byte count and reply subject were right.

The test **hard-fails when the binary is missing** rather than printing `SKIP: nats-server is
not installed` and returning `Ok(())`. That gate is what keeps `kubernetes`, `oci_registry`,
`maven` and `websocket` at Experimental: on a runner without the binary it is a silent pass, so
the rating rests on nothing. `npm`'s real-CLI test is the shape being copied. It follows that
**`nats-server` must exist wherever this suite runs**, CI included.

The other three tests are same-project and are *not* what the rating rests on — they cover what
a real broker cannot show (exact outbound bytes, injected `-ERR` frames, the parser in
isolation). Read them as internal consistency checks.

`async-nats` is a client, so it could never have served as the broker; using it as the
*requesting peer* on the far side of a real server is the legitimate role for it.

**What Beta still does not claim**: TLS, authentication, reconnect and cluster
failover are all unimplemented, not merely untested. `UNSUB … <max>` counting is exercised only
by `nats-server` (NetGet's own server records the threshold without counting), and header
(`HPUB`/`HMSG`) round-tripping through a real broker is untested — the hand-written broker
covers the framing, not the routing.

## Example prompts

```
Connect to the NATS broker at localhost:4222, subscribe to orders.>, and publish a one-line
summary of every order you see to orders.audit.
```

```json
{"type": "open_client", "protocol": "NATS", "remote_addr": "localhost:4222",
 "startup_params": {"subscribe_subjects": ["service.>"]},
 "event_handlers": [{"event_pattern": "nats_message_received", "handler": {"type": "script",
   "language": "python",
   "code": "import json,sys\nd=json.load(sys.stdin)\ne=d['event']\na=[]\nif e.get('reply_to'):\n    a.append({'type':'send_nats_publish','subject':e['reply_to'],'payload':'ack: '+e.get('payload',''),'encoding':e.get('payload_encoding','utf8')})\nelse:\n    a.append({'type':'wait_for_more'})\nprint(json.dumps({'actions':a}))"}}]}
```

That script is a responder with **zero** LLM calls, and is the right default for anything
deterministic.
