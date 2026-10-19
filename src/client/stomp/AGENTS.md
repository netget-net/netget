# STOMP 1.2 Client Implementation

Outbound STOMP 1.2 client. It opens a session against a broker, subscribes where the model
tells it to, publishes what the model composes, acknowledges deliveries, and leaves the way the
specification says to.

**State**: Experimental — see *Why the rating is Experimental* below, which is the most
important section in this file. **Privilege**: `None`. **Stack**: `ETH>IP>TCP>STOMP`.
**Library**: none. The codec is `src/server/stomp/frame.rs`, **reused, not copied**.

## The codec is the server's, on purpose

`crate::server::stomp::frame` is `pub`, and both halves are behind the same `stomp` feature, so
this client imports `StompFrame`, `parse_frame`, `ParseOutcome` and the escaping rules directly.
Nothing about framing is reimplemented here: one `should_escape` decision, one `content-length`
rule, one NUL convention for the whole protocol in both directions.

Two things in `src/server/stomp/actions.rs` are **private** and therefore *are* reimplemented
here, which is worth knowing before someone "de-duplicates" them:

| Server (private) | Client copy | Why it could not be shared |
|---|---|---|
| `body_for_event` | `mod.rs::body_for_event` | private `fn` in the server's `actions.rs` |
| `decode_body` / `extra_headers` | `actions.rs::decode_body` / `extra_headers` | same, and the client's `extra_headers` additionally drops `destination`/`content-type`/`receipt`, which have their own named parameters here |

Both copies are deliberately byte-compatible with the server's, because that is what makes an
echo exact: a `stomp_message_received` event's `body` + `body_encoding` pasted straight into
`send_stomp_send` reproduces the original bytes. If you change one side, change the other.

## The handshake is a gate

`connect()` does not return `Ok` until the broker has answered with a well-formed `CONNECTED`
carrying a `version` header naming `1.2`. Everything else is `Err`, so `client_startup` records
`ClientStatus::Error`, the operator sees a failure, and **no `stomp_connected` event is ever
raised**:

| Broker's reply | Result |
|---|---|
| `CONNECTED` with `version:1.2` | session opens |
| `CONNECTED` with no `version` | refused, naming the missing header |
| `CONNECTED` with `version:1.1` | refused — 1.1 and 1.2 disagree about the headers this client's `ACK` uses, so proceeding would corrupt the session rather than degrade it |
| `ERROR` | refused, carrying the broker's own `message` header into our log |
| any other command | refused, naming what arrived |
| nothing, within `handshake_timeout_secs` | refused; the client never sits in `Connecting` |
| socket closed | refused |

This is exactly the strictness `async-stomp` applies to *our* server — its `Connector::connect()`
refuses to hand back a transport otherwise. The server's own `AGENTS.md` records that deleting
the `version` header from `CONNECTED` makes `async-stomp` fail while a hand-written test peer
sailed past it. This client is on the strict side of that line, and
`tests/client/stomp/e2e_test.rs` proves the check exists rather than assuming it.

## What is done in Rust and never asked of the model

| Done here | Why |
|---|---|
| frame boundaries, the NUL terminator, `content-length` | a model that gets framing wrong produces a stream no broker can resynchronise from |
| header escaping and its `CONNECT`/`CONNECTED` exemption | an unescaped `:` forges a header |
| `accept-version` / `heart-beat` negotiation | see below — neither is a decision |
| the `DISCONNECT` receipt and waiting for it | a property of the shutdown, not of what it means |
| `content-length` on `SEND` | computed from the bytes actually sent |

The model decides content: which destination, what body, `ACK` or `NACK`, when to leave.

### Heart-beating is negotiated off and there is no parameter for it

`CONNECT` always carries `heart-beat:0,0`. This client runs no heart-beat timer and never emits
a bare EOL, so any other value would be a promise it does not keep — and a broker that believes
it will hear from us every N ms tears the connection down when it does not. A `0` in our send
position also makes the negotiated interval zero in both directions under the spec's formula,
so a compliant broker stops expecting them. Inbound heart-beats (bare EOLs) *are* tolerated:
`parse_frame` reports them as `ParseOutcome::Heartbeat` and the loop drains them.

### `accept-version` names 1.2 only

Offering `1.0,1.1,1.2` would mean being prepared to speak whichever the broker picks. This
client implements 1.2 only, so it offers 1.2 only, and refuses a `CONNECTED` naming anything
else. Same rule as the heart-beat: do not advertise what you do not do.

## Graceful shutdown, and why `disconnect` is not a hang-up

`disconnect` returns `ClientActionResult::SendData` containing a `DISCONNECT` frame with a fixed
`receipt` header (`DISCONNECT_RECEIPT_ID`), **not** `ClientActionResult::Disconnect`. The read
loop closes when the matching `RECEIPT` comes back. That acknowledgement is what tells a
publisher the broker durably took everything it sent; closing the socket instead would throw
that guarantee away.

Two details:

- **The receipt id is fixed rather than model-chosen** so the loop can recognise the
  acknowledgement of *its own* shutdown without tracking any state, and so an action injected
  from the dashboard behaves identically to one the model produced. The loop peeks at the
  action's `type` (in `run_actions`, and again in the command arm before the command is moved
  into `handle_stream_client_command`) purely to start the grace timer.
- **A broker that never sends the receipt is bounded** by `DISCONNECT_GRACE` (10s). Some
  brokers close the socket the moment they see `DISCONNECT`; that path ends the loop through
  the ordinary `Ok(0)` read.

The receipt for our own `DISCONNECT` is the one `RECEIPT` that does **not** raise
`stomp_receipt_received`: reporting it would spend a model call on a connection that is already
closing and whose answer could not be written anywhere. It is logged instead.

## Events

| Event | Fields |
|---|---|
| `stomp_connected` | `version`, `session`, `server` |
| `stomp_message_received` | `destination`, `message_id`, `subscription`, `headers`, `body`, `body_encoding` |
| `stomp_receipt_received` | `receipt_id` |
| `stomp_error_received` | `message`, `body`, `body_encoding` |

`stomp_message_received.headers` carries every header that is not already a named field — in
particular the **`ack`** header, which is what `send_stomp_ack` / `send_stomp_nack` take as
their `id` when the subscription used `ack_mode: "client"` or `"client-individual"`. It is not
the `message_id`; that is the commonest way to get 1.2 acknowledgement wrong.

`stomp_error_received` is reported and then the connection closes regardless of the answer: the
specification has the broker close immediately after an `ERROR`, so nothing written in reply
would arrive. The model still gets the turn so it can record what happened.

## Actions

| Action | Frame |
|---|---|
| `send_stomp_subscribe` | `SUBSCRIBE` — `destination`, `id`, `ack_mode` → the wire header `ack` |
| `send_stomp_send` | `SEND` — `destination`, `body` + `encoding`, `content_type`, `headers` |
| `send_stomp_unsubscribe` | `UNSUBSCRIBE` — `id` |
| `send_stomp_ack` / `send_stomp_nack` | `ACK` / `NACK` — `id` (the delivery's `ack` header) |
| `wait_for_more` | nothing on the wire; a real answer, distinct from silence |
| `disconnect` | `DISCONNECT` + receipt, then close on the `RECEIPT` |

Every one of them also accepts an optional `receipt`, which comes back as a
`stomp_receipt_received` event.

All seven live in `get_async_actions()`; `get_sync_actions()` is empty, and each event type
attaches the subset that makes sense for it. That is deliberate:
`client_llm_action_set` advertises the **union** of async ∪ sync ∪ the firing event's actions,
so a client cannot express a narrowing the way a server's `ssh_auth` can — duplicating the list
into both methods (which ~40 clients do) would say nothing.

### Body encoding — explicit, never sniffed

A STOMP body may be binary, so `body` always travels with an encoding field and the executor
**decodes** it:

- inbound: `body` is text when every byte is ASCII graphic/whitespace, otherwise hex;
  `body_encoding` says which.
- outbound: `encoding` is `"utf8"` (default) or `"hex"`; anything else is an error naming the
  valid values.

There is no sniffing, deliberately — `"48656c6c6f"` is simultaneously valid text and valid hex,
and only the sender knows which it means (the `send_tcp_data` bug, `d70bb5b5`).

`content-length` supplied through the `headers` map is dropped and recomputed; so are
`destination`, `content-type` and `receipt`, each of which has its own named parameter. Allowing
both routes would make which one applies depend on map ordering, because repeated headers are
resolved first-occurrence-wins.

## Startup parameters

| Parameter | Default | Read at |
|---|---|---|
| `host` | the host part of `remote_addr` | `build_connect_frame` |
| `login` | omitted entirely | `build_connect_frame` |
| `passcode` | omitted entirely | `build_connect_frame` |
| `use_stomp_command` | `false` (send `CONNECT`) | `build_connect_frame` |
| `handshake_timeout_secs` | 20 | `read_one_frame` |

Every one is read; every one that is read is declared. All accessors propagate with `?` — an
undeclared key or a wrong-typed value produces a clean error naming the key rather than a panic
that would kill an MCP request task before it could reply.

There is **no TLS**, so `login`/`passcode` travel in cleartext. That is stated in `metadata()`
and in the parameter's own description rather than being left for someone to discover.

## No per-connection state machine, and no boxed follow-up recursion

Both omissions are deliberate and both are the *same* argument:

- **No Idle/Processing/Accumulating.** A reader task (`read_frames`) frames the stream and puts
  each whole frame on a bounded queue (`MAX_BATCH_EVENTS` deep; when it is full the reader
  stops and TCP's own backpressure holds the broker). One answering loop takes frames off it and
  is the only place the model is called, so two model calls can never overlap and there is
  nothing to track.
- **No `MAX_FOLLOWUP_DEPTH`.** The root `AGENTS.md` requires a boxed, depth-capped recursive
  call for clients whose action → event → action cycle is self-referential *in process*. This
  client's is not: every action puts a frame on the wire, and the answer arrives as another
  frame that the same read loop parses and reports. The chain continues by itself through the
  socket, exactly as `datalink`'s does through its pcap queue — the model can subscribe, be told
  about the `MESSAGE` that arrives, and publish in response, without any function here calling
  itself. The bound that matters is the one every client already has, `client/llm_budget.rs`.

If a future action ever produces a follow-up event *without* a wire round trip, that reasoning
stops holding and the boxing is required. Do not remove this paragraph instead of the code.

## Batching (`BatchingMode::On`)

Frames the broker sends while the model is answering wait on the reader's queue with their
boundaries intact. With the client's batching on, the answering loop takes every frame already
waiting into one `call_llm_for_client_batch` call, one event per frame; off, one frame per
call. Each `MESSAGE` event keeps its own `ack` header, so a batch is still acknowledged one
delivery at a time. A frame that ends the session ends the gathering: events before an `ERROR`
are reported with it and the session closes; the `RECEIPT` for our own `DISCONNECT` closes it
after the events before it are reported. `tests/client/stomp/batching_test.rs` holds it against
a hand-written broker, off and on in one test.

## Failure behaviour

A STOMP **client** has no error frame: `ERROR` is a server frame. So when netget's own model
call fails, this client writes nothing and keeps the session open — the next delivery gets
another chance — and records the failure in both the log and the status stream. Inventing wire
traffic because our backend failed would tell the broker something untrue, which is the same
reasoning that keeps the 20 deliberately-silent server protocols silent.

A framing error from the broker *is* fatal: STOMP cannot resynchronise a stream once framing is
lost, so the loop closes rather than trying to skip past it.

## Command channel (injected actions)

The answering loop carries a `tokio::select!` arm on the bounded command channel, registered via
`command_support::register_command_channel` **before** the `stomp_connected` event is handled —
a `manual` routing rule can park that event at the dashboard for minutes, and until
registration the UI reports "no command channel", which reads as a protocol limitation when it
is only a queue. `AppState::send_to_client` therefore runs any of the seven actions through the
same executor the model's go through, with no LLM call, and the dashboard's `[ send ]` button
works.

Both tasks this client spawns — the answering loop and the reader — are registered with
`AppState::register_client_task`, so `stop_client` can abort them, and the loop aborts the
reader on every exit. On every exit the handle is removed so a later `send_to_client` fails
fast instead of timing out.

## Why the rating is Experimental

**The only peer this client has ever been run against is NetGet's own STOMP server.**

That is a real exchange over a real socket between two processes, and it is worth having: it
catches genuine disagreements between the two halves. But it is *same-project* evidence. It
shows that this repository agrees with itself, not that either half matches what a broker in
the wild does — a shared misreading of the specification is invisible to it. The bar the root
`AGENTS.md` sets for Beta is "works against real clients", and by symmetry a client needs a real
*broker*.

`async-stomp` cannot close the gap: it is a client, so it can only ever be our peer's opposite
number, never ours. There is no command-line STOMP client or broker on macOS and none in
Homebrew, so the `npm`/`git` "real binary" route is not available either.

### The exact test that would earn Beta

Do not install a broker to run this; record it and let whoever has one run it.

1. Start ActiveMQ (or RabbitMQ with `rabbitmq_stomp` enabled) with the STOMP connector on
   61613. RabbitMQ needs `guest`/`guest` and a `host` of `/`, which is why `login`, `passcode`
   and `host` are startup parameters.
2. Drive this client through `start_netget_client` with a mocked model answering
   `stomp_connected` with `send_stomp_subscribe` (`ack_mode: "client"`, so the acknowledgement
   path is exercised rather than skipped) and `stomp_message_received` with
   `send_stomp_ack` + `send_stomp_send`.
3. Publish one message to the subscribed destination from the broker's own tooling
   (`rabbitmqadmin publish`, or ActiveMQ's web console) so the delivery originates outside
   netget entirely.
4. Assert, from the broker's side: the subscription exists while the client is up and is gone
   after `disconnect`; the message was acknowledged rather than redelivered (this is what
   catches an `ACK` that quotes `message_id` instead of the `ack` header — the failure is
   silent against a lenient peer); the echo the client published is readable from
   `/queue/echo` with its `content-type` and `echo-of` headers intact.
5. Assert, from the client's side: the `RECEIPT` for its own `DISCONNECT` arrived and closed
   the session, rather than `DISCONNECT_GRACE` lapsing. A test that cannot tell those two apart
   would pass against a broker that ignores receipts entirely.

The test must **fail** when the broker is absent, not skip — `npm`'s real-CLI test is the shape
to copy. A skip-when-missing gate would leave the rating resting on nothing, which is what keeps
`kubernetes`, `oci_registry`, `maven` and `websocket` out of Beta today.

## Not implemented

None of it is hidden from the broker:

- **Heart-beating.** Negotiated `0,0`; see above.
- **Transactions.** `BEGIN`/`COMMIT`/`ABORT` are not in the vocabulary. Holding a `SEND` until
  `COMMIT` means queueing messages inside the protocol, which is storage, and protocols must
  not implement storage. A model that needs transactional semantics should use the generic
  SQLite facility and publish when it is ready.
- **STOMP 1.0 / 1.1.** `accept-version` offers 1.2 alone and a `CONNECTED` naming anything else
  is refused.
- **TLS.** Plain TCP only, so credentials travel in cleartext.
- **Reconnection.** A closed session stays closed; open another client.
- **Subscription bookkeeping.** The client does not remember what it subscribed to. The model
  chose the `id` and every delivery quotes it back, so remembering it here would be state with
  no reader.

## Testing

See `tests/client/stomp/AGENTS.md`.

```bash
./cargo-isolated.sh test --no-default-features --features stomp \
    --test client -- client::stomp::e2e_test --test-threads=100
```

## References

- STOMP 1.2 specification: <https://stomp.github.io/stomp-specification-1.2.html>
- `src/server/stomp/AGENTS.md` — the other half, and the codec's own documentation
