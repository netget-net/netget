# AMQP Client Implementation

AMQP 0-9-1 client for RabbitMQ and other AMQP brokers, driven by `lapin`. The model decides
what to do once the connection is up; `lapin` owns the wire.

**State**: Experimental (`actions.rs`). The only broker it has been run against is NetGet's own
AMQP server (`tests/client/amqp/`). No RabbitMQ, no Azure Service Bus, no Qpid.

**Library**: `lapin` **4.0.0-rc.1** (`Cargo.toml`), a release candidate. The version and the
maturity both matter, and this file used to claim "lapin v2.6 — mature, actively maintained".

> This file was rewritten in September 2026. Everything above the rewrite was written before
> the client worked and never updated: it documented `declare_queue`, `declare_exchange`,
> `bind_queue`, `publish_message`, `start_consumer`, `ack_message` and `nack_message` — **none
> of which exist** — and then showed three of them in worked "Example LLM Interactions". Since
> `execute_action` now rejects an unknown name rather than silently returning `WaitForMore`, a
> model copying that document got hard errors. Verify anything here against `actions.rs`.

## What the model can actually do

`get_async_actions` plus `get_sync_actions`, which is the union `call_llm_for_client` offers:

| Action | Parameters | Effect |
|---|---|---|
| `open_channel` | — | `Channel.Open`, awaited to `Open-Ok`. The handle is **kept** in `AmqpSession.channels`; a `lapin::Channel` closes when its handle drops |
| `publish` | `routing_key`, `payload`, optional `exchange` | `Basic.Publish` with its content header and body. Opens a channel on demand if none is open, otherwise uses the most recently opened one |
| `consume` | `queue_name` | `basic_consume`, acking each delivery |
| `disconnect` | — | `Connection.Close` |
| `wait_for_more` | — | "that response was partial" |

Publisher confirms are not enabled, so the `PublisherConfirm` a publish returns is dropped.

Still missing: queue, exchange and binding declaration.

## Events

`amqp_connected`, `amqp_channel_opened` and `amqp_message_received`, all three genuinely
emitted (`mod.rs`) — `tests/event_emit_sites_test.rs` fails the build if that stops being true.

## The model's answer is executed, and bounded

`raise_amqp_event` used to execute nothing, with this reason: *"the connect path and the command
loop own the session, and a delivery-driven action chain would be unbounded on a busy queue."*

The first half was false — the session is an `Arc<AmqpSession>` and `apply_action` already took
it by reference. The second half is true, and the remedy for an unbounded chain is a bound, not
silence: `MAX_FOLLOWUP_DEPTH = 4`, one chain per event, with the limit reported on the status
stream. As written, a model told to consume a queue and republish what it saw was asked on
every delivery and ignored every time — this repo's single most common client defect.

`apply_action` returns an explicitly boxed `Pin<Box<dyn Future + Send>>`, because
`apply_action` → `raise_amqp_event` → `apply_action` is a cycle of `async fn`s whose opaque
return types cannot be inferred (E0391).

The depth is 4 rather than the 6 used elsewhere in the tree: this is the one client where the
event source is a *stream* the broker controls, so the cheaper bound is the safer default.

Two earlier defects on the same path, for the record:

- The connected-event actions were parsed, logged and thrown away
  (`Ok(_result) => info!("AMQP client ready after connect event")`), so `open_channel` on
  `amqp_connected` — the shape this protocol's own static-mode startup example shows — did
  nothing at all.
- `Connection::run()` is gone. It is a **blocking** call and was made from inside a tokio task,
  so it parked a runtime worker for the lifetime of every AMQP client and never noticed the
  connection closing either. A supervisor task polls `conn.status().connected()` and the
  client's presence in `AppState`, and runs the disconnect path when either goes.

## Batching (`BatchingMode::On`)

Each `consume` runs a task that takes deliveries from lapin's consumer stream, acks them and
raises `amqp_message_received`. Deliveries that arrive while the model is answering wait, whole,
in lapin's consumer buffer. With the client's batching on, the task takes every delivery already
there (`now_or_never`, at most `MAX_BATCH_EVENTS`) into one `call_llm_for_client_batch` call,
one event each; off, one delivery per call. Acks are the task's, not the model's, so batching
cannot leave a delivery unacknowledged; the follow-up chain is bounded by `MAX_FOLLOWUP_DEPTH`
as before. `tests/client/amqp/batching_test.rs` holds it against a stand-in broker written on
NetGet's own AMQP codec, off and on in one test.

## Command channel — the dashboard's `[ send ]`

Adopted, archetype **(a)**: the connection lives in an `Arc<AmqpSession>` that both the
connected-event path and the command loop hold. Every action goes through the protocol's own
`execute_action` and then the shared `apply_action`, so the dashboard and the model cannot
drift.

The channel is registered **before** the `amqp_connected` LLM call, which a manual `*` rule
parks until a human answers; `tests/client/amqp/command_channel_test.rs` guards that with
`wait_for_client_handle` before it sends anything.

| Outcome | When |
|---|---|
| `Executed { detail }` | the method completed on the wire: `Channel.Open/Open-Ok completed; channel 1 is open`, or `Basic.Publish of 19 bytes to exchange "" routing key "tasks" on channel 1` |
| `Rejected { error }` | `execute_action` refused it (unknown name, missing `routing_key`/`payload`) |
| `Disconnected` | `disconnect`; `Connection.Close` was sent |
| `Err(..)` | lapin returned an error (broker gone, channel refused) |

**There is deliberately no `Sent { bytes_sent }`.** `Channel.Open` is a real round trip — lapin
resolves it only when `Open-Ok` comes back — and `basic_publish().await` is what puts the
method, content-header and body frames on the socket. But lapin frames and writes them
internally and reports no byte count, so there is no honest number to report.

## References

- [lapin](https://docs.rs/lapin/)
- [AMQP 0-9-1 spec](https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf)
