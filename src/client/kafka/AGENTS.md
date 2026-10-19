# Kafka Client Implementation

Pure-Rust Kafka client. Produces records, fetches records, reads cluster metadata and commits
offsets against a broker.

**Status**: `Experimental`. **Port**: connects to TCP 9092 by convention; no privilege needed.
**Stack**: `ETH>IP>TCP>Kafka`. **Feature**: `kafka` (the same one as the broker).
**Spec**: [Apache Kafka protocol guide](https://kafka.apache.org/protocol).

## Wire format: shared with the broker, not reimplemented

Every byte is encoded and decoded by **`kafka-protocol`**'s code-generated codecs, reached
through the `pub use kafka_protocol` re-export at the top of `src/server/kafka/mod.rs`. This is
the same arrangement the BGP client has with `src/server/bgp/wire.rs`: one Cargo feature, one
copy of the schemas, no second implementation to keep in sync.

The direction is the opposite of the broker's. The broker decodes requests and encodes
responses; this client encodes requests and decodes responses. The only functions it borrows
from `src/server/kafka/mod.rs` are `encode_field` and `decode_field`, which decide how record
bytes are shown to a model and how a model's text becomes bytes — sharing those is what keeps
`"hex"` meaning the same thing on both ends of one connection.

## What this replaced

An `rdkafka` (librdkafka) client that was **not reachable from any `--features kafka` build**:

| Was | Now |
|---|---|
| `src/client/mod.rs` gated the module on `#[cfg(all(feature = "kafka", feature = "rdkafka"))]`, and nothing but `all-protocols` turned the implicit `rdkafka` feature on. So `--features kafka` compiled the broker and silently no client, and `open_client` answered *"rebuild with --features kafka"* to someone who had used exactly that | gated on `feature = "kafka"` alone |
| Default builds linked librdkafka, a C dependency `Cargo.toml` itself annotated as *"causes malloc crashes"* | no C dependency; `rdkafka` is gone from `Cargo.toml` entirely |
| Four E2E tests, all `#[ignore]`d, one of which had passed while the client was completely non-functional because it only asserted a log line | two E2E tests, both driving NetGet's own broker, both mutation-checked |
| `mode: "producer" \| "consumer"` startup parameter, forcing two connections to do both | one connection does both, which is how Kafka works |
| Consumer built on a `group_id` and `StreamConsumer` subscription — impossible, because group coordination is implemented by neither half | manual partition assignment and explicit offsets, which the broker does support |
| Actions documented as "Text Payloads Only — binary must be base64-encoded", which the root CLAUDE.md forbids | `key`/`value` plus `key_encoding`/`value_encoding` (`"utf8"` default, `"hex"`), decoded by `decode_field` |

## Supported surface

Exactly the five APIs NetGet's broker implements. The version used for each is negotiated —
`min(this client's ceiling, the broker's max)` — and refused outright if that lands below the
broker's minimum. Nothing is hardcoded.

| API | key | ceiling | why that ceiling |
|---|---|---|---|
| ApiVersions | 18 | v3 | falls back to decoding the same bytes at v0 if the broker refuses v3 |
| Metadata | 3 | v12 | the newest `kafka-protocol` 0.14 knows; v9+ is flexible, v10+ reports topic ids |
| Produce | 0 | v11 | the newest the crate knows; v9+ is flexible |
| Fetch | 1 | v16 | v12+ is flexible; v13+ names the topic by id — learned from every Metadata answer (the one at connect included), so a described topic costs no extra round trip, else looked up once; a broker that reports no id is fetched by name at v12 |
| OffsetCommit | 8 | v9 | v8+ is flexible; a commit outside any group (generation/epoch -1) means the same at every version |

**Not implemented, because the broker does not implement them either**: `ListOffsets`,
`FindCoordinator`, `JoinGroup`, `SyncGroup`, `Heartbeat`, `LeaveGroup`, `OffsetFetch`, and every
admin API. Consequences, stated plainly:

- **No consumer groups.** Partitions are assigned manually via the `topics` + `partition`
  startup parameters, or implicitly by any `fetch_records` action.
- **No `auto.offset.reset`.** Resolving earliest/latest needs `ListOffsets`. A consumer starts
  at `start_offset` (default 0).
- `commit_offset` sends a bare `OffsetCommit` with generation `-1` and an empty member id. No
  broker that implements groups would accept it as a group commit, and it is not claimed to be.

## ApiVersions negotiation

The request goes out at v3. Kafka's own rule for a broker that does not implement that version
is to answer `UNSUPPORTED_VERSION` **plus the supported-API table**, encoded at v0 so the client
can always read the message telling it what to step down to. So the reply is decoded at v3
first, then at v0 from the same bytes, and the table is used either way. A reply that refuses
*and* carries no table is a hard failure — there would be nothing to step down to.

## Connection model

One `tokio::sync::Mutex` guards the whole connection, held for the duration of one
request/response exchange. Kafka multiplexes on a single TCP connection and matches replies by
correlation id; serialising the exchange makes that match trivially unambiguous without running
a demultiplexer task. The mutex is **not** held across an LLM call — the event is built, the
guard is dropped, and only then is the model consulted. Every socket operation carries a 30s
timeout, so a silent broker cannot hold the lock forever.

Requests are correlation-id checked on the way back. A mismatch is fatal: the connection is
desynchronised and continuing would attribute one reply to another request.

## Events and actions

`get_async_actions` and `get_sync_actions` return the same list. That is not laziness:
`call_llm_for_client` builds the model's tool list from **`get_async_actions` alone**, so an
action declared only in the sync list is never offered and is rejected as unknown if the model
returns it anyway.

| Event | Fires |
|---|---|
| `kafka_connected` | ApiVersions negotiated and the first Metadata answered. Carries brokers, topics with their partitions, and the negotiated versions |
| `kafka_records_received` | a Fetch returned **at least one** record. An empty poll raises nothing, so idling costs no model call |
| `kafka_message_delivered` | the broker answered a Produce, success **or** failure. `delivered` is true only when `error_code` is 0 |
| `kafka_metadata_received` | a `list_topics` action was answered |

| Action | Does |
|---|---|
| `produce_message` | one record to `topic`/`partition`, with `key`/`value` and their encodings, `acks` 1 (default), -1 or 0 |
| `fetch_records` | read from an explicit `offset`, or from the tracked position. Also adds the partition to the poll set |
| `list_topics` | Metadata request, all topics or a named list |
| `commit_offset` | OffsetCommit for one partition. `offset` is required — committing an offset nobody named would acknowledge consumption that may not have happened |
| `disconnect` | close the connection |
| `wait_for_more` | do nothing, keep the connection open |

`acks: 0` is the one action that reads no reply, because Kafka specifies that the broker writes
none. It raises no `kafka_message_delivered` and says so in its own description.

### Handler loop

Events are processed from a **queue, not by recursion**. A produce raises
`kafka_message_delivered`, whose handler may produce again; done recursively that is the shape
that made the DNS client overflow its stack after 211 model calls (`IMPROVEMENTS.md` item 49).
The per-client LLM budget (`src/client/llm_budget.rs`, 100 calls) bounds the total; the queue
bounds the stack.

### Failure is reported, never softened

- A Produce with a non-zero `error_code` logs at ERROR and raises the event with
  `delivered: false`. It is never presented as a quieter success.
- A Fetch whose response or partition carries an error fails the action rather than returning an
  empty batch that reads like "nothing new".
- A refused `commit_offset` fails the action.
- Transport-level failures (I/O error, timeout, desynchronised correlation id) end the session
  and set `ClientStatus::Error`; a merely refused request leaves the session healthy.

## Startup parameters

| Name | Default | Notes |
|---|---|---|
| `client_id` | `netget-kafka-client` | sent in every request header |
| `topics` | none | topics to describe at connect and then poll. Omit to connect without consuming |
| `partition` | 0 | the partition polled for each topic; 0-1024 |
| `start_offset` | 0 | where polling begins; there is no earliest/latest |
| `poll_interval_ms` | 1000 | delay *between* rounds, minimum 50. The first round runs immediately |
| `group_id` | `netget-consumer-group` | used by `commit_offset` when the action names none |

All are validated before the TCP connect, so a bad value fails `open_client` with a message
naming the key rather than half-starting a client. `mode` is **gone**: one connection produces
and consumes, and a parameter that only picked which half of the client existed had no meaning
once the client stopped being two clients.

## Limitations

1. **Run against Apache Kafka 3.9.1** (`tests/client/kafka/real_server_test.rs`), the client
   is Beta on that evidence. Redpanda and multi-broker clusters are untried. A commit goes to
   the bootstrap broker as a simple commit; on a cluster whose coordinator for the group is
   another broker it would be refused (no FindCoordinator).
2. **No consumer groups, no `ListOffsets`** — see above.
3. **No SSL/SASL.** Plaintext only.
4. **No transactions and no idempotent producer.** `producer_id` is -1.
5. **Produce is one record per request** and uncompressed. Compressed batches *are* decoded on
   the fetch path, via `kafka-protocol`'s built-in gzip/snappy/lz4/zstd codecs.
6. **No record headers.** They are neither sent nor surfaced.
7. **The poll loop's timed rounds are not covered by E2E tests.** NetGet's non-interactive
   *client* mode exits about 500ms after the prompt is handled (`src/cli/non_interactive.rs`
   only enters a keep-alive loop for `Mode::Server`), so only the immediate first round fits in
   a test. The loop's body — `fetch()` — is covered; its scheduler is not.
8. **`stop_client` aborts the task but the socket closes by drop**, in common with every other
   client.

## Testing

`tests/client/kafka/` — see its CLAUDE.md. Two mocked E2E tests, both driving a mocked NetGet
Kafka broker over a real socket, both mutation-checked.

## References

- [Apache Kafka Protocol Guide](https://kafka.apache.org/protocol)
- [`kafka-protocol` crate](https://docs.rs/kafka-protocol/) — `Cargo.toml` pins 0.14
- Broker half: `src/server/kafka/AGENTS.md`

### Dashboard injection (`[ send ]`)

`connect_with_llm_actions` registers a command channel
(`client::command_support::register_command_channel`) and spawns `Session::command_loop`
**before** the `kafka_connected` LLM call, which a manual `*` rule can park for minutes.

Kafka frames are read with `read_exact`, which is not cancellation-safe, so commands are
drained by their own task (registered with `register_client_task`) rather than a `select!`
arm. The two are serialised by the connection mutex the exchange already takes.

Injected actions go through `Session::perform` — the exact function `drive` uses for
LLM-produced actions — so there is no second copy of the wire encoding.

**Outcome semantics.** `KafkaConn::write_frame` records the size of the frame it just wrote in
`last_request_bytes`, and `produce`/`fetch`/`commit`/metadata read it back **while still
holding the connection mutex**. That is why the reply is a genuine
`ClientSendOutcome::Sent { bytes_sent }` and not a counter snapshot racing the poll loop.
A broker that refuses the request is an `Err`, never a quieter `Sent`; a fatal error also
marks the client `Error` and drops the handle. A follow-up event (Produce ack, Fetch result,
Metadata) is handed to `drive` in its own registered task rather than inline, so a handler
parked for a human cannot block the next injected command. `close()` and `mark_error()` both
call `remove_client_handle`, which is also what ends `command_loop`.

Test: `tests/client/kafka/command_channel_test.rs` (zero LLM calls; a NetGet broker answers
through one `*` static rule).

### Batching: Unsupported

The client is pull-based: the poll loop fetches only between model calls, and the next Fetch
returns everything produced meanwhile as one `kafka_records_received` event's record list.
Every other event is the reply to the client's own request. Nothing arrives while the model
is answering, so there is nothing for batching to collect.
