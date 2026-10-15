# Kafka Protocol Implementation

## Status: EXPERIMENTAL

`DevelopmentState::Experimental` (`src/server/kafka/actions.rs`). It was `Incomplete` until
this pass, for three disqualifying reasons that are all fixed: ApiVersions advertised an
empty API list so no client could negotiate, every decode and encode was hardcoded to
version 0 so every request body after `client_id` was garbage, and the LLM was never called
so all nine actions and all four event types were dead.

It is now Beta, and three independent clients complete against it: librdkafka (kcat), Apache
Kafka's own Java client 3.9.1 and franz-go 1.18.1 — see [Testing](#testing) and "Flexible
versions and topic ids" below.

## Supported surface — this is the whole of it

| API | key | versions | answered by |
|---|---|---|---|
| ApiVersions  | 18 | 0–3  | Rust, no LLM call |
| Metadata     | 3  | 0–12 | LLM / script / static handler |
| Produce      | 0  | 0–11 | LLM / script / static handler |
| Fetch        | 1  | 0–16 | LLM / script / static handler |
| OffsetCommit | 8  | 0–9  | LLM / script / static handler |

`SUPPORTED_APIS` in `mod.rs` is the single source of truth: ApiVersions is generated from
it and the dispatcher validates against it, so the advertised table and the implemented set
cannot drift apart.

The ceilings are the newest versions `kafka-protocol` 0.14 knows, flexible (tagged-field)
versions and the topic-UUID versions (Metadata v10+, Fetch v13+) included. Anything above
them is refused rather than mis-encoded.

### Flexible versions and topic ids

The codec does the flexible encoding; what the broker had to add was topic ids. NetGet
stores no topics, so there is nowhere to keep an id assigned at creation: `topic_id(name)`
derives one from the name (two FNV-1a hashes, RFC 9562 version nibble 8), so the same name
gets the same id across connections and restarts, as a real broker's stored id would.
Metadata v10+ reports it, and the broker remembers the most recent 4096 it reported
(`MAX_KNOWN_TOPIC_IDS`, in `TopicIds`) so a Fetch v13+ or a Metadata v12 request naming a
topic **by id alone** can be answered. Past 4096 the oldest id is forgotten, one at a time —
a forgotten id costs a client one `UNKNOWN_TOPIC_ID` and a metadata refresh. The names come
from the model, so a topic named over Kafka's own 249-byte limit (`MAX_TOPIC_NAME_LEN`) is
left out of the Metadata answer and never remembered; if the client asked for it, it is
answered `UNKNOWN_TOPIC_OR_PARTITION` like any topic the model did not describe. An id it
never reported is `UNKNOWN_TOPIC_ID` (100), and the handler is not asked. The produce, fetch and offset-commit events carry `api_version`.

Which client speaks what, measured: librdkafka 2.3 (kcat) negotiates Metadata v12, Produce
v7 and Fetch v11; Apache Kafka's Java client and franz-go both take Metadata v12, Produce
v11 and Fetch v16. Wireshark 4.2's dissector stops at Metadata v9, Produce v8, Fetch v11
and OffsetCommit v8 and warns on an ApiVersions response advertising more, which the
pcap-oracle test allows by name.

**Not implemented, and not advertised**: `ListOffsets`, `FindCoordinator`, `JoinGroup`,
`SyncGroup`, `Heartbeat`, `LeaveGroup`, `OffsetFetch`, and every admin API. The practical
consequence is worth stating plainly:

- **Consumer groups do not work.** Group coordination needs FindCoordinator/JoinGroup/
  SyncGroup/Heartbeat. A consumer must use manual partition assignment.
- **`auto.offset.reset` cannot be resolved**, because that needs ListOffsets. A consumer
  must fetch from an explicit offset.
- A committed offset is acknowledged and then forgotten, because there is no storage and
  OffsetFetch does not exist.

## What happens to everything else

Nothing is answered with a body this broker cannot build correctly.

- **Unknown API key** → ERROR log + status message, connection closed.
- **Known API key at an unsupported version** → same. Real brokers close the connection
  here too.
- **ApiVersions at an unsupported version** → the one exception, and it is Kafka's own
  rule: reply `UNSUPPORTED_VERSION` (35) *plus the supported-API table*, both encoded at
  v0, which every client can parse. That is how a client steps down to a version this
  broker implements. Encoding that reply at the requested version would leave the client
  unable to read the message telling it what to do.

The old `create_error_response`, which wrote a bare `i16` as an entire response body — not
a valid body for any Kafka API — is gone.

## Version handling

`api_key`, `api_version` and `correlation_id` are read from fixed offsets in the first
eight bytes, before any decode. Then:

- request header ← `ApiKey::request_header_version(api_version)`
- request body ← `api_version`, decoded from the *same cursor* the header left
- response header ← `ApiKey::response_header_version(api_version)`
- response body ← `api_version`

Because `correlation_id` sits at a fixed offset in every request header version, the error
paths echo it without having decoded a header. `correlation_id` is echoed on every path,
including the ones that then close the connection.

## LLM integration

Each request unit raises one event through `call_llm`, which is also where script and
static `event_handlers` are dispatched — so all three handling modes work here exactly as
they do elsewhere.

| Event | raised | expects |
|---|---|---|
| `kafka_metadata_request`      | once per Metadata request | `metadata_response` |
| `kafka_produce_request`       | once per (topic, partition) | `produce_response` |
| `kafka_fetch_request`         | once per (topic, partition) | `fetch_response` |
| `kafka_offset_commit_request` | once per (topic, partition) | `offset_commit_response` |

`error_response` is accepted for all four. The first recognised action wins, so a refusal
is never overridden by a later success.

A Produce or Fetch naming many partitions therefore costs many model round trips.
`MAX_UNITS_PER_REQUEST` (64) caps that; units beyond it are rejected with
`UNKNOWN_SERVER_ERROR` without consulting the model, so an attacker cannot use one frame to
amplify requests against the model backend.

There are **no async actions**. Kafka is pull-based — a broker cannot push a record to a
consumer, only answer a Fetch — and this broker stores nothing, so there is no topic list
to create or delete against. The previous `publish_message`, `create_topic`, `delete_topic`
and `set_retention` had no implementation and could not have had one; they are deleted
rather than left as documentation of a lie.

## Failure is refusal

If the model returns nothing usable, the client gets the correct response *type* carrying an
error code. Silence never becomes success:

- Produce: the failure code, `base_offset = -1`.
- Fetch: the failure code, empty record set.
- OffsetCommit: the failure code.
- Metadata: every topic the client *asked about* comes back with it. A topic the client
  asked about that the model simply did not describe comes back `UNKNOWN_TOPIC_OR_PARTITION`
  (3) — omission is reported, never silently dropped.

An `error_response` carrying `error_code: 0` is a contradiction and is rewritten to -1 with
a WARN, so a refusal can never be mistaken for an acknowledgement.

**A saturated backend is not a broken broker.** The three ways of getting no usable answer
are distinct on the wire and in the log:

| what happened | wire | log tag |
|---|---|---|
| the LLM backend is at capacity | `REQUEST_TIMED_OUT` (7), which every Kafka client treats as **retriable** | `decision=fail_closed_llm_error class=overloaded` |
| the backend erred or timed out | `UNKNOWN_SERVER_ERROR` (-1), permanent | `decision=fail_closed_llm_error class=unavailable` |
| the handler ran and produced nothing usable | `UNKNOWN_SERVER_ERROR` (-1), permanent | `decision=model_silent` |
| the model deliberately refused | its own `error_response` code | `decision=model_reject` |

Collapsing all of these onto -1 made an overloaded backend look like a broken broker, so a
client recorded a permanent fault where it should have backed off and retried. The `class=`
comes from `crate::utils::WireFailure`, which classifies the error without ever rendering it
— the error text goes to the log, the peer gets a code.

**The one default.** A Metadata reply always carries at least one broker, and if the model
names none it is this server's own `advertised_host` and bound port, with `broker_id` as the
node id and the default partition leader. That is transport truth the model has no way to
know, and no client can proceed without it. A topic the model lists with zero partitions is
given one partition led by this broker for the same reason (logged at DEBUG). Neither
invents a topic; both only make a topic the model *did* declare usable.

## No storage

`topics` and `consumer_offsets` — an in-Rust broker database written from unauthenticated
network input and never evicted — are gone. `KafkaServer` now holds `cluster_id`,
`broker_id` and `advertised_host`, all fixed at startup.

There is no per-connection or per-server offset bookkeeping either. A Fetch returns exactly
the records the handler supplied for that request; if the model wants a consumer to advance,
it returns different records next time. The only transport state is the record offsets
*within one response*, which are derived from the request's `fetch_offset` and not retained.

## Record encoding

Record keys and values are bytes; models cannot produce or read base64. Following the
pattern TCP settled on, the encoding is stated explicitly rather than sniffed:

- **Inbound** (produce events): each record carries `key`/`value` plus `key_encoding`/
  `value_encoding`, which is `"utf8"` when the bytes were printable text and `"hex"`
  otherwise. Values are truncated to 1 KiB and at most 20 records are described.
- **Outbound** (`fetch_response`): each record may carry `key_encoding`/`value_encoding`
  (or a single `encoding` for both), defaulting to `"utf8"`. `"hex"` **is** decoded —
  `decode_field` is the executor, so the documented encoding and the implementation agree.
  Invalid hex fails the whole partition with `UNKNOWN_SERVER_ERROR` rather than putting
  literal ASCII on the wire.

Fetch offsets are made contiguous from the batch base, which is never below the request's
`fetch_offset`. Kafka's v2 batch stores per-record offset *deltas* and the encoder requires
`offset - sequence` to be constant across a batch, so honouring arbitrary gaps would split
or corrupt it. A rewritten offset is logged at DEBUG.

## Startup parameters

- `cluster_id` (string, default `"netget-kafka-1"`) — reaches the wire at Metadata v2+;
  earlier Metadata versions have no such field.
- `broker_id` (number, default 0) — node id, controller id and default partition leader.
- `advertised_host` (string) — host advertised in Metadata when the model names no broker.
  Defaults to the bound IP, or `localhost` when bound to a wildcard address, because
  `0.0.0.0` is not a connectable address.

`auto_create_topics`, `default_partitions` and `log_retention_hours` are **removed**. All
three were parsed and never read, and with no storage none of them has a meaning. Passing
one now produces a clean startup error naming the key.

## Bounds and DoS surface

Kept from the earlier audit and still enforced:

- Size prefix read with `read_exact` into a fixed `[u8; 4]`; validated against
  `MIN_REQUEST_BYTES` (8) and `MAX_REQUEST_BYTES` (100 MiB) **in i64** before any
  allocation, so neither sign extension nor `4 + len` can wrap. The read buffer only ever
  grows.
- Partition indices outside `0..=MAX_PARTITIONS` (1024) are rejected with error 3, on both
  the produce path and the metadata path.
- TRACE hex dumps capped at `MAX_TRACE_HEX_BYTES` (4 KiB) in both directions.
- Accept loop breaks on error instead of spinning.
- Connections are closed through `AppState::close_connection_on_server` when their task ends,
  which marks the row `Closed` **and** reaps the connection's scheduled tasks. This used to be
  `update_connection_status(…, Closed)`: the same row, the same status, and none of the
  reaping, so a `TaskScope::Connection` task outlived the socket that owned it — and a
  *recurring* one kept ticking, each tick an LLM prompt about a peer that had hung up. The
  distinction is invisible from the dashboard, since both leave the row looking identical;
  `tests/server/kafka/connection_task_cleanup_test.rs` asserts the reaping directly.

Added this pass:

- `MAX_UNITS_PER_REQUEST` (64) caps model round trips per frame.
- `MAX_RECORDS_PER_FETCH` (1000) and `MAX_FETCH_PAYLOAD_BYTES` (8 MiB) cap what a handler
  can make the broker encode.
- Byte and packet counters are now updated, so connection stats no longer read zero.
- A record batch that fails to decode returns `CORRUPT_MESSAGE` (2). It used to be replaced
  by an empty placeholder record and acknowledged with `error_code(0)` — the producer was
  told its data was durable after it had been silently dropped.

There are no `unwrap()`s on parsed bytes anywhere in the module.

**The bounds that were not NetGet's to enforce live in the decoder, and the decoder is
vendored for them.** `kafka-protocol` 0.14.1 sized allocations from peer-supplied numbers
before reading the bytes they describe. An allocator failure aborts the whole process: not a
panic, so `tokio::spawn` cannot contain it and `panic_log` never sees it, and the frame-size
check above cannot help because each lever is a tiny, legitimately sized frame:

- **Arrays** — `Vec::with_capacity(n)` from the wire count, so a Metadata v1 request of
  **18 bytes** whose topics array declares `0x7fffffff` entries asked for ~144 GiB.
- **Record batches** — every Produce request's batches are decoded here (and the client
  decodes every Fetch response's the same way). `records.reserve(record_count)` took the
  batch's `i32` count as given, so a **61-byte** batch with a correct CRC declaring
  `0x7fffffff` records reserved hundreds of GiB; each record's header count did the same.
- **Snappy** — a snappy batch's 5-byte length header made the decompressor zero-fill up to
  4 GiB before decoding anything.
- **Owned byte/string decoders** — `vec![0; n]` from a declared length. No generated message
  reaches these in 0.14.1; they are bounded anyway.

The `netget-kafka-protocol` fork (github.com/netget-net/kafka-protocol-rs) bounds every count by `buf.remaining()` (each element costs at least
one byte), refuses every declared length the buffer cannot hold before allocating it, and
caps a snappy header at 32× the compressed input. `NETGET.md` there lists each patched
site and the upgrade steps; `tests/vendored_kafka_protocol_patch_test.rs` fails if Cargo
builds anything else, if a patched line goes missing, or if any allocation-sizing call in the
vendored source cannot be classified as bounded; and
`tests/server/kafka/declared_array_length_test.rs` sends the 18-byte Metadata request and a
Produce request carrying the 61-byte batch to a running broker and decodes each hostile batch
beside a well-formed control. The reproduction is one `sed` away: removing the array bound
makes the ratchet's decode test die with `memory allocation of 154618822584 bytes failed`.

**Still open in the decoder:** gzip, lz4 and zstd inflate whatever the data inflates to (a
compression bomb inside the 100 MiB request cap inflates in full), and legacy (magic 0/1)
nested compressed messages recurse with no depth bound. See `README.netget.md`.

## Compression

`RecordBatchDecoder::decode_with_custom_compression(.., None)` selects `kafka-protocol`'s
built-in codecs, and the crate's default features enable gzip, snappy, lz4 and zstd. An
earlier note in this file claimed passing `None` made every compressed batch fail; that was
wrong — `None` means "use the built-ins", not "no decompression".

## Testing

`tests/server/kafka/e2e_test.rs`, 2 tests, ~1-2 s, 7 LLM calls.

There is no usable pure-Rust Kafka client here (`rdkafka` was removed for malloc aborts;
adding a dev-dependency would mean editing `Cargo.toml`), so the tests build requests and
decode responses with `kafka-protocol`'s **client-side** codecs — the opposite direction
from this module's encoders — reached through the `pub use kafka_protocol;` re-export in
`mod.rs`. That validates NetGet's framing, version negotiation, dispatch, event emission
and action handling against schemas generated from Apache Kafka's own message definitions.
It does **not** validate those schemas, and it is not a substitute for driving a real
client. See `tests/server/kafka/AGENTS.md`.

## Dashboard injection (peer handle)

Every connection registers a peer handle (`server::peer_support`) **before its first read**,
so the dashboard shows `[ message this peer ]` / `[ disconnect this peer ]` on a live broker
connection. Before the first read is the point that matters: Kafka is client-speaks-first and
the broker says nothing until a request arrives, so a `*` manual rule parks the connection's
very first request — and the operator being asked to answer it must be able to reach, or hang
up, the connection while it waits.

The socket is split with `tokio::io::split` (never cloned) and the write half is an
`Arc<Mutex<WriteHalf>>` shared by the session and the peer-command task. `write_frame` takes
one lock for the whole frame, because the size prefix and the body are a single unit on the
wire and an injected write landing between them would desynchronise the client for the rest of
the connection.

- **`[ disconnect this peer ]`** works: it injects a bare `{"type": "close_connection"}`,
  which `execute_action` maps to `ActionResult::CloseConnection`. That arm exists for this
  button alone and is deliberately **not advertised** in `get_sync_actions`/`get_async_actions`
  — Kafka has no close message, so the model has nothing to gain from it and the tool list
  stays as it was. The generic peer task half-closes the write side; the reader's
  `UnexpectedEof` path runs the normal teardown and the peer reads EOF.
- **Custom-result gap:** all five wire verbs (`metadata_response`, `produce_response`,
  `fetch_response`, `offset_commit_response`, `error_response`) return `ActionResult::Custom`,
  never `ActionResult::Output`, because a Kafka response is `(size)(correlation_id)(body)` and
  the correlation id belongs to the **request being answered** — an out-of-band injection is
  answering none. The generic peer task therefore reports an injected wire verb as `Executed`
  and writes nothing. No bespoke path is provided: a response carrying an invented correlation
  id is matched to the wrong in-flight request by every client, which is worse than not
  writing. Wire replies stay driven by the read loop, where the id is known.
- Connection counters (`update_connection_stats`) were already updated on every request read
  and every response write, size prefix included, and still are. Bytes written by the generic
  peer task are not counted here (that is `peer_support.rs`'s job).

`tests/server/kafka/peer_inject_test.rs` proves all of it with zero LLM calls.

## Route to Beta

1. Drive it with a real client (librdkafka via a scratch binary, or the Java console
   producer/consumer) and fix what breaks.
2. Add `ListOffsets` so `auto.offset.reset` resolves; that alone makes a normal
   assign-based consumer work out of the box.
3. Add `FindCoordinator` + `JoinGroup` + `SyncGroup` + `Heartbeat` + `OffsetFetch` if
   consumer groups are wanted. This is the large one, and it needs the model to hold group
   state across requests — server memory rather than Rust storage.
4. ~~Raise the version ceilings past the flexible boundary~~ — done: Metadata v12, Produce
   v11, Fetch v16 and OffsetCommit v9, topic ids derived from names (see above).

## References

- [Apache Kafka Protocol Guide](https://kafka.apache.org/protocol)
- [kafka-protocol Rust Crate](https://docs.rs/kafka-protocol/) — `Cargo.toml` pins 0.14
- [Kafka Error Codes](https://kafka.apache.org/protocol.html#protocol_error_codes)
- Testing notes: `tests/server/kafka/AGENTS.md`

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/kafka/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_REQUEST_READ_TIMEOUT` | 30s | Kafka is client-speaks-first with no broker greeting, and every real client opens with `ApiVersions` — `librdkafka`, the Java client and `kcat` all send it inside the connect path. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 600s | Not a guess: it is `connections.max.idle.ms`, the setting real Kafka ships with exactly this job at exactly this default. A producer between batches or a consumer between long polls is legitimately silent for minutes, and copying the broker's own number is the one choice no real client can be surprised by. |
| `MAX_CONNECTIONS` | 256 | Each connection may buffer up to `MAX_REQUEST_BYTES` (100 MiB). Refusal: **a plain close**, which is what a real broker does. Every Kafka response is `(size)(correlation_id)(body)` and the correlation id belongs to the request; a refused peer has sent none. Brokers hitting `max.connections` close without a word for the same reason. |

**NetGet's own Kafka client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `src/client/kafka/mod.rs` sends an `ApiVersions` frame and then a `Metadata`
frame unconditionally before any model turn — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** The deadline wraps the `read()` call in this protocol's own loop, and everything that can legitimately take minutes happens after it returns. Both the size-prefix read and the announced-body read are bounded, so a peer that declares a request size and then stalls is closed too. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.
