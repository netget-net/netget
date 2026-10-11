# Kafka Protocol E2E Test Documentation

**Location**: `tests/server/kafka/e2e_test.rs`
**Runtime**: ~1-2 s
**LLM calls**: 7 (budget < 10)
**Client library**: none — see below

## How these tests avoid asserting NetGet against itself

A test that feeds NetGet's encoder output to NetGet's decoder proves nothing. There is also
no usable pure-Rust Kafka client in this workspace: `rdkafka` was removed because it aborts
in malloc, and adding a dev-dependency would mean editing `Cargo.toml`.

So the "client" in these tests is built from `kafka-protocol`'s **client-side** codecs —
`Encodable` on the request types and `Decodable` on the response types, both generated from
Apache Kafka's own message schemas. The broker does the opposite: decodes requests, encodes
responses. Nothing in these tests calls a function `src/server/kafka/` wrote.

`kafka-protocol` is not a dev-dependency, so it is reached through the re-export at the top
of `src/server/kafka/mod.rs`:

```rust
use netget::server::kafka::kafka_protocol::messages::{ApiKey, MetadataResponse, ...};
```

**What this validates**: NetGet's framing, request/response header version selection, body
version selection, API dispatch, event emission, action handling, and the record-batch
encode/decode round trip.

**What it does not validate**: the schemas themselves, and behaviour against a real client's
state machine — which is what `real_client_test.rs` (kcat) and `flexible_versions_test.rs`
(the Java client and franz-go) are for.

## Proof the tests can fail

Both tests were re-run against two deliberate mutations of `mod.rs`:

| Mutation | Result |
|---|---|
| `let header_version = 0;` (the original bug: hardcoded request header version) | both tests fail; server logs show `client_id=""`, the exact symptom |
| `encode_field` forced to always return hex | `test_kafka_produce_fetch_roundtrip` fails at the value assertion; the metadata test still passes |

The second mutation matters because it fails *only* the test that should fail, which means
the round-trip assertion is load-bearing rather than incidentally satisfied.

## Test 1: `test_kafka_api_versions_and_metadata`

3 LLM calls (startup + 2 metadata events). Seven stages on one server:

1. **ApiVersions v3** — asserts `error_code == 0`, the correlation id echoes, and the
   advertised table contains exactly the implemented ranges: ApiVersions 0–3, Metadata 0–12,
   Produce 0–11, Fetch 0–16, OffsetCommit 0–9. Also asserts `ListOffsets` is **absent**,
   because advertising an API with no handler is worse than not advertising it.
2. **ApiVersions v9** (unsupported) — hand-encodes the header, then asserts the reply
   decodes *at v0* with `error_code == 35` and a non-empty api_keys table. This is Kafka's
   negotiation rule; without the table the client has nothing to step down to.
3. **Metadata v8 for `orders`** — the mock returns a topic list and deliberately names **no
   broker**. Asserts `cluster_id == "netget-test"` and `controller_id == 7` (both from
   `startup_params`, and both gated on Metadata v2/v1 so a v0-only encoder would drop them),
   exactly one broker whose `node_id == 7` and whose **port equals the server's actual bound
   port**, and one partition whose `leader_id == 7`. That last pair is the "leadership points
   back at this server" check.
4. **Metadata v8 for `ghost`** — a topic the model does not describe. Asserts `error_code == 3`
   on that topic rather than it being silently absent.
5. **ListOffsets v1** on a fresh connection — asserts the broker closes the connection
   (`read` returns 0) rather than answering.
6. **Hostile length prefixes** `0, 3, -1, i32::MIN, i32::MAX` — each on a fresh connection,
   each must close cleanly. These are the sign-extension and under-minimum cases that used
   to abort the process or panic inside a detached `tokio::spawn`.
7. **ApiVersions again** — proves the broker survived stages 5 and 6.

## Test 2: `test_kafka_produce_fetch_roundtrip`

4 LLM calls (startup + produce + fetch + offset commit).

The produce and fetch mocks share one `Arc<Mutex<Vec<Value>>>`. The produce mock stores the
`records` array NetGet decoded off the wire; the fetch mock hands exactly those back as its
`fetch_response`. The final assertion — that the fetched key and value equal the bytes the
test originally encoded into the batch — therefore only holds if NetGet's produce-side
record-batch decoding and its fetch-side record-batch encoding are both correct *and* agree.

Also asserted:

- `base_offset == 42`, the offset **the model chose**, not one Rust computed. Under the old
  implementation this came from `partition.len()`.
- The produce event carried `key`/`value` as text with `value_encoding == "utf8"` — no raw
  bytes and no base64 reach the model.
- `high_watermark == 43` for one record at offset 42.
- The fetched record sits at offset 42, the offset the consumer asked from. A batch whose
  base offset is below `fetch_offset` is discarded by real consumers.
- The batch decodes with `RecordBatchDecoder` — i.e. CRC, magic byte and offset deltas are
  all right, not just the field values.
- OffsetCommit v2 returns `error_code == 0` for the right partition index.

Both tests end with `server.verify_mocks().await?` and `server.stop().await?`.

## Mock notes

- The `on_any()` startup rule is declared **last**. Rules are first-match-wins, and the
  server instruction contains the word "Kafka", so an `on_instruction_containing("Kafka")`
  rule placed first would also swallow every event request — the event rules must precede it.
- The produce/fetch/offset-commit rules use `respond_with_actions_from_event` so they can
  echo the event's own `topic`, `partition` and `fetch_offset` back. Static action JSON is
  fine for metadata, which has nothing to echo.
- `expect_calls` is set on every rule, so an extra or missing model round trip fails the
  suite rather than passing silently.

## Not covered

- Any real client — in this file. See `real_client_test.rs` and `flexible_versions_test.rs`.
- Compressed record batches (gzip/snappy/lz4/zstd). The decoder path uses `kafka-protocol`'s
  built-in codecs and should work; it is untested here.
- `acks=0`, where the broker deliberately writes no response.
- OffsetCommit v8+ from a third-party client: Java and franz-go both look up a coordinator
  first, and FindCoordinator is not implemented.
- Consumer groups, which are not implemented at all.

## `connection_task_cleanup_test.rs` — teardown reaps what the connection owned

Zero LLM calls, in-process `AppState`, `instruction: Some(String::new())`. A peer connects, a
recurring `TaskScope::Connection` task is registered against the connection the broker tracked,
the peer's socket is dropped, and once the row reaches `Closed` the test asserts
`get_connection_tasks` is empty.

Two things make it evidence rather than decoration. It asserts the task is present **while the
connection is live** first, so a run that registered nothing cannot pass by reaping nothing.
And it looks at the task map rather than at the connection row: `update_connection_status(…,
Closed)` and `close_connection_on_server` leave the row identical and differ only in whether
`cleanup_connection_tasks` ran, so the row says nothing about which one the teardown called.
Put `update_connection_status` back in `src/server/kafka/mod.rs` and it fails naming the
surviving task.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features kafka \
    --test server -- --test-threads=100 kafka
```

## References

- [Kafka Protocol Guide](https://kafka.apache.org/protocol)
- Implementation: `src/server/kafka/AGENTS.md`
- Test helpers: `tests/helpers/`

## The real client: `kcat` on librdkafka

Until September 2026 this suite's only peer was `kafka-protocol`'s own client-side codecs —
the same crate `src/server/kafka/mod.rs` frames with. That proves the crate round-trips through
itself, which is the circular case CLAUDE.md names for `websocket`/tokio-tungstenite. It is why
Kafka sat at Experimental with a full e2e suite.

`real_client_test.rs::test_kafka_produce_and_fetch_against_kcat` closes that. `kcat` 1.7 on
librdkafka 2.15 is C, and NetGet links none of it. It is **not** `#[ignore]`d and it **fails**
rather than skipping when kcat is absent. Kafka is Beta on the strength of it.

Two runs against one broker:

1. **Produce.** `kcat -P -K :` completes ApiVersions → Metadata → Produce. The test then asserts
   on what the *server* decoded out of librdkafka's v2 record batch — key `order-1`, value the
   JSON body — before going anywhere near the fetch. Without that intermediate check the fetch
   assertion would be vacuous: the broker stores nothing, so a fetch returns whatever the
   produce captured, and an empty capture would make the round trip assert against itself.
2. **Fetch.** `kcat -C -o 0 -c 1 -e` completes ApiVersions → Metadata → Fetch and prints the key
   and value back. librdkafka checks the batch CRC, the varint framing, the attributes word and
   the per-record offset deltas, so printing the body at all means this broker's v2 encoder is
   acceptable to the reference non-JVM implementation.

Four things about the invocation are load-bearing, and three of them cost a debugging pass:

- **stdin, not a file argument.** In produce mode `kcat` sends each **file** as one whole
  message, so `-K :` never splits a key off it: the first version of this test passed a temp
  file and the record arrived with `key: null` and a value of `order-1:{...}\n`, delimiter and
  trailing newline included. Line splitting and key splitting only happen on stdin.
- **`-o 0`, an absolute offset, not `-o beginning`.** Resolving `beginning` needs ListOffsets,
  which this broker does not implement — and an unsupported API key closes the connection
  rather than erroring, so the symptom would be a hang, not a message.
- **`brokers` is omitted from `metadata_response`,** so the server advertises itself. librdkafka
  connects to the address the metadata names; a fabricated `localhost:9092` sends it somewhere
  that does not exist.
- **`expect_at_least`, never `expect_calls`.** librdkafka refreshes metadata on its own schedule
  and each `kcat` run is a fresh client, so the metadata and fetch counts are not predictable.

Still unproven here: consumer groups (the APIs do not exist), the Java client, compression,
transactions, TLS/SASL, and multi-broker metadata.

## Flexible versions (`flexible_versions_test.rs`)

Apache Kafka's Java client (kafka-clients 3.9.1, run from `peer/JavaPeer.java` as a
single-file source program) and franz-go 1.18.1 (`peer/franz/`, built by `install_peers.py`
with its `go.sum` pinned) each produce one record and consume one. One python handler plays the
store; a fetch from offset 0 answers a record whose value is `served at fetch v<N>`, so the
line each client prints proves it decoded a response encoded at that version. The versions
are also read from the broker's events: both clients negotiate Metadata v12, Produce v11 and
Fetch v16, by topic id. A third test sends a Fetch v16 by an id never reported and asserts
`UNKNOWN_TOPIC_ID` without the handler being asked. Leaving the topic id out of Metadata
fails both client tests (they fall back below v13). `NETGET_KAFKA_PEERS` is mandatory.

`topic_id_cache_test.rs` holds the topic-id table's two bounds: on `TopicIds` directly (a
249-byte name is remembered and a 250-byte one is not; past `MAX_KNOWN_TOPIC_IDS` only the
oldest id goes and the rest still resolve), and on the wire, where a Metadata v12 answer
naming both lengths describes the 249-byte topic with its id, answers the 250-byte one
`UNKNOWN_TOPIC_OR_PARTITION` with no id, and a Fetch v16 by the id the long name would have
is `UNKNOWN_TOPIC_ID`. No peer needed.

The tshark oracle in `e2e_test.rs` allows expert info containing ` version. Supports v0-`:
Wireshark 4.2's Kafka dissector says that on any ApiVersions response advertising beyond
its own table, which is a statement about the dissector, not these bytes.
