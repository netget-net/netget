# Kafka Client E2E Testing

## Strategy

A mocked NetGet **broker** speaks Kafka to a mocked NetGet **client** over a real socket, in two
processes. The client encodes requests and decodes responses; the broker does the opposite. So
every assertion below is about content that crossed the wire and was decoded by the *other*
codec — never `output_contains`, which a failure message satisfies just as well as a success.

| Test | Asserts | LLM calls |
|---|---|---|
| `test_kafka_client_produces_a_record_the_broker_decodes` | the `records` array the broker decoded from the client's v2 record batch has `key == "order-1"` / `key_encoding == "utf8"` / `value == the JSON sent` / `value_encoding == "utf8"`; the client's `kafka_connected` carries `topics` containing `orders`; the client's `kafka_message_delivered` carries `base_offset 42` and `delivered true` | 6 |
| `test_kafka_client_fetches_polls_and_commits` | the broker sees exactly two fetches, at offsets 0 and 1; the client's `kafka_records_received` carries the payload **and** `next_offset 1`; the broker sees exactly one OffsetCommit, for offset 1 | 8 |

**Total: 14 LLM calls, ~7s.** Run:

```bash
CARGO_TARGET_DIR=/tmp/clients-target ./cargo-isolated.sh test --no-default-features \
    --features kafka --test client -- --test-threads=100 kafka
```

## Why the assertions are where they are

**The hex key.** The producing handler is given the key as `"6f726465722d31"` with
`key_encoding: "hex"`. If the client failed to call `decode_field` — the exact defect the root
CLAUDE.md names as its reference case, where documentation promises hex and the executor does
`as_bytes()` — the broker would report that literal string and the assertion would fail. The
value goes the other way, as plain text, so one record covers both encodings.

**`base_offset 42`.** That offset is chosen by the *broker's* model. The client has no other way
to know it, so the rule matching on it fires only if the Produce response really came back and
decoded.

**`next_offset 1` and fetch offsets `[0, 1]`.** The broker hands back one record at offset 0,
and only to a consumer asking from offset 0. The handler then commits and asks for more
*without naming an offset*, so the second fetch carries whatever the client worked out for
itself. Getting 1 requires decoding the record batch, reading the record's own offset out of it
and adding one — a client that forwarded bytes or guessed could not produce it.

## Mutation-checked

Both tests were re-run against deliberate mutations of `src/client/kafka/mod.rs`:

| Mutation | Result |
|---|---|
| `decode_field(data.get("key"), "utf8")` — ignore the declared `key_encoding` | `test_kafka_client_produces_a_record_the_broker_decodes` fails with `left: Some("6f726465722d31") / right: Some("order-1")` |
| `let next_offset = last_offset;` — do not advance past what was read | `test_kafka_client_fetches_polls_and_commits` fails with `left: [0] / right: [0, 1]`, plus `Rule #1: Expected 2 calls, got 1` and `Rule #2: Expected 1 calls, got 0` |

Each mutation fails only the test that should fail, which is what makes the assertions
load-bearing rather than incidentally satisfied.

## Harness quirk worth knowing

The mock server evaluates a `respond_with_actions_from_event` generator **twice per request** —
once inside `report_routing_inconsistencies` and once to build the answer
(`tests/helpers/mock_ollama.rs`). A generator that *appends* to a list therefore records every
value twice; the first version of the second test asserted `[0, 1]` and saw `[0, 0, 1, 1]`.

What each generator observes is still exactly what arrived on the wire — only the multiplicity
is an artefact. So the captures here are `BTreeSet`s, and the counts come from `expect_calls` on
the rules, which are incremented once per request by `record_call`. The Kafka *server* suite is
unaffected because its generator assigns (`*lock = ...`) rather than appending.

## Mock notes

- The `on_any()` startup rule is declared **last** in both configs. Rules are first-match-wins,
  so a rule that matches anything placed first would swallow every event request.
- Client startup parameters live in the `open_client` action's `startup_params`, not in the
  prompt: the mock decides them, the model's wording does not.
- `poll_interval_ms` in the second test is 60000, far longer than the test window. That is
  deliberate — see below.

## Why the poll loop's *timer* is not tested

NetGet's non-interactive **client** mode exits about 500ms after the prompt is handled:
`run_non_interactive` (`src/cli/non_interactive.rs`) enters a keep-alive loop only when
`state.get_mode() == Mode::Server`. A client process therefore cannot outlive a second timed
poll round, and an earlier draft of the second test failed for exactly that reason — the broker
saw zero fetches, because the first round was scheduled after a sleep the process did not
survive.

Two consequences:

1. `poll_loop` now runs its first round **immediately** and sleeps only between rounds. That is
   better behaviour independently — a consumer should not sit idle for an interval before its
   first read — and it is what makes the second test possible at all.
2. The interval is set beyond the test window so that exactly one round happens and the
   assertions are deterministic. The loop's body is covered; its scheduler is not.

## What these replaced

Four `#[ignore]`d tests. Their stated premise — that no Kafka client was compiled into any
`--features kafka` build — was correct and is now fixed, so the ignores are gone rather than
re-worded. Two of the four were additionally written against consumer groups, which neither the
client nor the broker implements; there was no version of them that could have passed.

`test_kafka_client_protocol_detection` is not carried over. It asserted `client.protocol ==
"Kafka"`, a string the harness parses out of a log line NetGet prints *before* the connect is
attempted — it passed with the client entirely non-functional. Both surviving tests still check
that field, but only alongside assertions that require bytes to have moved.

## Not covered

- Redpanda, or a multi-broker Kafka cluster.
- Consumer groups, `ListOffsets`, SSL/SASL, transactions — none of which either half implements.
- Compressed record batches on the fetch path (the codecs are `kafka-protocol`'s built-ins and
  should work; untested here).
- `acks: 0`, where the client deliberately reads no reply.
- `list_topics` as an action (the connect-time Metadata request covers the same code path).
- Version step-down: the ApiVersions v3 → v0 fallback never fires against NetGet's broker,
  which supports v3.

## Against Apache Kafka (`real_server_test.rs`)

The official Apache Kafka 3.9.1 release, unpacked by `tests/server/kafka/install_peers.py`,
run single-node KRaft through `RealServer` (`kafka-storage.sh format` as the setup command,
`{port}` the broker listener and `{port1}` the controller). kcat seeds `inbox`; `kcat -L -t
outbox` makes Kafka create `outbox` (it creates topics on Metadata, never on Produce); Kafka's
own `kafka-consumer-groups.sh` is run once first so the offsets topic exists. NetGet's client
polls `inbox` and a script handler answers by producing `netget saw: <value>` to `outbox` and
committing `inbox` for group `netget-test`. Then kcat consumes `outbox` and
`kafka-consumer-groups.sh` must show offset 1 — both from the broker's side. The client's
events show Fetch v16 (by topic id) and Produce v11. Fetching by name at v16 instead fails the
test (Kafka answers UNKNOWN_TOPIC_ID). About 11 s, most of it JVM start-up.
