# etcd server tests

Seven files, all declared in `tests/server/etcd/mod.rs`:

| file | what it is for | LLM calls |
|---|---|---|
| `real_client_test.rs` | maturity evidence — the real `etcdctl` binary (grpc-go), two sessions: put/get/prefix/del, then txn both ways, compaction, `--limit`/`--keys-only`/`--count-only`, `--prev-kv` on put and del, and an error status | 6 + 10 |
| `grpcio_client_test.rs` | maturity evidence — Python grpcio (C-core, upb protobuf) driving every KV method, from `grpcio_client.py` | 11 |
| `e2e_test.rs` | `etcd_client` (tonic over prost) driving Put / Get / Range / Delete — not counted as independent, see below | ~6 |
| `bounds_test.rs` | every declared bound from the wire, both sides | 0 |
| `llm_failure_test.rs` | which gRPC status a backend failure produces, and why it matters which | 1 |
| `unanswered_request_test.rs` | a handler that produces no action must not be answered for | 1 |
| `connection_tracking_test.rs` | connections reach `AppState` and close again | 0 |

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
    --test server -- server::etcd:: --test-threads=8
```

Every protocol is compiled into every build; `etcd`'s protobuf schemas are compiled by
`build.rs` with the vendored `protoc`. The suite is not in the blocking `test` job's
`CI_PROTOCOL_TESTS`; `registry-audit` runs `etcd::real_client_test`,
`etcd::grpcio_client_test` and `etcd::bounds_test` with etcdctl, grpcio and protobuf installed.

## The maturity evidence, and why it takes two clients

`DevelopmentState::Stable` rests on `real_client_test.rs` (etcdctl: grpc-go and golang/protobuf)
and `grpcio_client_test.rs` (gRPC C-core's chttp2 and upb). Neither shares a line with the
server's hyper/h2/prost stack or with the other, neither is `#[ignore]`d, and both hard-fail
when their client is absent. `e2e_test.rs`'s `etcd-client` is tonic — hyper and `h2` — over
`prost`: the server's own HTTP/2 stack and protobuf codec at both ends, so its agreement proves
little beyond the gRPC framing between them. It was the second client until the Stable pass
re-derived condition 1 and found it to be the `dot`/`doh` case of 8 November 2026.

grpcio needs no generated code: `grpcio_client.py` builds the message types from etcd's
`rpc.proto` field numbers with protobuf's descriptor API, so encoding and decoding are upb's.

**One of them was not enough, and that is the lesson worth keeping.** This file used to say the
gRPC status is returned in the initial HEADERS rather than in HTTP/2 trailers, that tonic
accepts it and "grpc-go **may** not", and that nobody should touch it without a Go client to
test against. September 2026: a Go client was pointed at it, and grpc-go did not.

```
$ etcdctl --endpoints=http://127.0.0.1:PORT put /config/database localhost:5432
Error: rpc error: code = Internal desc = server closed the stream without sending trailers
```

Not a get, not an edge case — the **first** RPC, and every other one that carries a body.
`src/server/etcd/mod.rs` wrote the status into the initial HEADERS and then sent DATA, so the
stream ended after DATA with no trailing HEADERS. Error replies were unaffected because they
are Trailers-Only by construction, which is exactly why no existing test caught it: **only the
success path was broken, and the failure paths were the ones being asserted on.**

So the old Beta rested on tonic being lenient about a thing the reference implementation is
strict about — the same shape as `mysql`'s Beta resting on `mysql_async` where the real `mysql`
CLI cannot connect at all. One client agreeing is not "works against real clients".

The success path now emits real trailers and the error path stays Trailers-Only. Both
placements are asserted, so neither can drift: `real_client_test.rs` fails if the status leaves
the trailers, and `llm_failure_test.rs` / `unanswered_request_test.rs` fail if it leaves the
initial headers on the error path. That the bug reproduces was checked by removing the trailers
frame and watching `etcdctl put` fail with its own message.

### Running the etcdctl test

`etcdctl` comes from `brew install etcd` (or any etcd release tarball). It must be on `PATH`;
the test names the reason it refuses to skip.

```bash
./cargo-isolated.sh test --no-default-features --features etcd \
    --test server -- server::etcd::real_client --test-threads=8
```

Use `tokio::process::Command`, not `std::process`. `#[tokio::test]` runs a current-thread
runtime, so a blocking `output()` parks the only worker, stops the tasks draining the netget
child's pipes, and etcdctl times out against a server that is perfectly correct.

## No Ollama, and no store

An earlier version of this file said Ollama must be running and described a
prompt telling the server to "store it in memory with revision tracking". Both
are wrong, and the second is wrong in a way worth naming:

- **The mock is the model.** Every test here uses `NetGetConfig::with_mock`, an
  in-process axum server. Nothing contacts a real backend.
- **etcd stores nothing, by rule.** `EtcdMeta` holds a revision counter, a
  cluster id and a member id — no keys. A `kvs: HashMap` field once sat there
  behind `#[allow(dead_code)]`; it is gone rather than left as a half-built
  store, and `max_keys` was removed from the startup parameters because it
  advertised exactly the store this protocol must not have. A test that expects
  a Get to return what an earlier Put wrote is expecting the **mock** to be
  consistent, not the server.

## Mock rules

`e2e_test.rs` uses one rule per etcd event with
`respond_with_actions_from_event`, which is what lets a Get after a Delete answer
`count: 0` while the earlier Get answers with the value. Two rules on the same
event with nothing to tell them apart is the most common mock mistake in this
repo: the first answers every occurrence and the second reports zero calls.

The mocks answer each Txn from `compares[0].key` and each Range from `key`/`range_end`, and
the Range answers deliberately carry more pairs than `--limit` asks for: the server, not the
mock, must truncate.

Event ids are `etcd_range_request`, `etcd_put_request`, **`etcd_delete_request`**
(not `etcd_delete_range_request` — the action is
`etcd_delete_range_response`, the event is not) and `etcd_txn_request`. Check
them against `src/server/etcd/actions.rs`, because a rule that never matches does
not fail: the request falls through to a real LLM call and the failure surfaces
two steps later on a different expectation.

Always finish with `wait_for_mocks(30)` then `verify_mocks()`. Without the
second, a test asserts nothing at all about LLM interaction.

## What is not covered

- **Watch, Lease, Auth, Cluster, Maintenance** — the server answers all of them
  `12 UNIMPLEMENTED`; Watch needs server streaming.
- **Nested transactions** — refused `12 UNIMPLEMENTED`, asserted by nothing here beyond the
  decode path the fuzz target covers.
- **Binary keys and values** — they cross the action boundary as lossy UTF-8.

## Stable conditions 2 and 3: the pcap oracle and the fuzz target

**Condition 2.** `real_client_test.rs` puts a recording relay
(`tests/helpers/recording_relay.rs`) between `etcdctl` and the server and runs the pcap oracle
over every connection it recorded — six, one per command. Wireshark's `http2` dissector and its
`grpc` sub-dissector read the preface, both SETTINGS exchanges, the HPACK headers, the
length-prefixed messages and the trailers of every success path — Put, Range, DeleteRange, Txn
and Compact — and the Trailers-Only error replies of the second etcdctl session and of
`grpcio_client_test.rs`. tshark has no `rpc.proto`, so it checks each protobuf message's wire
structure, not its field names.

**Condition 3.** `fuzz/fuzz_targets/etcd_request.rs` drives `etcd::unary_message` and the
prost decoder of each KV method, with decode → encode → decode asserted equal. `TxnRequest` is
recursive (`RequestOp.request_txn`), so the corpus carries a 20 000-level `txn_depth_bomb` and
a 20 000-level unknown-group bomb; prost's recursion limit (100) refuses both. That limit is
not NetGet's: any crate in the build that enables prost's `no-recursion-limit` feature removes
it for every decoder in the process, and these seeds are what would catch it. Rebuilt and run (nightly-2025-12-04, `-s none`, the `-undefined,dynamic_lookup` link flag, the fuzz workspace's lockfile seeded from the root `Cargo.lock`) `-max_total_time=300 -timeout=25` from the 9 committed seeds on 13 November 2026: 142 929 executions in 301 s, clean, 1 244 new units (kept out of the tree).

## Condition 4: `bounds_test.rs`

Model-free (a dead LLM port; static and manual rules), raw HTTP/2 frames where a client would
honour the limit being tested, `h2` only to push flow-controlled bodies:

| bound | at the bound | one past it |
|---|---|---|
| `MAX_REQUEST_BYTES` | a Put of exactly 1.5 MiB is answered, timed | `8 RESOURCE_EXHAUSTED` |
| `MAX_BUFFERED_REQUEST_BYTES` | 32 maximum-size requests parked over two connections fill it exactly; and twice the budget sent one at a time is never refused | a 5-byte request is `8` |
| `MAX_CONCURRENT_STREAMS` | 200 streams open, and stream 1 is still answered | SETTINGS carries 200; stream 401 is `RST_STREAM(REFUSED_STREAM)` |
| `MAX_CONNECTIONS` | the 256th connection gets the server's SETTINGS | the 257th reads HTTP/1.1 503 |
| `first_byte_timeout_secs` | a peer that sent its preface is served | a silent peer is closed (window kept under the 30 s default) |
| `idle_timeout_secs` | a second request inside the window is answered | a request whose body stopped arriving closes the connection |

Each was checked by removing the bound in `src/server/etcd/mod.rs` and watching its test fail.
