# etcd server tests

Five files, all declared in `tests/server/etcd/mod.rs`:

| file | what it is for | LLM calls |
|---|---|---|
| `e2e_test.rs` | maturity evidence — the real `etcd_client` crate driving Put / Get / Range / Delete | ~6 |
| `real_client_test.rs` | maturity evidence — the real `etcdctl` binary, which is grpc-go | 6 |
| `llm_failure_test.rs` | which gRPC status a backend failure produces, and why it matters which | 1 |
| `unanswered_request_test.rs` | a handler that produces no action must not be answered for | 1 |
| `connection_tracking_test.rs` | connections reach `AppState` and close again | 0 |

```bash
./cargo-isolated.sh test --no-default-features --features etcd \
    --test server -- server::etcd --test-threads=100
```

`etcd` needs `protoc` to build (`build.rs` compiles the etcd protobuf schemas
under `#[cfg(feature = "etcd")]`), so this suite does not run in Claude Code for
Web and is outside the blocking CI feature set.

## The maturity evidence, and why it takes two clients

`DevelopmentState::Beta` rests on **both** client tests, and each survives the three checks
this repo applies to such a claim: not `#[ignore]`d, no skip-when-missing path, and the client
is compiled wherever the gate runs (`etcd-client` is a plain optional dependency, not an
`optional = true` **dev**-dependency — the hole that makes AMQP's Beta rest on a test its gate
never builds; `real_client_test.rs` hard-fails when `etcdctl` is absent and says why).

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
- **Txn's nested operations.** The handler decides `succeeded`; the Range/Put/
  Delete operations inside the branches are not executed, so `responses` is
  always empty. Compare-and-swap (the distributed-lock pattern) works; reading a
  value out of a transaction result does not.
- **Concurrency, large values, many keys.**

## Stable conditions 2 and 3: the pcap oracle and the fuzz target

**Condition 2.** `real_client_test.rs` puts a recording relay
(`tests/helpers/recording_relay.rs`) between `etcdctl` and the server and runs the pcap oracle
over every connection it recorded — six, one per command. Wireshark's `http2` dissector and its
`grpc` sub-dissector read the preface, both SETTINGS exchanges, the HPACK headers, the
length-prefixed messages and the trailers of the Put, Range (single and `--prefix`) and
DeleteRange success paths. tshark has no `rpc.proto`, so it checks each protobuf message's
wire structure, not its field names. Txn and the error paths are not in that capture.

**Condition 3.** `fuzz/fuzz_targets/etcd_request.rs` drives `etcd::unary_message` and the
prost decoder of each KV method, with decode → encode → decode asserted equal. `TxnRequest` is
recursive (`RequestOp.request_txn`), so the corpus carries a 20 000-level `txn_depth_bomb` and
a 20 000-level unknown-group bomb; prost's recursion limit (100) refuses both. That limit is
not NetGet's: any crate in the build that enables prost's `no-recursion-limit` feature removes
it for every decoder in the process, and these seeds are what would catch it. run 120 s clean on 1 November 2026 (unoptimised, `-s none`, macOS):
20 314 executions, no crash.
