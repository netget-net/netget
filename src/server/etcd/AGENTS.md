# etcd Protocol Implementation

etcd v3 KV service over gRPC. The handler (LLM, script, or static) answers every key-value
request; the server itself stores nothing.

**State**: `Stable` (13 November 2026; see "Maturity: the six conditions" at the foot) · **Port**: 2379 · **Stack**: `ETH>IP>TCP>GRPC>ETCD`

## Libraries

- **prost** 0.13 — protobuf encode/decode. The etcd v3 schemas in `proto/etcd/` are compiled
  by `build.rs` into `etcdserverpb` / `mvccpb`.
- **hyper** 1.5 — `server::conn::http2` directly, with a hand-written gRPC router.
- **tonic** is a dependency of the `grpc` feature and is **not used here.** `metadata()` used
  to claim "tonic gRPC"; the routing, framing and status handling in `mod.rs` are all local.

## No storage (the rule that matters most here)

etcd is a key-value store, so this is the protocol most likely to grow one by accident. It has
not. The only server-side state is:

```rust
struct EtcdMeta {
    revision: i64,     // monotonic counter for the response header
    cluster_id: u64,   // constant
    member_id: u64,    // constant
}
```

A `kvs: HashMap<Vec<u8>, KeyValue>` field used to sit alongside these behind
`#[allow(dead_code)]`, never read and never written. It has been removed rather than left as a
half-built store. Keys and values live only in the request event and the handler's reply.

The revision counter is metadata, not data: it exists because `ResponseHeader.revision` is a
required field on every etcd reply and a client that sees it go backwards will complain. A
handler can override it on Put via `etcd_range_response`/`etcd_put_response`; the server only
ever raises it, never lowers it.

## Request flow

```
HTTP/2 stream -> route on :path -> decode protobuf -> emit event -> handler
             <- encode protobuf <- build response  <- actions   <-
```

Routed methods, all of `etcdserverpb.KV`:

| gRPC method | Event | Handler decides |
|---|---|---|
| `Range` | `etcd_range_request` | the key-value pairs returned (and the previous pair, sorting and point-in-time reads are described to it when asked for) |
| `Put` | `etcd_put_request` | the revision (optional), and the previous pair when `prev_kv` is asked for |
| `DeleteRange` | `etcd_delete_request` | how many keys were deleted, and the deleted pairs when `prev_kv` is asked for |
| `Txn` | `etcd_txn_request` | which branch ran, and the result of each operation in it |
| `Compact` | — | nothing: the revisions are the server's own, so it answers from them |

### What the server applies itself

Some parts of a reply are rules about the reply rather than claims about the key space, and the
server applies them so a handler that overlooks one cannot hand a client more than it asked for:

- **Range `limit`** truncates the handler's `kvs` and sets `more` (as etcd does when keys
  remain); `count` stays the handler's. **`keys_only`** drops the values; **`count_only`** drops
  the pairs and keeps the count. `tests/server/etcd/real_client_test.rs` drives all three with
  etcdctl, `grpcio_client_test.rs` the first two with grpcio.
- **Revision.** A Put the handler gives no revision moves the counter by one; a DeleteRange moves
  it only when it deleted something, and a Txn only when the branch it ran wrote (a put, or a
  delete of at least one key) — a read or an empty delete changes nothing in etcd and is not
  given a revision of its own here either.
- **Compact** refuses a revision past the current one (`required revision is a future revision`)
  or at or below the last one compacted (`required revision has been compacted`), both
  `11 OUT_OF_RANGE` with etcd's own messages; anything else succeeds and records it.

Anything else — `Watch`, `Lease`, `Auth`, `Cluster`, `Maintenance`, reflection — is answered
with `12 UNIMPLEMENTED`. It used to `bail!`, which reset the whole HTTP/2 connection and took
every concurrent RPC on it down with the unknown one.

## Actions

| Action | Fields | Used by |
|---|---|---|
| `etcd_range_response` | `kvs[]` (`key`, `value`, `create_revision`, `mod_revision`, `version`, `lease`), `more`, `count` | Range |
| `etcd_put_response` | `revision` (optional), `prev_kv` (when asked for) | Put |
| `etcd_delete_range_response` | `deleted`, `prev_kvs` (when asked for) | DeleteRange |
| `etcd_txn_response` | `succeeded`, `responses[]` — one per operation of the branch that ran | Txn |
| `etcd_error` | `code`, `message` | any |

Every one of these is listed in `execute_action`. `etcd_put_response` and
`etcd_delete_range_response` previously were not: `handle_put` and `handle_delete_range` looked
for them by name while `execute_action` rejected them as unknown action types, so a model could
never produce one. A Put could not choose its revision and a DeleteRange always reported
`deleted 0` no matter what the handler said.

`etcd_error.code` maps onto a gRPC status: `KEY_NOT_FOUND`/`NOT_FOUND` → 5,
`INVALID_ARGUMENT`/`BAD_REQUEST` → 3, `UNIMPLEMENTED` → 12, `RESOURCE_EXHAUSTED` → 8,
`FAILED_PRECONDITION` → 9, `OUT_OF_RANGE`/`COMPACTED`/`FUTURE_REV` → 11, `INTERNAL` → 13,
anything else → 2 `UNKNOWN`. It was previously offered on the Range event and
then never looked for, so a handler reporting "key not found" had its answer silently dropped
and the client saw an empty success.

### Actions the model can see

All four request events call `.with_actions(...)`. `etcd_put_request`, `etcd_delete_request`
and `etcd_txn_request` used to call neither, and each carried an `etcd_range_response` as its
response example — the wrong action for the event. `call_llm` builds the model's tool list from
`event.event_type.actions`, so those three events fell back to the full sync set with a logged
BUG and a `debug_assert`.

## No bytes on the action boundary

etcd keys and values are `bytes` on the wire. They cross the action boundary as **UTF-8
strings**, converted with `from_utf8_lossy` inbound and `as_bytes()` outbound — never hex, never
base64. This satisfies the no-bytes rule and matches how anyone actually uses etcd (`etcdctl put
/config/db localhost:5432`), at the cost of being lossy for genuinely binary keys: a key
containing invalid UTF-8 reaches the handler with U+FFFD substitutions and cannot be echoed back
byte-exactly. Storing binary blobs in etcd through this server does not work.

The Txn comparison enums are given to the handler by name (`EQUAL`, `VERSION`, …) rather than as
the raw protobuf integers, each with the operand it compares against as `value`, and each branch
is given as its operations — `op` (`range`, `put`, `delete_range`) with their keys, values and
flags. The handler used to receive only the counts of each, so it decided a compare-and-swap
without knowing what was compared or what would be written.

## Correlation

Request/response matching is HTTP/2's job, and hyper does it: each stream is one `service_fn`
future and hyper binds the returned `Response` to the originating stream id. There is no manual
stream bookkeeping to get wrong, and nothing correlation-related needs to appear in event data.

One consequence worth knowing: `connection_id` is minted per TCP connection, not per stream, and
gRPC multiplexes. Concurrent RPCs on one connection share it in the access log. The handlers
pass `None` for `connection_id` to `call_llm` anyway.

## Nothing the handler did not say

Every KV method refuses when its handler ran and produced no response action:
`Range`, `Put` and `DeleteRange` all reply `grpc-status 13 (INTERNAL)` with no
message frame, logged `decision=fail_closed_no_action`. INTERNAL rather than
UNAVAILABLE, because nothing is saturated and a retry would not help.

The reason this matters more here than in most protocols is that etcd's
"nothing" responses are **positive claims**, and so are indistinguishable from
real answers:

| method | what the old fall-through sent | how a client reads it |
|---|---|---|
| `Range` | `kvs: [], count: 0` | the key does not exist |
| `DeleteRange` | `deleted: 0` under a **bumped** revision | the delete ran and committed |
| `Put` | a `PutResponse` with a fresh revision | the write committed |

`Put` was fixed first; `Range` and `DeleteRange` carried the same shape for
longer. A handler that genuinely means "no such key" still says so — with
`etcd_range_response` carrying an empty `kvs` — and that is a different thing
from having produced no action at all.

`Txn` refuses the same way: no `etcd_txn_response`, or a branch with a Range or
DeleteRange operation whose entry in `responses` is missing, is `13 INTERNAL`. It
used to default to `succeeded: false` with no per-operation results, on the
reasoning that "the compare did not hold" is the safe direction. It is not: in
etcd `succeeded: false` means the **failure branch ran**, so a failure branch
holding a write was reported as committed, and a reply with no `responses` for a
branch with operations is malformed — `etcdctl txn` prints nothing for them and
clientv3's mutex reads the lock owner out of `responses[0]`. A Put operation's
entry may be omitted: its reply carries only the header (and the previous pair,
when asked for), and the handler already said the write ran by choosing its
branch. A nested Txn operation is refused `12 UNIMPLEMENTED` before the handler
is asked, since its reply would need a branch and responses of its own.

`tests/server/etcd/unanswered_request_test.rs` drives `Range` and `DeleteRange`
through a zero-action static handler — the shape that reaches the response
builder with nothing and no backend error to blame — and asserts a non-zero
status and an empty body.

## Robustness

- **Request bodies are bounded twice**, by `collect_request_body`, frame by frame: at 1.5 MiB
  per request (`MAX_REQUEST_BYTES`, etcd's own `--max-request-bytes` default) and at 48 MiB
  across the whole server (`MAX_BUFFERED_REQUEST_BYTES`, 32 maximum-size requests). Each DATA
  frame takes its length out of the server-wide budget before it is kept and the bytes go back
  when the request has been answered; a frame past either bound is answered
  `8 RESOURCE_EXHAUSTED` (retryable in gRPC). The per-request cap alone did not bound memory:
  each of 256 connections may carry `MAX_CONCURRENT_STREAMS` (200, set explicitly on the
  builder and advertised in SETTINGS) requests at once, so the per-request cap allowed 75 GiB.
- **The 5-byte frame header is honoured.** The declared length is checked against the bytes
  that actually follow before slicing; the code used to take "everything after byte 5",
  feeding a second frame's bytes into the protobuf decoder as trailing garbage.
- **A set compression flag is rejected** with `12 UNIMPLEMENTED` instead of being ignored and
  passed to prost as if it were uncompressed.
- **No handler returns `Err` to hyper.** Every failure becomes a well-formed gRPC status reply.
  An error out of `service_fn` resets the whole multiplexed connection.
- **`grpc-message` is built with `HeaderValue::from_str` and a fallback**, not `unwrap`. The
  message comes from LLM output and `anyhow` chains; a single non-ASCII character in it is
  illegal in a header value and would otherwise panic the connection task.
- **The accept loop breaks** on error instead of retrying immediately, which spun a hot loop
  on a persistent EMFILE and flooded the unbounded status channel.
- Bind uses `?`; the accept-loop `JoinHandle` is registered via `register_server_task()`, so
  `stop_server` releases the port. Each connection task is spawned with `spawn_server_task`, so `stop_server` ends open connections too.

There are no `unwrap()`s, no slicing, and no signed-to-`usize` casts on network input left in
this module.

## Known limitations

- **KV only.** No Watch (needs server streaming), no Lease, no Auth, no Cluster, no
  Maintenance, no reflection.
- **Txn has no nested transactions.** A `request_txn` operation is refused `12 UNIMPLEMENTED`;
  Range, Put and DeleteRange operations are answered by the handler as above.
- **`Compact` discards nothing** — nothing is stored. It answers for the revisions it owns
  (future and already-compacted revisions are refused) without consulting the handler.
- **Request flags described but not enforced:** `serializable`, `sort_order`/`sort_target`,
  `revision` and the `min_/max_*_revision` filters are put in the Range event when set and left
  to the handler; `ignore_value`/`ignore_lease` likewise for Put.
- **No MVCC.** One revision counter, no history, no point-in-time reads. Earlier docs described
  "simplified MVCC" and a `kvs` map; neither exists.
- **No persistence, no Raft, single node.**
- Startup parameters: `cluster_name` (a log label), `first_byte_timeout_secs` and
  `idle_timeout_secs` (the two read deadlines below). `initial_cluster_state` and `max_keys`
  used to be declared and were never read — `max_keys` in particular advertised a key store
  this protocol must not have.

## Verified

**State: Beta**, restored September 2026 — and the route back is the useful part, because the
rating it lost and the rating it has now rest on different things.

Two clients independent of the server **and of each other**, neither `#[ignore]`d and neither
skipping when something is missing:

| test | client | its HTTP/2 and protobuf |
|---|---|---|
| `tests/server/etcd/real_client_test.rs` | the real `etcdctl` binary | grpc-go, golang/protobuf |
| `tests/server/etcd/grpcio_client_test.rs` (driver `grpcio_client.py`) | Python grpcio | gRPC C-core's chttp2, upb |

`tests/server/etcd/e2e_test.rs` drives `etcd-client` 0.15 as well, but it is **not** counted:
it is tonic, which is hyper and `h2`, over `prost` — the server's own HTTP/2 stack and protobuf
codec — so only the gRPC framing between them is independent. That is the `dot`/`doh` finding
of 8 November 2026 (the "second peer" doing the DNS was the server's own codec) in another
protocol, and it was this file's second client until the Stable pass. Both counted clients
hard-fail when absent.

### Why one client was not enough

This file used to say the gRPC status is returned in the initial HEADERS rather than in HTTP/2
trailers, that tonic accepts it and grpc-go "may not", and that nobody should touch it without
a Go client to test against. A Go client was pointed at it:

```
$ etcdctl --endpoints=http://127.0.0.1:PORT put /config/database localhost:5432
Error: rpc error: code = Internal desc = server closed the stream without sending trailers
```

Not a corner of the API — the **first** Put, and every other RPC carrying a body. The spec
requires `grpc-status` in Trailers for any response with a body; the success path wrote it into
the initial HEADERS and then sent a `Full<Bytes>` DATA frame, so the stream ended with no
trailing HEADERS. Error replies were unaffected because an empty body makes them Trailers-Only
by construction, so **only the success path was broken** — which is exactly why every test in
the tree passed. That made the old Beta an instance of one lenient client agreeing with one
bug, the same shape CLAUDE.md records for `mysql`/`mysql_async`.

### What the fix is

`grpc_body_with_trailers` in `mod.rs` builds a `StreamBody` of two frames — the
length-prefixed message, then `Frame::trailers` carrying `grpc-status`/`grpc-message` — boxed
into a `BoxBody`, because `Full<Bytes>` cannot emit trailers at all. That body type flows
through `handle_grpc_request`'s signature to hyper.

**The error path deliberately did not change.** A Trailers-Only reply is the one case where
the status belongs in the initial headers, and `grpc_status_reply` still puts it there over an
`Empty<Bytes>` body. Moving it into a trailers frame would be legal but pointlessly different
from what real etcd sends, and `llm_failure_test.rs` and `unanswered_request_test.rs` read it
from the headers. Both placements are now asserted, so neither can drift.

The concern this file raised — that emitting trailers might break tonic — was worth testing
rather than assuming, and it was unfounded: trailers are what tonic expects too. The header
placement was the non-standard one. The whole suite is green for both clients.

## References

- [etcd v3 API](https://etcd.io/docs/v3.5/learning/api/)
- [etcdserverpb](https://github.com/etcd-io/etcd/tree/main/api/etcdserverpb)
- [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/etcd/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` (`first_byte_timeout_secs`) | 30s | Enforced with `TcpStream::peek` before the socket reaches hyper, so the HTTP/2 preface is still there afterwards. HTTP/2 is client-speaks-first and every gRPC client sends the preface inside its dial path. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` (`idle_timeout_secs`) | 900s | etcd's `--grpc-keepalive-interval` defaults to two hours, a bound in name only, so there is no upstream number worth copying. Fifteen minutes is safe here because of a property of *this* server: every RPC is unary — `handle_grpc_request` returns a `Response<GrpcBody>` carrying one message frame and its trailers, so even Watch is one complete message rather than a held-open stream. There is no legitimate long-lived silent request. |
| `MAX_CONNECTIONS` | 256 | Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After`**, deliberately in the older protocol — a refused peer has not sent the HTTP/2 preface, so nothing has been negotiated and a GOAWAY would have to follow a SETTINGS exchange this server is declining. |

**NetGet's own etcd client is *lazy*, so it is never the silent peer this bound closes:**
`etcd_client::Client::connect` builds a tonic balance channel whose services are
`Connection::lazy`, so despite the name no socket opens until an RPC is issued —
`PROTOCOL_QUALITY.md`'s three-state test.

**A request whose body stops arriving is silence, not work.** The connection is marked busy
only once a request's body is complete; every DATA frame before that counts as activity. The
busy mark used to cover the body too, so a peer that sent HEADERS and then nothing held its
connection, task and slot forever — the watchdog refuses to fire while anything is in flight.

**The deadline covers the read and nothing else.** hyper owns every read once `serve_connection` starts, and it keeps polling the connection for new frames *while a request is being answered* — so a deadline on reads would be wrong here, not merely awkward. The idle bound is a watchdog over `ConnectionActivity` instead, which reports a connection with work in flight as not idle at all. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle. `tests/server/etcd/bounds_test.rs` drives every bound
above from the wire, on both sides.

## No peer handle — `[ message this peer ]` / `[ disconnect this peer ]` stay disabled

etcd is gRPC over HTTP/2, and `handle_connection` hands the socket to hyper's
`serve_connection` after the first-byte `peek`. From that point hyper owns every read and write,
so there is no `Arc<Mutex<WriteHalf>>` to share with a peer-command task, and raw bytes written
beside hyper's framing would corrupt the HTTP/2 stream rather than reach the client.

What the protocol *could* offer is also nothing: `EtcdProtocol`'s actions return
`ActionResult::Custom`, which `mod.rs` turns into a protobuf reply for the RPC that is in
flight. An injected one has no RPC to answer.

The dashboard renders that as a dim button reading "this protocol cannot message a peer from
here yet", which is the honest rendering. `tests/peer_handle_coverage_ratchet_test.rs` carries
this protocol on its shrink-only baseline with the reason above, and re-derives the reason from
source on every run, so if the mechanism changes the build fails rather than the file going
quietly stale.

## Maturity: the six conditions

The root `AGENTS.md` defines `Stable` as six conditions. Re-derived against source on
13 November 2026 rather than inherited. **The rating covers the surface this server
implements**: the five `etcdserverpb.KV` methods, unary, over cleartext HTTP/2, with keys and
values as UTF-8. Watch, Lease, Auth, Cluster, Maintenance, nested transactions, TLS and binary
keys are not implemented, and the rating claims none of them.

| # | condition | holds? |
|---|---|---|
| 1 | two independent third-party clients, no skip, no `#[ignore]` | **yes, as of this pass** — `etcdctl` (grpc-go) and grpcio (C-core, upb), each hard-failing when absent, each driving all five methods: Put (with `prev_kv`), Range (single, prefix, `limit`, `keys_only`, `count_only` for etcdctl), DeleteRange (with `prev_kv`), Txn both ways round with its branch's results, Compact (success and both refusals), and an `etcd_error` as a status. Before the pass the second client was `etcd-client`, which shares the server's h2 and prost, and neither client issued Txn or Compact |
| 2 | the pcap oracle is green over its wire traffic | **yes** — every etcdctl and grpcio connection crosses `recording_relay`; tshark's `http2`/`grpc` dissectors read Txn, Compact and Trailers-Only errors as well as the KV success paths |
| 3 | a fuzz target exists and has run clean, with a depth bomb | **yes** — `etcd_request` (`unary_message` and the prost decoder of each method; 20 000-level `txn_depth_bomb` and unknown-group bomb), rebuilt this pass and run (nightly-2025-12-04, `-s none`, the `-undefined,dynamic_lookup` link flag, the fuzz workspace's lockfile seeded from the root `Cargo.lock`) `-max_total_time=300 -timeout=25` from the 9 committed seeds on 13 November 2026: 142 929 executions in 301 s, clean, 1 244 new units (kept out of the tree) |
| 4 | every declared bound has a test | **yes, as of this pass** — `tests/server/etcd/bounds_test.rs`: `MAX_REQUEST_BYTES` (at and one past, timed), `MAX_BUFFERED_REQUEST_BYTES` (filled exactly, then one request more; and returned when answered), `MAX_CONCURRENT_STREAMS` (in SETTINGS; the 201st stream refused), `MAX_CONNECTIONS` (the 256th served, the 257th a 503), `first_byte_timeout_secs` and `idle_timeout_secs` (both sides, the stalled body included), each verified by removing it |
| 5 | both `AGENTS.md` files verified against source in this pass | **yes** — this file and `tests/server/etcd/AGENTS.md` |
| 6 | no `#[ignore]`, no skip-when-missing gate | **yes** — `grep -rn '#\[ignore' tests/server/etcd/` is empty; etcdctl and grpcio fail rather than skip |

What the pass found, each fixed and each with a test that fails without the fix:

- **The Txn reply invented outcomes.** The handler saw only the *counts* of compares and
  operations, not what was compared or written; the reply never carried per-operation results;
  and an unanswered Txn was reported `succeeded: false`, which in etcd means the failure branch
  ran — a committed write when that branch holds one.
- **Range's own flags were ignored.** `limit`, `keys_only` and `count_only` were not applied,
  so `etcdctl get --limit 2` printed every pair the handler gave; `prev_kv` on Put and
  DeleteRange was neither described nor answerable.
- **Compact acknowledged any revision**, including future and already-compacted ones.
- **A stalled request body disabled the idle bound** (above), and **the per-request size cap
  bounded nothing in total** (Robustness).
- **The revision moved for operations that change nothing** (a delete of no keys, a read-only
  Txn).
