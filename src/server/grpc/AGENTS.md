# gRPC Server Implementation

A gRPC server whose service implementation *is* the handler. The protobuf schema is supplied at
startup; every unary RPC and streaming message is decoded to JSON keyed by field name, handed to the handler, and the
handler's JSON is encoded back to protobuf.

**State**: `Experimental` · **Stack**: `ETH>IP>TCP>HTTP2>GRPC`

## Libraries

- **prost-reflect** 0.14 — `DescriptorPool` / `DynamicMessage`, so no code generation.
- **prost** 0.13, **prost-types** — `FileDescriptorSet` decode, message encode.
- **hyper** 1.x routes HTTP/2. **tonic** 0.12.3 owns streaming and reflection framing, gzip, decoding and trailers. Legacy unary framing remains local.
- The local tonic patch preserves upstream version/license and caps gzip expansion before allocation (the `netget-tonic` fork, github.com/netget-net/tonic (NETGET.md)).
- **protoc** — required on `PATH` unless a pre-built `FileDescriptorSet` is supplied.

## Schema input

`startup_params.proto_schema`, tried in this order:

1. **base64 `FileDescriptorSet`** — no protoc needed. Note that a schema which happens to be
   valid base64 but is not a valid descriptor set is a hard error rather than falling through.
2. **path to a `.proto` or `.pb` file** — read from anywhere on disk, with the file's directory
   added as `--proto_path`, so `import` can pull in siblings.
3. **inline `.proto` text** — compiled with protoc.

**Do not tell a model to use base64.** An earlier version of this document called base64
"recommended"; models truncate long base64 strings inside JSON responses, and the startup
parameter description and the E2E test both say the opposite. Inline proto3 text is the form to
use. Reaching a schema by file path is also driven by model output and reads an arbitrary local
file, which is worth knowing before exposing `open_server` to an untrusted instruction.

## Streaming and reflection

All four protobuf method shapes are routed from their descriptors. Unary methods retain
`grpc_unary_request`/`grpc_unary_response`. Streaming methods raise `grpc_stream_opened`,
`grpc_stream_message`, `grpc_stream_input_closed`, and requested `grpc_stream_tick` events.
Each carries a wire stream ID, method/shape facts, input/output counts, field-name JSON and
an expected response schema. The handler chooses `grpc_stream_send`, `grpc_stream_finish`,
`grpc_stream_cancel`, `grpc_stream_wait` (1..1000 ms), or `grpc_error`. Stream IDs are implicit
in an event handler and required for injected peer actions. Queued controls report `Executed`;
they do not claim a protobuf message was delivered.

A server-streaming method requires exactly one input and EOF before the open event. A
client-streaming method accepts inputs until EOF, then requires exactly one response before
finish. Bidirectional methods can respond between inputs; finish closes the response side.
The protocol retains only immutable descriptors and bounded ephemeral wire-lifecycle state;
it does not store application data or implement subscriptions on the handler's behalf.

New streams reject any reachable `bytes` field, including nested and map values, before
conversion. Legacy unary bytes/base64 compatibility remains. Streaming framing and gzip
are handled by tonic, with 4 MiB encoded and decoded message limits. Both peers use the
existing depth 32/node 100000/retained 8 MiB value converter.

`enable_reflection` defaults to true. Real generated v1 and v1alpha services answer service,
file, symbol, extension and transitive dependency queries. Unknown queries return reflection
error code5 and the same RPC remains usable. Reflection descriptors remain internal wire
metadata and never enter model events. No library worker is spawned: each response stream
polls its requests inside the owned HTTP/2 task. Built-in reflection file names are reserved;
a supplied descriptor with the same name must match the generated descriptor exactly.

The shared `schema.rs` accepts at most 4 MiB decoded descriptors/inline text and 128 files/
services. File reads check regular-file metadata and take at most limit+1. The protoc child
is killed on drop, with a 10-second whole compile deadline and 16 KiB stderr budget; its
output file is bounded before allocation. Qualified names are checked before prost-reflect
builds its pool: depth 32, identifiers 256 bytes, packages 256, qualified names 1024,
100000 symbols and 8 MiB aggregate expanded symbol names. Reflection's 128-file/service and
4 MiB descriptor totals include both built-in files. Queries are bounded to 128 per RPC,
64 KiB decoded request, 5 MiB response, and a 30-second whole RPC deadline.

## No storage

The only server state is the `Arc<DescriptorPool>` compiled from `proto_schema` at startup. It
is immutable, never written from network bytes or handler output, and no per-client data is
retained as a domain store. A bounded per-connection stream registry tracks only wire controls. `GrpcProtocol` is a unit struct. This protocol has never been near the storage rule.

## Request handling

```
/package.Service/Method  ->  find descriptors  ->  decode protobuf  ->  JSON
                                                                         |
        protobuf  <-  encode  <-  grpc_unary_response.message  <-  handler
```

Event `grpc_unary_request` carries `service`, `method`, `request` (JSON), and
`expected_response_schema` — a field-name → `{type, cardinality}` map built from the response
descriptor, so the handler is told what shape to return. It declares its actions via
`.with_actions([grpc_unary_response, grpc_error])`.

### Protobuf ↔ JSON

Messages are presented to the handler as **JSON keyed by protobuf field name** — never as wire
bytes and never as hex. `{"a": 5, "b": 3}`, not a blob. Round-trip rules:

| Protobuf | JSON |
|---|---|
| numeric, bool, string, enum | native JSON; enums accept the name or the number |
| `bytes` | **base64**, in both directions |
| message | nested object |
| `repeated` | array |
| `map` | object; keys are stringified and parsed back to the declared key type |

`bytes` is the one place base64 crosses the action boundary, against the project's general
rule. It is symmetric — `Kind::Bytes` decodes what `proto_value_to_json` encoded — and the
schema hint says `"bytes (base64)"`, so there is no encode/decode asymmetry of the kind the
root AGENTS.md warns about for `send_tcp_data`. It remains a poor fit for small models; a
schema that avoids `bytes` will work better.

Repeated and map fields **could not be produced at all** until recently: `json_to_proto_value`
switched on `field.kind()`, which for `repeated string` is `Kind::String`, so a handler
returning `{"tags": ["a","b"]}` failed with "Expected string" and the RPC came back as an
error — while `expected_response_schema` cheerfully told it the cardinality was `repeated`.
`json_to_field_value` now checks `is_map()` then `is_list()` before falling through to the
scalar path.

Numeric conversions are range-checked (`i32::try_from`) rather than truncated with `as`, and an
enum given a number is validated against the enum's declared values, matching what the
string branch already did. Unknown field names and non-object messages are rejected rather
than dropped or converted to empty messages. Multiple members of a `oneof`, map keys that
normalize to the same protobuf key, float overflow or underflow to zero, and non-finite
protobuf values are errors.

Both the client and server use `value_codec.rs`, with explicit bounds independent of the
serde/prost parser limits: depth 32, 100,000 logical nodes, and 8 MiB of retained-content
accounting. Root depth is zero; a field, list element, or map value adds one. Accounting
charges 64 bytes per node, 32 bytes per key plus its text, and strings/base64 content before
copying or decoding. These limits apply across siblings as well as recursion and are distinct
from the 4 MiB inbound wire-body cap. Conversion returns complete values or an error.

## Error handling

`grpc_error` takes `code` and `message`, and **the code now reaches the wire.** It used to be
parsed, logged, and then folded into a `bail!` string, so every error left as
`13 INTERNAL` over HTTP 500 with the real code embedded as text inside `grpc-message`. `code`
accepts the spec spellings (`NOT_FOUND`, `INVALID_ARGUMENT`, …), lowercase, or a bare integer;
anything unrecognized becomes `2 UNKNOWN` so a typo is visible as a typo rather than
disappearing into `INTERNAL`.

**Every reply is HTTP 200.** gRPC carries application failures in `grpc-status`, not the HTTP
status line; a non-200 makes a conformant client discard `grpc-message` and synthesize
`UNAVAILABLE`. Bad path, wrong content-type, oversized body, bad frame and handler errors used
to return 404/415/400/500 respectively and now all return 200 with the right `grpc-status`:

| Condition | Status |
|---|---|
| path not `/Service/Method`, unknown service, unknown method | `12 UNIMPLEMENTED` |
| request compression flag set | `12 UNIMPLEMENTED` |
| body over 4 MiB | `8 RESOURCE_EXHAUSTED` |
| request message fails protobuf decode | `3 INVALID_ARGUMENT` |
| request value exceeds conversion depth/node/byte bounds | `8 RESOURCE_EXHAUSTED` |
| request value cannot be represented as finite field-name JSON | `3 INVALID_ARGUMENT` |
| everything else | `13 INTERNAL` |

## Correlation

Each HTTP/2 stream is one `service_fn` future; hyper binds the returned `Response` to the
originating stream id. `handle_unary` shares no mutable state, so concurrent streams cannot
cross-talk. Nothing correlation-related needs to reach the handler.

Caveat: `connection_id` is minted per TCP connection, not per stream, and gRPC multiplexes — so
concurrent RPCs on one connection share a `connection_id` in the access log and in
`ConversationSource::Network`. Inbound gRPC metadata (`authorization`, `grpc-timeout`, trace
headers) is not parsed and does not reach the handler at all.

## Robustness

- **`grpc_error_response` no longer `unwrap()`s.** `grpc-message` is built from LLM output and
  `anyhow` chains; `HeaderValue` accepts only visible ASCII, so one non-ASCII character or
  newline made `Builder::body` return `Err` and **panicked the connection task**. Because the
  connection-cleanup code runs after `serve_connection().await` in the same task, the panic
  skipped it and left the connection permanently `Active` in `AppState`. It now falls back to
  a static message.
- **Request body capped** at 4 MiB (gRPC's own default `maxReceiveMessageLength`) via
  `http_body_util::Limited`; `req.collect()` was unbounded.
- **Frame length compared against bytes remaining**, not `5 + length`. That addition wraps on a
  32-bit target: a declared length of `0xFFFFFFFF` yields `4`, the guard passes, and
  `frame[5..4]` panics with start > end.
- **protoc output path is per-invocation.** It was the fixed
  `$TMPDIR/netget_grpc_descriptor.pb`, so two gRPC servers starting concurrently could load
  each other's schema. Each compilation now owns a temporary directory.
- Bind uses `create_reusable_tcp_listener(...)?`; the accept-loop `JoinHandle` is registered via
  `register_server_task()`. The accept loop breaks on error rather than spinning. Per-connection
  tasks use `AppState::spawn_server_task`. A connection-owned executor records and aborts all
  HTTP/2 children and deadline timers on exit; body guards retain admission/activity until EOS/drop.

## Connection bounds

New streaming/reflection admission is 64 active RPCs globally and 16 HTTP/2 streams per
connection; body EOS/drop releases the permit. A streaming RPC has at most 256 input/output
messages, 258 handler events and 16 queued outputs totalling at most 4 MiB. An injected
control channel holds one command. `stream_timeout_secs` defaults to 300 and accepts1..3600,
shortened by a valid grpc-timeout. No application worker outlives its owning connection.

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry
forever, pre-authentication — and this server has no auth at all. It now declares both halves;
the constants and the reasoning live beside them in `src/server/grpc/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | Enforced with `TcpStream::peek` before the socket reaches hyper, so the HTTP/2 preface is still there afterwards. HTTP/2 is client-speaks-first and every gRPC client sends the preface inside its dial path. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 900s | gRPC keepalive is **off by default** on both sides (grpc-go leaves `keepalive.ClientParameters.Time` unset and its server policy refuses pings more often than five minutes), so there is no interval to copy. Only a connection with no live RPC is idle. A streaming body holds its busy guard through EOS/drop. |
| `MAX_CONNECTIONS` | 256 | Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After`**, deliberately in the older protocol — the same choice `src/server/etcd/mod.rs` makes. A refused peer has not sent the HTTP/2 preface, so nothing has been negotiated and a GOAWAY would have to follow a SETTINGS exchange this server is declining. |

**NetGet's own gRPC client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `src/client/grpc/mod.rs` uses tonic's eager `Endpoint::connect()` rather than
`connect_lazy()`, so the HTTP/2 preface goes out before any model turn —
`PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** hyper owns every read once `serve_connection`
starts, and it keeps polling the connection for new frames *while a request is being answered* —
so a deadline on reads would be wrong here, not merely awkward. The idle bound is a watchdog over
`ConnectionActivity` instead, which reports a connection with work in flight as not idle at all.
The legacy unary model round-trip is outside the idle watchdog. Streaming and reflection
have independent whole-operation deadlines, including parked handlers and a peer that
stops reading. The hard timer aborts the owning HTTP/2 task even if flow control stops body polling.

`tests/server/grpc/connection_bounds_test.rs` drives both halves from the wire in raw HTTP/2: a
peer that says nothing is closed at the bound, and a peer that sent the preface still gets a
SETTINGS ACK 38 seconds later. Removing the `tokio::time::timeout` around the `peek` makes the
first test hang for its whole 70-second window and fail.
`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed, and
`tests/accept_bounded_test.rs` covers the shared helper.

## Known limitations

- **Legacy unary framing is unchanged.** Extra length-prefixed frames in a unary body remain ignored.
- **Trailers are emitted now, and the history is worth keeping** because it is the cleanest
  example in this tree of a test suite that cannot see the bug it is sitting on. This entry
  used to say `grpc-status` is sent in the initial HEADERS alongside the DATA body and that
  grpc-go "**may** not" accept it, with "there is no Go client available here to test against".
  grpcurl 1.9.4 was installed and pointed at the server on 16 September 2026:

  ```text
  ERROR:
    Code: Internal
    Message: server closed the stream without sending trailers
  ```

  **The success and error paths differed, and the asymmetry is the whole mechanism.** A success
  has a non-empty body, so `http_body_util::Full::is_end_stream()` is false: hyper emitted
  HEADERS (no END_STREAM) then DATA (END_STREAM) and the stream ended with no trailers, which
  grpc-go rejects. An **error** has an empty body, `is_end_stream()` is true, and hyper emits a
  single HEADERS frame with END_STREAM — a valid gRPC **Trailers-Only** response, which grpc-go
  accepts and parses. So NetGet could report a *failure* to a real gRPC client and could not
  report a *success*.

  `grpc_body_with_trailers` now builds a two-frame `StreamBody` — the length-prefixed message,
  then `Frame::trailers` carrying `grpc-status` — boxed into a `BoxBody`, because `Full<Bytes>`
  cannot emit trailers at all. `grpc_error_response` is unchanged: Trailers-Only is the one
  case where the status belongs in the initial headers.

  **The caution about tonic was tested rather than assumed, and it was unfounded.** The sibling
  etcd protocol had the identical defect, is verified against the real `etcd_client` crate, and
  passes unchanged with trailers — trailers are what tonic expects too, and the header
  placement was the non-standard one. Both were fixed in the same pass.

  `tests/server/grpc/real_client_test.rs::test_grpc_unary_call_against_real_grpcurl` was
  written `#[ignore]`d against the broken server, deliberately asserting correct behaviour
  rather than the behaviour of the day. It is now un-ignored and is the regression test.
- Legacy unary request compression remains rejected and unary `grpc-timeout` remains ignored.
  New streaming/reflection routes accept gzip and validate a unique grpc-timeout that can only
  shorten the configured deadline.
- **No auth** — no mTLS, no token checking, no metadata inspection.
- **Schema is fixed at startup.** `descriptor_pool` is an immutable `Arc` with no reload path.
- Legacy unary accepts methods other than POST; new streaming/reflection routes require POST
  and application/grpc over HTTP/2.
- Receiver TLS, mTLS, token checking, streaming retries, fuzzing and pcap evidence are unproved.
- The three async actions `reload_schema`, `list_services` and `describe_method` have been
  **removed**. All three built an `ActionResult::Custom` that no consumer matched, so they did
  nothing on any path, and `reload_schema` was unimplementable against an immutable pool.

## Examples

### Startup (inline proto3 text)

```
Start a gRPC server on port 50051 with this schema:

syntax = "proto3";
package calculator;
service Calculator { rpc Add(AddRequest) returns (AddResponse); }
message AddRequest { int32 a = 1; int32 b = 2; }
message AddResponse { int32 result = 1; }

Return the sum of a and b.
```

### Event

```json
{
  "event_type": "grpc_unary_request",
  "service": "calculator.Calculator",
  "method": "Add",
  "request": {"a": 5, "b": 3},
  "expected_response_schema": {"result": {"type": "int32", "cardinality": "optional"}}
}
```

### Handler response

```json
{"actions": [{"type": "grpc_unary_response", "message": {"result": 8}}]}
```

### Error

```json
{"actions": [{"type": "grpc_error", "code": "INVALID_ARGUMENT", "message": "a and b must be positive"}]}
```

## Verified

`tests/grpc_value_bounds_test.rs` covers both peers' shared converters with in-memory schema
and value fixtures, including programmatically constructed deep protobuf trees, exact limits,
base64 expansion, shared aggregate budgets, invalid values, and valid nested wire round trips.
This CPU-only target requires the `grpc` feature and no protoc, model, or external service.

**State: Experimental** for the expanded streaming/reflection scope. Legacy unary evidence
uses **grpcurl** (grpc-go), independently of tonic.
`tests/server/grpc/real_client_test.rs` has two tests, neither `#[ignore]`d and neither
skipping when the binary is missing: one completes a unary RPC and asserts grpcurl decoded our
protobuf response field by field, the other asserts it read back our `NOT_FOUND` code and
`grpc-message`.

`tests/server/grpc/e2e_test.rs` — 5 tests covering basic unary, inline proto text, `.proto`
file loading, error responses and concurrent requests. They drive the server with hand-framed
HTTP/2 via `reqwest` (`http2_prior_knowledge`), **not** a real gRPC client, and that is why
they could not see the trailers defect: `reqwest` exposes no trailers API, so no test here can
detect it either way. `test_grpc_unary_rpc_basic` used to assert `grpc-status: 0` on the
*initial* headers, which is what kept the defect satisfied for as long as it did; it now
asserts that header is **absent** and checks the reply frame instead, leaving the status to the
client that cares where it lives.

## References

- [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
- [proto3 language guide](https://protobuf.dev/programming-guides/proto3/)
- [prost-reflect](https://docs.rs/prost-reflect/)
