# Cassandra/CQL Server Implementation

Cassandra native binary protocol (CQL v4). The handler answers every query; the server holds no
tables and no rows.

**State**: `Beta`, and `metadata()` agrees — this line said `Experimental` while the code said
`Beta`, so neither was checkable. The evidence is `tests/server/cassandra/e2e_test.rs`, which
drives the real **scylla** driver in eight cases, none `#[ignore]`d and none skipping when
something is missing. Not Stable: spec compliance and scripting support have not been reviewed.
**Port**: 9042 · **Stack**: `ETH>IP>TCP>Cassandra`
**Startup parameters**: none. `send_first` was declared and discarded; CQL is strictly
client-first, so it could never have been honoured.

## Libraries

- **cassandra-protocol** 5.0 — `Envelope::from_buffer` / `encode_with` for frame headers only.
  Responses are built with `Envelope::new` (the struct has a private field since 5.0), through
  `mod.rs`'s `response_envelope`.
- Response **bodies are built by hand**: the crate does not offer server-side body builders for
  RESULT/SUPPORTED/PREPARED, so `mod.rs` writes the CQL wire encoding directly.

## No storage

There are no tables, no rows, and no keyspace. `send_result_rows` writes exactly what the
handler returned. The only per-connection state is:

```rust
struct CassandraConnectionState {
    ready: bool,
    protocol_version: u8,
    prepared_statements: HashMap<Vec<u8>, (String, usize)>,
    authenticated: bool,
    username: Option<String>,
}
```

`prepared_statements` is protocol session state, not a data store: PREPARE is a request that
the server remember a query string so a later EXECUTE can name it by id, and there is nowhere
else to put it. It holds query text the client itself sent, never any answer. It is capped at
`MAX_PREPARED_STATEMENTS` (1024) per connection — a client could previously PREPARE unlimited
distinct queries and every one was retained for the life of the connection.

## Frame flow

```
[version][flags][stream_id:2][opcode][length:4][body]
```

`stream_id` is echoed on every reply — `send_ready`, `send_supported`, `send_result_rows`,
`send_prepared`, `send_error`, `send_auth_success` and `send_authenticate` all take it from
`frame.stream_id`. **This is the correlation guarantee**: CQL v4 allows up to 32k in-flight
requests per connection and a driver matches replies purely by stream id. Because the server
echoes it structurally, the handler never sees it and cannot get it wrong — nothing
correlation-related needs to be in the event data or in a static handler.

| Opcode | Event | Handler answers with |
|---|---|---|
| STARTUP | `cassandra_startup` | `cassandra_ready` or `cassandra_authenticate` |
| OPTIONS | `cassandra_options` | `cassandra_supported` |
| QUERY | `cassandra_query` | `cassandra_result_rows` |
| PREPARE | `cassandra_prepare` | `cassandra_prepared` |
| EXECUTE | `cassandra_execute` | `cassandra_result_rows` |
| AUTH_RESPONSE | `cassandra_auth` | `cassandra_auth_success` |
| REGISTER | — | acknowledged with READY; server events are not supported |

`cassandra_error` and `close_this_connection` are accepted on most events. Every event type
calls `.with_actions(...)`, so the model is offered a narrowed, correct list rather than the
protocol's whole sync set.

`cassandra_query` and `cassandra_execute` both carry the **consistency level the client
actually asked for**, read from the frame's `query_parameters` — `ANY`, `ONE`, `TWO`, `THREE`,
`QUORUM`, `ALL`, `LOCAL_QUORUM`, `EACH_QUORUM`, `SERIAL`, `LOCAL_SERIAL`, `LOCAL_ONE`, or
`UNKNOWN` for a code outside that set. `cassandra_query` used to report the literal `"ONE"` for
every query whatever the client sent, and `parse_execute` read the two bytes and discarded them
under a comment saying "skip". It is the one part of a CQL request a handler might reasonably
branch on, and it was fiction.

## Authentication

A driver only sends credentials if the server answers STARTUP with AUTHENTICATE. Nothing used
to send it — `_send_authenticate` was dead code — so `cassandra_auth` never fired and
`cassandra_auth_success` was unreachable. The handler now reaches it by answering
`cassandra_startup` with:

```json
{"type": "cassandra_authenticate", "authenticator": "org.apache.cassandra.auth.PasswordAuthenticator"}
```

The client then sends SASL PLAIN credentials, `cassandra_auth` fires with `username` and
`password`, and the handler returns `cassandra_auth_success` or `cassandra_error`. If the
handler returns nothing, authentication is denied and the connection closes.

`PasswordAuthenticator` is the only authenticator drivers understand; advertising anything else
makes them give up.

## Column types

Only three types are encoded, and the **declared column type drives the encoding**:

| `type` | CQL type code | Wire encoding |
|---|---|---|
| `int` | `0x0009` | 4-byte big-endian; out-of-range or unparseable → NULL |
| `boolean` | `0x0004` | one byte; accepts `true`/`1`/`"yes"` etc. |
| anything else | `0x000D` (varchar) | UTF-8 |

`serialize_cell_value` used to ignore the column type and switch on the JSON type alone, so a
column declared `int` whose value arrived as `"5"` went out as the ASCII byte `0x35` — a
1-byte int the driver rejected — and a varchar column given a number went out as 4 binary
bytes. Types are now honored in both directions.

Rows are padded with NULL and truncated to the declared column count. A driver reads exactly
`columns.len()` cells and treats whatever follows as the next row, so a wrong-arity row from
the handler used to desynchronize the whole result set rather than just corrupt one row.

Not supported: collections (list/set/map), UDTs, blob, timestamp, uuid, bigint, float, double,
decimal. A handler that declares one of these gets varchar on the wire.

## Robustness

- **Frame length is capped** at 256 MiB (`MAX_FRAME_BODY_BYTES`, the protocol's own maximum).
  Without the cap the read loop simply waited for the declared bytes while `read_buf` grew the
  `BytesMut`, so a client declaring a 4 GiB frame and dribbling data grew the process without
  limit.
- **`close_this_connection` now closes.** It used to break only out of the inner frame loop;
  the outer loop then re-entered `read_buf` and the connection stayed open, making the action a
  no-op on every path. Frame-handling errors had the same shape.
- **A frame we cannot parse is answered, not dropped.** The `Err` exit from `handle_frame` set
  `closing = true` under a comment reading "send error frame and close connection" and then
  sent nothing, so a driver blocked on that stream id saw the socket vanish and reported a
  *transport* fault. It now answers ERROR `0x000A` PROTOCOL_ERROR first. The stream id comes
  from header bytes 2..4 and does not depend on the body parsing, so the reply reaches the
  right request; the message is a fixed string, never the internal error, which carries anyhow
  context and library wording.
- **An unknown prepared-statement id answers UNPREPARED (`0x2500`), not silence.** This was the
  same `Err` exit and it is reachable in ordinary use: ids are a hash of the query text and are
  held **per connection**, so a driver executing on a pooled connection that never saw the
  PREPARE lands here, as does one reconnecting. `0x2500` is the one native-protocol error with
  a payload after the message — `[short bytes]` naming the id — and it must be written, because
  a driver reads those trailing bytes unconditionally. scylla re-PREPAREs and retries on it, so
  the statement then succeeds instead of the session dying.
  `tests/server/cassandra/protocol_error_test.rs` covers both.
- **Two header bits are refused before `cassandra-protocol` sees them**: the *tracing* flag on a
  frame whose direction bit says response, and the *warning* flag. A server never receives a
  response frame (Apache Cassandra refuses one as "Wrong message direction") and warnings ride
  only on responses, so `parse_request_frame` refuses both and the frame takes the
  PROTOCOL_ERROR path above. `Envelope::from_buffer` does not refuse them itself: it decodes a
  well-formed response-direction frame as an ordinary one, and on a request carrying the warning
  flag strips a `[string list]` off the front of the body and hands on the rest. Its own handling
  of malformed shapes of those fields is sound since 4.1 — it returns `Err` for a missing tracing
  id, a negative list count and an over-long string, all three of which panicked in 3.3.0 (a
  panic inside the connection task: swallowed by `tokio::spawn`, the socket closed with no
  reply). A declared body length with the high bit set, 3.3.0's fourth panic, is refused by the
  read loop's `MAX_FRAME_BODY_BYTES` before a frame is assembled, and by the decoder too.
  `tests/server/cassandra/decoder_panic_test.rs` hands all four shapes to the linked decoder
  directly (each must be `Err`) and sends the first three from the wire;
  `fuzz/fuzz_targets/cassandra_envelope.rs` runs the read loop's checks and the decoder as a pair.
- **The accept loop breaks** on error rather than retrying immediately and spinning on a
  persistent EMFILE.
- **SUPPORTED is never empty.** If the handler supplies no options, the server answers with
  `CQL_VERSION: ["3.0.0"]`, `COMPRESSION: []`, `PROTOCOL_VERSIONS: ["4/v4"]`. An empty multimap
  tells the driver the server supports nothing.
- `parse_query`, `parse_execute` and `parse_sasl_plain` all bounds-check before slicing;
  `parse_execute` rejects negative and over-long parameter lengths. No `unwrap()` on
  network-derived data remains.
- Bind uses `?`; the accept-loop `JoinHandle` is registered via `register_server_task()`.
  Connections are added to and closed on the server instance. Per-connection tasks are
  untracked (project-wide gap).

## Known limitations

- **Protocol v4 only.** The version byte a client sends is not negotiated; replies are always
  v4.
- **No paging** — the whole result set goes in one frame; no paging state is set.
- **No BATCH, no compression, no server-side events** (REGISTER is acknowledged and ignored).
- **No tracing.**
- **Prepared statement ids are `DefaultHasher` over the query text.** Distinct queries can
  collide, and ids are not stable across processes.
- **Consistency is reported, never enforced.** The handler is told what the client asked for
  and can refuse; nothing here counts replicas, because there are none.
- **Keyspace/table in result metadata are hardcoded** to `system`/`local` for rows and
  `netget`/`data` for prepared statements. Drivers that route by token or by keyspace will not
  behave sensibly.
- **`authenticated` is recorded but not enforced** — nothing rejects a query on an
  unauthenticated connection. The handler decides what to answer.

## Verified

`tests/server/cassandra/e2e_test.rs` drives the real **scylla** driver: connect, SELECT,
error response, multiple queries, prepared statements, parameter mismatch, and concurrent
connections. All 8 pass. `llm_failure_test.rs` and `protocol_error_test.rs` add three more,
built against the v4 spec by hand rather than through the driver — a driver cannot be got to
the point of issuing a deliberately-bogus statement id, and the assertions are about specific
opcodes and four-byte codes. 11 in total, all passing.

The authentication path is exercised by no test — it is reachable now, but has not been driven
end to end by a real driver.

## Dashboard injection (peer handle)

Every connection registers a peer handle (`server::peer_support`) **before its first read**,
so the dashboard shows `[ message this peer ]` / `[ disconnect this peer ]` on a live CQL
connection. Before the first read is the point that matters: CQL is client-speaks-first and
this server says nothing until the driver sends OPTIONS/STARTUP, so a `*` manual rule parks
the connection's very first event — and the operator being asked to answer it must be able to
reach, or hang up, the connection while it waits.

The socket is split with `tokio::io::split` (never cloned) and the write half is an
`Arc<Mutex<WriteHalf>>` shared by the session and the peer-command task, so an injected send
and a reply cannot interleave bytes into the middle of each other's frame. All eight frame
senders now write through one `ConnWrite::write`, which locks, writes, flushes, drops the
guard and then counts the bytes.

- **`[ disconnect this peer ]`** works: it injects a bare `{"type": "close_connection"}`,
  which `execute_action` maps to `ActionResult::CloseConnection`. (That name is an
  unadvertised alias for `close_this_connection`, because the dashboard's button sends the
  bare name whatever a protocol calls its own close verb.) The generic peer task half-closes
  the write side; the reader's `read() == 0` path runs the normal teardown and the peer reads
  EOF.
- **Custom-result gap:** every Cassandra wire verb (`cassandra_ready`, `cassandra_supported`,
  `cassandra_result_rows`, `cassandra_prepared`, `cassandra_authenticate`,
  `cassandra_auth_success`, `cassandra_error`) returns `ActionResult::Custom`, never
  `ActionResult::Output`, because a CQL response frame is stamped with the **stream id of the
  request it answers** and an out-of-band injection is answering none. The generic peer task
  therefore reports an injected wire verb as `Executed` and writes nothing. No bespoke path is
  provided, because a frame carrying an invented stream id would be matched against the wrong
  pending request by the driver, or dropped — worse than not writing. Wire replies stay driven
  by the read loop, where the stream id is known.
- Connection counters (`update_connection_stats`) are updated on every read and every write
  the session makes, so the rail's `↓/↑` byte and packet counts move. **They did not before**
  — this server called `update_connection_stats` nowhere at all, so the counters sat at zero
  for the life of a session. Bytes written by the generic peer task are not counted here
  (that is `peer_support.rs`'s job).

`tests/server/cassandra/peer_inject_test.rs` proves all of it with zero LLM calls.

## References

- [Cassandra native protocol v4](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec)
- [cassandra-protocol](https://docs.rs/cassandra-protocol/)
- [scylla driver](https://docs.rs/scylla/)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/cassandra/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_FRAME_READ_TIMEOUT` | 30s | CQL is client-speaks-first; a driver sends OPTIONS then STARTUP inside its connect path. A peer that has connected and sent nothing has begun no handshake, and this is the bound an unauthenticated flood lives under. |
| `IDLE_BETWEEN_FRAMES_TIMEOUT` | 900s | Long on purpose: a driver holds a *pool* of persistent connections and most of them are legitimately silent. Both the DataStax and ScyllaDB drivers send a heartbeat OPTIONS on an idle connection every 30s by default, precisely so an idle-but-live connection keeps proving it is live — fifteen minutes is thirty of those. Cassandra's own `native_transport_idle_timeout_in_ms` ships disabled, so there is no upstream default to copy. |
| `MAX_CONNECTIONS` | 256 | Each connection may buffer a frame of up to `MAX_FRAME_BODY_BYTES` (256 MiB), so the cap is what turns that per-connection bound into a total one. **Refusal: a plain close.** There is a natural vocabulary — an ERROR frame with `Overloaded` — but every CQL frame is stamped with the protocol version, and the version is chosen by the client's first frame, which a refused peer has not sent. Guessing it replaces "server is full" with a version error. Real Cassandra past `native_transport_max_concurrent_connections` closes the channel for the same reason. |

**NetGet's own Cassandra client *speaks inside `connect()`*, so it is never the silent peer
this bound closes:** `src/client/cassandra/mod.rs`'s `SessionBuilder::build()` completes
scylla's OPTIONS/STARTUP handshake before returning, ahead of any model turn or keystroke —
`PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** The deadline wraps the `read()` call in this protocol's own loop, and everything that can legitimately take minutes happens after it returns. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.
