# PostgreSQL Protocol Implementation

PostgreSQL wire protocol server built on `pgwire` v0.35. pgwire owns startup,
framing and the Parse/Bind/Describe/Execute state machine; the LLM owns the
answer to every statement. **There is no database** — no tables, no planner, no
storage in Rust. The only per-connection state is a Describe→Execute correlation
cache (see below).

**State**: Beta (this file said Experimental while `actions.rs` said Beta; the
code was right). **Two** independent clients, sharing no code with each other or
with `pgwire`:

- **tokio-postgres** (Rust) covers both query protocols — `test.rs` for simple,
  `extended_query_test.rs` for Parse/Describe/Bind/Execute with binary result
  columns decoded into real Rust types.
- **psql 14 / libpq** (C) covers what tokio-postgres cannot reach:
  `real_client_test.rs` drives the real binary, which hard-fails when psql is
  absent. libpq defaults to `sslmode=prefer`, so psql opens every connection with
  an `SSLRequest` and expects `N` back — an exchange `NoTls` skips entirely, so
  nothing else here had ever driven it. It then asserts the *rendered* result:
  `t`/`f` booleans, a real NULL distinguished from an empty string by
  `\pset null`, four columns and three rows in order, the `INSERT 0 1` tag, and
  the SQLSTATE psql prints under `\set VERBOSITY verbose`.

**psql 14 does not exercise the extended protocol** — it sends every statement as
a simple `Query` (`\bind` arrived in psql 16) — so Parse/Bind/Describe/Execute
and the binary result format still rest on tokio-postgres alone. The two clients
are complementary, not overlapping.
**Port**: 5432 by default. **Privilege**: `None` (5432 > 1024).
**Stack**: `ETH>IP>TCP>PostgreSQL`.

## What the model sees and controls

**Event**: `postgresql_query`, fired once per statement on both the simple and
the extended query paths.

| Field | Notes |
|---|---|
| `query` | the SQL text |
| `answer_with` | which response shape the statement needs — `postgresql_query_response` for a statement that returns rows, `postgresql_ok_response` for one that does not — from its first keyword (`crate::utils::sql`); absent when the keyword does not say |

`client_ip`, `client_port`, `connection_id` and `server_id` are added by the
event logger, so log templates may reference them.

**Actions** (all sync; there are no async actions):

| Action | Parameters | Wire form |
|---|---|---|
| `postgresql_query_response` | `columns` (required), `rows` (required) | RowDescription + DataRows |
| `postgresql_ok_response` | `tag` (required) | CommandComplete |
| `postgresql_error_response` | `message` (required), `severity`, `code` | ErrorResponse |
| `close_this_connection` | — | `FATAL 57P01`, which terminates the session |

`columns` is an array of `{"name": …, "type": …}`. Recognised type names:
`int2`/`smallint`, `int4`/`int`/`integer`, `int8`/`bigint`, `float4`/`real`,
`float8`/`double`, `bool`/`boolean`, `date`, `time`, `timestamp`, `text`,
`varchar`. Anything unrecognised is sent as `varchar`.

Row handling, as implemented in `build_row_outcome`:

- A row shorter than the column list is padded with NULLs; extra values are
  dropped. PostgreSQL requires exactly one value per described column, and a
  mismatch desynchronises the client — the model does occasionally miscount.
- A row that is not a JSON array is skipped with a WARN.
- JSON `null` is encoded as a real SQL NULL (not the empty string).
- Each cell is encoded in **the format the client asked for**, not always text —
  see "Result formats" below. In text format booleans are `t`/`f`.

`tag` is sent verbatim, so use PostgreSQL's own forms: `INSERT 0 1`, `UPDATE 3`,
`DELETE 2`, `CREATE TABLE`, `SELECT 2`.

### Failure behavior

- **No response action** → `ERROR XX000` carrying the `WireFailure` category,
  logged `decision=fail_closed_no_action`. It used to answer success — an empty
  result set for a `SELECT` (which reads as "ran, matched no rows", a claim about
  the data that nothing supports) and the tag `OK` for anything else (so an
  INSERT the model declined was reported as having completed). `02000` (no_data)
  is deliberately not used: it would again assert something about the data rather
  than about netget.
- **Model chose to refuse** → its own `postgresql_error` severity/code/message,
  logged `decision=model_reject`. Structurally distinct from the path above, as
  `src/server/radius/` does — the wire code alone cannot tell a refusal from an
  outage, so the log must.
- **LLM call fails** → `ERROR 53300` (`too_many_connections`, class 53
  "insufficient resources") when `crate::llm::is_overload_error` says the failure
  was capacity exhaustion, otherwise `ERROR XX000`; logged
  `decision=fail_closed_llm_overloaded` / `decision=fail_closed_llm_error`.
  Drivers classify 53300 as transient and XX000 as a fault, so an outage does not
  read as a permanent error — and neither reads as success. **The message is a
  `crate::utils::WireFailure` category, never the error text**: backend URLs,
  model names and `anyhow` context chains do not reach the peer. Covered by
  `tests/server/postgresql/llm_failure_test.rs`.
- **Action result the handler does not recognise** → logged at WARN and skipped.

## The extended query protocol

An extended-protocol client asks for the row description (Describe) *before* the
rows (Execute). The schema here is whatever the LLM returns, so the two steps
have to agree.

`do_describe_statement` / `do_describe_portal` resolve the statement, return its
`FieldInfo` list, and stash the whole outcome in a small per-connection cache
keyed by SQL text (`MAX_PENDING_DESCRIBES` = 64, oldest evicted). `do_query`
takes the cached outcome, so a Parse/Bind/Describe/Execute round costs **one**
model call, not two, and the RowDescription always matches the DataRows.

This is protocol bookkeeping, not storage: an entry is consumed by the matching
Execute and nothing survives the connection.

Previously `do_describe_statement` returned an unconditional empty field list and
`do_describe_portal` guessed the schema from a substring match on `select 1` /
`version(`, so every other extended query told the client it produced zero
columns and then sent it data rows anyway. That is what the old "extended query
timeout" note in this file was describing.

### Result formats

A Bind message names the wire format of **each result column**, and every
mainstream driver — `tokio-postgres`, libpq, psycopg in its binary modes — asks
for binary. `encode_value` therefore takes the format from the `FieldInfo` and
`fields_for` takes it from `portal.result_column_format`.

This was the live defect. Both the RowDescription and every cell were hardcoded
to `FieldFormat::Text` while the client had asked for binary, so any
`client.query(...)` against a non-text column came back as *"error deserializing
column 0"* — while `simple_query`, which has no format negotiation and is always
text, worked perfectly. Every test in this directory used `simple_query`, which
is why it went unnoticed; the tests' own CLAUDE.md carried the symptom as an
unexplained "Extended Query Protocol Timeout … **UNRESOLVED**", and this file
claimed the path was verified with psycopg 3.

Two consequences worth keeping:

- `PgOutcome::Rows` carries the model's `columns` and raw JSON `values`, not
  encoded `DataRow`s. It cannot encode: the same resolved answer has to become
  text for one portal and binary for another, and `resolve()` does not know which.
- `format_for` bounds-checks `Format::Individual`. `pgwire`'s own `format_for`
  indexes `codes[idx]` unchecked, and a Bind naming fewer format codes than the
  model produced columns would otherwise panic the connection task.

## Architecture

- `spawn_with_llm_actions` binds with `?` (so a bind failure surfaces as
  `ServerStatus::Error`) and registers the accept-loop `JoinHandle` via
  `AppState::register_server_task()` so `stop_server` releases the socket.
- One task per connection running `pgwire::tokio::process_socket`, **registered
  with `register_server_task` as well** — registering only the accept loop
  released the port on `stop_server` while leaving every in-flight session
  running.
- `process_socket` runs inside a nested `tokio::spawn` whose `JoinError` is
  inspected. A panic in `tokio::spawn` is otherwise swallowed, so a panic in
  pgwire or in the handler used to unwind straight past
  `close_connection_on_server`: the row stayed `Active` for a socket that was
  gone, and PostgreSQL is not `connectionless`, so the 10-second idle sweep never
  collected it either. The entry now closes on every path and a panic is logged
  `decision=connection_aborted_decoder_panic`.
- That nested task and the idle watchdog are held in `utils::task_guard::AbortOnDrop`.
  The registered connection task is what `stop_server` aborts; the abort drops the
  `JoinHandle` it was awaiting, and a dropped `JoinHandle` detaches its task, so
  without the guard a stopped server's sessions kept their sockets.
  `tests/stop_server_stops_connections_test.rs::stopping_a_postgresql_server_disconnects_a_handshaken_peer`
  asserts it from the peer's side.
- **Malformed frontend messages are refused, not panicked on** (IMPROVEMENTS #77).
  Upstream pgwire 0.35's `decode_packet` bounds a declared message length only
  from above and hands the body decoder the whole remaining buffer, so a Query
  with no NUL (six bytes after the handshake), a Close or Describe with no body,
  or a Bind whose parameter runs past the message panicked the connection task.
  NetGet builds `vendor/pgwire` (README there), which isolates each message,
  reads with checked getters, and answers `FATAL 08P01`; `process_socket` then
  returns `InvalidData` and the connection is logged
  `decision=refused_malformed_message`. `tests/vendored_pgwire_patch_test.rs`
  drives every shape against the decoder and
  `tests/server/postgresql/decoder_panic_test.rs` asserts the ErrorResponse from
  the wire. A `[patch]` does not reach the crate as published to crates.io, so
  the panic containment above stays.
- `record_stats` keeps `update_connection_stats` current. pgwire never exposes the
  raw byte streams, so the counters are application-visible payload sizes at the
  handler boundary, not exact wire bytes — before this, nothing on this protocol
  called it at all and every peer row read `0 / 0` for its whole life.
- `PostgresqlHandlerFactory` builds both handlers from one `handler()` method and
  hands them the same `describe_cache` `Arc`, so a Describe served by the
  extended handler is visible to the Execute that follows.
- `resolve()` is the single place that calls the LLM and translates an action into
  wire output; both the simple and extended handlers go through it. (The two
  handlers previously carried ~250 lines of duplicated encoding logic each.)

## Not implemented

- **Authentication** — `NoopStartupHandler`; user and database are ignored.
- **TLS** — `process_socket(stream, None, …)`, no TLS acceptor.
- **Binary format, inbound** — bound parameter *values* are not decoded (see
  below). Outbound result columns do honour the requested format.
- **Parameter substitution** — `$1` placeholders reach the model as literal text;
  `do_describe_statement` reports zero parameters.
- **Cursors, `FETCH`, `max_rows`** — `do_query` always returns the whole result.
- **Transactions** — `BEGIN`/`COMMIT`/`ROLLBACK` reach the model as ordinary
  statements; no transaction state is tracked.
- **`COPY`**, **`LISTEN`/`NOTIFY`**, arrays, JSON, ranges and other composite
  types.
- Multi-statement simple queries return a single response, not one per statement.

## Testing

Five files, all declared in `tests/server/postgresql/mod.rs`:

- `test.rs` (note: `test.rs`, not `e2e_test.rs`) — four `client.simple_query`
  cases through the mock-model harness.
- `real_client_test.rs` — the real `psql` binary, two sessions: the SSLRequest
  negotiation plus a multi-row SELECT and a command tag, then the error path with
  its SQLSTATE. Hard-fails when psql is missing rather than skipping.
- `extended_query_test.rs` — Parse/Describe/Bind/Execute through
  `client.query` and `client.prepare`, asserting an `int4` arrives as a real
  `i32`, that a prepared statement's RowDescription matches its DataRows, and
  that the extended path fails closed rather than returning no rows.
- `decoder_panic_test.rs` — a malformed Query is answered `FATAL 08P01`, the
  connection row closes and the server keeps serving; a query moves the
  connection counters off zero.
- `llm_failure_test.rs` — the SQLSTATE a driver sees when the backend fails.

`--test` names a *target*, so it is `--test server -- postgresql`; the older
`--test server::postgresql::test` form makes cargo list targets and exit without
running anything.

```bash
./cargo-isolated.sh test --no-default-features --features postgresql \
    --test server -- server::postgresql --test-threads=100
```

Real-client checks used during review, with a static handler so no model is
involved:

```bash
netget --mcp-http 18899 &
# start_server protocol=postgresql port=15432 event_handlers=[{postgresql_query → static …}]
psql -h 127.0.0.1 -p 15432 -U u -d d -c "SELECT * FROM users"          # simple
python3 -c "import psycopg; …cur.execute('SELECT … WHERE id > %s',(0,))"  # extended
```

## Example prompts

```
Start a PostgreSQL server on port 5432 for a users table (id int4, name text).
Answer SELECT with postgresql_query_response, answer CREATE/INSERT with
postgresql_ok_response using the proper tag, and answer a query against an
unknown relation with postgresql_error_response code 42P01.
```

## References

- [PostgreSQL frontend/backend protocol](https://www.postgresql.org/docs/current/protocol.html)
- [pgwire](https://docs.rs/pgwire/)
- [tokio-postgres](https://docs.rs/tokio-postgres/) — used by the E2E tests
- [PostgreSQL error codes](https://www.postgresql.org/docs/current/errcodes-appendix.html)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/postgresql/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 60s | Enforced with `TcpStream::peek` before the socket reaches pgwire, so the StartupMessage is untouched. Matches pgwire's own internal `STARTUP_TIMEOUT`, which bounds the startup *exchange*; this bounds the silence before it begins, which pgwire does not. |
| `IDLE_SESSION_TIMEOUT` | 600s | Real PostgreSQL's `idle_session_timeout` ships disabled, so there is no upstream default to copy. Ten minutes, for the same reason as MySQL's: no tables, no temp tables, no open transaction, so a reaped pooled connection costs `tokio-postgres`, SQLAlchemy or pgbouncer one transparent reconnect. |
| `MAX_CONNECTIONS` | 256 | Refusal: **a v3 `ErrorResponse` with SQLSTATE `53300 too_many_connections`** — the state real PostgreSQL uses for "sorry, too many clients already", and the one this file already maps backend overload onto, so a driver treats it as transient. Sending it before the StartupMessage is a small liberty that libpq-family clients handle: they write startup, then read, and an ErrorResponse is a legal thing to find there. |

**NetGet's own PostgreSQL client *speaks inside `connect()`*, so it is never the silent peer
this bound closes:** `tokio_postgres::connect` writes the StartupMessage and completes
authentication before returning — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** `process_socket` takes a concrete `TcpStream` and owns every read, so the idle bound is a watchdog over `ConnectionActivity` instead. `resolve` holds a busy guard for the whole answer, so a statement waiting on the model or parked for a human is never counted as idle. The connection is dropped rather than sent a FATAL 57P05, because pgwire exposes no way to write into the socket from outside. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.

## No peer handle — `[ message this peer ]` / `[ disconnect this peer ]` stay disabled

`pgwire::tokio::process_socket` takes a concrete `TcpStream` and never exposes it again. This
file already records the consequence in another place: the idle watchdog **aborts the task**
rather than sending a FATAL 57P05, because pgwire owns the socket and there is no way to write
into it from outside. The same absence of a seam is why there is no write half to give
`peer_support`.

The protocol's own actions are `ActionResult::Custom` — a row description and rows encoded
against the query being answered, by the handler pgwire calls — so even with a socket there
would be no free-standing message to inject. The realistic path to `[ disconnect this peer ]`
here is the `abort_handle` the watchdog already holds, which is a different mechanism from a peer
handle and would need `peer_support` to grow a non-socket variant.

The dashboard renders that as a dim button reading "this protocol cannot message a peer from
here yet", which is the honest rendering. `tests/peer_handle_coverage_ratchet_test.rs` carries
this protocol on its shrink-only baseline with the reason above, and re-derives the reason from
source on every run, so if the mechanism changes the build fails rather than the file going
quietly stale.

## One query, one answer

The real-model eval (`./run-eval.sh postgresql`) found two things no mocked test could. Told to
report the current user or the server version, llama3.1:8b answered the `SELECT` with the
command-tag / OK action — copied from that action's example — so the client printed a tag (or
nothing) instead of the value; and it answered single queries with several response actions.

- The event carries `answer_with` (above), and the two actions' descriptions say which statements
  each answers — a `SELECT` of a single value is one column and one row, never a tag.
- The server has always sent the **first** response action and ignored the rest; it now says so,
  `decision=duplicate_response_dropped` with the count, instead of dropping them in silence.
  `tests/server/postgresql/one_answer_per_query_test.rs` pins both: its rule matches only when
  `answer_with` names the rows action, and it asserts the client got the first of two result sets
  and the log carries the decision. Both halves were verified by removing them.

Measured with seed 42, five runs per case: `postgresql/current-user` went 2/5 → 5/5 and `postgresql/users-table` 0/5 → 5/5.

