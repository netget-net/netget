# PostgreSQL Protocol Implementation

PostgreSQL wire protocol server built on upstream `pgwire` 0.42 (0.42.3 or later). pgwire owns startup,
framing and the Parse/Bind/Describe/Execute state machine; the LLM owns the
answer to every statement. **There is no database** — no tables, no planner, no
storage in Rust. The only per-connection state is a Describe→Execute correlation
cache (see below).

**State**: Stable (13 November 2026; see "Maturity: the six conditions" at the
foot). Two independent clients **on each query protocol**, none sharing code with
`pgwire`:

- **Simple query**: psql 14 / libpq (C), `real_client_test.rs` — the real binary,
  hard-failing when absent. libpq defaults to `sslmode=prefer`, so psql opens every
  connection with an `SSLRequest` and expects `N` back. It asserts the *rendered*
  result: `t`/`f` booleans, a real NULL distinguished from an empty string by
  `\pset null`, four columns and three rows in order, the `INSERT 0 1` tag, and the
  SQLSTATE psql prints under `\set VERBOSITY verbose`. And tokio-postgres's
  `simple_query` (`test.rs`).
- **Extended query**: psycopg 3 over libpq, `psycopg_client_test.rs` — bound
  parameters (int, text, NULL), binary results for int4, text, bool, float8, date
  and timestamp, text results, a parameterised write's tag, an error's SQLSTATE and
  a named prepared statement executed twice. And tokio-postgres
  (`extended_query_test.rs`, `parameters_test.rs`). tokio-postgres alone was not
  enough here: pgwire encodes binary values with `postgres-types`, the crate
  tokio-postgres decodes them with, so its agreement on binary cells is the
  server's own codec at both ends. psql 14 sends every statement as a simple
  `Query`, which is why the extended path needed psycopg.
**Port**: 5432 by default. **Privilege**: `None` (5432 > 1024).
**Stack**: `ETH>IP>TCP>PostgreSQL`.

## What the model sees and controls

**Event**: `postgresql_query`, fired once per statement on both the simple and
the extended query paths.

| Field | Notes |
|---|---|
| `query` | the SQL text |
| `parameters` | the values bound to `$1`…`$n`, in order (`null` is SQL NULL): text-format values as strings, binary ones decoded by type; present when the statement has placeholders, `null` while it is only being described |
| `parameter_types` | the type of each placeholder |
| `describe_only` | `true` when the client prepared the statement and asked for its columns before binding anything |
| `columns` | the columns a Describe already promised for this statement; the answer must use exactly these |
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

Every value is checked against its column's type before anything is sent
(`coerce_cell`): integers must be integers in range (a numeric string is read as
its number), floats numbers (or `NaN`/`Infinity`), booleans booleans or
`t`/`f`/`true`/`false`/`1`/`0`, and `date`/`time`/`timestamp` must parse
(`YYYY-MM-DD`, `HH:MM:SS`, `YYYY-MM-DD HH:MM:SS`). A value that does not fails
the statement `XX000`, logged `decision=fail_closed_unencodable_value`. It used
to be sent as something else — `"abc"` in an `int4` column as `0`, `"true"` in a
`bool` as `false`, `3000000000` in an `int4` wrapped negative — and a date in a
binary-format column went out as its ten ASCII bytes, which no driver decodes.

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
- **An answer in a different shape from the one already described** → `ERROR
  XX000`, logged `decision=fail_closed_column_mismatch`: rows with a different
  number of columns, or a command tag where rows were described.

## The extended query protocol

An extended-protocol client asks for the row description (Describe) *before* the
rows (Execute). The schema here is whatever the LLM returns, so the two steps
have to agree.

`do_describe_statement` / `do_describe_portal` resolve the statement, return its
`FieldInfo` list, and stash the whole outcome in a small per-connection cache
keyed by SQL text and bound parameters (`MAX_PENDING_DESCRIBES` = 64, oldest
evicted). `do_query` takes the cached outcome, so a Parse/Bind/Describe/Execute
round costs **one** model call, not two, and the RowDescription always matches
the DataRows.

### Parameters

`PostgresqlQueryParser` gives every statement one type per placeholder: the type
the Parse named, or `text` where it named none (PostgreSQL infers one from
context; a server with no planner cannot, and an unknown literal resolves to
`text` there too). The count is the higher of the types named and the highest
`$n` in the text (`highest_placeholder`, which skips string literals, quoted
identifiers, dollar-quoted strings and nested comments). The
ParameterDescription carries those types, and `bound_parameters` decodes each
Bind into the event's `parameters`; a count that does not match the statement is
`08P01`, invalid UTF-8 `22021`, a binary value of a type other than the integers,
floats, bool and text `0A000`.

Describe Statement happens **before** any Bind — tokio-postgres always does it —
so a statement with parameters is described with `describe_only` and nothing
cached; its Execute is a second model call, with the values and with `columns`
set to what was described. Each statement's described columns are kept
(bounded like the cache) so every later Execute of it is held to them.

This was the largest defect of the Stable pass: the model never saw a bound
value. `do_describe_statement` reported zero parameters, so tokio-postgres
refused to bind any, and psycopg's parameterised statements were answered with
`$1` still in the text and the value nowhere.

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
- **Malformed frontend messages are refused `FATAL 08P01`, before pgwire reads
  them** (IMPROVEMENTS #77). pgwire 0.42.3 is the first release that isolates each
  message's body and refuses a short one instead of panicking; before it, a Query
  with no NUL (six bytes after the handshake), a Close or Describe with no body,
  or a lying Bind panicked the connection task. What 0.42.3 still does with them
  is not PostgreSQL's answer: a message its decoder refuses ends the session with
  nothing written (`process_socket` returns `Ok`), and a Query with no NUL is
  served as an empty query. So the frontend screen (below) runs pgwire's decoder
  on every message first and refuses the ones it would not serve as sent; the
  close is logged `decision=refused_malformed_message`.
  `tests/pgwire_frontend_screen_test.rs` drives every shape found through the
  screen and checks Cargo builds pgwire 0.42.3 or later;
  `tests/server/postgresql/decoder_panic_test.rs` sends the six original frames to
  a running server and asserts exactly one ErrorResponse each. The panic
  containment above stays for any other panic in pgwire or the handler.
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
- **Binary parameters of types other than** int2/4/8, float4/8, bool and text —
  refused `0A000`; bind them in text format.
- **Type inference for untyped parameters** — they are `text`.
- **SQL-level cursors** (`DECLARE`/`FETCH`) reach the model as statements.
  Execute's `max_rows` is honoured — pgwire sends that many rows and
  `PortalSuspended` — but the model's whole answer is resolved at once.
- **Transactions** — `BEGIN`/`COMMIT`/`ROLLBACK` reach the model as ordinary
  statements; no transaction state is tracked.
- **`COPY`**, **`LISTEN`/`NOTIFY`**, arrays, JSON, ranges and other composite
  types.
- Multi-statement simple queries return a single response, not one per statement.

## Testing

Nine files, all declared in `tests/server/postgresql/mod.rs` (`tests/server/postgresql/AGENTS.md` has the table); besides those below,
`psycopg_client_test.rs` (psycopg/libpq, extended protocol), `parameters_test.rs`
(tokio-postgres: parameters, promised columns, cell values),
`bounds_test.rs` (every declared bound, both sides) and
`one_answer_per_query_test.rs`:

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
  connection row closes and the server keeps serving; each of the six frames that
  panicked pgwire 0.35 gets exactly one `FATAL 08P01` and a close; a query moves
  the connection counters off zero.
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
| `FIRST_BYTE_READ_TIMEOUT` (`first_byte_timeout_secs`) | 60s | Enforced with `TcpStream::peek` before the socket reaches pgwire, so the StartupMessage is untouched. Matches pgwire's own internal `STARTUP_TIMEOUT`, which bounds the startup *exchange*; this bounds the silence before it begins, which pgwire does not. |
| `IDLE_SESSION_TIMEOUT` (`idle_timeout_secs`) | 600s | Real PostgreSQL's `idle_session_timeout` ships disabled, so there is no upstream default to copy. Ten minutes, for the same reason as MySQL's: no tables, no temp tables, no open transaction, so a reaped pooled connection costs `tokio-postgres`, SQLAlchemy or pgbouncer one transparent reconnect. |
| `MAX_FRONTEND_MESSAGE_BYTES` | 1 MiB | See "The frontend screen" below. `MAX_STARTUP_PACKET_BYTES` (10 000, pgwire's and PostgreSQL's own) is checked by the same screen. |
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

## The frontend screen

`guard.rs` stands between the peer and pgwire, and it does two things pgwire does
not.

**Size.** pgwire bounds a Query, Parse or Bind at 0x3ffffffe bytes —
PostgreSQL's 1 GB — and buffers a message whole before decoding it. The bound is
a per-message-type constant in pgwire (`Message::max_message_length`), not a
setting, so there is nothing to configure. PostgreSQL can afford it because a
peer authenticates before it may send a Query; this server authenticates nobody,
so a stranger could make it hold a gigabyte per connection. Everything a message
carries goes to the model, so 1 MiB is the bound
(`guard::MAX_FRONTEND_MESSAGE_BYTES`), and 256 connections hold 256 MiB at most
rather than 256 GiB.

**Format.** Each typed message is decoded with pgwire's own decoder and
re-encoded (`guard::check_typed`); one that does not decode, or whose re-encoding
is not the bytes that arrived — an unterminated string, bytes after the last
field, a NULL written as length -2, an unknown type — is refused. The
StartupMessage is checked for PostgreSQL's layout, `name NUL value NUL` pairs
ended by a NUL and nothing after (`guard::check_startup`), because pgwire stops
reading parameters at the first malformed one and drops the rest. pgwire reads a
string lossily, so a message whose only difference on re-encoding is invalid
UTF-8 turned into U+FFFD, where the arrived bytes were invalid UTF-8, is passed on
as it arrived, as pgwire has always served it. An SSLRequest or GSSENCRequest
must be exactly 8 bytes: pgwire reads one as 8 bytes whatever it declares, so a
longer one would have the screen hold as its body a StartupMessage and typed
messages that pgwire reads and the screen never checked (found by the fuzz
target, seed `ssl_request_length_lie`).

pgwire has no seam for either — `process_socket` takes a concrete `TcpStream`
and owns every read — so NetGet keeps the peer's socket and serves pgwire one end
of a loopback pair (`guard::Backend::pair`, which accepts only the connection it
opened). `guard::relay` copies between the two, reading the frontend framing as
it goes. A message is refused by its **declared** length before its body is
read, and otherwise held until it is whole and checked, then forwarded, so
pgwire never sees part or all of a refused message. On a refusal the relay
half-closes pgwire's side so pgwire answers everything it already has and ends,
then writes `FATAL 08P01` and closes, logged `decision=refused_oversize_message`
or `decision=refused_malformed_message`. The relay holds one message per
connection, at most the bound; the check is one decode and one encode per
message, so the walk to the bound is linear.
`fuzz/fuzz_targets/pgwire_frontend.rs` feeds the same bytes to the screen whole
and a byte at a time, requires the same verdict, and requires pgwire to decode
every typed message the screen forwards.

**What it is for, against upstream pgwire.** pgwire 0.42.3 does not panic on a
malformed message, so the screen is not a panic guard. It is the part of
PostgreSQL's behaviour pgwire does not have: a size a server chooses,
`FATAL 08P01` for a message that does not decode (pgwire's `process_socket`
closes in silence), and an end-of-message check (pgwire's decoders accept a
message they did not read to the end). If pgwire comes to answer decode errors
`08P01` itself and to check the end of each message, `check_typed` and
`check_startup` can go; the size bound stays until pgwire lets a server choose
it.

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

## Maturity: the six conditions

The root `AGENTS.md` defines `Stable` as six conditions. Re-derived against source on
13 November 2026 rather than inherited. **The rating covers the surface this server
implements**: startup without authentication or TLS, the simple and extended query protocols,
bound parameters of the types above, results in the types above in either format. COPY,
LISTEN/NOTIFY, transactions as state, authentication, TLS and composite types are not
implemented, and the rating claims none of them.

| # | condition | holds? |
|---|---|---|
| 1 | two independent third-party clients, no skip, no `#[ignore]` | **yes, as of this pass** — simple query: psql (libpq) and tokio-postgres; extended query: psycopg 3 (libpq) and tokio-postgres. Before the pass the extended path rested on tokio-postgres alone, whose binary decoding shares `postgres-types` with pgwire's encoding, and no client bound a parameter |
| 2 | the pcap oracle is green over its wire traffic | **yes** — psql's sessions, tokio-postgres's prepared statement and psycopg's whole session (Parse/Bind with parameters, binary DataRows, the error) cross `recording_relay` and tshark's `pgsql` dissector reads them |
| 3 | a fuzz target exists and has run clean, with a depth bomb | **yes** — `pgwire_frontend` (upstream pgwire's frontend decoder), which also drives NetGet's frontend screen and placeholder scanner, with 30 000-level nested-comment and parenthesis bombs in the corpus; rebuilt this pass and run (nightly-2025-12-04, `-s none`, the `-undefined,dynamic_lookup` link flag, the fuzz workspace's lockfile seeded from the root `Cargo.lock`) `-max_total_time=300 -timeout=25` from the 19 committed seeds, both bombs among them, against pgwire 0.42.3 on 18 November 2026: 77 916 executions in 301 s, clean, 349 new units (kept out of the tree). The run before it, without the screen's SSLRequest length check, crashed in seconds on the bypass that check closes (`ssl_request_length_lie`) |
| 4 | every declared bound has a test | **yes, as of this pass** — `tests/server/postgresql/bounds_test.rs`: `MAX_FRONTEND_MESSAGE_BYTES` (at the bound, timed; one past, after a pipelined query is answered), `MAX_STARTUP_PACKET_BYTES`, `MAX_CONNECTIONS`, `MAX_PENDING_DESCRIBES` (64 stay cached, the 65th evicts), `first_byte_timeout_secs`, `idle_timeout_secs`, each verified by removing it |
| 5 | both `AGENTS.md` files verified against source in this pass | **yes** — this file and `tests/server/postgresql/AGENTS.md` |
| 6 | no `#[ignore]`, no skip-when-missing gate | **yes** — `grep -rn '#\[ignore' tests/server/postgresql/` is empty; psql and psycopg fail rather than skip |

What the pass found, each fixed and each with a test that fails without the fix:

- **Bound parameters never reached the model**, and the statement declared none (above).
- **The rows did not have to match the columns already described**: a prepared statement
  executed again was answered fresh, with nothing holding the model to its first answer.
- **Cell values were invented** when they did not fit their column, and **binary date, time
  and timestamp columns were undecodable**.
- **A gigabyte per unauthenticated connection** (the guard above).
- **A connection closed by the first-byte bound kept its row `Active`**: the early return
  skipped `close_connection_on_server`.
- This file said `max_rows` was ignored (pgwire honours it) and that results were text only
  (`metadata().notes`); both were wrong.
