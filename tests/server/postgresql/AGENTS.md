# PostgreSQL Protocol E2E Tests

Nine files, all declared in `tests/server/postgresql/mod.rs`. Three client
implementations, none of them the `pgwire` crate the server frames with:
`tokio-postgres` (Rust), `psql` 14 / libpq (C) and psycopg 3 over libpq (Python).

| File | Peer | What it proves | LLM calls |
|---|---|---|---|
| `test.rs` | tokio-postgres | Four simple-query cases through the mock-model harness | 8 |
| `extended_query_test.rs` | tokio-postgres | Parse/Describe/Bind/Execute really works | 0 |
| `parameters_test.rs` | tokio-postgres | bound parameters reach the model; an Execute is held to its Describe; a cell that is not its type fails closed | 11 |
| `psycopg_client_test.rs` | **psycopg / libpq** | the extended protocol from a second client: parameters, binary results of six types, a write, an error, a prepared statement twice; pcap oracle | 8 |
| `real_client_test.rs` | **psql / libpq** | A real session, asserted on what psql printed | 4 |
| `bounds_test.rs` | raw socket | every declared bound, both sides | 0 |
| `decoder_panic_test.rs` | raw socket | Each of the six frames that panicked pgwire 0.35 gets exactly one FATAL 08P01 and a close (NetGet's frontend screen; `tests/pgwire_frontend_screen_test.rs` has the full table); counters move | 0 |
| `llm_failure_test.rs` | tokio-postgres | The SQLSTATE a driver sees when the backend fails | 1 |
| `one_answer_per_query_test.rs` | tokio-postgres | a second response action is dropped and logged | 2 |

## The second client, and what it is for

One client can agree with one bug. `real_client_test.rs` exists because
tokio-postgres was the only peer this server had ever faced, and a rating resting
on one client rests on that client's leniency.

**What psql adds over tokio-postgres:**

- **The SSLRequest negotiation.** libpq defaults to `sslmode=prefer`, so psql
  opens every connection by asking for TLS and expecting a single `N` byte back
  before it sends the StartupMessage. `NoTls` skips that exchange entirely, so no
  test here had ever driven it.
- **The rendered result rather than the deserialised one.** The assertions are on
  the bytes a human sees: `t`/`f` for booleans, a real NULL distinguished from an
  empty string by `\pset null`, and the exact CSV lines in order. A
  column-count or column-order mistake fails as a wrong line, not a wrong count.
- **The SQLSTATE.** `\set VERBOSITY verbose` makes psql print the `C` field of
  the `ErrorResponse`, so the code the model chose is read off the wire.

**What it does not add:** psql 14 sends every statement as a simple `Query`
(`\bind` arrived in psql 16). The extended protocol's second client is
psycopg (`psycopg_client_test.rs`), and it is needed for more than coverage:
pgwire encodes binary cells with `postgres-types`, the crate tokio-postgres
decodes them with, so tokio-postgres alone agreeing on a binary `date` is the
server's own codec at both ends. psycopg found two defects tokio-postgres had
never shown: the model never saw a bound parameter (psycopg binds every value
server-side), and a binary `date` or `timestamp` column was sent as its text.

**On first contact psql completed a session with no server change required** —
the simple-query path, the SSLRequest negotiation, NULL, booleans, floats, the
command tag and the SQLSTATE all behaved. `sslmode=require` is correctly refused
(`server does not support SSL, but SSL was required`), which is the honest
outcome for a server that implements no TLS. The test was nevertheless verified
non-vacuous by breaking `encode_value` to send `Some("")` where a JSON `null`
arrives: psql then printed `2,bob,f,` and `3,,t,0.25` and the test failed naming
the missing `<NULL>`.

## Running

`--test` names a **target**, not a module path. `--test server::postgresql::test`
makes cargo list its targets and exit having run nothing — it does not fail, so
it silently looks like a pass. Use `--test server` and filter afterwards:

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
    --test server -- server::postgresql:: --test-threads=8
```

psql comes from `brew install postgresql@14` (or `postgresql-client`), psycopg
from `python3 -m pip install 'psycopg[binary]'`; both tests fail rather than skip
without them. `registry-audit` runs `postgresql::real_client_test`,
`postgresql::psycopg_client_test`, `postgresql::parameters_test` and
`postgresql::bounds_test` with both installed.

## The two protocols, and why that distinction cost a real bug

PostgreSQL has two query protocols, and **which one a test uses decides what it
can detect**:

- `client.simple_query(...)` sends a single `Query` message. There is no format
  negotiation: every cell is text, always.
- `client.query(...)` / `client.prepare(...)` send Parse → Describe → Bind →
  Execute. The Bind names the wire format of **each result column**, and
  tokio-postgres asks for **binary**.

Every test in `test.rs` used `simple_query`. The server hardcoded
`FieldFormat::Text` for the RowDescription and for every cell, so it was correct
for the only path under test and wrong for the other one: `client.query` against
any non-text column returned `error deserializing column 0`.

That symptom was recorded in this file for a long time as *"Extended Query
Protocol Timeout (CRITICAL) … Status: **UNRESOLVED** - root cause unknown"*,
with the advice to "use simple queries instead" — which is what kept the suite
away from the one path that would have shown the defect. It was never a timeout.
`extended_query_test.rs` exists so that cannot recur, and it runs with **no LLM
in the loop at all** (a `*` static handler), so a hang there is unambiguously
ours.

**The general lesson**: when a protocol has two paths and the suite only exercises
one, "works" means "works on the tested path". This is the same shape as the MySQL
prepared-statement defect found in the same pass — there, every test used
`conn.query*` (text protocol) and `conn.exec*` (binary) had never worked.

## Zero-LLM tests

`extended_query_test.rs` and `decoder_panic_test.rs` build their servers directly
through `ServerForm` with a `*` static handler, rather than through the
mock-model harness.

Both pass **`instruction: Some(String::new())`**. This is load-bearing:
`ServerForm::create` substitutes a default instruction (`"You are a {protocol}
server…"`) whenever `instruction` is `None`, and any non-empty instruction makes
`operator_wants_dynamic` true — so a server built with `..Default::default()`
consults the model whatever the test's comments claim. Two `peer_inject` tests
elsewhere in this repo documented "Zero LLM calls" while doing the opposite.

The one exception is
`an_unanswerable_extended_query_errors_rather_than_returning_no_rows`, which
deliberately *does* want a model it cannot reach: it sets a real instruction and
no handlers, pointing at a closed port, to assert the extended path fails closed
rather than answering with an empty result set.

## LLM call budget

`test.rs`: 4 tests × (1 startup + 1 query) = **8 calls**.
`llm_failure_test.rs`: **1 call** (the startup; the query call is answered 500 on
purpose).
`real_client_test.rs`: **4 calls** — 1 startup plus 3 statements, all answered by
one `respond_with_actions_from_event` rule that branches on the query. Two
sessions share the server, so the startup handshake runs twice for one startup
call.

`parameters_test.rs`: **11** — the startup, then describe + execute for each
parameterised statement (a statement described before its Bind is asked twice:
once for its columns, once with its values), and one each for the unencodable
values. `psycopg_client_test.rs`: **8** — the startup and one per statement;
psycopg describes the portal after binding, so each costs one.

`extended_query_test.rs`, `decoder_panic_test.rs` and `bounds_test.rs` cost
**0** — they neither start a netget subprocess nor reach a model.

## Waiting

The mocked suites call `wait_for_mocks(30)` before `verify_mocks()`: a protocol
exchange finishes with the last LLM call it provokes, so waiting on the
expectations waits on the exchange. The zero-LLM suites poll for the condition —
a bound port, a closed connection row, a non-zero counter — rather than sleeping.

## Failure semantics under test

`llm_failure_test.rs` asserts the peer gets an `ErrorResponse` with a SQLSTATE
rather than silence, and reads it back through tokio-postgres.
`an_unanswerable_extended_query_errors_rather_than_returning_no_rows` additionally
asserts the message is netget's own `WireFailure` category and that it leaks no
backend URL, model name or transport error text — the peer gets a category, the
log gets the error.

## Not covered

- **Authentication and TLS** — the server implements neither.
- **`COPY`, `LISTEN`/`NOTIFY`, SQL cursors, arrays and composite types.**
- **Multi-statement simple queries** return a single response, not one per
  statement.
- **Binary parameters of other types** than integers, floats, bool and text —
  refused `0A000` by the server; no test binds one.

## Stable conditions 2 and 3: the pcap oracle and the fuzz target

**Condition 2.** Both psql sessions in `real_client_test.rs`, the prepared-statement test in
`extended_query_test.rs` and psycopg's whole session in `psycopg_client_test.rs` cross a
recording relay, and the pcap oracle reads every stream with
Wireshark's `pgsql` dissector: libpq's SSLRequest and the `N` refusal, startup,
RowDescription/DataRow/CommandComplete for a three-row SELECT, a command tag, an ErrorResponse
with SQLSTATE, and tokio-postgres's Parse/Describe/Bind/Execute/Sync with a binary-format
DataRow; psycopg's Parse/Bind with parameters, binary DataRows of six types and an
ErrorResponse.

**Condition 3.** `fuzz/fuzz_targets/pgwire_frontend.rs` drives upstream `pgwire`'s frontend
decoder — the version and features the root manifest builds — through the SSL, startup and query
states, and NetGet's own code on the same bytes: the frontend screen (`guard::FrontendScreen`, fed
whole and a byte at a time, which must agree, and every typed message it forwards must decode in
pgwire) and the placeholder scanner and statement classifier on every SQL text. The protocol is
flat, but PostgreSQL comments nest and the scanner counts them, so the corpus carries 30 000-level
nested-comment and parenthesis bombs as well as length lies and a 60 000-parameter Bind. Its first
seed found an upstream defect, since fixed upstream: `CopyFail::message_type()` was `b'c'`,
CopyDone's tag, so pgwire's *encoding* of a CopyFail did not decode. The screen re-encodes every
message it checks, so `tests/pgwire_frontend_screen_test.rs` keeps the round trip. Against
pgwire 0.42.3 its "every forwarded message decodes" check found an SSLRequest declaring more than
8 bytes carrying a StartupMessage and typed messages past the screen, since pgwire reads an
SSLRequest as 8 bytes whatever it declares; the screen refuses one now, and the seed is
`ssl_request_length_lie`. Rebuilt and run (nightly-2025-12-04, `-s none`, the
`-undefined,dynamic_lookup` link flag, the fuzz workspace's lockfile seeded from the root
`Cargo.lock`) `-max_total_time=300 -timeout=25` from the 19 committed seeds on 18 November
2026: 77 916 executions in 301 s, clean, 349 new units (kept out of the tree).

## Condition 4: `bounds_test.rs`

Model-free (a dead LLM port, a static rule), raw frontend messages:

| bound | at the bound | one past it |
|---|---|---|
| `MAX_FRONTEND_MESSAGE_BYTES` (1 MiB) | a Query of exactly that size is answered, timed | refused `FATAL 08P01` on its header alone, after the Query pipelined before it is answered |
| `MAX_STARTUP_PACKET_BYTES` (10 000) | a StartupMessage of that size completes startup | `FATAL 08P01` |
| `MAX_CONNECTIONS` (256) | the 256th completes startup | the 257th reads `53300` |
| `MAX_PENDING_DESCRIBES` (64) | 64 described statements: executing the first asks the handler nothing (`access_log_total` unchanged) | 65: the first was evicted and is resolved again |
| `first_byte_timeout_secs` | a started peer is served; the silent peer's row closes | a silent peer is closed |
| `idle_timeout_secs` | queries inside the window are answered | a silent session is closed |

Each was checked by removing the bound in `src/server/postgresql/` and watching its test fail.
