# PostgreSQL Protocol E2E Tests

Five files, all declared in `tests/server/postgresql/mod.rs`. **Two** peers, and
neither is the `pgwire` crate the server frames with, so nothing here is
circular: `tokio-postgres` (Rust) and `psql` 14 / libpq (C).

| File | Peer | What it proves | LLM calls |
|---|---|---|---|
| `test.rs` | tokio-postgres | Four simple-query cases through the mock-model harness | 8 |
| `extended_query_test.rs` | tokio-postgres | Parse/Describe/Bind/Execute really works | 0 |
| `decoder_panic_test.rs` | raw socket | A malformed Query gets FATAL 08P01, not a panic (`vendor/pgwire`); counters move | 0 |
| `llm_failure_test.rs` | tokio-postgres | The SQLSTATE a driver sees when the backend fails | 1 |
| `real_client_test.rs` | **psql / libpq** | A real session, asserted on what psql printed | 4 |

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
(`\bind` arrived in psql 16), so the extended protocol and the binary result
format are still proven by tokio-postgres and by nothing else. The two clients
are complementary rather than overlapping, which is the point.

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
./cargo-isolated.sh test --no-default-features --features postgresql \
    --test server -- server::postgresql --test-threads=100
```

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

`extended_query_test.rs` and `decoder_panic_test.rs` cost **0** — they neither
start a netget subprocess nor reach a model.

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
- **Bound parameter values.** `$1` placeholders reach the model as literal text;
  `do_describe_statement` reports zero parameters, so a driver that binds real
  parameters gets a statement it believes takes none.
- **`COPY`, `LISTEN`/`NOTIFY`, cursors/`FETCH`, arrays and composite types.**
- **Multi-statement simple queries** return a single response, not one per
  statement.
- **psycopg, or any client that binds real parameters.** `real_client_test.rs`
  covers psql; psycopg in a binary mode would additionally drive the extended
  path from a non-Rust client, which nothing here does.

## Stable conditions 2 and 3: the pcap oracle and the fuzz target

**Condition 2.** Both psql sessions in `real_client_test.rs` and the prepared-statement test in
`extended_query_test.rs` cross a recording relay, and the pcap oracle reads every stream with
Wireshark's `pgsql` dissector: libpq's SSLRequest and the `N` refusal, startup,
RowDescription/DataRow/CommandComplete for a three-row SELECT, a command tag, an ErrorResponse
with SQLSTATE, and tokio-postgres's Parse/Describe/Bind/Execute/Sync with a binary-format
DataRow.

**Condition 3.** `fuzz/fuzz_targets/pgwire_frontend.rs` drives `pgwire`'s frontend decoder —
the patched copy in `vendor/pgwire`, which the fuzz workspace patches in the same way the root
manifest does — through the SSL, startup and query states. The format is flat; the corpus
carries length lies and a 60 000-parameter Bind. Its first seed found an upstream defect:
`CopyFail::message_type()` was `b'c'`, CopyDone's tag, so pgwire's *encoding* of a CopyFail did
not decode. The server only decodes CopyFail and was unaffected; `vendor/pgwire` now carries the
fix and `tests/vendored_pgwire_patch_test.rs` the round trip. Run 120 s clean on 6 November
2026 (unoptimised, `-s none`, macOS): 12 812 executions, no crash.
