# MySQL Protocol E2E Tests

## Test Overview

**Two independent clients, and the second one is the point.** `mysql_async` (a Rust
reimplementation) covers query execution, multi-row results, DDL, the binary
(prepared-statement) protocol and rows whose value count disagrees with the column list.
`real_client_test.rs` drives the **real `mysql` CLI**, which is the client a person actually
types, and it hard-fails rather than skipping when the binary is absent — a skip would put the
protocol's maturity rating back on one client.

## `real_client_test.rs` — the second client

Two tests, one server each.

- `test_mysql_real_client_selects_and_errors` — one connection, `--force`, two statements: a
  `SELECT` whose rows the model authors and a statement answered with an ERR packet. The
  assertions are on what the **client printed**: the tab-separated rows on stdout, and
  `ERROR 1146 (42S02)` with the model's message on stderr.
- `test_mysql_real_client_with_a_password_completes_fast_auth` — the same handshake with
  `--password=…`, which is a different code path: a client that sent a 32-byte
  `caching_sha2_password` scramble blocks reading for the `AuthMoreData` `0x01 0x03` packet
  before it will accept the OK packet, while a client with an empty password expects the OK
  alone. Nothing about the password is checked — **this server verifies nothing** — the test
  exists because the two branches are different bytes on the wire.

**Both tests failed before September 2026 with `ERROR 2059 … mysql_native_password cannot be
loaded`**, which is what they are the regression test for. Verified by removing the three auth
hooks from `src/server/mysql/mod.rs` and watching both fail with that message in the panic.

### The `select $$` trap, which costs a debugging pass if you do not know it

The CLI issues two queries of its own before yours:

| query | what a real `mysqld` 9.3.0 answers |
|---|---|
| `select @@version_comment limit 1` | a one-row result set |
| `select $$` | **ERR 1064**, SQLSTATE 42000 |

Answer `select $$` with a result set — which is what a single catch-all rule does — and the
client is left holding one it never read. Your actual statement then fails with `ERROR 2014
(HY000): Commands out of sync`, and it reads exactly like a framing bug in the server. The
mock rules here answer it the way the real server does.

Neither probe carries a strict `expect_calls`: how many system variables a client asks about,
and whether it still sends `$$`, is that client version's business. The `@@` rule uses
`expect_at_least(1)`, the `$$` rule asserts nothing, and the load-bearing assertions are on
the CLI's own output.

`tokio::process::Command`, never `std::process` — `#[tokio::test]` gives a current-thread
runtime, and a blocking `output()` parks the only worker, which is also what has to drain the
child's pipes: the test deadlocks instead of failing.

## Test Strategy

**Consolidated Approach**: Multiple test functions but each tests a distinct MySQL feature (simple query, multi-row,
DDL). Each test spawns its own server with specific instructions.

**Why not more consolidated?** MySQL tests are already efficient - each test targets a different protocol feature and
completes quickly.

## LLM Call Budget

### Test: `test_mysql_simple_query`

- **1 server startup** (scripting disabled, action-based only)
- **1 SELECT 1 query** → LLM call for query response
- **Total: 2 LLM calls**

### Test: `test_mysql_multi_row_query`

- **1 server startup**
- **1 SELECT * FROM users query** → LLM call for multi-row response
- **Total: 2 LLM calls**

### Test: `test_mysql_create_table`

- **1 server startup**
- **1 CREATE TABLE query** → LLM call for DDL response
- **Total: 2 LLM calls**

### `prepared_statement_test.rs`

Three tests, each **1 server startup + 2-3 query calls** (mysql_async issues one `SELECT @@*`
during handshake, then the statement). `placeholder_counting_skips_literals_and_comments` is a
pure unit test and makes **0** LLM calls.

### `prepared_params_test.rs` / `stmt_params_test.rs`

The bound parameter values, and the refusal of malformed `COM_STMT_EXECUTE` packets (see
"Prepared-statement parameters" in `src/server/mysql/AGENTS.md`).

- `stmt_params_test.rs` makes **0** LLM calls: the decoder against packets built byte by byte
  (every type, every `opensrv-mysql` `ParamParser` panic shape, lying lengths, every prefix of a
  valid packet), the `⟨ ⟩` rendering, and `CommandTapReader` read 1, 2, 3, 7 and 4096 bytes at a
  time so the framing is exercised at every split.
- `mysql_async_bound_values_reach_the_model_with_their_types`: 1 startup + `SELECT @@…` + **1**
  execute. The mock records the event; the assertions are on its `params` and `query_rendered`.
- `malformed_executes_get_an_err_packet_and_the_connection_survives`: 1 startup + **4** executes.
  Nine malformed executes are sent from a raw socket first and make **0** calls — the final
  assertion is that exactly the four well-formed ones reached the model. A raw socket because no
  real client will send a malformed execute, and `CLIENT_DEPRECATE_EOF` so the PREPARE reply has
  no EOF packet to account for.

- `pipelined_commands_reach_opensrv_one_packet_per_read` (0 LLM calls) runs a bare
  `opensrv-mysql` server beneath `CommandTapReader` over an in-memory pipe and sends two long-data
  chunks and an execute in one write. It is the regression test for the crate's use-after-free on
  pipelined packets (`src/server/mysql/AGENTS.md`).

- `long_data_past_its_bounds_never_reaches_the_crate` (0 LLM calls) reads a stream through
  `LongDataGate::with_limits(…, 100, 150)` and the tap, as the server stacks them, and checks
  the crate is handed exactly the admitted packets: a statement's second chunk past 100 bytes
  and a fourth statement's chunk past 150 across the connection are withheld, and an execute
  and a `COM_STMT_CLOSE` release their statement's count.
- `long_data_past_max_allowed_packet_is_refused_at_execute`: 1 startup + **1** execute. Five 16 MB
  chunks (80 MB on loopback — the cost of the real 64 MiB bound), then an execute answered ERR
  1105 with mysqld's text and no model call, then one that works.

The raw-socket test tells the model's OK from the crate's own by `affected_rows` (the mock answers
1; the crate's OKs carry 0), because a stray OK from the crate is exactly the failure the
pipelining fix exists for. Verified by mutation: letting a read cross a packet boundary fails the
pipelining test (both long-data chunks then draw a stray OK) and the raw-socket test; answering a
decode failure by running the statement anyway fails the raw-socket test on its first case.

### `llm_failure_test.rs` / `connection_stats_test.rs`

`connection_stats_test` runs with a static handler and makes **0** LLM calls, which is what
makes it a counter test rather than a timing test.

### `packet_limit_test.rs`

Four tests. Two are pure framing tests against `PacketLimitReader` and make **0** LLM calls:
they drive the decision at an exact boundary and across a legitimate multi-fragment chain,
using the reader's `with_limit` constructor so the boundary can be asserted at 1 KiB rather
than at 64 MiB. The wire test makes **1** call (the startup) and asserts **zero**
`mysql_query` calls, because the oversized packet is sent as the *handshake response* — the
bound is pre-authentication, so nothing the model could be asked about has happened. The
control makes 1 startup + 2 query calls.

Two things about the wire test are deliberate and worth keeping:

- **A raw socket, not `mysql_async`.** The refusal has to survive the peer still writing, and
  a client that polls its read side while writing can parse the answer before the close lands
  — hiding exactly the RST-discards-the-reply failure the drain exists to prevent. The `ipp`
  suite measured that difference at 5 failures in 8 runs versus 5 in 5.
- **`ONE_OVERSIZED_PACKET_AT_A_TIME`.** Reaching a 64 MiB bound costs 64 MiB on the wire by
  construction: the refusal is taken at the header that crosses it, so every earlier
  fragment's payload really has to be delivered. Same reasoning as `ipp`'s serialising mutex.

### `real_client_test.rs`

Two tests. Each is 1 startup + the CLI's own `@@` and `$$` probes + the statements the test
issues: **4** calls for the selects-and-errors test, **4** for the password one. It reads as
more than `mysql_async` costs because the CLI talks to the server before it talks for you.

**Total for the MySQL suite: ~29 LLM calls across 15 tests**, each test on its own server.

The raw-socket assertion in `packet_limit_test.rs` is also the suite's only check that a MySQL
packet reaches the wire as **one** write. It caught `FastAuthWriter` not implementing
`poll_write_vectored`, which split every packet into a 4-byte header and a body — nothing else
in the suite could see the difference, because every real client reassembles.

## Scripting Usage

**Scripting Disabled**: All tests use `ServerConfig::new()` which disables scripting by default. MySQL tests rely on
action-based responses for flexibility in testing different query patterns.

**Why no scripting?** MySQL queries are highly variable (SELECT vs DDL vs DML), making scripting less practical.
Action-based responses provide better test coverage.

## Client Libraries

**the `mysql` CLI** (9.3.0 here, anything 8.0+ will do):

- The client a user actually types, and a separate C implementation — the reason this
  protocol's rating does not rest on one lenient client.
- Driven as a subprocess in `real_client_test.rs`; never linked.
- Required, not optional: the test fails with install instructions if it is missing.

**mysql_async** v0.34:

- Full-featured async MySQL client using tokio
- Supports both simple and prepared statements
- Handles connection handshake and authentication
- Provides typed result extraction
- Used for protocol correctness validation

**Client Setup**:

```rust
let opts = mysql_async::OptsBuilder::default()
    .ip_or_hostname("127.0.0.1")
    .tcp_port(port)
    .user(Some("root"))
    .pass(Some(""));
let pool = mysql_async::Pool::new(opts);
let mut conn = pool.get_conn().await?;
```

## Expected Runtime

**Model**: qwen3-coder:30b (default)
**Total Runtime**: ~40-60 seconds for all 3 tests
**Breakdown**:

- Each test: ~15-20 seconds (1 startup + 1 query call)
- Variability: LLM response time, network latency

**Optimization**: Tests could be parallelized but already fast enough individually.

## Failure Rate

**Historical**: ~5% failure rate
**Causes**:

1. **Connection timeout**: Client timeout (10s) expires before LLM responds
2. **Type mismatch**: LLM returns wrong column type (e.g., VARCHAR instead of INT)
3. **Empty result**: LLM forgets to include query_response action
4. **Variable queries**: `SELECT @@*` system variable queries may confuse LLM

**Mitigation**:

- Explicit prompts for system variable queries
- Timeout extended to 10s (may need longer for slow models)
- Test retries on timeout failures

## Test Cases

### 1. Simple Query (`test_mysql_simple_query`)

**Validates**: Basic SELECT query with single row

- Connects to MySQL server
- Executes `SELECT 1`
- Verifies result is integer `1`
- **Expected LLM Response**: `mysql_query_response` with INT column

### 2. Multi-Row Query (`test_mysql_multi_row_query`)

**Validates**: SELECT query returning multiple rows

- Executes `SELECT * FROM users`
- Expects 3 rows: Alice, Bob, Charlie
- Verifies row count and data structure
- **Expected LLM Response**: `mysql_query_response` with 3-row array

### 3. CREATE TABLE (`test_mysql_create_table`)

**Validates**: DDL operation handling

- Executes `CREATE TABLE test (id INT PRIMARY KEY)`
- Expects success or non-fatal error
- Tests server doesn't crash on DDL
- **Expected LLM Response**: `mysql_ok` with affected_rows=1

## Known Issues

### System Variable Queries

**Issue**: `SELECT @@version_comment`, `SELECT @@max_allowed_packet` etc.
**Symptom**: mysql_async client sends these during connection setup, LLM may not handle them
**Workaround**: Prompt explicitly instructs LLM to return `mysql_query_response` for `SELECT @@*` queries
**Example Fix**:
`For SELECT @@* queries, return mysql_query_response columns=[{name:'value',type:'VARCHAR'}] rows=[['1000']]`

### Connection Timeout

**Issue**: LLM takes >10s to respond, client times out
**Symptom**: "Connection timeout" error
**Workaround**: Consider increasing timeout to 30s for slow models
**Not Flaky**: Consistent on slow hardware/models

### Type Precision

**Issue**: LLM may return string `"1"` where the column is declared `INT`.
**Status**: Handled. `write_cell` coerces the JSON value to the declared column type (a
numeric string parses), and a value that genuinely cannot be represented is sent as **NULL**
with a WARN rather than as a wrong number or as an error that ends the session.

**This used to say "implementation converts JSON to strings; client parses strings to expected
types", and that was the bug, not the workaround.** It is true of the *text* protocol only. In
the binary protocol (`conn.exec*`) opensrv-mysql encodes by `Column::coltype` and rejects a
string for any numeric or temporal column with an `io::Error` that ends the session — so the
protocol's own advertised example, `{"name": "id", "type": "INT"}`, killed the connection on
every prepared statement. `prepared_statement_test.rs` is the regression test.

## Test Execution

```bash
# Run all MySQL server tests. `--test` names a test *target*; `server` is the target and the
# filter goes after `--`. `--test server::mysql::test` makes cargo list targets and exit.
./cargo-isolated.sh test --no-default-features --features mysql \
    --test server -- server::mysql --test-threads=100

# Run one test
./cargo-isolated.sh test --no-default-features --features mysql \
    --test server -- server::mysql::test::test_mysql_simple_query

# Run with output
./cargo-isolated.sh test --no-default-features --features mysql \
    --test server -- server::mysql --nocapture
```

## Test Output Example

```
=== E2E Test: MySQL Simple Query ===
Server started on port 54321
Connecting to MySQL server...
✓ MySQL connected
Executing SELECT 1...
✓ Received correct result: 1
✓ MySQL simple query test passed
```

## Future Improvements

1. **Transactions**: Test BEGIN/COMMIT/ROLLBACK sequences
2. **Consolidation**: Merge tests into a single server with multiple queries

Done, and recorded so they are not re-listed: prepared statements
(`prepared_statement_test.rs` covers PREPARE with and without a bound parameter, and the
binary result-set encoding for INT/BIGINT/DOUBLE/VARCHAR/TEXT plus SQL NULL) and
LLM-generated error responses (`llm_failure_test.rs`; opensrv-mysql has had
`QueryResultWriter::error` since 0.4, so "once opensrv supports errors" was never true).
