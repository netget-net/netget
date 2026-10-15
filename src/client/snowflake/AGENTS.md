# Snowflake client

NetGet as a Snowflake connector: it logs in over Snowflake's connector REST protocol, and the
model decides what SQL to run and reads typed rows back. Feature `snowflake` (shared with the
server, `src/server/snowflake/`). **Experimental** — see Maturity below.

Rust owns the HTTP and JSON envelope, the `Authorization: Snowflake Token="…"` header, the
session and master tokens, polling, result decoding and every bound. The model never sees the
envelope, a token or a byte of Arrow.

| file | what |
|---|---|
| `mod.rs` | `resolve_endpoint`, `Session` (login, `execute`, renewal, polling, logout), the session and turns tasks |
| `result.rs` | a query response's `data` → `snowflake_query_result`: `rowtype` read as logical types, JSON rowsets and Arrow cells typed by them, every result bound |
| `arrow.rs` | a hand-written, bounded Arrow IPC stream reader for `rowsetBase64` |
| `actions.rs` | events, actions, startup parameters, metadata |

## The target is mandatory, and it is the only host contacted

The client talks to `endpoint_url` exactly as given, else to its `remote_addr` (`host:port`
means `http://host:port`). Without either it refuses to start. **It never derives
`<account>.snowflakecomputing.com`** from the account name — `account` is sent as
`ACCOUNT_NAME` and decides nothing about where the client connects. The same rule holds after
login: a `getResultUrl` must resolve to the target's origin (`http_fetch::resolve_same_origin`)
or the statement fails, and a result's `chunks` (presigned cloud-storage URLs) are counted and
reported, never fetched. Plain HTTP is the normal case here — both test peers speak it; HTTPS
works natively through reqwest's rustls. Redirects are not followed.

## The conversation

`connect()` logs in before it returns, so a refused login fails client creation and the model
is never asked anything (`decision=fail_closed_login`):

| request | notes |
|---|---|
| `POST /session/v1/login-request?request_id=…&databaseName=…&schemaName=…&warehouse=…&roleName=…` | body `{"data": {CLIENT_APP_ID: "NetGet", LOGIN_NAME, PASSWORD, ACCOUNT_NAME?, CLIENT_ENVIRONMENT, SESSION_PARAMETERS: {}}}`. `SESSION_PARAMETERS` is always sent: fakesnow indexes it unconditionally. `success:false` → `connect` fails naming the code |

Then one action at a time:

| action | HTTP | event |
|---|---|---|
| `run_sql` | `POST /queries/v1/query-request?requestId=…` with `{sqlText, asyncExec: false, sequenceId, …}` | `snowflake_query_result` or `snowflake_error` |
| `logout` | `POST /session?delete=true` | none; the client ends `Disconnected` |

Inside one `run_sql`:

- **390112** (session expired) → `POST /session/token-request` with the master token as the
  `Authorization` and `{oldSessionToken, requestType: "RENEW"}`, then the statement once more.
  At most one renewal per statement; a refused renewal is a `snowflake_error`.
- **333333 / 333334** (still running) → `GET` the same-origin `getResultUrl` every 500 ms until
  it answers otherwise, at most `MAX_POLLS` times and within `request_timeout_secs`.

The action is `run_sql`, not `execute_sql`: `execute_sql` is NetGet's own SQLite **tool**
(`TOOL_ACTION_NAMES` in `src/llm/actions/tools.rs`), and the LLM layer routes any action of a
tool's name to the tool. A protocol action under that name parses as a malformed tool call and
never reaches the client.

## Results

`result.rs`'s header table is the contract. In short: FIXED scale 0 a number (a string past 64
bits), FIXED with a scale an exact decimal string, REAL a number, BOOLEAN a bool, DATE
`2026-10-14`, TIME `12:34:56` plus the column's scale of fraction digits, TIMESTAMP_NTZ without
a zone, TIMESTAMP_LTZ as the UTC instant (`…Z`), TIMESTAMP_TZ with its offset, VARIANT/OBJECT/
ARRAY as the JSON value, BINARY as `{binary_length}` (never bytes), NULL as `null`. Rows are
objects keyed by column name; a repeated name gets `_2`, `_3`.

**Both result formats are read, because a server picks.** Snowflake answers JSON (`rowset`,
every cell a string) or Arrow (`rowsetBase64`). Asking for JSON is not enough: fakesnow answers
every SELECT in Arrow regardless. `arrow.rs` reads the subset a Snowflake result uses — Int,
FloatingPoint, Bool, Utf8, Binary, Decimal128, Date, Time, Timestamp, Null and one level of
Struct (Snowflake's `{epoch, fraction[, timezone]}` timestamps) — and refuses dictionaries,
compression, big-endian data and every nested type by name.

**A cell that does not read as its column's type is handed on as the server's text, with a
`decode_warnings` entry naming the column and why.** It is never guessed into a plausible value.
snowflake-emulator is the worked example: it writes NULL as `""` and DATE as a Go time string
(`2026-10-14 00:00:00 +0000 UTC`), and the model sees both as they came, flagged.

One deliberate leniency: fakesnow marks a NULL timestamp in the struct's **children** rather
than on the struct (pyarrow then reads it as the epoch, `1970-01-01`, which is what
snowflake-connector-python reports). A struct whose every child is null is read as NULL.

DML answers with a row of `number of rows inserted/updated/deleted` columns; their sum is
`rows_affected`. `total` is the server's own count (the emulator reports affected rows there and
sends no rowset).

## Bounds

| bound | value | where |
|---|---|---|
| a response body | 16 MiB | `MAX_RESPONSE_BYTES`, enforced while reading (`FetchClient::with_max_body`) |
| columns | 1024 | `result::MAX_COLUMNS` |
| rows delivered | `max_rows` (default 100, at most 1000); more → `truncated` | `DEFAULT_MAX_ROWS`, `MAX_ROWS_LIMIT` |
| a text cell | 16 KiB, then cut and counted in `truncated_cells` | `result::MAX_CELL_BYTES` |
| VARIANT nesting | 64 levels, measured iteratively before parsing; deeper → text + warning | `result::MAX_VARIANT_DEPTH` |
| Arrow messages / fields / field nesting | 4096 / 2048 / 1 | `arrow::MAX_MESSAGES`, `MAX_FIELDS`, `MAX_FIELD_NESTING` |
| a statement | 1 MiB | `MAX_SQL_BYTES` |
| polls of a running query | 1000, 500 ms apart | `MAX_POLLS` |
| a login, or a statement with its polling | `request_timeout_secs`, default 120 s | `REQUEST_TIMEOUT` |
| model turns from one another | 8 | `MAX_FOLLOWUP_DEPTH`, `decision=followup_depth` |
| events waiting for the model | 64 | `TURNS`, `decision=turn_queue_full` |

No decoder recurses: the Arrow schema's one level of children is read in a second loop.

## Fail closed

- A refused or failed login fails `connect()`; the client never reads as connected.
- An LLM failure sends nothing: `decision=fail_closed_llm_error`, and the session waits.
- A statement the server refuses, a response that is not JSON, too large, unreadable as its
  declared types or timed out becomes a `snowflake_error` naming why; no result is invented.
  The session stays open — HTTP holds no connection state a failed request could corrupt.

## Evidence and maturity

`tests/client/snowflake/` (see its `AGENTS.md`): **fakesnow 0.11.22** (Python, Arrow results)
and **snowflake-emulator v0.0.9** (Go, JSON results), two independent re-implementations of the
connector protocol over DuckDB, each read back by a second session; Snowflake's own Python
driver is that second session for fakesnow.

**Experimental.** The client Beta bar's conditions 2–4 hold for both servers, and condition 1
asks for two independent third-party servers, which this has — but both are emulators, each
reproducing a subset of Snowflake (fakesnow forces Arrow and issues no master token; the
emulator mis-encodes NULL, DATE and TIME), and no test touches a real Snowflake account. Token
renewal and query polling are exercised only against a scripted server, because neither
emulator issues expiring tokens or answers `333334`. That is a judgement call left to a human;
nothing here claims Beta.

## Not implemented

Bound parameters (`bindings`), multi-statement requests, `PUT`/`GET` stage transfers, result
chunks (counted, never fetched), the heartbeat, MFA / key-pair / OAuth / SSO authenticators,
query cancellation (`abort-request`), session-parameter negotiation.
