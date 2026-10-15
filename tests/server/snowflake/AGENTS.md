# Snowflake Server E2E Tests

Declared in `tests/server/mod.rs` (`pub mod snowflake;`).

## Against the official Python driver

`real_client_test.rs` runs **snowflake-connector-python 4.8.0** (`connector_peer.py`, from the
venv `tests/client/snowflake/install_peers.sh` builds; `NETGET_SNOWFLAKE_PEERS` must point at
it, and the test **fails** rather than skips without it) against one NetGet server, three times:

| run | the model | the driver shows |
|---|---|---|
| `analyst`, `SELECT * FROM notes ORDER BY id` | grants the login (`has_password` true), answers a six-column rowset | `[1, "123.45", "hello", true, "2026-10-14", "2026-10-14 12:34:56.123456"]` and an all-NULL row — typed by the driver's own JSON converters (a `Decimal` for FIXED scale 2, a `date` from day count 20740, a `datetime` from `seconds.fraction`); `sfqid` is the model's query id; `description` says FIXED scale 2 |
| `analyst`, `SELECT * FROM nope` | `snowflake_error` 002003 with `sql_state` 42S02 | `ProgrammingError`, errno 2003, sqlstate 42S02 |
| `intruder` | `snowflake_error` 390100 at login | a 390100 error, no rows |

Both granted sessions end with the driver's `POST /session?delete=true`, which must reach the
model as `op=logout decision=model_answer`. LLM calls: 8. Run with
`--test server -- snowflake::real_client_test` after exporting `NETGET_SNOWFLAKE_PEERS`.

Each of the three server fixes it led to (gzip bodies, the logout route, `data` on a query
error) was checked by reverting it: the test fails at the login, at the logout assertion and at
the error run respectively.

## Against reqwest

## Strategy

Real Snowflake drivers are hard to point at localhost, so these tests **drive the
exact REST/JSON endpoints** a driver uses with `reqwest` against a running NetGet
server (LLM mocked) and assert the envelope shapes a genuine connector expects.
This is envelope-shape evidence, **not** a real-driver-on-a-live-connection test.

Cited driver expectations:
- Login success returns `data.token` / `data.masterToken` / `data.sessionId`; the
  connector sends the token back as `Authorization: Snowflake Token="..."`.
- Query success returns `data.rowtype` + `data.rowset` (every cell a string) with
  `queryResultFormat: "json"`.
- Failures are HTTP 200 with `success:false` and a `code`.

## Tests & LLM call budget (all mocked)

| Test | Flow | Mock LLM calls |
|---|---|---|
| `test_snowflake_login_and_query` | startup + login + query | 3 |
| `test_snowflake_login_refused` | startup + refused login | 2 |

**Total: 7** (under the ~10 budget). Each finishes `server.verify_mocks().await?`.

`llm_failure_test` is the third test and covers the case the other two cannot: not a
model *denial* (that is `test_snowflake_login_refused`) but netget failing to reach a
model at all. Those two must not be the same thing, and the dangerous direction is
one-way — a login endpoint that fell open on an outage would issue a session to anyone
who asked while the backend was down. It asserts `success:false` with `data:null`, and
that the `message` on the wire carries none of the backend URL, model name or retry
wording; a Snowflake driver prints that string to a human.

## What each asserts

- `test_snowflake_login_and_query`: `success:true`, `data.token` matches the
  minted token, `masterToken`/`sessionId` present; then a query with that token
  returns `rowset == [["1"]]`, `returned == 1`, `queryResultFormat == "json"`.
- `test_snowflake_login_refused`: **fail-closed shape** — `success:false`, error
  `code == "390100"`, and `data` is null (no token leaked on a refusal).

Localhost only (`127.0.0.1`), plaintext HTTP (the server does not do TLS).

## The `decision=` tag, and why it is asserted in two files

Every Snowflake reply is HTTP `200` with a JSON `success` flag, so the status line carries no
information and a `success:false` envelope looks the same whether the model refused or netget
could not reach a model at all. The `decision=` token in `netget.log` and on the status stream
is the only place those separate, and it is asserted from both sides deliberately:

- `e2e_test.rs::test_snowflake_login_refused` — the model answers `snowflake_error`. Asserts a
  line containing `Snowflake login` and `decision=model_reject`, and that **no** line contains
  `decision=fail_closed_`.
- `llm_failure_test.rs::test_snowflake_refuses_login_when_llm_fails` — no rule matches, the
  mock 500s, `call_llm` returns `Err`. Asserts `Snowflake login` with `decision=fail_closed_`,
  and that **no** line says `decision=model_reject`.

Either assertion alone would pass against a server that tagged both outcomes identically. The
pair is the actual contract.

Not covered: `decision=default_logout_ack`, the one arm that answers `success:true` when the
model said nothing — see `src/server/snowflake/AGENTS.md` for why it is tagged that way rather
than as a fail-closed, and why it is (currently) harmless.
