# Snowflake client tests

The peers are **fakesnow 0.11.22** (Python/Starlette over DuckDB; answers every SELECT as an
Arrow stream) and **nnnkkk7/snowflake-emulator v0.0.9** (Go/chi over DuckDB; answers JSON
rowsets) — two independent re-implementations of Snowflake's connector protocol, neither of
which shares code with NetGet or with each other. **Never NetGet's own Snowflake server**: that
would be the circular case.

`install_peers.sh ROOT` makes a venv with fakesnow and **snowflake-connector-python 4.8.0**
(Snowflake's official driver, used as fakesnow's read-back session and to drive NetGet's
*server* in `tests/server/snowflake/real_client_test.rs`), builds the emulator with
`go install …@v0.0.9` (its module checksum is pinned by the Go checksum database), and prints
`export NETGET_SNOWFLAKE_PEERS=ROOT`. **Nothing skips**: without it every peer test fails and
says how to install them. LocalStack's Snowflake emulator was not used — it needs a paid
LocalStack licence — and no other open server of this protocol was found.

```bash
sh tests/client/snowflake/install_peers.sh /tmp/sf && export NETGET_SNOWFLAKE_PEERS=/tmp/sf
./cargo-isolated.sh test --no-default-features --features tcp,snowflake --test client -- snowflake:: --test-threads=4
```

| file | what | LLM calls |
|---|---|---|
| `decode_test.rs` | `result::decode` alone, over responses **captured** from both peers (`fixtures/`, by `capture_fixtures.py`): fakesnow's Arrow rows of ten types plus a NULL row, VARIANT/TIMESTAMP_TZ/BINARY/negative decimal/pre-epoch date/duplicate names, a DML row count; the emulator's JSON rows and its mis-encodings reported rather than guessed; a hand-written rowset in Snowflake's documented JSON encodings; truncation, chunks, every bound; every truncation and single-byte corruption of a real Arrow stream (none may panic); the mandatory target | 0 |
| `session_test.rs` | `Session` against a scripted HTTP server: the login and query request shapes, renewal of an expired session with the master token (once, and a refused renewal not retried), polling a `333334` at its result URL, a result URL on another origin refused, an oversized and a non-JSON response, a refused login | 0 |
| `real_server_test.rs` | the whole client with the model mocked, against both peers: see below | 7 + 7 + 8 + 2 + 1 |

`real_server_test.rs`:

- **fakesnow** — the model creates a ten-column table (INT, NUMBER(9,2), VARCHAR, BOOLEAN,
  DATE, TIME, TIMESTAMP_NTZ, FLOAT, VARIANT, NUMBER(38,0)), inserts two rows (one all-NULL),
  reads them back (Arrow), inserts a row whose text it built from the decoded values
  (`summarise`), reads a server error (`002043`, an unknown column) and logs out. Snowflake's
  own Python driver must then read back exactly rows 1–3, row 3 as
  `the model saw: hello from the model|123.45|true|2026-10-14|12:34:56.000000000|2026-10-14T12:34:56.123456000|1.5|{"k":[1,2]}|3000000000|nulls 9`
  — so a BIGINT as a string, a lost scale, a timestamp off by a zone or a NULL miscounted
  changes what the driver reads. fakesnow's access log must show `POST /session?delete=true`.
- **snowflake-emulator** — the same chain over the types it supports, with JSON results; the
  read-back is a REST session by hand (`readback.py rest`), because the official driver gzips
  its bodies and the emulator cannot read them. Row 3 reads `…|nulls 0`: the emulator sends
  NULL as `""`, and the client hands those cells on flagged rather than guessing NULL.
- **Follow-up bound** — a model that answers every result with another INSERT: the mock is
  asked exactly 7 times about results, `decision=followup_depth` is logged, and the driver
  counts exactly 7 rows in fakesnow.
- **LLM failure** — no rule answers `snowflake_connected`: `decision=fail_closed_llm_error`,
  and fakesnow's log shows the login and **no** query-request.
- **Refused login** — the emulator refuses an empty password: `decision=fail_closed_login`,
  and the model is never asked about a session.

Every rule is matched on the event's own content, most specific first.

## Mutation checks (each applied, run, reverted; the named tests failed)

| mutation | caught by |
|---|---|
| `resolve_endpoint` falls back to `http://<account>.snowflakecomputing.com` when no target is given | `decode_test::the_target_is_mandatory_and_never_derived` |
| an Arrow Decimal delivered as a float instead of an exact decimal string | `decode_test::fakesnow_arrow_rows_decode_to_typed_values` and `…_variants_zones_binary_and_duplicate_names` (the fakesnow chain does **not** catch it: `123.45` as a float prints the same) |
| a DATE decoded one day late | the same two `decode_test`s, `decode_test::snowflake_json_encodings_decode`, and the fakesnow chain (the driver reads `2026-10-15` in row 3) |
| the response body bound lifted (both the read bound and the length check) | `session_test::an_oversized_or_unreadable_response_is_an_error_not_a_result` |
| `MAX_FOLLOWUP_DEPTH` check disabled | `real_server_test::followup_chain_stops_at_the_bound` |
| LLM failure answered with a fallback statement | `real_server_test::llm_failure_sends_nothing` (fakesnow's log) |
| the model's actions dropped in the turns task | both `real_server_test` chains |

The server fixes in `tests/server/snowflake/real_client_test.rs` were checked the same way:
reverting gzip inflation, the `/session?delete=true` route or the error `data` object each fails
that test.

## What only CI shows

The `snowflake` job in `.github/workflows/protocol-pairs.yml` (dispatched by hand, or by
`release.yml`) installs the peers on Ubuntu with `install_peers.sh` (Python 3.12, Go 1.24 — the
emulator's DuckDB binding is cgo and links DuckDB's Linux static library) and runs
`client/snowflake::` and the server's `snowflake::real_client_test`, plus the shared
declaration ratchets. Everything above was run on macOS only.
