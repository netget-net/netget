# Db2 client tests

The peer is **Apache Derby 10.17.1.0's network server** (`org.apache.derby.drda`), a Java DRDA
server that shares no code with NetGet. `install_derby.py` fetches Derby's jars from Maven
Central, checks each against a pinned SHA-256 and prints `export NETGET_DERBY_LIB=...`; the
tests need that and Java 21+ (Derby 10.17's minimum). **Nothing skips**: without java, the
jars or tshark the tests fail and say how to install them.

```bash
python3 tests/client/db2/install_derby.py /tmp/derby && export NETGET_DERBY_LIB=/tmp/derby
./cargo-isolated.sh test --no-default-features --features tcp,db2 --test client -- db2:: --test-threads=4
```

`derby.rs` starts a server per test (`RealServer`: probed loopback port, `derby.system.home`
in the guard's temp dir, `derby.language.logStatementText=true` so `derby.log` lists every
statement executed), runs Derby's `ij` over **Derby's own DRDA client driver** to read the
results back, and provides a recording TCP proxy for the pcap oracle.

| file | what | LLM calls |
|---|---|---|
| `wire_test.rs` | the codec alone: Derby's **captured** QRYDSC/QRYDTA/SQLCARD bytes (from Derby talking to its own `ij`) decoded to typed rows; rows cut by a block boundary; little-endian servers; packed decimals; every decode bound; DSS continuation and its bound; request framing | 0 |
| `derby_session_test.rs` | `Conn` (the object the client runs the model's actions through) against Derby: 13 columns of 12 types decoded to exact values including NULL, extended PKGNAMCSN (35-byte database name), row counts, commit/rollback, two error SQLCAs, 600 rows across query blocks via CNTQRY, `max_rows` truncation then another query on the same connection, `ij` read-back; and a refused login against Derby with BUILTIN authentication | 0 |
| `real_server_test.rs` | the whole client with the model mocked: see below | 11 + 8 + 2 |

`real_server_test.rs`:

- **The model's SQL** — create a ten-type table and insert two rows (one all-NULL), commit,
  select them, insert a row whose text the model built from the decoded values
  (`summarise`), commit, insert and roll back, then a bad query whose `db2_error`
  (SQLSTATE 42X04, token `NOSUCH`) the model reads. `ij` must read back exactly rows 1–3 —
  row 3 as `...|7|3000000000|ab  |123.45|2026-10-14|12:34:56|2026-10-14-12.34.56.123456000|1.5|nulls 9`,
  so a BIGINT delivered as a string, a lost scale or a miscounted NULL changes what Derby
  holds — and not the rolled-back row. Derby's statement log must show the statements, and
  tshark's `drda` dissector must read both directions of the recorded conversation with no
  expert info at Warn. Every rule is matched on the event's own content, most specific first.
- **Follow-up bound** — a model that answers every result with another INSERT (autocommit on):
  `decision=followup_depth` is logged, the mock is asked exactly 7 times about results, and
  `ij` counts exactly 7 rows.
- **LLM failure** — no rule answers `db2_connected`: `decision=fail_closed_llm_error`, and
  Derby's statement log shows nothing compiled or executed for NetGet's connection.

## Mutation checks (each applied, run, reverted; the named tests failed)

| mutation | caught by |
|---|---|
| VARCHAR value longer than its declared length accepted | `wire_test::a_value_longer_than_its_column_is_refused` |
| SMALLINT read unsigned | `derby_session_test` (−7 read back as 65529) |
| BIGINT delivered as a string | `wire_test` captured rows, `derby_session_test`, `real_server_test` (`ij` reads `"3000000000"`) |
| DECIMAL scale dropped | `wire_test` (2 tests), `derby_session_test`, `real_server_test` |
| `MAX_FOLLOWUP_DEPTH` check disabled | `real_server_test::followup_chain_stops_at_the_bound` |
| LLM failure answered with a fallback statement | `real_server_test::llm_failure_sends_nothing` (Derby's log) |
| the model's actions dropped in the turns task | `real_server_test::db2_client_runs_the_models_sql_against_derby` |
| SECCHKCD ignored | `derby_session_test::refused_login_fails_the_handshake` — Derby then refuses ACCRDB (PRCCNVRM), so the test asserts the refusal is SECCHK's own (`login refused: SECCHKCD 0x..`) |

## What only CI shows

The `db2` job in `.github/workflows/protocol-pairs.yml` (dispatched by hand) installs Temurin
21, the pinned Derby jars and tshark on Ubuntu and runs `client/db2::` plus the shared
declaration ratchets.
