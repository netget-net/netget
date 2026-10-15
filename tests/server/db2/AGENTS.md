# Db2 (DRDA) Server E2E Tests

`drda_test.rs`, `e2e_test.rs`, `peer_inject_test.rs`, `real_client_test.rs`, declared in
`tests/server/db2/mod.rs` (`pub mod db2;` in `tests/server/mod.rs`).

## Strategy

The independent evidence is `real_client_test.rs`: **Apache Derby 10.17.1.0's JDBC client
driver** (`derbyclient.jar`, driven through Derby's `ij`) and **IBM's CLI driver** (`ibm_db`
3.3.0), against NetGet's server. Neither shares code with NetGet or with each other. The rest
is byte-literal: the codec against spec-derived bytes, and the server driven with bytes from
that codec.

`real_client_test.rs` needs Java 21+ and the Derby jars (`NETGET_DERBY_LIB`, printed by
`python3 tests/client/db2/install_derby.py <dir>`), a Python with `ibm_db`
(`NETGET_IBM_DB_PYTHON`) and tshark; it **fails** rather than skips without them.

## `real_client_test.rs` — two independent drivers

### Derby's JDBC driver (LLM mocked, 6 calls)

`ij` connects as `app` (the model accepts), creates a table, inserts a row, drops a missing
table, disconnects, and connects as `intruder` (the model refuses). Asserted on what the
driver printed and what the model was shown:

- each `db2_query` rule matches the exact statement text — the SQLSTT decoded from the
  driver's UTF-8 FD:OCA string (it used to arrive as EBCDIC-decoded garbage);
- `0 rows inserted/updated/deleted` for the CREATE, `1 row` for the INSERT — the model's
  `rows_affected` in SQLERRD3;
- `ERROR 42704` — the model's SQLSTATE in a complete SQLAM 7 SQLCA;
- the intruder's connect fails (`ERROR 08004 ... Userid or password invalid`);
- tshark's `drda` dissector reads both directions of the recorded conversation.

The driver also calls `SYSIBM.SQLCAMESSAGE` to fetch message text after the error; that is a
PRPSQLSTT, answered with one CMDNSPRM and never shown to the model. The driver prints the
SQLCODE and SQLSTATE without text.

### IBM's CLI driver, `ibm_db` 3.3.0 (LLM mocked, 5 calls)

`ibm_db_peer.py` (run with the interpreter `NETGET_IBM_DB_PYTHON` names; `pip install
ibm_db==3.3.0` in a venv — it installs on macOS arm64 and Linux x86_64) prints one JSON line
per step:

- its default connection asks for encrypted EUSRIDPWD (9); the server offers `[3, 4]` and
  the driver reports reason 17, UNSUPPORTED FUNCTION;
- with `AUTHENTICATION=SERVER` it logs in as `app` (the model accepts), sets its special
  registers (EXCSQLSET, acknowledged without the model), inserts (`num_rows` 1, the model's
  `rows_affected`) and fails a drop with `SQLSTATE=42704 SQLCODE=-204`;
- `intruder` is refused with reason 24, USERNAME AND/OR PASSWORD INVALID;
- tshark's `drda` dissector reads both directions.

### Mutation checks (each applied, run, reverted)

| mutation | result |
|---|---|
| no reply chaining (`chain_reply` removed) | Derby's driver: `Data Stream Syntax Error ... Reason: 0x11`, nothing reaches the model |
| `rows_affected` not sent | Derby's driver loses `1 row inserted/updated/deleted` |
| ACCSEC echoes any mechanism | IBM's driver logs in with an encrypted token; the model sees an empty user id (reason 24, not 17) |
| a refused SECCHK leaves its reply chained and the chained ACCRDB answered | IBM's driver: SQL30020N data stream syntax error instead of reason 24 |

Not caught: dropping only the discard of the chain's remainder (keeping the refusal
unchained) — IBM's driver stops reading at the unchained SECCHKRM either way.

## `drda_test.rs` — pure codec (no server, no LLM)

- DDM object header and DSS envelope layout, including the chaining flags.
- `parse_dss` round-trips a SECCHK carrying an EBCDIC USRID, and reports `Truncated` /
  `BadMagic` on malformed input.
- IBM037 EBCDIC known values and `"SELECT 1"` round-trip.
- `sqlcard_success` = the 5-byte null SQLCA; `sqlcard_error` is a complete SQLAM 7 SQLCA
  (SQLCAXGRP present, SQLDIAGGRP null indicator last, character fields in UTF-8) — the
  layout Derby's own server sends.
- `chain_reply` sets "chained" / "same correlator" on a reply to a chained request.
- `decode_sqlstt` reads the FD:OCA UTF-8 form and still reads bare EBCDIC.

## `e2e_test.rs` — handshake over real TCP (LLM mocked, 3 calls)

`EXCSAT→EXCSATRD`, `ACCSEC→ACCSECRD`, `SECCHK→SECCHKRM` (INFO/SUCCESS), `ACCRDB→ACCRDBRM`,
then `EXCSQLIMM` with an embedded SQLSTT → `SQLCARD` carrying SQLCODE 0 and the mock's
`rows_affected` 1 in SQLERRD3.

## `peer_inject_test.rs` — dashboard peer injection (zero LLM calls)

`injected_close_connection_sends_eof_and_counters_move`: `EXCSAT→EXCSATRD`, counters move,
`send_to_peer` of a wire verb is `Executed` with nothing written (correlator-bound),
`close_connection` → `Disconnected` and EOF.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features tcp,db2 \
    --test server -- db2:: --test-threads=4
```

The `db2` job in `.github/workflows/protocol-pairs.yml` runs `db2::real_client_test` with
Derby, `ibm_db` and tshark installed.

## Not covered

SELECT result sets (not implemented), prepared statements, IBM's JDBC driver (JCC), TLS.
See `src/server/db2/AGENTS.md`.
