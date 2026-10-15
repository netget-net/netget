# Db2 (DRDA) client

NetGet as a DRDA application requester: it logs in to IBM Db2 or Apache Derby, and the model
decides what SQL to run, reads decoded results and commits or rolls back. Feature `db2`
(shared with the server, `src/server/db2/`). **Experimental** — see Maturity below.

Rust owns everything below the SQL; the model never sees a byte of DRDA.

| file | what |
|---|---|
| `wire.rs` | the requester codec: request builders, DSS/object reading, SQLCA, SQLDA, QRYDSC, QRYDTA rows; every bound |
| `mod.rs` | `Conn` (one connection: handshake, `exchange`, the operations), the session and turns tasks |
| `actions.rs` | events, actions, startup parameters, metadata |

## The conversation

`connect()` runs the whole handshake before it returns, so a refused login fails client
creation and the model is never asked anything (`decision=fail_closed_handshake`):

| request | reply read | refused when |
|---|---|---|
| `EXCSAT` (AGENT, SQLAM, RDB, SECMGR at 7) | `EXCSATRD` | the server's SQLAM is below 7 — every FD:OCA layout here is SQLAM 7's |
| `ACCSEC` (SECMEC 3 with a password, 4 without) | `ACCSECRD` | the mechanism is not among those the server lists |
| `SECCHK` (USRID, PASSWORD) | `SECCHKRM` | SECCHKCD ≠ 0 or SVRCOD ≥ 8; the error names the code (`password invalid`, ...) |
| `ACCRDB` (PRDID, `QTDSQLASC`, TYPDEFOVR UTF-8, CRRTKN) | `ACCRDBRM` | no ACCRDBRM (RDBNFNRM, RDBATHRM, ...), SVRCOD ≥ 8, or a negative SQLCA |

Then one action at a time, each a request and its whole reply chain:

| action | DRDA | event |
|---|---|---|
| `execute_statement` | `EXCSQLIMM` + `SQLSTT` | `db2_statement_result` (SQLCODE, SQLSTATE, `row_count` = SQLERRD3) |
| `execute_query` | `PRPSQLSTT` (+`SQLSTT`, extended SQLDA) → `SQLDARD`; `OPNQRY` → `OPNQRYRM` + `QRYDSC` + `QRYDTA`; `CNTQRY` until end of data; `CLSQRY` if stopped early | `db2_query_result` (columns, rows keyed by name, `truncated`) |
| `commit` / `rollback` | `RDBCMM` / `RDBRLLBCK` | `db2_transaction_result` (outcome from UOWDSP, the statements of that unit of work) |
| any of them refused | — | `db2_error` (SQLCODE/SQLSTATE/tokens, or the DRDA reply message) |

`autocommit` (startup parameter, off by default) commits after every successful statement and
query.

Wire details that are not obvious, each learnt from Derby:

- **Every request chain starts at correlator 1.** Each chain here is one command, and Derby
  answers a chain starting elsewhere with correlator 1 anyway; a reply carrying a correlator
  other than the request's is a protocol error.
- **The product id must contain `DNC` for Derby.** Its server refuses any other client
  (`invalidClient` → PRCCNVRM). `product_id` defaults to `DNC10170`; Db2 accepts any. Claiming
  10.17 means Derby uses its newer encodings: 29-character timestamps, BOOLEAN, PBSD (`0xC000`)
  objects (ignored), and a SQLUDTGRP **without a null indicator** for Java UDT columns
  (SQLTYPE 2000/2001), which `parse_sqldard` reads.
- **PKGNAMCSN** names `NULLID.SYSLH200` (large, with hold, cursor stability), token `SYSLVL01`,
  section 1. Derby reads isolation and holdability from the name. A database name over 18
  bytes switches to the extended form (each name length-prefixed); Derby checks it against
  the name ACCRDB opened.
- **DDM strings are CCSID 37** (UNICODEMGR is not negotiated). A user id or password holding
  anything but printable ASCII is refused rather than substituted.
- **SQL text is UTF-8** (TYPDEFOVR CCSIDMBC 1208); answer data is decoded in the CCSIDs the
  server declared in ACCRDBRM (1208, 1200, 37/500/1047, Latin-1 family), and in the byte order
  its TYPDEFNAM implies (`QTDSQLX86`/`QTDSQLVAX` little-endian). SQLCCSID in the SQLDA is
  always big-endian. `QTDSQL370` floats (hexadecimal) are refused.
- **SQLERRMC** tokens are split on 0x14 (Derby, which appends the SQLSTATE) and 0xFF (Db2)
  before decoding. Db2 sends tokens, never message text.
- A DSS may hold several objects (Derby's OPNQFLRM DSS carries its SQLCARD), may continue in
  2-byte-headed segments, and an object may have an extended length; all three are read.
- A row can be split across query blocks: `decode_row` returns `None` and the row is finished
  from the next CNTQRY's QRYDTA.

Row values: integers and floats are JSON numbers, DECIMAL an exact string (`"-0.500"`),
DATE/TIME/TIMESTAMP the server's strings (`2026-10-14-12.34.56.123456000`), CHAR keeps its
padding, NULL is `null`, binary columns are `{"binary_length": n}` (never bytes). LOBs,
locators, XML, DECFLOAT, zoned decimal and UDT values are refused with the column named.

## Bounds

| bound | value | where |
|---|---|---|
| one DSS with its continuations | 8 MiB | `wire::MAX_DSS_BYTES`, checked while walking segment headers |
| read buffer | 8 MiB + 64 KiB | `MAX_READ_BUFFER` |
| one reply chain | 16 MiB, 4096 DSSes | `MAX_REPLY_BYTES`, `MAX_REPLY_DSS` |
| objects or parameters in one DSS/object | 256 | `MAX_OBJECTS_PER_DSS` |
| columns | 1024 | `MAX_COLUMNS` (QRYDSC and SQLDA) |
| rows per query | `max_rows` (default 100, at most 1000) | `MAX_ROWS_LIMIT`; more → `truncated`, CLSQRY |
| answer-set bytes per query | 8 MiB | `MAX_RESULT_BYTES` |
| CNTQRY round trips per query | 512 | `MAX_CONTINUES` |
| a varying value | the length the QRYDSC declared | `text_var` |
| packed decimal | precision 1..=31, scale ≤ precision, digits 0–9, sign A–F | `decimal` |
| statement | 2 MiB | `MAX_SQL_BYTES` |
| credentials, RDB name | 255 bytes | `MAX_CREDENTIAL_BYTES`, `MAX_RDBNAM_BYTES` |
| a whole reply | `reply_timeout_secs`, default 120 s | `REPLY_TIMEOUT`; past it the connection is given up |
| TCP connect | 30 s | `CONNECT_TIMEOUT` |
| model turns from one another | 8 | `MAX_FOLLOWUP_DEPTH`, `decision=followup_depth` |
| events waiting for the model | 64 | `TURNS`, `decision=turn_queue_full` |
| statements remembered per unit of work | 16, 200 bytes each | `MAX_UOW_STATEMENTS` |

No decoder recurses.

## Fail closed

- A refused or failed handshake fails `connect()`; the client never reads as connected.
- An LLM failure sends nothing: `decision=fail_closed_llm_error`, and the session waits.
- A reply that cannot be read, a timeout, a fatal reply message (SYNTAXRM, PRCCNVRM, AGNPRMRM,
  MGRLVLRM), a server that hangs up or sends bytes with no request outstanding ends the
  connection with `ClientStatus::Error` (`decision=connection_failed`); no result is invented.
- An SQL error or a non-fatal reply message is reported to the model as `db2_error` and the
  session goes on.

## Evidence and maturity

`tests/client/db2/` (see its `AGENTS.md`): Apache Derby 10.17.1.0's network server, a Java
DRDA implementation sharing no code with NetGet, with Derby's own `ij` client reading back what
the model did, Derby's statement log, and tshark's DRDA dissector over a recording proxy.

**Experimental**: the client Beta bar's conditions 2–4 hold for Derby (the tests fail without
it, run a real session, and assert the model's actions from Derby's side), but condition 1
asks for a real third-party server and this has **one**. IBM Db2 Community Edition was not
used: its image is linux/amd64 only (emulated on this Mac), needs a privileged container and a
multi-minute first start, and this machine's Docker is unreliable and nearly out of disk.

## Not implemented

Parameter markers (`EXCSQLSTT` with `SQLDTA`), LOBs (`EXTDTA`), scrollable cursors, stored
procedures and their result sets, XA, encrypted security mechanisms (SECMEC 7/9) and Kerberos,
TLS, UNICODEMGR, multi-row fetch (`QRYROWSET`), more than one open cursor.
