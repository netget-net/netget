# IBM Db2 (DRDA) Protocol Implementation

Db2 speaks **DRDA** (Distributed Relational Database Architecture), a binary wire
protocol framing messages in DSS envelopes carrying DDM objects. There is no
maintained Rust crate for the server side of DRDA, so the codec is **hand-rolled**
against the public DRDA specification (`src/server/db2/drda.rs`) — the same code
points Apache Derby's `org.apache.derby.impl.drda` and IBM's Db2 docs use.

The LLM plays the database: it decides whether a login is accepted and what SQLCA
a statement produces. **There is no storage** — no catalog, no tables, no rows.

**State**: Experimental. **Port**: 50000 by default (unprivileged → `None`).
**Stack**: `ETH>IP>TCP>DRDA>Db2`.

> **Byte-literal evidence only — NOT real-client validated.** A real Db2 driver is
> very unlikely to be available on macOS, so the handshake and reply bytes are
> asserted against **spec-derived literals** (see `tests/server/db2/drda_test.rs`),
> not interoperability with a genuine driver on a live connection. Treat this as
> unverified against a real peer.

## DRDA wire format (see `drda.rs` for the full comment)

- **DSS** (6-byte header): `length(u16) | 0xD0 | format | correlator(u16)`.
  `format` low nibble = DSS type (1 RQSDSS request, 2 RPYDSS reply, 3 OBJDSS
  object); high nibble = chaining flags.
- **DDM object** (4-byte header): `length(u16) | codepoint(u16) | data`. The data
  region may hold nested code-pointed parameters.
- Character fields (user id, RDB name, SQL text) are **IBM037 EBCDIC**; `drda.rs`
  has a range-based CP037 codec both ways.

## What is implemented

**The connection handshake**, none of which needs the LLM except SECCHK:

| Client command | Server reply | LLM? |
|---|---|---|
| `EXCSAT` (exchange server attributes) | `EXCSATRD` | no |
| `ACCSEC` (access security) | `ACCSECRD` (echoes SECMEC) | no |
| `SECCHK` (security check, carries USRID/PASSWORD/RDBNAM) | `SECCHKRM` | **yes** → `db2_connect` |
| `ACCRDB` (access RDB) | `ACCRDBRM` (INFO if authenticated, else ERROR) | no |

**The basic-query path**: `EXCSQLIMM` (execute immediate) with the SQL delivered
as a `SQLSTT` object → `db2_query` event → the server replies with an `SQLCARD`
carrying the model's SQLCA.

### Events and actions

Every event `.with_actions(...)`; both events are emitted.

- `db2_connect` (after SECCHK): data `user_id`, `rdb_name`, `has_password`.
  Actions: `db2_accept_connection` (SECCHKRM severity INFO, code SUCCESS) /
  `db2_reject_connection` (SECCHKRM severity ERROR; `sec_check_code` selects
  `password_invalid`/`userid_unknown`/`userid_missing`).
- `db2_query` (on EXCSQLIMM): data `sql_text`, `statement_type`. Actions:
  `db2_query_ok` (`sqlcode` default 0 → null SQLCA = success; positive → warning
  SQLCA; negative → error) / `db2_query_error` (`sqlcode`, `sqlstate`, `message`).

All action params are structured — no raw bytes/base64.

## Fail-closed behaviour

Every outcome carries a stable `decision=` tag in the log, following
`src/server/radius/`. That is not decoration here — it is the **only** place two
of the three refusals can be told apart:

| situation | wire | log tag |
|---|---|---|
| model accepts | `SECCHKRM` INFO / code `0x00` | `decision=model_accept` |
| model denies | `SECCHKRM` ERROR / the model's code | `decision=model_reject` |
| handler ran, produced neither verdict | `SECCHKRM` ERROR / `0x0F` | `decision=fail_closed_no_action` |
| LLM call failed | `SECCHKRM` ERROR / `0x0F` | `decision=fail_closed_llm_error` |

The last two are **byte-identical** on the wire, and differ from a model denial
only by a code the model itself chose. DRDA's `SECCHKRM` has no field that could
carry "netget could not reach a decision", and inventing one would be a worse
answer than the log entry.

The statement path is the same shape, for the same reason — the SQLCA extended
group that would carry message text is sent NULL:

| situation | wire | log tag |
|---|---|---|
| `db2_query_ok` | success or warning SQLCA | `decision=model_answer` |
| `db2_query_error` | error SQLCA with the model's SQLCODE | `decision=model_reject` |
| statement before an accepted SECCHK | SQLCODE `-30082` / SQLSTATE `08001` | `decision=fail_closed_not_authenticated` |
| handler produced no result | SQLCODE `-901` / SQLSTATE `58004` | `decision=fail_closed_no_action` |
| LLM call failed | SQLCODE `-901` / SQLSTATE `58004` | `decision=fail_closed_llm_error` |

An LLM outage is therefore **never** an accept and never a success SQLCA. The
backend error itself reaches the log and the status stream only — truncated with
`truncate_for_log`, and never the wire, which for this protocol is structurally
guaranteed: no reply DRDA builds here has a free-text field.

- **Unknown DRDA command** → `CMDNSPRM` at severity ERROR (a real reply, never a
  hang).

## SQLCARD encoding

- **Success** (`sqlcode 0`): SQLCARD (0x2408) whose SQLCAGRP is the FDOCA NULL
  indicator `0xFF` — the reply a real Db2 sends after a successful non-query
  statement.
- **Error**: SQLCAGRP present, then `SQLCODE(i32 BE) | SQLSTATE(5 EBCDIC) |
  SQLERRPROC(8, "NETGET  ") | 0xFF`. The **extended diagnostic group
  (SQLCAXGRP)** — SQLERRD counters, warning flags, message text — is sent NULL.

## Architecture

- `spawn_with_llm_actions` binds with `?` (bind failure → `ServerStatus::Error`)
  and registers the accept-loop `JoinHandle` via `register_server_task()`.
- One task per connection over `tokio::io::split()` (never clone the stream). The
  write half is an `Arc<Mutex<WriteHalf>>` shared by the reader loop and the peer
  command task; the read loop buffers until a full DSS is present
  (`dss_declared_len`), parses one DSS, dispatches, and writes the reply. No lock
  is held across an `.await`.
- Per-connection `authenticated` flag, set by an accepted SECCHK; ACCRDB and any
  statement require it.

## Dashboard peer injection

Each connection registers a peer handle (`peer_support::register_peer_channel` +
`spawn_peer_command_task`) after it is added to the server, and drops it
(`remove_peer_handle`) on every exit of the read loop. So the dashboard shows
`[ message this peer ]` / `[ disconnect this peer ]` on a live Db2 connection.

- **`[ disconnect this peer ]`** works: it injects `close_connection`, which
  `execute_action` maps to `ActionResult::CloseConnection`. The generic peer task
  half-closes the write side; the reader's `read() == 0` path runs the normal
  teardown and the peer reads EOF.
- **Custom-result gap:** Db2's four wire verbs (`db2_accept_connection`,
  `db2_reject_connection`, `db2_query_ok`, `db2_query_error`) return
  `ActionResult::Custom` because their DRDA replies (SECCHKRM / SQLCARD) are
  **correlator-bound** — the correlator comes from the client's pending request
  DSS, which an out-of-band injection does not have. The generic peer task
  therefore reports an injected wire verb as `Executed` and writes nothing, and no
  bespoke path is provided because encoding a correlator-less reply would be
  incorrect. Wire replies remain driven by the read loop's dispatch, where the
  correlator is known.
- Connection counters (`update_connection_stats`) are updated on every DSS read
  and every reply write, so the rail's `↓/↑` byte and packet counts move.

## NOT implemented (be honest)

- **SELECT result-set retrieval**: `OPNQRY` / `QRYDSC` (FDOCA descriptor) /
  `QRYDTA` (row data) / `CNTQRY` / `CLSQRY`. Only the SQLCA (success/error
  indicator) is returned, so a driver can run INSERT/UPDATE/DELETE/DDL and read
  the SQLCODE, but **tabular rows are not delivered**.
- Prepared statements with parameter markers (`PRPSQLSTT` + parameter marshalling).
- The SQLCA extended diagnostic group (message text etc.).
- TLS, Kerberos/GSSAPI/encrypted SECMEC, connection pooling nuances, DRDA
  chaining beyond per-DSS request/reply.

## Testing

- `tests/server/db2/drda_test.rs` — byte-literal codec tests (DSS/DDM layout,
  IBM037 EBCDIC, SQLCARD success/error) against spec-derived constants.
- `tests/server/db2/e2e_test.rs` — a real TCP connection driving the full
  handshake + an EXCSQLIMM statement against a running server with the LLM mocked,
  asserting reply code points and severities.

```bash
./cargo-isolated.sh test --no-default-features --features db2 \
    --test server -- db2:: --test-threads=100
```

## References

- DRDA specification (The Open Group) — DSS/DDM framing and code points.
- Apache Derby `org.apache.derby.impl.drda` — a readable reference server.

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/db2/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_REQUEST_READ_TIMEOUT` | 30s | DRDA is client-speaks-first with no server greeting: a real driver sends EXCSAT the moment the socket is up. A peer that has connected and sent nothing has made no request at all. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 300s | Applies only once the security check has been accepted. An authenticated Db2 session legitimately idles — JDBC, pureQuery and `ibm_db` all pool connections and hold them open between statements, with idle-reap defaults in minutes. An unauthenticated peer never reaches this bound, which is the half that matters against an attacker. |
| `MAX_CONNECTIONS` | 256 | Refusal: **a plain close.** Every DDM reply is a DSS carrying the *request's* correlation identifier, and a refused peer has sent no request — so no well-formed refusal exists. Invented bytes would be reported as a protocol violation, which tells an operator less than the WARN line tagged `decision=fail_closed_connection_cap`. |

**NetGet's own Db2 client (`src/client/db2/`) speaks inside `connect()`**: EXCSAT, ACCSEC,
SECCHK and ACCRDB all go out before it returns, so the first-request bound cannot strand it.
Once authenticated it may sit idle while a human answers a parked turn; the 300s idle bound
equals the manual-intercept default, so that wait is covered.

**The deadline covers the read and nothing else.** The deadline wraps the `read()` call in this protocol's own loop, and everything that can legitimately take minutes happens after it returns. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.
