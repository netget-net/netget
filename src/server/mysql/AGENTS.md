# MySQL Protocol Implementation

MySQL wire protocol server built on `opensrv-mysql` v0.7. The library owns the
handshake, packet framing and command parsing (`AsyncMysqlShim`); the LLM owns
the answer to every query. **There is no database** — no tables, no rows, no
storage of any kind in Rust. The only per-connection state is the prepared
statement text map the wire protocol requires.

**State**: Beta — two independent clients complete a session: `mysql_async`, and the
real `mysql` CLI 9.3.0 (`tests/server/mysql/real_client_test.rs`, which hard-fails
rather than skips when the binary is absent).
**Port**: 3306 by default. **Privilege**: `None` (3306 > 1024).
**Stack**: `ETH>IP>TCP>MySQL`.

## Authentication: there is none, and that is what the handshake says

**Nothing here verifies anything.** No password is stored or compared, the model is
never asked, and every connection is admitted whatever it sends. The server offers
`caching_sha2_password` (`src/server/mysql/caching_sha2.rs`) so that a *current*
client can get past its own plugin loader — that is a statement about which packets
go on the wire, not about security, and it must not be written down as though it
were about security.

Until September 2026 the greeting named `mysql_native_password`, whose client plugin
MySQL 9.0 deleted, so the shipping CLI could not connect:

```text
ERROR 2059 (HY000): Authentication plugin 'mysql_native_password' cannot be loaded: dlopen(…)
```

**The greeting alone was not what broke it**, and the distinction decides where the
fix goes. Captured from the wire: the 9.3 client answers a greeting it cannot honour
by naming `caching_sha2_password` itself, and dies on the **AuthSwitchRequest** that
`opensrv-mysql` sends whenever `auth_plugin_for_username` disagrees with the client's
choice. So this shim returns `""` there — no switch, ever — which is also what keeps
an older `mysql_native_password` client working.

The end of the connection phase has two shapes and the choice is made from the length
of the client's auth response, not from the plugin name it claimed:

| client sent | server answers |
|---|---|
| 0 bytes (no password) | the OK packet alone — an `AuthMoreData` here is read as a failure |
| 32 bytes (caching_sha2 SHA-256 scramble) | `AuthMoreData` `0x01 0x03` (*fast auth success*), **then** the OK packet |
| 20 bytes (`mysql_native_password` SHA-1) | the OK packet alone, exactly as before |

Both shapes were checked against a throwaway real `mysqld` 9.3.0 for comparison, and
`mysql_async`'s own client code states the same two cases.

`opensrv-mysql` writes that OK packet itself and its `authenticate` hook cannot write,
so the `0x01 0x03` packet is injected *beneath* the crate by `FastAuthWriter`, using the
same generic-writer seam the packet bound uses on the reader. It takes the OK packet's
sequence id and renumbers the OK to the next one; MySQL numbers packets within a phase
and a conforming client discards a reply out of order.

Two traps that writer produced, both worth keeping:

- **It must implement `poll_write_vectored`.** `PacketWriter::end_packet` writes header
  and payload in one `write_vectored`, and tokio's default implementation of that method
  forwards only the first slice — so without it every packet became two writes and the
  greeting arrived as a 4-byte read followed by the rest.
  `packet_limit_test.rs` reads the greeting from a raw socket and is what caught it.
- **The nonce is a fixed string** (`opensrv-mysql`'s `salt()` default). Harmless only
  because nothing is verified against it; it would be a real defect the moment anything
  were.

## What the model sees and controls

**Event**: `mysql_query`, fired for `COM_QUERY` and for `COM_STMT_EXECUTE`
(the prepared statement's text, with the values the execute bound beside it).

| Field | Notes |
|---|---|
| `query` | the SQL text; for a prepared statement exactly as prepared, `?` placeholders and all |
| `answer_with` | which response shape the statement needs — `mysql_query_response` for a statement that returns rows, `mysql_ok_response` for one that does not — from its first keyword (`crate::utils::sql`); absent when the keyword does not say |
| `params` | prepared statements only: one object per `?`, in order — `{"index": 1, "type": "LONGLONG", "value": 42}`. See "Prepared-statement parameters" below |
| `query_rendered` | prepared statements only, **for reading**: `query` with each `?` replaced by `⟨value⟩`. Not SQL; `params` is authoritative |

`client_ip`, `client_port`, `connection_id` and `server_id` are added by the
event logger, so log templates may reference them.

**Actions** (all sync; there are no async actions):

| Action | Parameters | Wire form |
|---|---|---|
| `mysql_query_response` | `columns` (required), `rows` (required) | result set |
| `mysql_ok_response` | `affected_rows`, `last_insert_id` (both optional) | OK packet |
| `mysql_error_response` | `error_code` (required), `message` (required) | ERR packet |
| `close_this_connection` | — | answers the current query, then drops the connection |

`columns` is an array of `{"name": …, "type": …}`. Recognised type names —
`INT`/`INTEGER`, `BIGINT`, `SMALLINT`, `TINYINT`, `FLOAT`, `DOUBLE`, `DECIMAL`,
`DATE`, `TIME`, `DATETIME`/`TIMESTAMP`, `BLOB`/`BINARY`, `TEXT`, `VARCHAR` —
set the column metadata *and* the encoding.

**The declared type is not cosmetic, and believing it was cost the binary
protocol entirely.** `COM_QUERY` uses MySQL's text protocol, where opensrv-mysql
writes every cell as a length-encoded string whatever the column says — so
handing it a `String` worked. `COM_STMT_EXECUTE` (every prepared statement) uses
the **binary** protocol, where opensrv encodes according to `Column::coltype` and
returns `io::Error` for a Rust type it cannot write as that type. `String` is
rejected by every numeric and every temporal column, and that error ends the
*session*. The protocol's own advertised example,
`{"name": "id", "type": "INT"}`, therefore killed the connection on
`conn.exec(...)` while working perfectly on `conn.query(...)`.

`write_cell` now encodes each value as its column demands: integer columns take
an integer, `FLOAT`/`DOUBLE` a float, `DATE`/`TIME`/`DATETIME`/`TIMESTAMP` a
parsed `YYYY-MM-DD` / `HH:MM:SS` / `YYYY-MM-DD HH:MM:SS` string, everything else
a string. A value that cannot be represented as its column's type is sent as
**SQL NULL with a WARN** — one odd cell must not cost the connection, and a
silently coerced wrong number would be worse than an explicit absence. (`TIME`
is additionally bounded at 34 days, because opensrv's `Duration` encoder holds
`assert!(d <= 34)` and the value comes from model output.)

JSON `null` is a real SQL NULL (the NULL bitmap in binary, `0xFB` in text). It
used to be written as the four-character string `"NULL"`, which every client read
as data.

**Rows are padded and truncated to the column count.** opensrv returns
`InvalidData` from `end_row()` for a short row and that error ends the session,
so a model that miscounted one row used to kill the connection instead of
producing one odd row. PostgreSQL's handler has always padded; MySQL now matches
it, with a WARN naming the mismatch.

### Error codes

`opensrv_mysql::ErrorKind::from(u16)` **panics** on any code outside its table
(`opensrv-mysql-0.7.0/src/errorcodes.rs:2807`). Because the code comes from model
output, `mysql_error_kind()` accepts a fixed list and falls back to 1105
(`ER_UNKNOWN_ERROR`) with a WARN rather than calling `From` directly:

> 1044, 1045, 1046, 1049, 1050, 1051, 1052, 1054, 1062, 1064, 1065, 1136, 1146,
> 1149, 1216, 1217, 1364, 1451, 1452, 1690

The message is always sent verbatim; only the numeric code and SQLSTATE fall
back. Verified: `mysql_error_response` with 1146 arrives as
`ERROR 1146 (42S02) … Table 'd.users' does not exist`; with 987654 it arrives as
`ERROR 1105 (HY000)` and the server stays up.

### Failure behavior

- **No response action** → ERR packet `1105` / `HY000` carrying the `WireFailure` category,
  logged at WARN with `decision=fail_closed_no_action`. It used to be an empty OK packet, which
  a driver reads as a statement that ran and affected zero rows — so an INSERT/UPDATE/DELETE the
  model declined was reported as completed. 1105 and not 1205, because nothing timed out here
  and a retryable code would invite the client to try again.
- **EXECUTE against an unknown or already-closed statement id** →
  `ER_UNKNOWN_STMT_HANDLER` (1243). It used to be an OK packet, so a client reusing a stale
  handle after a reconnect saw a successful write that never ran.
- **LLM call fails** → ERR packet `1105` / SQLSTATE `HY000`, message
  `netget: <error>`. (It used to send an empty OK, which the client could not
  distinguish from success.) When `crate::llm::is_overload_error` says the
  failure was capacity exhaustion the code is `1205`
  (`ER_LOCK_WAIT_TIMEOUT`, also `HY000`) instead — the code drivers already
  treat as transient and safe to retry, rather than 1105's permanent server
  fault. Covered by `tests/server/mysql/llm_failure_test.rs`.
- **More than 4096 live prepared statements on one connection** →
  `ER_MAX_PREPARED_STMT_COUNT_REACHED`. The map is only pruned by
  `COM_STMT_CLOSE`, so without the cap a PREPARE loop would grow it unbounded.
- **A malformed `COM_STMT_EXECUTE` parameter block** → ERR `1835`
  `ER_MALFORMED_PACKET` / `HY000`, `Malformed communication packet.` (mysqld's own
  text), logged at WARN as `decision=fail_closed_malformed_execute` with what was wrong.
  The model is not called and the session continues.
- **`COM_STMT_SEND_LONG_DATA` naming a parameter the statement does not have** → ERR
  `1210` `ER_WRONG_ARGUMENTS` at the next execute, as mysqld does (long data has no
  reply of its own); `decision=fail_closed_long_data_index`.
- **Long data past its bounds** — more than 64 MiB (`max_allowed_packet`) pending for one
  statement, or 128 MiB across a connection's statements → ERR `1105` / `HY000` at that
  statement's next execute, with mysqld's own text (`Parameter of prepared statement which
  is set through mysql_send_long_data() is longer than 'max_allowed_packet' bytes`);
  `decision=fail_closed_long_data_too_large`. See the long-data bound below.
- **An execute the capture beneath the crate did not see** (reachable only by
  overflowing its queue, see below) → ERR `1105` with the `WireFailure` category;
  `decision=fail_closed_no_capture` at ERROR. The statement is never run without its
  values.

## Dashboard injection & connection counters

**No peer handle — the dashboard cannot message or disconnect a MySQL peer.**

A correction to what this section used to say, because the reason matters elsewhere in
this file: `run_on` does **not** have to be given the write half. Its `W` is only
`AsyncWrite + Send + Unpin`, which `&mut WriteHalf<TcpStream>` satisfies, so the write
half can be *lent* for the session and taken back when the crate's loop gives up. That
is exactly what the packet bound below does to answer with an ERR packet. What it does
not do is make a peer handle possible, and the three reasons are unchanged — they are
about writing *during* a session, not after one:

1. opensrv owns the socket and the packet **sequence-id counter** for the whole
   session; an unsolicited packet written from outside would desync it.
2. MySQL is strictly request/response — the server must not emit a packet the
   client did not ask for.
3. All wire verbs (`mysql_query_response`, `mysql_ok_response`,
   `mysql_error_response`) return `ActionResult::Custom` and are encoded by a
   `QueryResultWriter<'a, W>` that only exists *inside* an `on_query`/`on_execute`
   callback. The generic peer task can only execute `Output`/`CloseConnection`,
   so even with a write half it could not encode a MySQL response.

Consequently the dashboard shows the dim "cannot message or disconnect a peer
from here yet" row for MySQL connections, and there is no `close_connection`
arm in `execute_action` (nothing out-of-band can reach it).

**Connection counters are still updated.** opensrv hides the raw byte streams,
but the shim sees the application-visible payload at each command boundary, so
`handle_query`, `on_prepare` and `on_init` call
`AppState::update_connection_stats` with the SQL/DB text received and an estimate
of the response payload produced (see `MysqlHandler::record_stats`). These are
payload-size approximations, **not** exact wire bytes — opensrv adds a 4-byte
packet header and text-protocol framing on top — but they keep the rail's `↓/↑`
counters live and refresh `last_activity`. Proven with zero LLM calls by
`tests/server/mysql/connection_stats_test.rs`.

## Architecture

- `spawn_with_llm_actions` binds with `?` (so a bind failure surfaces as
  `ServerStatus::Error`) and registers the accept-loop `JoinHandle` via
  `AppState::register_server_task()` so `stop_server` releases the socket.
- One task per connection running `AsyncMysqlIntermediary::run_on` over a
  `tokio::io::split()` stream. On exit the connection is marked `Closed` in
  `AppState`.
- `close_this_connection` is implemented by writing the current response and then
  returning `io::ErrorKind::ConnectionAborted` from the shim, which is the only
  way to stop the loop opensrv drives.
- The per-connection task is registered with `register_server_task` as well as
  the accept loop. Aborting only the accept loop releases the port but leaves
  every in-flight session running, so `stop_server` did not actually stop the
  server. `register_server_task` prunes finished handles on each call, so the
  vector cannot grow without bound.
- PREPARE stores the SQL text, its placeholder offsets, and (once an execute
  binds them) the parameter types, keyed by an incrementing statement id;
  EXECUTE decodes the bound values and asks the model; CLOSE removes it.
- **PREPARE reports the statement's `?` count** (`count_placeholders`, which
  skips `?` inside string literals, quoted identifiers and comments). The count
  is not cosmetic: the client stores it and uses it to frame COM_STMT_EXECUTE.
  Replying "no parameters" unconditionally — as this did — meant
  `conn.exec("… WHERE id = ?", (42,))` was rejected client-side and never reached
  the wire at all. Statements past `MAX_PLACEHOLDERS` (1024) get
  `ER_PS_MANY_PARAM` rather than a silently wrong count.
- Parameter **values** are decoded by NetGet's own parser, never by
  `ParamParser` — see the next section.

## Prepared-statement parameters

`on_execute` is handed an `opensrv_mysql::ParamParser` and **never iterates it**.
Its iterator, `Params::next` in the published opensrv-mysql 0.7.0 crate's `params.rs`, trusts every
length the peer sent and panics the connection task on five shapes:

| line | panic | the peer sends |
|---|---|---|
| 81 | `split_at(nullmap_len)` | fewer bytes than the NULL bitmap |
| 86 | `rest[1..].split_at(2 * params)` | the new-params-bound flag, then a short type map |
| 90–91 | `panic!("bad column type …")` | one unknown type byte |
| 103 | `bound_types[col]` out of bounds | the flag clear on a statement's first execute |
| 127 | `Value::parse_from(…).unwrap()` | a value shorter than its type, or a length past the packet |

(`ParamParser::new` only stores the bytes, so none of this runs unless a shim
iterates — which is why the values used to be dropped rather than read.)

Two pieces replace it:

- **`command_tap.rs` — getting the bytes.** `ParamParser`'s fields are
  `pub(crate)`, so the packet is copied where the crate cannot hide it: in the
  reader beneath it, the same generic-reader seam `packet_limit` uses.
  `CommandTapReader` frames the stream alongside the crate and queues
  `COM_STMT_EXECUTE` (whole), `COM_STMT_SEND_LONG_DATA` (statement, parameter, a
  prefix of at most 516 bytes and the chunk's length — long data is how a client
  sends a value bigger than a packet, so only what the model is shown is kept) and
  `COM_STMT_RESET` (which opensrv does not parse at all). It captures only
  sequence-0 packets, so no connection-phase packet is ever taken for a command,
  and only packets long enough for opensrv's own parser to accept, so every
  capture has exactly one `on_execute`. `on_execute` pops the queue up to the
  next execute and checks its statement id; a mismatch is discarded and logged,
  never decoded as the wrong statement's values. The queue holds at most 4096
  commands; past that it stops capturing and every later execute is refused
  (1105) rather than risk a wrong pairing. An execute is copied whole, so its size
  is `packet_limit::MAX_PACKET_BYTES` at most — the limiter sits beneath the tap
  and trips first.

  **The tap is also a memory-safety fix, and must stay the reader the crate reads
  from.** It hands `opensrv-mysql` at most the rest of one packet per read.
  The crate's `PacketReader::next_async` (`packet_reader.rs:132-141`) parses from
  a raw-pointer slice of `self.bytes` and, when a read held more than one
  packet, runs `self.bytes = rest.to_vec()` before returning — freeing the
  buffer the returned packet points into. Any two pipelined commands hit it:
  two `COM_STMT_SEND_LONG_DATA` chunks (what `mysql_async` sends), or
  `COM_STMT_CLOSE` and the next command. Measured here as a stray OK packet for
  the first long-data chunk (the freed bytes no longer parsed, and the crate
  answers a parse failure with OK), after which every reply was one behind.
  `stmt_params_test.rs::pipelined_commands_reach_opensrv_one_packet_per_read`
  drives the bare crate through the tap.
- **`LongDataGate` (in `command_tap.rs`, beneath the tap) — the long-data bound.**
  `opensrv-mysql` appends every `COM_STMT_SEND_LONG_DATA` chunk to the
  statement's buffer with no limit (`lib.rs:663-678`) and keeps it until the
  statement is executed or closed, so a peer that sends chunks and never executes
  grows the process as far as it likes, one 64 MiB packet at a time. The gate
  holds back each command's header and first seven payload bytes, and a long-data
  chunk that would take its statement past `LONG_DATA_PER_STATEMENT` (64 MiB,
  the published `max_allowed_packet`; mysqld applies the same number per
  parameter) or the connection past `LONG_DATA_PER_CONNECTION` (128 MiB) is read
  and discarded whole, so the crate never stores it. Long data has no reply, so
  dropping a chunk desynchronises nothing; the refusal is queued and answered
  1105 at the statement's next execute, where mysqld reports it. A statement's
  count is released by its execute or `COM_STMT_CLOSE` (what makes the crate free
  it), not by `COM_STMT_RESET`, which the crate does not parse. A chunk chained
  past 16 MiB is decided on its first fragment, so a bound can be overshot by one
  packet at most, which `packet_limit` bounds.
  `stmt_params_test.rs::long_data_past_its_bounds_never_reaches_the_crate` checks
  both bounds at small sizes, and
  `prepared_params_test.rs::long_data_past_max_allowed_packet_is_refused_at_execute`
  sends 80 MB to reach the real one.
- **`stmt_params.rs` — decoding them.** Every length is compared, as a `u64`,
  with the bytes remaining before it is used, so an 8-byte length-encoded size of
  2⁶⁴−1 is a refusal, not an overflow; values are borrowed from the packet, not
  copied. Supported: the integer types (signed and unsigned), `FLOAT`, `DOUBLE`,
  `NULL`, `DATE`/`DATETIME`/`TIMESTAMP` (lengths 0, 4, 7, 11), `TIME` (0, 8, 12),
  and every length-encoded string type — `VARCHAR`, `VAR_STRING`, `STRING`, the
  `BLOB`s, `DECIMAL`/`NEWDECIMAL` (as their text), `ENUM`, `SET`, `BIT`, `JSON`,
  `GEOMETRY`. It is **stricter than mysqld**, deliberately: an unknown type byte,
  a temporal length the format does not define, or bytes left after the last
  value are refused rather than guessed at, because the model answers as though
  the decoded values were what the client meant. Long data takes the place of a
  parameter's value whatever the NULL bitmap says, as in mysqld, and is cleared
  after every execute. An execute that clears the new-params-bound flag reuses the
  types the last successful execute bound.

What the model sees, for `INSERT INTO t (a, b) VALUES (?, ?)` executed with
`(42, "O'Brien")`:

```json
"query": "INSERT INTO t (a, b) VALUES (?, ?)",
"params": [{"index": 1, "type": "LONGLONG", "value": 42},
           {"index": 2, "type": "VAR_STRING", "value": "O'Brien"}],
"query_rendered": "INSERT INTO t (a, b) VALUES (⟨42⟩, ⟨\"O'Brien\"⟩)"
```

- `value` is a JSON number for integers and floats (a non-finite float is its
  name as a string), `null` for NULL, and a string otherwise — dates as
  `YYYY-MM-DD[ HH:MM:SS[.ffffff]]`, `TIME` as `[-]HH:MM:SS[.ffffff]` with hours
  past 24 for a multi-day value. `unsigned: true` marks an unsigned integer.
- A string longer than 512 bytes is cut on a character boundary and carries
  `"truncated": true` and `"byte_length"`. Bytes that are not UTF-8 are a lossy
  rendering with `"not_utf8": true` — never hex or base64 (the project rule).
  `"long_data": true` marks a value that arrived as `COM_STMT_SEND_LONG_DATA`.
- **`query_rendered` cannot be mistaken for SQL, by construction.** Values sit
  inside `⟨ ⟩` (U+27E8/U+27E9), which are not SQL syntax; strings are JSON
  literals, so an embedded quote is `\"` and never SQL's `''`; and a `⟨` or `⟩`
  inside a value is escaped as `⟨`/`⟩`, so a value can never close its
  own bracket and make the text after it read as statement. A truncated string
  ends `"…"…`. `query` keeps the text the client prepared, so a rule matching on
  it still matches.

Tests: `tests/server/mysql/stmt_params_test.rs` (the decoder and the tap, the
framing split at every byte), `prepared_params_test.rs` (`mysql_async` binding
eight types; a raw socket sending each panic shape and several lying lengths,
each answered 1835 at the right sequence id, none reaching the model, and the
connection then answering a ping, an execute, a type-reusing execute and a
long-data execute), and `fuzz/fuzz_targets/mysql_stmt_execute.rs`.

## Not implemented

- **Authentication** — every connection is accepted; username and password are
  ignored. See the section above: the connection *phase* is now completed the way
  a `caching_sha2_password` client expects, which is not the same thing as checking
  anything. Any current `mysql` CLI can be pointed at it.
- **TLS**.
- **Cursors and multi-row parameter arrays** — the execute's cursor flags and
  iteration count are read and ignored; every execute is answered with one result.
- **Binary column data** — `BLOB`/`BINARY` values are sent as UTF-8 text.
- **Transactions, stored procedures, multi-statement queries** — `BEGIN`,
  `COMMIT` and friends reach the model as ordinary queries.
- **`SELECT @@version` and other system variables** — the model must be told to
  answer them; nothing is auto-generated.

## Testing

`tests/server/mysql/test.rs` (note: `test.rs`, not `e2e_test.rs`), declared in
`tests/server/mod.rs`.

```bash
./cargo-isolated.sh test --no-default-features --features mysql \
    --test server -- server::mysql::test --test-threads=100
```

Real-client check by hand, with a static handler so no model is involved:

```bash
netget --mcp-http 18899 &
# start_server protocol=mysql port=13306 event_handlers=[{mysql_query → static …}]
mysql --no-defaults -h 127.0.0.1 -P 13306 -u root --protocol=TCP -e "SELECT * FROM t"
```

**Give that handler a branch for `select $$`.** The CLI sends two queries of its own
before it sends yours — `select @@version_comment limit 1` and `select $$` — and a real
MySQL server answers the second with **ERR 1064**. Answer it with a result set instead,
as a single static rule does, and the client is left holding an unread one; your actual
statement then fails with `ERROR 2014 (HY000): Commands out of sync`, which looks
exactly like a protocol defect and is not.

## Example prompts

```
Start a MySQL server on port 3306 for a database with a users table
(id INT, email VARCHAR). Answer SELECT with mysql_query_response, answer
INSERT/UPDATE/DELETE with mysql_ok_response, and answer a query naming an
unknown table with mysql_error_response error_code 1146.
```

## References

- [MySQL client/server protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html)
- [opensrv-mysql](https://docs.rs/opensrv-mysql/)
- [mysql_async](https://docs.rs/mysql_async/) — used by the E2E tests

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/mysql/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `HANDSHAKE_RESPONSE_TIMEOUT` | 30s | MySQL is server-speaks-first: `opensrv-mysql` writes the initial handshake and a real client answers at once, with the credentials already in hand. This bounds "connected, took the greeting, said nothing". |
| `IDLE_BETWEEN_COMMANDS_TIMEOUT` | 600s | Real MySQL's `wait_timeout` defaults to **eight hours**, a bound in name only, so copying it was not an option the way copying Kafka's was. Ten minutes is safe because of what this server is: it holds no session state a reconnect would lose (the no-storage rule), so a reaped pooled connection costs `mysql_async` or a JDBC pool one transparent reconnect. |
| `MAX_CONNECTIONS` | 256 | Refusal: **an ERR packet carrying error 1040 `ER_CON_COUNT_ERROR`, SQLSTATE `08004`** — precisely what a real MySQL server sends, in precisely this position, in place of the initial handshake as packet sequence 0. `mysql_async` surfaces "Too many connections" and the CLI prints `ERROR 1040 (08004)`. |
| `packet_limit::MAX_PACKET_BYTES` | 67108864 | The number the server **publishes**. `opensrv-mysql` answers `SELECT @@max_allowed_packet` with 67108864 itself, without consulting the shim, and never compared anything against it — a published ceiling that is not applied is worse than none, because a client sizes its writes by it. Enforcing anything *smaller* would leave the same mismatch pointing the other way. Refusal: **error 1153 `ER_NET_PACKET_TOO_LARGE`, SQLSTATE `08S01`**, with the message text mysqld itself uses. |
| `command_tap::LONG_DATA_PER_STATEMENT` / `LONG_DATA_PER_CONNECTION` | 64 MiB / 128 MiB | Long data the crate may hold between executes: `max_allowed_packet` per statement (mysqld applies it per parameter), two statements' worth per connection. Chunks past either are withheld from the crate; refusal: **1105 `HY000`** at the next execute, with mysqld's text. |

**NetGet's own MySQL client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `src/client/mysql/mod.rs`'s `Conn::new` has mysql_async answer the greeting
with HandshakeResponse41 before any model turn — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** `AsyncMysqlIntermediary::run_on` owns the protocol loop, so there is no `read()` of ours to wrap — but it takes a *generic* reader, which is the seam. `IdleTimeoutReader` arms its clock only while a read is actually outstanding, so while `MysqlHandler` is working the reader is not being polled and no clock runs. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.

### The packet bound: where it sits, and the seam that lets it answer

`opensrv-mysql` 0.7.0 has **no maximum-packet check anywhere**. `PacketReader::next_async`
grows its buffer by `max(1 MiB, len * 2)` until a whole *logical* packet fits, and `packet()`
assembles that logical packet with `nom::multi::fold_many0(fullpacket, …)` — an unbounded fold
over 16 MiB continuation fragments. So the peer decided how much this process allocated, and it
decided **before authentication and before any model call**: the first thing a client sends is
its handshake response, read through exactly this path.

Two seams make the repair possible, and neither is obvious from the crate's docs:

- **The reader.** `run_on` takes a *generic* `R: AsyncRead`, so
  `packet_limit::PacketLimitReader` sits beneath the crate and decides each packet from the
  length the peer **declared** in its 4-byte header — before the payload behind it is read, and
  therefore before anything is allocated for it. For a chain of `0xFFFFFF` fragments the bound
  is on the running sum, because that is what a logical packet's declared size *is*; a
  per-fragment check would pass every fragment forever.
- **The writer.** `run_on`'s `W` is `AsyncWrite + Send + Unpin`, which `&mut WriteHalf` meets,
  so the connection task lends the write half instead of giving it away. When the limiter trips,
  the crate's loop returns and the task still owns the socket — which is the only moment at
  which a refusal decided *beneath* the crate can be expressed *in* the crate's protocol.

The ERR packet carries sequence `refused + 1`. That is not a detail: MySQL numbers packets
within a command and a conforming client discards a reply out of sequence, so getting it wrong
turns a clear refusal back into the silence the bound exists to replace.

**It then drains before it closes** (`LINGER_DRAIN_BYTES` / `LINGER_DRAIN_TIMEOUT`, nginx's
`lingering_close`). A peer refused here is by definition still writing, and closing a socket
with unread data in the receive queue sends `RST`, which discards the bytes already written —
so without the drain the peer's `write` fails with `ECONNRESET` and it never reads the error
number, the SQLSTATE or the message.

`tests/server/mysql/packet_limit_test.rs` covers all of it: the framing decision at an exact
boundary and across a legitimate chain, an oversized packet sent **as the handshake response**
(so the bound is demonstrably pre-auth) answered 1153 with zero model calls, and an ordinary
query still working. Verified by removing the check, at which point three of the four fail and
the ordinary-query control still passes.

### The same header carries the sequence ids the crate panics on

`opensrv-mysql` 0.7.0 answers each client packet with `writer.set_seq(seq + 1)` on the client's
`u8` sequence id (`lib.rs:389`, `:452`, `:502`, `:563`), so a client sending `0xFF` overflows
it — a panic in every debug and test build, wrapped silently in release. And `packet()`
reassembles a chain with `assert_eq!(nseq, seq + 1)` between fragments and
`assert_eq!(last.0, full.0 + 1)` before the last (`packet_reader.rs:252`, `:266`), so a peer
that misnumbers its fragments panics the connection task in every build. Both are reachable in
the handshake response, before authentication. A panic there is swallowed by `tokio::spawn`:
the peer sees a bare close and `close_connection_on_server` never runs.

`PacketLimitReader` therefore also refuses a header with sequence id `0xFF` (nothing legitimate
sends it: a client's packets in one exchange start at 0 or 1, and reaching 255 would take a
4 GiB chain) and a chain fragment that is not numbered one past the previous, recording
`Refusal::OutOfOrder`; the connection task answers MySQL's own **1156
`ER_NET_PACKETS_OUT_OF_ORDER`**, SQLSTATE `08S01`, through the same write-first-then-drain path.
`tests/server/mysql/sequence_id_test.rs` covers both from the wire and the reader's boundaries
directly; `fuzz/fuzz_targets/mysql_session.rs` runs the crate's whole loop behind the reader.

**Still exposed, in the prepared-statement path (not changed here):** `ParamParser`
(`params.rs`) splits the null bitmap and type map with `split_at` on lengths the client controls
(`params.rs:86`), `panic!`s on an unknown column type (`:91`), and `unwrap`s
`Value::parse_from` (`:127`) — each a panic on a malformed COM_STMT_EXECUTE once a statement is
prepared. And COM_STMT_SEND_LONG_DATA appends to a per-parameter `Vec` with no bound
(`lib.rs:663-678`), so a peer that keeps sending long data for one prepared statement grows the
process without limit, 64 MiB per packet.

## One query, one answer

The real-model eval (`./run-eval.sh mysql`) found two things no mocked test could. Told to
report the current user or the server version, llama3.1:8b answered the `SELECT` with the
command-tag / OK action — copied from that action's example — so the client printed a tag (or
nothing) instead of the value; and it answered single queries with several response actions.

- The event carries `answer_with` (above), and the two actions' descriptions say which statements
  each answers — a `SELECT` of a single value is one column and one row, never a tag.
- The server has always sent the **first** response action and ignored the rest; it now says so,
  `decision=duplicate_response_dropped` with the count, instead of dropping them in silence.
  `tests/server/mysql/one_answer_per_query_test.rs` pins both: its rule matches only when
  `answer_with` names the rows action, and it asserts the client got the first of two result sets
  and the log carries the decision. Both halves were verified by removing them.

Measured with seed 42, five runs per case: `mysql/users-table` went 2/5 → 5/5 and `mysql/server-version` stayed 5/5.

