# Bolt Protocol Implementation (Neo4j)

Neo4j's **Bolt** protocol — the binary protocol every Neo4j driver and `cypher-shell` speaks to
a Neo4j graph database. The model is the graph database: it decides whether a login is accepted
and what each Cypher query returns. NetGet stores no graph, owns the whole protocol state
machine, and writes every byte.

**State**: Beta (see Maturity). **Privilege**: `None` — the well-known port is 7687.
**Stack**: `ETH>IP>TCP>BOLT`. **Feature**: `bolt` (the server codec needs no additional dependencies).

## Library choice

None. The crates on crates.io (`bolt-proto`, `bolt-client`, `neo4rs`) are client-side or
Bolt-4-era, and none states the property the decoder needs most: that a peer cannot make it
recurse without bound or allocate what the bytes do not contain. PackStream is ~300 lines
(`packstream.rs`), so it is hand-written with both guards explicit.

## Files

| File | What it holds |
|---|---|
| `mod.rs` | accept loop, handshake, the session loop and state machine, streaming, ROUTE, the admin queries |
| `packstream.rs` | `Value`, `decode` (depth-bounded, declared lengths checked), `encode` (smallest form), `chunk`, `Dechunker` (1 MiB cap) |
| `messages.rs` | handshake negotiation, request tags and `parse_request`, SUCCESS / RECORD / IGNORED / FAILURE builders |
| `values.rs` | model JSON → PackStream (with `$node` / `$relationship` / `$path`), parameters → JSON, stats, failure-code validation, `query_answer` |
| `actions.rs` | the `Protocol`/`Server` impls, five actions, two events |

## What the real client sends (captured before writing this)

`cypher-shell` 2026.09.0 (Java, neo4j-java-driver 6.2.1) was pointed at a raw TCP recorder
(a Python script answering SUCCESS to everything) with `-a bolt://…` and `-a neo4j://…`, both
one-shot and interactive (through a pty), and with `:begin`/`:commit`, `-d`, `-P` and
`--access-mode read`. What it sent:

```
handshake 60 60 b0 17 | 00 00 01 ff | 00 08 08 05 | 00 02 04 04 | 00 00 00 03
          magic        manifest v1   5.8 range 8   4.4 range 2   3.0
>> HELLO  {user_agent: "neo4j-cypher-shell/v2026.09.0",
           bolt_agent: {product: "neo4j-java/6.2.1-…", language: "Java/21", …},
           routing: {address: "127.0.0.1:7687"}}          # routing only for neo4j://
>> LOGON  {scheme: "basic", principal: "neo4j", credentials: "<password>"}
>> ROUTE  [{address: …}, [], {}]                           # neo4j:// only, then RESET
>> RUN    "CALL db.ping()" {} {tx_metadata: {type: "system", app: "cypher-shell_v2026.09.0"}}
>> PULL   {n: 1000}                                         # pipelined with the RUN
>> RESET
>> RUN    "CALL dbms.licenseAgreementDetails()" {} {…system…}   + PULL, RESET
>> RUN    "<the user's query>" {params} {tx_metadata: {type: "user-direct"}, db?, mode: "r"?}
>> PULL   {n: 1000}
>> RESET
>> BEGIN  {tx_metadata, db?, mode?}  … RUN "<q>" {params} {} + PULL {n: 1000} … COMMIT   # :begin/:commit
>> GOODBYE
```

Two things the recorder established that the specification would not have told us:

- **The driver refuses a HELLO `server` agent that does not start `Neo4j/`** ("Server does not
  identify as a genuine Neo4j instance"). The agent is `Neo4j/<neo4j_version>`, default 5.26.0.
- **From Bolt 5.7 a FAILURE must be the GQL error object.** Answering 5.8 with the pre-5.7
  `{code, message}` made cypher-shell die with a Java `NullPointerException` reading a field
  that was not there.

## Version

The first client proposal overlapping **5.0–5.8** wins, at the highest minor both sides speak.
cypher-shell 2026.09 offers the 5.7+ handshake manifest first; it names major 255 and is passed
over, so cypher-shell falls back to its plain `5.8 range 8` proposal and gets **5.8**. The
manifest (which is how a client reaches Bolt 6) is not implemented. Nothing overlapping →
`00 00 00 00` and close (`decision=fail_closed_no_common_version`); not the Bolt magic → close
without an answer (`decision=fail_closed_bad_magic`).

Why 5.8 and not lower: every 5.x difference that matters here is small and implemented — 5.0
carries credentials in HELLO (handled: the auth event is raised from HELLO and a success moves
straight to READY), 5.1+ splits auth into LOGON/LOGOFF, 5.4 adds TELEMETRY (answered SUCCESS),
5.7 changes the FAILURE shape (both shapes are rendered, by negotiated minor). 5.6's GQL
statuses in summaries and 5.8's home-database hints are optional server metadata and are not
sent.

FAILURE on 5.7+: `{gql_status: "50N42", description: "error: general processing exception -
unexpected error. <message>", message, neo4j_code: <code>, diagnostic_record: {OPERATION: "",
OPERATION_CODE: "0", CURRENT_SCHEMA: "/"}}`. `50N42` is Neo4j's own status for an error with no
more specific GQL mapping; the driver classifies on `neo4j_code`. The real-client test asserts
`ClientException` for a `Neo.ClientError.Statement.*` code and `AuthenticationException` for
`Unauthorized`; `TransientException`, `SecurityException` (`Security.Forbidden`),
`FatalDiscoveryException` (`Database.DatabaseNotFound`) and `DatabaseException` were checked by
hand against their codes with `--error-format stacktrace`.

## State machine (NetGet's, never the model's)

| State | Accepts | Goes to |
|---|---|---|
| CONNECTED | HELLO | AUTHENTICATION (5.1+) / READY (5.0, after the auth event) |
| AUTHENTICATION | LOGON | READY on accept; FAILURE and **close** on reject |
| READY | RUN, BEGIN, ROUTE, LOGOFF, TELEMETRY (5.4+) | STREAMING / TX_READY / READY / AUTHENTICATION / READY |
| STREAMING | PULL, DISCARD | READY when the result is drained, else STREAMING (`has_more: true`) |
| TX_READY | RUN, COMMIT, ROLLBACK | TX_STREAMING / READY / READY |
| TX_STREAMING | RUN (another result, new `qid`), PULL, DISCARD (by `qid`, `-1` = last opened) | TX_READY when every result is drained |
| FAILED | — everything but RESET/GOODBYE is **IGNORED** | READY on RESET |
| any | RESET → READY (or AUTHENTICATION if not logged in), GOODBYE → close | |

- **INTERRUPTED**: a message already received *ahead of* a RESET the client has also sent is
  answered IGNORED without being handled. This is checked over messages already in the buffer;
  a model call already in flight is not cancelled — the RESET is handled after it answers.
- **Anything else** (a PULL in READY, COMMIT with a result still open, RUN before LOGON, an
  unknown tag) is FAILURE `Neo.ClientError.Request.Invalid` "Message 'X' cannot be handled by
  a session in the Y state." and a close (`decision=fail_closed_protocol_violation`).
- Messages are handled strictly in order; pipelined RUN+PULL is the normal case.

## What the model sees and controls

| Event | Data | Actions |
|---|---|---|
| `bolt_authenticate` | `user_agent`, `scheme`, `principal`, `credentials_present`, `password_configured`, `answer_with` — **never the credential** | `accept_bolt_login`, `reject_bolt_login {code?, message?}` (code must be `Neo.ClientError.Security.*`, default `…Unauthorized`), `close_connection` |
| `bolt_query` | `query`, `parameters` (JSON), `database` (when named), `mode: read\|write`, `in_transaction`, `answer_with` | `send_bolt_records {fields, records, stats?, query_type?}`, `send_bolt_failure {code, message}`, `close_connection` |

**The login decision says what it is decided on.** `bolt_authenticate`'s description and its
`answer_with` (`actions::login_answer_with`) say the decision is about this user, this scheme and
whether a credential was sent — before any query exists — and that the instructions' rules about
queries apply to each query when it arrives, never to the login. Told "act as a Neo4j graph
database that accepts any login. Reject any query that is not valid Cypher with Neo4j's syntax
error", llama3.1:8b answered the login with `reject_bolt_login` five runs in five (real-model
eval, seed 42): "Reject" was the instruction's operative verb, and nothing in the login event
said no query was being decided.

**The query says whether it even begins like Cypher.** `bolt_query`'s `answer_with`
(`actions::query_answer_with`) says to hold the query against the instructions first and answer
`send_bolt_failure` with the code that says why when they refuse it
(`Neo.ClientError.Statement.SyntaxError` for invalid Cypher), names the query's first word and
whether it is one of the clauses a Cypher statement begins with (`MATCH`, `CREATE`, `RETURN`,
`CALL`, `SHOW`, …), and otherwise asks for the rows the instructions say the graph holds. That is
a fact read off the text and no substitute for Neo4j's parser. Told "reject any query that is not
valid Cypher with Neo4j's syntax error", llama3.1:8b answered `SELECT name FROM people` with rows
— the event example's Alice and Bob — in every run (real-model eval, seed 42); a hint that only
said to check validity first was replayed against the captured prompt and changed nothing, and
naming the first word turned five seeds in five into the syntax error, while a `MATCH` under the
same hint still got its rows. `send_bolt_failure`'s example message (`Invalid input 'RETRUN'…`)
is copied for the message text; the eval case passes either way.

**A record may be an object keyed by exactly the field names.** `{"name": "Ada"}` for fields
`["name"]` is the same row as `["Ada"]` and is read in field order — the shape a Neo4j driver
hands back as a record, and the one llama3.1:8b used for every row of
`MATCH (p:Person) RETURN p.name AS name` in the eval, each refused until this was accepted. An
object with any key missing, extra or misnamed is still refused, so nothing is guessed.

`send_bolt_records` is validated before anything is sent: each record must have exactly one
value per field, field names non-empty and distinct, `query_type` one of `r`/`w`/`rw`/`s`
(default `r`), `stats` keys among Neo4j's counters (`nodes_created` or `nodes-created`, …,
non-negative integers; `contains-updates` / `contains-system-updates` derived). A refused answer
is `decision=fail_closed_invalid_answer`. `send_bolt_failure` codes must have the shape
`Neo.{ClientError|TransientError|DatabaseError}.<Category>.<Title>`.

### Values

Plain JSON maps to PackStream the obvious way (integers that fit i64 → INT, other numbers →
FLOAT, strings, booleans, null, lists, maps). Three single-key objects are graph values:

```json
{"$node": {"id": 1, "labels": ["Person"], "properties": {"name": "Alice"}, "element_id": "…"?}}
{"$relationship": {"id": 7, "type": "KNOWS", "start": 1, "end": 2, "properties": {}}}
{"$path": {"nodes": [{…node…}, …], "relationships": [{…rel…}, …]}}
```

Nodes are Bolt 5 `Node` structures (4 fields, `element_id` defaulting to the id as a string),
relationships 8-field `Relationship`s. In a path, `relationships[i]` must join `nodes[i]` and
`nodes[i+1]` in **either** direction; NetGet dedupes nodes and relationships and computes the
index sequence (1-based relationship index, negative when traversed against its direction;
0-based node index). cypher-shell renders all three as graph values — the real-client test
asserts `(:Person {…})-[:ACTED_IN {…}]->(:Movie {…})` and the `<-[…]-` form. **Not supported:**
temporal and spatial values (give them as strings), bytes. Model values are bounded to the same
32 levels the decoder accepts.

Parameters reach the model as JSON; bytes become `{"$bytes_length": n}` and any structure
(a `date()` parameter, a node) becomes `{"$structure": "Date", "fields": […]}`.

### Answered by NetGet, never by the model

HELLO, ROUTE, BEGIN, COMMIT (`bookmark`), ROLLBACK, RESET, LOGOFF, TELEMETRY, GOODBYE, all
IGNORED/FAILURE mechanics, and the admin queries cypher-shell runs on every connect, matched on
the whole query (case- and whitespace-insensitive):

| Query | Answer |
|---|---|
| `CALL db.ping()` | `success: true` |
| `CALL dbms.licenseAgreementDetails()` | `status: "yes", daysLeftOnTrial: 0, totalTrialDays: 0` — cypher-shell reads `status`; `yes` prints nothing |
| `CALL dbms.components()` | `name: "Neo4j Kernel", versions: [<neo4j_version>], edition: "community"` |
| `CALL dbms.components() YIELD versions` | `versions: [<neo4j_version>]` |

So connecting cypher-shell costs exactly one event (the login), and a one-shot query one more.
`SHOW DATABASES` and friends are not special-cased: cypher-shell does not send them on connect,
and when a user does, the model answers.

ROUTE answers a one-server routing table (`ttl: 300`, the requested `db` or `neo4j`, WRITE /
READ / ROUTE all naming one address). The address is the one the client put in its routing
context — what it dialled — so `neo4j://` clients come back to this server; failing that, the
listener's own address.

A write's summary (query type other than `r`, auto-commit) carries a `bookmark`; COMMIT always
does. Bookmarks are opaque `FB:netget:<server>:<ms>` strings — NetGet stores nothing, so no
causal-consistency guarantee is implied.

### The password

`password` (startup parameter): NetGet compares a basic-auth credential against it in constant
time; a mismatch, or any non-basic scheme, is FAILURE `Neo.ClientError.Security.Unauthorized`
and a close (`decision=reject_bad_credentials`) **without raising the event**. With it unset,
every login reaches `bolt_authenticate`, which decides with `credentials_present` and the
principal. The credential is in no event and no log line either way (asserted by
`state_machine_test.rs`).

## Failure behaviour

`FailureMode::Answers` (`.answers_on_failure()`).

| Cause | On the wire | Log |
|---|---|---|
| backend failed | FAILURE `Neo.TransientError.General.DatabaseUnavailable`, fixed message per `WireFailure` category ("…unavailable…" / "…at capacity; retry…") | `decision=fail_closed_llm_error category=…` |
| answer refused by the executor | same FAILURE | `decision=fail_closed_invalid_answer` |
| nothing answered | same FAILURE | `decision=model_silent` |
| a login answer to a query (or vice versa) | same FAILURE | `decision=fail_closed_mismatched_reply` |
| the model's own failure | FAILURE with its code and message | `decision=model_reject` |
| rows | SUCCESS / RECORD… / SUCCESS | `decision=model_answer` |

For a **query**, the connection enters FAILED and recovers on RESET — Bolt's own path, which
every driver takes. For a **login**, the connection closes: a login nobody could decide is
refused, never admitted (a backend outage must not open the database). No error text reaches
the client; the messages are constants.

## Request and answer schema guards

Known requests require their native exact field count. HELLO/LOGON/BEGIN/RUN maps
cannot be omitted or replaced with null. PULL/DISCARD require an explicit integer
`n` (positive or -1); an optional `qid` is an integer at least -1. A malformed count
never means drain-all. ROUTE requires string bookmarks and Bolt5 metadata; TELEMETRY
requires an API integer0..3.

Owned answer actions receive iterative JSON preflight before copying/conversion:
container depth36 (the JSON action/records/row wrappers are included),65,536nodes,
8MiB retained content. Over-budget owned values are disposed iteratively. Converted
cells are checked at their actual wire position inside RECORD/row envelopes, so
PackStream container depth32 is accepted and33 is refused before any RECORD.
`schema_guard_test.rs` exercises each boundary, constructed10,000-depth owned input,
malformed wire PULL and recoverable overdepth answers.

## Bounds

| Bound | Value | Override | Why |
|---|---|---|---|
| `MAX_MESSAGE_BYTES` (= `max_inbound_bytes`) | 1 MiB summed over a message's chunks | — | Checked on each chunk's declared size before its payload is awaited, so a stream that never sends the zero chunk cannot grow past it. Refusal: FAILURE `Neo.ClientError.Request.Invalid`, close, `decision=fail_closed_message_too_large`. |
| `MAX_PACKSTREAM_DEPTH` | 32 | — | One byte opens a level; without it ~100 KB of `0x91` overflows the stack and kills the process (verified). Refusal: FAILURE `Request.Invalid`, close, `decision=fail_closed_too_deep`. |
| declared lengths | ≤ bytes remaining | — | A LIST_32 header declares four billion entries in five bytes; counts are checked (an element ≥ 1 byte, a map entry ≥ 2) before `Vec::with_capacity`. |
| `FIRST_BYTE_TIMEOUT` | 30 s for the whole 20-byte handshake | `first_byte_timeout_secs` | Bolt is client-first and drivers send the handshake with the connect. Half a handshake does not reset the clock. |
| `IDLE_TIMEOUT` | 300 s between messages | `idle_timeout_secs` | Drivers pool connections and leave them idle between queries. Wraps the read only, so a query parked on a `manual` rule is never closed by it. |
| `MAX_CONNECTIONS` | 256 (house default) | — | The peer past the cap is closed without a handshake answer (Bolt has nothing to say before the handshake). |

Every close lingers (2 s / 64 KiB) so a FAILURE sent with pipelined input still unread arrives
before FIN rather than being destroyed by an RST.

## Peer handle

Registered for every connection, so the dashboard's `[ disconnect ]` works (`close_connection`
half-closes, the peer reads EOF). `[ message ]` accepts and validates an answer action but
writes nothing: Bolt defines no server-initiated message, and bytes out of turn would
desynchronise the client's response queue. `peer_inject_test.rs` asserts both.

## Wireshark

This Wireshark build (4.6.8) has no Bolt dissector — `tshark -G protocols` lists nothing matching
bolt, neo4j or packstream — so `src/tui/wireshark.rs` maps `bolt` to plain TCP and there is no
pcap-oracle test.

## Maturity

Beta. Evidence: `tests/server/bolt/real_client_test.rs` drives Neo4j's own `cypher-shell`
(Java, neo4j-java-driver 6.2; not linked, not written by us, and the server uses no Bolt
library) through rows, nodes, relationships and paths both ways, write statistics, a
model-chosen error classified by the driver, a wrong password, an explicit transaction with
`-d` and `-P`, `neo4j://` routing, and a mocked model's rows. It is not `#[ignore]`d and fails,
never skips, when cypher-shell or its Java runtime is absent; CI's `registry-audit` installs the
release zip and runs it. Promoted after the whole suite passed three consecutive runs at
`--test-threads=100` and `scripts/beta_evidence_table.py --check` stayed green with
`cypher-shell` ✓ as the peer.

What would still be missing for Stable: a second independent client (the Python `neo4j`
driver, or a Go/JS driver — condition 1); a pcap oracle (no dissector exists — condition 2).
A fuzz target exists (`fuzz/fuzz_targets/packstream_message.rs`, depth-bomb and
huge-declared-length seeds; verified to crash with the depth guard removed, then 60 s clean).
