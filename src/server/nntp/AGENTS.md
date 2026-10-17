# NNTP Protocol Implementation

## Overview

NNTP (Network News Transfer Protocol) server implementing Usenet news server functionality. The LLM controls news
article distribution, newsgroup management, and article retrieval. Focuses on core NNTP commands (LIST, GROUP, ARTICLE,
POST, etc.) with line-based text protocol.

**Status**: Experimental (Application Protocol)
**RFC**: RFC 3977 (Network News Transfer Protocol), RFC 2980 (Common NNTP Extensions)
**Port**: 119 (plain TCP), 563 (verified implicit TLS when configured)

## Library Choices

- **No NNTP library** - Manual protocol implementation
    - NNTP is line-based text protocol (simple parsing)
    - Commands parsed from text lines
    - Responses constructed as formatted strings with numeric codes
    - Multi-line responses end with ".\r\n"
- **tokio** - Async runtime and I/O
    - `TcpListener` for accepting connections
    - `BufReader` for line-based reading
    - `AsyncWriteExt` for sending responses

**Rationale**: NNTP protocol is straightforward enough that no dedicated library is needed. Messages are text lines
ending with `\r\n`, commands are space-separated tokens, responses use numeric codes (similar to SMTP/FTP). Manual
implementation gives LLM full control over newsgroup and article management.

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM receives NNTP commands and responds with structured actions:

- `send_nntp_message` - Send raw NNTP message
- `send_nntp_response` - Send response with code and text (e.g., "200 Service ready")
- `send_nntp_article` - Send article with headers and body (multi-line)
- `send_nntp_list` - Send list of newsgroups (multi-line)
- `send_nntp_group` - Send GROUP response (211 count low high group)
- `send_nntp_overview` - Send article overview (XOVER/OVER command)
- `wait_for_more` - Buffer more data before responding
- `close_connection` - Close client connection

### 2. Line-Based Message Processing

NNTP message flow:

1. Accept TCP connection
2. Send greeting (200 Service ready or 201 No posting)
3. Read lines with `BufReader::read_line()` (splits on `\n`)
4. Parse NNTP command from line (e.g., "GROUP comp.lang.rust\r\n")
5. Send line to LLM as `nntp_command_received` event
6. LLM returns actions (e.g., `send_nntp_group`)
7. Execute actions (send responses)
8. Loop for next line

### 3. Automatic Line Termination

All NNTP messages must end with `\r\n`:

- Received messages: Preserved as-is from `read_line()`
- Sent messages: Automatically add `\r\n` if not present
- `send_nntp_message`: Formats to ensure `\r\n` termination
- Multi-line responses: End with `.\r\n` (dot-stuffing for lines starting with dot)

### 4. Multi-Line Responses

NNTP uses multi-line responses for articles, lists, etc.:

- Start with status line (e.g., "220 <msg-id> article follows")
- Content lines
- End with `.\r\n` on its own line
- Lines starting with `.` should be dot-stuffed (`.` → `..`)

### 5. Dual Logging

- **DEBUG**: Command summary with 100-char preview ("NNTP received 15 bytes: GROUP comp.lang.rust")
- **TRACE**: Full text message ("NNTP data (text): \"GROUP comp.lang.rust\\r\\n\"")
- Both go to netget.log and TUI Status panel

### 6. Connection Management

Each NNTP client gets:

- Unique `ConnectionId`
- Entry in `ServerInstance.connections` with `ProtocolConnectionInfo::Nntp`
- Tracked bytes sent/received, packets sent/received
- State: Active until client disconnects or sends QUIT

## What NetGet answers itself, and what the model is told

The real-model eval (`./run-eval.sh nntp`, llama3.1:8b, seed 42) scored all three NNTP cases
0/5. nntplib sends `CAPABILITIES` from its constructor, before the command a case is about, and
the model answered it with the `200` greeting - copied from `send_nntp_response`'s example,
`200 NetGet NNTP Service Ready` - so nntplib raised `NNTPReplyError` and the `GROUP` or `LIST`
under test was never sent. It also answered one greeting with two, and an unknown group with
`501` (syntax error) where RFC 3977 says `411`.

**`CAPABILITIES` and `MODE READER` are answered by NetGet** (`netget_answer` in `mod.rs`),
logged `decision=netget_answer`. Each has one correct form. `CAPABILITIES` is `101` with
`VERSION 2`, `READER`, `LIST ACTIVE` and `OVER` - what this server has actions for
(`send_nntp_group`/`send_nntp_article`, `send_nntp_list`'s active format, `send_nntp_overview`),
plus the selected posting/feed extensions: `POST` when the greeting is 200, `IHAVE`, `STREAMING`, and `AUTHINFO USER` only on TLS. `MODE READER` repeats the
greeting's own status: `200` if the greeting said `200`, otherwise `201`. A hint could not have
fixed `CAPABILITIES`: its answer is a multi-line `101` block no action renders except the raw
`send_nntp_message`, so answering it removes the failure class outright. The cost is that an
event handler can no longer see either command; `tests/server/nntp/peer_inject_test.rs` and
`connection_bounds_test.rs` used `MODE READER` as an arbitrary command for a static rule to
answer and now use `HELP`.

**Every other command the verb identifies carries `answer_with`** (`nntp_command_event_data`),
naming the action and reply code for that one command - for `GROUP`, `send_nntp_group` if the
group exists and `send_nntp_response` with `411` if it does not - plus `group` (GROUP) or
`article` (ARTICLE/HEAD/BODY) split out. `send_nntp_response`'s example is now a `201` greeting
for `news.example.invalid`, and its description names the codes other commands take.

**One command, one reply.** `SessionWrite` keeps one `Output` of a batch and counts the rest,
which are logged `decision=duplicate_response_dropped` - on the greeting as on every command.
The one kept is the reply of the action `answer_with` names when the batch has it
(`nntp_preferred_actions`: `send_nntp_group` for `GROUP`, `send_nntp_list` for `LIST`, …), else
the first - a model that sends a status line and *then* the answer is answering with the
second (`ExecutionResult::chosen_reply`).

`tests/server/nntp/answer_with_test.rs` pins all of it from the wire; the drop and the
NetGet-answered commands were each verified by removing them and watching it fail.

## LLM Integration

### Event Type

**`nntp_command_received`** - Triggered when NNTP client sends a command

Event parameters:

- `command` (string) - The NNTP command received (e.g., "GROUP comp.lang.rust")
- `answer_with` (string, when the verb says) - the action and reply code for this command
- `group` / `article` (string) - GROUP's newsgroup, ARTICLE/HEAD/BODY's number or message-id

### Available Actions

#### `send_nntp_message`

Send raw NNTP message (for custom responses).

Parameters:

- `message` (required) - NNTP message to send (auto-adds `\r\n` if missing)

Example:

```json
{
  "type": "send_nntp_message",
  "message": "200 NetGet NNTP Service Ready"
}
```

#### `send_nntp_response`

Send NNTP response with code and text.

Parameters:

- `code` (required) - NNTP response code (e.g., 200, 211, 500)
- `text` (required) - Response text

Example:

```json
{
  "type": "send_nntp_response",
  "code": 200,
  "text": "NetGet NNTP Service Ready - posting allowed"
}
```

Sends: `200 NetGet NNTP Service Ready - posting allowed\r\n`

#### `send_nntp_article`

Send NNTP article with headers and body (multi-line response).

Parameters:

- `code` (optional) - Response code (220=article, 221=head, 222=body, default: 220)
- `message_id` (optional) - Message-ID
- `headers` (required) - Article headers (one per line)
- `body` (optional) - Article body text

Example:

```json
{
  "type": "send_nntp_article",
  "code": 220,
  "message_id": "<12345@example.com>",
  "headers": "Subject: Welcome to Rust\r\nFrom: user@example.com\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000",
  "body": "This is a test article about Rust programming."
}
```

Sends:

```
220 <12345@example.com> article follows
Subject: Welcome to Rust
From: user@example.com
Date: Mon, 1 Jan 2024 00:00:00 +0000

This is a test article about Rust programming.
.
```

#### `send_nntp_list`

Send list of newsgroups (multi-line response).

Parameters:

- `groups` (required) - Array of newsgroups with name, high, low, status

Example:

```json
{
  "type": "send_nntp_list",
  "groups": [
    {"name": "comp.lang.rust", "high": 100, "low": 1, "status": "y"},
    {"name": "comp.lang.python", "high": 200, "low": 1, "status": "y"}
  ]
}
```

Sends:

```
215 list of newsgroups follows
comp.lang.rust 100 1 y
comp.lang.python 200 1 y
.
```

#### `send_nntp_group`

Send GROUP response with count and article range.

Parameters:

- `name` (required) - Newsgroup name
- `count` (optional) - Estimated number of articles (default: 0)
- `low` (optional) - Lowest article number (default: 0)
- `high` (optional) - Highest article number (default: 0)

Example:

```json
{
  "type": "send_nntp_group",
  "name": "comp.lang.rust",
  "count": 100,
  "low": 1,
  "high": 100
}
```

Sends: `211 100 1 100 comp.lang.rust\r\n`

#### `send_nntp_overview`

Send article overview information (XOVER/OVER command).

Parameters:

- `articles` (required) - Array of articles with number, subject, from, date, message_id, references, bytes, lines

Example:

```json
{
  "type": "send_nntp_overview",
  "articles": [
    {
      "number": 1,
      "subject": "Welcome",
      "from": "user@example.com",
      "date": "Mon, 1 Jan 2024 00:00:00 +0000",
      "message_id": "<12345@example.com>",
      "references": "",
      "bytes": 100,
      "lines": 5
    }
  ]
}
```

Sends:

```
224 overview information follows
1	Welcome	user@example.com	Mon, 1 Jan 2024 00:00:00 +0000	<12345@example.com>		100	5
.
```

## Connection Management

### Connection Lifecycle

1. **Accept**: TCP listener accepts connection
2. **Register**: Connection added to `ServerInstance` with `ProtocolConnectionInfo::Nntp`
3. **Split**: Stream split into ReadHalf and WriteHalf
4. **Track**: WriteHalf stored in `Arc<Mutex<WriteHalf>>` for sending
5. **Greeting**: Send initial greeting (200 or 201)
6. **Read Loop**: Continuous line reading until disconnect
7. **Close**: Connection removed when client closes or sends QUIT

### Dashboard injection (`[ message this peer ]` / `[ disconnect this peer ]`)

`handle_connection` registers a peer handle (`server::peer_support`) right after the connection
is tracked and *before* the greeting event, so a manual `*` rule parking the greeting still
leaves the operator able to reach the connection. `AppState::send_to_peer` runs the action
through the same executor as the LLM path; every wire verb here returns `ActionResult::Output`
and `close_connection` half-closes, so there is no `Custom` gap. Every read and every write the
server itself makes goes through `update_connection_stats` (injected writes are counted by the
generic peer task, not here), and the handle is removed on every exit path (EOF, read error,
`close_connection`, refused greeting, overload 400) by the single cleanup in
`handle_connection`. Test: `tests/server/nntp/peer_inject_test.rs` (zero LLM calls).

### State Management

- `ProtocolState`: Idle/Processing/Accumulating (prevents concurrent LLM calls)
- `queued_data`: Data buffered while LLM is processing
- Connection stays in ServerInstance until closed
- UI updates on every message (bytes sent/received, last activity)

## Failure contract: the peer always gets a line, and it is always a category

NNTP is strictly one response line per command and the server speaks first, so silence is not a
neutral outcome here - the client blocks on a line that is never coming, and if it gives up and
sends the next command it reads that command's reply as this one's. Every path in `run_session`
that produces nothing to send therefore writes a 4xx instead:

| Situation | Greeting | Command | Log tag |
|---|---|---|---|
| LLM backend overloaded | `400`, then close | `400`, then close (RFC 3977 3.1: come back later) | `decision=fail_closed_llm_error` |
| LLM call errored otherwise | `400`, then close | `403`, session stays open | `decision=fail_closed_llm_error` |
| An action failed to execute | `400`, then close | `403`, session stays open | `decision=fail_closed_action_error` |
| The answer contained no actions | `400`, then close | `403`, session stays open | `decision=fail_closed_no_actions` |
| `wait_for_more` / `close_connection` | nothing written (deliberate) | nothing written (deliberate) | - |
| The model answered | its own line | its own line | `decision=model_answer` / `model_reject` |

Two rules hold across all of it:

- **The peer gets a category, the log gets the error.** The free text comes from
  `crate::utils::WireFailure` (`&'static str`), never from the error, the action name, the
  backend URL or the model name. A newline in an error could otherwise forge a second response
  line and desynchronise the session on its own. `tests/wire_failure_test.rs` fails the build if
  an interpolated form reappears.
- **An answer with no actions is the worse case, not the exempt one.** It is what an empty model
  reply, a manual "answer with nothing" and a zero-action static handler all produce, and it
  arrives as `Ok` with no failures - which is exactly why it used to slip through. Only an
  explicit `wait_for_more` or `close_connection` buys silence.

`model_reject` (a 4xx/5xx line the model itself chose) is kept distinct in the log from
netget's own `fail_closed_*` replies, so a real denial is never confused with a backend outage.

Tests: `tests/server/nntp/llm_failure_test.rs` covers all four failure rows.

## Batching (on by default)

RFC 3977 §3.5 lets a client pipeline any command. Commands pipelined while the model is
answering an earlier one are answered in one model call, one response each, in order. The
reading commands (`GROUP`, `LISTGROUP`, `LIST`, `ARTICLE`/`HEAD`/`BODY`, `STAT`, `NEXT`, `LAST`,
`OVER`/`XOVER`, `HDR`/`XHDR`, `NEWGROUPS`, `NEWNEWS`, `DATE`, `HELP`) join a batch and `QUIT`
ends one (`nntp_batch_role`); `CAPABILITIES` and `MODE` (NetGet's), `AUTHINFO`, `POST`, `IHAVE`,
`TAKETHIS`, `CHECK` and `STARTTLS` are always handled alone, and a session that still has to
authenticate batches nothing. Lines join only when already buffered and only when one model call
would answer them all. `answer_batch` writes the answer only when it holds exactly one response
per command; otherwise every pipelined command gets `403`
(`decision=fail_closed_batch_mismatch`), and a backend failure answers each as a single command's
failure is answered. `tests/server/nntp/batching_test.rs` holds the control, the claim and the
fail-closed short answer.

## Known Limitations

### 1. No Article Storage

- Server doesn't store articles persistently
- No database or filesystem storage
- LLM generates articles on-demand from prompts
- No real article retention or expiry

**Workaround**: LLM can maintain pseudo-storage through conversation context or external database via actions.

### 2. Handler-owned Authentication

AUTHINFO USER/PASS requires implicit TLS. Handlers approve or reject each login; there is no account database. SASL is outside the scope. `require_auth=true` refuses reader/feed commands before approval.

### 3. Handler-owned Posting

POST, IHAVE and TAKETHIS accept bounded articles through handler decisions. No articles are retained automatically; external storage belongs to the handler.

### 4. Sequential Feed Transactions

MODE STREAM, CHECK and TAKETHIS are supported on the selected connection. No asynchronous feed scheduler, peer routing or durable delivery queue is supplied.

### 5. Implicit TLS Only

`use_tls=true` requires PEM `cert_path`/`key_path`. STARTTLS is not implemented.

### 6. Limited NNTP Extensions

- No XPAT (pattern matching)
- No LISTGROUP (list article numbers)
- No HDR (header retrieval)
- Basic NNTP commands only

**Future Enhancement**: Add common NNTP extensions as needed.

### 7. No Newsgroup Hierarchy Management

- No dynamic newsgroup creation/deletion
- Newsgroups defined in LLM prompt
- No newsgroups file

## Example Prompts

### Basic Read-Only News Server

```
listen on port 119 via nntp
Send greeting: "200 NetGet NNTP Service Ready - posting allowed"
Support newsgroups: comp.lang.rust, comp.lang.python, misc.test
When users send LIST, show all newsgroups
When users send GROUP <name>, respond with article count
When users send ARTICLE <number>, generate a test article
When users send QUIT, close connection
```

### News Server with Categories

```
listen on port 119 via nntp
Newsgroups: comp.lang.rust, comp.lang.python, sci.math, rec.arts.books
For GROUP command, show: comp.lang.rust has 50 articles (1-50)
For ARTICLE command, generate relevant article based on newsgroup
For XOVER command, show article summaries with subject, author, date
```

### Tech News Server

```
listen on port 119 via nntp
Act as a tech news aggregator
Newsgroups: tech.programming, tech.linux, tech.security
Generate articles about recent tech topics
Each article has proper headers (Subject, From, Date, Message-ID)
Support ARTICLE, HEAD, BODY commands
```

### Simple Test Server

```
listen on port 119 via nntp
One newsgroup: misc.test
10 test articles (numbers 1-10)
All articles say "This is test article <number>"
Support LIST, GROUP, ARTICLE commands
```

## Performance Characteristics

### Latency

- **Per Command (with scripting)**: Sub-millisecond
- **Per Command (without scripting)**: 2-5 seconds (LLM call)
- Line parsing: <1 microsecond
- Response formatting: <1 microsecond

### Throughput

- **With Scripting**: Thousands of commands per second
- **Without Scripting**: ~0.2-0.5 commands per second (LLM-limited)
- Concurrent connections: Unlimited (bounded by system resources)
- Each connection processes independently

### Scripting Compatibility

Good scripting candidate:

- Text-based protocol (easy to parse and generate)
- Repetitive command/response patterns
- Article content can be templated
- Newsgroup lists are static

## NNTP Protocol References

### Common Commands

- **CAPABILITIES** - List server capabilities (RFC 3977)
- **MODE READER** - Switch to reader mode
- **LIST** - List newsgroups
- **GROUP** - Select newsgroup
- **ARTICLE** - Retrieve article (headers + body)
- **HEAD** - Retrieve article headers only
- **BODY** - Retrieve article body only
- **STAT** - Check article existence
- **NEXT** - Move to next article
- **LAST** - Move to previous article
- **POST** - Post new article
- **QUIT** - Close connection
- **XOVER** (or OVER) - Article overview (subject, author, etc.)
- **XHDR** (or HDR) - Retrieve header field
- **AUTHINFO** - Authentication (RFC 4643)

### Common Response Codes

- **200** - Service available, posting allowed
- **201** - Service available, posting not allowed
- **211** - Group selected (count low high name)
- **215** - List of newsgroups follows
- **220** - Article retrieved (headers + body)
- **221** - Article headers retrieved
- **222** - Article body retrieved
- **224** - Overview information follows
- **281** - Authentication accepted
- **400** - Service temporarily unavailable
- **411** - No such newsgroup
- **420** - No current article selected
- **423** - No such article in group
- **430** - No such article
- **440** - Posting not allowed
- **500** - Command not recognized
- **501** - Command syntax error
- **502** - Permission denied

### Response Format

```
<code> [parameters] <text>
```

Examples:

- `200 NetGet NNTP Service Ready`
- `211 100 1 100 comp.lang.rust`
- `220 0 <12345@example.com> article follows`

### Multi-Line Format

```
<status line>
<content line 1>
<content line 2>
...
.
```

Example (ARTICLE response):

```
220 0 <12345@example.com> article follows
Subject: Welcome
From: user@example.com
Date: Mon, 1 Jan 2024 00:00:00 +0000

This is the article body.
.
```

## References

- [RFC 3977: Network News Transfer Protocol (NNTP)](https://datatracker.ietf.org/doc/html/rfc3977)
- [RFC 2980: Common NNTP Extensions](https://datatracker.ietf.org/doc/html/rfc2980)
- [RFC 4643: NNTP Authentication](https://datatracker.ietf.org/doc/html/rfc4643)
- [Wikipedia: NNTP](https://en.wikipedia.org/wiki/Network_News_Transfer_Protocol)
- [NNTP Command Reference](https://www.ietf.org/rfc/rfc3977.txt)

## Max inbound message size

`MAX_COMMAND_BYTES = 4096` (`mod.rs`), declared as `metadata().max_inbound_bytes`.

RFC 3977 §3.1 fixes the NNTP command line at 512 octets including the CRLF. 4 KiB is eight
times that, leaving room for the long wildmat arguments `NEWNEWS` and `LIST ACTIVE` carry while
staying far below anything worth buffering from an unauthenticated peer.

The bound exists because `AsyncBufReadExt::read_line` grows its `String` until it finds a `\n`
and caps nothing: a peer that connected and streamed bytes with no newline made the server
allocate without limit. The read now goes through
`crate::utils::line_reader::read_bounded_line`, shared with POP3 and IMAP.

An over-long line is answered `501 command line too long` — RFC 3977's syntax-error response —
and the session closes, because the peer is mid-line and there is no resynchronisation point.
Logged `decision=fail_closed_oversized_command`. Closing *without* a 501 would have made an
oversized request indistinguishable from a dropped connection, and NNTP is strictly one
response line per command, so a client that read the close would desynchronise rather than
learn anything.

The refusal happens **before** the `nntp_command_received` event is built, so an oversized line
never reaches a prompt. `tests/server/nntp/line_limit_test.rs` asserts exactly that — zero
model calls, not merely a 501 — and its second test asserts a 2 KiB command is still answered.

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever. It now
declares both halves; the constants and the reasoning live beside them in
`src/server/nntp/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_COMMAND_READ_TIMEOUT` | **300s**, overridable per server with `first_byte_timeout_secs` | Was 60s. NNTP is server-speaks-first: the peer is answered with a `200`/`201` greeting and every reader — `nntp`, `slrn`, `tin`, a mail client's news backend — replies inside its own connect path with `CAPABILITIES` or `MODE READER` — true of every third-party reader and **irrelevant to the peer this server most often has**, because the greeting is *ours* and sending it says nothing about whether the other end will answer it. `src/client/nntp/mod.rs` reads the welcome line in its read loop and writes nothing until an action or `[ send message ]` says to, and a dashboard-made client is routed `*` → manual, so at 60s the server dropped the operator's own client while they were still looking at it. 300s is the window a `manual` rule gives a human (`src/state/intercepts.rs`). Cost: one idle stranger holds a slot for 300s rather than 60s, still capped at `MAX_CONNECTIONS` and still answered above that cap. A listener exposed to strangers should set the parameter low; 60 remains a sound choice for one. The greeting is generated and written before this loop begins, so however long the model or a `manual` rule takes over it, the clock has not started. |
| `IDLE_BETWEEN_COMMANDS_TIMEOUT` | 600s, overridable per server with `idle_timeout_secs` | A newsreader is idle for as long as the person at it takes to read an article, so the bound has to be on a human timescale — which is why news server operators configure their client timeout in minutes. It is safe to be this generous because this server holds nothing on the client's behalf that a reconnect cannot rebuild: the model answers every command afresh. |
| `MAX_CONNECTIONS` | 256 | Refusal: **`400 too many connections`**. `400` is NNTP's "service temporarily unavailable, the connection is closing" response, and RFC 3977 lets a server send it at any point — including in place of a greeting, which is exactly where a refused peer is. A client reads it as *retry later* rather than as a permanent refusal, which is what a connection cap means. |

**NetGet's own NNTP client is the *connected-and-silent* case, and this bound is therefore
wrong as it stands:** `src/client/nntp/mod.rs` connects, reads the greeting in its read loop
and writes nothing until a model action or a human's `[ send message ]`, so at 60s the server
drops a peer the operator is still looking at. Server-speaks-first exempts nothing here: the
bound closes a peer that is connected and silent, and the greeting is ours, not the peer's. It
wants 300s with declared `first_byte_timeout_secs`/`idle_timeout_secs`, as `src/server/redis/`
has — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline wraps the read and nothing else.** The LLM round-trip, and a `manual` rule parking
a command for a human (`src/state/intercepts.rs`, 300s by default), happen after a line has
already been read, so neither can be timed out from under itself.

`tests/server/nntp/connection_bounds_test.rs` drives all five from the wire: a silent peer is
closed at `first_byte_timeout_secs`, a connection whose answer is parked for a human is not
closed at all however far past that bound the park runs, an answered connection that goes quiet
is closed at `idle_timeout_secs` rather than at the first-byte one, and the connection past
`MAX_CONNECTIONS` is answered with the refusal above and then a clean EOF. The fifth is the
regression for the raise: with **no parameters passed at all**, a silent peer is still open past
the 60 seconds this bound used to be, which is why that test is deliberately the slow one. Each
was verified by removing the thing it tests — the deadline, the parameter read, the busy
marking, the cap — and watching it fail; the default was verified by putting 60 back and watching
the regression test fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound
is removed from the source, and `tests/accept_bounded_test.rs` covers the shared cap mechanism
itself, including that a busy connection is never reported as idle.

## October 2026 extensions

POST, IHAVE and RFC 4644 MODE STREAM/CHECK/TAKETHIS are now supported as sequential transactions. Handlers receive `operation`, `article`, `message_id` and `answer_with`; respond with `nntp_article_result` or `nntp_check_result` and an explicit `accepted` boolean. No article database is retained. Streaming mode does not promise an autonomous feed scheduler or delivery outside the selected connection.

Implicit NNTPS uses `use_tls`, PEM `cert_path`/`key_path`. AUTHINFO USER/PASS is offered only on encrypted connections and cleartext credentials receive 483. With `require_auth=true`, authentication is handler-approved through `nntp_auth_result`; application commands receive 480 until approved. STARTTLS and SASL are outside this scope. A 201 greeting excludes POST from capabilities and rejects posting with 440. Articles are capped at 8 MiB and lines at 64 KiB; commands remain capped at 512 bytes. Invalid feed IDs and ordering return protocol errors. Authentication secrets are redacted from wire diagnostics.

Independent extension verification uses Python 3.10 nntplib, including its verified SSL implementation. See `tests/server/nntp/extensions_test.rs` and `tests/peers/README.md`.

Browser regression: after `./web/build.sh`, run `node web/test/nntp.mjs`. It drives both roles through capabilities, dot-stuffed POST, sequential TAKETHIS and QUIT over the browser’s virtual loopback; this is runtime coverage, not independent-peer interoperability evidence. Browser CI runs it beside the general bundle smoke test.
