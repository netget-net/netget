# IMAP Protocol Implementation

## Overview

IMAP4rev1 (Internet Message Access Protocol) server covering enough of RFC 3501 for real
clients to log in, select a mailbox and fetch messages.
**Plain TCP on port 143 only** - there is no IMAPS and no STARTTLS.

**Status**: `DevelopmentState::Beta`, on **two** independent clients. Neither is a crate this
server frames with, because it frames by hand:

| client | file | what only it covers |
|---|---|---|
| `async-imap` 0.11 (Rust) | `tests/server/imap/e2e_client_test.rs` | LIST, EXAMINE, STATUS, NOOP, concurrent sessions, LOGIN failure |
| python3 stdlib `imaplib` | `tests/server/imap/real_client_test.rs` | the literal **byte** count against a multi-byte body, that imaplib reads NetGet's answer to its own `CAPABILITY` command (the greeting there carries no capability code, so it is the only source), and `select()`'s return value — the untagged `EXISTS` count rather than the tagged completion |

Neither is `#[ignore]`d or skip-gated; the `imaplib` test **fails** when python3 is absent, and
`imaplib` itself needs no install. One client can agree with one bug, which is why the second
exists — and the `imaplib` test was verified non-vacuous by two breaks whose *tagged* response
stayed correct in both cases: `body.len()` made `body.chars().count()` (FETCH completed `OK`,
imaplib returned no FETCH data at all) and the `* n EXISTS` line removed (SELECT completed `OK`,
`imaplib.select()` returned `[None]`). A test asserting only on the completion would have passed
both.

## Library Choices

- **Manual Implementation** - No external IMAP library used
- **Manual parsing** - Line-based command parsing without imap-codec. Commands are split into
  at most three fields (`splitn(3, ' ')`); quoting, literals (`{n}`) and continuation requests
  are not modelled, and whatever the split does not understand is handed to the model as text.
- Raw TCP handling with tokio for async I/O
- Chosen for maximum LLM control over mailbox and message storage

An `ImapServer::spawn_with_tls` advertising IMAPS on 993 used to live in `mod.rs`. Nothing
called it and it could not have worked - it passed a concatenated PEM string to
`native_tls::Identity::from_pkcs12`, which only accepts DER PKCS#12 - so it was deleted rather
than left looking implemented.

## Every response's `{N}` literals are checked before they reach the wire

`send_imap_response`'s `response` field relays a **pre-framed, model-authored** response
verbatim, and for a long time nothing checked its framing. RFC 3501 §4.3 makes a client read
*exactly* the declared number of octets, so a count that is wrong by even one desynchronises the
connection **permanently**: the client swallows the start of the next line as message body, then
reads the remainder as a response it cannot parse, and every tag after that is off by the
difference. There is no recovery, and no error the server can send afterwards that the client
will understand.

`validate_imap_literals` (`actions.rs`) walks the bytes once and refuses the action when they
disagree. It is wired at the single choke point in `execute_action`, so it covers every
`ActionResult::Output` this protocol produces rather than only the one action that needed it.
The actions that build their own literals are correct by construction and pass unchanged —
`send_imap_fetch` computes its counts from `body.len()`, which is a **byte** count — the
`imaplib` test above fetches a body containing `ü`, `ß` and an em dash precisely so that
`chars().count()` would be a different, wrong number.

What it accepts and rejects:

- `{N}` is a literal marker **only** when CRLF immediately follows it. `A001 OK fetched {46}
  bytes` is ordinary text and is left alone.
- At least `N` octets must follow, or the client blocks on octets never sent.
- Octet `N` must be followed by a space, a `)` or the CR of a CRLF — the three things RFC 3501's
  response grammar puts after a literal (last element of a line, or one element of a
  space-separated parenthesised list). This is what catches an over-count that is still long
  enough to exist.
- The walk skips *over* each literal's payload, so a `{5}` inside a message body is data rather
  than a second marker.

**Why a guard rather than a lint.** This defect is invisible to the assertions a test naturally
writes. A fixture in `tests/server/imap/test.rs` declared `{50}` for a 46-octet body and passed
for as long as it existed, because every assertion there is `line.contains("FETCH")` on a
**trimmed** string — and trimming discards precisely the framing the RFC cares about. It was the
pcap oracle, handing the raw bytes to Wireshark's dissector, that saw it. A short count could
still land on a legal follower and pass, so this is a guard against the counting mistake models
actually make, not a parser. `tests/server/imap/literal_framing_test.rs` pins both directions.

## Architecture Decisions

### Session State Machine

IMAP maintains explicit session state transitions:

- **NotAuthenticated** - Initial state after connection
- **Authenticated** - After successful LOGIN
- **Selected** - After SELECT/EXAMINE mailbox
- **Logout** - Terminal state

**Transitions happen only on a tagged `OK`.** `update_session_state` takes a `command_ok` flag
derived from the tagged completion the client actually received: the model's own tagged line
if it sent one (via `tagged_ok_for`), otherwise the synthesised completion (`OK` when untagged
data went out, `NO` when nothing did). LOGOUT is the sole exception and always transitions —
the client is leaving either way, and a dead session marked live is worse.

This used to run unconditionally, which was a fail-open on session state rather than on the
wire: a SELECT the model refused with `tag NO` still moved the session to `Selected` and
recorded the mailbox, so the client was told no while the server believed yes, and every later
FETCH/STORE ran against a mailbox the model had just declined. A command still awaiting more
data (`WaitForMore`) now transitions nothing either, since it has not completed.

State stored in `ProtocolConnectionInfo::Imap`:

```rust
ImapSessionState: NotAuthenticated | Authenticated | Selected | Logout
authenticated_user: Option<String>
selected_mailbox: Option<String>
mailbox_read_only: bool
```

### LLM Integration

- **Three event types**, each advertising its own action list. That list - not
  `get_sync_actions()` - is what `call_llm` offers the model, so an action missing from it is
  unreachable over the LLM path even though `execute_action` handles it:
    - `IMAP_CONNECTION_EVENT` - Initial greeting. Offers `send_imap_greeting`,
      `send_imap_untagged` and `send_imap_response`, because an IMAP banner is an untagged line
      and all three can produce one.
    - `IMAP_AUTH_EVENT` - LOGIN command (special handling). Deliberately narrow:
      `send_imap_response` and `close_connection`.
    - `IMAP_COMMAND_EVENT` - All other commands (SELECT, FETCH, etc.). `CAPABILITY` is not
      among them: NetGet answers it (below). `LIST`/`LSUB` and `SELECT`/`EXAMINE` are raised
      as narrowed copies of it (`actions::command_event`), same id, offering only their data
      action and `send_imap_response`
- **Action-based responses** - LLM returns JSON actions for all protocol interactions
- **Tagged responses** - IMAP uses command tags (A001, A002) for request/response correlation
- **Untagged responses** - Server data (EXISTS, RECENT, FLAGS) sent before tagged completion

### Connection Management

- Connections tracked in `AppState` with full statistics; `update_connection_stats` fires on
  every read and every write, so the dashboard's `↓ ↑` counters and `last_activity` stay live
- Each connection spawns independent async task
- Write operations use `Arc<Mutex<WriteHalf>>` for safe concurrent access
- Read operations use `BufReader` for line-based parsing

### Dashboard injection (`[ message this peer ]` / `[ disconnect this peer ]`)

Every connection registers a peer handle (`server::peer_support`) in the accept loop, right
after it is tracked and *before* the greeting event, so a manual `*` rule parking the greeting
still leaves the operator able to reach the connection while it waits. `AppState::send_to_peer`
runs the action through the same executor as the LLM path; every IMAP wire verb returns
`ActionResult::Output` and `close_connection` half-closes, so there is no `Custom` gap. The
handle is removed on every exit path (EOF, read error, refused greeting, LOGOUT) through the
single cleanup after `session.handle()` returns, and again idempotently by the peer task itself
on an injected close. Test: `tests/server/imap/peer_inject_test.rs` (zero LLM calls).

### Response Actions

The LLM controls IMAP responses through these actions:

- `send_imap_greeting` - Initial `* OK [CAPABILITY ...]` greeting; `IMAP4rev1` is always first
- `send_imap_response` - Tagged completion (`tag` + `status`), or one verbatim line via
  `response` (used for untagged banners)
- `send_imap_untagged` - Untagged informational responses
- `send_imap_list` - LIST response with mailbox list
- `send_imap_status` - STATUS response with mailbox info
- `send_imap_select` - the full untagged block for SELECT/EXAMINE (EXISTS, RECENT, UIDVALIDITY,
  UIDNEXT, FLAGS, PERMANENTFLAGS) in one action
- `send_imap_fetch` - FETCH response with message data
- `send_imap_search` - SEARCH response with message IDs
- `send_imap_exists` - EXISTS count
- `send_imap_recent` - RECENT count
- `send_imap_flags` - FLAGS list
- `send_imap_expunge` - EXPUNGE notification
- `wait_for_more` - Accumulate multi-line commands (APPEND)
- `close_connection` - Terminate session

### What NetGet answers itself, and what the model is told

The real-model eval (`./run-eval.sh imap`, llama3.1:8b, seed 42) scored `imap/list-folders` and
`imap/inbox-count` 0/5. imaplib sends `CAPABILITY` from its constructor, and the model answered
it with a bare tagged `OK` - **twice**, so imaplib read the second as the answer to `LOGIN` and
aborted (`unexpected tagged response`) - or with an empty `[CAPABILITY]` response code, after
which imaplib refused the server as "not IMAP4 compliant". Where the session got as far as
`SELECT`, the model answered it with a tagged `OK` and no `* n EXISTS`, so `select()` returned
`[None]`.

**`CAPABILITY` is answered by NetGet**, from the list the connection's greeting announced
(`greeting_capabilities` in `mod.rs`): `* CAPABILITY <list>` then `<tag> OK CAPABILITY
completed`, logged `decision=netget_answer`. That list is the one fact the command reports, so
the operator still decides it - through the greeting - and the model is not asked the same
question twice. `IMAP4rev1` is always first (`with_imap4rev1`; RFC 3501 6.1.1 requires it, and
imaplib refuses a server without it), in the greeting and in the answer, and a greeting with no
capability code gives `IMAP4rev1` alone. Only the argument-less command is answered: a
`CAPABILITY` carrying arguments is malformed and goes to the model like any other line. The
weighed alternative, a hint naming `send_imap_capability`, would have left the model answering
a question whose answer it had already given in the greeting; `send_imap_capability` is gone
from the vocabulary.

**Every other command the verb identifies carries `answer_with`** (`imap_answer_with`), and so
does `LOGIN`'s `imap_auth` event: `send_imap_select` with `exists` = the mailbox's message count
for `SELECT`/`EXAMINE` (NetGet adds the tagged `OK`), `send_imap_list` for `LIST`, and so on.
`send_imap_select`'s description says that a bare tagged `OK` is not an answer to `SELECT`.

**One tagged completion, written last.** A batch's untagged data is written first and its first
tagged completion (the line carrying the command's own tag) last, whatever order the model put
them in - a completion *before* `send_imap_select` would otherwise end the command before its
`EXISTS` line. Any further tagged completion - a second tagged `OK` was the common case - is
dropped and logged `decision=duplicate_response_dropped`, and so is an untagged block
byte-identical to one already queued (the model sent `send_imap_select` twice, and imaplib read
two `EXISTS` counts); so is anything after `LOGIN`'s
completion, and the greeting keeps only its first `Output`.

**A tagged response always has text.** RFC 3501's `resp-text` is at least one character, and
imaplib aborts on a bare `a1 OK` ("unexpected response") - measured on `LOGIN` in the eval - so
`send_imap_response` without a `message` renders `completed`.

**`LIST` and `SELECT` are offered only their own answer.** `actions::command_event` raises
`imap_command` - the same id, so handlers match as before - as a narrowed copy for `LIST`/`LSUB`
(`send_imap_list`, `send_imap_response`) and `SELECT`/`EXAMINE` (`send_imap_select`,
`send_imap_response`), with a description naming the command instead of the general one, which
lists every command and mentions `LOGIN`. Every other command gets the declared event with all
thirteen actions. Offered everything, llama3.1:8b answered `LIST` with a bare tagged `OK` - or a
tagged `OK` reading "Login successful. Folders: INBOX, Archive, Receipts." - in 6 of 8 replays
of one captured prompt, its reasoning beginning "User wants to log in"; offered the two, it sent
`send_imap_list` with the three mailboxes in 8 of 8. A `send_imap_response` description saying a
tagged `OK` carries no data had been measured before and made both cases worse (1/5, 1/5 - the
model started writing `* LIST` lines as `send_imap_untagged` data); removing the other eleven
actions does what that sentence could not.

**A completion carrying another tag is given the command's own** (`retag_completion`, logged
`decision=completion_retagged`). One command is in flight at a time, so the only tagged response
the server can owe is that command's completion; the model copied the `A001` of an action example
onto a `LIST` completion, and written as given imaplib read it as a response to a command it never
sent and aborted ("unexpected response"). A single `<tag> OK|NO|BAD …` line with a tag other than
the command's is rewritten; untagged (`*`), continuation (`+`) and multi-line output are left
alone. `LOGIN`'s completion goes through the same rewrite.

The `send_imap_response` example no longer carries `code: READ-WRITE` (the model put it on its
`CAPABILITY` answer), and the greeting example lists `IMAP4rev1` alone, since whatever it lists
is now what `CAPABILITY` reports.

`tests/server/imap/answer_with_test.rs` pins all of it from the wire; the two drops were each
verified by removing them and watching it fail.

### Command Parsing

Simple 3-field parser splits IMAP commands:

```rust
(tag, command, args) = parse_imap_command(line)
// Example: "A001 LOGIN alice secret"
// → ("A001", "LOGIN", "alice secret")
```

LOGIN command has special handling for authentication event.

## State Management

IMAP session state tracked in `AppState`:

- `ImapSessionState` - Current session state
- `authenticated_user` - Username after successful LOGIN
- `selected_mailbox` - Currently selected mailbox (INBOX, Sent, etc.)
- `mailbox_read_only` - Whether mailbox is read-only (EXAMINE vs SELECT)

State transitions:

- `LOGIN OK` → `Authenticated`
- `SELECT/EXAMINE OK` → `Selected`
- `CLOSE` → `Authenticated`
- `LOGOUT` → `Logout`

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that took the greeting and said nothing held a socket, a connection task, a peer-command channel
and an `AppState` entry forever — before any `LOGIN` — on a server that would happily accept a
hundred more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/imap/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_COMMAND_READ_TIMEOUT` | 60s | Dovecot's `login_timeout` default, which is the same idea for a connection that has got nowhere. This bound is tighter in *scope* — it ends at the first command rather than at authentication. The greeting's own model round-trip happens before the loop and is outside it. |
| `IDLE_BETWEEN_COMMANDS_TIMEOUT` | 2100s (35 min) | **This number exists because of `IDLE`.** A client in IDLE (RFC 2177) is legitimately silent, waiting for the *server* to speak, and an operator can advertise `IDLE` through the greeting's capability list, which is also what `CAPABILITY` reports. RFC 2177 §3 requires the client to terminate and re-issue IDLE **at least every 29 minutes**, so 29 minutes is the interval this bound sits above; 35 gives the `DONE` and the re-issued `IDLE` room to cross a slow link and still count as activity. |
| `MAX_CONNECTIONS` | 256 | Refusal: an untagged **`* BYE [UNAVAILABLE] too many connections`** — IMAP's own way of ending a session unilaterally (RFC 3501 §7.1.5) with RFC 5530's machine-readable reason, the same pair this server already uses for a failed greeting and an oversized command line. There is no tag to echo: the peer has sent nothing. |

**NetGet's own IMAP client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `src/client/imap/mod.rs` runs async-imap's `login()`, putting `LOGIN` on the
wire before any model turn or keystroke — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline wraps the read and nothing else**, so `handle_command`'s model round-trip — or a
`manual` rule parking a command for a human at the dashboard, 300s by default — is never inside
it. The longer bound is armed on the first *complete command line*, so a peer dripping a partial
line still gets the shorter one. An idle close writes `* BYE [UNAVAILABLE] idle timeout` and logs
`decision=fail_closed_idle_timeout`, because a client told why does not record a permanent fault.

`tests/server/imap/connection_bounds_test.rs` drives both halves from the wire against a
model-free server (static handlers answer the greeting and the commands, so nothing there depends
on a backend): a greeted peer that says nothing gets `* BYE` and is closed, and a peer that has
issued one command is still answered 68 seconds later. Replacing the `tokio::time::timeout`
around `read_bounded_line` with the bare call makes the first test hang for its whole 100-second
window and fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is
removed, and `tests/accept_bounded_test.rs` covers the shared helper.

## Limitations

- **No message persistence** - LLM manages mailbox data in memory/context
- **Batching is opt-in** - see "Batching" below for why it is not on by default
- **No TLS** - plain TCP only; neither IMAPS nor STARTTLS
- **No SASL AUTH** - Only LOGIN authentication supported
- **No IMAP extensions** - IDLE, CONDSTORE, QRESYNC not implemented
- **No mailbox subscriptions** - SUBSCRIBE/UNSUBSCRIBE not tracked
- **No server-side search** - SEARCH criteria interpreted by LLM
- **No message flags persistence** - Flags not persisted across sessions
- **State transitions are unconditional** - `update_session_state` moves the session to
  `Selected` on any `SELECT`/`EXAMINE` line, whatever the model answered, so a SELECT the model
  refused with `NO` still leaves the session reported as Selected.

## Examples

### Example LLM Prompt

```
listen on port 143 via imap. Support IMAP4rev1, IDLE, NAMESPACE capabilities.
Allow LOGIN for 'alice' with password 'secret'.
INBOX has 5 messages, 2 recent.
For FETCH 1, return message with From: test@example.com, Subject: Test.
```

### Example LLM Response (Greeting)

```json
{
  "actions": [
    {
      "type": "send_imap_greeting",
      "hostname": "mail.example.com",
      "capabilities": ["IMAP4rev1"]
    }
  ]
}
```

### Example LLM Response (LOGIN Success)

```json
{
  "actions": [
    {
      "type": "send_imap_response",
      "tag": "A001",
      "status": "OK",
      "message": "LOGIN completed"
    }
  ]
}
```

### Example LLM Response (SELECT)

```json
{
  "actions": [
    {
      "type": "send_imap_exists",
      "count": 5
    },
    {
      "type": "send_imap_recent",
      "count": 2
    },
    {
      "type": "send_imap_flags",
      "flags": ["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"]
    },
    {
      "type": "send_imap_response",
      "tag": "A002",
      "status": "OK",
      "code": "READ-WRITE",
      "message": "SELECT completed"
    }
  ]
}
```

### Example LLM Response (FETCH)

```json
{
  "actions": [
    {
      "type": "send_imap_fetch",
      "sequence": 1,
      "data": {
        "FLAGS": ["\\Seen"],
        "UID": 1001,
        "RFC822.SIZE": 2048,
        "BODY[]": "From: test@example.com\r\nSubject: Test\r\n\r\nHello World"
      }
    },
    {
      "type": "send_imap_response",
      "tag": "A004",
      "status": "OK",
      "message": "FETCH completed"
    }
  ]
}
```

## References

- RFC 3501 - IMAP4rev1 Protocol Specification
- RFC 4551 - IMAP Extension for Conditional STORE (CONDSTORE)

## Max inbound message size

`MAX_COMMAND_BYTES = 8192` (`mod.rs`), declared as `metadata().max_inbound_bytes`.

IMAP4rev1 sets no line limit of its own, so the reference point is what a real server chose:
Dovecot's `imap_max_line_length` defaults to 64 KiB. 8 KiB is deliberately tighter, because
this server does not implement literals — a `{n}` continuation is passed to the model as raw
text rather than parsed (see Library Choices) — so no command reaching this reader legitimately
carries a message body. What is left is tags, mailbox names and UID sets.

The bound exists because `AsyncBufReadExt::read_line` grows its `String` until it finds a `\n`
and caps nothing: a peer that connected and streamed bytes with no newline made the server
allocate without limit, before `LOGIN` and therefore before any authentication. The read now
goes through `crate::utils::line_reader::read_bounded_line`, shared with POP3 and NNTP.

The refusal is an untagged `* BYE [UNAVAILABLE] command line exceeds 8192 bytes`, and the
untagged form is forced rather than chosen: an IMAP tag is the *first* token of a line, and the
line never arrived, so there is nothing for a tagged `NO` to correlate to. RFC 3501 §7.1.5
makes `* BYE` the server's way of ending a session unilaterally. Logged
`decision=fail_closed_oversized_command`.

The refusal happens **before** `handle_command` builds any event, so an oversized line never
reaches a prompt. `tests/server/imap/line_limit_test.rs` asserts exactly that — zero model
calls, not merely a BYE — and its second test asserts a 4 KiB command is still answered.

## Batching (supported, off by default)

With `batching: true`, commands a client pipelines while the model is answering an earlier one
are answered in one model call. `collect_batch` takes only whole, distinctly tagged lines that
are already buffered and that one model call would answer (`imap_batch_role`): `LOGIN`,
`AUTHENTICATE`, `STARTTLS`, `IDLE`, `APPEND`, any line ending in a literal and `CAPABILITY` are
always answered alone, and `SELECT`/`EXAMINE`/`CLOSE`/`UNSELECT`/`LOGOUT` end a batch so the next
command's event reports the new session state. Each batched event's `answer_with` tells the
model to end that command with its own tagged completion. `split_batch_answer` then divides the
answer at the completions and uses it only when every tag is completed exactly once, in order,
with untagged data before its own completion and nothing after the last; a completion for a
tag outside the batch is not rewritten as it is for a single command. Otherwise every command
gets `<tag> NO [SERVERBUG]` (`decision=fail_closed_batch_mismatch`) and no session state
changes.

It is off by default because the single-command path writes the tagged `OK` itself for
`LIST`/`SELECT`/`STATUS`/`FETCH`/`SEARCH`, and the event hints say so: a model answering a batch
the way it answers one command leaves completions out, and in a batch nothing can say which
command each untagged line belongs to, so every pipelined command would be refused. Turn it on
for a model that follows the batched hint. `tests/server/imap/batching_test.rs` holds the
control, the claim (one call, every line and tag in order) and the fail-closed short answer.
