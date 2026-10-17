# FTP Server Implementation

## Overview

FTP (RFC 959) **control connection** server. Every reply the client sees is produced by a
handler — script, static or LLM. There is no filesystem behind it: the model invents the
directory listings and file contents, and nothing is read from or written to disk.

**Status**: Experimental
**Port**: 21 (privileged — `privilege_requirement` is `PrivilegedPort(21)`)
**Feature**: `ftp` (no extra crates; `ftp = []` in `Cargo.toml`)
**Files**: `mod.rs` (accept loop, session I/O), `actions.rs` (actions, event, metadata)

## What this is not

Read this before choosing FTP for anything.

**There is no data connection.** `PASV`, `EPSV` and `PORT` are not implemented — the server
never opens a second socket. Everything is written on the control connection. A real FTP
client (`ftp`, `lftp`, `curl`, FileZilla) will therefore:

- happily complete the login handshake (`USER`/`PASS`/`SYST`/`PWD` are plain replies), and
- fail or hang on anything that needs a transfer (`LIST`, `NLST`, `RETR`, `STOR`), because the
  handler's `PASV` reply is whatever the model made up and no data socket is listening behind it.

`send_ftp_list` and `send_ftp_data` write their bytes on the control connection anyway. That is
useful against a raw client (`nc localhost 2121`) and against an attacker who is reading the
transcript, and it is useless for interoperating with a real client. The action descriptions say
so; do not treat listing support as working file transfer.

Also missing: FTPS / `AUTH TLS`, binary vs ASCII mode (`TYPE` is just another reply), `REST`,
and any notion of a current working directory — the model tracks the cwd in its own memory or
not at all.

## Architecture

### Connection flow

1. Accept TCP (`create_reusable_tcp_listener`, so restarts do not hit `EADDRINUSE`).
2. Register the connection in `ServerInstance` so it appears in the TUI.
3. Raise `ftp_command` with `command = "CONNECTION_ESTABLISHED"` and write whatever the handler
   returns — this is how the mandatory 220 greeting is produced.
4. Read command lines with `read_command_line`, raise `ftp_command` per line, write the
   handler's output, repeat.
5. On `close_connection`, EOF, or a write error, mark the connection closed.

`read_command_line` exists because `BufReader::read_line` grows its buffer until it finds a
newline: a peer that connects and streams bytes with no `\n` made the server allocate without
bound, which is a one-connection out-of-memory from an unauthenticated client. It caps the
line at `MAX_COMMAND_LINE` (8 KiB — RFC 959 commands are short) and answers an over-long line
with `500 Command line too long` before closing, rather than dropping the connection silently.

### Dashboard injection (peer handle + counters)

`handle_session` owns `tokio::io::split(stream)`; the write half is an `Arc<Mutex<_>>` shared
with a `peer_support::spawn_peer_command_task`, registered right after the connection is added
and removed on every exit (EOF, both 421 paths, `close_connection`, errors) through the single
return at the end of `handle_session`. So `[ message this peer ]` / `[ disconnect this peer ]`
work: an injected `send_ftp_response` / `send_ftp_multiline` / `send_ftp_data` / `send_ftp_list`
is encoded by the same `execute_action` the handlers use and written to the control connection;
`close_connection` half-closes it. All of FTP's wire actions return `ActionResult::Output`, so
there is no `Custom`-result gap. Every read line and every write goes through
`update_connection_stats`, so the rail's `↓ ↑` counters and `last_activity` are live.
Proven with zero LLM calls in `tests/server/ftp/peer_injection_test.rs`.

The accept-loop `JoinHandle` is registered with `AppState::register_server_task()`, so
`stop_server` aborts it and releases port 21. `spawn_with_llm_actions` propagates bind failure
with `?`, so a port clash is reported as `Error` and not as a phantom `Running` server.

### Startup parameters

None. The previously advertised `passive_port_range` was never read by any code — there is no
passive mode to configure — and has been removed. `send_first` is not declared either: the
server always sends the greeting event itself, so passing `send_first` would only earn an
"unsupported" warning from `server_startup`.

## Failure behaviour

FTP is **not** one of the deliberately-silent protocols: RFC 959 gives it a reply code for
every terminal outcome, so a refusal can be stated on the wire and does not have to live only
in the log. Every outcome below is tagged with a `decision=` token in `mod.rs`, at the level
named, so `grep decision=fail_closed` finds exactly the requests the model did not answer.
The peer never sees the error text — both failure paths put only
`crate::utils::WireFailure`'s `&'static str` category in the 421, and the error goes to the log.

`<cmd>` below is the command line as received (`CONNECTION_ESTABLISHED` for the greeting
event, which is a sentinel and not something a client sends).

| Outcome | On the wire | Log |
|---|---|---|
| Model answered with `send_ftp_response` / `_multiline` / `_data` / `_list` | those bytes verbatim | INFO `decision=model_answer (reply <code>)` |
| Model answered `close_connection` and nothing else | control connection closed, no reply | INFO `decision=model_reject` |
| Model answered `wait_for_more` and nothing else | nothing — the next command line is read | INFO `decision=model_wait_for_more` |
| Model answered with no usable action at all | **nothing**; the client waits for its own timeout | WARN `decision=model_silent` |
| Executor refused the model's action (bad `code`, CR/LF in `message`, unknown action) | **nothing**; the client waits for its own timeout | ERROR `decision=fail_closed_bad_action` naming the action and the reason |
| Backend failed (unreachable, retries exhausted, malformed) | `421 Service not available, closing control connection (netget: request could not be processed)` then close | ERROR `decision=fail_closed_llm_error` with the full error |
| Backend saturated | `421 Service not available, closing control connection (netget: backend at capacity, retry later)` then close | ERROR `decision=fail_closed_llm_overloaded` with the full error |
| Control line over `MAX_COMMAND_LINE` with no newline | `500 Command line too long` then close | WARN `decision=refused_line_too_long` |

421 rather than silence because an FTP client may not send a command until it has read a
greeting, so a silent greeting failure hangs the client until its own timeout. The two
categories are kept apart deliberately: one is retryable and one is not.

**There is no fail-open here, and that is the property to preserve.** Nothing in `actions.rs`
can synthesise a reply — `execute_action` produces only the packet a named action asked for,
and an unknown action name is an `Err`, not a default. So no failure path can produce a 2xx:
an LLM outage during `USER`/`PASS` yields 421 and a closed connection, never 230. If you add a
fallback reply to either failure path, it must not be in the 2xx range.

**Three outcomes still share one thing on the wire — nothing.** `model_reject`,
`model_wait_for_more`, `model_silent` and `fail_closed_bad_action` all write no bytes, so only
the log distinguishes them. That is why `model_silent` is WARN and `fail_closed_bad_action` is
ERROR while the two deliberate ones are INFO. Tagging them was this pass's job; giving
`model_silent` and `fail_closed_bad_action` a real reply (451 and 500 respectively would be
the RFC 959 answers) was deliberately **not**, because it changes what a peer sees.

## LLM Integration

`call_llm` is used for both the greeting and every command, so script and static handlers run
in-process with **zero** LLM calls (`call_llm` → `try_execute_event_handler`). Only when no
handler matches does the model get invoked, once per command line.

### Event

| Event         | When                                            | Parameters |
|---------------|-------------------------------------------------|------------|
| `ftp_command` | connection accepted, and once per command line  | `command`, `answer_with` |

`command` is the raw line with the trailing CRLF stripped — not upper-cased, not split into
verb and argument. The single sentinel value `CONNECTION_ESTABLISHED` means "TCP connection
accepted, send your 220 greeting"; it is never sent by a client.

`answer_with` is the reply RFC 959 expects for the verb (`actions::answer_with_for_command`:
one 220 greeting, 331 **or** 230 for `USER`, 230/530 for `PASS`, a `257 "<dir>"` for `PWD`, …),
absent for a verb it does not classify.

### One completion reply per command

RFC 959 gives each command exactly one completion reply (2xx–5xx), optionally preceded by 1xx
replies. The real-model eval saw llama3.1:8b greet a connection with five `220`s and answer
`USER` with `331` and two `230`s; the client read each surplus reply as the answer to its *next*
command, so `USER anonymous` got `220 FTP Server Ready` and no login happened. `OneReply`
(`mod.rs`) writes up to the first completion reply of each answer and drops the rest with WARN
`decision=duplicate_response_dropped`; `tests/server/ftp/one_reply_test.rs` pins it (verified by
removing the check: the client then reads the second greeting as its USER reply). A non-numeric
write is not a reply and is let through.

### Actions

| Action                | Sends                                                     | Parameters        |
|-----------------------|-----------------------------------------------------------|-------------------|
| `send_ftp_response`   | `<code> <message>\r\n`                                    | `code`, `message` |
| `send_ftp_multiline`  | `<code>-<line>\r\n` … `<code> <last>\r\n`                 | `code`, `lines[]` |
| `send_ftp_data`       | raw text + CRLF, **on the control connection**            | `data`            |
| `send_ftp_list`       | one CRLF-terminated line per entry, **on the control connection** | `entries[]` |
| `wait_for_more`       | nothing — read another line first                         | –                 |
| `close_connection`    | nothing — closes the control connection                   | –                 |

`code` is validated: it must be a three-digit RFC 959 code in 100–599. Out-of-range values and a
missing `code` or `message` are errors, not silently substituted defaults — a wrong reply code
is worse than a visible failure.

`message`, each element of `lines`, and each `entries` element are rejected if they contain CR
or LF (`reject_line_breaks`). All three descriptions already promised this and nothing checked
it, which left `send_ftp_response` a response-splitting primitive: a `message` of
`"ok\r\n230 Logged in"` makes the client read a second, forged reply and treat a 331 as a
successful login. `send_ftp_data` is deliberately exempt — it is the documented raw escape
hatch for bytes the reply actions cannot express, and it normalises the ending so exactly one
CRLF is written (a bare `\n` is upgraded; previously this path emitted a lone `\r` and
truncated the line for the client).

There are no async (user-triggered) actions.

### Common reply codes

220 ready · 221 goodbye · 230 logged in · 250 command ok · 257 pathname created ·
331 need password · 421 service unavailable · 425 cannot open data connection ·
500 syntax error · 530 not logged in · 550 file unavailable

## Batching (supported, off by default)

With `batching: true`, command lines a pipelining client sent while the model was answering
are answered in one call (`lines_already_here`, `write_batch_answer` in `mod.rs`). FTP owes
each command exactly one completion reply and a client matches them by position alone, so a
batch is written only when the handler gave exactly one completion reply (2xx–5xx) per command,
in order — 1xx and non-numeric writes pass through, a handler that says nothing leaves every
command unanswered as it would one, and `close_connection` may end it early. Any other count
cannot be matched to commands: nothing of it is written, the client gets `421` and the
connection closes, logged `decision=fail_closed_batch_mismatch`. A small model miscounting
would therefore close sessions, which is why it is not on by default; real clients rarely
pipeline anyway. The greeting is never batched. `tests/server/ftp/batching_test.rs` covers the
off control, the matched batch and the refused mismatch.

## Storage

None, by design. The protocol holds no files, no directory tree and no cwd. Directory listings
and file contents come from the handler on every request; `send_ftp_list` formats strings the
model supplies and nothing else.

## Testing

`tests/server/ftp/` has mocked E2E tests (greeting, USER/PASS, PWD/QUIT, the 421 failure path)
and `peer_injection_test.rs` for the dashboard's per-peer injection. To verify by hand:

```
nc localhost 2121
USER anonymous
PASS a@b.c
SYST
PWD
QUIT
```

A real FTP client can be used to exercise login, but not transfers — see "What this is not".

## Example prompt

```
listen on port 2121 via ftp
Reply 220 "NetGet FTP" to CONNECTION_ESTABLISHED
Accept user anonymous with any password (331 then 230)
SYST -> 215 "UNIX Type: L8"
PWD  -> 257 "\"/\" is current directory"
QUIT -> 221 "Goodbye" then close_connection
```

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a control connection, a task and an `AppState` entry
forever. It now declares both halves; the constants and the reasoning live beside them in
`src/server/ftp/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_COMMAND_READ_TIMEOUT` | **300s**, overridable per server with `first_byte_timeout_secs` | Was 60s, on the argument that FTP is server-speaks-first and every real client — `ftp(1)`, `lftp`, curl, a browser — answers the `220` with `USER` from inside its own connect path, with no human in the loop yet. True of every third-party client and **irrelevant to the one this server most often has**: the greeting is *ours*, and sending it says nothing about whether the peer will answer it. `src/client/ftp/mod.rs` reads the `220` in its read loop and writes nothing until an action or `[ send message ]` says to, and a client made with the dashboard's `[ + ftp client ]` is routed `*` → manual — so it connects, parks our greeting for a person, and waits. At 60s the server dropped it while the operator was still looking at it. 300s is the window a `manual` rule gives a human (`src/state/intercepts.rs`). Cost: one idle stranger holds a slot for 300s rather than 60s, still capped at `MAX_CONNECTIONS` and still answered above that cap with `421`. A listener exposed to strangers should set the parameter low; 60 remains a sound choice for one. The greeting is generated and written before the command loop begins, so the model's time over it is outside this bound by construction. |
| `IDLE_BETWEEN_COMMANDS_TIMEOUT` | 300s, overridable per server with `idle_timeout_secs` | vsftpd's `idle_session_timeout` default — the idle bound on the FTP control connection that every client in use is already built to tolerate, and which ProFTPD's `TimeoutIdle` only doubles. It has to be on a human timescale: `ftp(1)` prompts the person at it for the password after `USER`, and again for each command, so the silence between two commands is someone typing. |
| `MAX_CONNECTIONS` | 256 | Refusal: **`421 Too many connections, closing control connection`**. RFC 959's own reply for a server declining to open a session, and what real FTP servers send at their client limit. A `4xx` is a transient negative reply, so a client retries later rather than recording a permanent failure. |

**NetGet's own FTP client is the *connected-and-silent* case, which is why this bound is 300s
and both bounds are declared parameters.** `src/client/ftp/mod.rs` connects, reads the `220` in
its read loop and writes nothing until a model action or a human's `[ send message ]`; at the
60s this bound used to carry, the server dropped a peer the operator was still looking at.
Server-speaks-first exempts nothing here — the bound closes a peer that is connected and
silent, and the greeting is ours, not the peer's. That was the wrong test, and it is the reason
this protocol was missed when `tcp`, `telnet`, `ldap`, `whois` and `redis` were raised.
`PROTOCOL_QUALITY.md`'s three-state test, and `src/server/redis/` is the shape copied.

**The deadline wraps the read and nothing else.** The LLM round-trip, and a `manual` rule parking
a command for a human (`src/state/intercepts.rs`, 300s by default), happen after a line has
already been read, so neither can be timed out from under itself.

`tests/server/ftp/connection_bounds_test.rs` drives all five from the wire: a silent peer is
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
