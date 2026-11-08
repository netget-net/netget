# FTP Server Implementation

## Overview

FTP (RFC 959, RFC 2428) server: the control connection **and** passive and active data
connections. Every reply on the control connection, every directory listing and every file is
produced by a handler — script, static or LLM. There is no filesystem behind it: the handler
supplies listings and file contents, and an upload is handed to the handler, never written to
disk.

**Status**: Beta (see "Maturity" at the foot)
**Port**: 21 (privileged — `privilege_requirement` is `PrivilegedPort(21)`)
**Files**: `mod.rs` (accept loop, session I/O, the transfer sequence), `data.rs` (setup verbs,
data-connection open/read/write, ASCII conversion, bounds), `actions.rs` (actions, event,
metadata)

## What the server answers itself, and what the handler answers

The data-connection setup verbs are mechanics: their replies name a socket only the server can
open, or change how the server frames bytes, so a handler inventing a `227` would point the
client at a port nothing listens on. They never reach the handler (`data::answer_setup`,
logged `decision=server_answer` or `decision=refused_*`):

| Command | Reply |
|---|---|
| `PASV` | binds a listener on the **configured host**, port 0, and answers `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` with the control connection's local address (a wildcard bind host is not an address a client can connect to). `425` on an IPv6 control connection (use `EPSV`) |
| `EPSV`, `EPSV 1`/`2` | the same listener, `229 Entering Extended Passive Mode (\|\|\|port\|)`; the other family's number is `522`; `EPSV ALL` is `200` and refuses every other setup verb with `501` afterwards |
| `PORT h1,…,p2` / `EPRT \|1\|addr\|port\|` | `200`, if the address is the control connection's own peer and the port is 1024 or above; otherwise `500 Illegal PORT command` (the FTP bounce attack, RFC 2577 §3; vsftpd's `port_promiscuous=NO`). An unknown EPRT family is `522` |
| `TYPE A`, `A N` / `TYPE I`, `L 8` | `200 Type set to A` / `I`; anything else `504`, nothing `501` |
| `MODE S`, `STRU F` | `200`; any other mode or structure `504` |

A passive listener binds the host the server was configured with and nowhere wider — `0.0.0.0`
only when that is the configured host. A passive data connection from any address but the
control connection's peer is dropped and the wait goes on (vsftpd's `pasv_promiscuous=NO`), so
another host that guessed the port cannot take the transfer. Each setup command replaces a
channel no transfer has used yet, and each transfer consumes the channel whatever its outcome:
one channel, one transfer.

The transfer verbs are the handler's, with the server writing RFC 959 §5.4's reply sequence
around its answer (`Transfer` in `mod.rs`):

| Command | Handler answers with | Then the server writes |
|---|---|---|
| `LIST`, `NLST`, `MLSD` | `send_ftp_list` (`ls -l` lines, bare names, or RFC 3659 fact lines; `[]` is an empty directory) | `150`, the listing on the data connection (CRLF after every line, whatever `TYPE` says), `226` |
| `RETR` | `send_ftp_data` with the file's contents | `150`, the contents (in `TYPE A` every LF not already after a CR becomes CRLF; in `TYPE I` unchanged), `226` |
| `LIST`/`NLST`/`MLSD`/`RETR` | a `450`/`550` reply | that reply, and no `150` — a refusal must come before one |
| `STOR`, `APPE` | one completion reply (`226` to confirm, `451`/`552` to refuse) | `150` **first**, then reads the upload to EOF, then raises the event with it, then the handler's reply |

An upload has to be read before there is anything to ask about, so its `150` comes before the
handler is consulted; a download is asked about first, so a refusal can precede any `150`. The
upload reaches the handler as `upload_bytes`, plus `upload_text` when it is valid UTF-8
(`upload_is_text`); in `TYPE A` CRLF is turned back into LF first. A binary upload is described
by its size alone — the event never carries raw bytes or base64.

A transfer command with no prepared channel is answered `425 Use PASV, EPSV, PORT or EPRT
first` without consulting the handler. A `150`/`226` the handler wrote beside a payload is not
sent — the server owns that sequence — except that a `226`/`250` of its own replaces the
server's default `226 Transfer complete` text; anything else is dropped with WARN
`decision=transfer_reply_dropped`. `send_ftp_list` / `send_ftp_data` in answer to any other
command have no data connection to go to: `decision=fail_closed_bad_action`, answered `451`.

Also missing: FTPS / `AUTH TLS`, `REST` (no resumed transfers), `STOU`, `ABOR` during a
transfer (the control connection is not read while one runs), `MODE`s other than stream,
`TYPE E`, and any notion of a current working directory — the handler tracks the cwd in its own
memory or not at all. File contents are text (`send_ftp_data`'s `data` is a string), so a binary
download can carry only what a UTF-8 string can.

### Data-connection bounds

Constants in `data.rs`, each overridable per server:

| Bound | Default | Parameter | Over it |
|---|---|---|---|
| `DATA_CONNECT_TIMEOUT` | 60s (vsftpd's `accept_timeout` / `connect_timeout`) | `data_connect_timeout_secs` | the client did not connect to the passive port, or the server's connect to the `PORT`/`EPRT` address did not complete: `425 Can't open data connection` after the `150` |
| `DATA_IDLE_TIMEOUT` | 300s (vsftpd's `data_connection_timeout`) | `data_idle_timeout_secs` | one read or write on an open data connection made no progress: `426 Connection closed; transfer aborted`. Writes go in 64 KiB chunks, so this bounds a stall rather than the length of a transfer |
| `MAX_UPLOAD_BYTES` | 1 MiB | `max_upload_bytes` | more bytes than this crossed the data connection: `552 Requested file action aborted: exceeded storage allocation`, and the handler is never asked. The whole upload goes into one event, so this bounds what an event can carry into a prompt |

The control connection's read deadlines (below) wrap only the read of a command line, so a long
transfer is never cut off by them.

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
work: an injected `send_ftp_response` / `send_ftp_multiline` is encoded by the same
`execute_action` the handlers use and written to the control connection; `close_connection`
half-closes it. `send_ftp_data` / `send_ftp_list` return the `ftp_transfer` `Custom` result,
which only a transfer in progress can carry to a data connection, so injecting one writes
nothing and the injection reports it. Every read line, every write and every data-connection
byte goes through `update_connection_stats`, so the rail's `↓ ↑` counters and `last_activity`
are live.
Proven with zero LLM calls in `tests/server/ftp/peer_injection_test.rs`.

The accept-loop `JoinHandle` is registered with `AppState::register_server_task()`, so
`stop_server` aborts it and releases port 21. `spawn_with_llm_actions` propagates bind failure
with `?`, so a port clash is reported as `Error` and not as a phantom `Running` server.

### Startup parameters

`first_byte_timeout_secs` and `idle_timeout_secs` (the control connection's read deadlines,
"Connection bounds" below) and `max_upload_bytes`, `data_connect_timeout_secs` and
`data_idle_timeout_secs` (the data-connection bounds above). There is no passive port range:
a passive listener takes an OS-assigned port on the configured host. `send_first` is not
declared: the server always sends the greeting event itself, so passing `send_first` would only
earn an "unsupported" warning from `server_startup`.

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
| Model answered with `send_ftp_response` / `_multiline` | those bytes verbatim | INFO `decision=model_answer (reply <code>)` |
| Model answered a transfer with `send_ftp_list` / `send_ftp_data` | `150`, the payload on the data connection, `226` | INFO `decision=model_answer (<n> bytes on the data connection, then 226)` |
| Model answered `close_connection` and nothing else | control connection closed, no reply | INFO `decision=model_reject` |
| Model answered `wait_for_more` and nothing else | nothing — the next command line is read | INFO `decision=model_wait_for_more` |
| Model answered with no usable action at all | `451 Requested action aborted: local error in processing` (the greeting: `421 … (netget: no greeting was produced)` and close) | WARN `decision=model_silent` |
| Executor refused the model's action (bad `code`, CR/LF in `message`, unknown action, a payload outside a transfer) | `451` as above (the greeting: `421` and close) | ERROR `decision=fail_closed_bad_action` naming the action and the reason |
| A download answered with a `1xx`/`2xx` and no payload; an upload answered with no completion reply | `451` | WARN `decision=fail_closed_no_payload` / `fail_closed_no_completion` |
| Backend failed (unreachable, retries exhausted, malformed) | `421 Service not available, closing control connection (netget: request could not be processed)` then close | ERROR `decision=fail_closed_llm_error` with the full error |
| Backend saturated | `421 Service not available, closing control connection (netget: backend at capacity, retry later)` then close | ERROR `decision=fail_closed_llm_overloaded` with the full error |
| Control line over `MAX_COMMAND_LINE` with no newline | `500 Command line too long` then close | WARN `decision=refused_line_too_long` |
| Transfer with no `PASV`/`EPSV`/`PORT`/`EPRT` first | `425 Use PASV, EPSV, PORT or EPRT first`; the handler is not asked | INFO `decision=refused_no_data_connection` |
| Data connection did not open within `data_connect_timeout_secs` | `425 Can't open data connection` after the `150` | WARN `decision=refused_data_connection` |
| Data connection stalled past `data_idle_timeout_secs`, or broke | `426 Connection closed; transfer aborted` | WARN `decision=transfer_aborted` |
| Upload over `max_upload_bytes` | `552 Requested file action aborted: exceeded storage allocation`; the handler is not asked | WARN `decision=refused_upload_too_large` |

421 rather than silence because an FTP client may not send a command until it has read a
greeting, so a silent greeting failure hangs the client until its own timeout. The two
categories are kept apart deliberately: one is retryable and one is not. 451 rather than
silence for a command, because a client reads a 4xx as a failed command and goes on, where
silence leaves it waiting for a reply until its own timeout.

**There is no fail-open here, and that is the property to preserve.** Nothing in `actions.rs`
can synthesise a reply — `execute_action` produces only the packet a named action asked for,
and an unknown action name is an `Err`, not a default. So no failure path can produce a 2xx:
an LLM outage during `USER`/`PASS` yields 421 and a closed connection, never 230, and a
transfer the handler gave nothing to send is 451, never a 226 for an empty file. If you add a
fallback reply to any failure path, it must not be in the 2xx range.

Only `model_reject` and `model_wait_for_more` write nothing, and both are decisions the handler
declared.

## LLM Integration

`call_llm` is used for both the greeting and every command, so script and static handlers run
in-process with **zero** LLM calls (`call_llm` → `try_execute_event_handler`). Only when no
handler matches does the model get invoked, once per command line.

### Event

| Event         | When                                            | Parameters |
|---------------|-------------------------------------------------|------------|
| `ftp_command` | connection accepted, and once per command line the handler answers (not the setup verbs) | `command`, `answer_with`; on transfers `transfer_type`; on uploads `upload_bytes`, `upload_text`, `upload_is_text` |

`command` is the raw line with the trailing CRLF stripped — not upper-cased, not split into
verb and argument. The single sentinel value `CONNECTION_ESTABLISHED` means "TCP connection
accepted, send your 220 greeting"; it is never sent by a client.

`answer_with` is the reply RFC 959 expects for the verb (`actions::answer_with_for_command`:
one 220 greeting, 331 **or** 230 for `USER`, 230/530 for `PASS` and "not the 331 that answered
USER" (without it llama3.1:8b repeated that 331 on 15 replayed seeds in 40, with it on 5), a `257 "<dir>"` for `PWD`, …),
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
| `send_ftp_data`       | the file, **on the data connection**, to answer `RETR` (nothing appended) | `data` |
| `send_ftp_list`       | one CRLF-terminated line per entry, **on the data connection**, to answer `LIST`/`NLST`/`MLSD` | `entries[]` |
| `wait_for_more`       | nothing — read another line first                         | –                 |
| `close_connection`    | nothing — closes the control connection                   | –                 |

`code` is validated: it must be a three-digit RFC 959 code in 100–599. Out-of-range values and a
missing `code` or `message` are errors, not silently substituted defaults — a wrong reply code
is worse than a visible failure.

`message`, each element of `lines`, and each `entries` element are rejected if they contain CR
or LF (`reject_line_breaks`). All three descriptions already promised this and nothing checked
it, which left `send_ftp_response` a response-splitting primitive: a `message` of
`"ok\r\n230 Logged in"` makes the client read a second, forged reply and treat a 331 as a
successful login. On the data connection the same rule keeps one listing entry one line.
`send_ftp_data` is exempt: a file's contents are whatever they are, and nothing is appended.

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
model supplies and nothing else, and an upload is handed to the handler in its event and then
dropped — a handler that wants to serve it back later keeps it in memory itself.

## Testing

`tests/server/ftp/real_client_test.rs` drives python3's stdlib `ftplib` and curl's libcurl
through logins, every listing verb, downloads and uploads in both representation types, passive
(`PASV`, `EPSV`) and active (`PORT`, `EPRT`) data connections and refused downloads; both fail
rather than skip without their client, and the pcap oracle reads ftplib's control connection.
`data_connection_test.rs` holds each data-connection bound from both sides, the setup verbs the
server answers itself, the bounce guard, the 451 fail-closed answers, and that a passive listener
of a server on 127.0.0.1 refuses a connection to the machine's LAN address. The rest of the
directory covers the greeting, login, 421 paths, one reply per command, batching, the read
deadlines and peer injection; `tests/server/ftp/AGENTS.md` lists them. To verify by hand:

```
curl -v ftp://127.0.0.1:2121/            # LIST over EPSV
curl -v --list-only ftp://127.0.0.1:2121/
curl -v -T somefile ftp://127.0.0.1:2121/upload.txt
```

## Example prompt

```
listen on port 2121 via ftp
Reply 220 "NetGet FTP" to CONNECTION_ESTABLISHED
Accept user anonymous with any password (331 then 230)
SYST -> 215 "UNIX Type: L8"
PWD  -> 257 "\"/\" is current directory"
LIST -> send_ftp_list with an ls -l line for readme.txt
RETR readme.txt -> send_ftp_data "Welcome!\n"
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

## Maturity: Beta

Two independent clients complete real sessions in `tests/server/ftp/real_client_test.rs`, and
both tests fail rather than skip when the client is absent: python3's stdlib `ftplib` (login,
`PWD`, `NLST` passive and active, `LIST`, `MLSD` with its facts parsed, `RETR` in TYPE I and
TYPE A and over `PORT`, a refused `RETR`, `STOR` in TYPE A and in TYPE I with a non-UTF-8 file,
`QUIT`) and curl's libcurl FTP (`LIST` and `NLST` over `EPSV`, `RETR` in TYPE I and TYPE A and
over `PASV`, `EPRT` and `PORT`, `SIZE`, `STOR`, `APPE`, a refused `RETR`). The pcap oracle reads
ftplib's control connection through a recording relay. Every data-connection bound has a test
on both sides (`data_connection_test.rs`), and the control connection's bounds have theirs
(`connection_bounds_test.rs`, `test.rs`).

The rating covers the surface listed under "What the server answers itself" — stream mode, file
structure, types A and I, RFC 2428's extended commands. It does not cover FTPS, `REST`, `STOU`,
`ABOR` mid-transfer, or any client that needs them.
