# SMTP Protocol Implementation

## Overview

SMTP (Simple Mail Transfer Protocol) server implementing basic RFC 5321 functionality for sending and receiving email
messages.

## Library Choices

- **Manual Implementation** - No external SMTP library used
- Raw TCP handling with tokio for async I/O
- Line-based protocol parsing using `AsyncBufReadExt`
- **TLS Support** - rustls and tokio-rustls for optional SMTPS (implicit TLS)
- **Certificate Generation** - rcgen for self-signed certificates
- Chosen for maximum flexibility and LLM control over protocol behavior

## Architecture Decisions

### Connection Handling

- **Single Event Type**: `SMTP_COMMAND_EVENT` handles all SMTP commands
- Commands are parsed line-by-line from the TCP stream
- Each command except `EHLO`/`HELO` triggers an LLM call for action-based response (see
  "What NetGet answers itself" below)
- Connection ID tracked for multi-connection support

### LLM Integration

- **Action-based responses** - LLM returns JSON actions for all protocol interactions
- **Greeting on connect** - Special `CONNECTION_ESTABLISHED` command triggers initial 220 greeting
- **One bit of state** - whether the session is inside `DATA` (a `354` has gone out and the
  terminating `.` has not arrived). Everything else about the transaction (MAIL FROM, RCPT TO)
  is the model's to track
- **DATA is not accumulated** - after `send_smtp_start_data` every body line arrives as its own
  `smtp_command` event, terminated by a line containing only `.`. That is one model call per
  line of the message. Use a script or static event handler for anything that receives real
  mail; the LLM path is only practical for short messages.
- **Protocol-aware actions** - Dedicated actions for SMTP responses (greeting, OK, error, etc.)

### Error Handling

A failed handler call is answered with a 4xx, never with silence and never with a 2xx. SMTP
already has the vocabulary for "the backend is unavailable, come back later" (RFC 5321 §4.2.1),
and a sending MTA that gets one requeues the message instead of bouncing it:

| Failure | Reply | Then |
|---|---|---|
| greeting (`CONNECTION_ESTABLISHED`) | `421 4.3.0` (`4.3.2` on overload) | session closes, per RFC 5321 §3.1 |
| any later command | `451 4.3.0` (`4.3.2` on overload) | session stays open |
| model answered a command with **no actions** | `451 4.3.0` | session stays open |
| line over `MAX_LINE_BYTES` | `500 5.5.2` | session closes |
| idle past `READ_TIMEOUT` | `421 4.4.2` | session closes |

**An empty answer is a failure, not silence.** The `Ok` arm used to iterate zero results and
loop straight back to the read, leaving the peer blocked until its own timeout — the same
defect the 451 exists to remove, reached through the success path instead of the error path.
SMTP is not one of the deliberately-silent protocols: every command owes a reply, and
`wait_for_more` is already the way for the model to decline one (and is what `DATA` body lines
use). So an empty answer gets the 451 and `wait_for_more` does not, and the log records
`decision=model_silent` so the two are distinguishable afterwards.

**A refused greeting is honoured.** `close_connection` is advertised on `smtp_command`, and
the greeting *is* an `smtp_command` event, so refusing the connection is an answer the model is
explicitly offered. `send_greeting` used to match only `ActionResult::Output`, dropping the
refusal and carrying on into the command loop on a connection the model had declined — a denial
that did not deny. It now returns `Ok(false)` and the session closes, logged
`decision=model_reject`. That is deliberately *not* an `Err`: a refusal is not a backend
failure and must not be reported as one.

The enhanced code splits the two cases apart: 4.3.2 ("system not accepting network messages")
is used when `crate::llm::is_overload_error` says the failure was capacity exhaustion, 4.3.0
otherwise. Both are refusals — a failure must never be able to look like acceptance, or an
outage would silently report mail as delivered.

Both are still logged at ERROR on the tracing and status channels. Covered by
`tests/server/smtp/llm_failure_test.rs`.

### Session Management

- No persistent session state beyond connection tracking
- SMTP transaction state (MAIL FROM → RCPT TO → DATA) determined by LLM logic
- Each command is stateless from NetGet's perspective

### Response Actions

The LLM controls SMTP responses through these actions:

- `send_smtp_greeting` - 220 greeting banner
- `send_smtp_ok` - 250 OK responses
- `send_smtp_start_data` - 354 start data input
- `send_smtp_error` - 4xx/5xx error responses
- `send_smtp_quit` - 221 closing connection
- `send_smtp_message` - Custom SMTP response
- `wait_for_more` - Send nothing and read the next line (used during DATA, where SMTP expects
  no per-line reply)
- `close_connection` - Terminate session

## What NetGet answers itself, and what the model is told

The real-model eval (`./run-eval.sh smtp`, llama3.1:8b, seed 42) scored all three SMTP cases
0/5 on its first run. Reading the runs showed one failure class, not three: the model reused
the greeting action for every command. `EHLO` and `MAIL` were answered `220 localhost ESMTP
Service Ready`, a greeting was answered with five greetings, and the banner the instruction
named was replaced by the action example's `mail.example.com ESMTP Service Ready`.

**`EHLO` and `HELO` are answered by NetGet** (`ehlo_reply` in `mod.rs`), never by the model.
The reply has exactly one correct form - the greeting's hostname and the extensions this
server implements - and both are facts about NetGet, not decisions: `250-<host> greets
<client>` then `250 8BITMIME` (`EHLO_EXTENSIONS`), or `250 <host> greets <client>` for
`HELO`, or `501` when the argument is missing. `8BITMIME` is the only extension because it is
the only one this server honours (the reader is 8-bit clean). An extension list the model
chose could advertise `STARTTLS` or `AUTH` - the `send_smtp_ehlo` example this replaced listed
`STARTTLS` - and a real MTA would then try it and fail. The weighed alternative was a per-request hint naming `send_smtp_ehlo`; it would still
leave the model choosing the extension list, which is the one thing it must not choose, so the
action is gone from the vocabulary rather than hinted at. The cost is that an event handler
can no longer see `EHLO`; nothing in the tree relied on that, and the one startup example that
answered it has been rewritten. Logged `decision=netget_answer`.

**Every other command carries `answer_with`** (`smtp_command_event_data`): the action and reply
code for that one line - `send_smtp_greeting` for `CONNECTION_ESTABLISHED`, `send_smtp_ok (250)`
or `send_smtp_error with code 550` for `MAIL FROM`/`RCPT TO`, `send_smtp_start_data (354)` for
`DATA`, `send_smtp_quit` then `close_connection` for `QUIT`, `wait_for_more` for a body line and
`send_smtp_ok`/`send_smtp_error` for the terminating `.`. `MAIL FROM`/`RCPT TO` also carry the
`address` and its `domain`, because "refuse any other domain" is a decision about the domain.
A command whose verb says nothing (`VRFY`, an unknown verb) carries no hint.

**One command, one reply.** SMTP here has no pipelining, so a second reply is read by the
client as the answer to its *next* command and every reply after it is one step late. One
`Output` of a batch is written - on the greeting as on every command - and the rest are logged
`decision=duplicate_response_dropped`. The one written is the reply of the action the line's
`answer_with` names when the batch has it (`smtp_preferred_actions`: the greeting, `354` for
`DATA`, `221` for `QUIT`, `send_smtp_ok`/`send_smtp_error` for `MAIL`, `RCPT` and the
terminating `.`), else the first: a model that acknowledges and *then* answers is
answering with the second (`ExecutionResult::chosen_reply`, `src/llm/actions/executor.rs`).

**Batching (on by default).** Commands a client pipelines while the model is answering an
earlier one are answered in one model call (`call_llm_batch`), and still one reply each, in
order. Only `MAIL`, `RCPT` and `RSET` start or continue a batch; `DATA`, `QUIT`, `NOOP`,
`VRFY`, `EXPN` and `HELP` end one (RFC 2920 §3.1), so a 354 is only ever the last reply and a
message body is never batched. `EHLO`/`HELO`, `AUTH`, `STARTTLS` and unknown verbs are always
answered alone. Lines join only when already buffered (`command_batch::peek_ready_line`), and
only when one model call would answer them all (`command_batch::one_model_call_answers` — a
script, static or manual rule answers each command alone, because a fallen-back batch's
concatenated replies could not be told apart). `SmtpSession::answer_batch` writes the answer
only when it holds exactly one reply per command and a 354 only for `DATA`; otherwise every
pipelined command gets `451 4.3.0` (`decision=fail_closed_batch_mismatch`), which keeps the
client in step and accepts nothing. The EHLO reply still does not advertise `PIPELINING`, so
batching applies to clients that pipeline anyway. `tests/server/smtp/batching_test.rs` holds
the control (off: one call per command), the claim (on: one call, same replies, same order)
and the fail-closed short answer.

**Inside `DATA`** a line is message text whatever it looks like: `EHLO` in a body is not
answered by NetGet, and its event says `wait_for_more`. The state flips on when a reply
beginning `354` is written and off at the `.` line.

The greeting action's example is now `mx.example.invalid` / `ESMTP`: copied when the
instruction names no banner it is a harmless default, and it no longer looks like a plausible
answer to "greet with the banner X".

`tests/server/smtp/answer_with_test.rs` pins all four from the wire; each guard was verified
by removing it and watching the test fail.

## Connection Management

- Connections tracked in `AppState` (bytes sent/received, packet counts): `handle_session`
  calls `add_connection_to_server` and `update_connection_stats` on every read and write, so
  the dashboard's `↓ ↑` counters and `last_activity` are live
- Each connection spawns independent async task
- Write operations go through a shared `Arc<Mutex<WriteHalf>>` (reader task and peer command
  task share it); the guard is dropped before any LLM call
- Read operations use `BufReader` for line-based parsing

### Dashboard injection (`[ message this peer ]` / `[ disconnect this peer ]`)

Every connection registers a peer handle (`server::peer_support`) right after it is tracked and
*before* the greeting event, so a manual `*` rule parking the greeting still leaves the operator
able to reach the connection. `AppState::send_to_peer` runs the action through the same executor
as the LLM path; every wire verb here returns `ActionResult::Output` and `close_connection`
half-closes, so there is no `Custom` gap. The handle is removed on every exit path (EOF, read
error, `close_connection`, refused 421 greeting) through the single cleanup in `handle_session`,
which wraps `run_session`. Test: `tests/server/smtp/peer_inject_test.rs` (zero LLM calls).

## State Management

- **No protocol-specific state** - SMTP doesn't use `ProtocolConnectionInfo::Smtp`
- Connection lifecycle managed by tokio tasks
- Session state implicit in LLM conversation context

## TLS Support (SMTPS)

- **Implicit TLS** - SMTPS on port 465 (connection starts with TLS handshake)
- **Configurable** - Enable via `enable_tls: true` in open_server action options
- **Fails closed** - if the certificate cannot be generated, `spawn` returns an error. It used
  to log and fall back to plain text, handing a caller who asked for SMTPS a cleartext mail
  port that reported itself as Running.
- **Self-signed certificates** - Auto-generated using rcgen
- **Customizable certificates** - LLM can specify CN, SAN, validity, organization
- **Backward compatible** - TLS is optional, defaults to plain SMTP

### Enabling SMTPS

Use the `open_server` action with TLS options:

```json
{
  "type": "open_server",
  "protocol": "smtp",
  "port": 465,
  "options": {
    "enable_tls": true,
    "tls_common_name": "mail.example.com",
    "tls_san_dns_names": ["mail.example.com", "localhost"],
    "tls_validity_days": 365
  }
}
```

## Limitations

- **No STARTTLS support** - Only implicit TLS (SMTPS) is supported, not STARTTLS upgrade
- **No SMTP AUTH** - Authentication not implemented
- **No message persistence** - Messages logged but not stored; NetGet is not an MTA and never
  delivers or relays anything
- **Privileged default port** - `metadata()` declares `PrivilegedPort(25)`, so `server_startup`
  preflights the bind against `SystemCapabilities` instead of failing with a bare EPERM
- **No PIPELINING advertised** - pipelined commands are read in order and, with batching on,
  answered together (see "Batching" above)
- **No size validation** - MESSAGE_SIZE limits not enforced. A *line* is bounded
  (`MAX_LINE_BYTES`, 64 KiB) and an idle session is bounded (`READ_TIMEOUT`, 300s, RFC 5321
  §4.5.3.2), but nothing caps the total size of a message across lines
- **No relay control** - Accepts all MAIL FROM/RCPT TO

### Reading is bounded, and 8-bit clean

`read_line_bounded` replaces `BufReader::read_line`, which was wrong in two ways that only
show up under a hostile or merely non-English peer:

- It grew its `String` until it found a `\n`, so a peer that connected and streamed bytes
  without one allocated until the process died — one unauthenticated socket. Now capped at
  `MAX_LINE_BYTES`, answered `500 5.5.2 Line too long`, then closed (we stopped reading
  mid-line, so the remainder would otherwise be parsed as fresh commands).
- It required valid UTF-8 and returned `InvalidData` otherwise, which killed the session with
  **no reply at all** — while the default EHLO advertises `8BITMIME`, promising exactly the
  octets that killed it. One Latin-1 byte in a body was enough. The reader now decodes lossily;
  these bytes only ever become the model's event payload and a log line, and nothing here is
  re-emitted on the wire, so nothing a peer can observe is lost.

An idle connection now gets `421 4.4.2` and a close rather than holding a task forever.

## Examples

### Example LLM Prompt (Plain SMTP)

```
listen on port 25 via smtp. Send greeting '220 mail.example.com ESMTP'.
Accept all MAIL FROM and RCPT TO commands with '250 OK'.
For DATA, respond with '354 Start mail input' then '250 Message accepted'.
```

### Example LLM Prompt (SMTPS with TLS)

```
listen on port 465 via smtp with TLS enabled. Send greeting '220 secure.mail.example.com ESMTPS'.
Accept all MAIL FROM and RCPT TO commands with '250 OK'.
For DATA, respond with '354 Start mail input' then '250 Message accepted'.
```

### Example LLM Response (Greeting)

```json
{
  "actions": [
    {
      "type": "send_smtp_greeting",
      "hostname": "mail.example.com",
      "message": "ESMTP Service Ready"
    }
  ]
}
```

### Example LLM Response (Error)

```json
{
  "actions": [
    {
      "type": "send_smtp_error",
      "code": 550,
      "message": "Mailbox unavailable"
    }
  ]
}
```

## References

- RFC 5321 - Simple Mail Transfer Protocol
- RFC 5322 - Internet Message Format
- tokio documentation: https://docs.rs/tokio
