# POP3 Client Implementation

## Overview

The POP3 client allows LLM-controlled email retrieval from POP3 servers. It speaks **plain
POP3 only** (port 110). There is no TLS: `use_tls: true` is refused at connect, see below.

## Library Choice

**Custom Implementation**

- No external POP3 library used (considered rust-pop3-client but opted for custom)
- Direct TCP/TLS connection using tokio
- Line-based protocol parsing with `BufReader`
- TLS support via rustls and tokio-rustls
- Full control over protocol behavior for LLM integration

## Architecture

### Connection Model

POP3 is a **request-response protocol** similar to SMTP:

- Connection established when client is opened
- Persistent connection with command/response cycle
- Read loop processes server responses
- LLM decides which commands to send
- Connection closed with QUIT command

### State Management

Client state tracked in `ClientInstance`:

- `pop3_server`: Server hostname
- `remote_addr`: Full server address with port
- Responses framed on a registered task into a bounded queue (see "Batching")

### TLS Support — there is none, and `use_tls: true` is refused

- **Plain POP3**: Port 110, no encryption. This is the only mode that exists.
- **POP3S**: **Not implemented.** Nothing in `src/client/pop3/` performs a TLS handshake;
  the session runs on a bare `tokio::net::TcpStream`.
- **`use_tls`**: declared, and `connect_with_llm_actions` returns an `Err` naming the reason
  when it is `true`. It is refused rather than ignored because a POP3 session's next move is
  `USER`/`PASS`: silently continuing would put the password on the wire in cleartext while
  the parameter list claimed the session was encrypted. `imap` has the identical defect and
  takes the identical exit. `use_tls: false` is valid and means what it says.
- To reach a POP3S server, terminate TLS in front of it (stunnel, a sidecar) and point the
  client at the plaintext side.

### LLM Integration

#### Events

1. **`pop3_connected`** - Triggered when client connects and receives greeting
    - Parameters: `pop3_server` (hostname), `greeting` (server banner), `is_ok` (boolean)
    - LLM decides: Authenticate with USER/PASS, or quit

2. **`pop3_response_received`** - Triggered after server responds to command
    - Parameters: `response` (full response including multiline), `is_ok` (true for +OK, false for -ERR)
    - LLM decides: Next command (STAT, LIST, RETR, DELE, QUIT)

#### Actions

**Async Actions** (user-triggered):

- `disconnect` - Close POP3 connection
    - Sends QUIT command before closing

  `modify_pop3_instruction` used to be listed here. It was never runnable — `execute_action`
  rejected the name and clients read their `instruction` once at connect — so it was removed
  rather than left as a tool the model is punished for using.

**Sync Actions** (LLM response to events):

- `send_pop3_command` - Send POP3 command to server
    - Parameters: `command` (e.g., "USER alice", "PASS secret", "STAT", "LIST", "RETR 1")

- `disconnect` - Close connection (same as async)

- `wait_for_more` - Wait for more server responses

### POP3 Command Flow

```
1. Client connects → pop3_connected event with greeting
2. LLM sends: send_pop3_command("USER alice")
3. Server responds: +OK or -ERR
4. pop3_response_received event
5. LLM sends: send_pop3_command("PASS secret")
6. Server responds: +OK or -ERR
7. pop3_response_received event
8. LLM sends: send_pop3_command("STAT")
9. Server responds: +OK 3 1024
10. pop3_response_received event
11. LLM sends: send_pop3_command("RETR 1")
12. Server responds: +OK\r\n<email content>\r\n.\r\n
13. pop3_response_received event with full email
14. LLM sends: disconnect (sends QUIT)
```

## POP3 Protocol

### Common Commands

- `USER username` - Specify username
- `PASS password` - Provide password
- `STAT` - Get mailbox status (message count, total size)
- `LIST [msg]` - List message sizes (multiline response)
- `RETR msg` - Retrieve message content (multiline response)
- `DELE msg` - Mark message for deletion
- `TOP msg n` - Get message headers and n body lines (multiline response)
- `UIDL [msg]` - Get unique message IDs (multiline response)
- `NOOP` - No operation (keep-alive)
- `RSET` - Reset session (undelete marked messages)
- `QUIT` - Close connection

### Response Format

- **Success**: `+OK [message]`
- **Error**: `-ERR [message]`
- **Multiline**: `+OK\r\nline1\r\nline2\r\n.\r\n` (terminated with single dot)

### Multiline Handling

The client automatically detects and reads multiline responses:

- Checks if response starts with `+OK`
- Reads lines until a single `.` is encountered
- Returns full multiline response to LLM as a single string

## Implementation Details

### Startup

```rust
Pop3Client::connect_with_llm_actions(
    remote_addr,      // e.g., "pop.example.com:110" or "pop.example.com:995"
    llm_client,
    app_state,
    status_tx,
    client_id,
)
```

- Checks `use_tls`; `true` returns an `Err` and no connection is made
- Connects to the server in plaintext
- Reads greeting from server
- Calls LLM with `pop3_connected` event
- Spawns read loop for responses

### Connection Types

**Plain POP3** (`use_tls: false`, or unset) — the only one:
- Direct TCP connection
- No encryption
- Port 110 (default)

**POP3S** (`use_tls: true`) — refused at connect with an error; see TLS Support above.

### Dashboard injection (`[ send_pop3_command ]`, `[ disconnect ]`)

`connect_plain` registers a command channel (`client::command_support::register_command_channel`)
*before* the read-loop task and therefore before the `pop3_connected` LLM call, which a manual
rule can park. Because `read_line` is not cancellation-safe, commands are drained by a separate
`command_loop` task (registered with `register_client_task`) that shares the write half, not by
a `select!` arm. `send_pop3_command` yields `ClientActionResult::Custom`, which the generic
`handle_stream_client_command` cannot write, so `command_loop` routes the result through
`apply_action` — the one function the LLM path also uses to encode commands — then records an
`injected_action` access-log entry and replies with `ClientSendOutcome`. An injected
`disconnect` writes `QUIT`, half-closes, and the read loop sees EOF. Test:
`tests/client/pop3/command_channel_test.rs` (zero LLM calls).

### Read Loop

- Responses framed on a registered task into a bounded queue (see "Batching")
- Reads line-by-line from server
- Detects multiline responses (LIST, RETR, TOP, UIDL)
- Calls LLM with each response
- Executes LLM-returned actions

## Limitations

1. **No APOP**: Challenge-response authentication not supported
2. **No TLS of any kind**: neither implicit POP3S nor STARTTLS/STLS
3. **Command-aware multiline replies**: RETR/TOP/CAPA and argumentless LIST/UIDL use dot termination
4. **Ordered command expectations**: pipelined commands have FIFO reply framing expectations
5. **No SASL**: Extended authentication not supported

## Example Prompts

```
"Connect to localhost:110 and authenticate as user 'alice' password 'secret', then list all messages"

"Connect to localhost:110, login, retrieve message 1, then delete it"

(A `:995` POP3S endpoint cannot be reached directly — see TLS Support.)
```

## Testing Strategy

See `tests/client/pop3/AGENTS.md` for:

- E2E test approach
- Local POP3 server setup (NetGet POP3 server, Dovecot, or similar)
- LLM call budget
- Expected runtime

## Future Enhancements

1. **APOP support**: MD5 challenge-response authentication
2. **TLS**: implicit POP3S and/or STLS upgrade — neither exists today
4. **Certificate validation control**: Option to accept self-signed certs
5. **Connection pooling**: Reuse connections for multiple sessions
6. **Asynchronous DELE**: Queue deletions and apply on QUIT
7. **TOP command optimization**: Efficient header-only retrieval
8. **UIDL tracking**: Remember seen messages across sessions

## References

- RFC 1939 - Post Office Protocol - Version 3
- RFC 2449 - POP3 Extension Mechanism
- RFC 2595 - Using TLS with IMAP, POP3 and ACAP

## Bounded response reading (October 2026 review)

Response lines now use `client::response_reader::read_response_line`, sharing the
existing bounded line decoder. The 64 KiB cap includes the line terminator; a partial
line at EOF is an error. Oversized or incomplete replies are not forwarded as successful
responses.
Dot-terminated responses additionally have an 8 MiB aggregate cap, require an exact
`.` terminator and undo dot stuffing. A peer closing before that terminator is a
framing failure, avoiding POP3's former EOF loop and NNTP's partial-success result.
Read-loop exits now always clear the command handle and update client status. The
reply framing follows a FIFO of command expectations, recorded under the same mutex as writes.
A negative status consumes its expectation without trying to read a multiline body.
Pure decoder tests are in `tests/client_review_regression_test.rs::text_responses`.

## Atomic command framing (October 2026 follow-up)

`CommandWriter` is shared by both injected and event-generated commands. USER/PASS replies
stay single-line regardless of status wording; LIST/UIDL with a message argument stay single-line,
while their argumentless variants, RETR, TOP and CAPA consume exact dot-terminated bodies.
CR/LF injection is rejected. A cancelled/failed write poisons the writer so future commands
cannot reuse ambiguous framing. Outstanding expectations are capped at 1024. Whole writes,
greetings and multiline bodies have 30-second deadlines; an idle established session may wait
for the first byte, after which each partial response line has a 30-second completion deadline.

## Batching (what arrives while the model is answering)

A POP3 server only answers, but a model often sends several commands in one answer (`USER`
then `PASS`, `LIST` then `RETR`), and the replies to the later ones arrive while it is still
on the first. Responses are framed (status line, dot-terminated body where the command calls
for one, decided by the shared `CommandWriter`) on a registered task into a bounded queue
(32). With batching off each response is its own model call; with it on everything waiting is
one call through `call_llm_for_client_batch`, one `pop3_response_received` event per
response. Declared `BatchingMode::On`. Test: `tests/client/pop3/batching_test.rs`.
