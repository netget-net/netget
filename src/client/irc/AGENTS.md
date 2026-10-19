# IRC Client Implementation

## Overview

The IRC client connects to IRC servers using a custom line-based protocol implementation.

## Library Choices

**NO external IRC library** - Custom implementation using:

- `tokio::net::TcpStream` - Raw TCP connection
- Line-based protocol parsing (CRLF-delimited), read through
  `crate::server::irc::wire::read_irc_line` so the read is bounded
- Manual IRC command construction, validated by the same `wire` module the server uses

**Rationale**: A full-featured IRC client library handles messages automatically, which would
limit LLM control. Hand-rolling gives the LLM direct control over all IRC commands and responses.

**The `irc` crate is a declared dependency of this feature and is used by nothing.** This file
used to say the *server* used it and that only the client was hand-rolled; neither is true -
`grep -rn "^use irc::" src/` finds no hits, both sides are hand-rolled, and the dependency is
pure weight. Both this file and the client's `metadata().implementation` claimed otherwise.

## Architecture

### Connection Flow

1. **TCP Connect** - Connect to IRC server (typically port 6667 or 6697 for TLS)
2. **Registration** - Automatically send `NICK` and `USER` commands
3. **PING/PONG** - The reader task answers PING itself, at once, even during a model call
4. **Message Loop** - The answering loop takes queued lines, parses them, calls the LLM

### IRC Message Format

```
:[source] COMMAND [params] :[trailing]
```

Examples:

```
PING :server.example.com
:nick!user@host PRIVMSG #channel :Hello world
:server 001 nick :Welcome to the IRC Network
```

### Reader task, queue and batching

A registered reader task reads lines (bounded by `MAX_IRC_READ_LINE`), answers `PING` itself and
puts every other line on a bounded queue (`READ_QUEUE_LINES` = `MAX_BATCH_EVENTS`; past it the
reader stops and TCP holds the server back). The answering loop takes one line per model call
with batching off; with batching on (the declared default) it hands every line already waiting
to `call_llm_for_client_batch`, one `irc_message_received` per line, the newest the trigger.
`tests/client/irc/batching_test.rs` drives both against a raw listener that sends during a slow
call, batching off as the control, and checks a PING sent mid-call is answered before the call
ends. Before this, the read loop awaited each call inline: PING waited behind the model, and the
Idle/Processing/Accumulating queue that preceded that could never fill (and cleared itself
unread).

## LLM Integration

### Events

**Connected Event** (`irc_connected`):

- Triggered when registration completes (001 welcome message)
- Contains: `remote_addr`, `nickname`
- LLM decides: Join channels, set modes, etc.

**Message Received Event** (`irc_message_received`):

- Triggered for every IRC message (except PING)
- Contains: `source`, `command`, `target`, `message`, `raw_message`
- LLM decides: Respond with PRIVMSG, join/part channels, change nick

### Actions

**Async Actions** (user-triggered):

- `join_channel` - Join a channel
- `part_channel` - Leave a channel
- `change_nick` - Change nickname
- `disconnect` - Quit the server

**Sync Actions** (response to messages):

- `send_privmsg` - Send message to channel/user
- `send_notice` - Send notice to channel/user
- `send_raw` - Send raw IRC command
- `wait_for_more` - Don't respond yet

### Startup Parameters

- `nickname` - IRC nickname (default: `netget_user`)
- `username` - IRC username (default: `netget`)
- `realname` - IRC real name (default: `NetGet IRC Client`)

## Implementation Details

### Line framing (`crate::server::irc::wire`, shared with the server)

The client and server are behind the same `irc` feature and share one definition of what an IRC
line may be. Two things this buys, both of which were missing:

**The read is bounded.** `AsyncBufReadExt::read_line` grows until it finds a newline, so a
*server* that streams bytes with no `\n` grew this client's buffer until the netget process was
out of memory. Reads go through `wire::read_irc_line`, capped at `MAX_IRC_READ_LINE` = 8704
bytes (RFC 1459's 512 plus IRCv3's 8191 of message tags). Over the cap the client sets
`ClientStatus::Error` and disconnects.

**Model text cannot forge a second command.** This is the highest-stakes direction in the whole
family: what the client writes lands in a channel other humans read, and the text comes from the
model. `PRIVMSG #chan :hi\r\nJOIN #ops` was one message *and* a JOIN, so a model told only to
chat could be steered into `JOIN`, `NICK`, `MODE` or `QUIT` by anything reaching its context -
on a chat protocol, every stranger in the channel. `IrcClientProtocol::execute_action` now runs
`reject_line_breaks` on every trailing parameter (`message`, `command`, `quit_message`) and
`reject_not_a_word` on every word-position one (`channel`, `target`, `new_nick`), and
`execute_irc_action` caps the finished line at RFC 1459's 512 bytes on a `char` boundary.

Validation lives in `execute_action` rather than at the point of writing because that is the one
gate both callers pass through - the LLM path and the injected-command loop each call it before
`apply_action`. That also means a refusal comes back as a `Rejected` outcome the dashboard can
show, rather than as a channel error that reads like the plumbing broke.

The startup parameters get the same treatment: `nickname` and `username` go through
`reject_not_a_word` and `realname` through `reject_line_breaks` before they are interpolated
into the NICK/USER registration, so a CRLF in an operator-supplied nickname cannot forge a
command before the session has even registered.

Tested by `tests/client/irc/framing_test.rs` (zero LLM calls), which injects each hostile field
and then asserts against **NetGet's own IRC server's access log** that no forged command
crossed the wire.

### PING/PONG Handling

PING messages are handled automatically without LLM involvement:

```rust
if let Some(rest) = line.strip_prefix("PING ") {
    write_all(format!("PONG {rest}\r\n").as_bytes()).await?;
    continue;
}
```

This ensures the connection stays alive without requiring LLM responses.

This used to be `line.replace("PING", "PONG")`, which rewrites **every** occurrence, not the
command word. IRC ping tokens are opaque cookies and real ircds do emit ones containing the
letters `PING`; those came back corrupted and the server dropped the link for failing its own
keepalive. Only the first word is a command.

### Dashboard injection (`[ send_privmsg ]`, `[ send_notice ]`, `[ send_raw ]`, `[ disconnect ]`)

`connect_with_llm_actions` registers a command channel
(`client::command_support::register_command_channel`) *before* the read-loop task and therefore
before the `irc_connected` LLM call, which a manual rule can park. Because `read_line` is not
cancellation-safe, commands are drained by a separate `command_loop` task (registered with
`register_client_task`) that shares the write half, not by a `select!` arm. Every IRC verb
yields `ClientActionResult::Custom`, which the generic `handle_stream_client_command` cannot
write, so `command_loop` routes the result through `apply_action` - the one function the LLM
path also uses, so each verb's encoding exists exactly once - then records an `injected_action`
access-log entry and replies with `ClientSendOutcome` (`Sent{bytes}`, `Rejected` on a missing
parameter, `Disconnected`). An injected `disconnect` writes `QUIT`, half-closes, and the read
loop sees EOF; every read-loop exit calls `remove_client_handle` so the rail stops offering
`[ send ]` on a dead client. Test: `tests/client/irc/command_channel_test.rs` (zero LLM calls).

### Message Parsing

The `parse_irc_message` function extracts:

- **Source** - Who sent the message (nick!user@host or server)
- **Command** - IRC command (PRIVMSG, JOIN, 001, etc.)
- **Target** - Channel or user (for PRIVMSG/NOTICE)
- **Message** - The actual message text

### Registration Flow

1. Connect to TCP socket
2. Send `NICK <nickname>`
3. Send `USER <username> 0 * :<realname>`
4. Wait for 001 (welcome) message
5. Fire `irc_connected` event to LLM

### Error Handling

- **Connection errors** - Return error immediately
- **Read errors** - Set client status to Error, disconnect
- **PING timeout** - Server disconnects (handled by server)
- **Nick collision** - the LLM does **not** receive the 433: it arrives before registration
  completes, and pre-001 lines are dropped (see limitation 7)

## Limitations

1. **No TLS** - Currently only plaintext IRC (port 6667)
    - Future: Add TLS support for port 6697 (IRC over TLS)

2. **No SASL** - No SASL authentication support
    - Future: Add SASL PLAIN mechanism for authenticated connections

3. **No DCC** - No Direct Client-to-Client protocol support
    - Rationale: DCC is rarely used, complex to implement

4. **No CTCP** - No Client-to-Client Protocol (VERSION, TIME, etc.)
    - Future: Add basic CTCP response actions

5. **Single Encoding** - Assumes UTF-8, doesn't handle legacy encodings
    - Rationale: Modern IRC servers use UTF-8

6. **No Message Splitting** - a message over RFC 1459's 512-byte line limit is **truncated
   locally** by `wire::cap_line` (on a `char` boundary, logged at WARN) rather than sent whole
   and truncated or dropped by the server. The tail is lost either way; doing it here keeps the
   line well-formed and puts the loss in netget's own log.
    - Future: Auto-split into several PRIVMSGs instead of truncating

7. **Registration only completes on numeric 001** - the `irc_connected` event fires when a line
   containing ` 001 ` arrives, and **every line before that is discarded without reaching the
   model**. A server that answers 433 (nickname in use), 464 (password required) or `ERROR`
   instead therefore leaves the client silently deaf, connected but never registered, until the
   socket closes. Known and not fixed.

## Testing Strategy

See `tests/client/irc/AGENTS.md` for testing details.

## Example Prompts

```
Connect to IRC at irc.libera.chat:6667 with nick testbot, join #test and say hello
```

```
Connect to IRC server localhost:6667, join #bots, respond to any message mentioning 'help'
```

```
Connect to IRC at irc.example.org:6667, join #monitoring and report any errors you see
```

## Future Enhancements

1. **TLS Support** - Use `tokio-rustls` for encrypted connections
2. **SASL Authentication** - Support SASL PLAIN and EXTERNAL
3. **CTCP Responses** - Handle VERSION, PING, TIME requests
4. **Message Splitting** - Auto-split long messages
5. **Channel State Tracking** - Track joined channels, modes, users
6. **Rate Limiting** - Prevent flooding servers with too many commands

## References

- [RFC 1459](https://tools.ietf.org/html/rfc1459) - Original IRC protocol
- [RFC 2812](https://tools.ietf.org/html/rfc2812) - IRC client protocol
- [Modern IRC Specs](https://modern.ircdocs.horse/) - Modern IRC documentation
