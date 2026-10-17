# IRC Protocol Implementation

## Overview

IRC (Internet Relay Chat) server implementing core IRC protocol for real-time text-based communication. The LLM controls
IRC responses, handles protocol commands (NICK, USER, JOIN, PRIVMSG, PING, etc.), and manages chat server logic.

**Status**: Experimental (see `metadata()` in `actions.rs` - that is the authoritative value)
**RFC**: RFC 1459 (Internet Relay Chat Protocol), RFC 2812 (IRC Client Protocol)
**Port**: 6667 (plain TCP), 6697 (with TLS, not implemented)

## Library Choices

- **No IRC library** - Manual protocol implementation
    - IRC is line-based text protocol (simple parsing)
    - Commands parsed from text lines
    - Responses constructed as formatted strings
    - No complex binary protocol
- **tokio** - Async runtime and I/O
    - `TcpListener` for accepting connections
    - `BufReader`, read through `wire::read_irc_line` rather than `read_line` (see below)
    - `AsyncWriteExt` for sending responses

**Rationale**: IRC protocol is simple enough that no dedicated library is needed. Messages are text lines ending with
`\r\n`, commands are space-separated tokens. Manual implementation gives LLM full control and avoids library
constraints.

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM receives raw IRC messages and responds with structured actions:

- `send_irc_message` - Send raw IRC message
- `send_irc_welcome` - Send 001 RPL_WELCOME numeric
- `send_irc_pong` - Respond to PING with PONG
- `send_irc_join` - Send JOIN confirmation
- `send_irc_part` - Send PART confirmation
- `send_irc_privmsg` - Send PRIVMSG (chat message)
- `send_irc_notice` - Send NOTICE (notification)
- `send_irc_numeric` - Send numeric response (e.g., 332 for topic)
- `wait_for_more` - Buffer more data before responding
- `close_connection` - Close client connection

### 2. Line-Based Message Processing

IRC message flow:

1. Accept TCP connection
2. Read one line with `wire::read_irc_line`, **bounded** at `MAX_IRC_READ_LINE` (8704 bytes)
3. Parse IRC command from line (e.g., "NICK alice\r\n")
4. Send line to LLM as `irc_message_received` event
5. LLM returns actions (e.g., `send_irc_welcome`)
6. Execute actions (send responses)
7. Loop for next line

### 3. Line framing is enforced, not assumed (`src/server/irc/wire.rs`)

IRC is line-oriented in both directions, and both directions are attacker-influenced: the peer
chooses what it sends, and the **model** chooses the text we relay to other humans in a channel.
`wire.rs` is the one place that decides what a line may be, and the IRC *client* shares it.

**Inbound: the read is bounded.** `AsyncBufReadExt::read_line` grows its buffer until it finds a
newline, so a peer that connects and streams bytes with no `\n` is a one-connection
out-of-memory - unauthenticated, since IRC has no authentication before NICK/USER. The read now
goes through `wire::read_irc_line`, capped at `MAX_IRC_READ_LINE` = 8704 bytes (RFC 1459's 512
plus IRCv3's 8191 bytes of message tags, so nothing real is refused). A peer that exceeds it
gets `ERROR :Closing link: message exceeds 8704 bytes` and the link is closed - there is no
resynchronisation point once the prefix has been thrown away.

**Outbound: model text cannot forge a second message.** Every `send_irc_*` action interpolates
model-supplied strings into a CRLF-terminated line, so a `message` containing `\r\n` did not
produce a longer message - it produced *two*, the second attributed to this server. This is the
same defect as FTP's reply splitting (`src/server/ftp/actions.rs`), and it is worse here because
the payload is chat. Three rules now apply, all in `wire.rs` and all erroring rather than
silently rewriting (a handler that meant two messages should emit two actions):

- `reject_line_breaks` - no CR, LF or NUL in any interpolated field. RFC 1459 §2.3.1 forbids all
  three in a message.
- `reject_not_a_word` - fields that land in *word* position (`nickname`, `channel`, `target`,
  `source`, `server`, `user`, `host`) additionally reject spaces, a leading `:` and emptiness,
  each of which shifts every parameter after it. Trailing parameters (a message body, a PART
  reason) get `reject_line_breaks` only, because spaces are exactly what belongs there.
- `cap_line` - the finished line is truncated to RFC 1459's 512 bytes including CRLF, on a
  `char` boundary, with a WARN naming the action. Truncation rather than refusal, because that
  is what a real ircd does and because dropping a chat message entirely is the worse answer.

`send_irc_numeric` additionally rejects a code outside 1..=999: `{:03}` pads a smaller number
but widens a larger one, and a four-digit "numeric" is read by the client as the start of the
next parameter.

Sent messages still get their `\r\n` added automatically; what changed is that the text may no
longer contain one of its own.

Tested by `tests/server/irc/framing_test.rs` (zero LLM calls), which asserts each refusal, the
512-byte cut on multi-byte text, and - on a real socket - that 64 KiB with no newline is cut off
with `ERROR` rather than buffered.

### 4. No Server-Side State

`IrcProtocol` is a unit struct. It previously carried an `IrcClientState` map (nickname,
username, realname, channels) with insert/update/lookup helpers, but nothing ever called any of
them - no nickname was recorded and no channel was joined - so it was removed. Protocols do not
keep protocol state in Rust; the model tracks nicknames and channel membership through its
instruction and server memory.

### 4a. Log Previews Must Be Char-Safe

Both message previews in `mod.rs` go through `crate::utils::truncate_for_log`. They used to be
`&line[..100]`, which panics whenever byte 100 of an IRC line falls inside a multi-byte
character - i.e. on ordinary non-ASCII chat text. A panic in a connection task is silent and
leaves the server reporting `Running`.

### 5. Dual Logging

- **DEBUG**: Message summary with 100-char preview ("IRC received 15 bytes: NICK alice")
- **TRACE**: Full text message ("IRC data (text): \"NICK alice\\r\\n\"")
- Both go to netget.log and TUI Status panel

### 6. Connection Management

Each IRC client gets:

- Unique `ConnectionId`
- Entry in `ServerInstance.connections` with `ProtocolConnectionInfo::empty()` (IRC stores no
  protocol-specific connection info)
- Tracked bytes sent/received, packets sent/received
- State: Active until client disconnects or LLM closes

## LLM Integration

### Event Type

**`irc_message_received`** - Triggered when IRC client sends a message. This is the only event
IRC emits, and its `.with_actions(...)` list is what `call_llm` offers the model - it carries
the full action set below.

Event parameters:

- `message` (string) - The IRC message line received, **CRLF stripped** (`line.trim()`)

### Available Actions

#### `send_irc_message`

Send raw IRC message (for custom responses).

Parameters:

- `message` (required) - IRC message to send (auto-adds `\r\n` if missing)

Example:

```json
{
  "type": "send_irc_message",
  "message": ":server NOTICE * :Looking up your hostname"
}
```

#### `send_irc_welcome`

Send IRC welcome message (numeric 001 - RPL_WELCOME).

Parameters:

- `nickname` (required) - Client nickname
- `server` (optional) - Server name (default: "irc.server")
- `message` (optional) - Welcome message (default: "Welcome to the IRC Network")

Example:

```json
{
  "type": "send_irc_welcome",
  "nickname": "alice",
  "server": "irc.example.com",
  "message": "Welcome to the IRC Network, alice!"
}
```

Sends: `:irc.example.com 001 alice :Welcome to the IRC Network, alice!\r\n`

#### `send_irc_pong`

Send IRC PONG response to PING.

Parameters:

- `token` (required) - Token from PING command

Example:

```json
{
  "type": "send_irc_pong",
  "token": "1234567890"
}
```

Sends: `PONG :1234567890\r\n`

#### `send_irc_join`

Send IRC JOIN confirmation.

Parameters:

- `nickname` (required) - Client nickname
- `channel` (required) - Channel name (e.g., "#general")
- `user` (optional) - Username (default: "user")
- `host` (optional) - Hostname (default: "localhost")

Example:

```json
{
  "type": "send_irc_join",
  "nickname": "alice",
  "channel": "#general"
}
```

Sends: `:alice!user@localhost JOIN #general\r\n`

#### `send_irc_privmsg`

Send IRC PRIVMSG (chat message).

Parameters:

- `source` (required) - Source (nickname or server)
- `target` (required) - Target (nickname or channel)
- `message` (required) - Message text

Example:

```json
{
  "type": "send_irc_privmsg",
  "source": "bot",
  "target": "alice",
  "message": "Hello, alice!"
}
```

Sends: `:bot PRIVMSG alice :Hello, alice!\r\n`

#### `send_irc_numeric`

Send IRC numeric response (e.g., 332 for topic, 353 for names).

Parameters:

- `code` (required) - Numeric code (e.g., 332, 353, 366)
- `target` (required) - Target nickname
- `message` (required) - Message text
- `server` (optional) - Server name (default: "irc.server")

Example:

```json
{
  "type": "send_irc_numeric",
  "code": 332,
  "target": "alice",
  "message": "#general Welcome to our channel!"
}
```

Sends: `:irc.server 332 alice :#general Welcome to our channel!\r\n`

See `actions.rs` for complete action list including `send_irc_part`, `send_irc_notice`, etc.

## Connection Management

### Connection Lifecycle

1. **Accept**: TCP listener accepts connection
2. **Register**: Connection added to `ServerInstance` with `ProtocolConnectionInfo::empty()`
3. **Split**: Stream split into ReadHalf and WriteHalf
4. **Track**: WriteHalf stored in `Arc<Mutex<WriteHalf>>` for sending
5. **Read Loop**: Continuous line reading until disconnect
6. **Close**: Connection removed when client closes or LLM sends `close_connection`

### Dashboard injection (`[ message this peer ]` / `[ disconnect this peer ]`)

Every connection registers a peer handle (`server::peer_support`) right after it is tracked
and *before* the first read - IRC does not speak first, so a manual `*` rule parking the
registration exchange still leaves the operator able to reach the connection.
`AppState::send_to_peer` runs the action through the same executor as the LLM path; every wire
verb here returns `ActionResult::Output` and `close_connection` half-closes, so there is no
`Custom` gap. `update_connection_stats` is called on every read line and every write (model
output and the numeric-400 failure reply alike), so the rail's `↓ ↑` counters and
`last_activity` are live. The handle is removed on every exit path (EOF, read error,
`close_connection`, backend-unavailable `ERROR`) through the single cleanup after the read
loop. Test: `tests/server/irc/peer_inject_test.rs` (zero LLM calls).

### State Management

- **No per-connection state machine.** Unlike TCP, IRC does not implement
  Idle/Processing/Accumulating and has no `queued_data`: the read loop awaits each LLM call
  before reading the next line, so lines are handled strictly in order and a slow model applies
  backpressure through TCP rather than being queued.
- **Batching (`BatchingMode::On`).** After a line is read, if the instance batches,
  `lines_already_here` (`mod.rs`) takes every further *complete* line already in the
  `BufReader` or readable without waiting — a zero-deadline `fill_buf`, which consumes nothing
  if it gives up — up to `MAX_BATCH_EVENTS - 1`, and the lot goes to `call_llm_batch` as one
  call with the newest line as trigger. It stops at a partial or over-long line and leaves it
  to the bounded `read_irc_line`. Every line is a model event (PING and registration
  included), so NICK and USER sent together arrive together. The decision line and a failure
  numeric name the trigger line's command. With batching off, one line per call as before.
  Test: `tests/server/irc/batching_test.rs` (off is the control: three calls; on: two).
- Connection stays in ServerInstance until closed
- No startup parameters. `send_first` was declared and then discarded; an IRC server does not
  speak first, so it is no longer declared and passing it now produces a warning.

## Known Limitations

### 1. No Channel State Management

- Server doesn't track which users are in which channels
- No channel topic storage
- No user lists per channel
- LLM must track channel state in conversation context

**Workaround**: LLM can maintain pseudo-state through prompts and memory.

### 2. No User Authentication

- No password checking
- No SASL support
- No NickServ integration
- All users accepted
- **No ident lookup.** A real ircd opens a connection back to the client's port 113 (RFC 1413)
  on accept and prefixes the resulting username with `~` when the lookup fails. NetGet does
  neither: it never contacts the peer's ident service, and the `user` field of a JOIN/PART
  prefix is whatever the model supplies (default `"user"`), not anything verified. NetGet does
  ship an `ident` protocol, but it is a separate server - nothing wires the two together, and a
  client that expects the connect-time ident probe will not see one.

### 3. Limited Numeric Responses

- Only generic `send_irc_numeric` action
- No dedicated actions for common numerics (353 NAMES, 366 ENDOFNAMES, etc.)
- LLM must know numeric codes

**Future Enhancement**: Add dedicated actions for common numerics.

### 4. No Server-to-Server Protocol

- Single-server only
- No IRC network support
- No server linking

### 5. No TLS Support

- Plain TCP only (port 6667)
- No SSL/TLS encryption (port 6697)
- See DoT/DoH for encrypted alternatives

**Workaround**: Use reverse proxy (e.g., nginx) for TLS termination.

### 6. No Operator Commands

- No /OPER command
- No /KILL, /KICK, /BAN commands
- No channel modes (+o, +v, etc.)

### 7. No CTCP Support

- No CTCP ACTION (/me)
- No CTCP VERSION, PING, TIME
- CTCP messages treated as regular PRIVMSG

## Example Prompts

### Basic IRC Server

```
listen on port 6667 via irc
When users send NICK and USER commands, send IRC welcome (001)
When users send PING, respond with PONG
When users send JOIN #channel, confirm with JOIN message
```

### Echo Bot

```
listen on port 6667 via irc
Respond to all PRIVMSG with an echo: "You said: <message>"
Ignore NICK, USER, and PING commands (send appropriate responses)
```

### Channel Server

```
listen on port 6667 via irc
Support channels: #general, #random, #dev
When users JOIN a channel, send JOIN confirmation and channel topic (332)
When users send PRIVMSG to channel, echo to all users (simulate broadcast)
```

### Interactive Bot

```
listen on port 6667 via irc
Act as a helpful chatbot named "NetBot"
Respond to PRIVMSG with relevant information
Support commands: !help, !time, !joke
Send welcome message when users connect
```

## Performance Characteristics

### Latency

- **Per Message (with scripting)**: Sub-millisecond
- **Per Message (without scripting)**: 2-5 seconds (LLM call)
- Line parsing: <1 microsecond
- Message formatting: <1 microsecond

### Throughput

- **With Scripting**: Thousands of messages per second
- **Without Scripting**: ~0.2-0.5 messages per second (LLM-limited)
- Concurrent connections: Unlimited (bounded by system resources)
- Each connection processes independently

### Scripting Compatibility

Good scripting candidate:

- Text-based protocol (easy to parse and generate)
- Repetitive command/response patterns
- State can be maintained in script
- High message volume typical for chat

## IRC Protocol References

### Common Commands

- **NICK** - Set nickname
- **USER** - Set username and realname
- **JOIN** - Join a channel
- **PART** - Leave a channel
- **PRIVMSG** - Send message to user or channel
- **NOTICE** - Send notice (non-reply message)
- **PING** - Keepalive ping
- **PONG** - Keepalive response
- **QUIT** - Disconnect from server

### Common Numerics

- **001** - RPL_WELCOME (welcome message)
- **332** - RPL_TOPIC (channel topic)
- **353** - RPL_NAMREPLY (channel user list)
- **366** - RPL_ENDOFNAMES (end of NAMES list)
- **433** - ERR_NICKNAMEINUSE (nickname in use)

### Message Format

```
:<prefix> <command> <params> :<trailing>
```

Examples:

- `:alice!user@host PRIVMSG #general :Hello everyone`
- `:server 001 alice :Welcome to the IRC Network`
- `PING :1234567890`
- `PONG :1234567890`

## References

- [RFC 1459: Internet Relay Chat Protocol](https://datatracker.ietf.org/doc/html/rfc1459)
- [RFC 2812: Internet Relay Chat: Client Protocol](https://datatracker.ietf.org/doc/html/rfc2812)
- [IRC Numeric List](https://www.alien.net.au/irc/irc2numerics.html)
- [Modern IRC Documentation](https://modern.ircdocs.horse/)

## Failure behaviour

Every terminal outcome of an `irc_message_received` line is logged with a stable `decision=`
token. IRC *does* have a wire vocabulary for failure — numeric 400 (`ERR_UNKNOWNERROR`) and
`ERROR :Closing link` — but only the backend-failure path uses it. A model that answered, a
model that asked to hang up and a model that produced nothing all end with the server going
quietly back to reading, so the log is the only place those three differ.

| Outcome | On the wire | Log |
|---|---|---|
| Model answered with any `send_irc_*` | that line, CRLF-terminated | INFO `decision=model_answer` |
| Model answered `close_connection` only | nothing, then the link is closed | INFO `decision=model_reject` |
| Model answered with no usable action | **nothing** | WARN `decision=model_silent` |
| Model answered but every action failed | **nothing** | ERROR `decision=fail_closed_bad_action` |
| Backend failed / retries exhausted | `:netget 400 * <CMD> :netget: request could not be processed` then `ERROR :Closing link` and a close | ERROR `decision=fail_closed_llm_error` |
| Backend saturated | `:netget 400 * <CMD> :netget: backend at capacity, retry later`, link kept | ERROR `decision=fail_closed_llm_overloaded` |
| Line over `MAX_IRC_READ_LINE` with no newline | `ERROR :Closing link: message exceeds …` and a close | ERROR `decision=refused_body_too_large` |

**No fail-open in the registration path.** Numeric 001 (`RPL_WELCOME`) exists only as the
`send_irc_welcome` action, so nothing in `mod.rs` can synthesise a completed registration; on
every failure path above the client either gets a 400 or gets nothing, never a 001. The
numeric's trailing parameter is a `WireFailure` category, never the error — that matters more
here than in most protocols, because a real IRC client prints a numeric's trailing parameter
verbatim to a human.

**`model_silent` writes nothing at all**, and that is worth knowing though it is not a
fail-open. A client that sent NICK/USER and got no answer waits out its own connection
timeout. This is not a fabricated success, but it is not a reply either; fixing it means
answering 400 on that path too, which is a wire change the tagging pass deliberately did not
make.

**`close_connection` now actually closes the connection.** It did not for a long time: in the
LLM path `ActionResult::CloseConnection => { … break; }` breaks the `for` over
`protocol_results`, not the read loop, so the link survived and the server read the next line
while logging a hang-up. The `for`-level `break` is still correct — it stops executing further
actions — so the fix is a second `break` after the decision line, guarded by the same
`asked_to_close` flag the log reads. Placing it after the log rather than inside the `for`
arm is deliberate: a refusal is recorded before the link goes. Dashboard-injected
`close_connection` goes through `peer_support` and always did half-close, which is why this
went unnoticed.

Tested by `tests/server/irc/decision_tag_test.rs`.

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever. It now
declares both halves; the constants and the reasoning live beside them in
`src/server/irc/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_MESSAGE_READ_TIMEOUT` | 60s | IRC is client-speaks-first and the first thing a client sends is its registration — `NICK` and `USER`, or `CAP LS` before them — from inside its own dial path. Every real ircd bounds exactly this: InspIRCd's connect timeout and charybdis/ratbox's registration timeout both default to 30 seconds, so a minute is twice the strictest thing a real client is already built to satisfy. |
| `IDLE_BETWEEN_MESSAGES_TIMEOUT` | 1800s | IRC is long-lived by nature: a registered client may sit in a channel for a whole working day without typing, and closing that breaks the protocol's own use rather than defending it. Half an hour is still an order of magnitude above any ircd's own liveness bound — InspIRCd and UnrealIRCd ping an idle client every 120 seconds and drop it after roughly twice that. |
| `MAX_CONNECTIONS` | 256 | Refusal: **`ERROR :Closing Link: too many connections`**. That is IRC's own way of ending a link before registration and verbatim what a real ircd sends at its connection limit; this file already uses the same form for an over-long line. |

**NetGet's own IRC client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `src/client/irc/mod.rs` writes `NICK` and `USER` unconditionally before any
model turn or keystroke — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline wraps the read and nothing else.** It is a `tokio::time::timeout` around
`read_irc_line`, which is shared with the IRC *client* and is left untouched. The model
round-trip, and a `manual` rule parking a message for a human (`src/state/intercepts.rs`, 300s by
default), happen after a line has been read, so neither can be timed out from under itself.

`tests/server/irc/connection_bounds_test.rs` drives all three from the wire: a silent peer is
closed at the first bound, a connection whose answer is parked for a human is not closed at all,
and the connection past `MAX_CONNECTIONS` is answered with the refusal above and then a clean
EOF. Each was verified by removing the thing it tests — the deadline, the busy marking, the cap —
and watching it fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound
is removed from the source, and `tests/accept_bounded_test.rs` covers the shared cap mechanism
itself, including that a busy connection is never reported as idle.
