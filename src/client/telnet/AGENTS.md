# Telnet Client Implementation

## Overview

The Telnet client implementation provides LLM-controlled outbound Telnet connections. The LLM can connect to Telnet
servers, send commands, handle option negotiations, and interpret server responses.

## Implementation Details

### Library Choice

- **tokio::net::TcpStream** - Async TCP connection
- **Custom Telnet Protocol Parser** - Handle IAC commands and option negotiation
- No external Telnet library needed (protocol is simple enough)

### Architecture

```
┌──────────────────────────────────────────────┐
│  TelnetClient::connect_with_llm_actions      │
│  - Connect to remote address                 │
│  - Split stream (read/write)                 │
│  - Spawn read loop                           │
└──────────────────────────────────────────────┘
         │
         ├─► Read Loop
         │   - Read raw TCP data
         │   - Parse Telnet protocol (IAC commands)
         │   - Handle option negotiation automatically
         │   - Extract actual text data
         │   - Call LLM with data_received event
         │   - Execute actions (send_command, send_text)
         │   - Strictly sequential: the LLM call happens inline
         │
         └─► Write Half (Arc<Mutex<WriteHalf>>)
             - Shared for sending data
             - Used by action execution & negotiation
```

### Telnet Protocol Handling

**Protocol Constants:**

```
IAC (Interpret As Command) = 255 (0xFF)
WILL = 251 (0xFB) - Server offers to enable option
WONT = 252 (0xFC) - Server refuses option
DO = 253 (0xFD) - Server requests client enable option
DONT = 254 (0xFE) - Server requests client disable option
SB = 250 (0xFA) - Subnegotiation begin
SE = 240 (0xF0) - Subnegotiation end
```

**Negotiation Strategy:**

- Server sends WILL <option> → Client responds DONT (refuse)
- Server sends DO <option> → Client responds WONT (refuse)
- Simple "refuse all" strategy keeps implementation straightforward
- LLM doesn't need to understand option negotiation details

**Supported Options** (for logging only):

- ECHO (1)
- SUPPRESS_GO_AHEAD (3)
- TERMINAL_TYPE (24)
- WINDOW_SIZE (31)
- And others (see `get_option_name()`)

### There is no connection state machine, and there never was one

This section used to describe an `Idle`/`Processing`/`Accumulating` machine with a
`queued_data` buffer, copied from the TCP *server*. **Nothing could reach any of it.**
The read loop is one sequential task: it reads, handles the data inline — LLM call
included — and only then comes back to read again. So the state was always `Idle` at
the point it was examined, `queued_data` was never appended to, and the `Processing`
and `Accumulating` arms were unreachable code. The line clearing `queued_data` after
every turn read as "data arriving mid-call is dropped", when in fact no data can
arrive mid-call.

The server-side machine exists because a server has two LLM entry points and can
genuinely be re-entered. Copying its shape here bought nothing and described a
concurrency this client does not have. The struct now holds the model's memory and
nothing else.

**Backpressure still works**, because it is TCP's: while an LLM call is in flight this
task is not reading, so the kernel receive buffer fills and the server is slowed. That
is what the queue was pretending to do.

### LLM Control

**Actions** — `send_command` (newline appended), `send_text` (exact bytes, no
newline), `wait_for_more` (say nothing, read again), `disconnect`.

All four are declared in **both** `get_async_actions` and `get_sync_actions`, and are
attached to both events. That is not redundancy for its own sake: a client has one LLM
entry point, so the async/sync split cannot express a narrowing and
`client_llm_action_set` unions them anyway — but
`events::handler::action_catalog_for_pattern` builds the `event_handlers` validation
catalog from the **sync** list plus the matching event's own actions, and reads the
async list not at all. `disconnect` was async-only, so a static handler naming it was
rejected at startup as an unknown action.

**Events** — `telnet_connected` (`remote_addr`) and `telnet_data_received` (`data`).

`get_event_types()` returns the two `LazyLock<EventType>` statics that `mod.rs`
actually emits. It used to build three `EventType`s inline instead: two duplicating the
statics' ids but with no parameters and `{"type": "placeholder"}` as the example
action, and a third — `telnet_option_negotiated` — that **nothing in `src/` ever
raised**. A routing rule on it could never match, and the model was told to expect
something that does not exist. It is gone rather than emitted: option negotiation is
answered here in Rust, deliberately, and the model has no say in it, so an event per
option would be noise with nothing to decide. `event_emit_sites_test` misses a case
like that precisely because the `EventType` was built inline rather than as a named
static it can find.

### Data Encoding

**Received Data:**

```json
{
  "data": "login: "
}
```

`raw_hex` — the whole read, hex-encoded, up to 16 KB of hex per turn — used to sit
alongside it. The repo's action/event rules forbid exactly that ("never put raw bytes
or base64 in action parameters or event data"): models cannot reliably parse hex, the
negotiation it exposed is answered in Rust rather than by the model, and it doubled the
prompt for nothing.

**Sent Actions:**

```json
{
  "type": "send_command",
  "command": "whoami"
}
// Sends: "whoami\r\n"

{
  "type": "send_text",
  "text": "password"
}
// Sends: "password" (no newline)
```

### Dual Logging

```rust
info!("Telnet client {} connected", client_id);           // → netget.log
status_tx.send("[CLIENT] Telnet client connected");      // → TUI
debug!("Telnet client {} received WILL ECHO", client_id); // → netget.log
```

### Connection Lifecycle

1. **Connect**: `TcpStream::connect(remote_addr)`
2. **Connected**: Update ClientStatus::Connected
3. **Negotiation**: Automatically respond to option negotiations
4. **Data Flow**: Read loop processes incoming data, strips Telnet commands
5. **LLM Interaction**: LLM sees clean text, sends commands
6. **Disconnect**: ClientStatus::Disconnected or Error

### Error Handling

- **Connection Failed**: Return error, client stays in Error state
- **Read Error**: Log, update status to Error, break loop
- **Write Error**: Log, connection may close
- **LLM Error**: Log, continue accepting data
- **Invalid UTF-8**: Use lossy conversion (show � for invalid bytes)

### Telnet Protocol Edge Cases

**IAC Escaping:**

- IAC IAC (255 255) = Literal byte 255
- Handled in `parse_telnet_data()`

**Subnegotiation:**

- IAC SB ... IAC SE sequences
- Skipped/ignored (not relevant for basic shell usage)

**Incomplete Sequences:**

- If buffer ends mid-IAC sequence, may lose command
- Acceptable for LLM-controlled client (rare edge case)

### Command channel (injected actions)

The read loop carries a `tokio::select!` arm on a bounded command channel
(`client/command_support.rs`), registered via
`AppState::register_client_handle`. `AppState::send_to_client(client_id,
action, timeout)` executes an action (`send_command`, `send_text`,
`disconnect`) inside the loop exactly as LLM-produced actions run — this is
what the dashboard's [send] button calls, and it needs no LLM. Each injected
action is recorded in the access log (owner = client, event
`injected_action`). On loop exit the handle is dropped so later sends fail
fast. E2E: `tests/client_handle_test.rs`.

## Limitations

- **No TLS Support** - Raw Telnet only (not Telnet over TLS)
- **No Reconnection** - Must manually reconnect via action
- **Simple Option Negotiation** - Refuses all options (good for most servers)
- **No Line Mode** - Character-at-a-time mode (some servers may expect line mode)
- **No Authentication Helpers** - LLM must handle login prompts manually
- **UTF-8 Only** - Non-UTF-8 encodings converted lossily

## Use Cases

**Typical LLM Flows:**

1. **Interactive Shell Session:**
   ```
   User: "Connect to telnet://localhost:23 and run 'ls'"
   LLM: Connects, waits for login prompt
   Server: "login: "
   LLM: Sends "user\r\n"
   Server: "Password: "
   LLM: Sends "password\r\n"
   Server: "$ "
   LLM: Sends "ls\r\n"
   Server: "file1\nfile2\n$ "
   LLM: Parses output, reports back to user
   ```

2. **Automated Command Execution:**
   ```
   User: "Check uptime on remote server"
   LLM: Sends "uptime\r\n" after login
   LLM: Extracts uptime from response
   ```

3. **Service Testing:**
   ```
   User: "Test if Telnet service is running"
   LLM: Connects, verifies banner
   LLM: Reports service status
   ```

## Testing Strategy

See `tests/client/telnet/AGENTS.md` for E2E testing approach.

## References

- RFC 854: Telnet Protocol Specification
- RFC 855: Telnet Option Specifications
- RFC 1073: Telnet Window Size Option
- RFC 1091: Telnet Terminal Type Option
