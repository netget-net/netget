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
         │   - Execute actions through execute_action (send_command, send_text)
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

**Actions** — `send_command` (one line: the text, then CRLF), `send_text` (the text
with no line ending), `wait_for_more` (say nothing, read again), `disconnect`.

**A line is the default answer, and the descriptions are what make it so.** Telnet servers
read lines: an answer without its CRLF is never seen. `send_command` is described as "the
normal way to answer anything the server says", and `send_text` as having NO line ending
and being only for a server that reads single keys or waits on the same line, not for
answering a question or a prompt. `telnet_data_received`'s description is unchanged on
purpose (below). The wording was chosen by measurement; the names are unchanged, so every
saved handler, `.netget` file and injected action that names either one means what it
always did.

`send_command` strips any CR/LF the model put at the end of its line before adding CRLF, so
`"hello\r\n"` is one line, not a line and an empty one. `send_text` sends its text exactly.
Both are decided in `actions.rs` alone (`line_bytes`, `execute_action`): the connect event's
answer, every later answer and every injected action run that one executor
(`TelnetClient::apply_action` in `mod.rs`). `tests/client/telnet/line_ending_test.rs` pins the
bytes on all three paths from the server's side of the socket.

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
  "text": "y"
}
// Sends: "y" (no line ending)
```

### Dual Logging

Every line meant for both `netget.log` and the TUI goes through
`crate::logging::emit::Log`, so the two cannot disagree on its level:

```rust
Log::to(&status_tx).info(format!("Telnet client {} connected to {} (local: {})", …));
Log::to(status_tx).info(format!("Telnet client {} negotiation: received WILL ECHO", id));
log.error(format!("Telnet client {} failed to send {} bytes: {}", …)); // a lost line is said out loud
```

What the client sends is logged as a byte count at TRACE, never as text: a telnet line is
as often a password as a command.

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
`disconnect`) inside the loop through the same `execute_action` the model's answers use — this is
what the dashboard's [send] button calls, and it needs no LLM. Each injected
action is recorded in the access log (owner = client, event
`injected_action`). On loop exit the handle is dropped so later sends fail
fast. E2E: `tests/client_handle_test.rs`.

### Which send action a model picks: measured

llama3.1:8b on Ollama, the quiz case of the restart-check measurement (root `AGENTS.md`; the
harness drives `--load` with a script-handled telnet server, so the server makes no model
calls, and counts the lines the server received). Each prompt below was captured from a
master (`539b7ddab`) run through a recording proxy, rewritten per variant and replayed with
only `options.seed` changed. "Line" is a first send action that ends in CRLF, "text" is
`send_text`, "other" is an empty answer or none that parses. "Action wording" is the
`send_command` and `send_text` descriptions as they ship; "event wording" is
`telnet_data_received` saying "Reply with send_command (one line, the usual answer)".

Question 1 as first asked, line / text / other:

| Prompt | seeds 1–20 | seeds 21–50 |
|---|---|---|
| master | 14 / 4 / 2 | 23 / 4 / 3 |
| **action wording (what ships)** | **18 / 0 / 2** | **27 / 0 / 3** |
| action and event wording | 19 / 0 / 1 | 26 / 0 / 4 |
| event wording only | 19 / 0 / 1 | 30 / 0 / 0 |
| `send_command` renamed `send_line` (`line`), action and event wording | 17 / 0 / 3 | — |
| one action, `send_line` with `line_ending: "crlf" \| "none"`, event names it | 13 / 0 / 7 | — |
| one action, `send_command` with `line_ending`, event names it | 17 / 0 / 3 | — |
| `send_text` not offered, event names only `send_command` | 18 / 0 / 2 | — |

Question 1 after the restart check refused a repeated `hello` and asked again, with the prompt
saying `send_command {"command":"hello"}` is "not to be sent again" — the turn on which most
of the real runs' answers were given. Seeds 1–30:

| Prompt | line / text / other |
|---|---|
| master | 2 / **22** / 6 |
| **action wording (what ships)** | **29 / 0 / 1** |
| action and event wording | 29 / 0 / 1 |
| event wording only | 17 / 0 / 13 |
| `send_text` not offered | 16 / 0 / 14 |

Told not to send `send_command` again, the model reads the *action* as spent and reaches for
the other one, or for nothing when there is no other one. Describing `send_command` as the way
to send any line is what survives that, which is why the action descriptions changed rather
than only the event's.

Question 2 ("what is 2 plus 2?"), with question 1 answered `Paris` in the history: answers
containing 4, seeds 1–40. This prompt is noisy — two edits that should not matter (a
lower-case "telnet", the `send_text` example) scored 9 and 10 of 20 against master's 10 —
but the event wording is far outside it:

| Prompt | says 4 |
|---|---|
| master | 15 |
| **action wording (what ships)** | 12 |
| action wording, event "Reply with send_command, which sends one line," | 9 |
| action and event wording | **3** |
| event wording only | 1 of 20 |

So the event description stays as it was ("Reply with send_command or send_text, …"): the
action wording alone does as well for the line and does not cost the next answer.

The full runs, seeds 42–49, 60 s each, restart check on (`--llm-seed`, `batching: false`):

| Build | Q1 reached the server as a line | `send_text` answers in the run | Q2 answered with a 4 | reached the last question | extra `hello`s | "again" case (exactly 3 PINGs) |
|---|---|---|---|---|---|---|
| master `539b7ddab` | 3 of 8 | 5 | 2 of the 3 that got there | 2 of 8 | 4 | 7 of 8 |
| **action wording (what ships)** | **7 of 8** | **0** | 2 of 7 | 2 of 8 | 0 | 8 of 8 |
| action and event wording | 8 of 8 | 0 | 0 of 8 | 2 of 8 | 10 | 8 of 8 |

The eighth shipped run answered question 1 with `{"actions": ["send_command", "command":
"Paris"]}`, which is not JSON, twice; nothing could be executed. Question 2 is where the
quiz now stops in most runs, with the model answering "2"; with master it stopped at
question 1 because the answer never became a line. The runs that reached question 2 on
master had answered question 1 as `answer: Paris`, and that history helps the arithmetic:
replayed, the same question 2 scores 17 of 20 with it in the history under either wording.
None of this is the line ending; it is an 8B model doing sums.

`eval-results/2026-11-07-telnet-line-ending/` has the three captured prompts, the scripts
(`harness.py` drives `--load` with `--llm-seed <seed> --run-for 60`; `replay.py` and
`replay_q2.py` post a captured `/api/generate` body back to Ollama with `options.seed` set;
`variants/` rewrites the prompt) and every tally. The scripts were run from
`/tmp/telnet-line/` and name it. In `tallies/runs-quiz.txt`, `fix` is "action and event
wording" and `fix2` is what ships.

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
