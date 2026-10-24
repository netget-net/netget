# TCP Protocol Implementation

## Overview

TCP server implementing raw TCP socket handling where the LLM has full control over the byte stream. This is the most
fundamental protocol in NetGet - the LLM can construct any TCP-based protocol on top of it (FTP, HTTP, SMTP, custom
protocols, etc.).

**Status**: Beta (Core Protocol)
**RFC**: RFC 793 (Transmission Control Protocol)

## Library Choices

- **tokio::net::TcpListener** - Async TCP server from Tokio runtime
- **tokio::io::{AsyncReadExt, AsyncWriteExt}** - Async I/O traits for reading/writing
- **Manual byte-level handling** - LLM receives raw bytes and constructs responses

**Rationale**: No high-level TCP library needed. The LLM directly controls the byte stream, making this the most
flexible protocol implementation.

## Architecture Decisions

### 1. Raw Byte Control

The LLM receives the exact bytes sent by the client and can respond with any byte sequence. This allows the LLM to:

- Implement any text protocol (FTP, SMTP, POP3, custom protocols)
- Handle binary protocols
- Mix text and binary data
- Create custom protocol parsers

### 2. Connection State Machine

Each connection has three states:

- **Idle**: Ready to process new data
- **Processing**: LLM is generating a response
- **Accumulating**: LLM requested `wait_for_more` to accumulate additional data

This prevents concurrent LLM calls for the same connection and ensures ordered processing —
but only because the **reader** makes every transition into `Processing`, in arrival order and
under the connection lock (`admit_read`), and the answering task (`answer`) is spawned only by
that transition. It leaves `Processing` only by taking the next queued payload or going `Idle`
under one lock. When each read's own spawned task checked the state and set it in two separate
lock acquisitions, two reads could both find the connection `Idle` and be answered at once, and a
later read's task could run first: `tests/server/tcp/read_order_test.rs` measured replies coming
back out of order in 140 of 200 runs. It also left a read queued between "is the queue empty?"
and "go `Idle`" stranded until the peer sent something else.

### 3. Data Queueing

When data arrives while the LLM is processing:

1. Data is queued in `ConnectionData.queued_data`
2. After LLM response, queued data is merged and processed
3. Loop continues until all queued data is processed

`wait_for_more` puts the payload the model was just shown back at the **head** of that queue, so
the next event carries the fragment joined to whatever arrived after it. It used to drop the
fragment, which made the action's name a lie: a model asked to reassemble a message across two
reads could only do it by copying the first half into its memory. If bytes arrived *during* the
call that returned `wait_for_more`, they are the "more" it asked for, so the loop goes round
again immediately rather than parking them until a read that may never come — the peer has
typically sent its whole message and is waiting on us.

The queue is bounded by `MAX_QUEUED_BYTES` (8 MiB, `src/server/tcp/mod.rs`). Both paths that
grow it check the bound and close the connection (`decision=queue_overflow`, FIN) rather than
trimming, because a truncated payload the model cannot tell is truncated is worse than a
dropped connection. Without the bound a peer that streams for the length of one LLM call — a
few seconds — could grow NetGet's memory as fast as its link allows, pre-authentication.

### 4. The connect event, and what `send_first` means

`tcp_connection_opened` is raised only for a server started with **`send_first`**, which means
the peer is owed a greeting: the reader does not read at all until the connect event is answered,
a silent answer is WARN `decision=model_silent`, and a backend failure half-closes
(`decision=fail_closed_llm_error`). Without `send_first` the connection is registered `Idle` and
no model call happens until the peer sends something; generic TCP is client-speaks-first.

Raising it for every connection was built and measured, and rejected. It cost one model call per
connection for any server with no rule for the event, and in the seeded real-model eval
llama3.1:8b answered the empty connect event with a greeting nobody asked for, taking `tcp` from
15/15 to 10/15. The event and parameter descriptions say `send_first` is how a server greets, which
is what IMPROVEMENTS item 78 asked for. `telnet`, where the server is expected to speak first, does
raise its connect event on every connection.

- With `send_first` the connection is registered `Processing`, so bytes that arrive while the
  connect event is answered queue behind it; `handle_connection_opened` then takes the queue
  and answers it (`answer`), or moves the connection to `Idle` if nothing arrived — under one
  lock. One model call at a time per connection.
- A peer that disconnects before the connect event is answered abandons the call
  (`decision=peer_left_before_answer`).

### 5. Stream Splitting

TcpStream is split into `(ReadHalf, WriteHalf)` using `tokio::io::split()`:

- **ReadHalf**: Owned by dedicated reader task
- **WriteHalf**: Wrapped in `Arc<Mutex<WriteHalf>>` and stored in connection map
- This allows concurrent reading and writing without cloning the stream

### 6. Dual Logging

All data operations use **dual logging**:

- **DEBUG**: Data summary with 100-char preview (for both text and binary)
- **TRACE**: Full payload (text as string, binary as hex)
- Both go to `netget.log` (via tracing) and TUI Status panel (via status_tx)

## LLM Integration

### Action-Based Response Model

The LLM responds to TCP events with actions:

**Events**:

- `tcp_connection_opened` - New connection accepted (only with `send_first`; see section 4)
- `tcp_data_received` - Data received from client

**Available Actions**:

- `send_tcp_data` - Send raw bytes to client (`data` plus an explicit `encoding`, see
  [Data Format](#data-format))
- `close_this_connection` - Close the connection
- `wait_for_more` - Keep this payload and wait for the rest of the message
- Common actions: `show_message`, `update_instruction`, etc.

The one async (user-triggered) action is `close_connection`, which the dashboard's
`[ disconnect this peer ]` injects. Its `connection_id` is optional and ignored — the executor
is only ever reached with one connection in scope. `send_to_connection` and `list_connections`
used to be advertised alongside it and **could not work**: nothing ever populated
`TcpProtocol`'s own connection map, so `list_connections` always saw none, and the executor's
`Output` is written to whichever connection is being handled, so `send_to_connection` parsed and
then discarded its `connection_id`. Both are gone, the same removal `socket_file` made.

### Example LLM Response

```json
{
  "actions": [
    {
      "type": "send_tcp_data",
      "data": "220 Welcome to NetGet FTP Server\r\n",
      "encoding": "utf8"
    },
    {
      "type": "show_message",
      "message": "Sent FTP greeting"
    }
  ]
}
```

### Data Format

Outbound (`send_tcp_data`) uses an **explicit** `encoding` field next to
`data`. There is no heuristic sniffing: `"48656c6c6f"` is simultaneously valid text and valid
hex, so the sender must declare which it means.

| `encoding`          | Bytes written to the socket                                   |
| ------------------- | ------------------------------------------------------------- |
| omitted (default)   | `data.as_bytes()` — the string's characters, unchanged         |
| `"utf8"`            | same as omitted                                               |
| `"hex"`             | `hex::decode(data)` — `"48656c6c6f"` sends the 5 bytes `Hello` |
| anything else       | action fails with an error naming the valid values            |

Invalid hex (odd digit count, non-hex characters) returns an `anyhow` error rather than
panicking; the connection stays open. `encoding: "hex"` tolerates whitespace, `:` separators
and a leading `0x`. Defaulting to `utf8` keeps every pre-existing prompt, handler and test
working unchanged.

Inbound (`tcp_data_received`) carries the same pair of fields:

- `data` — the received bytes as text if **all** of them are ASCII graphic/whitespace,
  otherwise hex-encoded (`src/server/tcp/mod.rs`)
- `encoding` — `"utf8"` or `"hex"`, saying which of the two the `data` field is

Echoing is therefore symmetric: pass the event's `data` **and** its `encoding` straight into
`send_tcp_data` and the exact received bytes go back out.

## Connection Management

### Connection Lifecycle

1. **Accept**: `TcpListener::accept()` creates new connection
2. **Register**: Connection added to `ServerInstance` with `ProtocolConnectionInfo::Tcp`
3. **Split**: Stream split into ReadHalf and WriteHalf
4. **Track**: WriteHalf stored in `connections` HashMap with `ConnectionData`
5. **Handle**: Separate tasks for reading and LLM processing
6. **Close**: Connection removed from maps when client disconnects or LLM closes

**Step 4 happens synchronously in the accept loop, before any task is spawned.** It used to be
the first thing the banner task did, which raced the reader task spawned immediately after it:
a read was dropped when the connection was not yet in the map, so a client
that wrote before the server accepted — the normal case, since `connect()` returns as soon as
the kernel completes the handshake — had its first payload dropped with no response, no error
and no log line. 8 of 64 clients in a burst lost their request that way. The connect task runs
for every connection and no longer registers anything, and `tests/connection_map_race_test.rs`
pins the behaviour. The same shape was fixed in `socket_file` (`1f3945ee`), `tls` and `ssh_agent`.

A connection can disappear while it is being answered (write-then-close clients do exactly
that), so every lookup in `admit_read` and `answer` returns early instead of unwrapping. A merge
step once `unwrap()`ed the miss and panicked the task, which is silent — the server keeps
reporting `Running`.

### Connection Data Structure

```rust
struct ConnectionData {
    state: ConnectionState,           // Idle/Processing/Accumulating
    queued_data: Vec<u8>,              // Data queued while processing
    memory: String,                    // Per-connection memory (unused currently)
    write_half: Arc<Mutex<WriteHalf>>, // For sending responses
}
```

### State Updates

- Connection state tracked in `ServerInstance.connections`
- Updates include: bytes sent/received, packets sent/received, last_activity
- UI automatically refreshes on state changes via `__UPDATE_UI__` message

## Known Limitations

### 1. No TLS Support

- Raw TCP only, no built-in TLS/SSL
- For HTTPS/FTPS, use the HTTP protocol with TLS or implement TLS manually

### 2. No Connection Timeouts

- Connections remain open indefinitely until client closes or LLM sends `close_connection`
- No idle timeout mechanism

### 3. No Backpressure Handling

- All received data is processed immediately
- Large bursts of data may overwhelm the LLM processing queue
- There is no flow control back to the peer; the only limit is `MAX_QUEUED_BYTES`, and reaching
  it closes the connection rather than slowing it

### 4. Memory Accumulation

- `wait_for_more` accumulates data in memory, bounded by `MAX_QUEUED_BYTES` (8 MiB per
  connection). Beyond that the connection is closed with `decision=queue_overflow`
- The bound is per connection, so total memory still scales with the number of peers

### 5. Half-Close Is a Failure Signal, Not a Feature

- The model cannot request a half-close: `close_this_connection` closes both directions
- The server half-closes (`write.shutdown()`) in exactly one case — the LLM call returned
  `Err` — on the data path, and on the connect event of a `send_first` server (which owes the
  peer a greeting; without `send_first` a failed connect event is only logged). Raw TCP has no error
  frame, so FIN is the only honest answer: the peer reads EOF immediately instead of
  blocking until its own timeout. Nothing derived from the error is ever written to the
  socket; the full error goes to the log and the status stream only
  (`decision=fail_closed_llm_error class=overloaded|unavailable`)
- The three outcomes are distinguishable in the log: `decision=model_close` (the model hung
  up), `decision=model_no_actions` (the model answered with no bytes — legitimate on raw
  TCP, connection stays open), `decision=fail_closed_llm_error` (the backend failed)

## Example Prompts

### FTP Server

```
listen on port 21 via ftp
When a client connects, send "220 NetGet FTP Server\r\n"
Handle USER command: respond with "331 Password required\r\n"
Handle PASS command: respond with "230 Login successful\r\n"
Handle PWD command: respond with "257 \"/home/user\"\r\n"
Handle QUIT command: respond with "221 Goodbye\r\n" and close connection
```

### Echo Server

```
listen on port 7 via tcp
When you receive any data, echo it back with "ACK: " prefix
```

### Binary Protocol

```
listen on port 9000 via tcp
When you receive a 4-byte big-endian integer, respond with the integer + 1
Reply with send_tcp_data using "encoding": "hex" so the digits are decoded into bytes
```

### Stateful Protocol

```
listen on port 8080 via tcp
Wait for command: HELLO, START, or STOP
After HELLO, send "READY\r\n"
After START, send "RUNNING\r\n"
After STOP, send "STOPPED\r\n" and close connection
```

## Performance Characteristics

### Latency

- One LLM call per received data chunk (unless using `wait_for_more`)
- Typical latency: 2-5 seconds per request with qwen3-coder:30b

### Throughput

- Limited by LLM response time
- Concurrent connections processed in parallel (each on separate tokio task)
- Queue mechanism prevents data loss but doesn't improve throughput

### Concurrency

- Unlimited concurrent connections (bounded by system resources)
- Each connection has independent state and processing
- Ollama lock serializes LLM API calls across all connections

## References

- [RFC 793: Transmission Control Protocol](https://datatracker.ietf.org/doc/html/rfc793)
- [Tokio TcpListener](https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html)
- [Tokio AsyncReadExt](https://docs.rs/tokio/latest/tokio/io/trait.AsyncReadExt.html)
- [Tokio AsyncWriteExt](https://docs.rs/tokio/latest/tokio/io/trait.AsyncWriteExt.html)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/tcp/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | **300s**, overridable per server with `first_byte_timeout_secs` | Was 30s, on the argument that generic TCP is client-speaks-first so a silent peer has made no claim. True of a stranger; **false of the peer this server most often has.** The dashboard offers `[ + tcp client ]` under a server's peers with `[ send message ]` beneath it — that client connects, says nothing, and waits for a person to type, and 30 seconds is less than a person takes. 300s is the window a `manual` rule gives a human (`src/state/intercepts.rs`), which is the number this product already uses for how long someone might take. A listener genuinely exposed to strangers should set the parameter low. |
| `IDLE_BETWEEN_MESSAGES_TIMEOUT` | 900s | This is the generic byte stream every kind of session is built on, so the bound between messages has to be a session's timescale rather than a request's. Fifteen minutes is three times the default a `manual` rule gives a human to answer one event, so a session whose last exchange was composed by hand still has minutes of ordinary think-time left afterwards. |
| `MAX_CONNECTIONS` | 256 | Refusal: **nothing**. Raw TCP has no framing, no status code and no error message a peer would not read as *payload*, and a fabricated payload is worse than silence. The peer gets a clean EOF; `accept_bounded` logs the refusal at WARN with `decision=fail_closed_connection_cap`. |

**The 30-second default was found by a test failing, and the failure looked like flakiness.**
`tests/mcp_stdio_test.rs::client_tools_manage_a_real_connection` creates a TCP server, attaches
a TCP client to it, and asks for the client's status. It began reporting `Disconnected`. It
takes about 38 seconds to drive that much of the MCP surface, so the server closed the client it
had just been given — and the test only *looked* load-sensitive because it is slow, not because
it races. Two runs settled it: in isolation it reproduced every time, and at the commit before
the bounds merge it passed. Neither run alone would have been enough.

Both bounds are now declared startup parameters, because the right value is a property of who is
on the other end and only the operator knows that. `tests/server/tcp/connection_bounds_test.rs`
sets the first to six seconds — a test cannot wait five minutes, and one that asserted the
default by waiting it out would be the slowest thing in the suite. What it asserts is that the
deadline is applied and that work in flight suspends it; the value is argued here.

**TCP is the one server here whose read loop does not stop while a request is answered.** Every
other protocol awaits the model inline, so its `read()` is not even being polled during the
answer. This one hands each answer to a spawned task and goes straight back to `read()`, so the
deadline and the answer are live at the same moment. `read_bounded` therefore consults
`ConnectionActivity`, which reports a connection with work in flight as not idle at all: the
per-message handler and the connect-event task each hold a `BusyGuard` for the whole of
their work, so an LLM round-trip, and a `manual` rule parking an event for a human
(`src/state/intercepts.rs`, 300s by default), can never be timed out from under themselves. That
is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse — TFTP evicted live
transfers because "idle" was measured wrongly.

`tests/server/tcp/connection_bounds_test.rs` drives all three from the wire: a silent peer is
closed at the first bound, a connection whose answer is parked for a human is not closed at all,
and the connection past `MAX_CONNECTIONS` is answered with the refusal above and then a clean
EOF. Each was verified by removing the thing it tests — the deadline, the busy marking, the cap —
and watching it fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound
is removed from the source, and `tests/accept_bounded_test.rs` covers the shared cap mechanism
itself, including that a busy connection is never reported as idle.
