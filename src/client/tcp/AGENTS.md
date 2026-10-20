# TCP Client Implementation

## Overview

The TCP client implementation provides LLM-controlled outbound TCP connections. The LLM can connect to TCP servers, send
raw bytes, and interpret responses.

## Implementation Details

### Library Choice

- **tokio::net::TcpStream** - Async TCP client
- Direct socket I/O with hex encoding for LLM interaction
- Split stream pattern for concurrent read/write

### Architecture

```
┌────────────────────────────────────────┐
│  TcpClient::connect_with_llm_actions   │
│  - Connect to remote address           │
│  - Split stream (read/write)           │
│  - Spawn read loop                     │
└────────────────────────────────────────┘
         │
         ├─► Read Loop
         │   - Read data from server
         │   - Call LLM with data_received event
         │   - Execute actions (send_data, disconnect)
         │   - State machine (Idle/Processing/Accumulating)
         │
         └─► Write Half (Arc<Mutex<WriteHalf>>)
             - Shared for sending data
             - Used by action execution
```

### Connection State Machine

**States:**

1. **Idle** - No LLM processing happening
2. **Processing** - LLM is being called, new data queued
3. **Accumulating** - LLM still processing, accumulating more data

**Transitions:**

- Idle → Processing: Data received, call LLM
- Processing → Accumulating: More data arrives during LLM call
- Accumulating → Accumulating: More data while LLM processing
- Processing/Accumulating → Idle: LLM returns, process queue

### LLM Control

**Async Actions** (user-triggered):

- `send_tcp_data` - Send hex-encoded bytes to server
- `disconnect` - Close connection

**Sync Actions** (in response to received data):

- `send_tcp_data` - Send bytes as response
- `wait_for_more` - Don't respond yet, accumulate data

**Events:**

- `tcp_connected` - Fired when connection established
- `tcp_data_received` - Fired when data received from server

### Data Encoding

The same contract as the TCP server: text travels as text, and `encoding` says when it is hex.

- Received: `{"data": "hello\r\n", "encoding": "utf8", "data_length": 7}` when every byte is
  printable ASCII or whitespace; otherwise `{"data": "00ff10", "encoding": "hex", …}`.
- Sent: `{"type": "send_tcp_data", "data": "world"}`, or
  `{"type": "send_tcp_data", "data": "776f726c64", "encoding": "hex"}` for bytes.

There is no detection on the way out: `"776f726c64"` is valid text and valid hex, and only the
sender knows which it means. `data_hex` is still accepted by the executor for handlers written
against it, but the model is shown only `data` + `encoding`.

### Dual Logging

```rust
info!("TCP client {} connected", client_id);           // → netget.log
status_tx.send("[CLIENT] TCP client connected");      // → TUI
```

### Connection Lifecycle

1. **Connect**: `TcpStream::connect(remote_addr)`
2. **Connected**: Update ClientStatus::Connected
3. **Data Flow**: Read loop processes incoming data
4. **Disconnect**: ConnectionStatus::Disconnected or Error

### Error Handling

- **Connection Failed**: Return error, client stays in Error state
- **Read Error**: Log, update status to Error, break loop
- **Write Error**: Log, connection may close
- **LLM Error**: Log, continue accepting data

### Command channel (injected actions)

The read loop carries a `tokio::select!` arm on a bounded command channel
(`client/command_support.rs`), registered via
`AppState::register_client_handle`. `AppState::send_to_client(client_id,
action, timeout)` executes an action (`send_tcp_data`, `disconnect`,
`wait_for_more`) inside the loop exactly as LLM-produced actions run — this is
what the dashboard's [send] button calls, and it needs no LLM. Each injected
action is recorded in the access log (owner = client, event
`injected_action`). On loop exit the handle is dropped so later sends fail
fast. E2E: `tests/client_handle_test.rs`.

## Limitations

- **No TLS Support** - Raw TCP only (TLS could be added later)
- **No Reconnection** - Must manually reconnect via action
- **No Buffering Control** - Uses default 8KB buffer
- **Hex Encoding Overhead** - 2x data size for LLM interaction

## Testing Strategy

See `tests/client/tcp/AGENTS.md` for E2E testing approach.
