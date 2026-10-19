# Socket File Client Implementation

## Overview

The Socket File client protocol enables LLM-controlled connections to Unix domain sockets. This allows communication
with local services that use socket files instead of TCP/IP networking.

## Library Choices

### tokio::net::UnixStream

**Choice:** Built-in Tokio UnixStream for Unix domain socket connections

**Rationale:**

- Native Tokio support (no external dependencies required)
- Async I/O with the same patterns as TcpStream
- Efficient, low-overhead local communication
- Cross-platform support (Unix-like systems)

**Limitations:**

- Unix-only (not available on Windows, though Windows 10+ has Unix socket support via WSL)
- No DNS resolution (uses file system paths)
- Requires socket file to exist on filesystem

## Architecture

### Connection Model

The implementation follows the same pattern as TCP client:

1. **Connect Phase:** Establish connection to Unix domain socket via file path
2. **Read Loop:** Spawn async task to read data from socket
3. **LLM Integration:** Call LLM when data arrives, execute resulting actions
4. **State Machine:** Prevent concurrent LLM calls using Idle/Processing/Accumulating states

### Key Components

**SocketFileClient:**

- Main client struct
- `connect_with_llm_actions()` - Establishes socket connection and spawns read loop
- Uses `UnixStream::connect()` for socket file connections

**SocketFileClientProtocol:**

- Implements `Client` trait for protocol registration
- Implements `Protocol` trait for metadata and actions
- Provides sync and async action definitions

### Data Flow

```
Socket File → UnixStream → Reader task → bounded queue → Answering loop → LLM Call
                                                                  → Actions → Write to Socket
```

## LLM Integration

### Events

The LLM receives two primary event types:

1. **socket_file_connected**
    - Triggered when connection is established
    - Contains socket file path

2. **socket_file_data_received**
    - Triggered when data arrives from socket
    - Contains `data` (text when every byte is printable ASCII, hex otherwise), `encoding`
      (`"utf8"` / `"hex"`) saying which, and `data_length`
    - One answering loop, so model calls never overlap

Both are the `LazyLock` statics the read loop emits. `get_event_types()` used to build two
*separate* `EventType`s with `{"type": "placeholder"}` example actions, no parameters and no
attached actions, so the model was shown one description and handed another.

### Actions

**Async Actions (user-triggered):**

- `send_socket_file_data` - `data` + optional `encoding` (`"utf8"` default, `"hex"`)
- `disconnect` - Close socket connection and end the read loop

**Sync Actions (LLM response to events):**

- `send_socket_file_data` - the same fields, in response to received data
- `wait_for_more` - queue data without immediate response
- `disconnect`

`data_hex` remains **accepted** by the executor, because it was the only shape this client ever
advertised and models reach for it out of habit; it means exactly
`{"data": ..., "encoding": "hex"}`. It is no longer what the client *advertises*: hex-only fields
are the "never put raw bytes in action parameters" defect, and they forced the model to encode
`PING` as `50494e47` to say hello.

`disconnect` used to `break` only the loop over the model's actions, leaving the socket open —
the model's decision to hang up did nothing. It now shuts down the write half and ends the read
loop.

### Action Results

Actions return `ClientActionResult` enum:

- `SendData(Vec<u8>)` - Binary data to write to socket
- `Disconnect` - Close connection
- `WaitForMore` - Continue accumulating data

## Reading and batching

A registered reader task reads the socket and puts each read on a bounded queue
(`READ_QUEUE_CHUNKS` = `MAX_BATCH_EVENTS` reads of at most 8 KiB; past it the reader stops and
the socket buffer holds the peer back). The answering loop takes one read per model call with
batching off; with batching on (the declared default) it joins every read already waiting
into one payload, as the tcp client does. `tests/client/socket_file/batching_test.rs` drives
both against a `UnixListener` that sends during a slow call, batching off as the control.

The Idle/Processing/Accumulating machine that used to be described here could never run: the
read loop awaited every model call inline, so nothing arrived mid-call. Before that it filled a
queue and `clear()`ed it unread. The data path also kept its own memory copy while the
connected event wrote `AppState`'s; both now use `AppState`'s.

### Dual Logging

All significant events are logged via:

1. **Tracing macros** (`info!`, `error!`, `trace!`) → `netget.log`
2. **Status channel** (`status_tx.send()`) → TUI display

## Limitations

### Platform Support

- **Unix-like systems only:** Linux, macOS, BSD
- **Windows:** Limited support (Windows 10+ with WSL, or AF_UNIX in newer Windows builds)
- Not suitable for cross-platform client applications

### Socket File Requirements

- Socket file must exist on filesystem before connection
- Client has no control over socket creation (server creates it)
- File permissions may prevent connection
- Socket paths are limited to ~108 bytes on most systems

### Addressing

- No traditional socket addresses (SocketAddr is a dummy value)
- Uses file system paths instead of IP:port
- Path resolution is synchronous (blocking)

### Security

- File system permissions control access — the *server's*, not this client's: a client creates no
  filesystem object at all. It opens the path it was given and nothing else.
- No encryption by default (unlike TLS/TCP)
- Shared memory namespace (all processes on same host)
- The path is caller-supplied and is passed straight to `UnixStream::connect`. Pointing it at
  `/var/run/docker.sock` is a documented use case, so treat "what this client may be told to
  connect to" as equal to "what the invoking user may connect to".

## Use Cases

### Local IPC

- Communication with local services (Docker daemon, systemd, databases)
- High-performance inter-process communication
- Avoiding network stack overhead

### Application Servers

- Connecting to web servers via socket (nginx, gunicorn, uvicorn)
- Database connections (PostgreSQL, MySQL can use Unix sockets)
- Redis, Memcached via Unix sockets

### Testing

- Testing services that only expose Unix socket interfaces
- Simulating local service communication
- Integration testing without network configuration

## Example Prompts

**Basic Connection:**

```
Connect to ./app.sock and send "PING"
```

**HTTP over Unix Socket:**

```
Connect to /var/run/docker.sock and send GET /containers/json
```

**Redis via Socket:**

```
Connect to /var/run/redis/redis.sock and execute SET key value
```

## Implementation Notes

### Dummy SocketAddr

Unix sockets don't have traditional socket addresses (IP:port). The implementation returns a dummy `SocketAddr` (
127.0.0.1:0) to satisfy the `connect()` method signature. The actual socket path is stored in the client's `remote_addr`
field in app_state.

### Path Validation

The implementation does not validate socket file existence before attempting connection. This is intentional - the OS
will return appropriate errors if the socket doesn't exist or lacks permissions.

### Automatic Cleanup

When the read loop exits (connection closed or error), the client status is automatically updated to `Disconnected` or
`Error`. No manual cleanup is required.

## Future Enhancements

### Abstract Namespace Support

Linux supports abstract Unix sockets (prefixed with `\0`) that don't use filesystem paths. Could be added as an optional
feature.

### Credential Passing

Unix sockets support passing credentials (PID, UID, GID) between processes via `SCM_CREDENTIALS`. Not currently
implemented but could be useful for authentication.

### File Descriptor Passing

Advanced feature: passing file descriptors between processes over Unix sockets. Low priority but interesting for certain
use cases.
