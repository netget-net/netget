# Socket File (Unix Domain Socket) Protocol Implementation

Raw byte-stream server over a Unix domain socket. The model sees exactly the
bytes the client sent and decides exactly what bytes go back — the same contract
as `tcp`, addressed by filesystem path instead of IP:port.

**State**: Experimental — the peer is a local descriptor, so no third-party client
exists to validate against and nothing can raise this rating on the usual
evidence. **Platform**: Unix only; the whole module is `#![cfg(unix)]`.
**Privilege**: none — access is controlled by filesystem permissions on the
socket file, not by port numbers.

## What it can reach on the host

One filesystem object: the socket node at `socket_path`, created by `bind` and
removed only when the path already held a socket (see below). It executes
nothing, spawns no process, and opens no other path. The bytes on the socket are
whatever the model authors.

**The node is chmod'd `0600` immediately after `bind`.** `bind` creates it with
`0777 & ~umask` — `srwxr-xr-x` under the usual `umask 022` — and both Linux and
macOS check write permission on the socket node at `connect(2)`, so the default
let *any* local user talk to a server the operator started for one process. The
model or an MCP caller chooses `socket_path`, and a predictable path under a
world-writable directory is the classic local-escalation shape. There is a short
window between `bind` and `chmod`; closing it completely means putting the socket
in a directory only the owner can traverse, which is the caller's choice of path
rather than something this protocol can impose.

## Startup

| Parameter | Required | Meaning |
|---|---|---|
| `socket_path` | yes | path to create, e.g. `./netget.sock` |
| `send_first` | no | send a banner on connect (raises `socket_file_connection_opened`) |
| `first_byte_timeout_secs` | no | seconds a connected peer may send nothing (default 300) |
| `idle_timeout_secs` | no | seconds a session may be silent between messages (default 900) |

No port is involved. `default_binding()` returns empty binding defaults so that
`server_startup.rs` does not demand one; without that declaration this protocol
could not be started over MCP at all ("requires 'port' parameter").

**A stale socket is removed only if it really is a socket.** `socket_path` comes
from the model or an MCP caller, so an unconditional `remove_file` is an
arbitrary-file delete — a typo'd or hostile path would unlink whatever is there
before binding. The server stats the path with `symlink_metadata` (which does not
follow symlinks) and refuses to start unless it is a socket, naming what it found.

## What the model sees and controls

**Events**

- `socket_file_connection_opened` — only when `send_first` is set. No fields.
- `socket_file_data_received` — `data` plus `encoding`.

**Actions**: `send_socket_data` (`data`, `encoding`), `wait_for_more`,
`close_this_connection` (`close_connection` is accepted as an alias).

There are no async actions. `send_to_connection`, `close_connection` and
`list_connections` used to be advertised as async actions backed by a second,
always-empty connection map inside `SocketFileProtocol`; nothing ever inserted
into it and nothing routed their output to a connection, so all three were
inert. The server owns the only connection map, because it holds the write
halves.

### Encoding is explicit in both directions

Inbound: `data` is the received bytes as text when every byte is printable
ASCII, hex otherwise, and `encoding` (`"utf8"` / `"hex"`) says which.

Outbound: `send_socket_data` reads the same `encoding` field, defaulting to
`"utf8"`. There is deliberately no auto-detection — `"48656c6c6f"` is both valid
text and valid hex — so echoing a payload back unchanged means passing back the
same `data` *and* `encoding`. Invalid hex is an action error, not a panic.

This mirrors the fix made to `send_tcp_data`; before it, the docs advertised hex
support that the executor did not implement, and a model following them put
literal ASCII on the wire.

## Connection handling

Per connection: `ReadHalf` owned by a reader task, `WriteHalf` behind
`Arc<Mutex<…>>` in the shared map, and an Idle → Processing → Accumulating state
machine that serialises LLM calls and queues data that arrives mid-call.

**Batching** (`BatchingMode::On`, the `tcp` shape). The queue remembers where each read ended
(`queued_chunks`), and `ConnectionData::take_next` decides what the next call answers: with
batching on, everything that arrived during the call is one `socket_file_data_received`
payload; with it off, one read per call, in order. Bytes held by `wait_for_more` are always
taken whole. `tests/server/socket_file/batching_test.rs` asserts both, control first.

**Queue cap** (`MAX_QUEUED_BYTES`, 8 MiB, declared as `max_inbound_bytes`, the same as `tcp`).
What queues during a call, and what `wait_for_more` accumulates, are both bounded; past it the
write half is shut, so the peer reads EOF, and the log says `decision=queue_overflow`. The
connection is closed rather than the queue trimmed, which would hand the model a message it could
not know was truncated. `wait_for_more` keeps the fragment it was shown: it goes back to the head
of the queue as one payload (`hold_as_one`), and bytes that arrived during the call complete it
at once. `tests/server/socket_file/queue_limit_test.rs` sends past the bound during a slow call.

`update_connection_stats` is called on every read and every write, so the
dashboard rail's `↓/↑` counters and `last_activity` reflect the connection. This
protocol used not to call it at all and every live connection read `0B/0B`.

**Every map lookup after the first is fallible, and none of them may panic.**
The lock is released between the state read and the merge, so the connection can
legitimately be gone by the time the merge runs — the peer reset, or another task
ran `close_this_connection`. That merge used `.unwrap()`, inside a
`tokio::spawn` that swallows the panic: the bytes vanished, the log said nothing,
and the server stayed `Running`. It is a `let … else { return }` with a DEBUG
line naming the connection and the byte count.

**The connection is registered in the accept loop, before either task is
spawned.** It used to be registered by the banner task, which raced the reader:
`handle_data_with_actions` returns silently when the connection is not in the
map, so a client that wrote immediately after connecting
(`printf ping | nc -U …`) had its first payload dropped with no response and no
log line. Verified: before the fix the log stopped at "received 5 bytes"; after
it, the handler runs.

Dual logging throughout: DEBUG summaries with a 100-character preview, TRACE full
payloads (text as a string, binary as hex), to both `netget.log` and the TUI. The
preview goes through `crate::utils::truncate_for_log` rather than `&s[..100]`:
the slice sat inside an all-printable-ASCII branch and so could not panic today,
but it is one edit to the guard away from the multi-byte-UTF-8 crash that
`truncate_for_log` exists to prevent.

### Connection bounds

Declared in `mod.rs` beside their arguments; the two read bounds are startup parameters.

| Bound | Default | Parameter | Mechanism |
|---|---|---|---|
| First byte | 300s | `first_byte_timeout_secs` | `read_bounded` (a `timeout` around the `read()` that consults `ConnectionActivity`) |
| Idle between messages | 900s | `idle_timeout_secs` | the same, once the peer has sent anything |
| Connections | 256 | — | `accept_bounded_unix`; the peer over the cap reads a clean EOF (a byte stream has no refusal vocabulary) |

- **Which client state the first-byte bound faces: connected and silent.** NetGet's own
  `socket_file` client connects inside `connect()` and writes nothing until a model action or a
  person's `[ send message ]`, so the default is `tcp`'s 300s — the window a `manual` rule gives
  a human — rather than a stranger-shaped 30s.
- **Busy is not idle.** The read loop hands every message to a spawned task and goes straight
  back to `read()`, so the deadline and an answer in progress are live at once. Each handler
  task (and a `send_first` banner task) holds `ConnectionActivity` busy, and `read_bounded`
  never closes a connection with work in flight — `tcp`'s shape exactly.
- `tests/server/socket_file/connection_bounds_test.rs` drives all three from the peer's end.

### When the LLM call fails

A raw byte stream has no error frame, so there is nothing safe to *say*: the only
honest signal is FIN. Both LLM entry points (the `send_first` banner and
`socket_file_data_received`) classify the error with
`crate::utils::WireFailure`, log the full error to `netget.log` and the status
stream, then `shutdown()` the write half, drop the connection from the map and
call `close_connection_on_server`. The peer's next read returns EOF immediately
instead of blocking until its own timeout. Nothing derived from the error — the
backend URL, the model name, an `anyhow` chain — ever reaches the socket.

Three outcomes stay distinguishable in the log:

| `decision=` | meaning |
|---|---|
| `model_close` | the model answered by hanging up |
| `model_no_actions` | the model answered with no bytes (legitimate; connection stays open) |
| `fail_closed_llm_error` | the LLM call errored; `class=overloaded\|unavailable` |

## Not implemented

A `mode` startup parameter: the socket is always `0600` and there is no way to
ask for group access. Peer credentials (`SO_PEERCRED` — a Unix socket can
identify the connecting process; the model is not told), backpressure, and any
bound on how much `wait_for_more` accumulates. `SocketAddr` is required by
internal APIs, so connections report the placeholder `127.0.0.1:0`; the real path
is in `protocol_info.socket_path`.

## Example prompts

```json
{"type": "start_server", "protocol": "socket_file",
 "startup_params": {"socket_path": "/tmp/nge.sock"},
 "event_handlers": [{"event_pattern": "socket_file_data_received",
   "handler": {"type": "static", "actions": [{"type": "send_socket_data", "data": "ACK\n"}]}}]}
```

```
Create socket file at ./echo.sock and echo back any data received, passing the
same encoding you were given.
```

```
Listen on ./greeter.sock with send_first=true. Send "READY\n" on connect, then
answer HELLO with "GREETINGS\n" and QUIT with "BYE\n" followed by
close_this_connection.
```

## Verified

Started over MCP with `startup_params.socket_path`, with static handlers (zero
LLM calls):

- A Python `AF_UNIX` client that writes immediately after connect gets the reply
  (this is the race described above).
- `{"data": "48454c4c4f0a", "encoding": "hex"}` puts `HELLO\n` on the wire.
- Pointing `socket_path` at a regular file is refused — "it exists but is not a
  Unix domain socket (it is a regular file)" — and the file is left intact.
- `nc -U` works, but macOS `nc` exits on stdin EOF, so
  `printf ping | nc -U …` can miss the reply; keep stdin open or use a real
  client.
- `ls -l` on the socket path shows `srw-------` after start.

`tests/server/socket_file/` is declared in `tests/server/mod.rs` and runs against
the mock LLM.
