# Named Pipe (POSIX FIFO) Protocol Implementation

Impersonates an OS-level IPC endpoint: a `mkfifo` FIFO the model reacts to. A writer process
writes bytes to `pipe_path`; each chunk becomes a `named_pipe_data_received` event; the model
answers with `write_named_pipe_data`, whose bytes are written to an optional second FIFO
(`response_pipe_path`) that a reader process drains. NetGet owns the plumbing; the model owns the
payload — the same contract as `socket_file`, addressed by a FIFO path.

**State**: Experimental. **Platform**: Unix only; the whole module is `#![cfg(unix)]`.
**Privilege**: none — access is filesystem permissions on the FIFO (created `0o600`), not ports.
**Windows**: out of scope. A Windows named pipe (`\\.\pipe\...`) is a different primitive and
would be a separate `#[cfg(windows)]` implementation.

## Startup

| Parameter | Required | Meaning |
|---|---|---|
| `pipe_path` | yes | FIFO to create and READ; a writer writes here |
| `response_pipe_path` | no | second FIFO to create and WRITE model output to; a reader reads here |

No port is involved; `default_binding()` returns empty binding defaults so `server_startup.rs`
does not demand one (the same reason `socket_file` needs it).

**An existing node is reused only if it really is a FIFO.** `pipe_path` comes from the model or an
MCP caller, so `ensure_fifo` stats it with `symlink_metadata` (no symlink following) and refuses to
start if it exists and is anything other than a FIFO, naming what it found — an arbitrary-file
clobber guard copied from `socket_file`.

## I/O model (why O_RDWR)

The read FIFO is opened `O_RDWR | O_NONBLOCK` and driven by tokio `AsyncFd`:

- `O_RDWR` returns immediately (no blocking wait for a writer to appear) and keeps both a reader
  and a writer reference open, so `read()` returns `EAGAIN` — not a spurious `EOF` — every time an
  external writer closes. Opening `O_RDONLY` instead would deliver a `read()==0` EOF on every
  writer close and busy-loop the readable() poll.
- `O_NONBLOCK` is required for `AsyncFd`.

The response FIFO is opened the same way — `O_RDWR | O_NONBLOCK`, wrapped in `AsyncFd` — and
written with an awaited `writable()` loop bounded by `RESPONSE_WRITE_TIMEOUT` (5s). Writes buffer
in the kernel FIFO buffer even before a reader attaches, and the reader drains them when it opens
the path. The server never reads the response FIFO, so an external reader gets all the bytes.

**Why not the blocking form.** It used to be `O_RDWR` blocking, written with
`std::io::Write::write_all` from inside the async read loop. A FIFO holds 64 KiB and nothing here
drains the response side, so once a model with no reader attached had produced that much, the
`write_all` blocked **a tokio worker thread** — not merely this task — indefinitely. That is the
`block_on`/`blocking_lock` class of defect CLAUDE.md lists under "Known systemic issues", reached
without any explicit blocking call. Through `AsyncFd` the same condition parks only this task, and
the timeout unparks it and logs, so the server keeps reading.

## What the model sees and controls

**Event**: `named_pipe_data_received` — `data` + `encoding`. Emitted for every chunk read from the
FIFO. It is the only event and it is always emitted (no declared-but-never-fired traps).

**Action**: `write_named_pipe_data` — `data` + optional `encoding`. Returns `ActionResult::Output`,
written to the response FIFO. If no `response_pipe_path` was configured the output has nowhere to
go and is dropped with a WARN on both log channels (never silently).

### Encoding is explicit in both directions

Inbound: `data` is text when every byte is printable ASCII, hex otherwise, and `encoding`
(`"utf8"`/`"hex"`) says which. Outbound: `write_named_pipe_data` reads the same `encoding` field,
defaulting to `"utf8"`, and decodes hex when asked. No auto-detection — `"48656c6c6f"` is both
valid text and valid hex — so echoing a payload back unchanged means passing back the same `data`
*and* `encoding`. Invalid hex is an action error, not a panic. This mirrors the `send_tcp_data`
fix.

## Failure and lifecycle

- **`spawn()` awaits readiness** (both FIFOs created and opened, read fd registered with the
  runtime) and returns `Err` on any failure, so `server_startup` sets `ServerStatus::Error`.
- **Fail closed, but not silent**, on LLM error. Nothing the model asked for is invented; the
  reader instead gets one attributed, newline-terminated line carrying a *category* and nothing
  else — `WireFailure::prefixed_text()`, which is `&'static str`, so no part of the error, the
  backend URL, the model name or an `anyhow` chain can reach the pipe. Silence would be worse
  here: a reader parked in `read()` on a FIFO has no timeout of its own (`cat` blocks forever).
  The two categories are worded differently (`Overloaded` reads as retryable) because a byte
  stream has no status codes to distinguish them with. The full error goes to `tracing::error!`
  and to the status stream. When no `response_pipe_path` is configured there is no reply channel
  at all, so nothing is written and that is logged.
- **Three outcomes stay apart in the log** via a stable `decision=` tag, greppable by an
  operator: `decision=model_output` (the model answered with bytes), `decision=model_no_output`
  (the model answered with nothing — a real answer for a one-way sink), and
  `decision=fail_closed_overloaded` / `decision=fail_closed_llm_error` (netget could not ask).
  A model that says nothing must never be indistinguishable from a backend that fell over.
- The read/dispatch loop is registered via `register_server_task`, so `stop_server` aborts it and
  releases the fds. A `FifoCleanup` guard is moved *into* the task, so aborting the task drops the
  guard and unlinks every FIFO node this server created — cleanup on stop, even on abort.
  **Only nodes it created**: `ensure_fifo` returns whether it ran `mkfifo`, and a FIFO that was
  already on disk (an operator's `mkfifo /tmp/app.fifo`, another process's endpoint) is reused but
  never unlinked. Deleting a path we merely borrowed is deleting someone else's object.

## Batching

`BatchingMode::On`. A reader task drains the FIFO into a bounded channel
(`READ_QUEUE_CHUNKS`, 32 reads of at most 8 KiB) while a dispatcher task asks the model, so
chunks written during a call keep their own boundaries instead of coalescing in the kernel
buffer. With batching off the dispatcher answers one chunk per call; with it on, every chunk
waiting (up to `MAX_BATCH_EVENTS`) goes to `call_llm_batch` as one event each, the newest the
trigger. A full channel stops the reader, the 64 KiB FIFO fills and the writer blocks — that is
the back-pressure. There is no connection, so `connection_id` is `None` and the server keeps no
history whatever `history` says. `tests/server/named_pipe/batching_test.rs` asserts off and on,
control first.

## Not implemented

Accumulation (`wait_for_more`), multiple concurrent named-pipe servers sharing a
path, and any framing — each `read()` chunk is one event. Responses to `CloseConnection` /
`WaitForMore` are meaningless for a connectionless FIFO sink and are ignored.

## Verified

`tests/server/named_pipe/e2e_test.rs`: a real, independent `std::fs` writer writes `PING\n` to the
input FIFO; the mocked LLM answers `write_named_pipe_data` `PONG\n`; a real `std::fs` reader reads
`PONG\n` off the response FIFO. Asserts actual bytes on the pipe, not "it opened".

A second case drives the backend-failure path: the event matches no mock rule, so the LLM call
errors, and the test asserts the response FIFO carries an attributed `netget: …` category line
and none of the tokens that leaked historically (`✗`, `retries`, the backend URL, the model
name). Both halves matter — that the reader is answered at all, and that it is told nothing.
