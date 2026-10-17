# Pseudo-Terminal (PTY) Protocol Implementation

Impersonates a program with a terminal. The server allocates a PTY with `openpty`, holds the
**master**, and role-plays: it reads what a terminal program types on the **slave**
(`pty_input_received`) and the model decides the bytes that appear on the terminal
(`write_pty_output`). A real client is any terminal program that opens the slave device —
`screen ./netget.pty`, `cat ./netget.pty`, a Python `open('/dev/ttysNNN')`.

**State**: Experimental. **Platform**: Unix only; the whole module is `#![cfg(unix)]`.
**Privilege**: none — a PTY is an unprivileged user resource.

## Master/slave orientation (important)

Normally a terminal emulator holds the master and the application holds the slave. Here it is
**inverted**: NetGet (the roleplayed program) holds the master, and the real client holds the
slave. Consequently:

- `write_pty_output` writes to the master → appears as bytes the client reads off the slave
  (what shows "on the terminal").
- The client writing to the slave → readable on the master → NetGet reads it as
  `pty_input_received`.

The slave is put in **raw mode** (`cfmakeraw`): echo off and canonical line-buffering off. Echo
off is essential — otherwise bytes written to the master would echo straight back and NetGet would
read its own output. Canonical off means bytes flow immediately without waiting for a newline, so
a prompt like `netget$ ` (no newline) reaches the client at once.

We use **libc directly** (`openpty`, `tcgetattr`/`cfmakeraw`/`tcsetattr`, `ttyname_r`, `fcntl`)
rather than `nix`, because `nix` is a dev-only dependency in this crate.

## Startup

| Parameter | Required | Meaning |
|---|---|---|
| `link_path` | no | symlink to create pointing at the allocated slave device, so a client can open a stable path |
| `send_first` | no | raise `pty_opened` on startup so the model can print a banner/prompt first |

No port; `default_binding()` returns empty binding defaults so `server_startup.rs` does not demand
one. `link_path` is symlinked to the kernel-assigned `/dev/ttysNNN`; an existing **symlink** there
is replaced, but a regular file/dir is refused rather than clobbered (same guard shape as
`socket_file`).

## What the model sees and controls

**Events**

- `pty_opened` — `slave_path`. Emitted once at startup, only under `send_first` (same conditional
  pattern as `socket_file_connection_opened`).
- `pty_input_received` — `data` + `encoding`. Emitted whenever the terminal program writes/types.

**Action**: `write_pty_output` — `data` + optional `encoding` (`"utf8"` default, `"hex"` for ANSI
escape sequences / binary). Both events attach this action, so the model always has a usable
vocabulary. Explicit encoding, no auto-detection, invalid hex is an action error not a panic —
the `send_tcp_data` lesson.

## Why the master never spins on EIO

Reading a PTY master returns `EIO` when **no** process holds the slave open. The server therefore
keeps its own `OwnedFd` on the slave open for the whole session, so clients can attach and detach
freely without ending the server; the read loop also treats a stray `EIO` as "no client attached"
and continues rather than dying.

That `continue` is only safe because it is preceded by `guard.clear_ready()`. `AsyncFd::try_io`
drops the cached readiness **only** when the closure reports `WouldBlock`; on any other outcome
readiness stays set, so the next `readable().await` returns instantly and the loop pins a core.
The heading is a claim about the code, not about the kernel — before the `clear_ready()` calls,
an `EIO` (or a `read()==0`) would have spun in exactly the way this heading calls impossible.

## Failure and lifecycle

- Both descriptors become Rust-owned immediately after `openpty`. Failures during raw-mode,
  symlink, or async registration setup therefore release the master as well as the slave.
- **`spawn()` awaits readiness** (PTY allocated, slave set raw, symlink created, master registered
  with the runtime) and returns `Err` on any failure → `ServerStatus::Error`.
- **Fail closed, but not silent**, on LLM error. A terminal client has no timeout of its own — it
  simply sits there — so writing nothing is the worst outcome. `dispatch` classifies the error with
  `crate::utils::WireFailure` and writes a **category only**:
  `\r\n[netget: backend at capacity, retry later]\r\n` for `Overloaded`,
  `\r\n[netget: request could not be processed]\r\n` for `Unavailable`. CRLF on both sides because
  `cfmakeraw` clears `ONLCR`, and a leading CRLF keeps the notice off a half-typed line. The error
  itself — backend URL, model name, `anyhow` chain — goes to `tracing::error!` and the status
  stream and **never** to the terminal.
- Three outcomes are distinguishable in the log by their `decision=` tag: `model_no_output` (the
  model answered with no `write_pty_output` — a legitimate answer on a terminal, so nothing is
  written), `fail_closed_overloaded`, and `fail_closed_llm_error`. PTY has no reject/deny verb, so
  there is no `model_reject` case to separate.
- The read/dispatch loop is registered via `register_server_task`, so `stop_server` aborts it and
  releases the fds. A `LinkCleanup` guard moved into the task removes the symlink on stop/abort.
- Processing is **serial** (a terminal is a serial line): one LLM round-trip at a time. A reader
  task drains the master into a bounded channel (`READ_QUEUE_CHUNKS`, 32 reads of at most
  8 KiB) while the dispatcher asks the model, so input typed during a call keeps its own read
  boundaries; a full channel stops the reader and the PTY's input queue holds the typist back.
- **Batching** (`BatchingMode::On`): with it off, one read per call; with it on, every read
  waiting (up to `MAX_BATCH_EVENTS`) goes to `call_llm_batch` as one `pty_input_received` each,
  the newest the trigger. `tests/server/pty/batching_test.rs` opens the slave in-process and
  asserts off and on, control first.
- **History**: one session per server, registered as its one connection (`register_session`;
  addresses are the `127.0.0.1:0` placeholder `socket_file` uses, `protocol_info` names the slave
  device), and its id goes to every model call, so the core keeps the declared `Last(40)`
  history. Per server rather than per terminal client because the server holds the slave open
  itself, so the master cannot tell one client attaching from the next. The connection is removed
  when the reader ends; `stop_server` removes the whole server. The batching test also asserts
  the second prompt carries the first exchange.

## Not implemented

Window size (`TIOCSWINSZ`) / `SIGWINCH`, job control / signals (raw mode disables `ISIG`),
multiple concurrent clients as distinct sessions, and any accumulation state machine.

## Verified

`tests/server/pty/e2e_test.rs`: a real terminal client opens the slave through the symlink, reads
the model's `netget$ ` banner (master→slave), types `whoami\n` (slave→master, surfaced as
`pty_input_received`), and reads the model's `root\n` answer. Asserts actual bytes on the
terminal.
