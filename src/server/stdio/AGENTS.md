# Standard I/O (stdin/stdout/stderr) Protocol Implementation

Impersonates a program in a pipe. NetGet itself becomes the child process behind a pipe
(`someprogram | netget ... | otherprogram`): it reads chunks from its own stdin
(`stdio_input_received`), and the model decides what to emit on stdout (`write_stdout`) and stderr
(`write_stderr`). NetGet owns the plumbing; the model owns the payload — over the process's own
standard streams.

**State**: Experimental. **Platform**: Unix only; the whole module is `#![cfg(unix)]`.
**Privilege**: none.

## What it can reach on the host

Three file descriptors that already belong to the process: fd 0, fd 1 and fd 2. It creates no
file, opens no path, binds nothing and spawns no process. What the model can do is put bytes on
this process's stdout and stderr — so the blast radius is whatever the operator piped NetGet
into, which is the operator's choice, not the model's.

## Coexistence — the subtlety, and how it is resolved

This protocol takes over the process's real stdin/stdout, which collides with two things. Both are
handled:

1. **Interactive TUI / a terminal** — ratatui owns the terminal. `spawn()` returns `Err` (→
   `ServerStatus::Error`) when `stdin` is a TTY. Refuse, don't corrupt the UI.
2. **`--mcp` stdio** — MCP JSON-RPC owns stdin/stdout. `spawn()` returns `Err` when `--mcp` /
   `--mcp-stdio` is in the process argv (`--mcp-http` is a different flag and is allowed).

**The TTY check really does cover the TUI**, which is worth stating because it is not obvious
from this file alone: `Args::is_interactive` (`src/cli/args.rs`) requires **both** stdin and
stdout to be terminals before either UI is entered, and `src/cli/mod.rs` enters the dashboard
only under `args.is_interactive()`. So "the TUI is running" implies "stdin is a TTY", and the
stdio server's condition is a superset of it — there is no arrangement where the dashboard is
painting and this refusal does not fire.

Neither refusal is exercised by a test, and the reasons differ.
`running_as_mcp_stdio()` reads `std::env::args()`, which under a test binary is the harness's
argv, so an in-process MCP server (as `tests/mcp_stdio_test.rs` builds) cannot reproduce it — it
would need the real binary spawned with `--mcp` and driven over JSON-RPC. The TTY refusal needs a
pty on fd 0 of the *test process*, which is shared with every other test in a 100-thread run.
Both are checked by reading, above; neither should be assumed from a green suite.

Only one stdio server may run per process (an `AtomicBool` claim, released on task end/abort).

### Launching it (three working paths, live stdin — IMPROVEMENTS item 12, fixed)

All three of these hand the stdio server a live, never-EOF stdin:

- **`prog | netget --server stdio -- <instruction> | prog`** — the recommended shape. The
  `--server` flag returns from `run_server_direct` *before* NetGet's prompt resolution runs, so
  stdin is never touched during bootstrap.
- **`prog | netget "be a stdio filter" | prog`** — a natural-language prompt as a trailing arg
  now also works. `Args::get_actions_json` / `get_prompt` (`src/cli/args.rs`) only consult
  `piped_stdin()` when **no** trailing prompt is present; with a prompt given, stdin is left for
  the server.
- **actions-JSON / `--load`** — `{"actions":[{"type":"open_server","base_stack":"stdio"}]}` or a
  `.netget` file; returns before `piped_stdin()` is ever called.

The old hazard, now removed: `piped_stdin` used to do an unconditional blocking `read_to_string`
on stdin for any non-actions-JSON invocation (to support `cat prompt.txt | netget`). On an open
pipe that hung forever before any server started, so only actions-JSON could launch a live-stdin
stdio server. The read is now skipped whenever a trailing prompt or `--load` supplies the input,
and `cat prompt.txt | netget` (no trailing prompt) still reads stdin as before.

### stdout is kept pristine for the payload (IMPROVEMENTS item 12, fixed)

The non-interactive runner used to `println!` its status stream to **stdout**, interleaving
NetGet status lines with the model's `write_stdout` bytes. It no longer does: whenever a server
that owns the process's real stdout is running (currently only `stdio`), NetGet routes all of its
own status/log lines to **stderr** instead (`src/cli/non_interactive.rs` `emit_status_line` /
`server_owns_stdout`; `--server stdio` decides this up front in `run_server_direct`). Tracing
logs already go to stderr in non-interactive mode. So a downstream pipe receives **only** the
model's payload. Every other protocol keeps status on stdout, which the E2E harness parses.

## What the model sees and controls

**Events** — all attach `write_stdout` / `write_stderr` (and `close_stdio` where sensible), and all
are actually emitted:

- `stdio_started` — no fields. Emitted once at startup only under `send_first` (same conditional
  pattern as `socket_file_connection_opened`).
- `stdio_input_received` — `data` + `encoding`. Emitted for each chunk read from stdin.
- `stdio_input_closed` — no fields. Emitted when stdin reaches EOF (upstream closed the pipe).

**Actions**: `write_stdout` (`data`, `encoding`) → written to fd 1; `write_stderr` (`data`,
`encoding`) → written to fd 2, carried internally as a `Custom{"stdio_stderr"}` result;
`close_stdio` → ends the session. Explicit `utf8`/`hex` encoding, no auto-detection, invalid hex is
an action error not a panic — the `send_tcp_data` lesson.

## Failure and lifecycle

- **`spawn()` refuses cleanly** (returns `Err`, no half-started state) under a TTY, `--mcp`, or a
  second stdio server.
- **Fail closed** on LLM error, and *say so on fd 2*. stdout is the payload stream a downstream
  process parses, so nothing diagnostic is ever written there. stderr is where a Unix filter
  reports that it could not do its job, so it receives exactly one category-only line from
  `crate::utils::WireFailure` — `netget: backend at capacity, retry later` (Overloaded) or
  `netget: request could not be processed` (Unavailable) — and never the backend error, model
  name, URL or `anyhow` chain, which go to the log/status channel alone.
- **Three outcomes, distinguishable in the log** via a `decision=` tag (the `radius` separation):
  `model_answer` / `model_close` (the model acted), `model_silent` (the model answered with no
  actions — a real answer for a filter, which emits nothing), and
  `fail_closed_overloaded` / `fail_closed_unavailable` (the backend failed).
- Processing is serial (a pipe is a serial stream): one model call at a time. A reader task
  (`spawn_server_task`) drains stdin into a bounded channel (`READ_QUEUE_CHUNKS`, 32 reads of
  at most 8 KiB) while the dispatcher (`register_server_task`) asks the model; a full channel
  stops the reader and the pipe holds the upstream writer back. A `StdioClaimGuard` in the
  dispatcher releases the process claim on stop/abort.
- **Batching** (`BatchingMode::On`): with it off, one read per call; with it on, every read
  waiting (up to `MAX_BATCH_EVENTS`) goes to `call_llm_batch` as one `stdio_input_received`
  each, the newest the trigger. An EOF read in the same sweep is answered after the batch as
  its own `stdio_input_closed`. `tests/server/stdio/batching_test.rs` drives the real binary
  (`--server stdio --batching false|true`) and asserts off and on, control first.
- **History**: the stdin/stdout pair is registered as the server's one connection
  (`register_session`, addresses the `127.0.0.1:0` placeholder `socket_file` uses,
  `protocol_info` `{"stream": "stdin/stdout"}`), and its id goes to every model call, so the core
  keeps the declared `Last(40)` history. The connection is removed when the session ends (EOF,
  read error, `close_stdio`), and with it its history; `stop_server` removes the whole server.
  The batching test also asserts the second prompt carries the first exchange.

## Verified

`tests/server/stdio/e2e_test.rs` spawns the NetGet binary as a real child with piped stdin/stdout
and a line typed on its stdin answered by the mocked model with an uppercased line:

- `test_stdio_pipe_filter` — launched via **actions-JSON**; asserts `HELLO` on the child's real
  stdout (tolerant `contains`, stderr nulled).
- `test_stdio_server_flag_clean_stdout` — launched via **`--server stdio`** with a **live** piped
  stdin and the instruction as the trailing prompt (the recommended shape). Asserts stdout is
  **pristine** — only the model's `write_stdout` payload, none of NetGet's status vocabulary — and
  that the status text (`Using model` / `Waiting for connections`) instead appears on **stderr**,
  proving both IMPROVEMENTS-item-12 fixes: stdin not drained at bootstrap, status off stdout.

- `test_stdio_llm_failure_writes_category_to_stderr_only` — the backend-failure path: a
  category-only line on stderr, nothing on stdout, and none of the historically leaked tokens.

All three confirm their LLM interaction via `verify_calls()`.
