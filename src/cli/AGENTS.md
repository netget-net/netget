# The command line (`src/cli/`)

Argument parsing (`args.rs`), the generic server and client startup paths
(`server_startup.rs`, `client_startup.rs` — no per-protocol `match`, see
`docs/agents/architecture.md`), the instance forms every surface applies through
(`management.rs`), the non-interactive runner (`non_interactive.rs`), the scheduled-task tick
(`tasks.rs`) and the native-crash terminal restorer (`crash_restore.rs`, described in
`docs/agents/building-and-disk.md`).

## Ways to run, and the non-interactive run

Three ways to run it: interactive TUI (default), headless (`--mcp` / `--mcp-http`, see
`src/mcp_stdio/AGENTS.md`), and non-interactive one-shot (`src/cli/non_interactive.rs`).

A non-interactive run (a prompt, `--load`, `--server`, `--client`) serves **every** server it
started until all have stopped or Ctrl+C, keeps a clients-only run alive while any client is
connected, and exits **non-zero** if anything it was asked to start failed. `--run-for <SECS>`
and `--exit-after-events <N>` end it with status 0; the event count is the access log's
monotonic total (`AppState::access_log_total`), so it counts every handled event on every
instance whoever answered it. `--ready-file <PATH>` writes a JSON report of every server's bound
address (and every client's target and status) once all of them have started — atomically, and
after removing any stale file at the path, so its appearance is the readiness signal for a
process started on port 0; a run that fails to start never writes it, and MCP and the TUI
refuse the flag. `tests/non_interactive_run_limits_test.rs` drives the binary. `--server <p>`
takes `--port`, `--host`, `--server-params` and `--server-handlers` (MCP's `event_handlers`
shape, as `--client-handlers` is for `--client`); when a `*` rule answers every event the run
asks no model and needs none (`tests/cli_server_direct_test.rs`). `--server` and `--client`
take a protocol *name*, resolved exactly as MCP's `start_server` / `start_client` resolve one
(`resolve_name`: the canonical name, or a stack name or alias only one protocol declares; an
alias several share is refused with their names, free text with suggestions —
`tests/cli_protocol_names_test.rs`). `-h` is a one-line-per-flag screenful; `--help` has each
flag's detail and the examples (`tests/cli_help_test.rs`). The test
fixture helpers built on it are `crates/netget-fixture` (Rust, depends only on `serde_json`) and
`sdk/python/netget_fixture` (stdlib, plus a pytest plugin); `tests/fixture_helpers_test.rs`
runs both against this tree's binary and needs `python3` with pytest. Neither is published.
