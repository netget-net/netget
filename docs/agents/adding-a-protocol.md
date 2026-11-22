# Adding a protocol

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

The nine steps are also in the root `AGENTS.md`; this is the version with the reasons, the
client side and the startup-parameter traps. `architecture.md` has what `metadata()` must
declare and why.

## Server checklist

1. `src/server/<protocol>/mod.rs` — server loop, dual logging, connection tracking, register
   the accept-loop `JoinHandle` via `AppState::register_server_task()` (required for
   `stop_server` to actually release the socket)
2. `src/server/<protocol>/actions.rs` — implement `ProtocolActions`: `metadata()` (state +
   privilege + `well_known_port` + `history` + `batching`, see "History and batching" in `architecture.md`),
   `get_startup_parameters()`, async/sync actions, `get_event_types()`, `execute_action()`
3. `src/server/<protocol>/CLAUDE.md` — implementation notes, library choice, limitations
4. `src/server/mod.rs` — `pub mod`, with a platform gate only if it cannot build everywhere
5. `src/protocol/server_registry.rs` — `register()` (same gate) and its `ALL_KNOWN_PROTOCOLS` row
6. `Cargo.toml` — its dependencies as plain (non-optional) dependencies, in the target table
   for the platforms that build it. **No feature.** See "Protocols are not Cargo features" in `architecture.md`.
7. `tests/server/<protocol>/e2e_test.rs` — mocked E2E (see `testing.md`)
8. `tests/server/<protocol>/CLAUDE.md` — strategy, mock expectations, LLM call budget
9. **`tests/server/mod.rs` — add `pub mod <protocol>;`** (see the mod.rs footgun in `testing.md`)

## Clients

Client protocols follow the same shape against `client_registry.rs`, `src/client/mod.rs`,
`tests/client/mod.rs`, and the `Client` trait. Consult `docs/planning/CLIENT_PROTOCOL_FEASIBILITY.md` first.
Clients are less finished than servers, but the blanket claim that their `JoinHandle` is never
stored is **stale** — `register_client_task` now has ~80 of 85 adopters (`bgp`, `ssh_agent` and
others among them). Check the specific client rather than assuming. Where it does bite, the
subtler form is worth knowing: aborting a task does **not** abort tasks it spawned, so BGP's
keepalive timer kept the socket alive after `remove_client()` even though the read loop was
registered. Register every task you spawn, not just the top one.

Two client-side gaps closed recently, both worth knowing before you touch a client:

- **Clients accept injected actions.** `AppState::send_to_client(client_id, action, timeout)`
  executes an action inside a running client's connection loop and returns a
  `ClientSendOutcome` (`src/state/client_handles.rs`). Until this existed, `Client::execute_action`
  was reachable *only* from inside each client's own loop, and only the LLM could produce an
  action for it — nothing, not even a scheduled task, could put bytes on the wire on demand.
  A client opts in with a ~25-line diff: `command_support::register_command_channel` plus a
  `tokio::select!` arm calling `handle_stream_client_command` (`src/client/command_support.rs`).
  **103 clients are wired as of 26 September 2026** — this paragraph said "`tcp` and `telnet`" for
  a long time after that stopped being true. Non-adopters simply never register (the dashboard
  greys out `[send]`); `grep -rl 'register_command_channel(' --include=mod.rs src/client` is
  the count. The channel is **bounded** — "client busy" backpressure is correct for
  user-initiated sends, unlike the unbounded status channels.
- **Client `event_handlers` are dispatched.** They were stored, validated and round-tripped for a
  long time while `get_client_event_handler_config` had *zero* callers, so every client event
  went to the LLM regardless. `try_execute_client_event_handler`
  (`src/llm/event_handler_executor.rs`) now mirrors the server dispatcher and is wired at the one
  choke point every client protocol uses — `client/llm_budget.rs::call_llm_for_client` — **before**
  the budget debit, so a deterministic handler costs no LLM budget. Its `Handled` variant returns
  raw action JSON rather than an `ExecutionResult`, because only the client's own loop owns the
  socket. Scripts get a client-shaped `ScriptInput` (`client` set, `server` absent and
  skip-serialized, so server scripts see byte-identical input).

## Startup parameters

**Startup parameters**: every key a caller may pass must be declared in
`get_startup_parameters()`. `StartupParams::new` and all `get_*` accessors return
`Result<_, StartupParamError>` (`src/protocol/spawn_context.rs`), and params are validated
*before* `add_server`, so an undeclared key or wrong-typed value produces a clean error naming
the key and listing the allowed ones, and leaves no half-registered server behind. They used to
panic, which over MCP killed the per-request task before it could reply — the caller hung with
no error and the server stuck in `Starting`. Propagate the error with `?`; never `unwrap()` it.

Two related traps when declaring parameters: a parameter that is declared but never read is
dead weight the model will try to use (nine were found in the cloud protocols alone), and a
parameter read but never declared is rejected at startup. Both are worth a grep when you touch
`get_startup_parameters()`.

**Declare `default` where the code falls back to a fixed value** — every read deadline
(`first_byte_timeout_secs`, `idle_timeout_secs`, `handshake_timeout_secs`) and size cap does.
Point it at the constant the code uses, `default: Some(json!(super::IDLE_TIMEOUT.as_secs()))`,
so the form, `get_protocol_docs` and the model's prompt show the number the server will actually
use; a literal copy drifts the first time someone tunes the constant.
`tests/startup_param_defaults_test.rs` refuses a literal (source scan, every feature set) and a
default that does not parse as its `type_hint` or sits on a required parameter (registry walk,
compiled protocols only). `default: None` is right where omitting the parameter switches a
feature off or derives the value from something else — no single number describes that.
