# NetGet — LLM-Controlled Network Protocol Server & Client

Rust CLI where an LLM (Ollama or any OpenAI-compatible endpoint) drives ~290 network protocols
as servers and ~250 as clients (about 310 distinct; `list_protocols` is the count). NetGet owns
the network stack; the model decides what to say on the wire, per request or through
deterministic handlers. Three ways to run it: the full-screen dashboard (default, `src/tui/`),
headless (`--mcp` / `--mcp-http`), and non-interactive one-shot (`--server`, `--client`,
`--load`, a prompt).

**This file is the rules, the commands and a map.** The reasoning, measurements and incident
history behind each rule live in `docs/agents/` and the per-module `AGENTS.md` files; the table
below says which to read before which kind of work. Three habits those documents teach:

- **Derive, never quote.** Protocol lists, counts and "current gaps" in any document go stale
  within weeks, in both directions. Run the command ("Deriving facts" below).
- **A document is a claim.** Per-protocol docs are frequently more aspirational than the code.
  Verify against source before acting on one, and correct it when it is wrong.
- **A zero nobody tried to turn into a one is not evidence.** A test you add must fail without
  your change; a control belongs in the same test as the claim it licenses.

Until 21 November 2026 all of that history was in this file, so a document that cites "the
root `AGENTS.md`" for a lesson or a story means the text now under `docs/agents/`
(`docs/agents/README.md` is the index).

## Read this before you…

| Before you… | Read |
|---|---|
| touch a protocol | `src/server/<p>/AGENTS.md` **and** `tests/server/<p>/AGENTS.md` (clients: `src/client/<p>/`, `tests/client/<p>/`), then check their claims against source |
| add a protocol, a startup parameter or a client command channel | `docs/agents/adding-a-protocol.md` |
| change shared plumbing: features and platform gates, history/batching, handler modes, privilege, ports, hosts, dependencies, logging, scheduled tasks | `docs/agents/architecture.md` |
| change what the model is offered or told: memory, the client restart check, `notify_operator`, decision events | `docs/agents/model-behaviour.md` |
| declare actions or events, or debug "the model never uses X" | `docs/agents/action-reachability.md` |
| set, cite or question a maturity rating | `docs/agents/maturity-history.md` (servers), `docs/agents/client-maturity-history.md` (clients) |
| write a decoder, a client, a failure path, or assume a subsystem is sound | `docs/agents/known-systemic-issues.md` (index at its top) |
| write or debug a test, a mock, a pty test, a ratchet, or run a sweep | `docs/agents/testing.md` |
| read a CI result or consider dispatching a workflow | `docs/agents/ci.md` |
| build, hit a disk or memory limit, reinstall the binary, need a system library | `docs/agents/building-and-disk.md` |
| commit while other agents are working, or tidy a tree you did not dirty | `docs/agents/collaboration.md` |
| change the dashboard | `src/tui/AGENTS.md` (`tests/dashboard_frame_test.rs` renders frames without a pty) |
| change MCP tools | `src/mcp_stdio/AGENTS.md` |
| change CLI flags or the non-interactive run | `src/cli/AGENTS.md` |
| change packet capture or adopt it in a protocol | `src/capture/AGENTS.md` |
| write a script handler | `src/scripting/AGENTS.md` |
| touch the browser build, or anything it compiles | `web/README.md` |
| change `site/` or deploy it | `site/AGENTS.md` |
| fuzz | `fuzz/README.md` |
| run or read real-model evals | `tests/eval/AGENTS.md`, `tests/llm_live/AGENTS.md`, `eval-results/` |
| look for known open work | `docs/planning/IMPROVEMENTS.md` |

## Module map

- `src/`: `cli/` (args, generic startup, non-interactive runner, scheduled-task tick) · `tui/`
  (dashboard) · `server/<protocol>/` · `client/<protocol>/` · `protocol/` (registries, metadata,
  spawn context, default ports, dependencies) · `state/` (`AppState`, intercepts, exchange
  history, SQLite) · `llm/` (backends, prompting, actions, handler dispatch, answer reuse) ·
  `events/` · `scripting/` · `mcp_stdio/` · `capture/` (pcap) · `logging/` · `utils/`
  (`wire_failure`, `clock`, `outbox`, `redact`, `sanitize`, `truncate`, `task_guard`, the depth
  screens).
- `tests/` (every test; `server/<p>/`, `client/<p>/`, `helpers/`, top-level ratchets) · `fuzz/`
  (its own workspace, nightly) · `crates/` (the wasm shims, `netget-web`, `netget-fixture`) ·
  `web/` · `site/` · `sdk/python/` · `scripts/` · `vendor/hyper` · `docs/` · `eval-results/`.

## Rules

Every bullet is CRITICAL unless it says otherwise. The document named in the table has the why.

### Protocols

- **Decentralized.** No per-protocol logic in shared code and no per-protocol `match`:
  `cli/server_startup.rs` and `cli/client_startup.rs` look the protocol up and call
  `spawn(ctx)` / `connect(ctx)`. A protocol's only central touchpoints are its `register()` line
  and `ALL_KNOWN_*` row (`protocol/server_registry.rs`, `protocol/client_registry.rs`), its
  dependencies in `Cargo.toml`, one `pub mod` in `src/server/mod.rs` or `src/client/mod.rs`, and
  one `pub mod` in `tests/server/mod.rs` or `tests/client/mod.rs`.
- **Never add a Cargo feature for a protocol**, and never write `#[cfg(feature = "<protocol>")]`.
  Every protocol compiles into every build of every platform that can build it. Gate by
  platform only — `not(target_arch = "wasm32")`, `unix`, or `all(unix, feature = "<lib>")` — on
  the `pub mod`, the `register()` and the test module, with dependencies in the matching target
  table. The only features are five system libraries (`libpcap`, `bluetooth`, `pcsc`, `libusb`,
  `libsmbclient`) and optional capabilities (`mcp-stdio`, `mcp-http`, `embedded-llm`, `sqlite`,
  `gpu`, `vendored-openssl`, `terminal-snapshot`).
- **No storage in a protocol**: no database, filesystem or persistence in its Rust code. The
  model supplies all data through actions, scripts, static responses or memory; the generic
  SQLite facility (`src/state/sqlite.rs`) is the one sanctioned exception.
- **Declare in `metadata()`, honestly**: state; `privilege_requirement` (no `PrivilegedPort`
  above 1023, no `Root` where `CAP_NET_RAW` is enough); `well_known_port`; `.history(…)` and
  `.batching(…)` (`Unsupported` unless you implemented batching); `.connectionless()` only where
  there is no connection concept at all (a UDP protocol with a transfer or session is *not*);
  `.answers_on_failure()` or `.deliberately_silent()`; `.max_inbound_bytes(…)`. Ratchets
  hold these.
- **Port and host are the caller's.** No port means the well-known port through
  `protocol::default_port`; an explicit port (`0` included) or host (`0.0.0.0` included) is bound
  as given, never replaced; no host means `127.0.0.1`.
- **Startup must report failure.** `spawn()` awaits readiness and returns `Err`. Every startup
  key is declared in `get_startup_parameters()`, every declared key is read, a `default` points
  at the constant the code uses, and `StartupParamError` is propagated with `?`, never
  `unwrap()`ed.
- **Track every task.** Register the accept loop with `register_server_task`; spawn
  per-connection tasks with `AppState::spawn_server_task` / `spawn_client_task` and `.await` the
  call; hold a child task a registered task awaits in `utils::task_guard::AbortOnDrop`.
  `stop_server` must end every connection.
- **Connection I/O.** Split streams with `tokio::io::split()`, never clone. Never hold a
  `Mutex`/`RwLock` guard across an `.await` that does I/O or calls the model. Pass the real
  `connection_id` to `call_llm` (`None` gets no history). Keep per-message bookkeeping off the
  `AppState` write lock (`with_server` for reads).
- **A per-connection writer task uses `utils::outbox`** with its `ConnectionCloser`: a peer that
  stops reading is cut off and its connection ended, never queued for.
- **Clocks**: `crate::utils::clock::{Instant, SystemTime, UNIX_EPOCH}`, never
  `std::time::…::now()`, which panics in the browser build.

### Actions, events and the model

- **No raw bytes or base64 in action parameters or event data.** Use structured fields. Where a
  field really is encoded, give it an explicit `encoding: "utf8"|"hex"` and make the executor
  decode what the description promises.
- **Every event type says what answers it** — `.with_actions(…)` or `.with_no_actions()` — every
  declared event has an emit site, and every advertised action runs with its own `example`
  through its own `execute_action`. A client's tool list is async ∪ sync ∪ the event's actions.
- **A client acts on the model's answer.** `let _ =`, a logged `.len()` or a one-step-deep
  follow-up are the same bug; follow the chain with a depth bound (`MAX_FOLLOWUP_DEPTH`, 4–8).
- **A client that loses its target refuses to connect.** A vendor SDK's default endpoint is
  production.
- **Handler modes**: script, static, manual (parks for a person; fails closed at
  `timeout_secs`), then the model. Scripts and static handlers are the default for anything
  deterministic. A static rule with empty `actions` is a real answer and costs no model call.
- **A yes/no event is `EventType::decision_only`.** `notify_operator` is a note on the
  operator's screen, never the wire answer. Facts about one peer go in connection memory,
  never instance memory.
- **The client restart check drops a repeat the instruction names no trigger for.** A client
  that relies on self-initiated retries needs `restart_check: false`; a scripted client is
  better written as a script or static handler.
- **A secret-bearing startup parameter is named so `utils::redact` masks it**, and a test
  asserts the secret appears in no event and no output.

### Failure

- **Fail closed.** When the model returns nothing usable, refuse; never fall through to a
  permissive default. Keep the model's rejection structurally distinct from its silence and tag
  the log (`decision=model_reject`, `decision=fail_closed_*`).
- **On model failure answer the peer in the protocol's own vocabulary** — never reset to Idle
  and write nothing — unless every reply the protocol defines is a positive assertion, in which
  case declare `.deliberately_silent()` and let the log carry the distinction.
- **The peer gets a category, the log gets the error.** Use `crate::utils::WireFailure`
  (`Overloaded` vs `Unavailable`, mapped to different codes); never interpolate an error into
  what goes on the wire.
- **Every decoder that can call itself, or follow a pointer or offset, needs a depth bound.** A
  stack overflow is a `SIGSEGV`, not a panic: the whole process dies. Check the crate, not its
  reputation. A byte cap bounds memory, not depth and not work.
- **Bound the size the peer declared before doing arithmetic on it**, and test both sides of
  every bound (`bound + 1` refused, the bound itself still completes).
- **No `block_on` or `blocking_lock()` from async code** (the panic is swallowed by
  `tokio::spawn` and the peer hangs; `grep PANIC netget.log`). No byte-index string slicing: use
  `utils::truncate`.
- **Build one `reqwest::Client` per process** through
  `llm::ollama_client::client_for_endpoint{,_with_timeout}`; a timeout against a healthy server
  means prove which step is stuck before blaming load.

### Logging

- **One call, both sinks**: `crate::logging::emit::Log` (`Log::to(&status_tx).info(…)`). Never a
  tracing macro beside a hand-typed `status_tx.send("[INFO] …")`. ERROR/WARN/INFO reach the
  operator; payloads, error chains and anything that may carry a credential go in a second
  DEBUG/TRACE line. No per-byte status messages.

### Tests

- **All tests live in `tests/`.** Never `#[cfg(test)] mod …` under `src/`; reach internals
  through `netget::` public APIs.
- **Declare every test directory** in `tests/server/mod.rs` / `tests/client/mod.rs`. An
  undeclared directory is silently never compiled or run (CI's `orphaned-tests` job checks).
- **Tests define behaviour.** When one fails, fix the implementation; change the test only when
  its expectation is wrong.
- **Mocked e2e** (no Ollama needed): `.with_mock()`, then `wait_for_mocks(30)` and
  `verify_mocks()` at the end. Rules are first-match-wins — express "then" as one rule with
  `respond_with_actions_from_event`. UDP-style protocols must echo the transaction id from the
  event. Check event ids and action names against the protocol, not the neighbouring suite.
  Under ~10 model calls per suite. Never a fixed sleep: wait for the condition. A server
  built with `..Default::default()` gets a default instruction and *does* consult the model;
  pass `instruction: Some(String::new())` for a model-free one.
- **Real-peer evidence fails rather than skips** when the peer is absent, and is never
  `#[ignore]`d. Check which server a test actually starts and which library sits at both ends.
- **Localhost only** (127.0.0.1 / ::1). Never contact an external endpoint.
- **Never build every test target at once** (no bare `cargo test`, no `--tests`): each binary is
  ~870 MB. Name targets or use `scripts/test_batches.sh`. `--test-threads=100` for one protocol,
  `32` for a whole tree.
- **Send a sweep to a file and parse the file.** No `test result` lines means it did not run,
  whatever the exit code. Never pipe it through `tail`.
- **Ratchets read the whole tree and new code trips them**; run the ones your change could
  touch (each is `tests/<name>.rs`, and `docs/agents/testing.md` says what each catches):
  `event_action_declarations_test`, `executable_examples_test`, `event_emit_sites_test`,
  `client_event_wiring_test`, `parameter_type_agreement_test`, `startup_param_drift_test`,
  `startup_param_defaults_test`, `history_batching_declaration_test`,
  `well_known_port_declaration_test`, `failure_mode_declaration_test`,
  `connectionless_audit_test`, `max_inbound_bytes_declaration_test`, `wire_failure_test`,
  `decision_tag_ratchet_test`, `hand_rolled_dual_logging_ratchet_test`,
  `control_character_sanitizer_ratchet_test`, `detached_task_drift_test`,
  `real_client_evidence_is_run_test`, `test_suite_hygiene_test`, `doc_paths_exist_test`,
  `doc_test_counts_test`. A baseline may only shrink.
- **A red run proves nothing alone**: diff against the same suite at unmodified `HEAD`, re-run a
  suspect in isolation — and if it reproduces at all, find the defect; "load-flaky" has hidden a
  real bug every time.

### Git and working beside other agents

- Commit as Matus Faro <matus@matus.io>, GPG-signed, Conventional Commits, one logical change
  per commit, **no co-author or AI attribution anywhere**:
  ```bash
  git config user.name 'Matus Faro' && git config user.email 'matus@matus.io' && \
  git config commit.gpgsign true && git config user.signingkey matus@matus.io
  ```
- **Never `git stash`, amend, rebase or squash. Merge with `--no-ff`.**
- **Never `git add -A`, `git add .`, `git add -u` or `git commit -a`.** Stage explicit paths and
  pass them to the commit too, with the message in a file (zsh runs backticks inside `-m`):
  ```bash
  git add -- <paths> && git commit -S -F /tmp/<your-task>-msg.txt -- <paths>
  ```
  Check `git diff --cached --name-only` first. For a file others may be editing (`Cargo.toml`,
  the registries, the `mod.rs` files) stage only your hunks; under heavy concurrency commit
  through a private index or your own worktree (`docs/agents/collaboration.md`).
- **Commit as you go, and push** (`git push origin master`, or your branch): pushing to `origin`
  is pre-authorised; force-pushing, deleting remote branches and rewriting history are not.
- **Never revert, restore or overwrite a dirty file you did not demonstrably write.** An error
  in code you did not touch is another agent mid-edit: pause, retry, report.
- **Never move a branch ref with `git update-ref`** except as a compare-and-swap from a private
  index.
- Shared files: `Edit` incrementally, never overwrite wholesale. Scratch files carry your task
  name. Verify `HEAD` in a throwaway worktree, not the shared working tree.
- **Never kill a `netget` process** (the maintainer runs `netget --mcp`). **Never `pkill
  cargo`**: `./cargo-isolated-kill.sh`. Do not run a sweep while anything else is building.
- Stop fanning out agents when they stall uniformly; that is the platform, and only waiting
  helps.

### Publishing and the outside world

- **A push to `master` starts no CI, and pushing authorises no workflow dispatch.** Local
  verification is the evidence; dispatch hosted runs only when asked.
- **The site does not deploy itself.** After changing `site/`, run `./site/deploy.sh` (it needs
  the bundle from `./web/build.sh`).
- **`site/` and `docs/` are both public** (`docs/` through GitHub Pages). Nothing secret in
  either; `site/*.md` and `deploy.sh` are excluded from the upload.
- **The installed binary** `/Users/matus/bin/netget` has every protocol: after changing the
  compiled surface, rebuild release with the **default** features (not `--all-features`) and
  swap it in with an atomic `mv`; smoke-test `--mcp` (`docs/agents/building-and-disk.md`).
- **Keep the repository root to `README.md`, `AGENTS.md`, the license and build entry points.**
  No session or status reports there. User docs are indexed in `docs/README.md`, agent notes in
  `docs/agents/README.md`; a lesson goes in the document that owns its topic, not in this file.

## Maturity bars

Maturity is `DevelopmentState` in each protocol's `metadata()`. A rating covers the surface the
protocol *implements* and must say so. Before changing one, read the history: every clause
below exists because its absence produced a false rating.

**Stable — all six:**

1. Two independent third-party clients complete a real session, in tests that fail rather than
   skip. Independent means of the server's own library *and codec*: count the libraries at
   both ends, and the verbs each client actually sends against the verbs the server implements.
2. The pcap oracle is green over its wire traffic (`tests/helpers/pcap_oracle.rs`), success
   paths included.
3. A fuzz target exists, **compiles today** and has run clean, with a depth bomb in its corpus.
4. Every declared bound has a test — size, idle timeout, connection cap, recursion depth — that
   fails when the bound is removed, checks the direction the bound governs and times the walk.
5. Both its `AGENTS.md` files were verified against source in the current pass; read the
   failure section as a list of assertions to test.
6. No `#[ignore]` and no skip-when-missing gate in its suite.

**Beta (server) — works against a real client:** the protocol's own third-party client
completes a real session in a test that is not `#[ignore]`d and fails when the client is absent.
Not evidence: the crate the server itself frames with; a generic HTTP client for a protocol
layered *on* HTTP; a client hand-written in the test; a codec used as a parser; a server that
implements only the front of the protocol. The evidence must cover every verb the rating names.

**Beta (client) — all four:** (1) the peer is a real third-party server, never NetGet's own and
never the crate the client is built on; (2) the test fails rather than skips when the peer is
absent (`tests/helpers/real_server.rs`); (3) a real session, not a connect; (4) the client acts
on the model's answer, asserted from the server's side of the wire and checked by emptying the
loop over the model's actions.

**Experimental** means "compiles and has a test", not "works". **Incomplete** hides a protocol
from the model and none may exist (`tests/no_protocol_is_hidden_from_the_model_test.rs`).
When you demote for missing evidence, check which rating that evidence still supports rather
than stepping down one notch.

## Deriving facts

```bash
# Protocols and their own maturity claims (at runtime: netget --mcp, then list_protocols)
grep -c "register(Arc::new" src/protocol/server_registry.rs src/protocol/client_registry.rs
grep -rn "DevelopmentState::" src/server/<p>/actions.rs
# Evidence behind every rating; --check exits 1 on a defective Beta
python3 scripts/beta_evidence_table.py [--all | --check | --experimental-with-evidence]
python3 scripts/beta_evidence_table.py --side client [--all | --check]
# Oracle and fuzz coverage (targets are named after the decoder: read their `use` lines)
grep -rln pcap_oracle tests/server/<p>/ ; grep -ln "<p>\|<decoder crate>" fuzz/fuzz_targets/*.rs
# What a protocol offers the model, and which events it raises
grep -c "\.with_actions(" src/server/<p>/actions.rs ; grep -rn "_EVENT" src/server/<p>/mod.rs
# Deliberately silent protocols; clients with a command channel
grep -rln 'deliberately_silent()' src/server
grep -rl 'register_command_channel(' --include=mod.rs src/client | wc -l
# Test modules under src/ (any hit is a violation); CI jobs and which block
grep -rnE '^[[:space:]]*#\[cfg\(test\)\]' src/ --include='*.rs'
python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); \
  [print(k, 'advisory' if v.get('continue-on-error') else 'BLOCKING') for k,v in d['jobs'].items()]"
```

Ratchet baselines are read out of the test file, never out of a document.

## Adding a protocol

Server (a client mirrors it against `client_registry.rs`, `src/client/mod.rs`,
`tests/client/mod.rs` and the `Client` trait; see `docs/planning/CLIENT_PROTOCOL_FEASIBILITY.md`):

1. `src/server/<p>/mod.rs` — the loop, `Log`, connection tracking, registered tasks.
2. `src/server/<p>/actions.rs` — `ProtocolActions`: `metadata()`, `get_startup_parameters()`,
   async and sync actions, `get_event_types()`, `execute_action()`.
3. `src/server/<p>/AGENTS.md` — implementation notes, library choice, limitations.
4. `src/server/mod.rs` — `pub mod`, platform-gated only if it cannot build everywhere.
5. `src/protocol/server_registry.rs` — `register()` and the `ALL_KNOWN_PROTOCOLS` row.
6. `Cargo.toml` — plain dependencies in the right target table. No feature.
7. `tests/server/<p>/e2e_test.rs` — mocked e2e.
8. `tests/server/<p>/AGENTS.md` — strategy, mock expectations, model-call budget.
9. `tests/server/mod.rs` — `pub mod <p>;`.

## Build, test, lint

`./cargo-isolated.sh` wraps cargo (sccache, logging to `./tmp/`, the **shared** `target/`):
serialize builds, and fix every error from one run before the next.

```bash
./cargo-isolated.sh test --test server -- server::<p>:: --test-threads=100     # one protocol
CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 scripts/test_batches.sh > /tmp/sweep.txt 2>&1
./cargo-isolated.sh test --test server --test client -- --test-threads=32 >> /tmp/sweep.txt 2>&1
cargo fmt --check
./cargo-isolated.sh clippy --locked --no-default-features \
  --features mcp-stdio,mcp-http,sqlite,terminal-snapshot --all-targets \
  -- -D clippy::correctness -D clippy::suspicious          # qualified groups, --all-targets
./cargo-isolated.sh --print-last | grep "error\[E"          # every compile error at once
./cargo-isolated.sh build --no-default-features --features mcp-stdio,mcp-http,sqlite  # no system libs
./test-e2e.sh <p>                 # mocked; --use-ollama for a real model
./web/build.sh && node web/test/smoke.mjs                   # browser bundle
```

A filter is a substring (`ftp::` also matches `tftp::`). Every build compiles every protocol, so
narrow a *run* with filters, never with features. Watch `df`: `target/` fills the disk, and at
zero bytes free no tool call can recover. Before pushing Rust changes run `cargo fmt --check`,
the affected suites with their real peers installed (a missing peer or zero matching tests is
missing evidence), the clippy line above, the ratchets your change could trip, and compile any
affected fuzz target in its own workspace. Report what you ran, what failed and what you could
not exercise.
