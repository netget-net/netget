# Notes for agents (and people) working in this repository

The root `AGENTS.md` is loaded into every agent session, so it holds only rules, commands
and pointers. What is behind each rule — the incident, the measurement, the protocol it was
found in — is here, one topic per file. The text was moved, not rewritten: a dated claim is
dated for a reason, and a list or count should be re-derived with the command beside it.

| File | What is in it |
|---|---|
| `architecture.md` | Modules, decentralization, platform gates instead of protocol features, connections, history and batching, handler modes, action and event design, privilege, well-known ports, hosts, dependencies, logging, bounded channels, scheduled tasks |
| `adding-a-protocol.md` | The server checklist, the client side (injected actions, client `event_handlers`), startup-parameter traps |
| `model-behaviour.md` | Memory scopes, the client restart check and its measurements, `notify_operator`, decision events |
| `action-reachability.md` | Six ways a declared action or event never reaches the model |
| `maturity-history.md` | Server ratings: the Stable passes, every Beta promotion, demotion and near-miss |
| `client-maturity-history.md` | The client bar and each pass that applied it |
| `known-systemic-issues.md` | Twenty-five defect classes found across the tree, indexed |
| `testing.md` | Test location, the mod.rs footgun, mocks, sweeps, pty traps, the ratchet table |
| `ci.md` | Workflows, jobs, which block, hosted validation, search versus gate |
| `building-and-disk.md` | `cargo-isolated.sh`, clippy, disk, the installed binary, system libraries |
| `collaboration.md` | The multi-agent git incidents and the git rules |

Topics a module owns are in that module's own file: the dashboard in `src/tui/AGENTS.md`,
MCP in `src/mcp_stdio/AGENTS.md`, the command line in `src/cli/AGENTS.md`, packet capture in
`src/capture/AGENTS.md`, script handlers in `src/scripting/AGENTS.md`, the browser build in
`web/README.md`, the website in `site/AGENTS.md`, fuzzing in `fuzz/README.md`, and each
protocol in `src/server/<protocol>/AGENTS.md` and `tests/server/<protocol>/AGENTS.md` (clients
likewise).

Everything under `docs/` is public: GitHub Pages serves it (see `site/AGENTS.md`). Put
nothing here that should not be.

## Where documents go

Keep the repository root focused on `README.md`, `AGENTS.md`, the license and build
entry points. User documentation is indexed in `docs/README.md`: installation guides in
`docs/guides/`, living backlogs and protocol plans in `docs/planning/`, and superseded
designs/reports in `docs/archive/`. Evaluation reports live with their data in
`eval-results/`. Keep historical evidence; do not add new session/status reports at root.
