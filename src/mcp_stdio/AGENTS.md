# MCP Server Implementation (STDIO + HTTP)

## Overview

Runs NetGet as an MCP (Model Context Protocol) server, allowing MCP clients like
Claude Desktop and Claude Code to control protocol servers programmatically. Two
transports share the exact same tool implementation:

- **STDIO** (`--mcp`, feature `mcp-stdio`): one client over stdin/stdout. Used by
  Claude Desktop / Claude Code.
- **HTTP/SSE** (`--mcp-http PORT`, feature `mcp-http`): the MCP Streamable HTTP
  transport for remote/web clients. Multiple sessions share one `SharedState`
  (servers started in one session are visible to all). Bind address comes from
  `--listen-addr` (default `127.0.0.1`).

  **Every request is admitted by `http_guard::HttpGuard` first.** The tools are a
  control plane (`start_server` takes `event_handlers`, and a `script` handler runs
  `python3 -c <code>` as the operator), and rmcp's transport validates neither `Origin`
  nor `Host` — so without the guard a web page could drive the endpoint through DNS
  rebinding. Two modes: on a loopback bind with no token, `Host` and `Origin` must name
  a loopback host; with `--mcp-token` / `NETGET_MCP_TOKEN`, every request needs that
  bearer token and `Host`/`Origin` are free (a rebound page cannot know the token), and
  that is the only way `--listen-addr` may be a non-loopback address — `run_mcp_http`
  refuses to start otherwise. Bodies are capped at
  `http_guard::MAX_REQUEST_BODY_BYTES` (4 MiB) because rmcp collects a body in full
  before parsing it. `tests/mcp_http_guard_test.rs` pins the policy;
  `tests/mcp_http_transport_test.rs` drives the real binary over a socket.

The two flags are mutually exclusive.

## Architecture

```
MCP Client (Claude Desktop/Code, or remote HTTP client)
  | stdin/stdout OR HTTP/SSE (JSON-RPC 2.0)
  v
rmcp STDIO transport  /  rmcp StreamableHttpService
  |
  v
NetGetMcpService (tools.rs)
  |--- MCP tools (list_protocols, start_server, get_next_llm_request, ...)
  |--- AppState (shared server/client state)
  v
Protocol Servers (tcp, http, dns, ...)
  |
  v
OllamaClient (3 backends)
  |--- Ollama /api/chat        (local)
  |--- OpenAI /v1/chat         (remote)
  |--- Agent queue (--llm-agent): the calling MCP agent answers
```

## Library

- **rmcp** v1.2 - Official Rust MCP SDK
- Base features (`mcp-stdio`): `server`, `transport-io`, `client`
  (the `client` feature is enabled so the in-process smoke tests can drive the server)
- Added by `mcp-http`: `transport-streamable-http-server` (+ `axum` for the router/listener)
- **schemars** v1.0 - JSON Schema generation for tool parameters

## Entry Points

`netget --mcp` (alias `--mcp-stdio`) triggers `mcp_stdio::run_mcp_stdio()`:
1. Creates `NetGetMcpService` with AppState and tool router
2. Serves via `rmcp::transport::stdio()` (stdin/stdout), wrapped in `drain::DrainOnEof`
3. Detects modern per-request metadata / `server/discover` and uses rmcp's
   `serve_directly` entry point for MCP `2026-07-28`; legacy clients retain rmcp's
   normal `initialize` handshake. The adapter in `stdio.rs` checks modern metadata
   and adds `resultType` while preserving the SDK's framing, tool dispatch and cancellation.
   Its envelope decoder preserves `_meta` on parameterless requests such as `ping`,
   which rmcp 1.2's legacy `RequestNoParam` deserializer otherwise discards.
4. Waits until the client disconnects (stdin EOF) **and every ordinary request already received has been
   answered**, bounded by `drain::DRAIN_LIMIT` (300s). rmcp's serve loop stops the moment its
   input ends and drops the response of a handler still running, so a caller that writes its
   requests and closes stdin (a shell pipeline, a one-shot script) used to get the answer to
   `initialize` and nothing after it. `tests/mcp_stdio_eof_test.rs` pins it, with a control
   showing the unwrapped transport still loses the answer.
   Open `events/stream` subscriptions do not delay EOF draining; cancellation also
   removes an ordinary request from the drain count.

`netget --mcp-http PORT` triggers `mcp_stdio::run_mcp_http()`:
1. Builds `SharedState` once via `NetGetMcpService::create_shared_state()`
2. Wraps it in an rmcp `StreamableHttpService` (one `NetGetMcpService` per session,
   all sharing the same `SharedState`) mounted at `/mcp` on an axum router, behind
   the `admit` middleware (`HttpGuard::check`, then an `http_body_util::Limited` body)
3. Serves until the process is stopped

## MCP Tools

| Tool | Description | Maps To |
|------|-------------|---------|
| `list_protocols` | List available server/client protocols (both halves carry maturity + description) | `ServerRegistry`, `ClientRegistry` |
| `start_server` | Start protocol server | `server_startup::start_server_from_action()` |
| `stop_server` | Stop server by ID (aborts its tasks + cancels its scheduled tasks) | `AppState::remove_server()` |
| `list_servers` | List running servers | `AppState::get_all_servers()` |
| `server_status` | Detailed server status, including each connection's id and whether it accepts `send_to_peer` | `AppState::get_server()` |
| `start_client` | Connect a protocol client to a remote server | `client_startup::start_client_from_action()` |
| `stop_client` | Stop a client by ID (aborts its registered tasks) — see below | `AppState::remove_client()` |
| `list_clients` | List clients | `AppState::get_all_clients()` |
| `client_status` | Detailed client status | `AppState::get_client()` |
| `send_to_client` | Put one of a client's actions on the wire now (the dashboard's `[ send ]`) | `AppState::send_to_client()` |
| `send_to_peer` | Put one of a server's actions on the wire to one live connection (`[ message ]`) | `AppState::send_to_peer()` |
| `disconnect_peer` | Hang up one live connection from the server side (`[ disconnect ]`) | `AppState::send_to_peer()` with `close_connection` |
| `list_intercepts` | Requests parked by a `manual` handler, with what they may be answered with and time left | `AppState::list_intercepts()` |
| `answer_intercept` | Answer a parked request with actions, or with `[]` ("say nothing") | `AppState::resolve_intercept()` |
| `fail_intercept` | Refuse a parked request now — the peer gets the fail-closed reply | `AppState::dismiss_intercept()` |
| `get_status` | Overall NetGet status | AppState model + server count |
| `set_model` | Change LLM model | `AppState::set_ollama_model()` |
| `get_protocol_docs` | MCP-shaped protocol documentation | `mcp_stdio::docs::render_protocol_docs()` |
| `update_server_instruction` | Update just a running server's instruction | `AppState::with_server_mut()` |
| `update_server` | Update a running server in place by id (supply only changed fields) — see below | `cli::management::update_server()` |
| `update_client` | Update a running client in place by id (supply only changed fields) — see below | `cli::management::update_client()` |
| `list_access_logs` | Recent request/response entries (newest first) | `AppState::list_access_logs()` |
| `get_access_log` | Full request + response for one entry by id | `AppState::get_access_log()` |
| `export_rules` | Turn an instance's model-authored answers into `event_handlers`; optionally apply them and/or write a `.netget` file — see below | `llm::rule_export::export_rules()` |
| `stop_all` | Stop all servers | Iterate + remove all |
| `get_next_llm_request` | (agent mode) Fetch next queued LLM request; optional long-poll | `LlmRequestQueue::wait_and_claim()` |
| `answer_llm_request` | (agent mode) Answer a queued request with action JSON | `LlmRequestQueue::answer()` |
| `list_llm_requests` | (agent mode) List outstanding requests with event/connection summaries | `LlmRequestQueue::list()` |
| `get_llm_request` / `release_llm_request` | (agent mode) Recover or release a claim | `LlmRequestQueue::get()` / `release()` |
| `answer_and_get_next_llm_request` | (agent mode) Answer then wait in one call | Answer + claim |
| `get_agent_status` | (agent mode) Listener activity and recent timings | `LlmRequestQueue::status()` |

## Protocol documentation (`docs.rs`)

`get_protocol_docs` has its own framing (`src/mcp_stdio/docs.rs`) rather than
reusing the model's `read_documentation`, which is framed around the `open_server` /
`open_client` **actions** — an API no MCP caller can invoke. `docs.rs` renders what an
MCP caller actually has:

- the exact `start_server` / `start_client` arguments that apply to the protocol
  (interface-bound protocols get `interface`/`mac_address` instead of `port`/`host`);
- its event ids with field names and types, so `event_handlers` scripts can be
  written without guessing;
- its action names with parameter schemas and JSON examples — **async ones included**, since
  `send_to_client` and `send_to_peer` make them invocable from MCP;
- its `startup_params` schema — each parameter with `default: <v>` where the protocol declares
  the value it falls back to (`ParameterDefinition::default`) — privilege requirement and
  maturity;
- for a server, its `failure_mode` (what the peer gets when the model cannot answer) and
  whether it is `connectionless`.

What both say about the protocol itself — each event with its fields, each action with its
parameters and example, each startup parameter with its default — is written by the shared
renderers in `src/protocol/docs.rs` (`render_event`, `render_action`, `render_startup_param`),
which `--docs` uses too, so the three cannot drift. `tests/prompt/mod.rs` snapshots both the
model's `read_documentation` output and this module's output for `http` and `ssh`.

## `start_server` without a `port`

An omitted `port` means the protocol's **well-known port** (`ProtocolMetadataV2::well_known_port`
— 6379 for redis, 53 for dns), resolved by `protocol::default_port` inside
`start_server_from_action`, so `open_server`, `--server` and the dashboard get the same answer:

- 1024 or above: taken as is.
- below 1024: taken when `SystemCapabilities::can_bind_privileged_ports`, otherwise an
  OS-assigned port;
- already held on the bind address (probed with the port's own transport): an OS-assigned port.

Every fallback puts one line in the tool result saying which and why ("well-known port 53 needs
root; starting on an OS-assigned port"). A protocol with no well-known port (tcp, udp, the
HTTP-carried mocks, anything interface- or path-bound — the list and the reasons are in
`tests/well_known_port_declaration_test.rs`) starts on an OS-assigned port.

**An explicit `port`, `0` included, is never replaced**, and a taken explicit port is an error.
Every MCP test passes `"port": 0`, so none of them depends on the default. Before this, an omitted
port was an error ("requires 'port' parameter") for every protocol without a `default_binding()`
— most of them — while `get_protocol_docs` said `0` was the default; the docs now render the
resolved default for this process, and the `start_server` schema says the same.

## Client control surface

`start_client` / `list_clients` / `client_status` / `stop_client` mirror the
server tools and route through `cli::client_startup::start_client_from_action`,
exactly as `start_server` routes through `start_server_from_action`. They take
the same `instruction` / `event_handlers` / `startup_params` /
`initial_memory` / `feedback_instructions` / `scheduled_tasks` arguments plus a
`remote_addr`.

**`stop_client` really stops a client.** `AppState::register_client_task()`
stores every background task a client spawns in `ClientInstance.handles` (a `Vec`,
not a single slot — several protocols spawn more than one task), and
`remove_client()` aborts them all. Dropping a Tokio `JoinHandle` only detaches the
task, so the abort is what releases the socket and stops further LLM calls.

Client protocols register their tasks from `connect_with_llm_actions`. Four spawn
sites are still unregistered because they have no `app_state` / `client_id` in
scope: `amqp`, `oauth2`, and the non-async helper spawns in `maven` and
`bluetooth`. For those, `stop_client` still only drops the bookkeeping. Protocols
that spawn nothing at all (`arp`, `datalink`, `isis`, `mssql`, `nfc`, `sqs`,
`syslog`, …) have no task to abort and are unaffected.

Related: clients also carry a per-session LLM call budget
(`AppState::try_consume_client_llm_call`, default 100, override with
`NETGET_CLIENT_LLM_CALL_LIMIT`, `0` = unlimited) so a non-converging client cannot
loop forever.

## Driving by hand (`send_to_client`, `send_to_peer`, intercepts)

Six tools give an MCP caller what the dashboard's buttons give a human. Each wraps an
`AppState` method the dashboard already calls; what the tool adds is **validation before
anything reaches a running loop** (`src/mcp_stdio/control.rs`): an action whose `type` the
target cannot execute is refused with the list of names it can, instead of travelling into the
connection task and coming back as an executor error.

- **`send_to_client {client_id, action, timeout_secs?}`** — `action` is checked against
  `client_llm_action_set` (async ∪ sync, what the model is shown). A client with no command
  channel (not connected, or a protocol that never registered one) fails **at once**; it does
  not wait out the timeout. If the client's loop is parked on a manual question, the error
  says so and names the request — its loop drains no commands until that is answered.
- **`send_to_peer {server_id, connection_id, action, timeout_secs?}`** — checked against the
  server protocol's sync ∪ async actions; needs a peer handle (`server/peer_support.rs`),
  which `server_status` now reports per connection alongside the connection ids a caller
  needs. A protocol declaring `ProtocolMetadataV2::request_only` (HTTP and the protocols on
  plain HTTP request/response) is refused up front with its own reason — it can only answer a
  request, so there is nothing to send unprompted — and `server_status` says so above its
  connections. **`disconnect_peer`** sends the protocol's own `close_connection` through the
  same handle and refuses on a protocol that declares none.
- **`list_intercepts`** — every request parked by a `manual` handler: id, owner and
  connection, event type and data, the actions it may be answered with (`name(param*, …)`),
  and seconds until it fails closed (`PendingIntercept::timeout_secs`, recorded at park time).
- **`answer_intercept {intercept_id, actions}`** — checked against the firing event's own
  actions ∪ the protocol's sync actions (for a client, its whole set) plus the common actions
  — the catalog a static handler for that event is held to. A refused answer leaves the
  request waiting. **`[]` is a real answer**: nothing is written and the connection carries
  on, which is distinct from a timeout.
- **`fail_intercept {intercept_id}`** — refuses now; the dispatcher takes the fail-closed path
  (TCP half-closes, HTTP answers an error status). There is deliberately **no separate
  `dismiss_intercept` tool**: `AppState::dismiss_intercept` *is* the dashboard's `[ Fail
  closed ]` — dropping the reply sender is what wakes the dispatcher onto the fail-closed
  branch — so a second tool would be the same call under another name.

`tests/mcp_client_send_test.rs` and `tests/mcp_intercept_test.rs` assert each of these from the
peer's side of a real socket (bytes read, EOF observed), not from the tool's text.

## In-place update (`update_server` / `update_client`)

`update_server` / `update_client` amend a **running** server/client by id instead of starting a
second one, and route through `cli::management::update_server` / `update_client` (the same code
the TUI's management UI uses). Supply only the fields to change.

- **Hot-applied without dropping connections/reconnecting**: `instruction`, `event_handlers`,
  `initial_memory`, `feedback_instructions`, `scheduled_tasks`.
- **Requires a clean stop+start / reconnect** (connections dropped, the entity gets a **new id**):
  `port` / `host` for a server, `remote_addr` for a client, and `startup_params` for either.
- An unknown id and invalid `startup_params` **error cleanly and leave the running entity
  untouched** (validation happens before any restart). `scheduled_tasks` is parsed by the shared
  `parse_scheduled_tasks` first, so a malformed task array errors without touching the server.

Both tools re-sync `AppState`'s LLM client before applying, in case the update restarts the
entity. Prefer `update_server` over a second `start_server` when a server already exists;
`update_server_instruction` remains as the narrow "just the instruction" tool.

`memoize_ttl_secs` / `memoize_across_connections` (on `start_server`, `start_client`,
`update_server`, `update_client`) are hot-applied too; a changed setting starts an empty cache,
and the setting (not the cached answers) survives a restart. See "Reusing the model's answers".

## Reusing the model's answers (`export_rules`, memoisation)

Both features live in `src/llm/answer_reuse.rs` (shared) and `src/llm/rule_export.rs`, and
both read `AccessLogEntry::answered_by` — `"model"`, `"cache"`, `"rule"` or `"easy"` — which
the shared paths (`action_helper::call_llm`, `llm_budget::call_llm_for_client`) record.
Entries a protocol logs itself carry none and are ignored by both.

**`export_rules { server_id | client_id, apply?, fallback?, save_to? }`** derives static rules
from the instance's `model`/`cache` entries ("record with the model, replay without it"):

- per event type, the fewest event fields that explain why the answers differ become each
  rule's `match` (an HTTP method + path, a DNS name), plus every other field that was constant
  and that the recording never showed to be irrelevant — so a rule is narrower rather than
  wrong;
- per-request fields (`answer_reuse::PER_REQUEST_FIELDS`: `query_id`, `id`, `tag`, `xid`,
  `client_port`, …, top-level only) are never conditions, and where an answer echoes one it
  becomes a `{{event.<field>}}` reference;
- every rule is validated by `parse_event_handlers` and replayed against each recorded event it
  covers before it is offered; groups the model answered differently with nothing to tell them
  apart are listed as undetermined, and answers that failed, carried credentials, answered a
  batch, or also wrote memory/tasks/logs are listed as skipped;
- the returned table is the derived rules, then the instance's other rules, then the fallback:
  `keep` (default — the instance's own `*` rule), `llm`, or `manual`. `apply: true` hot-applies
  it through `management::update_server`/`update_client`; `save_to` writes the instance with that
  table as a `.netget` file (`save_load::save_with_handlers`) that `--load` replays.

Rule matching gained an optional `match` object on each handler (field path → exact JSON
value; a missing field reads as `null`), validated in `parse_event_handlers` and used by
`EventHandlerConfig::find_handler_for`. `find_handler(id)` still ignores it, which is the
"might a rule answer this kind of event" question protocols ask without an event in hand.

**Memoisation** (`memoize_ttl_secs`, off by default) answers an event identical to one the
model answered within the TTL — same type, same data less per-request fields, same instruction,
memory and per-event handler instruction — with the stored actions re-rendered for the new
event, and logs it `answered_by: "cache"`. Rules and scripts still run first; a batch, a
credential-bearing event, a failed answer, an empty answer, or one that wrote memory/tasks is
never stored or replayed. With `history` on, answers are per connection unless
`memoize_across_connections` is set. 256 answers per instance, oldest dropped.

Tests: `tests/answer_reuse_test.rs` (HTTP and DNS record → export → apply → replay with zero
model calls, the `.netget` round trip, memoisation hits/expiry/failures/connection scope).

## Server teardown and state reaping

`stop_server` / `stop_all` go through `AppState::remove_server()`, which owns the
whole teardown rather than leaving half of it to the caller:

- every background task registered with `AppState::register_server_task()` is
  **aborted** (dropping a Tokio `JoinHandle` only detaches the task, so the abort is
  what releases the listening socket);
- the scheduled tasks scoped to that server — **and** to its connections — are
  cancelled.

The cleanup used to live only in the TUI's stop paths (`cleanup_server_tasks`), so the
MCP tools left orphaned tasks behind on every stop. Doing it inside `remove_server` is
what stops that recurring — no caller can forget half the teardown.

`tests/mcp_stop_cleanup_test.rs` pins this from the tool surface rather than the state
API (`tests/server_stop_cleans_scheduled_tasks_test.rs` covers the latter), so a
rewrite of `stop_server`/`stop_all` that stops routing through `remove_server` fails a
test instead of shipping. It needs to see behind the tools — a tool result is text, and
`stop_server` reports "stopped" whether or not the tasks went with it — so
`NetGetMcpService::app_state()` exposes the service's `AppState` (a clone of the `Arc`,
i.e. the live state the tools mutate).

**Scheduled tasks now fire in MCP mode.** A dedicated ticker (`spawn_task_ticker`, started from
`create_shared_state` alongside the reaper) drives `execute_due_tasks_owned_public` on a **1s** cadence
(`TASK_TICK_INTERVAL_SECS`, matching the TUI event loop and the non-interactive runner, with
`MissedTickBehavior::Skip` so a slow batch cannot stampede catch-up ticks). So `start_server`'s
`scheduled_tasks` array and the `schedule_task` action now actually execute over both the STDIO and
HTTP transports (which share the one `SharedState`). Scoping is not re-implemented in the ticker:
`execute_due_tasks_owned_public` reads the live task set from `AppState` each tick, so Global / Server /
Connection scoping — and the removal of server-/connection-scoped tasks by `remove_server` on
`stop_server`/`stop_all` — are honoured exactly as in the TUI; only Global tasks persist a server
stop. The shared service owns the reaper, ticker and status-drain handles; dropping
its final STDIO/HTTP service owner stops them. Holding an AppState clone alone does
not keep the MCP timers running. A per-service cancellation token also cancels
already-launched MCP scheduled executions and marks their retained task definitions
Failed. Executions launched by another AppState owner are unaffected. The ticker
finishes any current claim/spawn batch before stopping, avoiding stranded claims.

`register_server_task()` stores a `Vec` of handles per server, like the client side:
a protocol with two long-lived loops (a UDP listener plus a TUN reader) gets both
aborted instead of only the last-registered one.

MCP mode also runs its own **reaper** (`spawn_state_reaper`, started from
`create_shared_state`), ticking every 5s over `cleanup_old_servers`,
`cleanup_closed_connections`, `cleanup_old_connections` and
`cleanup_old_conversations`. The TUI drives these from its event loop; MCP mode has
no such loop, so without the reaper an LLM-initiated `close_server` — which marks a
server `Stopped` rather than removing it — left the entry in `AppState` forever.

## Access Logs

Every network event a protocol server handles is recorded as an `AccessLogEntry`
in a bounded ring buffer on `AppState` (last **1000**, oldest dropped). The **request**
is the structured event data (e.g. HTTP method/path/headers); the **response** is
the action JSON the LLM produced (e.g. `send_http_response`). Recording happens
centrally in `action_helper::call_llm` after the event is handled, so it works for
every protocol without per-protocol wiring.

- `list_access_logs { limit? }` — newest-first summaries (id, age, owner, protocol, request→response,
  and what answered it where recorded).
- `get_access_log { id }` — full request and response JSON for one entry, with `answered_by`.

**Clients record too, and entries carry an owner.** `AccessLogEntry` has
`server_id: Option<u32>` and `client_id: Option<u32>`, exactly one set, both
`skip_serializing_if = "Option::is_none"` — so a server entry's JSON is
byte-identical to what it always was and existing consumers are unaffected.
`AppState::list_access_logs_for(owner, limit)` filters per instance (what the
dashboard's per-band request panes use). Client entries come from
`llm_budget::call_llm_for_client` and from injected `send_to_client` actions
(event type `injected_action`).

Two limitations worth knowing: only successfully-handled events are logged — a
request whose LLM call errors out produces no entry; and a **client** entry records
the actions that were *produced*, not executed, because execution happens later
inside the client's own connection loop, which does not report back. The
`send_to_client` path is honest about outcomes via `ClientSendOutcome`.

## Startup configuration

`create_shared_state` is MCP's equivalent of the TUI's startup block, and must stay in
step with it. `--mcp` / `--mcp-http` return from `cli::run()` **before** every
`configure_rate_limiter` / `set_selected_scripting_mode` / `set_event_handler_mode` call
site, so anything the TUI or `non_interactive` applies has to be applied here too or the
flag is silently dead in headless mode. It used to build a bare `AppState::new()`, which
hard-codes `RateLimiterConfig::default()`, `ScriptingMode::On` and
`include_disabled_protocols: false` — so `--llm-max-concurrent`, `--llm-token-limit`,
`--llm-token-window`, `--env`, `--no-scripts`, `--handler` and
`--include-disabled-protocols` were all accepted and ignored, and the LLM client was built
without `with_app_state` (no token accounting) or `with_mock_config_file`.

All of those are wired now, plus the model falling back to the saved setting and `Ask`
web-search degrading to `Off` (MCP has no terminal to prompt on, same as the
non-interactive runner). `tests/mcp_startup_config_test.rs` asserts each one from the
service's `app_state()`, so a new flag that skips this path fails a test.

## LLM Backend

Protocol servers started via `start_server` are driven by NetGet's own configured
LLM client (`SharedState.llm_client`), built once from the CLI args. Three
mutually-exclusive sources:

- **Ollama** (default) - local Ollama instance, or
- **OpenAI-compatible** - when `--openai-url` / `--api-key` are provided, or
- **Agent queue** - when `--llm-agent` is set (see below).

MCP **sampling** (routing protocol-server LLM calls back to the MCP client's model
via the spec's `sampling/createMessage`) is intentionally **not** supported: that
capability is being removed from the MCP spec. Agent-LLM mode below achieves the
same "the calling agent is the model" outcome with our own tool workflow, so it is
spec-independent.

## Agent LLM Backend (`--llm-agent`)

`netget --mcp --llm-agent` builds an `OllamaClient` backed by a
`crate::llm::agent_queue::LlmRequestQueue` instead of contacting any model. Every
protocol-server LLM call (all of them — `chat_with_tools` and `generate_with_format`
route through the new `LlmBackend::Queue` arm) enqueues a request and blocks until
the calling MCP agent answers it, or until `--llm-agent-timeout` (default 300s)
elapses, at which point the call errors and the connection resets to Idle — exactly
like an Ollama/OpenAI timeout.

Wiring: the queue is created in `create_shared_state`, embedded in the queue-backed
`llm_client`, and a clone of the `Arc` is stored in `SharedState.agent_queue`.
`start_server` already copies `SharedState.llm_client` into `AppState`, so every
server produced to the queue automatically. A placeholder model (`"agent"`) is
pre-seeded so `ensure_model_selected` never reaches out to Ollama's `/api/tags`.

Agent workflow:
1. `get_next_llm_request { wait_seconds?, lease_seconds?, include_prompt? }` claims
   the next request. It returns `structuredContent` plus a compact JSON text view:
   `request_id`, `context` (instance instruction, handler instruction, memory,
   connection history and explicit event data), deadline, offered action schemas,
   `claim_token` and lease expiry. Network events do not repeat the general model
   prompt. `include_prompt: true` retrieves the original messages; non-event calls
   retain their messages automatically. Validator corrections survive in `continuation`.
2. `answer_llm_request { request_id, claim_token?, actions }` hands actions to the
   protocol. New clients should echo the token; omitting it preserves old clients.
   A token from an expired/reassigned claim cannot answer or release the new claim.
3. `answer_and_get_next_llm_request` accepts the answer fields plus the get-next
   fields. It commits the answer first, then waits for the next event in one call.
4. `get_llm_request { request_id, include_prompt? }` retrieves even a claimed request
   after an interrupted tool result. `release_llm_request { request_id, claim_token? }`
   makes it immediately available again. Claims default to 60 seconds, configurable
   from 1 to 300; a long poll also wakes when an existing claim expires. Request
   deadlines still apply independently. Tokens differ across process restarts.
   `renew_llm_request { request_id, claim_token, lease_seconds? }` keeps an active
   claim alive; an expired claim cannot be renewed.
5. `list_llm_requests` includes owner/connection identifiers, protocol, event,
   HTTP method/path and deadlines. `get_agent_status` reports waiting consumers,
   claimed work, recent listener activity and the last 64 terminal request timings.

Every producer holds a queue cleanup guard. When a browser disconnects, a server
stops or the model future is otherwise cancelled, dropping that guard removes its
request immediately. A cancelled long poll also releases its listener count. A
claim whose tool response was lost is recovered by id, release, or lease expiry.

`get_agent_status` reports monotonic queue wait, agent wait and total wait, with
wall timestamps and instance/event identifiers for correlation. `answered` means
handed to the protocol, not delivered to a peer. HTTP separately logs
`request_received` and `response_ready` (handler completion, not proof of network
delivery). Lifecycle logs contain identifiers/timings, never event payloads.

### Supported listener client

With `mcp-http` compiled, `netget --agent-connect http://127.0.0.1:18040/mcp`
connects to an existing `netget --mcp-http 18040 --llm-agent` process. Create the
protocol server using the normal `start_server` MCP tool. The listener uses rmcp's
HTTP/SSE transport, keeps the session open, reconnects after transport/server
failure, and accepts `NETGET_MCP_TOKEN` for authenticated endpoints. Loopback
connections bypass environment proxies. TLS verification remains enabled.

Stdout is JSON lines: `{"type":"request","request":{...}}`. Write one answer line
on stdin: `{"request_id":1,"claim_token":"<echo from request>","actions":[{"type":"send_http_response","status":200,
"headers":{"Content-Type":"text/html"},"body":"<h1>Hello</h1>"}]}`. The listener
requires the host to echo the current claim token, rejecting delayed answers even
when numeric ids are reused after a restart. It renews its 60-second lease every
20 seconds while composing. If the client disappears, another listener can recover
its work after the lease. Status is on stderr; malformed
answers can be corrected without abandoning the request. Answers are acknowledged
before polling again; stdin EOF and Ctrl+C stop the client, releasing a current
claim. Input lines are capped at 16 MiB. An unacknowledged answer is checked against
its claim on reconnection, so a restarted server's reused numeric id cannot receive
an old answer.

The host must actively consume and answer these events. A persistent connection
alone cannot wake a chat agent after its host has ended the agent's turn. Hosts
supporting the Events extension or Claude Code Channels below can react to push.

Legacy notification paths (also available alongside the extension below):
- **Long-poll** (reliable default): `get_next_llm_request(wait_seconds)` blocks
  server-side (rmcp runs each request in its own task, so it never blocks other
  tools). `wait_seconds` is capped at 120 to stay under client tool-call timeouts.
- **FIFO push** (`--llm-agent-pipe <PATH>`): the new request id is written to the
  named pipe (created if absent) on each enqueue, so an idle agent can block-read it
  (`read id < pipe`) instead of polling. Best-effort — if no reader is attached the
  non-blocking write is dropped; the long-poll tool is the source of truth.
  Existing paths must be actual FIFOs, not regular files, directories or symlinks.
  Every notification also opens without following symlinks and checks the opened
  descriptor is still a FIFO, so replacing the path after startup cannot overwrite
  a regular file. The configured path and its parent directories remain trusted
  local configuration: these checks do not authenticate another FIFO's owner or
  protect traversal through attacker-controlled ancestor directories.

Note: the answer must use an action offered for that event. Using an action the
event does not expose (e.g. `close_connection` on `tcp_data_received`) triggers
NetGet's unknown-action retry, which enqueues a *second* request.

## Events extension and Claude Code Channels

The implementation pins **SEP-3415 revision `b08e4f9dd684f39d846d94089487fbeb28e666f5`**:
<https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3415>.
The older working-group design sketch differs: the SEP requires protocol
`2026-07-28`, puts `io.modelcontextprotocol/events: {}` under
`capabilities.extensions`, and adds `resultType: "complete"` to results. Modern
stdio clients use `server/discover` and per-request `_meta` fields
`io.modelcontextprotocol/protocolVersion`, `io.modelcontextprotocol/clientInfo`
and `io.modelcontextprotocol/clientCapabilities`; they do not initialize. Legacy
clients still initialize and can use the same event methods as a compatibility
backport. No list-change capability is advertised: the event catalog is static.

`events/list` advertises these event types and their input/payload schemas:

| Event | Source | Read/control tools |
|---|---|---|
| `llm.request.pending` | Agent backend queue submission, with `--llm-agent` | `get_next_llm_request` to claim, `get_llm_request` to inspect, `answer_llm_request` to answer |
| `intercept.pending` | A `manual` handler parks a request | `list_intercepts`, `answer_intercept`, `fail_intercept` |
| `access_log.recorded` | Central server/client access-log insertion | `get_access_log` |

Each descriptor supports exact optional identifier filters (`request_id`,
`intercept_id` or `access_log_id`, plus `server_id`, `client_id`, `connection_id`),
`event_type`, and `protocol` where available. Unknown keys or wrong types fail
`InvalidParams`. Payloads contain identifiers and deadlines, never full prompts,
wire bodies, memory or claim tokens. Retrieve authoritative state through the tools:
an observed request may already have been claimed, answered or expired. The queue
and intercept code retain their existing validation and answer semantics.

**Polling**: `events/poll {name, arguments?, cursor?, maxAgeMs?, maxEvents?}`.
A missing/null cursor starts at now with an empty batch and a fresh cursor.
Responses carry `events`, `cursor`, `truncated`, `hasMore` and `nextPollMs` (1000).
The default batch is 100, capped at 1000. Drain `hasMore` immediately. Polling is
a protocol request, not a tool call, and never claims work.

**Stdio push**: `events/stream {name, arguments?, cursor?, maxAgeMs?}` stays open.
`notifications/events/active` confirms the start position, followed by
`notifications/events/event`. Every message carries the parent JSON-RPC request
id at `params._meta["io.modelcontextprotocol/subscriptionId"]`. Quiet streams
send `notifications/events/heartbeat` every 30 seconds, carrying the checked
cursor. Cancel with `notifications/cancelled {requestId}`. Each session permits
64 concurrent streams, separate from ordinary tool calls; cancellation and EOF
release them. Clients must exempt streams from ordinary request timeouts.

The shared journal (`events/journal.rs`) retains the latest **1024 occurrences**
across all event types, in memory. Stable process-unique event IDs support
deduplication across deliveries. Cursors advance over nonmatching events too.
Retention overflow, a previous process's cursor, a cursor ahead of the current
position, or `maxAgeMs` skipping history sets `truncated: true`. A push gap sends
a new `active` before continuing. Malformed cursors are `InvalidParams`.
State and history do not survive restart; clients can reconcile through the tools.

**Claude Code Channels**: stdio also advertises
`experimental: {"claude/channel": {}}`. After legacy initialization, actionable
`llm.request.pending` and `intercept.pending` occurrences are emitted as
`notifications/claude/channel {content, meta}`. `content` is the JSON occurrence;
`meta` contains string `event` and `event_id` values. Modern clients can opt in
with `experimental["claude/channel"]` in the per-request client capabilities of a
`subscriptions/listen {notifications:{}}` request. Its first notification is
`notifications/subscriptions/acknowledged`; channel messages carry the parent
subscription ID in `_meta`, and cancellation/EOF end that stream. Declaring the
capability on an ordinary modern tool request does not subscribe to channels.
Access logs are available through Events but do not flood the agent channel.
If a slow channel consumer falls behind retained history, a JSON `events.gap`
observation carries `truncated: true`; reconcile pending work through the tools.
Claude Code's own per-session opt-in decides whether it consumes the channel;
server advertisement alone cannot enable it. During research preview a configured
bare server uses `claude --dangerously-load-development-channels server:netget`.
The development flag is interactive-only; organization policy still applies.
There is no channel delivery acknowledgment. Choose one delivery mechanism, or
deduplicate by `eventId` if consuming more than one. Nothing is auto-claimed.

No webhooks are advertised or implemented. `events/subscribe` / `events/unsubscribe`
return `Unsupported` (`-32026`, deliveryMode=webhook). Unknown events use `NotFound`
(`-32023`), and the stream cap uses `ResourceExhausted` (`-32025`).
HTTP sessions retain the old transport and only advertise poll delivery in their
event descriptors; modern negotiation and push/Channels are specific to stdio.

`tests/mcp_events_stdio_test.rs` uses actual JSON-RPC lines through the binary's
stdio serving path, independent of rmcp's client models. It checks discovery,
advertisement, poll/replay/filter/gap behavior, concurrent streams, heartbeats,
cancellation/EOF, and real TCP replies driven by Events and Channels.

## Logging

All logging goes to stderr (stdout is JSON-RPC). Status messages from protocol servers are drained to stderr with `[NETGET]` prefix.

## Limitations

- **STDIO is single-session**: one client at a time (HTTP supports many)
- **No elicitation yet**: Interactive config gathering not implemented
- **No dynamic tool list**: All tools exposed from start (no `tools/list_changed`)
- **No sampling**: protocol servers always use NetGet's own LLM backend, never the MCP client's model

## Testing

Automated in-process smoke tests (no Ollama, no real stdio) live in
`tests/mcp_stdio_test.rs` — see `tests/mcp_stdio_CLAUDE.md`. Teardown regressions are
pinned separately in `tests/mcp_stop_cleanup_test.rs`, and the hand-driving tools in
`tests/mcp_client_send_test.rs` and `tests/mcp_intercept_test.rs`. All drive the real tools over
`tokio::io::duplex`, so they are root-level test files rather than entries in
`tests/server/mod.rs` and are compiled without the mod.rs footgun.

```bash
# Build
cargo build --no-default-features --features mcp-stdio,sqlite  # STDIO
cargo build --no-default-features --features mcp-http,sqlite   # HTTP

# Smoke tests
./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
    --test mcp_stdio_test -- --test-threads=100

# Claude Desktop config (claude_desktop_config.json):
{
  "mcpServers": {
    "netget": {
      "command": "/path/to/netget",
      "args": ["--mcp", "--model", "qwen3-coder:30b"]
    }
  }
}

# HTTP transport:
netget --mcp-http 8080          # serves MCP at http://127.0.0.1:8080/mcp
```

## Control validation boundary

MCP control rejects action names outside the offered vocabulary. Protocol action
executors own parameter semantics and types; `check_action_types` is deliberately
not a universal JSON-Schema validator. Script handlers are trusted local code,
with the resource/cleanup rules described in `src/scripting/AGENTS.md`; remote
untrusted script execution is outside this control interface's trust model.
