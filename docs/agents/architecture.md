# Architecture: the shared plumbing every protocol stands on

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

Contents: modules and decentralization · protocols are not Cargo features · connections ·
history and batching · actions and handling modes · action and event design rules ·
privilege, ports, hosts and dependencies · logging and bounded channels · scheduled tasks.
What the model is offered and told (memory, the restart check, `notify_operator`,
decision events) is in `model-behaviour.md`.

## Modules and decentralization

**Modules**: `cli/` (TUI, startup, args) · `server/<protocol>/` · `client/<protocol>/` ·
`protocol/` (registries, metadata, spawn context) · `state/` (app state) · `llm/` (backends,
prompting, actions) · `events/` (coordination) · `scripting/` (deterministic handlers) ·
`mcp_stdio/` (MCP server).

**Decentralization (CRITICAL)**: no centralized per-protocol logic. Each protocol implements
traits independently. The only legitimate central touchpoints are:

- `protocol/server_registry.rs` / `protocol/client_registry.rs` — one `register()` line
- `Cargo.toml` — the protocol's dependencies (no feature; see "Protocols are not Cargo features")
- `src/server/mod.rs` / `src/client/mod.rs` — one `pub mod`
- `tests/server/mod.rs` / `tests/client/mod.rs` — one `pub mod` (see the mod.rs footgun in `testing.md`)

## Protocols are not Cargo features (CRITICAL)

**Never add a Cargo feature for a protocol.** Since October 2026 every protocol compiles into
every build of every platform that can build it; `#[cfg(feature = "<protocol>")]` does not
exist anywhere, and a new one is a defect. crates.io caps a crate at 300 features, NetGet had
297, and a per-protocol feature list also hid protocols from whoever forgot to name one.

What gates a protocol is the platform, written as a target cfg:

| The protocol builds on | Gate (`#[cfg(...)]` on its `pub mod`, `register()` and test module) | Its dependencies go in |
|---|---|---|
| every target, browser included | none | `[dependencies]` |
| native targets, not the browser (real sockets, processes, C libraries) | `not(target_arch = "wasm32")` | `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` |
| Unix only (raw sockets, pty, Unix pipes) | `unix` | `[target.'cfg(unix)'.dependencies]` |
| Unix, linking a system library | `all(unix, feature = "<lib>")` | `[target.'cfg(unix)'.dependencies]`, `optional = true`, listed in that feature |

The only features are the five system libraries (`libpcap`, `bluetooth`, `pcsc`, `libusb`,
`libsmbclient`, all default-on) and optional capabilities (`mcp-stdio`, `mcp-http`,
`embedded-llm`, `sqlite`, `gpu`, `vendored-openssl`, `terminal-snapshot`). A protocol that
needs a new system library gets a new library feature, named after the library, not after
the protocol. Tests never gate on the browser (integration tests do not build for wasm32), so
under `tests/` only `unix` and the library features appear.

Add the protocol to `ALL_KNOWN_PROTOCOLS` / `ALL_KNOWN_CLIENT_PROTOCOLS` with what it needs
("a native build (not the browser)", "the `libpcap` feature, on Unix", …) — that string is
what the "not compiled into this build" error tells the user.

`cli/server_startup.rs` and `cli/client_startup.rs` are **fully generic** — they look the
protocol up in the registry and call `spawn(ctx)` / `connect(ctx)`. There is no
per-protocol match statement. Do not add one.

## Connections

**`ProtocolConnectionInfo`** (`state/server.rs`) is a generic `serde_json::Value` wrapper,
not an enum. Adding a protocol does not require touching it.

**Connection I/O**: split `TcpStream` with `tokio::io::split()` (never clone). Never hold a
`Mutex`/`RwLock` guard across an `.await` that performs I/O or an LLM call — acquire, copy
out what you need, drop the guard in an inner scope, then await.

**Per-connection state machine** (Idle → Processing → Accumulating) prevents concurrent LLM
calls on one connection and queues data arriving mid-call. There is no shared state-machine
type: each protocol that needs one holds its own. Copy the TCP implementation
(`src/server/tcp/mod.rs`) as the reference. **Most servers do not have one**: about 110 read,
call the model and write in one task, so what arrives mid-call waits in the socket — that is
the shape batching (below) has to work with.

## History and batching

**History and batching (CRITICAL — every protocol declares both).** The model used to see each
event alone; a telnet peer asking "what did I just say?" was answered from a prompt holding only
that question. Two per-instance settings now exist, each with a default the protocol declares
in `metadata()` and `tests/history_batching_declaration_test.rs` requires:

- `.history(HistoryMode::Last(SESSION_HISTORY_ENTRIES))` (40) wherever a peer's next message is
  read in the light of its last — streams, command sessions, databases, peering, every client —
  and `.history(HistoryMode::Off)` where each request stands alone (HTTP family, DNS, lookups,
  datagrams, telemetry). The record is kept in shared code: `AppState::record_access_log` writes
  each event and what answered it (model, script, static rule, person, operator send) into the
  connection's `ExchangeHistory` (`src/state/exchange_history.rs`), and `call_llm` /
  `call_llm_for_client` render it ahead of the event, bounded at 4 KB, credentials dropped. **A
  protocol only has to pass the real `connection_id` to `call_llm`** — `None` gets no history.
- `.batching(BatchingMode::On | Off | Unsupported)`: whether events that arrive while the model
  is answering are delivered together in one follow-up call
  (`action_helper::call_llm_batch`). This needs the protocol's cooperation, so declare
  `Unsupported` unless you implemented it; asking for batching on an `Unsupported` protocol is
  refused at start. Two reference implementations: `telnet` (a sequential reader collects every
  line already waiting after the first — `TelnetLineReader::lines_already_here` — and hands the
  `Vec<Event>` to `call_llm_batch`) and `tcp` (its mid-call byte queue is answered whole when
  batching, one read at a time when not). Never batch where each request owes its own
  correlated reply (HTTP, DNS, RPC).

  **Clients batch the same way**, through `llm_budget::call_llm_for_client_batch` (one budget
  unit per batch; falls back to one-by-one when the client has batching off or a rule answers
  any event). A client that calls the model inline in its read loop cannot batch as it is: what
  the server sends during the call merges in the kernel buffer into one read, so off and on are
  indistinguishable. The reference shape is the `tcp` and `telnet` clients — a registered reader
  task (`spawn_client_task`) feeding a bounded queue, and an answering loop that takes one read
  per call (off) or drains everything waiting (on). `tests/client_batching_test.rs` is the test
  shape: a local listener sends during a deliberately slow call, batching off as the control.

Both are overridable per instance everywhere an instance is started or updated (`history` /
`batching` on `ServerForm`/`ClientForm`, `open_*`/`update_*`, MCP, `--history`/`--batching`,
the dashboard form) and hot-applied. Memory is separate: it is what the model chooses to keep;
history is what happened and ends with the connection.

## Actions and handling modes

**Actions**: protocols implement `ProtocolActions` (`src/llm/actions/protocol_trait.rs`) with
async actions (user-triggered) and sync actions (network-event-triggered), in
`src/server/<protocol>/actions.rs`. Clients implement `Client` (`llm/actions/client_trait.rs`).

**Handling modes** — a matched `event_handlers` rule decides who answers:
1. **Script handler** — inline Python/JS, runs in-process, no LLM call
2. **Static handler** — fixed actions, no LLM call
3. **Manual handler** — the event parks (`src/state/intercepts.rs`) and a **human** composes
   the answer at the dashboard; no answer within `timeout_secs` (default 300) **fails closed**
   through the same path as an LLM failure. The dashboard shows parked events as
   "⚠ waiting for YOUR answer" rows. Instances created interactively through the dashboard
   default to a `*` → manual rule — the human is there, driving; instances the model creates
   through its own tools get no such default. **Dashboard-created clients refine this**: the
   `*` → manual rule is preceded by one zero-action static rule per connect event (each
   `<proto>_connected` id the client's registry entry declares), so establishing a connection is
   "answered with nothing" and does not park — several clients handle their connect event inline
   in `connect()`, so parking it would stall creation itself. Everything after the connect
   handshake still falls through to `*` → manual. **Servers get the same treatment for the events
   they raise on every connection** — `EventType::raised_on_every_connection()`, today
   `telnet_connection_opened` and `websocket_connection_opened` — one zero-action static rule each, then `*` → manual. Without the
   rule a person would be asked about every connection before its first message. `tcp` and
   `tls` raise their connect event only with `send_first`: raising it everywhere was measured to
   cost a model call per connection and to make a small model greet clients nobody asked it to.
4. **LLM** — one model round-trip per event (the fallback when no rule matches)

Scripts and static handlers are the right default for deterministic behavior (echo, canned
responses, routing). Reserve the LLM for responses that genuinely require reasoning.

A rule may narrow itself with `"match": {"method": "GET", "path": "/a"}` — event-field paths to
exact values, all of which must hold (`EventHandler::matches_event`). **Two ways to stop paying
for answers the model already gave** (`src/llm/answer_reuse.rs`, `src/llm/rule_export.rs`; MCP
details in `src/mcp_stdio/AGENTS.md`): the `export_rules` tool turns an instance's access-log
entries with `answered_by: "model"` into static rules keyed on the fields that explain the
answers, echoing per-request ids (`query_id`, `id`, `tag`, …) through `{{event.…}}`, replaying
each rule against its recordings before offering it, and reporting rather than guessing where
answers differ for no recorded reason; and `memoize_ttl_secs` (off by default) replays the
model's answer to an identical event within a TTL, logged as answered by `cache`, never across
connections where history makes the answer connection-specific unless
`memoize_across_connections` is set. `tests/answer_reuse_test.rs` counts the model calls.

A caveat manual handlers exposed: several clients handle their `*_connected` event inline in
`connect()` before returning, so a parked connect event delays creation until answered — the
command channel must therefore register **before** that call (`tcp` and `telnet` do), or
`[ send ]` reads "no command channel" for the whole park.

## Action & event design rules (CRITICAL)

**Never put raw bytes or base64 in action parameters or event data.** Models cannot reliably
produce or parse them. Use structured fields: `{"method": "GET", "path": "/", "headers": {…}}`,
not `{"data": "SGVsbG8="}`.

**If an action does document a hex or encoded field, the executor must actually decode it.**
TCP had a bug of exactly this shape and it is worth knowing as the reference case (fixed in
`d70bb5b5`): `send_tcp_data` was documented in three places as accepting "text or hex-encoded
binary", but its executor did `data.as_bytes()` and never decoded hex, so a model following the
documentation put literal ASCII on the wire. Inbound data *was* hex-encoded when non-printable,
making the round-trip asymmetric — an echo server could not echo. The fix was an explicit
`encoding` field (`"utf8"` default, `"hex"`) on both directions rather than sniffing, because
`"48656c6c6f"` is simultaneously valid text and valid hex and only the sender knows which it
means. When you touch a protocol, verify its documented encoding matches its executor.

**Protocols must not implement storage** — no databases, filesystems, or persistence written
into a protocol's Rust implementation. The LLM supplies all data via actions, scripts, static
responses, or server memory. MySQL has no tables; the model answers every query.

The sanctioned exception is the generic SQLite facility (`src/state/sqlite.rs`, feature
`sqlite`, which is in the default feature set). The LLM can call
`create_database` / `execute_sql` / `list_databases` / `delete_database` at runtime, scoped to
a server, a client, or globally. The point of the rule is that storage is a *generic runtime
capability the model opts into*, never something a protocol hardcodes. Two caveats worth
knowing: `create_database` defaults to **file-backed**, writing `./netget_db_<name>.db` into
the process's working directory, and server/client-scoped databases are deleted when their
owner closes while global ones persist.

## Privilege model

`ProtocolMetadataV2::privilege_requirement` declares `None` / `PrivilegedPort(u16)` /
`RawSockets` / `Root`, checked against `SystemCapabilities` (`src/privilege.rs`) in
`server_startup.rs` before spawn, which now gates on `PrivilegeRequirement::is_met_by()` alone
and detects capabilities by actually probing (a `SOCK_RAW` socket, `/dev/bpf*`, `geteuid()`)
rather than inferring. Both were broken until this pass — the probe used `pcap::Device::list()`,
which any unprivileged user can call, so the check never fired for anything.

Declare `privilege_requirement` on any new protocol that needs raw sockets, a TUN device, or a
port below 1024. Two failure modes to avoid:

- **A `PrivilegedPort` above 1023 can never fire.** `svn` declared `PrivilegedPort(3690)`, which
  read as protection and was dead code. Declare `None` if the default port is unprivileged.

**The port itself is `well_known_port`, not `PrivilegedPort`.** Every socket server declares
`.well_known_port(n)` / `.well_known_udp_port(n)` / `.well_known_sctp_port(n)` in `metadata()` —
IANA's number, or where IANA has none the default the protocol's own specification or reference
implementation documents (Elasticsearch 9200, `hg serve` 8000), never 8080 standing in for HTTP.
It is what a server starts on when the caller names no port (picker, create form, `ServerForm`,
MCP `start_server`, `open_server`, `--server`), through one function,
`protocol::default_port::default_port_for_server`: 1024 and above as is, below 1024 only when
`can_bind_privileged_ports`, and a port already held on the bind address falls back to an
OS-assigned one — each fallback said out loud. **An explicit port, `0` included, is never
replaced.** `tests/well_known_port_declaration_test.rs` requires every server to declare one or
sit in its `NO_WELL_KNOWN_PORT` list with the reason (link layer, devices, pipes, the generic
`tcp`/`udp`, and application protocols carried on plain HTTP), and requires every
`PrivilegedPort(n)` to equal the declared port and the transport to match `stack_name()`.

**The host is the caller's too, and so is exposing a server.** With no host a server binds
`127.0.0.1`; an explicit host — `0.0.0.0` and `::` included — is bound as given, on every
binding path. That is a deliberate decision of the maintainer's (October 2026), not an
oversight to tighten: the legacy path that ~240 servers still take used to build its address
from `127.0.0.1` "for security" and silently drop the host, so a request to expose a server on
the LAN quietly bound loopback. A host that is not an address (or `localhost`) is refused, never
replaced. `tests/legacy_host_binding_test.rs` holds both halves.
- **A test can start an entirely different protocol and still pass.** `ospf`'s three e2e
  tests pass `"base_stack": "UDP"`, which `open_server` renames to `protocol` — so what
  starts is the **generic UDP server**, not `src/server/ospf/`. The mocked event is
  `udp_datagram_received` and the mocked action `send_udp_response`, both the UDP server's;
  no test in the tree mocks `ospf_hello` or any other OSPF event. The test builds
  OSPF-shaped bytes, the mock hands OSPF-shaped bytes back, a UDP server relays them, and
  `assert_eq!(buf[1], 1)` asserts a constant the test itself wrote. The
  `"application_protocol": "OSPF"` sitting alongside is read by nothing in `src/`.
  **Check which server a test actually starts before believing what it covers.**

  If you want the real thing — a declared `transport: "udp"` startup parameter that routes
  through the protocol's *own* code so the whole event → LLM → action → frame path runs
  unprivileged — copy `lldp`, `stp`, `cdp`, `eapol`, `vrrp`, `ndp`, `rawip` or `tuntap`.
  Those genuinely implement it; `ospf` never did, despite its `Cargo.toml` comment having
  claimed so for a long time.

- **Don't claim more than you need.** `ospf` declared `Root` when it wants `CAP_NET_RAW`, which
  would refuse to start on a capability-only process that could in fact run it.

There is no variant for *device* access — Bluetooth adapters, USB, NFC readers. Those seventeen
protocols sit at `None` because every other option would be a lie; see IMPROVEMENTS item 60.

Startup must report failure. `spawn()` has to await readiness and return `Err` so
`server_startup` sets `ServerStatus::Error`. ARP, DataLink and ICMP used fire-and-forget
`spawn_blocking` and sat in `Running` having captured nothing — a server that lies about being
up is worse than one that refuses to start.

`get_dependencies()` / `ProtocolDependency` (`src/protocol/dependencies.rs`) is plumbed, and as
of September 2026 the default **derives** from `privilege_requirement` rather than being empty —
so the old claim here that "no protocol overrides it, so the mechanism does nothing" is no longer
true in either half.

What the September audit found is more useful than the gap it was sent to close: **most of what
looks like a runtime dependency is not one.** `libpcap` and `libsmbclient` are linked at load
time, so the process could not start for a check to fire; `protoc` is `build.rs` only. Devices
have no honest probe, which is why `DeviceAccess` derives nothing. Exactly two were real and
undeclared, and both are declared now — the **gRPC client**'s `protoc` (the server declared it;
the client running the identical `Command::new("protoc")` did not) and **wireguard-go** on macOS.

So before declaring a dependency, ask whether it can actually be *missing at runtime on a
process that started*. If not, the declaration is decoration.

**Startup enforces them, narrowly.** Every `start_*` path (server and client, `_from_action` and
`_by_id`) calls `dependencies::startup_blocker`, which refuses only a `SystemLibrary`/`ToolInPath`
the probe **established** is absent (`DependencyStatus::Missing`), before anything is
registered, naming it with its install hint. A probe that cannot answer (`Unknown` — no `PATH`
to search, no loader query on the platform) is logged and let through. A dependency that only
some configurations need is expressed with `startup_dependencies(startup_params)`: gRPC drops
`protoc` for a pre-compiled descriptor set.

## Logging

**Dual logging everywhere**, through one call: `crate::logging::emit::Log` writes a line to
`netget.log` (tracing) and to the TUI/MCP status stream from one level, so the `[LEVEL]` bracket
cannot disagree with the file. `Log::to(&status_tx).info(format!(…))`; ERROR/WARN/INFO reach
both sinks, DEBUG/TRACE stay in the file unless routed with `debug_to(Sink::Both, …)`. Levels:
ERROR critical, WARN non-fatal, INFO lifecycle, DEBUG summaries, TRACE full payloads. A tracing
macro beside a hand-typed `status_tx.send(format!("[INFO] …"))` is the form it replaces, and
`tests/hand_rolled_dual_logging_ratchet_test.rs` allows none of it anywhere in `src/`, bar the
status-only sites its `NOT_DUAL_LOGGING` list names. Where the operator and the file need
different detail, write one line both read — the subject, the `decision=` tag, what is safe on
the dashboard — and a second DEBUG/TRACE line for what only the file should hold (a full error
chain, a payload, a statement that may carry a credential).

The status channel is an unbounded `mpsc` on the sending side, so no protocol task ever waits
on the UI, and it is **bounded where it is drained**: the dashboard and the CLI forwarders take
everything queued in one go (`logging::status_drain::drain_queued`), keep 500 lines per frame
(1 000 per CLI write batch) and drop and count the rest behind one `[WARN]` notice. A flood
costs lines on screen, never memory or a frozen UI; `netget.log` has every line. Still don't
add per-byte messages — a dropped line is one the operator never sees.

**Per-connection writer channels are bounded where a peer could grow them.** A stream server
that funnels a connection's writes through one writer task uses `utils::outbox` (4096 frames or
8 MiB, Redis's pub/sub client limit): a peer that stops reading while it is answered, broadcast
to or relayed to is cut off — never queued for, and never carried on with a frame missing. Give
the outbox the socket (`OutboxSender::close_on_cut_off` with a `ConnectionCloser` taken before
the stream is split or wrapped) and the cut-off **ends the connection**: the socket is shut
down both ways, the blocked writer fails, the reader reads EOF and runs the protocol's own
close path, and the peer reads EOF — so a client that never reads does not keep a socket and a
connection slot until its read deadline. `tests/server/{mqtt,websocket}/slow_reader_test.rs`
assert it from the peer's side. The `mqtt`, `amqp`, `bgp`, `websocket`, `nostr`, `webrtc`,
`webrtc_signaling`, `guacamole` and `tor_relay` servers and the `websocket` and `guacamole`
clients do both; the `libp2p` yamux session bounds its queue but has no socket to hand over
(it runs over the Noise layer), so its cut-off peer waits for its read deadline. `redis` pub/sub
has its own 8 MiB limit. Use the outbox, with its closer, for any new writer task. The other unbounded channels are operator-paced, startup-only,
have their receiver dropped, or are limited upstream (a flow-control window, one request in
flight); `docs/planning/IMPROVEMENTS.md` item 23 has the census and the sites still open.

## Scheduled tasks

Three scopes: **Global** (any server), **Server** (auto-cleaned on close), **Connection**
(auto-cleaned on close). Create via the `open_server` action's `scheduled_tasks` array or the
`schedule_task` action; add `connection_id` for connection scope. Parameters: `task_id`,
`recurring`, `interval_secs`/`delay_secs`, `instruction`. Use connection scope only for
long-lived connections (SSH, WebSocket); short-lived request/response protocols should use
server scope.
