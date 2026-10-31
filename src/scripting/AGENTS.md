# Scripting Subsystem (`src/scripting/`)

Deterministic, in-process handling of protocol events by running a user-supplied
script instead of calling the LLM. This is the **recommended** path for
predictable behavior (echo servers, canned responses, routing, high throughput):
it costs no model call, is reproducible, and returns in milliseconds.

> ## ⚠️ TRUST BOUNDARY — READ FIRST
>
> **Scripts are not sandboxed.** A script handler is executed by spawning a real
> interpreter (`python3 -c <code>`, `node -e <code>`, `perl -e <code>`,
> `go run <file>`) with the code string passed straight through. There is **no
> sandbox, no syscall filter, no allowlist, and no privilege reduction**. A
> script runs as the same OS user as the netget process, with that user's full
> filesystem access, full network access, and full ability to spawn further
> processes.
>
> **Consequence:** `event_handlers` with `type: "script"` is an
> **arbitrary-code-execution surface**. The MCP `start_server` tool accepts
> `event_handlers`, so *any MCP client connected to netget — and any model
> driving that client — can execute arbitrary code as the user who launched
> netget* simply by registering a script handler.
>
> **Therefore:** treat `event_handlers` as **trusted input**, on the same footing
> as the netget command line itself. Do not accept script handler definitions
> from an untrusted source, do not expose the MCP endpoint to an untrusted
> peer, and do not run netget as root or with credentials you would not hand to
> an arbitrary program.
>
> This is a deliberate design choice for a local developer tool, not an
> oversight — but it is a boundary that must be stated, not assumed. See
> [Future work](#future-work) for sandboxing options if the threat model changes.
>
> **What a script's environment does not carry: this process's credentials.** Every
> interpreter spawn goes through `process_io::ProcessGroup::configure`, which removes from
> the child's environment, comparing names case-insensitively:
>
> - the exact names in `STRIPPED_ENV`: `NETGET_API_KEY`, `OPENAI_API_KEY`,
>   `ANTHROPIC_API_KEY`, `NETGET_MCP_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
>   `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`;
> - any name containing one of `SECRET_NAME_PARTS`: `SECRET`, `PASSWORD`, `PASSWD`,
>   `API_KEY`, `APIKEY`, `ACCESS_TOKEN`, `AUTH_TOKEN`, `PRIVATE_KEY`, `CREDENTIAL`;
> - any name ending with one of `SECRET_NAME_SUFFIXES`: `_TOKEN`, `_SECRET`, `_PASSWORD`,
>   `_API_KEY`, `_ACCESS_KEY` (so `HF_TOKEN` and `MINIO_ACCESS_KEY` go too).
>
> Nothing a handler does needs the model backend's key, and a handler's stderr is
> logged. `PATH`, `HOME`, `LANG`, `PYTHONPATH` and the rest pass through.
> `tests/scripting_env_secrets_test.rs` runs a Python handler that tries to read them.
>
> **This is defence in depth, not a boundary.** A script runs as the same user as NetGet:
> it can read `~/.aws/credentials`, `~/.netrc` or any other file the operator can, and on
> Linux the parent's own environment through `/proc/<ppid>/environ`. Withholding the
> variables keeps a secret out of the place a careless handler would print it from; it
> does not keep a deliberate one from finding it.

## Files

| File | Purpose |
|---|---|
| `executor.rs` | Spawns the interpreter, feeds stdin, drains stdout/stderr, enforces the timeout |
| `manager.rs` | Routes an event to a script when the config handles that context; falls back to LLM |
| `types.rs` | `ScriptLanguage`, `ScriptConfig`, `ScriptSource`, `ScriptInput`, `ScriptResponse`, response parsing |
| `event_handler.rs` | `EventHandler` / `EventHandlerType` (`llm` \| `script` \| `static` \| `manual`), pattern matching, and the optional `match` conditions on event fields (`matches_event`, `find_handler_for`) |
| `environment.rs` | Startup detection of which interpreters are installed |
| `resident.rs` | Long-lived (persistent) script processes — opt-in `"resident": true`, keeps in-process state across events |
| `highlight.rs` | Syntax highlighting of script source for the TUI |

## Execution model

**Default (stateless) mode:** one event → one fresh interpreter process. Nothing
is cached, pooled, or reused between invocations. This is the default and remains
unchanged; a per-event script keeps no state between events.

**Resident (persistent) mode** (opt-in, `resident.rs`) is the exception: see
[Resident scripts](#resident-persistent-scripts) below. A resident script is
spawned once per scope and driven with one event per line, so module-level state
does persist across events. The description of the stateless model in this
section applies only to the default path.

```
event  ──►  ScriptInput (JSON)  ──►  child stdin
                                     ┌──────────────────────────┐
                                     │ python3 / node / perl /  │
                                     │ go run                   │
                                     └──────────────────────────┘
child stdout  ──►  {"actions": [...]}  ──►  execute_actions(...)
child stderr  ──►  logged (warn on success, error on failure)
```

### Languages and their interpreters

| `language` | Executable required | How the code is delivered | Notes |
|---|---|---|---|
| `python` | `python3` | `python3 -c <code>` | Script must read stdin itself (`json.load(sys.stdin)`) |
| `javascript` / `js` | `node` | `node -e <wrapped code>` | netget wraps the code; `input` is pre-parsed and in scope |
| `perl` | `perl` | `perl -e <code>` | Script must read stdin itself (`<STDIN>`) |
| `go` | `go` (full toolchain) | temp `.go` file + `go run` | netget wraps the code in a `main`; `input` is a pre-parsed `map[string]interface{}`. Compiles on every invocation — noticeably slower than the others |

Availability is probed once at startup (`environment.rs`) and re-checked before
each script handler runs; an unavailable language falls back to the LLM handler
rather than erroring. If the interpreter disappears between the probe and the
spawn, the executor reports which executable was missing, which language needs
it, and how to install it — not a bare "failed to spawn".

### Input contract (stdin)

A single JSON object, `ScriptInput`:

```json
{
  "event_type_id": "http_request",
  "server":     { "id": 1, "port": 8080, "stack": "HTTP",
                  "memory": "...", "instruction": "..." },
  "connection": { "id": "...", "remote_addr": "127.0.0.1:54321",
                  "bytes_received": 128, "bytes_sent": 0 },
  "event":      { /* protocol-specific payload */ }
}
```

`connection` is omitted for connectionless events. stdin is closed (EOF) once
the payload has been written, so `read()`-to-EOF is safe. A script that never
reads stdin is fine — the resulting `EPIPE` is treated as benign.

Use `get_protocol_docs` (MCP) or `/docs` (TUI) to see the `event` shape and the
valid action types for a given protocol.

### Output contract (stdout)

stdout must be exactly one JSON value:

```json
{"actions": [{"type": "send_http_response", "status": 200, "body": "hi"}]}
```

A bare array `[{...}]` is also accepted for backwards compatibility. stdout is
trimmed before parsing, so a trailing newline is fine, but **any other output on
stdout (debug prints, banners) breaks parsing** — write diagnostics to stderr
instead. stderr is captured and logged: at `warn` if the script succeeded, at
`error` if it did not.

Actions must be **structured data, never bytes or base64** — see the root
`AGENTS.md`. Non-zero exit, unparseable stdout, or a timeout all produce an
error, and the caller falls back to the LLM handler.

### Timeout and process lifetime

- Budget: `SCRIPT_TIMEOUT_SECS` = **30s**, exposed as `DEFAULT_SCRIPT_TIMEOUT`.
- The budget covers the **entire** interaction — spawn, stdin write, stdout and
  stderr drain, and child exit. There is no un-timed phase.
- On expiry the child is signalled (`start_kill`) **and awaited** (bounded by
  `KILL_REAP_TIMEOUT`, 5s) so it is reaped rather than left as a zombie.
- `kill_on_drop(true)` is set, so cancelling the owning task (e.g. a connection
  closing) does not leak the interpreter.
- Go's compile step is inside the budget. Large Go scripts can approach it on a
  cold module cache.

## Async design (why it matters)

`execute_script_async` is built on `tokio::process` and `tokio::time::timeout`.
**No OS thread is parked while a script runs**, and the four halves of the
interaction — stdin write, stdout drain, stderr drain, child wait — are driven
concurrently by a single `tokio::try_join!` (BrokenPipe on stdin remains benign).

Both properties are load-bearing, and both were previously absent:

1. **Worker-thread starvation.** The old executor was synchronous and polled
   `child.try_wait()` in a `std::thread::sleep(100ms)` loop. Called from async
   code, each in-flight script parked one tokio worker for the script's full
   duration. `#[tokio::main]` sizes the pool to the CPU count, so on an 8-core
   machine 8 concurrent script-handled requests stalled *every* protocol server,
   *every* connection, the TUI, and the MCP stdio loop.
2. **Unbounded stdin write.** The old executor did a blocking `write_all` of the
   whole event payload *before* reading any child output, and *before* arming
   the timeout. A payload larger than the pipe buffer (~64KB — an HTTP body, an
   accumulated TCP buffer) against a child that was itself blocked writing output
   deadlocked both sides, with **no timeout at all**.

### Entry points

| Function | Use from | Behavior |
|---|---|---|
| `execute_script_async(config, input)` | **all async code** | Non-blocking, 30s budget |
| `execute_script_with_timeout_async(config, input, timeout)` | async code / tests | Non-blocking, explicit budget |
| `ScriptManager::try_execute_async(config, input)` | **all async code** | Routing + execution; `Ok(None)` if the script does not handle this context |
| `execute_script(config, input)` | sync callers only (tests, tooling) | Blocking wrapper; runs the async path on a dedicated thread with its own current-thread runtime. Never nests runtimes, but **does** block the calling thread |
| `execute_script_blocking_with_timeout(...)` | sync callers only | Blocking, explicit budget |
| `ScriptManager::try_execute(config, input)` | sync callers only | Blocking routing + execution |

**Rule: if you are in an `async fn`, use an `_async` entry point.** The blocking
variants exist purely so synchronous test and tooling code does not have to
build a runtime; reaching for them from async code reintroduces defect (1).

## Static handlers and `{{event.…}}` interpolation

`event_handler.rs` also defines the **static** handler: a fixed list of actions emitted
with no LLM call *and* no interpreter process. It is the cheapest deterministic path —
strictly cheaper than a script, which spawns `python3`/`node` per event.

Static actions may reference the event that triggered them:

| Form | Meaning |
|---|---|
| `{{event.query_id}}` | a top-level field |
| `{{event.headers.host}}` | a nested field |
| `{{event.questions.0.name}}` | an array element (numeric segment) |
| `{{event}}` | the entire event payload |

Substitution happens in `interpolate_actions` (called from
`llm/event_handler_executor.rs::execute_static_handler`) just before the actions are
executed. Three rules:

1. **A whole-string reference keeps the value's JSON type.** `"query_id": "{{event.query_id}}"`
   produces the *number* `4660`, not the string `"4660"`. This is the point of the
   feature: the action executor type-checks its fields, so a stringified correlation id
   is rejected and the client times out. Objects, arrays, booleans and null survive too.
2. **An embedded reference splices text.** `"reply to {{event.domain}}"` →
   `"reply to example.com"`. Non-strings render in JSON form (`42`, `true`, `null`,
   `{"a":1}`).
3. **Everything else is byte-identical.** Only `{{…}}` groups whose contents are `event`
   or start with `event.` are touched. `{{ message }}` in a served Vue page,
   `{{#if}}`/`{{> partial}}` in a served Handlebars template, `{` in a JSON body, `{{2}}`
   in a regex, `{{braces}}` in a Rust format string — all pass through unchanged. Actions
   containing no reference are returned untouched and never require event data.

An unresolvable reference is a **hard error** naming the reference and listing the fields
the event actually carries — never a silent `null` or empty string, so a typo cannot look
like it works. `EventHandlerType::validate()` performs the parse-time half of that check
(malformed paths such as `{{event.}}` or `{{event..x}}`); field existence can only be
checked when an event arrives.

```json
{ "event_pattern": "dns_query",
  "handler": { "type": "static",
    "actions": [{ "type": "send_dns_a_response",
                  "query_id": "{{event.query_id}}",
                  "domain":   "{{event.domain}}",
                  "ip": "93.184.216.34", "ttl": 300 }] } }
```

Use `get_protocol_docs` (MCP) or `/docs` (TUI) to see which fields a given event carries.

**Why not Handlebars**, which is already a dependency for prompt templates: it renders to
a `String`, so rule 1 would need a re-parse that turns `"007"` into `7`; it HTML-escapes
`{{…}}` by default, corrupting JSON and URLs unless every reference is triple-stashed; and
it owns the whole `{{…}}` namespace, so a handler that *serves* a Handlebars or Vue
template would be rewritten or rejected. The resolver borrows only the spelling.

This closes the gap that forced request/response UDP protocols — DNS `query_id`,
DHCP/BOOTP `xid`, SNMP `request-id`, STUN transaction id, NTP origin timestamp — to use a
script handler purely to copy one integer.

## Concurrency notes

- Go sources live in independently created random private directories (0700 on
  Unix). A RAII owner removes the directory and source on completion, failure or
  cancellation. Concurrent invocations share no writable staging path.
- **Default (per-event) scripts share nothing.** There is no cross-invocation
  state on that path, by design: per the root `AGENTS.md`, protocols must not
  implement storage. Durable state belongs in server `memory`, which is passed
  in on every invocation via `ScriptInput.server.memory`. Note this is *process*
  isolation, not the storage rule itself — a **resident** script (below) keeps
  in-process state across events within one scope, and is the sanctioned way to
  do so without a database.

## Resident (persistent) scripts

Opt-in with `"resident": true` on a `script` event handler. Instead of a fresh
interpreter per event, one process is spawned **per scope** and driven with one
JSON line in / one JSON line out per event, so module-level variables (counters,
a parsed config, a connection map) persist across events. Implemented in
`resident.rs`; the stateless per-event path is untouched and stays the default.

- **Same trust boundary.** Resident mode adds no new capability to the script —
  it only keeps the same unsandboxed interpreter alive between events. The banner
  at the top of this file applies unchanged.
- **Contract differs from per-event scripts.** The user code must define
  `handle(event_type, event, message)` (a function/sub), not read stdin itself.
  netget wraps it in a per-language harness (Python `python3 -u -c`, JavaScript
  `node -e`, Perl `perl -e` using core `JSON::PP`) that runs the read-loop, calls
  `handle`, and writes one JSON line of actions back. Return an actions list, a
  `{"actions": [...]}` object, or `None`/`undefined` for no actions. A `handle`
  that raises emits `{"error": ...}` — parsed as a failed event (→ falls back to
  the LLM) while the **process stays alive** for the next event, so its state
  survives. Unexpected return types also report an error instead of silently
  acknowledging with no actions. JavaScript handlers may return a Promise;
  the harness awaits it and handles rejection as a handler error.
- **Language support.** Python, JavaScript, Perl only. **Go is not supported**
  (compiled per `go run`, no cheap persistent form) and a resident Go handler
  transparently falls back to the per-event executor. A resident handler for a
  missing interpreter also falls back to the LLM rather than erroring per event.
- **Scope** (`ResidentScope`, parsed from a scope string; default `Server`):
  - `Server` — one process per server; every connection's events for this handler
    share one process and its state (e.g. a server-wide counter). Connectionless
    events use this.
  - `Connection` — one process per connection; independent state each. Falls back
    to server scope for connectionless events (no connection id to key on).
  Two handlers with identical code + scope share a process (keyed by
  `server_id` + optional `connection_id` + language + code hash); different code
  or a different connection gets its own.
- **Lifetime & robustness.** Each round-trip runs under the same
  `DEFAULT_SCRIPT_TIMEOUT` (30s) budget, including the time queued behind another
  event on the same resident. Cancelling an in-flight round-trip kills its child
  and leaves the registry slot dead; the next event replaces it, so a stale reply
  cannot answer a different event. On timeout or EOF-on-stdout (the process
  died) the round-trip returns `Err`, the process is killed and evicted, the
  caller falls back to the LLM, and the next event respawns. Processes idle longer
  than `IDLE_TTL` (300s) are evicted on the next registry access; `kill_on_drop`
  ensures none leak. Explicit teardown via `ResidentScriptManager::shutdown_server`
  / `shutdown_connection` / `shutdown_all`. One event round-trip at a time per
  process (stdin is serialized by a mutex). Nothing parks an OS thread — spawned
  and awaited via `tokio::process`.

## Testing

`tests/scripting_executor_test.rs` (top-level, not feature-gated) covers the
per-language happy paths plus the async guarantees: normal exit, timeout
returning an error promptly instead of hanging, ~1MB stdout, ~1MB stdin against
a child pre-filling its stderr pipe (the old deadlock), and a starvation test
that runs 8 one-second scripts on a 2-worker runtime alongside a 10ms ticker.

`tests/scripting_manager_test.rs` covers routing and config construction.

`tests/scripting_resident_test.rs` covers resident mode: state persisting across
dispatches, switch-on-`event_type`, shutdown resetting state, a hang timing out
and recovering, process death detected and recovered, a `handle()` error keeping
the process and its state alive, connection-scope isolation, targeted
`shutdown_connection`, a JavaScript resident, and Go being unsupported.

`tests/static_handler_interpolation_test.rs` covers `{{event.…}}` substitution: type
preservation per JSON type, embedded splicing, nested and indexed paths, the error text for
a missing/typo'd field, byte-identical pass-through of literal braces, and a DNS-shaped
static handler echoing a client's `query_id` both directly and through
`try_execute_event_handler`.

```bash
./cargo-isolated.sh test --no-default-features --features tcp \
  --test scripting_executor_test --test scripting_manager_test \
  --test static_handler_interpolation_test -- --test-threads=100
```

The Perl tests need the `JSON` CPAN module (`cpan JSON`); they fail on a stock
macOS/Homebrew Perl that lacks it. The Go test needs a working Go toolchain.

## Future work

Sandboxing is **not** implemented and is a maintainer design decision, not a bug
fix. It is worth considering if netget is ever exposed to a semi-trusted MCP
peer, run as a shared service, or run with elevated privileges. Options, roughly
in increasing order of cost:

1. **OS resource limits** — `setrlimit` for CPU/address space/file descriptors.
   Captured-output/source/interpolation caps and process-group/Job cleanup are
   already implemented; they do not contain a deliberately hostile script.
2. **Interpreter-level restriction** — Node's permission model
   (`--permission --allow-fs-read=...`), or a restricted Python builtin set.
   Partial, and easy to escape without care.
3. **OS sandbox** — `sandbox-exec` on macOS, seccomp/Landlock or a user
   namespace on Linux. Real containment; platform-specific.
4. **Opt-in trust flag** — leave execution unrestricted but require an explicit
   `--allow-scripts` (or per-source trust) before a script handler supplied over
   MCP is honored. Smallest change that closes the "remote peer gets ACE"
   path.

Whatever is chosen, the boundary above should stay documented — a local tool
that runs code as you is defensible; one that does so silently is not.

## Bounded resources and process ownership

Interpreter probes run concurrently, collect stdout/stderr concurrently, cap each
pipe at 64 KiB and include pipe EOF in their five-second deadline. A subprocess
that leaves inherited pipes open cannot hold startup indefinitely. Browser builds
report no subprocess interpreters without spawning threads or probing the host.

Per-event stdout is capped at 8 MiB and stderr at 1 MiB. An excess aborts the
interaction immediately. Resident replies have the same 8 MiB cap; malformed EOF
or an excess kills/evicts the process. Resident diagnostics retain/log at most
1 MiB over the process lifetime, then keep draining into fixed scratch space.
The stderr drain is owned by the resident, and is aborted with it.

Native children start in independent Unix process groups, or are assigned to
Windows kill-on-close Job Objects. Completion, timeout, cancellation and explicit
shutdown terminate the owned group/job. This is cleanup of trusted code, not a
sandbox: a Unix child deliberately creating another session can escape it, and
Windows assignment occurs immediately after spawn rather than claiming an atomic
security boundary. Windows runtime behavior requires Windows CI.

Source files must be regular files, checked on the opened descriptor; Unix opens
are nonblocking so FIFOs cannot trap the metadata check. Source is capped at
4 MiB, loaded on Tokio's blocking pool, and included in the caller's deadline.
Cancellation stops awaiting an in-flight filesystem operation; it cannot interrupt
a kernel filesystem call already running on that pool. Inline source has the same
size cap. Go staging and compilation are also inside the overall deadline.

Static action interpolation has a shared 8 MiB expanded-text budget and a 65,536
node budget, with 64-level input/reference trees validated iteratively. Resolved
values are checked before cloning and JSON embedded in text is serialized into a
bounded writer. Repeated references cannot amplify output without limit; keys
that resolve to the same name are rejected rather than silently overwriting data.
Entry-point checks tokenize language-specific comments/quoted literals, including
Python triple strings, JavaScript templates/regexes and Perl quote operators, and
recognize whitespace-separated declarations and arrow functions. These checks are
configuration diagnostics, not an executable language parser or a sandbox.

`tests/scripting_resources_test.rs` exercises noisy/inherited pipes, source bounds,
FIFO rejection, descendant cleanup and Go staging cancellation without any model.
