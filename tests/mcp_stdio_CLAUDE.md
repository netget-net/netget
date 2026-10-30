# MCP STDIO Test Strategy

## File

`tests/mcp_stdio_test.rs` (top-level integration binary, gated on
`#[cfg(feature = "mcp-stdio")]`).

## Approach

In-process, **no Ollama, no real stdin/stdout**. The server service is served
over a `tokio::io::duplex` pipe and driven by an rmcp client (`serve_client((), ..)`)
on the other end. This exercises the real JSON-RPC handshake, tool discovery, and
tool dispatch without any external process or LLM.

The rmcp `client` feature is enabled via the `mcp-stdio` / `mcp-http` Cargo
features specifically so these tests can act as an MCP client.

## Test cases

1. `initialize_and_list_tools` — completes the MCP handshake, asserts server
   name is `netget`, and that the core management tools (`list_protocols`,
   `start_server`, `stop_server`, `get_status`) are advertised.
2. `call_list_protocols_returns_tcp` — calls the `list_protocols` tool with
   `type=server` and asserts the compiled-in `tcp` protocol appears in the output.
3. `agent_mode_exposes_queue_tools` — with `--llm-agent`, asserts the
   `get_next_llm_request` / `answer_llm_request` / `list_llm_requests` tools are
   advertised and `get_status` reports the `agent` backend.
4. `agent_answers_tcp_request_end_to_end` — with `--llm-agent`, starts a real TCP
   server, connects a client and sends a line, fetches the queued LLM request via
   `get_next_llm_request`, answers it with a `send_tcp_data` action, and asserts the
   bytes arrive on the socket. This exercises the full producer→queue→agent→execute
   path with **no model**.
5. `agent_request_times_out` — with `--llm-agent --llm-agent-timeout 1`, claims a
   request but never answers it; after the timeout the backend expires it, so a late
   `answer_llm_request` fails.

## LLM call budget

**Zero real model calls.** The agent-mode tests *are* the model: the queue backend
never contacts Ollama/OpenAI; the test harness answers the queued requests directly.
The non-agent tests only read the protocol registry / app state.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio \
    --test mcp_stdio_test -- --test-threads=100
```

## Expected runtime

A few seconds after compilation (no network, no LLM).

## Not covered here

- `start_server` end-to-end (it invokes the LLM) — covered by the protocol E2E suites.
- HTTP transport (`--mcp-http`) wiring — `tests/mcp_http_transport_test.rs` spawns the
  real binary on an ephemeral port and drives `initialize` over HTTP, including the
  admission policy (rebound `Host`, foreign `Origin`, missing bearer token, oversized
  body); `tests/mcp_http_guard_test.rs` pins the policy itself without a socket.

## Agent serving regressions

`agent_http_events_are_compact_recoverable_and_cancelled_with_the_browser` exercises
real HTTP requests through MCP: explicit context, the offered response schema,
compact versus full prompt bytes, GET form query decoding, retrieval/release,
stale token rejection, answer-and-next, and browser-disconnect cleanup.
`agent_queue_recovery_test` verifies lease wakeups, cancelled producers/listeners,
request timings and form decoding. `agent_listener_cli_test` starts real NetGet
and listener processes, proves TCP reply bytes, restarts the MCP server, proves
reconnection and token uniqueness, and checks prompt exit on stdin EOF.

## Events and Channels

`mcp_events_stdio_test` drives newline-delimited JSON-RPC through the binary's
dual-era stdio serving path rather than relying on the SDK client's protocol
models. Modern discovery, request metadata, complete results and retained legacy
tools are checked alongside SEP-3415 poll/bootstrap, filtering, pagination, replay
gaps, heartbeats, concurrent streams, cancellation, the subscription cap and EOF.
Events and both legacy/scoped-modern Channels share stable event IDs. Real TCP
peers receive answers authored through the existing claim/answer and intercept
tools after a push notification; no model or polling loop is involved. A subprocess
test verifies that the actual binary accepts a modern connection and exits on EOF
even with an open stream. The quiet-stream heartbeat test takes 30 seconds.
