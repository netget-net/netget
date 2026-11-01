# MCP Client E2E Test Strategy

## Overview

Black-box E2E tests for MCP (Model Context Protocol) client using real NetGet binary with Ollama LLM integration. Tests
verify client connection, initialization, and MCP operations (tools, resources, prompts).

## Test Approach

### Black-Box Testing

- Spawn real `netget` binary with MCP server and client instances
- **Both ends are mocked** with `.with_mock()`, so the tests run by default and the assertions
  are about the exchange (`verify_mocks`) rather than about a substring in the output
- Tests are protocol-agnostic (don't inspect internal state)

### These three tests were all `#[ignore]`d, and that is how a real defect survived

Until September 2026 every test in `e2e_test.rs` carried `#[ignore]` with the note "No
`.with_mock()` configured: requires `--use-ollama`". That left the MCP **client** with no
running e2e coverage at all — only `command_channel_test.rs`, which points the client's LLM at
an unreachable URL and never exercises the handshake or an operation. An `#[ignore]`d test is
not evidence (root CLAUDE.md, rubric point 6).

What lived in the gap: the client sent phase 3 of the handshake as method `initialized`, where
MCP namespaces every notification under `notifications/`. NetGet's own MCP server matches
`notifications/initialized` and drops anything else into a `debug!("Unknown MCP notification")`
— and a notification has no reply, so the client logged that it had sent one, got its 204, and
declared the handshake complete. `test_mcp_client_initialize` now asserts on the **server's**
log line, the only place the difference is visible; reverting the client to the bare name fails
it.

### Two traps in mocking this client

- **`wait_for_more` is not an MCP client action.** Answering an event with it makes the
  executor reject the action, the LLM repair loop re-ask, and the event fire a second time —
  which surfaces as `expected 2, got 3` on an unrelated rule.
  `tests/helpers/mock_action_names.rs` catches the statically-declared form and says so
  usefully, but it cannot see inside a `respond_with_actions_from_event` closure. Use
  `notify_operator` to terminate a chain.
- **The initialize mock must include `serverInfo`.** `connect()` fails with "Missing serverInfo
  in initialize response" without it, so an incomplete mock fails the handshake rather than the
  assertion under test.

### Test Environment

- **LLM Required**: No — a per-test in-process mock LLM serves both binaries
- **Network**: Localhost only (127.0.0.1)
- **Ports**: Dynamic allocation via `{AVAILABLE_PORT}` placeholder

## LLM Call Budget

Counted per process, since server and client each run their own mock.

### Test 1: `test_mcp_client_initialize` — 2 server + 2 client

Server: startup, `mcp_initialize`. Client: startup, `mcp_client_connected`.

**Rationale**: verifies the three-phase handshake, including that phase 3 reached the
server's router.

### Test 2: `test_mcp_client_call_tool` — 4 server + 4 client

Server: startup, `mcp_initialize`, `mcp_tools_list`, `mcp_tools_call`. Client: startup,
`mcp_client_connected`, and `mcp_response_received` twice — **one** rule branching on the
event, because two rules on the same event with no way to tell them apart is first-match-wins
and the second would report zero calls.

**Rationale**: tests the whole tool workflow, and the second server call exists only because
the client acted on the first one's response.

### Test 3: `test_mcp_client_read_resource` — 4 server + 4 client

The same shape for `resources/list` → `resources/read`.

**Total: 20 calls across three tests and six processes** — under 10 per process.

## Test Coverage

### Initialization (Test 1)

- ✅ Three-phase handshake (initialize → response → initialized)
- ✅ Client receives server capabilities
- ✅ Client status becomes Connected

### Tool Operations (Test 2)

- ✅ List tools (JSON-RPC `tools/list`)
- ✅ Call tool (JSON-RPC `tools/call`)
- ✅ Receive tool result

### Resource Operations (Test 3)

- ✅ List resources (JSON-RPC `resources/list`)
- ✅ Read resource (JSON-RPC `resources/read`)
- ✅ Receive resource content

### Not Covered (Acceptable)

- ❌ Prompts (similar to tools/resources, low priority)
- ❌ Resource subscriptions (server push, complex)
- ❌ Error handling (requires more LLM calls)
- ❌ Concurrent operations (single-threaded test)

## Expected Runtime

**Per Test:**

- Server startup: ~500ms
- Client connection: ~1-2s (includes LLM call and initialization)
- Operations: ~1-2s per LLM call
- Cleanup: ~100ms

**Total per test: 3-5 seconds**
**All tests: 10-15 seconds**

With Ollama lock and serial execution, total suite runtime: **~20 seconds**

## Known Issues & Flakiness

### Potential Issues

1. **LLM Interpretation**: LLM may not immediately recognize MCP protocol from prompt
    - Mitigation: Clear prompt with "via MCP" instruction

2. **JSON-RPC Parsing**: LLM may struggle with JSON-RPC response formatting
    - Mitigation: Server provides clear action examples

3. **Timing**: Client may send requests before server is ready
    - Mitigation: 500ms sleep after server startup

4. **Output Inspection**: Tests rely on string matching in output
    - Mitigation: Flexible assertions (OR conditions)

### Flaky Test Indicators

- Tests should pass >95% of the time
- If tests fail, check Ollama model availability
- Check for port conflicts (unlikely with dynamic allocation)

## Test Execution

### Run All MCP Client Tests

```bash
./cargo-isolated.sh test --no-default-features --features mcp --test client -- client::mcp::e2e_test
```

### Run Specific Test

```bash
./cargo-isolated.sh test --no-default-features --features mcp --test client -- client::mcp::e2e_test::test_mcp_client_initialize
```

### Debug Output

Tests capture NetGet stdout/stderr. On failure, output is printed for debugging.

## Success Criteria

**All tests must:**

1. Complete within expected runtime (< 10s per test)
2. Use ≤ budgeted LLM calls
3. Verify client protocol is "MCP"
4. Show relevant output (connection, tools, resources)
5. Clean up gracefully (no zombie processes)

## Comparison with Other Client Tests

| Aspect         | MCP Client                     | HTTP Client           | TCP Client           |
|----------------|--------------------------------|-----------------------|----------------------|
| **LLM Calls**  | 8 total                        | 4 total               | 6 total              |
| **Complexity** | Medium (JSON-RPC)              | Low (HTTP)            | Low (Raw TCP)        |
| **Operations** | 3 types (init, tool, resource) | 2 types (GET, custom) | 2 types (send, echo) |
| **Protocol**   | HTTP + JSON-RPC                | HTTP                  | Raw TCP              |
| **Runtime**    | ~20s                           | ~10s                  | ~15s                 |

## Future Enhancements

**If budget allows (> 10 calls):**

- Test prompts (list + get)
- Test error handling (invalid tool/resource)
- Test multiple sequential operations
- Test resource subscriptions

**If architecture changes:**

- Add WebSocket transport tests
- Add SSE (Server-Sent Events) tests
- Add progress notification tests
