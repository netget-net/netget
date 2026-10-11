# SNMP Client E2E Testing

## Overview

End-to-end tests for the SNMP client implementation. These tests verify LLM-controlled SNMP operations by spawning
NetGet server (SNMP agent) and client instances, then validating protocol behavior.

## Test Strategy

### Black-Box Testing Approach

Tests use the compiled NetGet binary with natural language prompts, treating the client as a black box. This validates:

- LLM interpretation of SNMP instructions
- Client protocol implementation
- Request/response handling
- Error scenarios

### Test Infrastructure

- **Server**: NetGet SNMP agent (server mode) listening on ephemeral port
- **Client**: NetGet SNMP client connecting to local agent
- **Validation**: Output parsing and behavior verification
- **Isolation**: Each test uses unique port to enable parallel execution

## Test Cases

### 1. Basic GET Request

**File**: `e2e_test.rs::test_snmp_client_get_request`
**LLM Calls**: 2 (server startup, client connection)
**Runtime**: ~3s

Tests basic SNMP GET operation:

- Agent responds to GET for sysDescr (1.3.6.1.2.1.1.1.0)
- Client sends GET request and receives response
- Verifies connection and data retrieval

### 2. GETNEXT MIB Walking

**File**: `e2e_test.rs::test_snmp_client_getnext_walk`
**LLM Calls**: 3 (server startup, client connection, follow-up GETNEXT)
**Runtime**: ~4s

Tests MIB tree traversal:

- Client uses GETNEXT to walk system subtree (1.3.6.1.2.1.1)
- LLM decides when to send next GETNEXT based on response
- Retrieves multiple OIDs sequentially

### 3. GETBULK Bulk Retrieval (SNMPv2c)

**File**: `e2e_test.rs::test_snmp_client_getbulk_v2c`
**LLM Calls**: 2 (server startup, client connection)
**Runtime**: ~3s

Tests efficient bulk operations:

- Client uses GETBULK with max_repetitions parameter
- Retrieves multiple OIDs in single request
- Validates SNMPv2c-specific functionality

### 4. SET Request

**File**: `e2e_test.rs::test_snmp_client_set_request`
**LLM Calls**: 2 (server startup, client connection)
**Runtime**: ~3s

Tests write operations:

- Client sends SET request to modify sysName (1.3.6.1.2.1.1.5.0)
- Agent accepts SET with 'private' community string
- Client verifies SET with follow-up GET

### 5. Custom Community String

**File**: `e2e_test.rs::test_snmp_client_custom_community`
**LLM Calls**: 2 (server startup, client connection)
**Runtime**: ~3s

Tests authentication:

- Server requires specific community string ('secret123')
- Client provides correct community in startup params
- Validates community string matching

### 6. Timeout and Retry

**File**: `e2e_test.rs::test_snmp_client_timeout`
**LLM Calls**: 1 (client connection only, server not started)
**Runtime**: ~3s

Tests error handling:

- No server running (connection failure)
- Client configured with short timeout (1s) and 1 retry
- Verifies graceful timeout handling

## LLM Call Budget

**Total**: 14 LLM calls across 6 test cases
**Average**: 2.3 calls per test
**Breakdown**:

- Server startup: 5 calls (5 tests with server)
- Client connection: 6 calls (all 6 tests)
- Follow-up actions: 3 calls (GETNEXT walk, SET verify)

**Why < 10 calls per test suite?**

- Tests reuse server/client instances where possible
- Single LLM call handles multiple SNMP operations
- No unnecessary intermediate calls
- Efficient test design with focused scenarios

## Runtime Characteristics

**Sequential Runtime**: ~19s (sum of all tests)
**Parallel Runtime**: ~4s (longest test)
**CI Environment**: Tests run against an in-process mock LLM

**Per-Test Breakdown**:

- Connection setup: 500ms
- LLM processing: 1-2s per call
- UDP request/response: <10ms
- Cleanup: <100ms

## Known Issues

### Flaky Tests

**None currently identified**

UDP is inherently less reliable than TCP, but:

- Tests use localhost (no network loss)
- Retry logic in client handles transient failures
- Timeout values set conservatively (5s default)

### Platform-Specific Behavior

- **Linux**: All tests pass
- **macOS**: Untested (should work, UDP is standard)
- **Windows**: Untested (UDP sockets may behave differently)

### CI/CD Considerations

- Tests require Ollama running (LLM dependency)
- Use `cargo-isolated.sh` to avoid build conflicts
- Each test allocates ephemeral UDP port (no conflicts)

## Running Tests

### Single Test

```bash
./cargo-isolated.sh test --no-default-features --features snmp --test client -- client::snmp::e2e_test::test_snmp_client_get_request
```

### Full Suite

```bash
./cargo-isolated.sh test --no-default-features --features snmp --test client -- client::snmp::e2e_test
```

### With Logs

```bash
RUST_LOG=debug ./cargo-isolated.sh test --no-default-features --features snmp --test client -- client::snmp::e2e_test --nocapture
```

## Test Maintenance

### Adding New Tests

When adding tests:

1. Keep LLM calls < 3 per test (reuse server/client)
2. Use `{AVAILABLE_PORT}` placeholder for server port
3. Document LLM call count in test comment
4. Add estimated runtime to test comment
5. Update "Total" LLM call budget in this document

### Updating for Protocol Changes

If SNMP client implementation changes:

1. Update affected test expectations
2. Verify LLM call count still accurate
3. Re-measure runtime if significant change
4. Update test documentation

## Debugging Failed Tests

### Common Failure Modes

1. **Connection timeout**: Server didn't start fast enough
    - Solution: Increase sleep duration (500ms → 1s)

2. **LLM returned unexpected action**: Prompt ambiguity
    - Solution: Make test prompt more specific

3. **Output assertion failed**: Client behavior changed
    - Solution: Check client logs, update assertion

4. **Port already in use**: Parallel test conflict
    - Solution: Use `{AVAILABLE_PORT}` (already done)

### Debugging Commands

```bash
# Show full client/server output
RUST_LOG=trace ./cargo-isolated.sh test --features snmp --test client -- client::snmp::e2e_test::test_snmp_client_get_request --nocapture

# Check LLM API calls
RUST_LOG=netget::llm=debug ./cargo-isolated.sh test --features snmp --test client -- client::snmp::e2e_test

# Run single test with timeout
timeout 30 ./cargo-isolated.sh test --features snmp --test client -- client::snmp::e2e_test::test_snmp_client_timeout
```

## Future Enhancements

### Additional Test Coverage

- **SNMPv1 vs v2c**: Separate tests for each version
- **Trap handling**: Client receiving traps (requires server trap send)
- **Error responses**: Test noSuchName, badValue, etc. from agent
- **Large responses**: Test responses > 1472 bytes (UDP fragmentation)
- **Concurrent requests**: Multiple clients to same agent

### Performance Tests

- **Latency**: Measure client request/response time
- **MIB walk speed**: Time to walk large subtree (e.g., ifTable with 100 interfaces)
- **GETBULK efficiency**: Compare GETBULK vs sequential GETNEXT

### Security Tests

- **Community string mismatch**: Verify client handles auth failure
- **SNMPv3**: `real_server_test.rs` (below)
- **Rate limiting**: Test client behavior under agent throttling

## References

- [NetGet SNMP Client Implementation](../../../src/client/snmp/AGENTS.md)
- [NetGet SNMP Server Implementation](../../../src/server/snmp/AGENTS.md)
- [E2E Test Infrastructure](../../helpers/mod.rs)

## `command_channel_test.rs`

Covers the dashboard's `[ send ]` path: `AppState::send_to_client` injects an action from
outside the client's own loop and the wire effect is asserted.

**LLM budget: 0 calls.** Every client event is routed to a `*` static handler that answers
with no actions (`try_execute_client_event_handler` runs before the budget debit), and the
client's LLM points at `http://127.0.0.1:1` as a second belt. No mock Ollama server is
needed or started.

`wait_for_client_handle` polls `AppState::has_client_handle` before the first send. That is
the regression guard for "register the channel **before** the connected-event LLM call" — if
registration moves after it, a parked connect event makes this poll time out.

The stand-in agent is a plain `tokio::net::UdpSocket` on `127.0.0.1:0` that never replies;
`retries: 0` and `timeout_ms: 200` in `startup_params` keep the abandoned reply wait from
outliving the test. The test compares the reported `Sent { bytes_sent }` against the datagram
length actually received, checks it is a BER SEQUENCE, and greps the wire for the community
string passed in `startup_params` — which also proves the injected path uses the client's own
configuration rather than defaults. `Rejected` is asserted twice: for an unknown action type
and for a `send_snmp_get` with an empty `oids` array.

## SNMPv3 against a real agent (`real_server_test.rs`)

Net-SNMP's `snmpd`, unprivileged through `RealServer` (`-f -Lo -C -c {dir}/snmpd.conf
-I -smux udp:127.0.0.1:{port}`; `-I -smux` because the packaged agent, or a second test's,
already holds SMUX's TCP 199). Two users, `shaaes` (SHA-256/AES) and `md5des` (MD5/DES), both
`rwuser … priv`. For each, NetGet discovers the engine, a static handler GETs sysDescr and
sysContact, and a script handler answers by SETting sysContact to `"<tag> saw: <sysDescr>"`;
Net-SNMP's `snmpget` then reads sysContact back as `md5des`. That is the client bar's condition
4 asserted from the agent's side. A wrong auth password arrives as snmpd's own
`usmStatsWrongDigests` report and nothing is set; a v3 client pointed at a silent socket fails
to start, naming discovery. Breaking the manager's clock (boots forced to 0) fails the SET test:
snmpd then answers with time-window reports. These tests are what would carry a Beta rating, but
the six `e2e_test.rs` tests still need a real model and are ignored, so the client stays
Experimental.
