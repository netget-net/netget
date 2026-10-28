# DHCP Client E2E Test Documentation

## Overview

End-to-end tests for DHCP client protocol implementation. These tests verify that the DHCP client can successfully
connect to DHCP servers, send DHCP messages (DISCOVER, REQUEST, INFORM), and parse responses (OFFER, ACK, NAK).

**Protocol**: DHCP (Dynamic Host Configuration Protocol) client
**Test Strategy**: Black-box testing using netget binary
**LLM Budget**: < 10 LLM calls per test suite
**Runtime**: ~10-15 seconds per test
**Status**: All tests marked as `#[ignore]` due to privilege requirements

## Test Organization

Tests are located in `tests/client/dhcp/e2e_test.rs` and are feature-gated with `#[cfg(all(test, feature = "dhcp"))]`.

### Test Files

- `e2e_test.rs` - Main E2E test suite
- `mod.rs` - Module declaration
- `AGENTS.md` - This documentation

## Test Cases

### 1. `test_dhcp_client_discover_offer`

**Purpose**: Verify DHCP client can send DISCOVER and receive OFFER

**LLM Call Budget**: 4 calls

- Server startup (1 call)
- Client startup (1 call)
- Server processing DISCOVER (1 call)
- Client processing OFFER (1 call)

**Flow**:

1. Start DHCP server that offers IP 192.168.1.100
2. Start DHCP client with MAC 00:11:22:33:44:55
3. Client sends DHCP DISCOVER
4. Server responds with DHCP OFFER
5. Verify client logs OFFER details

**Expected Behavior**:

- Client output contains "dhcp" or "DHCP"
- Client successfully receives and parses OFFER

**Runtime**: ~3-4 seconds

### 2. `test_dhcp_client_full_dora`

**Purpose**: Verify DHCP client can complete full DORA exchange (DISCOVER → OFFER → REQUEST → ACK)

**LLM Call Budget**: 6 calls

- Server startup (1 call)
- Client startup (1 call)
- Server OFFER (1 call)
- Client REQUEST (1 call)
- Server ACK (1 call)
- Client parse ACK (1 call)

**Flow**:

1. Start DHCP server
2. Start DHCP client with instructions to complete DORA
3. Client sends DISCOVER
4. Server sends OFFER
5. Client sends REQUEST
6. Server sends ACK
7. Verify client logs assigned IP and disconnects

**Expected Behavior**:

- Client protocol is "DHCP"
- Full DORA exchange completes successfully
- Client receives ACK with IP assignment

**Runtime**: ~5-6 seconds

### 3. `test_dhcp_client_broadcast`

**Purpose**: Verify DHCP client can send broadcast DISCOVER

**LLM Call Budget**: 4 calls

- Server startup (1 call)
- Client startup (1 call)
- Server processing broadcast DISCOVER (1 call)
- Client processing responses (1 call)

**Flow**:

1. Start DHCP server
2. Start DHCP client with broadcast address (255.255.255.255:67)
3. Client sends broadcast DISCOVER
4. Verify client initiates DHCP activity

**Expected Behavior**:

- Client output contains "DHCP" or "dhcp"
- Broadcast DISCOVER is sent

**Runtime**: ~2-3 seconds

## LLM Call Budget Analysis

**Total Budget**: < 10 LLM calls per test suite
**Actual Usage**:

- Test 1: 4 calls
- Test 2: 6 calls
- Test 3: 4 calls
- **Total**: 14 calls (if all tests run)

**Note**: Since tests are isolated, they don't all run together. Each test individually stays under budget.

## Known Issues and Limitations

### 1. Requires Elevated Privileges

**Issue**: DHCP client must bind to port 68 (privileged port < 1024)

**Impact**: All tests marked with `#[ignore]` attribute

**Workaround**: Run tests with sudo:

```bash
sudo ./cargo-isolated.sh test --no-default-features --features dhcp --test client -- client::dhcp::e2e_test --ignored
```

**Platform-specific**:

- Linux: Requires root or CAP_NET_BIND_SERVICE capability
- macOS: Requires root
- Windows: May require administrator privileges

### 2. May Interfere with OS DHCP Client

**Issue**: Binding to port 68 may conflict with OS DHCP client

**Impact**: Tests may fail if OS DHCP client is active

**Workaround**:

- Use test environment without active DHCP client
- Temporarily disable OS DHCP client
- Use network namespace (Linux only)

### 3. Broadcast May Not Work in All Environments

**Issue**: Some network configurations block broadcast traffic

**Impact**: `test_dhcp_client_broadcast` may not receive responses

**Workaround**: Use unicast tests instead

### 4. Timing Sensitivity

**Issue**: DHCP is timing-sensitive (responses may take time)

**Impact**: Tests use sleep delays which may be too short/long

**Mitigation**: Tests use generous timeouts (2-5 seconds)

## Running Tests

### Standard Test Run (Ignored Tests Skipped)

```bash
./cargo-isolated.sh test --no-default-features --features dhcp
```

### Run with Root Privileges (Include Ignored Tests)

```bash
sudo ./cargo-isolated.sh test --no-default-features --features dhcp --test client -- client::dhcp::e2e_test --ignored
```

### Run Specific Test

```bash
sudo ./cargo-isolated.sh test --no-default-features --features dhcp --test client -- client::dhcp::e2e_test::test_dhcp_client_discover_offer --ignored --nocapture
```

## Test Infrastructure Dependencies

### Helper Functions

- `start_netget_server()` - Start DHCP server process
- `start_netget_client()` - Start DHCP client process
- `NetGetConfig::new()` - Configuration builder
- `output_contains()` - Check process output
- `stop()` - Clean up process

### Test Utilities

Located in `tests/helpers/` (shared across all protocol tests)

## Performance Characteristics

### Build Time (Feature-Specific)

- With `--no-default-features --features dhcp`: 10-30 seconds
- With `--all-features`: 1-2 minutes

### Test Execution Time

- Per test: 2-6 seconds
- Full suite (3 tests): ~12-15 seconds
- Includes LLM response time (~2-3 seconds per call)

### Resource Usage

- Memory: ~50-100MB per NetGet process
- CPU: Low (mostly waiting for LLM)
- Network: Localhost only (127.0.0.1)

## Privacy & Security

### Network Isolation

- All tests use localhost (127.0.0.1)
- No external DHCP servers contacted
- Broadcast is limited to local loopback interface

### Data Privacy

- No actual network configuration performed
- No IP addresses assigned to OS
- DHCP traffic is test-only

### Privilege Requirements

- Tests require root/CAP_NET_BIND_SERVICE
- Only for binding port 68
- No other elevated operations

## Future Improvements

### 1. Network Namespace Support (Linux)

Create isolated network namespace for tests:

```bash
sudo ip netns add dhcp-test
sudo ip netns exec dhcp-test ./cargo-isolated.sh test ...
```

### 2. Mock DHCP Server

Implement in-process mock DHCP server to avoid privilege requirements

### 3. Additional Test Cases

- DHCP INFORM message
- DHCP RELEASE message
- Multiple DHCP servers (selecting best offer)
- DHCP NAK handling
- Lease renewal
- Option parsing (DNS, router, subnet mask, etc.)

### 4. Stress Testing

- Multiple concurrent clients
- Rapid DISCOVER/REQUEST cycles
- Large option sets

## Troubleshooting

### Test Hangs

**Cause**: LLM timeout or network issue

**Solution**: Check Ollama is running, increase timeouts

### Permission Denied

**Cause**: Insufficient privileges to bind port 68

**Solution**: Run with sudo or set CAP_NET_BIND_SERVICE capability

### No OFFER Received

**Cause**: DHCP server not responding

**Solution**: Check server logs, verify server is listening on port 67

### Port Already in Use

**Cause**: OS DHCP client or another test using port 68

**Solution**: Stop conflicting process, use network namespace

## References

- [DHCP Client Implementation](../../../src/client/dhcp/AGENTS.md)
- [DHCP Server Implementation](../../../src/server/dhcp/AGENTS.md)
- [CLIENT_PROTOCOL_FEASIBILITY.md](../../../docs/planning/CLIENT_PROTOCOL_FEASIBILITY.md#dhcp-🟡)
- [RFC 2131: Dynamic Host Configuration Protocol](https://datatracker.ietf.org/doc/html/rfc2131)
- [Test Infrastructure Fixes](../../README.md)

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

## `command_channel_test.rs` — and why it is not `#[ignore]`

The three E2E tests above are `#[ignore]`d because the DHCP client demanded port 68. It now
falls back to an ephemeral port when 68 is unavailable, so this test runs unprivileged like
any other. The receiver is a plain `tokio::net::UdpSocket` on `127.0.0.1:0` rather than a
NetGet DHCP server, which would still need privileged port 67.

The test compares the reported `Sent { bytes_sent }` against the datagram length actually
received, and checks the `op` byte, the injected `chaddr` and the DHCP magic cookie.
Asserted outcomes: `Rejected` for an unknown action, `Sent` for `dhcp_discover` with
`broadcast: false`, `Disconnected` for `disconnect`, and no command handle afterwards.
