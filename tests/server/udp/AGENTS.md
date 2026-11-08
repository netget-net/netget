# UDP Protocol E2E Tests

## Test Overview

Tests the raw UDP server implementation with a simple echo protocol. Validates that the LLM can construct UDP datagram
responses.

## Test Strategy

- **Single test**: Only one test for basic UDP echo functionality
- **Raw UDP socket**: Uses `std::net::UdpSocket` for datagram communication
- **Simple validation**: Send datagram, verify echo response
- **Lenient failure**: Test doesn't fail on timeout (just logs a note)

## LLM Call Budget

- `test_udp_echo_server()`: 1 LLM call (datagram received event)
- `test_send_to_address_reaches_the_named_address_only()`: 1 LLM call (datagram received event)
- `llm_failure_test.rs`: 1 LLM call (startup only; the event is deliberately unmatched)
- `decision_tag_test.rs`: 2 tests x 2 LLM calls (startup + one datagram each)
- **Total: 7 LLM calls**

**Note**: This is the bare minimum for UDP testing. Most UDP protocol testing happens in dedicated protocol tests:

- DNS: `tests/server/dns/` (uses hickory-net's client)
- DHCP: `tests/server/dhcp/` (uses dhcproto)
- NTP: `tests/server/ntp/` (uses rsntp)
- SNMP: `tests/server/snmp/` (uses snmp crate + snmpget)

## Scripting Usage

❌ **Scripting Disabled** - Action-based responses only

**Rationale**: Single simple test doesn't benefit from scripting overhead.

## Client Library

- **std::net::UdpSocket** - Synchronous UDP socket from standard library
- **No async**: Uses blocking socket with 5-second read timeout

**Why synchronous socket?**:

1. Simpler for basic test (no tokio runtime needed in test itself)
2. Sufficient for single datagram send/receive
3. Consistent with legacy test pattern

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~5-10 seconds (1 LLM call + network I/O)
- Very fast due to minimal test scope

## Failure Rate

- **Medium** (~10-20%) - Test has lenient failure handling
- Does NOT fail if response times out (just logs a note)
- Actual failure only on server start errors

**Reason for leniency**: UDP echo is not a critical test case since most UDP functionality is validated through
protocol-specific tests (DNS, DHCP, NTP, SNMP).

## Test Cases

### 0. The `decision=` pair (`decision_tag_test.rs`, and `llm_failure_test.rs` beside it)

UDP writes **nothing** on every unhappy path, so the log is the only place those paths differ.
Each of these tests asserts **both** halves, and neither half means anything alone: silence
with no log is indistinguishable from the "reset to Idle and write nothing" defect, and a log
line with a datagram beside it would mean the tag was lying.

| Test | Model answered | Asserted |
|---|---|---|
| `test_udp_ignore_datagram_is_silent_and_logged_as_a_refusal` | `ignore_datagram` | nothing on the socket; `decision=model_reject`; **no** `decision=fail_closed` |
| `test_udp_empty_answer_is_silent_and_logged_as_model_silence` | `[]` | nothing on the socket; `decision=model_silent`; **no** `decision=fail_closed` |
| `test_udp_stays_silent_but_logs_when_llm_fails` (`llm_failure_test.rs`) | nothing — the mock 500s | nothing on the socket; the "bare UDP has no error form" sentence; `decision=fail_closed_llm_*` |

Do **not** "fix" the silence — see `src/server/udp/AGENTS.md`. Any bytes invented here could be
parsed as a real reply by whatever protocol the peer is actually speaking.

### 1. UDP Echo (`test_udp_echo_server`)

- **Prompt**: Echo back any received data
- **Client**: Sends "Hello UDP" datagram
- **Expected**: Response contains "Hello UDP"
- **Timeout**: 5 seconds
- **Purpose**: Basic UDP send/receive validation
- The mock's `data` carries an explicit `"encoding": "hex"`. Without it the payload went through
  the `auto` guess, so the test asserted the guess rather than the echo

### 2. `send_to_address` (`test_send_to_address_reaches_the_named_address_only`)

- **Prompt**: Forward what you receive elsewhere
- **Client**: a peer sends one trigger datagram; a separate observer socket is the named target
- **Expected**: the observer receives `FORWARDED`, and the triggering peer receives nothing
- **Purpose**: the address used to be parsed and thrown away, so this action was a second
  `send_udp_response`. Both halves are asserted, because a fix that sent to *both* addresses
  would satisfy the first half alone

## Known Issues

### 1. Lenient Failure Handling — fixed

`test_udp_echo_server` used to catch the timeout and the receive error and *log a note* instead
of failing:

```rust
Err(_) => {
    println!("Note: UDP echo timeout after 5 seconds");
    // Don't fail the test, just note it
}
```

The single assertion lived in the success arm, so a server that answered nothing at all passed.
Both arms now return `Err`. It was labelled "initially a placeholder"; it had long since stopped
being one.

### 2. No Response Validation

Test only checks if response contains input string. Doesn't validate:

- Response format (could have extra text/formatting)
- Response timing (LLM might be slow)
- Datagram size (no check for truncation)

### 3. Single Datagram Test

Only tests one send/receive cycle. Doesn't test:

- Multiple datagrams from same peer
- Concurrent datagrams from different peers
- Large datagrams (near 65K limit)
- Binary datagram handling

### 4. No Statelessness Validation

UDP should be stateless, but test doesn't verify that multiple datagrams are independent.

## Performance Notes

### Why So Minimal?

This test suite is intentionally minimal because:

1. **DNS tests cover UDP thoroughly** - DNS uses UDP and has comprehensive tests
2. **DHCP tests validate binary UDP** - DHCP uses binary UDP datagrams
3. **NTP tests validate timing** - NTP requires precise UDP timing
4. **SNMP tests validate structured data** - SNMP uses ASN.1 over UDP

Adding duplicate tests here would increase LLM call budget without adding value.

### UDP vs. TCP Test Coverage

- TCP tests: 5 tests, 5 LLM calls - thorough testing of FTP and custom protocols
- UDP tests: 1 test, 1 LLM call - minimal, relies on protocol-specific tests

This is acceptable because:

- TCP is more complex (connection management, state machines, data queueing)
- UDP is simpler (stateless, no connections)
- UDP protocols are well-tested in their own test suites

## Future Enhancements

### Test Coverage Gaps

1. **Binary datagrams**: No tests for hex-encoded binary data
2. **Large datagrams**: No tests near 65K limit
3. **Concurrent peers**: No tests for multiple simultaneous clients
4. **Statelessness**: No tests verifying independent datagram handling
5. **`auto` encoding**: no test pins the ambiguous default, in either direction

### Potential Improvements

1. **Make test strict**: Remove lenient error handling, require echo to work
2. **Add binary test**: Send hex-encoded binary data, verify echo
3. **Add concurrent test**: Multiple clients sending datagrams simultaneously
4. **Add large datagram test**: Send 60K+ datagram, verify echo
5. **Add statelessness test**: Send two datagrams, verify second doesn't depend on first

### Consolidation with Protocol Tests

Consider moving this test into a general "raw protocols" test suite that includes both TCP and UDP basic functionality
tests.

## References

- [RFC 768: User Datagram Protocol](https://datatracker.ietf.org/doc/html/rfc768)
- [std::net::UdpSocket](https://doc.rust-lang.org/std/net/struct.UdpSocket.html)
- Related protocol tests: DNS, DHCP, NTP, SNMP
