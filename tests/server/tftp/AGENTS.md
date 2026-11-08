# TFTP Server E2E Tests

## Test Strategy

**Approach**: Mock-based E2E tests using real TFTP protocol packets over UDP.

**LLM Call Budget**: 4 LLM calls total (1 per test scenario)
- Test 1: Read request (single block) - 2 mock calls
- Test 2: Write request - 3 mock calls
- Test 3: Error handling - 2 mock calls
- Test 4: Multi-block transfer - 3 mock calls

**Rationale**: TFTP is stateful with multiple request-response cycles per transfer. Each test validates a complete transfer flow with minimal LLM overhead using mocks.

## Test Coverage

### 1. Read Request (RRQ) - Single Block
- Client sends RRQ packet for "test.txt"
- Mock LLM responds with `send_tftp_data` action (block 1, final)
- Server sends DATA packet with file content
- Client sends ACK
- Verifies: Correct block number, file content, final flag

### 2. Write Request (WRQ)
- Client sends WRQ packet for "upload.txt"
- Mock LLM responds with `send_tftp_ack` action (block 0)
- Server sends ACK 0 (ready to receive)
- Client sends DATA packet (block 1)
- Mock LLM responds with `send_tftp_ack` action (block 1)
- Server sends ACK 1
- Verifies: Correct ACK sequence, data received event triggered

### 3. Error Handling - File Not Found
- Client sends RRQ for "nonexistent.txt"
- Mock LLM responds with `send_tftp_error` action (code 1)
- Server sends ERROR packet
- Verifies: Error code 1, error message "File not found"

### 4. Multi-Block Transfer
- Client sends RRQ for "large.bin" (1024 bytes = 2 blocks)
- Mock LLM responds with `send_tftp_data` action (block 1, not final)
- Server sends DATA block 1 (512 bytes)
- Client sends ACK 1
- Mock LLM responds with `send_tftp_data` action (block 2, final)
- Server sends DATA block 2 (512 bytes)
- Client sends ACK 2
- Verifies: Correct block sequence, complete data transfer

## Mock Pattern

Tests use the standard NetGet mock builder:

```rust
let config = NetGetConfig::new("prompt")
    .with_mock(|mock| {
        mock
            .on_instruction_containing("listen")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("tftp_read_request")
            .and_event_data_contains("filename", "test.txt")
            .respond_with_actions(json!([{
                "type": "send_tftp_data",
                "block_number": 1,
                "data_hex": "...",
                "is_final": true
            }]))
            .expect_calls(1)
            .and()
    });

let mut server = start_netget_server(config).await?;
// ... test logic ...
server.verify_mocks().await?;
```

## `real_client_test.rs` - two independent clients

curl's libcurl TFTP (8 LLM calls: a `send_tftp_file` download of three blocks, a
`send_tftp_data` download answered block by block, a refused RRQ curl reports as exit 68, and an
upload of two blocks) and the system `tftp(1)` — BSD tftp on macOS, tftp-hpa on Linux — (6: a
`netascii` download, an `octet` download of exactly 1024 bytes ending in an empty block, and an
upload). Both fail rather than skip when the client is absent. Downloads are compared byte for
byte with what the model served; uploads are reassembled from the `data` the model was shown.

## `retransmit_test.rs` - the lockstep's failure cases

One server, raw sockets, 6 LLM calls: the same RRQ twice back to back (one transfer, one TID),
a withheld ACK (block 1 again, same TID), a stranger's datagram on the TID (`ERROR 5`), a stale
ACK (no retransmission), an upload whose block 1 is sent twice (ACK 1 again, one model call),
and a `netascii` download whose blocks must carry CR LF. The dedupe and the encoding were each
verified by removing them.

## TFTP Client Implementation

The other files use **manual packet construction** (no external TFTP library):
- Helper functions: `build_rrq_packet()`, `build_wrq_packet()`, `build_ack_packet()`, `build_data_packet()`
- Parsers: `parse_data_packet()`, `parse_ack_packet()`, `parse_error_packet()`
- UDP socket via `tokio::net::UdpSocket`

**Rationale**: TFTP is simple enough for raw packet construction. Avoids dependency on external TFTP client libraries.

## Expected Runtime

- Mock mode: < 1 second per test (< 5 seconds total)
- Real Ollama mode (if used): 5-10 seconds per test (~30 seconds total)

## Known Issues

None currently. All tests pass in mock mode.

## Event Types Tested

1. **tftp_read_request**: Triggered when client sends RRQ
   - Parameters: filename, mode, client_addr
   - Expected actions: send_tftp_data or send_tftp_error

2. **tftp_write_request**: Triggered when client sends WRQ
   - Parameters: filename, mode, client_addr
   - Expected actions: send_tftp_ack (block 0)

3. **tftp_data_block**: Triggered when client sends DATA (write operation)
   - Parameters: block_number, data_hex, data_length, is_final
   - Expected actions: send_tftp_ack

4. **tftp_ack_received**: Triggered when client sends ACK (read operation)
   - Parameters: block_number
   - Expected actions: send_tftp_data (next block) or none (transfer complete)

## Actions Tested

1. **send_tftp_data**: Send data block to client
   - Parameters: block_number, data_hex, is_final
   - Opcode: 3 (DATA)

2. **send_tftp_ack**: Acknowledge received data block
   - Parameters: block_number
   - Opcode: 4 (ACK)

3. **send_tftp_error**: Send error and terminate transfer
   - Parameters: error_code, error_message
   - Opcode: 5 (ERROR)

## UDP-Specific Considerations

- TFTP uses **Transaction ID (TID)** = unique UDP port per transfer
- Server creates new socket for each transfer (not bound to port 69)
- Client must track peer address from first response
- Tests handle dynamic port allocation correctly

## Running Tests

```bash
# Mock mode (default, no Ollama required)
./test-e2e.sh tftp

# Real Ollama mode
./test-e2e.sh --use-ollama tftp

# Cargo directly (mock mode)
cargo test --features tftp --test server -- server::tftp::e2e_test

# Cargo with Ollama
NETGET_USE_OLLAMA=1 cargo test --features tftp --test server -- server::tftp::e2e_test
```

## Test Quality Metrics

- **Coverage**: 4 scenarios covering RRQ, WRQ, errors, multi-block
- **Mock verification**: All tests call `verify_mocks().await?`
- **Assertions**: Multiple assertions per test (opcode, block numbers, data content)
- **Timeouts**: 5-second timeouts on all UDP receives (prevents hanging)
- **LLM efficiency**: < 10 LLM calls total (meets project requirement)

## `decision_tag_test.rs`

Two tests, 2 LLM calls each, pinning the one distinction the TFTP wire cannot carry.

| Test | What it asserts |
|---|---|
| `test_tftp_backend_failure_is_tagged_fail_closed` | An RRQ during a backend outage returns ERROR code 0 with one of the two **fixed** category messages (never netget's error text), and the log carries `decision=fail_closed_llm_*` and *not* `decision=model_reject` |
| `test_tftp_handler_refusal_is_tagged_model_reject` | An RRQ the handler refuses with `send_tftp_error` returns the handler's own code and message, and the log carries `decision=model_reject` and *not* `decision=fail_closed` |

Both put **opcode 5** on the wire, and a client parses nothing that tells them apart — which
is the point. Each test asserts the packet *and* the log line, because either half alone
proves nothing: a tag with no packet behind it describes something that did not happen, and a
packet with no tag is the defect the pass exists to remove.

See `src/server/tftp/AGENTS.md`, "Failure behaviour", for every outcome and its token,
including the two that still write nothing at all (`model_silent`, `fail_closed_bad_action`).
