# SSH Agent Protocol Server E2E Tests

## Test Overview

Tests the SSH Agent server implementation using Unix domain sockets. SSH Agent is a binary protocol that manages SSH
keys and performs signing operations for SSH clients.

## Test Strategy

- **Unix socket communication**: SSH Agent uses Unix domain sockets (socket files), not TCP/IP
- **Binary wire protocol**: SSH wire format with uint32 length prefix + message type byte + data
- **Minimal validation**: Tests basic connectivity and message parsing, not full protocol compliance
- **Future implementation**: Currently includes placeholder tests documenting expected behavior

## Current Status

✅ **E2E TESTS WITH MOCKS IMPLEMENTED** - Full e2e tests with Ollama mocks using Unix domain sockets.

### What Works

- ✅ Unit tests for message parsing (6 tests in `test.rs`)
- ✅ E2E tests with mocks (5 tests in `e2e_test.rs`)
- ✅ Unix socket connection handling
- ✅ Mock LLM responses for all operations

### Test Files

- `test.rs` - Unit tests for SSH Agent protocol message parsing (no LLM)
- `e2e_test.rs` - E2E tests with mock LLM responses (requires Unix sockets)
- `executor_test.rs` - `execute_action` as a pure `Value -> ActionResult` mapping: no socket,
  no LLM, 0 calls. It exists because both of this protocol's advertised hex examples declared
  more key/signature bytes than they supplied — a truncation a client walks off the end of, and
  one nobody had proofread. It pins the replacement (an authorized_keys line for a key, an
  algorithm name for a signature, both framed by the server), that a truncated or mislabelled
  blob is *refused*, that the hex escape hatches still pass bytes through verbatim, and that
  giving both spellings of the same thing is an error rather than a coin toss.
- `connection_bounds_test.rs` - the connection cap and both read deadlines, from the peer's
  end of the socket. In-process (`ServerForm` + `AppState`) and model-free: the LLM endpoint is
  a dead port and every rule is static or manual, so 0 calls. The read bounds are set short
  through `first_byte_timeout_secs` / `idle_timeout_secs`. Five tests: a silent peer reads EOF
  at the first-byte bound; after one static-answered request the idle bound governs (the
  first-byte one is set 60s, the wrong way round); a request parked for a human keeps its
  connection far past both bounds; 256 sockets fill the cap, the 257th reads EOF at once, and
  closing one frees exactly one slot; and `remove_server` unlinks the socket node (removing
  the `SocketCleanup` guard leaves it on disk). Removing the read deadline failed the first two and
  raising the cap to 100 000 failed the fourth. The parked test has no guard to remove —
  requests are answered inline, so the read is simply not polled — and is a regression pin
  against the deadline being moved outward. It also pins `default_binding()`: before it, this
  protocol could not be started with only a `socket_path` ("requires 'port' parameter").

## LLM Call Budget

### Unit Tests (test.rs) - 0 LLM calls
- `test_ssh_agent_protocol_parsing()`: 0 LLM calls (pure unit test)
- `test_ssh_agent_identities_answer_parsing()`: 0 LLM calls (pure unit test)
- `test_ssh_agent_sign_response_parsing()`: 0 LLM calls (pure unit test)
- `test_ssh_agent_failure_response()`: 0 LLM calls (pure unit test)
- `test_ssh_agent_success_response()`: 0 LLM calls (pure unit test)

### E2E Tests with Mocks (e2e_test.rs)
- `test_ssh_agent_request_identities_with_mocks()`: 2 LLM calls (startup + REQUEST_IDENTITIES)
- `test_ssh_agent_sign_request_with_mocks()`: 2 LLM calls (startup + SIGN_REQUEST)
- `test_ssh_agent_add_identity_with_mocks()`: 2 LLM calls (startup + ADD_IDENTITY)
- `test_ssh_agent_multiple_operations_with_mocks()`: 4 LLM calls (startup + 3 operations)
- **Total: 10 LLM calls** (all mocked, no real Ollama required)

**At the 10 LLM call budget limit.** All LLM calls are mocked for fast, deterministic testing.

## Scripting Usage

❌ **Scripting Disabled** - Action-based responses only

**Rationale**: SSH Agent operations are stateful and require structured responses (binary protocol). The LLM should use
actions like `send_identities_answer`, `send_sign_response`, etc., rather than scripts.

## Client Library

- **tokio::net::UnixStream** - Async Unix domain socket
- **tokio::io::{AsyncReadExt, AsyncWriteExt}** - For socket I/O
- **ssh-agent-lib** - Could be used for message parsing/construction, but currently using manual parsing for minimal
  dependencies

**Why manual parsing?**:

1. Educational - shows exact wire format
2. Minimal dependencies - just tokio + std
3. Tests don't need full SSH Agent client library
4. Direct control over message construction for edge case testing

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~20-30 seconds when implemented (2 tests × ~10s each)
- Each test includes: server startup (2-3s) + LLM response (5-8s) + validation (<1s)

## Failure Rate

- **Unknown** - Tests not yet fully implemented
- Expected: Low (~5%) similar to other protocols
- Potential issues: Binary format errors, Unix socket permissions, file cleanup

## Test Cases

### Unit Tests (test.rs)

#### 1. Message Parsing (`test_ssh_agent_protocol_parsing`) - ✅ IMPLEMENTED

- **Status**: Runnable, no LLM calls
- **Test**: Validates message construction helpers
- **Verifies**:
    - REQUEST_IDENTITIES is 5 bytes (4 length + 1 type)
    - SIGN_REQUEST has correct format
- **Purpose**: Ensures test infrastructure correctly constructs SSH Agent messages

#### 2-5. Response Parsing Tests - ✅ IMPLEMENTED

- `test_ssh_agent_identities_answer_parsing()` - Tests IDENTITIES_ANSWER format
- `test_ssh_agent_sign_response_parsing()` - Tests SIGN_RESPONSE format
- `test_ssh_agent_failure_response()` - Tests FAILURE message
- `test_ssh_agent_success_response()` - Tests SUCCESS message

### E2E Tests with Mocks (e2e_test.rs)

#### 1. REQUEST_IDENTITIES (`test_ssh_agent_request_identities_with_mocks`) - ✅ IMPLEMENTED

- **Status**: Runnable with mocks
- **Setup**: Creates Unix socket, starts NetGet SSH Agent server
- **Mock**: LLM responds with one test key
- **Client**: Sends REQUEST_IDENTITIES (type 11) via UnixStream
- **Expected**: IDENTITIES_ANSWER (type 12) with 1 key
- **Purpose**: Tests basic SSH Agent query/response cycle with LLM integration
- **LLM Calls**: 2 (server startup + REQUEST_IDENTITIES event)

#### 2. SIGN_REQUEST (`test_ssh_agent_sign_request_with_mocks`) - ✅ IMPLEMENTED

- **Status**: Runnable with mocks
- **Mock**: LLM responds with test signature
- **Client**: Sends SIGN_REQUEST (type 13) with test key and data
- **Expected**: SIGN_RESPONSE (type 14) with signature
- **Purpose**: Tests signing operation with LLM integration
- **LLM Calls**: 2 (server startup + SIGN_REQUEST event)

#### 3. ADD_IDENTITY (`test_ssh_agent_add_identity_with_mocks`) - ✅ IMPLEMENTED

- **Status**: Runnable with mocks
- **Mock**: LLM responds with SUCCESS
- **Client**: Sends ADD_IDENTITY (type 17) with Ed25519 key
- **Expected**: SUCCESS (type 6)
- **Purpose**: Tests key addition with LLM integration
- **LLM Calls**: 2 (server startup + ADD_IDENTITY event)

#### 4. Multiple Operations (`test_ssh_agent_multiple_operations_with_mocks`) - ✅ IMPLEMENTED

- **Status**: Runnable with mocks
- **Mock**: LLM responds to sequence of operations
- **Operations**:
  1. REQUEST_IDENTITIES (expect 0 keys)
  2. ADD_IDENTITY (add key)
  3. REQUEST_IDENTITIES (expect 1 key)
- **Purpose**: Tests state management across multiple operations
- **LLM Calls**: 4 (server startup + 3 operations)

## Known Issues

### 1. Unix Socket Path Requirements

E2E tests create Unix sockets in `std::env::temp_dir()` with unique names per test. Tests handle:

- ✅ Socket creation and cleanup
- ✅ Connection handling with UnixStream
- ✅ Proper file removal after tests

**Note**: Tests assume NetGet server can create Unix sockets. If server doesn't support socket_path parameter, tests will gracefully report socket not created.

### 2. Binary Protocol Complexity

SSH Agent wire format is more complex than text protocols:

- Requires proper length prefixing
- Uses big-endian uint32 for lengths
- SSH string format: uint32 length + bytes
- Easy to get message structure wrong

**Mitigation**: Use `ssh-encoding` crate from `ssh-key` dependency for proper encoding.

### 3. Unix Socket Permissions

Unix sockets require proper file permissions. Tests must:

- Create sockets in writable temp directory
- Clean up socket files after tests
- Handle permission errors gracefully

### 4. No Full Protocol Coverage

Tests only cover 2 basic message types (REQUEST_IDENTITIES, SIGN_REQUEST). SSH Agent supports 12+ message types
including:

- ADD_IDENTITY (17)
- REMOVE_IDENTITY (18)
- REMOVE_ALL_IDENTITIES (19)
- ADD_ID_CONSTRAINED (25)
- LOCK (22)
- UNLOCK (23)

**Rationale**: Testing all message types would exceed LLM budget and require extensive mock data.

## Implementation Roadmap

### Phase 1: Test Helper Updates (Required first)

1. Add Unix socket support to `tests/helpers/mod.rs`
2. Implement `{SOCKET_PATH}` placeholder
3. Add socket file cleanup logic

### Phase 2: Basic Tests

1. Implement `test_ssh_agent_request_identities`
2. Implement `test_ssh_agent_sign_request`
3. Remove `#[ignore]` attributes

### Phase 3: Enhanced Coverage (Optional)

1. Add ADD_IDENTITY test
2. Add REMOVE_IDENTITY test
3. Add error handling tests (invalid messages)

## Alternative: Mock Socket Tests

If modifying test helpers is too complex, could use direct `tokio::net::UnixListener` in tests:

```rust
#[tokio::test]
async fn test_with_mock_socket() -> E2EResult<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("test.sock");

    // Spawn server manually with socket path
    // Connect via UnixStream
    // Send/receive messages
    // Cleanup

    Ok(())
}
```

This would bypass the need for helper modifications but lose consistency with other protocol tests.

## References

- [IETF SSH Agent Draft](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent-05)
- [SSH Wire Format](https://datatracker.ietf.org/doc/html/rfc4251#section-5)
- [Tokio UnixStream](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html)
- [ssh-agent-lib crate](https://docs.rs/ssh-agent-lib/)
