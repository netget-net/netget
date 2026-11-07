# Telnet Client E2E Test Strategy

## Overview

E2E tests for the Telnet client verify LLM-controlled Telnet connection, command sending, and option negotiation
handling.

## Test Approach

### Test Infrastructure

- **Server**: NetGet Telnet server (LLM-controlled)
- **Client**: NetGet Telnet client (LLM-controlled)
- **Verification**: Black-box output inspection
- **Runtime**: ~3-5 seconds per test

### LLM Call Budget

**Total Budget**: < 10 LLM calls per test suite

**Test Breakdown**:

1. `test_telnet_client_connect_to_server` - 2 LLM calls
    - Server startup (1 call)
    - Client connection (1 call)

2. `test_telnet_client_send_command` - 2 LLM calls
    - Server startup (1 call)
    - Client with command (1 call)

3. `test_telnet_client_option_negotiation` - 2 LLM calls
    - Server with option negotiation (1 call)
    - Client response (1 call)

**Total**: 6 LLM calls

## Test Cases

### 1. Connection Test

**Purpose**: Verify Telnet client can connect to server

**Flow**:

1. Start Telnet server on available port
2. Start Telnet client connecting to server
3. Wait for connection establishment
4. Verify client output shows "connected"

**Expected Behavior**:

- Client successfully connects
- Option negotiation happens automatically
- Client reports connection status

### 2. Command Sending Test

**Purpose**: Verify client can send Telnet commands

**Flow**:

1. Start Telnet echo server
2. Start client with instruction to send "hello"
3. Wait for command execution
4. Verify client protocol is Telnet

**Expected Behavior**:

- Client sends command with `\r\n` termination
- Server receives and echoes back
- Client processes response

### 3. Option Negotiation Test

**Purpose**: Verify automatic option negotiation handling

**Flow**:

1. Start server that sends Telnet options (WILL ECHO, DO TERMINAL_TYPE)
2. Start client that connects
3. Wait for negotiation
4. Verify client handled negotiation

**Expected Behavior**:

- Client automatically responds to WILL with DONT
- Client automatically responds to DO with WONT
- Connection remains stable after negotiation
- No manual LLM intervention needed for negotiation

### 4. Wire bytes (`line_ending_test.rs`)

**Purpose**: pin exactly what each action puts on the wire, read from the server's side.

In-process: a local `TcpListener` is the server, `MockOllamaServer` the model, and the client
is created with `ClientForm` (batching and the restart check off, so each event is one call).

- `telnet_connected` answered with `send_command` `"hello\r\n"` → exactly `hello\r\n` (a line
  ending the model wrote is not doubled);
- a question answered with `send_command` `"Paris"` → exactly `Paris\r\n`;
- `Press a key: ` answered with `send_text` `"y"` → exactly `y`;
- `send_to_client` with `send_command` / `send_text` → `status\r\n` / `no newline`;
- the question's prompt describes `send_command` as the way to answer and says `send_text`
  is not for answers.

Each read takes the expected bytes and then waits 400 ms for anything more, so an extra CRLF
fails rather than sitting unread. 3 model calls, about 3 s.

## Known Issues

### Test Flakiness

- **Option Negotiation Timing**: Some servers send options immediately, others after data
    - Mitigation: Generous sleep durations (1000ms)
    - Future: Add retry logic with backoff

- **Server Startup Race**: Client may connect before server is fully ready
    - Mitigation: 500ms sleep after server start
    - Future: Poll server port availability

### LLM Variability

- **Command Format**: a model can pick `send_text` (no line ending) where a line was meant,
  and a line-based server then never sees the answer. The action descriptions steer it to
  `send_command`; `src/client/telnet/AGENTS.md` has the measurement. A mocked suite cannot
  show this either way — it is a property of the model and the prompt.

- **Option Response**: LLM shouldn't need to handle negotiation
    - Automatic negotiation in client implementation
    - LLM sees clean text data only

## Test Data

### Server Prompts

```
"Listen on port {AVAILABLE_PORT} via Telnet. When client connects, send 'Welcome!\r\n' prompt."
"Listen on port {AVAILABLE_PORT} via Telnet. Echo back any text received."
"Listen on port {AVAILABLE_PORT} via Telnet. Send WILL ECHO and DO TERMINAL_TYPE options."
```

### Client Prompts

```
"Connect to 127.0.0.1:{port} via Telnet. Wait for welcome message."
"Connect to 127.0.0.1:{port} via Telnet and send the command 'hello'."
"Connect to 127.0.0.1:{port} via Telnet. Handle option negotiation automatically."
```

## Runtime Expectations

**Per Test**:

- Server startup: 500ms
- Client connection: 500-1000ms
- Option negotiation: <100ms (automatic)
- Command execution: 200-500ms
- Total: ~2-3 seconds

**Full Suite**: ~6-10 seconds (3 tests)

## Future Improvements

1. **Interactive Session Test**: Multi-turn command/response
2. **Authentication Test**: Handle login/password prompts
3. **Binary Data Test**: Verify IAC escaping (255 255)
4. **Timeout Test**: Handle unresponsive servers
5. **Reconnection Test**: Client handles dropped connections

## Debugging Tips

**If tests fail**:

1. Check netget.log for detailed Telnet negotiation
2. Verify "nectar" dependency is available
3. Ensure server is bound before client connects (check logs)
4. Look for IAC command traces in debug output

**Common Failures**:

- `connection refused`: Server not started yet (increase sleep)
- `output_contains failed`: LLM didn't produce expected text (check prompt)
- `timeout`: LLM call took too long (check Ollama)

## References

- Implementation: `src/client/telnet/AGENTS.md`
- Protocol spec: RFC 854 (Telnet Protocol)
- Option specs: RFC 855-1143 (various Telnet options)
