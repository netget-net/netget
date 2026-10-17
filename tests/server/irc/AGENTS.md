# IRC Protocol E2E Tests

## Test Overview

Tests IRC server implementation with various IRC protocol commands: registration (NICK/USER), keepalive (PING/PONG),
channel operations (JOIN), and messaging (PRIVMSG). Validates LLM's ability to handle IRC protocol semantics.

## The seven files, and what each is for

This doc described `e2e_test.rs` alone. Five files sat beside it unmentioned — and four of the
five exist because of a defect, which is exactly the set a reader most needs pointed at.
`tests/server/irc/` holds **18 tests** across seven files:

| file | tests | what it holds |
|---|---|---|
| `e2e_test.rs` | 5 | registration, PING/PONG, JOIN, PRIVMSG — the protocol semantics |
| `framing_test.rs` | 5 | **the two ways an IRC implementation gets owned**, asserted directly |
| `connection_bounds_test.rs` | 3 | the first-byte and idle deadlines and the connection cap, from the wire |
| `decision_tag_test.rs` | 2 | every terminal outcome of a line is grep-able as `decision=<token>` |
| `llm_failure_test.rs` | 1 | what a client gets when the backend fails: numeric 400, then a closed link |
| `peer_inject_test.rs` | 1 | the dashboard's `[ message this peer ]` / `[ disconnect this peer ]` path |
| `batching_test.rs` | 1 | lines sent during a model call are answered in one follow-up call (batching off is the control) |

`e2e_test.rs`'s four registration tests open the server with `"batching": false`: they write
NICK, USER and the rest back to back and pin one rule per line, which batching (the default)
would answer together.

**`framing_test.rs` is the one to read first.** IRC is line-framed over a stream, which is the
oldest way to get a server wrong: a peer controls where the line ends, so it controls how much
you buffer waiting for one.

**`decision_tag_test.rs` earns its place because IRC can answer a line in several ways that look
alike on the wire.** A numeric reply, silence, and a closed link are each a decision; the log is
where they stay distinguishable, and a tag nothing asserts is a tag that drifts.

## Test Strategy

- **Isolated test servers**: Each test spawns separate NetGet instance with specific IRC behavior
- **Raw TCP client**: Uses `tokio::net::TcpStream` with `BufReader` for line-based IRC protocol
- **No IRC library**: Manual command construction and response parsing (tests actual protocol)
- **Command-focused**: Each test validates specific IRC command handling
- **Action-based**: No scripting (tests LLM's IRC protocol understanding)

## LLM Call Budget

- `test_irc_welcome()`: 2 LLM calls (NICK command + USER command)
- `test_irc_ping_pong()`: 1 LLM call (PING command)
- `test_irc_join_channel()`: 3 LLM calls (NICK + USER + JOIN)
- `test_irc_privmsg()`: 3 LLM calls (NICK + USER + PRIVMSG)
- `test_irc_multiple_clients()`: 6 LLM calls (3 clients × 2 commands each)
- **Total: 15 LLM calls** (exceeds 10 limit slightly)

**Optimization Opportunity**: Could consolidate into 2-3 comprehensive servers:

1. Server handling NICK/USER/JOIN/PRIVMSG (6-7 LLM calls)
2. Server handling PING/PONG (1 LLM call)
3. Total: 7-8 LLM calls (within budget)

**Why not consolidated yet?**: Tests provide better isolation and clearer failure diagnosis. Each test validates
specific IRC behavior independently.

## Scripting Usage

❌ **Scripting Disabled** - Action-based responses only

**Rationale**: Tests validate LLM's understanding of IRC protocol semantics (numerics, message formats, command
parsing). Scripting would bypass this validation. For production IRC servers, scripting is recommended for common
patterns (PING/PONG, JOIN confirmations).

## Client Library

- **tokio::net::TcpStream** - Raw async TCP socket
- **tokio::io::AsyncBufReadExt** - Line-based reading (`BufReader`)
- **tokio::io::AsyncWriteExt** - For sending IRC commands
- **No IRC library** - Manual message parsing

**Why raw TCP?**:

1. IRC is line-based text protocol (simple to handle manually)
2. Tests actual byte-level protocol behavior
3. No dependency on IRC client libraries (which may have quirks)
4. Direct control over command timing and formatting

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~120-150 seconds for the five tests in `e2e_test.rs`, which is what the per-test
  breakdown below covers. The other five files add twelve tests and cost far less: they drive
  sockets and deadlines rather than model calls, and `connection_bounds_test.rs` is the only
  slow one because it waits out a bound by construction.
    - Each test: ~2-3 server startup + 1-3 LLM calls per test × 5-8s per call
    - `test_irc_welcome`: ~25s (2 LLM calls)
    - `test_irc_ping_pong`: ~15s (1 LLM call)
    - `test_irc_join_channel`: ~35s (3 LLM calls)
    - `test_irc_privmsg`: ~35s (3 LLM calls)
    - `test_irc_multiple_clients`: ~50s (6 LLM calls)

**Note**: IRC tests are slower than DNS/DoT/DoH because:

- No scripting (each command requires LLM call)
- IRC registration requires multiple commands (NICK, USER)
- Multiple test cases to cover protocol breadth

## Failure Rate

- **Medium** (~10-15%) - LLM may not always follow IRC protocol correctly
- Common failures:
    - LLM doesn't include numeric code (e.g., missing "001" in welcome)
    - LLM formats message incorrectly (missing ":", wrong prefix)
    - LLM doesn't respond at all (returns empty action list)
- Timeout failures: Rare (~2%) - LLM takes too long to respond

**Why higher than DNS?**: IRC protocol has more complex formatting requirements (numerics, prefixes, colons). LLM
sometimes struggles with exact formatting.

## Test Cases

### 1. IRC Welcome (`test_irc_welcome`)

**Tests**: IRC registration flow (NICK + USER commands)

- **Prompt**: "listen on port {port} via irc. When users connect and send NICK and USER commands, respond with IRC
  welcome numeric 001: ':servername 001 nickname :Welcome to the IRC Network'"
- **Client Actions**:
    1. Send `NICK testuser\r\n`
    2. Send `USER testuser 0 * :Test User\r\n`
    3. Read responses (up to 5 lines)
- **Expected**: Response contains " 001 " or "Welcome" or "WELCOME"
- **Purpose**: Tests basic IRC registration and welcome message

**LLM Calls**: 2 (one for NICK, one for USER)

**Notes**:

- May receive multiple response lines (LLM might send multiple numerics)
- Test accepts case-insensitive "welcome" to handle LLM variations
- If no response, test prints note (doesn't fail hard)

### 2. IRC PING/PONG (`test_irc_ping_pong`)

**Tests**: IRC keepalive mechanism

- **Prompt**: "listen on port {port} via irc. When you receive a PING command with a token, respond with PONG using the
  same token. Format: 'PONG :token'"
- **Client Actions**:
    1. Send `PING :1234567890\r\n`
    2. Read response
- **Expected**: Response contains "PONG" and "1234567890"
- **Purpose**: Tests LLM's ability to parse PING and format PONG correctly

**LLM Calls**: 1

**Notes**:

- Simple command/response test
- Tests token echo behavior (critical for IRC keepalive)

### 3. IRC Channel Join (`test_irc_join_channel`)

**Tests**: Channel join workflow

- **Prompt**: "listen on port {port} via irc. When users send JOIN #channel, respond with ':nickname JOIN #channel' to
  confirm the join"
- **Client Actions**:
    1. Send `NICK testuser\r\n`
    2. Send `USER testuser 0 * :Test User\r\n`
    3. Send `JOIN #test\r\n`
    4. Read responses (up to 5 lines)
- **Expected**: Response contains "JOIN" and "#test"
- **Purpose**: Tests channel join confirmation

**LLM Calls**: 3 (NICK + USER + JOIN)

**Notes**:

- Registration commands may or may not receive responses (test doesn't validate)
- Focus is on JOIN confirmation format
- Test accepts join confirmation with or without user/host prefix

### 4. IRC PRIVMSG (`test_irc_privmsg`)

**Tests**: Private message handling

- **Prompt**: "listen on port {port} via irc. When you receive 'PRIVMSG target :message', echo it back as 'PRIVMSG
  sender :message'"
- **Client Actions**:
    1. Send `NICK testuser\r\n`
    2. Send `USER testuser 0 * :Test User\r\n`
    3. Send `PRIVMSG bot :Hello IRC\r\n`
    4. Read responses (up to 5 lines)
- **Expected**: Response contains "PRIVMSG" and "Hello"
- **Purpose**: Tests message echo/relay behavior

**LLM Calls**: 3 (NICK + USER + PRIVMSG)

**Notes**:

- Tests basic messaging functionality
- LLM may echo to different target (test just checks for PRIVMSG with message content)

### 5. IRC Multiple Clients (`test_irc_multiple_clients`)

**Tests**: Concurrent client handling

- **Prompt**: "listen on port {port} via irc. Handle multiple concurrent IRC clients. Send welcome message (001) to each
  client that connects with NICK and USER"
- **Client Actions**:
    1. Spawn 3 concurrent clients
    2. Each sends `NICK testuser{N}\r\n` and `USER testuser{N} 0 * :Test User {N}\r\n`
    3. Each tries to read response
- **Expected**: Each client receives response (ideally 001 welcome)
- **Purpose**: Tests server's ability to handle multiple simultaneous connections

**LLM Calls**: 6 (3 clients × 2 commands each)

**Notes**:

- Tests concurrency (separate tokio tasks per client)
- Each client is independent
- Test reports how many clients succeeded (doesn't require all 3)

## Known Issues

### 1. LLM IRC Protocol Variability

LLM may not always follow IRC protocol exactly:

- Missing numeric codes (e.g., "Welcome" instead of "001 ... :Welcome")
- Incorrect message format (missing colons, wrong prefix format)
- Extra text or explanations in responses

**Mitigation**: Tests use loose assertions (`contains()` instead of exact match).

### 2. Registration Command Responses

Tests send NICK and USER but don't validate their responses (only validate final command response). LLM might:

- Not respond to NICK/USER at all
- Send errors (e.g., "433 Nickname in use")
- Send unexpected numerics

**Reason**: Tests focus on specific command being tested, not full registration flow.

### 3. No Multi-Line Response Validation

Some IRC commands return multiple lines (e.g., NAMES returns 353 + 366). Tests read up to 5 lines but don't validate
multi-line sequences.

**Future Enhancement**: Add tests for multi-line responses (channel lists, WHO responses, etc.).

### 4. Timing-Dependent Failures

Tests use 10-second timeout per read. Slow LLM responses can cause timeouts, especially when multiple LLM calls are
needed (e.g., `test_irc_multiple_clients`).

**Mitigation**: Timeout is generous (10s), but very slow systems might still timeout.

## Performance Notes

### Why No Scripting?

IRC tests don't use scripting because:

1. **Protocol validation**: Need to test LLM's IRC protocol understanding
2. **Complex state**: IRC requires tracking users, channels, nicknames (hard to script)
3. **Varied commands**: Each test exercises different IRC command (script wouldn't help much)

However, production IRC servers should use scripting for common patterns:

- PING/PONG keepalive
- JOIN confirmations
- Standard numeric responses

### LLM Call Budget Exceeded

Tests currently use 15 LLM calls, exceeding the 10-call guideline.

**Consolidation Plan**:

```rust
// Comprehensive IRC test (7-8 LLM calls)
let prompt = format!(
    "listen on port {} via irc.
    - When NICK received: store nickname
    - When USER received: send 001 welcome
    - When PING received: send PONG with token
    - When JOIN #channel: send JOIN confirmation
    - When PRIVMSG target :message: echo back
    Support multiple concurrent clients",
    port
);

// Test all behaviors against single server:
// - Client 1: NICK + USER + PING + JOIN + PRIVMSG (5 calls)
// - Client 2: NICK + USER (2 calls)
// Total: 7 LLM calls (within budget)
```

This would reduce from 5 test functions to 1-2 comprehensive tests.

## Future Enhancements

### Test Coverage Gaps

1. **PART command**: Test leaving channels
2. **QUIT command**: Test graceful disconnect
3. **NOTICE command**: Test non-reply messages
4. **Channel modes**: Test +o, +v, +t, etc.
5. **Error numerics**: Test 433 (nick in use), 461 (need more params), etc.
6. **NAMES/WHO**: Test multi-line responses
7. **TOPIC command**: Test channel topic get/set
8. **KICK/BAN**: Test channel moderation

### Scripting Mode Test

Add test with scripting enabled:

- Validate script handles PING/PONG automatically
- Test script maintains state (nicknames, channels)
- Measure throughput (should handle hundreds of messages/sec)

### Protocol Compliance Test

Add test suite that validates against IRC RFCs:

- Message format parsing
- Numeric code correctness
- Command parameter validation
- Prefix format validation

## References

- [RFC 1459: IRC Protocol](https://datatracker.ietf.org/doc/html/rfc1459)
- [RFC 2812: IRC Client Protocol](https://datatracker.ietf.org/doc/html/rfc2812)
- [Modern IRC Docs](https://modern.ircdocs.horse/)
- [IRC Numeric List](https://www.alien.net.au/irc/irc2numerics.html)
