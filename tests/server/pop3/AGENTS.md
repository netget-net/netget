# POP3 Protocol E2E Tests

## Test Overview

Tests POP3 server with raw TCP clients validating RFC 1939 command/response sequences.

## Test Strategy

- **Consolidated tests** - Each test focuses on a specific POP3 workflow
- **Multiple server instances** - 4 separate servers (one per test)
- **Real TCP clients** - Manual socket I/O with line-based protocol
- **No POP3 library** - Tests use `tokio::net::TcpStream` directly

## LLM Call Budget

- `test_pop3_greeting()`: 1 startup call (greeting on connect)
- `test_pop3_authentication()`: 1 startup call + 2 commands (USER, PASS)
- `test_pop3_stat()`: 1 startup call + 3 commands (USER, PASS, STAT)
- `test_pop3_quit()`: 1 startup call + 1 QUIT command
- `answer_with_test.rs`: 1 startup call + 5 events (greeting, USER, STAT, RETR 1, RETR 2). `CAPA` is answered
  by NetGet and never reaches the model, so no test mocks it.
- **Total: 18 LLM calls** (5 startups + 13 command calls)

## `answer_with_test.rs` - each command told its answer, and given exactly one

Pins, from the wire, what the real-model eval's `pop3/message-subject` (0/5) needed. Every rule
matches on the event's `answer_with` and `message_number`, so a missing hint is an unmatched
event:

- the greeting is answered with a greeting **and** a stray `+OK`; the client must read the
  greeting, then NetGet's `CAPA` block, then `USER`'s own `+OK` - never the stray one;
- `CAPA` is `+OK Capability list follows` / `USER` / `TOP` / `UIDL` / `RESP-CODES` / `.`, with
  no rule for it (an event would fail the session);
- `RETR 1` is answered with `from`/`subject`/`body` fields; the client must read the headers
  NetGet wrote, a byte-stuffed body line, the `.`, and an octet count equal to what was sent;
- `STAT` is answered with a bare `+OK` and then the `STAT` line; the client must read the
  `STAT` line, the reply of the action `answer_with` names;
- `RETR 2` is answered with a `+OK` and the message as raw `send_pop3_message` text; the client
  must read it framed, terminating `.` included (`decision=multiline_assembled`);
- `decision=duplicate_response_dropped` and `decision=netget_answer` are in the log.

Verified by removing the drop (the stray `+OK` precedes the `CAPA` block), the preferred reply
(`STAT` reads the bare `+OK`), the `CAPA` answer (the session fails on an unmatched event) and
the `RETR` assembly (the client waits for a `.` that never comes).

## Scripting Usage

**Scripting Disabled** - POP3 tests use action-based responses only

- POP3 protocol is conversational (each command requires context)
- Script generation not beneficial for command/response patterns
- LLM interprets each command dynamically
- State machine (Authorization → Transaction → Update) managed by LLM

## `real_client_test.rs` - two independent clients

python3's stdlib `poplib` (14 LLM calls: every transaction command on one connection) and
curl's libcurl POP3 (11: a listing and a retrieval, each its own connection), each failing
rather than skipping when its client is absent. One mock rule per verb, keyed on the
`answer_with` hint, so `verify_mocks` counts what each client drove. The message served has a
line starting with `.` and multi-byte UTF-8, so the test sees both the unstuffing and that
`RETR`'s octet count equals the `LIST` size. The pcap oracle reads poplib's session through
`helpers::recording_relay`.

## Client Library

**Manual TCP Client** for every file except `real_client_test.rs`

- `tokio::net::TcpStream` for connections
- `BufReader::read_line()` for reading responses
- `AsyncWriteExt::write_all()` for sending commands
- Line-based parsing with `\r\n` terminators

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~45-60 seconds for full test suite
- Moderate speed due to 12 LLM calls

## Failure Rate

- **Low-Medium** (5-10%) - Occasional LLM non-compliance
- LLM may not format POP3 responses correctly (missing \r\n, wrong prefix)
- Most common issue: LLM returns prose instead of protocol responses
- LLM may forget +OK/-ERR prefix

## Test Cases

1. **test_pop3_greeting** - Validates +OK greeting on connect
2. **test_pop3_authentication** - Tests USER and PASS commands with +OK responses
3. **test_pop3_stat** - Tests STAT command for mailbox status (message count, total size)
4. **test_pop3_quit** - Tests QUIT command and +OK response
5. **answer_with_test** - `answer_with`, one reply per command, structured `RETR`, `CAPA` (above)

## Known Issues

- **Lenient assertions** - Tests check for response codes anywhere in output (not just at start)
- Some tests may pass even if responses are malformed
- LLM occasionally forgets to send greeting on connection
- Timeouts set to 10 seconds to accommodate slow LLM responses
- Multiline responses (LIST, RETR) not tested yet (future enhancement)

## Example Test Pattern

```rust
// Start server with prompt
let server = start_netget_server(ServerConfig::new(prompt)).await?;

// Connect via TCP
let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
let (read_half, mut write_half) = stream.into_split();
let mut reader = BufReader::new(read_half);

// Read greeting
let mut line = String::new();
reader.read_line(&mut line).await?;

// Send POP3 command
write_half.write_all(b"USER alice\r\n").await?;

// Read response
line.clear();
reader.read_line(&mut line).await?;
assert!(line.contains("+OK"));
```

## Future Enhancements

1. **Multiline response testing** - Test LIST, RETR, UIDL, TOP commands
2. **Error handling** - Test -ERR responses for invalid commands
3. **Message retrieval** - Test RETR command with full email content
4. **Deletion** - Test DELE command for message deletion
5. **TLS support** - Test POP3S (implicit TLS on port 995)

## `connection_bounds_test.rs` — 5 in-process tests, **0 LLM calls** (the backend is a dead port)

The read deadlines in `src/server/pop3/mod.rs` — `FIRST_COMMAND_READ_TIMEOUT` (300s) and `IDLE_BETWEEN_COMMANDS_TIMEOUT` (600s) — driven from the wire. No
mock: these assert on *clocks*, not on answers, and a reachable backend would only add noise.
Loopback only.

**What each test is for.** A peer that has connected and said nothing must eventually be let go
of, because nothing else in the process will close that socket. A connection whose answer is
parked for a human must **not** be let go of, which is what stops the lazy fix of wrapping the
answer in the deadline as well as the read. The two bounds are different claims, so one test
drives a connection into the post-answer state and checks it is governed by `idle_timeout_secs`
rather than by the first-byte one; the connection past `MAX_CONNECTIONS` is refused in POP3's own words and then a clean EOF.

**The last test is the regression, and it is deliberately the slow one.** The first-byte bound
was 60 seconds, and NetGet's own POP3 client is precisely a peer that bound stranded:
`src/client/pop3/mod.rs` reads the `+OK` greeting in its read loop and writes nothing until an action or `[ send message ]` says to, and a client made from the dashboard is routed `*` → manual — so it connects and
waits for a person, who gets 300 seconds (`src/state/intercepts.rs`). It is now 300s. Proving
that means holding a silent peer open **past 60 seconds with no startup parameters passed at
all**, so the wait cannot be made cheaper than the claim.

Every other test passes a short override instead of waiting the default out, which is also what
proves `first_byte_timeout_secs` and `idle_timeout_secs` are read rather than merely declared:
a parameter that was ignored would leave the 300-second default in force and the test would time
out. Each bound was verified by removing it and watching its test fail, and the default was
verified by putting 60 back and watching the regression test fail.
