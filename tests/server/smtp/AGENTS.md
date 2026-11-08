# SMTP Protocol E2E Tests

## Test Overview

Tests SMTP server with raw TCP clients validating RFC 5321 command/response sequences.

## Test Strategy

- **Consolidated tests** - Each test focuses on a specific SMTP workflow
- **Multiple server instances** - 5 separate servers (one per test)
- **Real TCP clients** - Manual socket I/O with line-based protocol
- **No SMTP library** - Tests use `tokio::net::TcpStream` directly

## LLM Call Budget

`EHLO`/`HELO` are answered by NetGet and never reach the model, so no test mocks them; an EHLO
rule would report zero calls.

- `test_smtp_greeting()`: 1 startup call + 1 greeting
- `test_smtp_ehlo()`: 1 startup call + 1 greeting. Asserts NetGet's EHLO/HELO replies byte for
  byte (`250-mail.test greets client.test`, `250 8BITMIME`), and `501` for a bare `EHLO`
- `test_smtp_mail_transaction()`: 1 startup call + 4 mocked `smtp_command` events (greeting on
  connect, MAIL FROM, RCPT TO, DATA). Every step **must** have an event mock: an
  unmatched event returns HTTP 500 from the mock, the greeting then fails closed with a 421
  that closes the session, and every later write dies on a broken pipe.
- `test_smtp_quit()`: 1 startup call + 1 QUIT command
- `test_smtp_error_handling()`: 1 startup call + 1 invalid command
- `answer_with_test.rs`: 1 startup call + 7 events (greeting, MAIL, two RCPT, DATA, a body
  line, `.`)
- `llm_failure_test.rs`: the 451 case fails on `MAIL FROM`, not `EHLO`, since `EHLO` no longer
  reaches the backend

## `answer_with_test.rs` - one reply per command, and each told its answer

The real-model eval's SMTP failures were one action reused for a whole session. This test pins
the fix from the wire, with every rule matched on the event's `answer_with` / `address` /
`domain` rather than on the raw command, so a missing hint is an unmatched event:

- the greeting is answered with **two** banners and the client must read the first and then
  NetGet's EHLO reply - not the second banner;
- `MAIL` is answered with two replies and the next `RCPT` must read its own `550`;
- inside `DATA`, a body line reading `EHLO …` must not be answered by NetGet and reaches the
  model inside the one event for the whole message (its `body`);
- `decision=duplicate_response_dropped` is in the log.

Verified by removing the drop (RCPT reads the stale `250`) and by answering `EHLO` inside
`DATA` (the client reads an EHLO reply where the `.`'s `250` belongs).

## Scripting Usage

**Scripting Disabled** - SMTP tests use action-based responses only

- SMTP protocol is conversational (each command requires context)
- Script generation not beneficial for command/response patterns
- LLM interprets each command dynamically

## `real_client_test.rs` - two independent clients

python3's stdlib `smtplib` (12 LLM calls) and curl's libcurl SMTP (8), each against its own
server, each failing rather than skipping when its client is absent. One mock rule per verb, so
`verify_mocks` counts what each client drove; the message rule records the event and answers
with what it saw (`queued: <bytes> bytes, subject <subject>`), so the client's own output
shows the model's view. The pcap oracle reads smtplib's session through
`helpers::recording_relay`. The header lists the verbs each client drives and the defects
they found.

## `data_framing_test.rs` - where a message ends, and how large it may be

A raw socket sends `<LF>.<LF>` and `<LF>.<CRLF>` inside a message with a `MAIL FROM` behind
them: the model must receive one message containing that line. Then a message one byte over
`MAX_MESSAGE_BYTES` must get `552 5.3.4` from NetGet with no model call. 8 LLM calls.

## Client Library

**Manual TCP Client** for every file except `real_client_test.rs`

- `tokio::net::TcpStream` for connections
- `BufReader::read_line()` for reading responses
- `AsyncWriteExt::write_all()` for sending commands
- Line-based parsing with `\r\n` terminators

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~60-90 seconds for full test suite
- Moderate speed due to 15 LLM calls

## Failure Rate

- **Low-Medium** (5-10%) - Occasional LLM non-compliance
- LLM may not format SMTP responses correctly (missing \r\n, wrong code)
- Most common issue: LLM returns prose instead of protocol responses

## Test Cases

1. **test_smtp_greeting** - Validates 220 greeting on connect
2. **test_smtp_ehlo** - NetGet's own EHLO/HELO replies, byte for byte, with no model call
3. **test_smtp_mail_transaction** - Full mail transaction (EHLO → MAIL FROM → RCPT TO → DATA)
4. **test_smtp_quit** - Tests QUIT command and 221 response
5. **test_smtp_error_handling** - Validates 5xx error for invalid commands
6. **answer_with_test** - `answer_with`, one reply per command, `DATA` mode (above)

## Known Issues

- **Lenient assertions** - Some tests still check for response codes anywhere in output;
  `test_smtp_greeting` and `test_smtp_mail_transaction` now assert `starts_with` on each
  reply code and fail on a missing/timed-out reply instead of printing a note
- Some of the remaining tolerant tests may pass even if responses are malformed
- LLM occasionally forgets to send greeting on connection
- Timeouts set to 10 seconds to accommodate slow LLM responses

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

// Send SMTP command
write_half.write_all(b"EHLO client.test\r\n").await?;

// Read response
line.clear();
reader.read_line(&mut line).await?;
assert!(line.contains("250"));
```
