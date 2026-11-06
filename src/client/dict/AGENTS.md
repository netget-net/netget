# DICT client

Uses the existing `dict` feature with no extra dependencies. Canonical name DICT,
TCP/2628. Specification: https://www.rfc-editor.org/rfc/rfc2229.html

`dict_request` supports define, match, databases (SHOW DB), strategies (SHOW STRAT),
info (SHOW INFO), server (SHOW SERVER), status, help, client and quit. Words, database
names, strategy and client identification are structured fields; Rust quotes and escapes
them and rejects controls before writing. DEFINE/MATCH default database to `*`, MATCH
strategy to `.`. There is no raw command action.

`dict_connected` occurs only after the real 220 greeting and includes its text. Subsequent
`dict_response` events contain the request and a response with code plus definitions,
entries, text, message or protocol error. Definitions carry word, database, database
description and decoded text. Listing counts and the final 250 are checked. The first
three parameters of a 151 response carry its structured fields; following explanatory
text is permitted by RFC 2229. Dot-stuffed text is decoded, with CRLF normalized to LF.
A leading single dot followed by text is preserved: dictd1.13.3 emits this for some
dictionary text, and only a line containing exactly a dot terminates a block.

All events use call_llm_for_client (static/script/manual handlers, memory and LLM budgets).
The separately tracked handler task cannot block injected commands. A tracked I/O task
owns the socket and a command handle is registered before reading the greeting. Injected
`disconnect` interrupts a stalled greeting or transaction; requests while either is pending
receive a busy rejection. Request/reply transactions are serialized, with bounded event
and handler-action queues of 16. Clean EOF drains the final event; removal aborts both tasks.
QUIT waits for the 221 reply before closing. 4xx/5xx replies are surfaced as errors, without
inventing definitions or retrying automatically. Malformed/truncated responses fail the session.
Every event carries its depth in the handler chain; an answer to an event at depth
`wire::MAX_FOLLOWUPS` (4) is logged and not sent, so a model that answers every response
with another request stops there. `tests/client/dict/real_server_test.rs` counts the DEFINEs
in dictd's own command log.

Bounds: connect/write/greeting/complete-response deadlines 30s; outbound commands1024 bytes;
response line64KiB; response total1MiB; block lines/list rows/definitions4096. These local
resource caps are deliberately explicit (RFC 2229 describes command length in characters).
A transaction deadline covers the whole response, so slow trickles cannot keep it alive.

No dictionary storage exists. Plain TCP and UTF-8 only; AUTH, SASL, OPTION MIME and command
pipelining are not implemented. Evidence includes independent
dictd1.13.3/rf, the existing NetGet server, framing negatives and lifecycle regressions.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/dict/`:

1. the peer is dictd 1.13 serving a dictfmt fixture — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: dictd's own command log shows the DEFINE the mocked model chose, and counts the bounded chain. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
