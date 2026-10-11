# WebSocket Client E2E Tests

## Strategy: a hand-written server as the peer

The client is built on `tokio-tungstenite`, so testing it against the NetGet WebSocket server
would test that crate against itself. Instead `e2e_test.rs` contains a **hand-written WebSocket
server** (~180 lines): it parses the upgrade request itself, recomputes `Sec-WebSocket-Accept`
from the RFC algorithm with `sha1` + `base64` directly, and reads the client's frames byte by
byte.

The byte-level reading is the point. A WebSocket *client* can violate RFC 6455 §5.3 — "every
client-to-server frame MUST be masked with a fresh 32-bit key" — completely invisibly, because
plenty of servers accept unmasked frames anyway. Only a peer that inspects the mask bit will ever
notice. `Observed.all_frames_masked` is that assertion.

## The one test

`test_websocket_client_against_hand_written_server` asserts, in order:

1. the request is `GET … HTTP/1.1` with `Upgrade: websocket`, `Connection: Upgrade` and
   `Sec-WebSocket-Version: 13`
2. `Sec-WebSocket-Key` decodes to **exactly 16 bytes** of base64 (§4.1)
3. the `path` startup parameter reaches the request line (`/ws`)
4. the `subprotocols` startup parameter reaches `Sec-WebSocket-Protocol` **in order**
   (`chat, superchat`)
5. **every** client frame carries the mask bit
6. the client sends the text frame the `websocket_client_connected` handler asked for
7. **the binary round-trip**: the server sends `00 ff fe 01 80 7f c3 28` (not valid UTF-8, not
   printable); the mock feeds the event's own `data` and `encoding` straight back into
   `send_websocket_binary`; the bytes that come back are compared byte-for-byte

Step 7 uses `respond_with_actions_from_event`, which is the only way to prove symmetry — a static
mock would hardcode the encoded form and could pass while the two directions disagreed.

The server then sends a close frame with code 1000 so `websocket_client_closed` fires.

## LLM call budget: 4

`open_client`, `websocket_client_connected`, `websocket_client_binary_message`, and
`websocket_client_closed` (declared `expect_at_least(0)` — the process may be torn down before
the close event is processed, and that is not what this test is about).

The test ends with `client.verify_mocks().await?`.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features websocket \
    --test client websocket -- --test-threads=100
```

Expected runtime: ~1.5s. The hand-written server binds 127.0.0.1:0; nothing external is
contacted.

## Known gaps

- `wss://` is not testable — the client has no TLS backend by design.
- The `headers` startup parameter (and the ignore-list for handshake headers) is not covered.
- Fragmented **inbound** messages are not exercised on the client side, only the server side.
- `wait_for_websocket_data` on the client has no assertion.

## `command_channel_test.rs` — the dashboard's `[ send ]`

A second, cheaper peer: a **NetGet WebSocket server** with static handlers (`websocket_handshake`
→ `accept_websocket`, `*` → no actions). The point here is not the framing — `e2e_test.rs` owns
that — but the injection path, so a NetGet server is the right peer: its access log is the proof
the frame arrived.

**LLM calls: 0.** Both sides answer from static handlers, and the client's LLM URL is
`http://127.0.0.1:1`, so its `websocket_client_connected` call fails; the loop has to tolerate
that and the command task must be independent of it.

Asserts, in order: the command handle exists **before** anything is sent (the regression guard
for registering the channel ahead of the connected-event LLM call); `send_websocket_text` returns
`Sent { bytes_sent: 16 }` for a 16-byte payload; the injection appears in the client's access log
and the text in the server's; a payload-less ping returns `Executed`, not `Sent{0}`; close code
1006 is `Rejected` by the protocol's own validation; a polite close returns `Disconnected` and the
command handle disappears.

## `keepalive_test.rs` — Pings are answered while a turn is parked

The peer is a **NetGet WebSocket server** with `idle_timeout_secs = 2`: it Pings at one second
and closes with 1001 a peer that has sent no frame, not even a Pong, for two. That is
deliberately NetGet against NetGet — the server's liveness bound is what the client has to
satisfy, and no third-party server here has a bound short enough to test in seconds. It is
regression evidence for the client's keep-alive, not interoperability evidence.

Two turns are parked on `manual` rules for ten seconds each: `websocket_client_connected`, then
`websocket_client_text_message` for the server's static reply to the first answer. After each
park the server must still list the connection as live, and after each answer the answered text
must appear in the server's access log. **LLM calls: 0.** Runtime ~20s, almost all of it the two
deliberate parks.

Verified by removal both ways: with the pre-split client (connected turn run inside `connect()`,
before any read loop) the first park fails; with the read loop calling `handle_inbound` inline
instead of queueing, the second park fails — `left: 0, right: 1` on the live-connection count in
both cases.

## permessage-deflate: `deflate_real_server_test.rs`

The client against Python websockets 15 and Node ws 8 servers (peers and install as in
`tests/server/websocket/AGENTS.md`). Python's server defaults impose 12-bit windows; NetGet's
15 000-byte message repeats at a distance of 5000, so the relay's frame length is itself the
evidence the window was honoured — compressed (under 15 000 bytes, RSV1 set) but not below half,
because within 4 KiB the repeats cannot be referenced. Node runs with no context takeover and
receives two long messages, each compressed from a fresh context. Mutation-checked as above.
