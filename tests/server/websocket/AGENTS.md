# WebSocket Server E2E Tests

## Strategy: the peer is deliberately not a WebSocket library

The server's framing comes from `tokio-tungstenite`. Driving it with `tokio-tungstenite` would
prove only that the crate agrees with itself — the weak-evidence trap CLAUDE.md warns about, and
the reason several protocols rated `Stable` turned out to be broken.

So the primary peer is a **raw TCP client written inside `e2e_test.rs`** (`RawWsClient`, ~150
lines). It:

- composes the HTTP upgrade request by hand
- recomputes `Sec-WebSocket-Accept` from the RFC 6455 §4.2.2 algorithm using `sha1` + `base64`
  directly (both already dependencies), and compares it to what the server sent
- masks its own frames per §5.3 with an explicit XOR
- parses the server's frame headers byte by byte, so it can assert on FIN, opcode, the mask bit
  and the payload length encoding

That last point is what makes it worth the lines: it asserts the server **never masks** (§5.1),
which no high-level client API would expose.

`websocat` 1.14.1 is the second peer — a separately built, widely used binary — and runs the
same server end to end, and it **fails rather than skips** when `websocat` is absent. That is
what makes it evidence: a `SKIP: … is not installed` gate returns `Ok(())` on any runner without
the binary, which is a silent pass, and the rating would rest on nothing.

`websocat` 1.14.1 links `websocket-0.27.1` / `websocket-base-0.26.5` (rust-websocket), **not**
`tungstenite` — read out of the installed binary's embedded crate paths. So it is a genuinely
independent RFC 6455 implementation and not the circular-evidence case where the peer is the
same crate the server frames with.

## `real_client_test.rs` — every verb, three independent clients

The Stable rating's condition 1 rests here. Python `websockets` 15 (`peer/verbs.py`) and Node
`ws` 8 (`peer/verbs.cjs`) each run one scenario against a script-handled server with a 2-second
idle bound, and the test asserts their JSON report and the server's access log:

| Verb | What the client reports / the server saw |
|---|---|
| upgrade offering `v2.chat.example`, `chat` | `chat` agreed; the handshake event lists both |
| greeting in the accept | `welcome` is the first message |
| text, multi-byte UTF-8 | `echo:héllo ✓` |
| binary, not UTF-8 | `00fffe01807fc328` back byte for byte |
| one message in two frames | `echo:fragment`; the handler saw `fragment` |
| client Ping `p1` | Pong carrying `p1`; the handler saw `websocket_ping` with `p1` |
| 3 s of silence over a 2 s idle bound | still open (the server's keepalive Ping answered by the client; `ws` counts it) |
| server close (`close_websocket` 4002) | the client reads 4002 "asked to" |
| client close 4001 "bye" | the echo carries 4001; the handler saw 4001 "bye" |
| upgrade with no subprotocol | none agreed |
| upgrade to `/reject` | HTTP 403 |

`websocat` drives subprotocol, text, binary (`--binary`), its own Pings (`--ping-interval 1`) and
a close with `--close-status-code 4001`. Every session crosses `recording_relay`, and the pcap
oracle reads each upgraded one with `require_named("websocket")` and the refused one with
`http`. No LLM calls. Each test fails, never skips, without its peer.

## `limits_test.rs` — every size and time bound, both sides of the number

| Test | Inside | Past it |
|---|---|---|
| `the_request_head_limit_is_16_kib_exactly` | a 16 384-byte head is upgraded | 16 385 bytes, or 20 KiB with no blank line: 431 |
| `an_unfinished_request_head_is_answered_408_at_the_handshake_timeout` | a head finished at 400 ms of a 1 s bound | 408 at ~1 s |
| `an_uncompressed_frame_of_exactly_max_frame_size_is_taken_and_one_more_byte_is_1009` | 1000 of 1000 | 1001: Close 1009 |
| `a_compressed_frame_is_held_to_max_frame_size_too` | a compressed frame under 1000 bytes inflating to 5000 | a compressed frame over 1000 bytes: Close 1009 |
| `a_fragmented_message_of_exactly_max_message_size_is_taken_and_one_more_byte_is_1009` | 2 × 1000 of 2000 | 2001: Close 1009 |
| `a_message_inflating_to_exactly_max_message_size_is_taken_and_one_more_byte_is_1009` | inflates to 4096 of 4096 | 4097: Close 1009, `inflates past 4096` |
| `compressed_frames_past_max_message_size_are_refused_before_inflating` | — | compressed bytes past 4096: refused while collecting |
| `the_125_byte_floor_applies_to_a_smaller_max_message_size` | 125 under `max_message_size: 1` | 126: Close 1009 |
| `a_message_joined_by_wait_for_websocket_data_is_held_to_max_message_size` | two held 900-byte parts joined (1800) | a third: Close 1009 |
| `a_peer_outrunning_its_handler_is_held_back_by_the_byte_bound` | — | 64 KiB messages behind a parked handler: the peer's writes stop well short of 40 MiB |
| `a_peer_outrunning_its_handler_is_held_back_by_the_message_bound` | — | the same with empty messages |
| `a_mebibyte_compressed_message_in_one_byte_frames_is_answered_promptly` | the walk to the size bound, timed | — |

Verified by removal: with the deflate layer's frame limit set back to the message limit the
compressed-frame test fails (the oversized frame is echoed); with the backlog wait removed both
backlog tests fail (the peer writes the full 96 MiB); with the join check removed the joined
message test fails (no close); with `read_error_close` mapping nothing the 1009 tests fail on
EOF without a close frame; with the head check reading the whole buffer before the size test
the 16 385-byte head is upgraded.

## Tests

| Test | What it proves | LLM calls |
|---|---|---|
| `test_sec_websocket_accept_matches_the_rfc6455_worked_example` | the §1.3 published vector: `dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` | 0 |
| `test_accept_response_echoes_only_a_chosen_subprotocol` | no `Sec-WebSocket-Protocol` header when none was chosen | 0 |
| `test_parse_request_head_splits_target_and_headers` | path/query split; `Sec-WebSocket-Protocol` both repeated **and** comma-separated (§4.1) | 0 |
| `test_validate_upgrade_enforces_rfc6455_preconditions` | multi-token `Connection` accepted; version 8 → 426 **with** `Sec-WebSocket-Version: 13` (§4.4); short key → 400; POST → 405; plain GET → 400 | 0 |
| `test_binary_payload_encoding_is_symmetric` | encode/decode are inverses for non-UTF-8 bytes; no sniffing; bad input errors instead of panicking | 0 |
| `test_websocket_wire_protocol_against_raw_client` | the main one — see below | 1 |
| `test_non_upgrade_request_is_refused_without_a_model_call` | 400 and 426 are answered directly, and `verify_mocks` proves the model was never consulted | 0 extra |
| `test_websocket_subprotocol_and_rejection` | the model picks one offered subprotocol and it is echoed; its accept's `greeting` is the first frame; `websocket_connection_opened` is not asked (`expect_calls(0)`) because the model answered the handshake; a declined upgrade returns the handler's own status. The accept rule requires the event's `answer_with` to list the offered subprotocols, so it matches only when the hint reaches the model | 3 |
| `answer_with_test::an_unoffered_subprotocol_is_dropped_and_the_accept_stands` | an accept naming a subprotocol the client did not offer (none offered, or others offered) still accepts, with no subprotocol | 0 |
| `answer_with_test::an_offered_subprotocol_is_agreed` | an offered one is kept; accepting with none is always valid | 0 |
| `answer_with_test::the_hint_says_whether_anything_was_offered` | `handshake_answer_with` says that no subprotocol is normal, lists them when there are some, that a greeting goes in the accept only when the instructions ask for one, and that echoes wait for messages | 0 |
| `answer_with_test::an_accept_carries_its_greeting_and_an_empty_one_is_none` | the accept's `greeting` is kept word for word, an empty or absent one is none, a non-string one is refused | 0 |
| `answer_with_test::an_empty_greeting_is_dropped_but_an_empty_reply_is_sent` | while speaking first an empty text message is not sent, a real greeting is, and an empty reply afterwards is | 0 |
| `answer_with_test::the_opened_and_message_hints_leave_the_words_to_the_instructions` | the opened hint speaks first only when told to; the message hint's echo is the message's own text; no example on connect carries a greeting | 0 |
| `test_websocket_with_websocat` | a real external client gets the unprompted greeting and its echo | 1 |
| `test_websocket_handshake_backend_failure_is_tagged_fail_closed` | an unanswerable `websocket_handshake` is refused with 503, logged `decision=fail_closed_llm_error`, and never as `decision=model_reject` | 1 + one deliberately failing event |
| `connection_bounds_test::the_handshake_past_the_cap_gets_a_503_and_the_slot_comes_back` | 256 upgrades admitted, the 257th gets 503, closing one frees one slot | 0 |
| `connection_bounds_test::an_upgraded_peer_that_never_answers_the_keepalive_is_closed_with_1001` | a raw peer that never writes after the upgrade is sent the `netget-keepalive` Ping, then Close 1001, then EOF, at `idle_timeout_secs` (2s here) | 0 |
| `connection_bounds_test::a_client_that_only_answers_pings_is_not_closed` | a tokio-tungstenite client that sends nothing but its automatic Pongs is kept for five idle bounds and pinged at least twice | 0 |
| `connection_bounds_test::a_message_parked_for_a_human_keeps_its_connection` | a text message routed to `manual` keeps its connection for four idle bounds, and the busy connection is sent nothing — no Ping, no Close | 0 |

The three idle tests were verified by removal: with the watchdog arm disabled the first two
fail; with the keepalive Ping removed a live client is closed; with the `busy()` guards removed
the parked connection is sent Close 1001. The tungstenite client in the second is not circular
evidence in the sense the header warns about — it asserts this server's keepalive schedule, not
its framing.

### `test_websocket_wire_protocol_against_raw_client`

Six protocol-level assertions on one connection:

1. the server speaks **first** (`welcome` as a text frame, FIN set) — the unprompted direction
2. text round-trip including multi-byte UTF-8 (`héllo ✓`)
3. **the binary round-trip**: `00 ff fe 01 80 7f c3 28 0d 0a` — asserted not to be valid UTF-8 —
   is echoed and compared byte-for-byte. This is the `send_tcp_data` asymmetry bug
   (`d70bb5b5`) as a test: the static handler feeds the event's own `data` and `encoding`
   straight back into `send_websocket_binary`, so any disagreement between the two directions
   fails here.
4. a ping is answered by a **pong with the same payload** (§5.5.3)
5. two continuation frames (`frag` + `ment`, FIN clear then set) arrive at the handler as one
   reassembled `fragment`
6. a close with code 1000 is echoed with the same big-endian status code

## LLM call budget: 6 total, plus repair retries on one deliberate failure

The echo server used by three of the tests is configured entirely with **static handlers** in
the `open_server` action, so the handshake, the greeting, every echo, the ping and the close all
cost **zero** model calls. Only `test_websocket_subprotocol_and_rejection` spends calls on
events, because choosing a subprotocol and declining an upgrade are exactly the decisions worth
paying for.

`{{event.data}}` / `{{event.encoding}}` interpolation in the static handler is what makes the
binary round-trip testable without a model — see `src/scripting/event_handler.rs`.

## Mock expectations

Every test that starts a server ends with `server.verify_mocks().await?`. That is load-bearing
in `test_non_upgrade_request_is_refused_without_a_model_call`, where the *whole point* is that
the mock was called exactly once (the `open_server`) and not once more.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite \
    --test server -- server::websocket:: --test-threads=16
```

`NETGET_WS_PYTHON` and `NETGET_WS_NODE_MODULES` must be set (`install_peers.py`), and `websocat`
and `node` on `PATH`. All connections are to 127.0.0.1 on an ephemeral port; nothing external
is contacted.

## Known gaps

- **Autobahn** conformance is not run.
- `push_websocket_text` / `push_websocket_binary` / `list_websocket_connections` — the
  unprompted-push actions — are not covered end to end, because the harness has no way to send
  a user command to a running server mid-test.

## permessage-deflate: `deflate_real_client_test.rs`

Two independent RFC 7692 implementations, neither sharing code with tungstenite or with
`deflate.rs`, set up by `install_peers.py <dir>` (prints `NETGET_WS_PYTHON` and
`NETGET_WS_NODE_MODULES`; the tests fail rather than skip without them):

- **Python websockets 15** (`peer/deflate_peer.py`) through a TCP relay that records each
  frame's RSV1 bit and length: a short text, a 15 000-byte text, a text fragmented across three
  frames and a binary message come back echoed, and every frame NetGet sent had RSV1 set; the
  repetitive ones shrank to under half. The relay is the point — an uncompressed frame is legal
  on a deflate connection, so the library alone cannot show NetGet compressed.
- **Node ws 8** (`peer/ws_deflate.cjs`) offering a 10-bit window for the server and no context
  takeover either way. The long text repeats at a distance of 5000 bytes (an LCG block, built
  identically by both peers and the Rust tests), so a server compressing with a 15-bit window
  sends back-references ws cannot follow.
- With `permessage_deflate: false` the offer is declined and no frame has RSV1.
- A decompression bomb (a ~1 KB frame inflating to 1 MB, `max_message_size` 4096) closes the
  connection, never reaches the handler, and is refused by the inflate bound itself — asserted
  on its `decision=permessage_deflate_refused` line, because tungstenite's own message limit
  would also close the connection after a full inflation.

Mutation-checked: compressing with a 15-bit window regardless of the negotiation fails the ws
test; keeping the compression context when no-context-takeover was agreed fails it too;
removing the inflate bound fails the bomb test. CI: the `websocket-deflate-pairs` job in
`protocol-pairs.yml`.

## Stable conditions 2 and 3: the pcap oracle and the fuzz target

**Condition 2.** `deflate_real_client_test.rs::python_websockets_reads_compressed_frames_from_netget`
runs through a recording relay, and the pcap oracle reads the session with Wireshark's `http`
and `websocket` dissectors — the upgrade, the 101 with its `Sec-WebSocket-Extensions`, and every
frame after it, which tshark inflates itself. `require_named("websocket")` fails it if no frame
was dissected. The other peers' sessions (node `ws`, websocat) are not captured.

**Condition 3.** `fuzz/fuzz_targets/websocket_session.rs` drives the whole inbound stack —
`parse_request_head`, `validate_upgrade`, `deflate::negotiate`, then `DeflateStream` under
tungstenite's server-role decoder on an in-memory socket. WebSocket does not nest; the corpus
carries a 64 MiB decompression bomb in one frame, a frame declaring 2^63 - 1 bytes and a
20 000-fragment message. run 120 s clean on 1 November 2026 (unoptimised, `-s none`, macOS): 3 986 executions, no crash.
