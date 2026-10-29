# tests/server/bitcoin

Bitcoin P2P **server**. Every peer here is a raw `tokio::net::TcpStream` with messages built
and parsed by the `bitcoin` crate used as a codec. There is no third-party Bitcoin node in
this suite — no `bitcoind`, no regtest, nothing to install — which is exactly why
`src/server/bitcoin` is `DevelopmentState::Experimental` and must stay there. A codec on both
ends proves the framing round-trips through one crate; it does not prove a real node would
accept our handshake.

## Files

### `e2e_test.rs` — four mocked E2E tests, **17 LLM calls**

Spawns the NetGet binary with a mock Ollama (`NetGetConfig::with_mock`). Every rule is
`.expect_calls(1)`.

| test | calls | what it drives |
|---|---|---|
| `test_bitcoin_version_verack_handshake` | 4 | startup, `bitcoin_connection_opened`, version → `send_version` + `send_verack`, verack → nothing |
| `test_bitcoin_ping_pong` | 5 | the above plus ping → `send_pong` echoing the nonce |
| `test_bitcoin_getaddr` | 5 | the above plus getaddr → no response (no peers to share) |
| `test_bitcoin_testnet` | 3 | startup with `network=testnet`, connection opened, version → testnet `send_version` |

`build_version_message()` and `read_bitcoin_message()` are **local `fn`s inside this file**,
not shared helpers — copy them, don't import them.

Three `bitcoin_message_received` rules coexist per test and are separated only by
`.and_event_data_contains("message_type", …)`. Rules are first-match-wins, so dropping that
discriminator makes the first rule answer everything and the rest report zero calls.

The ping test uses `respond_with_actions_from_event` to echo the peer's random nonce; a
hardcoded nonce fails.

A local `wait_for_mocks(&server, limit)` exists in this file because the handshake test ends
with a message the server answers with *no bytes* — the mock call is recorded asynchronously,
so a bare `verify_mocks()` samples the counters too early. The other three tests use the
harness's own `server.wait_for_mocks(30)`.

### `peer_inject_test.rs` — one in-process test, **0 LLM calls**

`injected_bitcoin_action_reaches_raw_socket_and_close_sends_eof`. Uses `netget::` APIs
directly (no subprocess). A `*` static handler answers the opened event with `verack`, so the
model is never consulted. Asserts `AppState::send_to_peer` puts `send_ping` on the socket as
exactly 32 bytes (`ClientSendOutcome::Sent { bytes_sent: 32 }`), that `bytes_sent`/
`packets_sent` counters move, and that the dashboard's generic `close_connection` name (the
model's own verb is `close_this_connection`) half-closes, yields EOF, and releases the peer
handle.

### `queue_limit_test.rs` — one in-process test, **0 LLM calls**

`a_peer_that_queues_past_the_cap_behind_an_answer_is_closed`. The opened event is parked on a
`manual` rule, so an answer is in flight for as long as the test likes, and the peer queues
pings behind it. Control first: a quarter of `MAX_QUEUED_BYTES` is queued, the opened event is
answered with nothing, and the first `pong` (nonce 0) comes back. Then past the cap: the peer
reads EOF and no `pong`. Without the bound the second half is answered like the first.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features bitcoin \
    --test server -- server::bitcoin --test-threads=100
```

No Ollama and no `ollama pull`: all four E2E tests are mocked and `peer_inject_test` points
its LLM at an unreachable port on purpose.
