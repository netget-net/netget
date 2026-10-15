# devp2p server (Ethereum node)

**Status**: `DevelopmentState::Experimental`. Two independent implementations drive it in
tests that fail rather than skip — go-ethereum 1.17 (geth, plus go-ethereum's `devp2p` tool,
the same code family) and reth 2.7 (Rust; NetGet uses none of its crates) — but there is no
fuzz target, nobody has reviewed it against the devp2p specs line by line, and the `devp2p`
pair job had not run in CI when this was written.

Feature `devp2p` (= `secp256k1` with `recovery`, `aes`, `ctr`, `hmac`, `sha2`, `sha3`, `snap`).
Well-known port 30303 (TCP; discovery would be UDP 30303, which is not implemented).

## Why hand-written

No maintained RLPx crate exists outside the Ethereum clients themselves, and using reth's
(`reth-ecies`, `reth-eth-wire`, `alloy-rlp`) would make reth — one of the two independent
peers — circular evidence. So RLPx, ECIES, RLP and the messages are written here on generic
primitives: `secp256k1` 0.29 (the one `bitcoin` and `nostr` already link) for ECDH and
recoverable signatures, RustCrypto `aes`/`ctr`/`hmac`/`sha2`/`sha3`, and `snap` for Snappy.

## Files

| File | What |
|---|---|
| `rlp.rs` | RLP: canonical-only decoding, `MAX_RLP_DEPTH` 16, `MAX_RLP_ITEMS` 200 000, lengths checked against the input before slicing |
| `crypto.rs` | Node keys, node ids, keccak-256, ECDH x-coordinate, recoverable signatures, ECIES (go-ethereum's `ECIES_AES128_SHA256`) |
| `rlpx.rs` | EIP-8 auth/ack handshake (both roles), secret derivation, the frame codec (AES-256-CTR, the keccak/AES MAC construction), Snappy |
| `eth.rs` | Hello, Disconnect (reason names), Ping/Pong; Status for eth/68 and eth/69; header JSON ⇄ RLP and hashes; bodies; transactions; GetBlockHeaders; responses; NewPooledTransactionHashes; BlockRangeUpdate; EIP-2124 fork hash (CRC-32); enode URLs |
| `session.rs` | Shared with the client: `establish` (handshake + Hello), the reader task (answers Ping), `Session` (both Statuses, requests owed and outstanding), `parse_command`, `build_status`, `validate_answer` |
| `mod.rs` | Accept loop, Status phase, event loop, `consult` |
| `actions.rs` | Events, actions (shared with the client), metadata, startup parameters |

## Wire, in one paragraph

Dialler sends `auth` (ECIES to the listener: signature by an ephemeral key over
`ecdh(static keys) ⊕ nonce`, its id, nonce, version 4, padding), listener answers `ack`
(ephemeral id, nonce). Secrets from the ephemeral ECDH and both nonces; MACs seeded with the
two packets. Frames: 16-byte AES-CTR header (24-bit size + `rlp([0,0])`), header MAC, padded
body, body MAC. Both sides send Hello immediately; with version ≥ 5 everything after Hello is
Snappy. `eth` starts at code 0x10. Verified byte-for-byte against EIP-8's vectors
(`tests/server/devp2p/wire_test.rs`).

## What the model does

| Event | When | Answer |
|---|---|---|
| `eth_status` | Hello done and the peer's Status read | `eth_send_status` (fields, `mirror_peer`, or startup defaults; fork hash computed from genesis + `forks`) admits; `devp2p_disconnect` refuses |
| `eth_block_headers_requested` | GetBlockHeaders | `eth_send_block_headers` with header **JSON fields** (eth_getBlockByNumber names) |
| `eth_block_bodies_requested` | GetBlockBodies | `eth_send_block_bodies` (`transactions` as signed 0x-hex, `uncles`, `withdrawals`) |
| `eth_pooled_transactions_requested` | GetPooledTransactions | `eth_send_pooled_transactions` |
| `eth_transactions_announced` | NewPooledTransactionHashes | optional `eth_request_pooled_transactions` |
| `eth_block_headers_received` / `_bodies_received` / `eth_pooled_transactions_received` | an answer to the node's own request | further requests |
| `eth_request_timed_out` | a request unanswered for 20 s | — |

Rust computes every block hash (keccak of the RLP header) and refuses a header answer that is
not the one asked for: more headers than `amount`, a first header that is not the origin
(number, or hash), numbers that do not follow `skip`/`reverse`, a contiguous run whose
`parentHash` does not link, or a `hash` field the fields do not produce. Unknown header fields
are refused rather than ignored (ignoring one would hash a different header). Transactions are
the one place the model hands over an encoding: a signed transaction is an opaque signature
blob no structured form could produce, so it travels as its canonical `0x` encoding (what
`eth_getRawTransactionByHash` returns); Rust checks it is a legacy RLP list or an EIP-2718
envelope over one, hashes it, and refuses pooled transactions the peer did not ask for.

Handled without the model: Ping/Pong (in the reader task, so a model call never trips the
peer's 30 s read deadline), GetReceipts (answered with an empty list — NetGet keeps none),
BlockRangeUpdate (recorded), Transactions/NewBlock broadcasts (ignored).

## Failing closed

| Situation | Wire | Log |
|---|---|---|
| Handshake failure, oversize auth (> 2048), not RLPx | close | WARN `decision=protocol_error` |
| Hello names another node / no shared eth / is this node | Disconnect `unexpected_identity` / `useless_peer` / `connected_to_self` | `decision=protocol_reject` |
| No Status within 10 s | Disconnect `timeout` | `decision=fail_closed_status_timeout` |
| A message before Status, malformed message, bad MAC | Disconnect `breach_of_protocol` | `decision=protocol_error` |
| Frame or decompressed message over 4 MiB | Disconnect `breach_of_protocol`, before the body is read / decompressed | `decision=fail_closed_message_too_large` |
| `eth_status`: backend down / nothing / refused action | Disconnect `subprotocol_error` | `fail_closed_llm_error` / `model_silent` / `fail_closed_bad_action` |
| `eth_status` answered without `eth_send_status` | Disconnect `useless_peer` | `model_reject` |
| A peer request still owed after the model's turn | Disconnect `subprotocol_error` | `decision=fail_closed_unanswered` |

Never a fabricated answer: an empty header list goes out only when the model wrote it.

## Bounds

Handshake packet 2048 bytes (go-ethereum's); Hello 2048 bytes and 64 capabilities; message
4 MiB after decompression (`max_inbound_bytes`), frame the same plus Snappy's expansion; RLP
depth 16 and 200 000 items; 64 requests owed by the node and 16 outstanding from it; requests
the model sends ask for at most 64 headers or 256 hashes; answers carry at most 1024 items;
10 s for the handshake + Hello, 10 s for the Status, 60 s idle (peers ping every 15 s; the node
pings too), 20 s per outstanding request; follow-up chains stop at depth 8; 256 connections.

## Not implemented

Discovery (discv4/discv5): peers are added statically (`admin_addPeer`, `--bootnodes`,
static nodes). The `snap` protocol. Body validation against the header's `transactionsRoot`
(needs a Merkle Patricia trie). eth/66, eth/67 and eth/70+ (geth 1.17 speaks 69–72, reth
66–71, so 69 is what both use). The dashboard's `[ message ]` injects any of the actions
above through the peer handle; `[ disconnect ]` sends Disconnect `requested`.
