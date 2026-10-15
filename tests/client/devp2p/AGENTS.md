# devp2p client tests

| File | What it shows |
|---|---|
| `real_server_test.rs` | NetGet's client dials go-ethereum (a chain geth sealed) and reth (`--dev`); the python policy mirrors the peer's Status, asks for headers 0–2 by number, then the same three backwards by the last one's hash, then their bodies. Every hash NetGet computed equals the node's `eth_getBlockByNumber` hash; the by-hash answer is the node confirming NetGet sent the hash the model chose |
| `bounds_test.rs` | A hostile listener built from NetGet's wire code: an RLP bomb as a Status (Disconnect `breach_of_protocol`, no model call), a model that is down (Disconnect `subprotocol_error`), a peer request the model leaves unanswered (Disconnect `subprotocol_error`), a model that never stops asking (exactly `MAX_FOLLOWUP_DEPTH` requests), wrong headers (`matches_request: false`) and more headers than asked for (Disconnect, never shown to the model) |

Peers and binaries as in `tests/server/devp2p/AGENTS.md`; the real-server tests fail when
geth or reth is missing. No LLM: python policies answer.
