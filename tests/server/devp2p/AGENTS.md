# devp2p server tests

| File | What it shows |
|---|---|
| `wire_test.rs` | The wire code against vectors NetGet did not produce: RLP examples, EIP-8's auth/ack packets and derived secrets (`aes`, `mac`, the ingress MAC over "foo"), EIP-2124's mainnet fork hashes, go-ethereum's block-test encodings and hashes. The bounds: RLP depth (a 100 000-level bomb), item count, non-canonical forms, a frame over the bound refused from its header alone, a Snappy bomb refused before decompression, every MAC checked |
| `e2e_test.rs` | NetGet client ↔ NetGet server over a chain the test builds; refusals (model down, silent, explicit); a header that does not answer the request never sent; Hello identity and capability checks; oversize handshake, frame and Snappy; an RLP bomb as a Status; a request before Status; the operator's injected request and `close_connection`; the model's own path through a mocked LLM and the NetGet binary (3 LLM calls) |
| `real_client_test.rs` | go-ethereum dials NetGet (`admin_addPeer`) and lists it in `admin_peers` with NetGet's name, eth/69 and the block range NetGet sent; `--eth.requiredblocks 3=<hash>` makes geth fetch block 3's header from NetGet and log `Peer required block verified`, and a second NetGet node serving a changed block 3 is dropped (`Required block mismatch`). go-ethereum's `devp2p rlpx ping` decodes NetGet's Hello. reth dials NetGet and keeps it as a peer |
| `support.rs` | The in-process node, the python policy (mirror the Status, serve headers from a map), and `RawPeer`, NetGet's own wire code as a hand-driven peer for the paths no real node takes |
| `vectors.rs` | The EIP-8 and block-test byte strings |
| `install_peers.py` | Linux: geth 1.17.8 (geth-alltools tarball, sha256-pinned), `devp2p` built with `go install …/cmd/devp2p@v1.17.8`, reth 2.7.0 (tarball, sha256-pinned). macOS: reth only; geth and devp2p from `brew install ethereum` |

No LLM except the mocked test: python policies answer. The real-peer tests **fail** when a
binary is missing. Binaries come from `$NETGET_GETH`, `$NETGET_DEVP2P`, `$NETGET_RETH`, else
`PATH` (`tests/helpers/ethereum.rs`). Every peer runs on loopback with discovery off.

geth `--dev` cannot also be a network node (it forces `--maxpeers 0`), so the chain is sealed
by `geth --dev --exec 'admin.sleepBlocks(N)…' console` and served by a second, ordinary geth
on the same data directory. The console may seal one block more than asked; the tests read
geth's own head instead of assuming.

tshark has no RLPx dissector and every frame after the handshake is encrypted, so there is no
pcap oracle; the EIP-8 vectors are the byte-level check.

Run: `NETGET_RETH=/path/to/reth ./cargo-isolated.sh test --no-default-features --features tcp,devp2p --test server -- devp2p:: --test-threads=4`
