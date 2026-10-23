# libp2p client tests

No LLM calls: a python chain is the model. The peer is go-libp2p listening (`libp2p-peer
listen`, see `tests/server/libp2p`). It prints what it sees, opens a chat stream of its own to
NetGet once identify is done, and echoes what NetGet sends.

## The chain

1. On connect, NetGet opens `/netget/chat/1.0.0` with "hello from netget".
2. When the stream is open, it pings.
3. Any message that is not an echo, it echoes.

## What is asserted

From go-libp2p's side:

- it identified NetGet (agent, protocols);
- it received NetGet's hello;
- NetGet answered the stream go opened.

From NetGet's side:

- the go agent, and a peer id equal to the multiaddr's;
- the echo of its hello;
- a successful ping;
- go's message, on an even (listener-opened) stream.

Injected actions:

- identify, answered with go's protocols;
- an unsupported protocol, answered `ok: false`;
- an unknown stream, rejected locally.

`a_wrong_peer_id_fails_the_connect` dials go under another peer id and expects the connect to
fail naming the mismatch.

Mutation-checked: discarding the model's actions fails the chain.

## IPFS (`ipfs_test.rs`, the dialler with `ipfs: true`)

Kubo 0.43.1 (`NETGET_KUBO`) run by `tests/helpers/kubo.rs`, confined to loopback (see
`tests/server/libp2p/AGENTS.md`), and the go peer's `bitswap-liar` mode.

- `netget_fetches_what_kubo_added`: Kubo `ipfs add`s a CIDv0 UnixFS file, a CIDv1 raw file
  and a 3000-byte file chunked at 1024 with raw leaves. The chain wants the three on
  connect, and the links of any dag-pb block that arrives. Asserted: each block reported
  once, the UnixFS file's data, the raw file's bytes, the root's `file_size` and three links,
  and the leaves in link order reassembling the file. Kubo's `swarm peers` is NetGet alone.
- `netget_asks_kubos_dht`: Kubo as `dhtserver`. FIND_NODE for Kubo's own id names Kubo;
  GET_PROVIDERS on the LAN protocol names Kubo as the provider of a file it added; a
  malformed peer id is rejected locally.
- `a_block_that_does_not_hash_is_refused`: NetGet wants two CIDs from the liar, which answers
  both in one message, one with the right bytes and one with "tampered" under the wanted
  CID's prefix. Only the first is reported; the other is logged `refused_block`. A dag-cbor
  CID is rejected before anything is sent.

Mutation-checked: reporting blocks that match no want fails the liar test.

## Whole DAGs (`dag_test.rs`, `ipfs_fetch`)

Every fetch starts from the model's own `ipfs_fetch` action (a python chain on connect), so
dropping the model's actions fails these tests.

- `netget_fetches_trees_and_files_kubo_added`: Kubo `ipfs add`s a tree (CIDv0 and CIDv1), a
  2.2 MB file, a depth-4 file (256-byte chunks, 3 links) and has a symlink; NetGet fetches
  each. Asserted against the bytes on disk: the listings (name, kind, size, in order), the
  2.2 MB file's size, SHA-256, first 100 bytes and its 10 blocks at depth 1, the depth-4
  file's bytes, the symlink's target; a CID nobody added ends in DONT_HAVE. Prints NetGet's
  counts per fetch, `ipfs bitswap stat` and Kubo's ledger for NetGet. (Kubo answers DONT_HAVE
  for the empty raw block; the walk never asks for it.)
- `netget_fetches_a_tree_helia_serves`: Helia serves a CIDv1 tree; the chain fetches the root,
  then `big.bin` and `sub` from its listing.
- `a_tampered_block_never_completes_a_fetch`: from the go-libp2p liar, injected: the block it
  has is fetched; the one it tampers with is refused (`refused_block`) and the fetch gives up
  at its timeout; a bad `max_bytes` is refused before anything is sent.
- `netget_reads_an_ipns_record_from_kubos_dht`: `ipfs_kad_get_value` against a Kubo DHT
  server returns its name's record, verified.

Mutation-checked: routing a block to the walk by its prefix and dropping `Walk::give`'s
hash check (the tampered block completes the fetch); dropping the model's actions (no fetch
happens).
