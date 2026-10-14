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
