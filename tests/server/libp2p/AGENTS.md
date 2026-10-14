# libp2p server tests

No LLM calls: a python policy is the model. Two independent peers, both installed by
`install_peers.py <root>`, which prints their exports; the tests fail rather than skip
without either:

- **go-libp2p** v0.41.1 (`peer/`, go.sum-pinned, built from source, `NETGET_LIBP2P_GO_PEER`).
  It runs TCP, Noise and yamux only, so every byte is go-libp2p's negotiation, encryption and
  multiplexing. Its `raw` mode writes bytes verbatim on a stream of a named protocol and
  prints what comes back, plus every Bitswap message NetGet then sends it, read with go-cid
  (which recomputes each block's CID from its prefix and bytes). `bitswap-liar` listens and
  answers wants with a tampered block (the client suite uses it).
- **Kubo** 0.43.1 (`NETGET_KUBO`), the official release tarball, sha256-pinned for macOS
  arm64 and Linux amd64. `tests/helpers/kubo.rs` runs it as a daemon in a repository of its
  own, confined to loopback: `ipfs init --profile=test` (loopback swarm/API/gateway, no
  bootstrap, no MDNS, no AutoConf), TCP only, `Swarm.AddrFilters` refusing every address
  outside 127.0.0.0/8, no relay/AutoNAT/HTTP routers, `IPFS_TELEMETRY=off`. Checked on
  macOS by sampling `lsof -i` of a running daemon: only its three loopback listeners. The
  tests also assert `ipfs swarm peers` lists NetGet alone.

The server runs with a fixed `private_key_seed`, so the test knows its peer id.

## `go_libp2p_dials_netget`

go-libp2p dials, verifies NetGet's peer id, and reports what its identify service parsed: agent
`netget/…`, protocol version, protocols and listen addrs. Then:

1. It pings.
2. It talks two messages on `/netget/chat/1.0.0` (echoed by the policy).
3. A protocol NetGet does not offer is refused.
4. A message announcing 2 MiB resets its stream.

When the peer connected, the policy opened a stream of its own. go's echo handler printed
what arrived on it, and NetGet saw the echo come back.

## The other tests

- `a_wrong_peer_id_is_refused_by_the_dialler`: go dials NetGet under another valid peer id,
  and go-libp2p refuses NetGet's proof.
- `a_failed_handler_resets_the_stream`: with an unreachable model, go's read ends in a stream
  reset rather than a wait.
- `multistream_refusals_over_raw_tcp`: hand-written multistream bytes.
  - `/tls/1.0.0` gets `na`.
  - Past `MAX_PROPOSALS` the connection closes.
  - A message announcing more than `MAX_MULTISTREAM_MESSAGE` closes it unread.
- `base58_and_varint_round_trip`

## IPFS (`ipfs_test.rs`, the host with `ipfs: true`)

The policy offers, for every want, two contents in both formats (raw, single-block UnixFS)
plus wrong bytes claimed under the wanted CID, so every answer exercises the matching rule.

- `kubo_fetches_what_the_model_serves`: Kubo computes CIDs with `ipfs add --only-hash`
  (nothing stored), and NetGet's data model must agree with every one. Kubo connects and
  `ipfs cat`s a CIDv1 raw block, a CIDv0 UnixFS file and a 200 KB single-block file, and
  `ipfs block get`s the UnixFS block byte for byte. Kubo verifies each hash itself. The bad
  offers are logged `refused_block` and never sent.
- `kubo_finds_netget_as_a_provider_through_its_dht`: Kubo as `dhtclient`, LAN DHT. Once
  NetGet is in its routing table (`ipfs stats dht`), `ipfs routing findprovs` finds NetGet
  through GET_PROVIDERS. `ipfs add` makes Kubo send ADD_PROVIDER naming itself with a
  loopback address. Only GET_PROVIDERS and ADD_PROVIDER reach the model.
- `a_block_that_does_not_hash_is_never_sent`: over go-libp2p. For a want the model answers
  rightly, go-cid recomputes the CID of the one block sent; for the other, wrong bytes are
  claimed under its CID, and DONT_HAVE is all that arrives.
- `a_failed_model_answers_dont_have`: an unreachable model gives DONT_HAVE (no block), and a
  GET_PROVIDERS stream is reset with nothing written.
- `refusals_before_the_model`: a message announcing more than 4 MiB, malformed protobuf,
  1025 wantlist entries (all reset); a dag-cbor want (DONT_HAVE without asking); ADD_PROVIDER
  naming a peer other than the sender (dropped); a malformed DHT message and PUT_VALUE
  (reset); PING (echoed). No model event at all.
- `find_node_is_answered_from_what_netget_knows`: FIND_NODE for NetGet's own id names NetGet
  with its listen address; for another id, with only the asker connected, nobody; a key that
  is not a peer id is reset. No model call. (Kubo 0.43 does not insist on the self-entry
  before routing through a peer, so only this test can show it.)
- `a_block_over_two_mib_is_refused_both_ways` and `the_data_model_round_trips`: pure.

Mutation-checked (each made a test fail, then reverted): trusting the model's claimed CID
and dropping the per-want hash check; removing the 4 MiB message bound, the wantlist-entry
bound and the 2 MiB block bound; answering nothing when the model fails; not resetting a
failed GET_PROVIDERS; letting an unknown codec reach the model; omitting the host from
FIND_NODE for its own id; accepting ADD_PROVIDER for a third party.
