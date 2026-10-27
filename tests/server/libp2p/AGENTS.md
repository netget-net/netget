# libp2p server tests

No LLM calls: a python policy is the model, or an unreachable one. Three independent peers,
all installed by `install_peers.py <root>`, which prints their exports; the tests fail rather
than skip without any of them:

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
  tests also assert `ipfs swarm peers` lists NetGet alone. `Kubo::offline()` is a repository
  with no daemon, for `ipfs add --only-hash`.
- **Helia** 7.1.16 (`helia/`, `NETGET_HELIA`): js-libp2p 3.5.1, @helia/unixfs 8.0.9,
  @helia/bitswap 4.0.20 and ipfs-unixfs-importer 17.1.1, every module pinned with its
  integrity hash by `helia/package-lock.json` and installed with `npm ci` (Node 22 or
  newer). `helia/helia_peer.mjs` is one TCP listener on 127.0.0.1 with Noise and yamux and
  nothing else (no bootstrap, DHT, delegated or HTTP routing, gateways): `cid` builds a root
  with the importer, `cat` and `get` dial a multiaddr and read a file or a whole tree over
  Bitswap, `serve` adds a tree and serves it until stdin closes. It is a second, independent
  implementation of both the importer and Bitswap, so a CID that NetGet and Kubo agree on is
  not just Kubo agreeing with itself.

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
  with its listen address; for another id, with only the asker connected, nobody; an
  `/ipns/…` key (Kubo looks those up before it puts a record) is answered, with nobody; an
  empty key is reset. No model call. (Kubo 0.43 does not insist on the self-entry
  before routing through a peer, so only this test can show it.)
- `a_block_over_two_mib_is_refused_both_ways` and `the_data_model_round_trips`: pure.

Mutation-checked (each made a test fail, then reverted): trusting the model's claimed CID
and dropping the per-want hash check; removing the 4 MiB message bound, the wantlist-entry
bound and the 2 MiB block bound; answering nothing when the model fails; not resetting a
failed GET_PROVIDERS; letting an unknown codec reach the model; omitting the host from
FIND_NODE for its own id; accepting ADD_PROVIDER for a third party.

## UnixFS DAGs (`unixfs_test.rs`, `dag_test.rs`)

Every root is checked before it is fetched: the same bytes are written to disk and added
with `ipfs add --only-hash` and the matching flags, so Kubo holds nothing and can only get
blocks from NetGet. Profiles: the defaults; `--cid-version=1`; `--raw-leaves` alone (a CIDv0
root over raw leaves); `--cid-version=1 --raw-leaves=false`; 1 MiB chunks with 1024 links;
256-byte chunks with 3 links (depth 4, and the last node with a single child), under both
versions. The model is unreachable in the reading tests, and each asserts its connect event
failed closed (the control) while no want reached it.

- `unixfs_files_agree_with_kubo`: 85 files, 0 B to 2.2 MB, and a 1 MB file described by
  text and fill extents.
- `unixfs_directories_agree_with_kubo`: a tree with an empty file, an empty directory, a
  symlink, a nested directory and a UTF-8 name, under five profiles; a lone symlink; the empty
  directory (`QmUNLLs…`).
- `helia_importer_agrees_with_netget_and_kubo`: the same through Helia's importer, three
  ways, for 33 files and the tree without its symlink (the importer takes none).
- `a_directory_kubo_would_shard_is_refused`: 900 entries with 200-byte names agree with Kubo;
  1200 are refused, and Kubo's own root for them is a `hamt-shard`.
- `the_builder_is_bounded`, `the_walker_is_bounded`, `the_walker_reads_back_what_the_builder_built`:
  pure. Block count, size, directory depth, `MAX_DAG_DEPTH` (a file 20 directories down),
  names; a chain one past `MAX_DAG_DEPTH` and one 10000 deep, a fan-out naming 9004 blocks, a
  block that does not hash, a root that lies about its size.
- `kubo_reads_trees_and_large_files_from_descriptions`: from `ipfs_content`, Kubo `ls`, `cat`
  (through a path, a 700 KB file, a 3 MB file of repeated leaves, a depth-4 file), `get` of
  both trees (files, the empty directory and the symlink compared on disk), `dag get` (names,
  Tsizes and link CIDs as NetGet wrote them) and `refs -r --unique` (exactly NetGet's
  blocks). Prints `ipfs bitswap stat`, Kubo's ledger for NetGet and NetGet's
  `bitswap_ledger`.
- `helia_reads_trees_from_descriptions`: Helia `get`s both trees (every file's size and
  SHA-256, the symlink's kind) and `cat`s the 3 MB file; one ledger per Helia connection.
- `a_want_is_remembered_until_content_arrives_and_forgotten_on_cancel`: go-libp2p wants
  alpha (block), beta (have) and gamma (block) and then cancels gamma, on one stream; the
  model declines. Injected `ipfs_add`s then deliver alpha's block and a HAVE for beta (3 KB,
  too big to answer a want-have with) and nothing for gamma; go-cid recomputes the block's
  CID. The model was asked once.
- `kubo_cat_completes_when_the_model_adds_the_content_later`: Kubo's `ipfs cat` of a
  600 KB file waits on its want while the model has nothing; an injected `ipfs_add` answers
  the want Kubo is still holding, and the cat finishes byte for byte. The model was asked
  about the root once; the leaves came from the store.
- `kubo_finds_described_content_through_netgets_dht_without_the_model`: GET_PROVIDERS for a
  stored root is answered in Rust.
- `an_add_is_refused_whole_when_it_breaks_a_bound`: pure.

## DHT records (`ipns_test.rs`)

- `kubo_publishes_a_name_into_netgets_dht_and_another_kubo_resolves_it`: Kubo A (dhtclient)
  `ipfs name publish`es through NetGet's DHT; Kubo B (dhtclient) resolves the name there, and
  again after A republishes (sequence 1). B can dial A, but A answers no DHT questions: NetGet
  logs both GET_VALUEs it answered from its store. A's record verifies with `ipns::verify` and
  fails with a byte changed; put back by hand over go-libp2p, the sequence-0 record and the
  tampered one are refused (stream reset) and GET_VALUE still returns sequence 1. A's
  `ipfs add` sends ADD_PROVIDER, which Rust keeps, and B's `findprovs` finds A through NetGet
  with no model.
- `records_are_verified_before_they_are_kept`: pure. Forged, expired, oversized and non-IPNS
  records; a V1 field disagreeing with the signed data; newest-wins and same-again in the
  store; the fuzz corpus's Python-signed records verify and its CBOR depth bomb is refused by
  the reader; provider bounds.
- `the_host_asks_a_kubo_dht_itself`: injected `ipfs_kad_query`s to a Kubo DHT server
  (FIND_NODE, GET_PROVIDERS for a file it added, GET_VALUE for its name) come back as
  `ipfs_kad_answer` events with Kubo named and its record verified; the ninth question in a
  minute is refused.

Mutation-checked in this pass (each made the named tests fail, then reverted): `blocksizes`
holding Tsizes instead of file sizes (Kubo's and Helia's roots disagree: files, directories,
three-way); no block bound in the walk (the fan-out completes); no `MAX_ADD_BLOCKS`; no depth
bound in the walk (the chain one past it completes); no `MAX_DAG_DEPTH` in the builder; not
remembering declined wants (both remembered-want tests); answering nothing when the model
fails (`a_failed_model_answers_dont_have`); ignoring CANCEL (gamma's block is sent); keeping an
older IPNS record; skipping the IPNS signature check.

No pcap oracle: every stream is Noise-encrypted, so tshark reads only ciphertext.
