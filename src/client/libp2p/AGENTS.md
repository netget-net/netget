# libp2p client

The server's stack (`src/server/libp2p`) in the dialler role. `remote_addr` is `host:port` or
a multiaddr `/ip4|ip6|dns/…/tcp/…[/p2p/<id>]`; `peer_id` may name the id separately, and both
must agree. A named id is checked in the Noise handshake, and a mismatch fails the connect
naming both ids.

After the upgrade NetGet runs the remote's identify and raises `libp2p_connected` (agent,
protocols, listen and observed addrs). The remote's own identify and ping are answered by
Rust, as on the server.

## Tasks

All are registered with `register_client_task`:

- the yamux reader;
- the yamux writer;
- the inbound-stream acceptor;
- the notes→events converter;
- the dispatcher, which asks the handler;
- the session, which performs actions from the handler and from `send_to_client`.

The connection ending ends the session.

## Actions

- `libp2p_open_stream{protocol, data?}`: answered by `libp2p_response{ok, stream_id}`, or
  `ok: false` when the remote answers "na".
- `libp2p_send{stream_id, data, encoding}`
- `libp2p_close_stream{stream_id}`
- `libp2p_ping`: answered with `rtt_ms`.
- `libp2p_identify`
- `ipfs_bitswap_want`, `ipfs_bitswap_cancel`, `ipfs_kad_find_node`, `ipfs_kad_get_providers`
  (below)
- `disconnect`

Messages on any stream, opened by either side, arrive as `libp2p_message`. When the remote
half-closes a stream, the writer is kept so the handler can still answer on it.

A handler chain stops after `MAX_FOLLOWUP_DEPTH` (8).

Every event is recorded in the access log once, by `call_llm_for_client`; the dispatcher
does not record it again, or each event would count twice (the access log's total is what
`--exit-after-events` counts).

## IPFS (`ipfs: true`, `ipfs.rs`)

The server's `bitswap`, `ipfs` and `kad` modules (see `src/server/libp2p/AGENTS.md`). With
`ipfs`, identify advertises Bitswap and the host accepts the remote's Bitswap streams, which
is where blocks arrive. It does not advertise the DHT: this client answers no DHT requests.

- `ipfs_bitswap_want{cids, want: block|have}`: the CIDs join the connection's `WantSet` (at
  most `MAX_OUTSTANDING_WANTS`, 1024), then one wantlist goes out on a stream of its own,
  with `sendDontHave`. A CID in a codec other than raw or dag-pb, or with another hash
  function, is refused before anything is sent.
- `ipfs_bitswap_cancel{cids}`: forgets them and tells the remote.
- Each received message goes through `bitswap::accept_blocks`: a block is hashed and
  reported only if it is an outstanding want, as `ipfs_block_received {cid (as asked), codec,
  size, data, encoding, truncated, unixfs_type, file_size, links}`; the want is then
  satisfied. Anything else is refused (`decision=refused_block`) and the model never hears
  of it. HAVE/DONT_HAVE for an outstanding want arrive as `ipfs_bitswap_presence`. A
  malformed message resets its stream.
- `data` is the block for raw and the UnixFS data for dag-pb, cut at `MAX_SHOWN_BLOCK`
  (64 KiB) with `truncated` set; the block was verified whole. A chunked file or a directory
  is walked by wanting the `links`.
- `ipfs_kad_find_node{peer_id, protocol?}` and `ipfs_kad_get_providers{cid, protocol?}` ask
  the remote's DHT one question on a stream of their own (20 s) and raise `libp2p_response`
  with `closer_peers` and `provider_peers`. `protocol` is `/ipfs/kad/1.0.0` (default) or
  `/ipfs/lan/kad/1.0.0`. Kubo with no public peers keeps its own provider records in its LAN
  DHT, so on a private network ask the LAN protocol.
