# libp2p server (a host)

libp2p over TCP, well-known port 4001 (IPFS's swarm port). Everything is hand-rolled on
crates already in the tree: ring (ChaCha20-Poly1305), x25519-dalek, ed25519-dalek, sha2 and
hkdf. The client (`src/client/libp2p`) uses the same modules in the dialler role.

## Layers

- `wire.rs`:
  - uvarints, and the protobuf subset libp2p's small messages use (`pb_fields_bounded` caps
    the field count before collecting);
  - base58btc, and Ed25519 peer ids (an identity multihash of the 36-byte `PublicKey`
    protobuf, so every id starts `12D3KooW`);
  - binary and text multiaddrs: the `/ip4|ip6/…/tcp/…[/p2p/…]` subset, with unknown
    components shown by code, stopping there; `multiaddr_from_text` the other way, refusing
    what it does not know;
  - multistream-select 1.0 (`ms_dial_any` proposes several ids on one stream);
  - the identify message;
  - `shown`/`data_bytes`: messages as text, or hex with an explicit `encoding`, never sniffed.
- `noise.rs`: `Noise_XX_25519_ChaChaPoly_SHA256` with an empty prologue.
  - Each handshake and transport message is framed by a u16 big-endian length.
  - The handshake payload carries the identity key and its signature over
    `"noise-libp2p-static-key:" ‖ static key`. It is verified before anything else is
    trusted. A dialler that named a peer id checks it, and refuses before sending its own
    message 3.
  - Only Ed25519 identities are accepted; RSA, secp256k1 and ECDSA are refused by name.
- `yamux.rs`: a reader task routes frames to streams; a writer task owns the Noise writer and
  every stream's send window.
  - Data the peer has no window for waits in the writer.
  - Data past the window *we* gave is a protocol error that ends the connection.
  - A stream's receive window is granted back at half of `INITIAL_WINDOW`.
  - At most `MAX_STREAMS` streams are open at once; excess SYNs are reset.
  - Pings are answered. GoAway ends the session.
  - Our half of a stream stays open until closed explicitly, so a reply can follow the peer's
    half-close.
- `host.rs`: upgrading a connection (`/noise`, then `/yamux/1.0.0`), with a 10 s negotiation
  deadline.
  - The peer's streams are served in Rust: identify (our key, listen and observed addrs,
    protocols, `netget/<version>`), identify-push (read and dropped), and ping (32-byte echo).
  - The application protocols' streams become `Note::Message`s: uvarint-length-prefixed
    messages, at most `MAX_MESSAGE` (1 MiB; `Config::max_message` gives Bitswap 4 MiB and the
    DHT 64 KiB). A longer announcement resets the stream before it is read.
  - Stream writers are kept for actions, at most `MAX_REMEMBERED_STREAMS`.

## The model (`mod.rs`)

Each connection has one loop over its notes and the dashboard's injected actions, so the
model answers one event at a time, in arrival order. After the upgrade, NetGet runs the peer's
identify and raises:

- `libp2p_peer_connected {peer_id, remote_addr, agent_version, protocols, listen_addrs}`:
  `libp2p_open_stream`, `libp2p_disconnect`, or nothing.
- `libp2p_message {peer_id, stream_id, protocol, data, encoding}`: `libp2p_send` (defaults to
  the same stream), `libp2p_open_stream`, `libp2p_close_stream`, `libp2p_disconnect`.

When the peer closes a stream, NetGet closes its own half after the queue has drained, so a
reply to the last message still goes out. A model failure resets the stream being answered
(`decision=fail_closed_llm_error`). Silence leaves it open (`model_silent`). The peer has a
handle, so `send_to_peer` and the dashboard's buttons work.

Startup parameters:

- `protocols`: default `host::DEFAULT_PROTOCOLS`, `/netget/chat/1.0.0`. Identify, ping and
  the IPFS protocol ids are refused here; they are NetGet's own.
- `private_key_seed`: any text; its SHA-256 is the identity key, for a stable peer id. The
  name puts it under the redactor.
- `ipfs` (default `actions::IPFS_DEFAULT`, false): also be an IPFS peer, below.

## IPFS (`ipfs: true`)

An extension of this host, not a separate protocol: Bitswap and the DHT are stream protocols
that multistream-select negotiates like any other, and identify advertises them. The client
turns on Bitswap only (it receives blocks on streams the remote opens) and serves no DHT.

- `ipfs.rs`, the data model:
  - CIDv0 (`Qm…`, base58btc) and CIDv1 (`b…` base32; `z…` and `f…` are parsed too);
  - sha2-256 multihashes only: another function is refused by name;
  - the `raw` and `dag-pb` codecs: PBNode/PBLink in canonical order (links before data);
  - UnixFS `Data`, and a single-block file built exactly as `ipfs add` builds one, so its
    CIDv0 equals Kubo's (the Kubo test checks this both ways).
  - Every CID is computed from the bytes; nothing a peer or the model says about a block's
    identity is taken on trust. Protobuf nesting is fixed by the schema; no decoder recurses.
- `bitswap.rs`: messages for 1.2.0, 1.1.0 and 1.0.0 (and the bare `/ipfs/bitswap`).
  - Bounds, checked before anything is collected: `MAX_MESSAGE` 4 MiB (boxo's own limit),
    `ipfs::MAX_BLOCK` 2 MiB per block, `MAX_WANTLIST_ENTRIES` 1024, `MAX_MESSAGE_FIELDS`
    4096. `wire::pb_fields_bounded` refuses a message with too many fields before it
    allocates for them. Over a bound, the stream is reset.
  - `answer_wants` (host): the model's blocks against the wants. A block goes out only under
    a want whose codec and digest its bytes have. A block claimed (`cid`) under a CID it does
    not hash to is refused; so is one that matches no want. A want-have is answered with the
    block itself, which Bitswap allows: it spares the model a second question whose answer
    would have to hash the same. Everything unsatisfied gets DONT_HAVE where the peer asked.
  - `accept_blocks` (dialler): a received block's CID is its prefix applied to its own
    bytes. It is reported only if that CID is an outstanding want, and under the CID the model
    asked for. Tampered bytes name another CID, which nothing wanted, so they are refused.
- `kad.rs`: the DHT message on `/ipfs/kad/1.0.0` and the LAN DHT's `/ipfs/lan/kad/1.0.0`.
  - At most `MAX_PEERS` 20 peers per list and `MAX_ADDRS` 16 addresses per peer, in 64 KiB.
  - Peer ids must be identity or sha2-256 multihashes.
- `serve_ipfs.rs`, the host's side:
  - A Bitswap message's wants become `ipfs_bitswap_want {peer_id, wants: [{cid, codec,
    want}], full}`. A want in a codec NetGet cannot build (dag-cbor, …) is answered DONT_HAVE
    without asking. The model answers `ipfs_bitswap_blocks {blocks: [{content, encoding,
    format: raw|unixfs, cid?}]}`. Answers go on a stream the host opens, as Bitswap does,
    split so no message passes the bound. A failed model is DONT_HAVE
    (`decision=fail_closed_llm_error`), never a block; refusals are `decision=refused_*`.
  - DHT: FIND_NODE and GET_VALUE are routing facts answered in Rust: the connected peers
    nearest the key by XOR over SHA-256 (from `Config::directory`, one entry per live
    connection with the addresses its identify gave), and this host when the key is its own
    id. That also spares a model call per routing-table refresh; Kubo sends dozens.
    GET_PROVIDERS becomes `ipfs_kad_request` and the model answers `ipfs_kad_reply
    {provider_peers, closer_peers}` (`"self"` is this host; omitted addrs are filled in for
    this host and connected peers; closer peers default to the nearest connected ones).
    ADD_PROVIDER is shown to the model and needs no reply; a provider other than the sender
    is dropped first. PUT_VALUE is reset (records are not stored); PING is echoed. A failed
    model resets a GET_PROVIDERS stream.

### Not done

Chunked (multi-block) files and directories on the serving side: the model supplies raw
blocks and single-block UnixFS files; a model could serve a DAG only block by block, and
there is no action for dag-pb nodes with links. Fetching is not limited: a dag-pb block's links
are shown, and the model wants them. No Bitswap sessions, ledgers, want rebroadcast or
peer-want tracking: each wantlist is answered once, as it arrives. No DHT records (IPNS,
PUT_VALUE, GET_VALUE values), no provider store in Rust (the model can remember ADD_PROVIDER),
no signed peer records, no DHT client of the host's own (it never queries other peers).
Other hash functions and codecs (dag-cbor, dag-json, blake3, …) are refused.

## Not implemented

QUIC, WebTransport, WebRTC, the TLS security protocol, mplex, early muxer negotiation (Noise
extensions), signed peer records, gossipsub, relay, AutoNAT, hole punching.
