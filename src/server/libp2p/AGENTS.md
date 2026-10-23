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
- `ipfs_content` (with `ipfs`): files and directories to serve from the start, each described
  as `ipfs_add` describes one; a description that does not build fails the startup.

## IPFS (`ipfs: true`)

An extension of this host, not a separate protocol: Bitswap and the DHT are stream protocols
that multistream-select negotiates like any other, and identify advertises them. The client
turns on Bitswap only (it receives blocks on streams the remote opens) and serves no DHT.

- `ipfs.rs`, the data model:
  - CIDv0 (`Qm…`, base58btc) and CIDv1 (`b…` base32; `z…` and `f…` are parsed too);
  - sha2-256 multihashes only: another function is refused by name;
  - the `raw` and `dag-pb` codecs: PBNode/PBLink in canonical order (links before data);
  - UnixFS `Data`, and a single-block file built exactly as `ipfs add` builds one.
  - Every CID is computed from the bytes; nothing a peer or the model says about a block's
    identity is taken on trust. Protobuf nesting is fixed by the schema; no decoder recurses.
- `unixfs.rs`, whole DAGs:
  - **Building** (`parse`, `build`, `add`). A description uses `described_disk`'s content
    vocabulary: a file is `{text}`, `{hex}` or `{size, extents: [{offset, text|hex|fill,
    length}]}` (zeroes elsewhere); a directory is `{entries: [{name, kind: file|dir|symlink,
    …}]}`, the tree shape FUSE and HDFS use; a symlink is `{kind: symlink, target}`.
    `described_tree` itself is not reused: it is Unix-only (errno names), carries inodes,
    modes and an overlay IPFS has no use for, and libp2p builds on every native target.
  - Layout is Kubo's: the fixed-size chunker (`chunk_size`, default 262144, 256 B–1 MiB), the
    balanced layout (`max_links`, default 174, up to 1024), UnixFS leaves under CIDv0 or raw
    leaves under CIDv1 (`cid_version`, `raw_leaves` defaulting to true under CIDv1; raw leaves
    under a CIDv0 root are what `--raw-leaves` alone makes). The balanced tree is built a level
    at a time; go-unixfs builds it top down and the two give the same tree, including a last
    node with a single child. Directories are basic: links sorted by name, `Data` naming the
    type alone (no mode or mtime, as `ipfs add` writes without `--preserve-*`).
  - Bounds: `MAX_ADD_BYTES` 256 MiB and `MAX_ADD_BLOCKS` 65536 per add, `MAX_ADD_ENTRIES`
    16384, `MAX_DIR_ENTRIES` 4096, `MAX_DIR_DEPTH` 24 directories, `MAX_DAG_DEPTH` 32 levels
    root to leaf, 16 MiB of text and hex per add. A directory whose node would reach Kubo's
    HAMT threshold (256 KiB, by boxo's link estimate or by its encoded size, whichever is
    larger) is refused: NetGet does not build HAMT shards, and building a basic directory
    where Kubo would shard would give a different root.
  - **Serving** (`Store`, `Shared`). Only the description is kept; a leaf's bytes are read
    back out of it when a peer wants the leaf, and every block is hashed again before it goes
    out. Bounded at 256 adds, 262144 blocks and 64 MiB of described bytes per host; an add
    over a bound is refused whole. `Shared` tells every connection when content is added.
  - **Walking** (`Walk`): iterative, in file order, at most `WALK_WINDOW` 32 wants in flight,
    `MAX_WALK_BLOCKS` 8192 blocks, `MAX_DAG_DEPTH` levels and 1 GiB of file bytes (it keeps
    only what it shows and a SHA-256 of the rest), and it checks a file's size against its
    root. A directory is listed with each entry's kind and size (its root block, at most
    1024 entries looked at); HAMT shards are refused. The empty raw block is named by its own
    content and Kubo 0.43 answers DONT_HAVE for it, so it is never asked for.
- `bitswap.rs`: messages for 1.2.0, 1.1.0 and 1.0.0 (and the bare `/ipfs/bitswap`).
  - Bounds, checked before anything is collected: `MAX_MESSAGE` 4 MiB (boxo's own limit),
    `ipfs::MAX_BLOCK` 2 MiB per block, `MAX_WANTLIST_ENTRIES` 1024, `MAX_MESSAGE_FIELDS`
    4096. `wire::pb_fields_bounded` refuses a message with too many fields before it
    allocates for them. Over a bound, the stream is reset.
  - `answer_wants` (host): the model's blocks against the wants. A block goes out only under
    a want whose codec and digest its bytes have. A block claimed (`cid`) under a CID it does
    not hash to is refused; so is one that matches no want. A want-have is answered with the
    block itself, which Bitswap allows: it spares the model a second question whose answer
    would have to hash the same.
  - `accept_blocks` (dialler): a received block's CID is its prefix applied to its own
    bytes. It is reported only if that CID is an outstanding want, and under the CID the model
    asked for. Tampered bytes name another CID, which nothing wanted, so they are refused.
  - `Counts`: messages, want-block/want-have/cancel entries, full wantlists, blocks, HAVEs
    and DONT_HAVEs, one per direction.
- `kad.rs`: the DHT message on `/ipfs/kad/1.0.0` and the LAN DHT's `/ipfs/lan/kad/1.0.0`.
  - At most `MAX_PEERS` 20 peers per list and `MAX_ADDRS` 16 addresses per peer, in 64 KiB.
  - Peer ids must be identity or sha2-256 multihashes. A record (field 3) is carried as its
    key and value; whoever keeps it checks it.
  - `ask`: one question to a connected peer's DHT on a stream of its own (20 s), shared by
    the host's `ipfs_kad_query` and the client's `ipfs_kad_*` actions.
- `ipns.rs`, what the host's DHT keeps in Rust:
  - IPNS records. Kept only when the record is at most 10 KiB, its key is `/ipns/<peer id>`,
    `signatureV2` over `"ipns-signature:" ‖ data` verifies with the Ed25519 key the peer id
    inlines (and `pubKey`, if present, is that key), the data is one flat DAG-CBOR map of
    Value, Validity, ValidityType, Sequence and TTL, every V1 protobuf field Kubo still writes
    agrees with it, and it has not expired. A record replaces the one held only if its
    sequence (then its validity) is not lower, as the IPNS validator selects; an older one is
    refused. At most 1024 names. The CBOR reader refuses anything nested, so it never
    recurses.
  - Provider records: 4096 keys, 20 providers per key (newest kept), 48 hours each.
- `serve_ipfs.rs`, the host's side:
  - Each connection has a `Ledger`: its peer's outstanding wants and the Bitswap counts in
    both directions, logged as `operation=bitswap_ledger` when the connection ends.
  - A wantlist: a full wantlist replaces the wants remembered, a CANCEL forgets one. Each want
    is answered from the store when it holds the block (BLOCK for want-block; for want-have,
    the block itself when it is at most 1024 bytes, as boxo's engine does, else HAVE), at no
    model cost. A want in a codec NetGet cannot build is DONT_HAVE without asking. The rest
    become `ipfs_bitswap_want {peer_id, wants: [{cid, codec, want}], full}`; the model answers
    `ipfs_bitswap_blocks {blocks: [{content, encoding, format: raw|unixfs, cid?}]}` or
    `ipfs_add`. What is still unanswered gets DONT_HAVE where asked and is remembered
    (`MAX_TRACKED_WANTS` 1024, oldest dropped). A want the model declined is not put to it
    again while the peer keeps it; one it failed on is.
  - When content is added (on any connection), every connection sends its remembered wants
    what the store now holds, as BLOCK or HAVE. An injected `ipfs_bitswap_blocks` goes to the
    wants this peer still has. Answers go on a stream the host opens, as Bitswap does, split
    so no message passes the bound. A failed model is DONT_HAVE
    (`decision=fail_closed_llm_error`), never a block; refusals are `decision=refused_*`.
  - `ipfs_add` (any event's answer, and `send_to_peer`) and the `ipfs_content` startup
    parameter build a description on a blocking thread and add it to the host's store; the
    root is logged as `operation=ipfs_add decision=added root=…`.
  - DHT: FIND_NODE (any non-empty key: Kubo looks up `/ipns/…` keys this way before it puts a
    record) and GET_VALUE are answered in Rust from the connected peers nearest the key by XOR
    over SHA-256 (`Config::directory`), this host when the key is its own id, and for
    GET_VALUE the IPNS record held. PUT_VALUE keeps a record that verifies and echoes the
    request (what the putter checks); a refused record resets the stream. GET_PROVIDERS is
    answered in Rust when Rust knows a provider (this host for stored content, peers that
    announced it); otherwise it becomes `ipfs_kad_request` and the model answers
    `ipfs_kad_reply {provider_peers, closer_peers}` (`"self"` is this host; omitted addrs are
    filled in for this host and connected peers; closer peers default to the nearest
    connected ones). ADD_PROVIDER is kept in Rust and shown to the model, and needs no reply;
    a provider other than the sender is dropped first. PING is echoed. A failed model resets
    a GET_PROVIDERS stream.
  - `ipfs_kad_query {request: FIND_NODE|GET_PROVIDERS|GET_VALUE, peer_id|cid|name,
    protocol?}`: the model asks this connection's peer's DHT; the answer, any IPNS record in
    it verified, arrives as `ipfs_kad_answer`. At most `MAX_KAD_QUERIES` 8 a minute per peer,
    which also bounds a model that answers every answer with another question.

### Not done

- HAMT-sharded directories, both ways: the builder refuses a directory Kubo would shard, and
  the walk refuses a shard it is given.
- Chunkers other than fixed-size (rabin, buzhash), the trickle layout, `--inline`,
  `--preserve-mode`/`--preserve-mtime`, other hash functions and codecs (dag-cbor, dag-json,
  blake3, …): refused.
- Bitswap on the dialler side is one fetch at a time per connection, with no multi-peer
  sessions or peer selection: the walk asks the one peer it is connected to.
- No want rebroadcast from the host (it serves; it does not want).
- The host's DHT keeps records and provider records but is not a full Kademlia node: no
  routing table of its own beyond the connected peers, no iterative lookups (one question to
  one connected peer), no republishing, no IPNS publishing of its own names, and only
  Ed25519 names (`/ipns/` records under RSA, secp256k1 or ECDSA keys are refused).
- No signed peer records.

## Not implemented

QUIC, WebTransport, WebRTC, the TLS security protocol, mplex, early muxer negotiation (Noise
extensions), signed peer records, gossipsub, relay, AutoNAT, hole punching.
