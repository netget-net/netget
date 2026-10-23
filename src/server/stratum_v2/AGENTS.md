# Stratum V2 server: pool, template provider, job declarator

Stratum V2 over its Noise-encrypted transport, hand-rolled from
[sv2-spec](https://github.com/stratum-mining/sv2-spec). The `role` startup parameter chooses the
protocol: `pool` (default; the Mining Protocol, below), `template_provider` (the Template
Distribution Protocol, `template_provider.rs`) or `job_declarator` (the Job Declaration
Protocol's server, `job_declarator.rs`); all three share the handshake, the certificate and the
framing, and `network` (default `mainnet`) names the chain the last two check heights, nbits and
the subsidy against. Well-known port 3333: IANA assigns none, and SRI's pool documents 3333 in
its README and mainnet configurations (the spec's URL example uses 34254, which SRI uses for its
Job Declaration Server; sv2-tp listens on 8442). The client roles share `noise.rs`, `wire.rs` and
`bitcoin.rs`.

## Why hand-rolled, and what is borrowed

The only mature implementation is the Stratum Reference Implementation (SRI), and its binaries
(`pool_sv2`, `mining_device`) are the peers the tests use. Framing with SRI's crates
(`noise_sv2`, `codec_sv2`, `binary_sv2`) would make those peers circular — the same code at both
ends. So the handshake state machine, HMAC/HKDF, the BIP 324 tagged hash, the certificate, the
transport framing, the binary codec, every message and the share arithmetic are this
directory's. Borrowed are primitives only: `secp256k1` 0.29 (libsecp256k1) for ElligatorSwift
x-only ECDH and BIP 340 Schnorr, `chacha20poly1305` for the AEAD, `sha2`.

## What Rust owns

- **Noise NX** (`noise.rs`): `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256` exactly as §4.5:
  `-> e` (64 bytes), `<- e, ee, s, es` with the certificate as payload (234 bytes), then
  `split()`. The static key is generated per server start; its certificate (`version 0`,
  `valid_from = now`, `not_valid_after = now + cert_validity_secs`, Schnorr over
  `SHA-256(version‖valid_from‖not_valid_after‖server_xonly)`) is signed by the authority in
  `authority_secret_key` (base58check, SRI's format), or by a fresh authority whose public key is
  logged at start (`authority public key …`) for miners to pin. Note libsecp256k1's
  `ElligatorSwift::new` uses a context without generator tables and aborts; encoding goes through
  `from_seckey` with a full context.
- **Transport** (`wire.rs`): header and payload encrypted separately (22 bytes, then 65519-byte
  chunks), the header's length is the plaintext length, and the declared length is checked
  against `MAX_INBOUND_PAYLOAD` (16 KiB) before a byte of payload is read or allocated.
- **Messages**: SetupConnection(.Success/.Error), Open{Standard,Extended}MiningChannel(.Success),
  OpenMiningChannel.Error, NewMiningJob, NewExtendedMiningJob, SetNewPrevHash, SetTarget,
  UpdateChannel(.Error), CloseChannel, SubmitShares{Standard,Extended}, SubmitShares.Success/.Error
  (and Reconnect, SetExtranoncePrefix, SetGroupChannel, ChannelEndpointChanged for the client).
  Decoding refuses fields that overrun the payload, leftover bytes, OPTION/B0_32 over their
  bound, and F32 that is NaN, infinite or negative.
- **Setup**: protocol must be 0 (Mining), versions must include 2, and flags other than
  `REQUIRES_STANDARD_JOBS` and `REQUIRES_VERSION_ROLLING` (i.e. `REQUIRES_WORK_SELECTION` and
  unknown bits) are refused with `SetupConnection.Error{flags: <those bits>,
  "unsupported-feature-flags"}` — no job declaration here. Anything before SetupConnection, a
  second SetupConnection, an unknown core message or one a device never sends ends the
  connection. Messages with a non-zero extension type are discarded (§3.4).
- **Channels**: at most `MAX_CHANNELS` (16) per connection; a 4-byte extranonce prefix from a
  pool-wide counter; extended channels get `max(min_extranonce_size, 8)` bytes (over 32 is
  `min-extranonce-size-too-large`; a `REQUIRES_STANDARD_JOBS` device asking for one is
  `unsupported-extended-channel`). The default difficulty is the declared hash rate over
  `shares_per_minute` (floor `MIN_DEFAULT_DIFFICULTY` 0.001); the target never exceeds the
  device's `max_target`. UpdateChannel lowering `max_target` below the target is answered with
  SetTarget; CloseChannel removes the channel.
- **Jobs**: a version-2 coinbase whose scriptSig pushes the BIP 34 height, the model's message
  (≤ 32 bytes) and the extranonce (prefix, plus the device's part on extended channels); one
  zero-value `OP_RETURN "netget"` output; no other transactions, so the merkle path is empty.
  Version 0x20000000, nbits 0x207fffff, ntime_start = now. The first job of a channel is a future
  job activated by SetNewPrevHash, as §5.3.15 requires. A new prev hash retires every job
  (`MAX_RETIRED_JOBS` remembered, so their shares are `stale-share`); a job without one joins the
  current work (`MAX_JOBS` 16). The pool is connected to no node: nothing is ever a real block.
- **Shares**, refused with these codes before anyone is asked: `invalid-channel-id`,
  `invalid-channel-type` (standard submit on an extended channel and vice versa),
  `invalid-extranonce-size`, `invalid-job-id`, `stale-share`, `invalid-timestamp` (before the
  job's ntime_start or more than 7200 s ahead), `invalid-version` (bits outside BIP 320's
  0x1fffe000), `duplicate-share` (last `MAX_SEEN_SHARES`), and `difficulty-too-low` — the header
  is rebuilt, double-SHA-256 hashed and compared with the channel's current target as a
  little-endian 256-bit number. Only a share that meets it reaches the model.
  `new_shares_sum` is the channel difficulty rounded, at least 1 (U64 cannot carry a fraction).
  The share is measured against the channel's target when it arrives, not the target in force
  when its job was sent; a SetTarget raising the difficulty therefore applies to old jobs too.

## What the model decides

- `stratum_v2_setup_connection {vendor, hardware_version, firmware, device_id, endpoint_host,
  endpoint_port, flags, remote_addr}` → `stratum_v2_accept` / `stratum_v2_reject {error_code}`.
- `stratum_v2_open_channel {channel_kind, user_identity, nominal_hash_rate,
  max_target_difficulty, default_difficulty, extranonce_size?, remote_addr}` → accept (with
  `stratum_v2_set_target {difficulty}` for the first target and `stratum_v2_new_job {message?,
  prev_hash?}` for the first job) or reject.
- `stratum_v2_share {user_identity, channel_id, channel_kind, job_id, sequence_number, hash,
  share_difficulty, difficulty, nonce, ntime, version, remote_addr}` → accept (credit) or reject.
- Any answer may carry `stratum_v2_set_target`, `stratum_v2_new_job` and
  `stratum_v2_close_channel {reason_code}` for the channel in question. Codes are 1–64
  printable ASCII characters (§3.5).

## Failure

A failed model call, an invalid reply, silence, or both accept and reject refuse the request —
`SetupConnection.Error`, `OpenMiningChannel.Error` or `SubmitShares.Error` with
`service-unavailable` (or `service-overloaded` when the backend is at capacity) — and never
admit, open or credit anything. Decisions are logged
`decision=model_answer|model_reject|model_silent|fail_closed_*`.

## Bounds

16 KiB per inbound frame; 10 s for the device's half of the handshake; idle
`idle_timeout_secs` (default 900); 16 channels per connection; 16 live jobs and 64 retired ids
per channel; 4096 remembered shares per channel; `DEFAULT_MAX_CONNECTIONS`; difficulty in
(0, 1e15]; `cert_validity_secs` 60..=31536000; `shares_per_minute` 0.01..=600.

## Template provider (`role: template_provider`)

The Template Distribution Protocol as template_distribution_sv2 7.0 (sv2-apps v0.8.0) speaks it:
CoinbaseOutputConstraints (not the older CoinbaseOutputDataSize), NewTemplate, SetNewPrevHash
with its `target`, RequestTransactionData(.Success/.Error) and SubmitSolution. SetupConnection
must name protocol 2 and no flags (TDP defines none).

- **The model writes the template** in answer to CoinbaseOutputConstraints or a verified
  solution: `stratum_v2_new_template {prev_hash, height, nbits, ntime, version,
  coinbase_value_sats, transactions}`. Transactions are structured — inputs by txid, vout and
  the value they spend (so fees are known without a UTXO set); outputs pay `OP_TRUE` or carry an
  `OP_RETURN` text — never bytes. Answering nothing sends no work; that is the fail-closed path
  too, since a template the model did not write would be NetGet inventing a block.
- **Rust makes it a template** (`bitcoin.rs`): it serialises the transactions (version 2,
  empty scriptSigs), computes their txids and wtxids, the coinbase's merkle path (leaf 0 is the
  coinbase; an odd level pairs its last hash with itself), the BIP 141 witness commitment for a
  32-byte zero reserved value (the coinbase outputs it sends), and the BIP 34 height push that is
  the whole coinbase prefix (`CScript() << height`: OP_1..OP_16 or a minimal push; at most 8
  bytes, sv2-spec §7). It refuses a template whose first appearance lacks prev_hash and height,
  that changes height or nbits without a new prev_hash, whose nbits is negative, zero,
  overflowing or easier than the network's limit, whose version is below 4, whose coinbase value
  exceeds the subsidy at that height (`network`'s halving interval) plus fees, whose outputs spend
  more than its inputs, or whose weight (with the client's declared coinbase size) exceeds a
  block's. A template on a new prev_hash goes out as `future_template` followed by
  SetNewPrevHash naming it, as Bitcoin Core does; later ones on the same tip are not future.
- **RequestTransactionData** is answered from what was sent: Success with the serialised
  transactions, `stale-template-id` for a template on a superseded tip, `template-id-not-found`
  otherwise. SRI's jd_client asks for it; SRI's pool never does.
- **SubmitSolution** is rebuilt before the model hears of it: the coinbase must parse (segwit or
  not), spend the null outpoint, start its scriptSig with the template's height push, keep the
  template's version/sequence/locktime, end with the template's outputs, pay no more than the
  template allows, carry the 32-byte zero reserved value if it has a witness, roll only BIP 320
  version bits and have a timestamp from the tip's to two hours ahead; then the merkle root is
  folded from its txid, and the header hash must meet the template's target. A verified block is
  logged in full (`… block <hash> at height H solved template N; B bytes: <hex>`) — to the
  operator for a template's first solution, to the file for the rest — because a template
  provider exists to relay blocks and NetGet has no node. Refusals are logged
  `decision=refused_*` with Bitcoin Core's reason vocabulary where one exists (`high-hash`,
  `bad-cb-amount`, …); SubmitSolution has no reply.
- Events: `stratum_v2_tp_setup_connection` (accept/reject), `stratum_v2_tp_coinbase_output_
  constraints` and `stratum_v2_tp_solution` (answer with templates). Bounds: 66 KiB per frame
  (SubmitSolution's coinbase is a B0_64K), 32 templates and 1024 solved hashes per connection,
  4 templates per answer, 64 transactions of at most 16 inputs and 16 outputs per template.

## Job declarator (`role: job_declarator`)

The Job Declaration Protocol as job_declaration_sv2 10.0 speaks it: AllocateMiningJobToken
(.Success), DeclareMiningJob (.Success/.Error), ProvideMissingTransactions(.Success) and
PushSolution. SetupConnection must name protocol 1; DECLARE_TX_DATA is the only flag accepted
(SRI's jd_client sets it in full-template mode, and SRI's own JDS refuses a client without it).

- **The model decides** who connects, whether a token is allocated (`stratum_v2_accept` with
  `stratum_v2_allocate_token {pay_to | op_return}`, the output a declared coinbase must pay) and
  whether a declared job is accepted, with the error code it chooses. There is no
  AllocateMiningJobToken.Error in this revision of the protocol, so a refused allocation ends the
  connection.
- **Rust keeps the token table**: 8-byte random tokens, at most `MAX_TOKENS` (64) per
  connection with the oldest evicted, each usable once and only on the connection it was issued
  to; an accepted declaration's token is spent and a new one issued with the Success, a refused
  one's is spent too.
- **Rust keeps a mempool** shared by the server's connections, keyed by wtxid, at most 16384
  transactions and 32 MiB, oldest evicted. A declaration naming transactions it lacks is asked
  for them (ProvideMissingTransactions with their positions); each supplied transaction must
  parse and hash to the wtxid at its position, or the job is `invalid-job`.
- **Before the model sees a declaration**: the token must be one this connection holds unused
  (`invalid-mining-job-token`), the wtxid list at most `MAX_DECLARED_TXS` (8192, `invalid-job`),
  at most 16 declarations waiting on transactions, the coinbase must split the way SRI's JDS
  splits it — prefix to the end of the scriptSig bytes written, the rest of the scriptSig (at
  most 32 bytes) the extranonce — and parse (`invalid-coinbase-tx`) with exactly one input on
  the null outpoint (`invalid-coinbase-tx-input`), commit to a BIP 34 height, and, if it carries
  a witness, its commitment must cover the declared wtxids (`invalid-job`). The event says what
  the coinbase pays, by script type, whether it includes the token's required outputs, the
  height, the transaction count and the weight.
- **PushSolution** names no job: Rust rebuilds each accepted job's coinbase with the pushed
  extranonce (newest first, at most 16 jobs per connection) and takes the one whose header
  meets nbits (which must itself be valid for `network`). The block is logged to the file, the
  model is told (`stratum_v2_jd_solution`, no reply exists), and anything else is logged
  `decision=refused_invalid_solution`.
- **Failure**: a failed model, silence or both verdicts refuse — SetupConnection.Error or
  DeclareMiningJob.Error with `service-unavailable`/`service-overloaded`, or the connection ends
  for an allocation — and a job is never accepted without the model's yes.
- Bounds: 4 MiB per frame (ProvideMissingTransactions.Success carrying a block's worth),
  every SEQ0_64K count checked against the bytes left before allocation, every CompactSize
  count likewise and canonical.

## Not built

- **The Mining Protocol's work selection**: the pool refuses `REQUIRES_WORK_SELECTION`, so it
  takes no SetCustomMiningJob and a NetGet JDS's tokens cannot be redeemed at a NetGet pool.
- **Relaying blocks**: neither new role is connected to a node; a solved block is verified and
  logged, and nothing submits it.
- **Sigop accounting**: CoinbaseOutputConstraints' sigops are reported, not checked.
- **Transactions beyond `OP_TRUE` and `OP_RETURN` outputs and empty scriptSigs** in templates
  the model writes; a JDS accepts any transaction a client supplies.

## Maturity: Experimental

**Pool.** SRI's `mining_device` — an independent implementation — completes the handshake
against the certificate, opens a standard channel, mines the model's job and has its shares
verified and credited, and prints hashes identical to NetGet's. That is one third-party client
against Stable's two, and the extended-channel path is driven only by NetGet's own client and
raw frames.

**Template provider.** SRI's `pool_sv2` takes NetGet's templates over network TDP (pinning
NetGet's authority key), SRI's `mining_device` mines on the pool, the pool sends SubmitSolution,
and the block NetGet assembles from its own template and SRI's coinbase is accepted by Bitcoin
Core 31.0's `submitblock` — merkle path (with an odd level), commitment, height, value and two
transactions. SRI's `jd_client` also takes NetGet's templates and asks for their transactions.
Two SRI programs, but one implementation of the template-receiving code (`channels_sv2`).

**Job declarator.** SRI's `jd_client` sets up, takes tokens, declares its job, supplies the
missing transaction when asked and receives DeclareMiningJob.Success. PushSolution from an
independent client is not shown: jd_client pushes solutions only for jobs its pool acknowledged,
and SRI's pool v0.8.0 checks custom-job tokens only with its own embedded JDS, so it answers
`jd-not-supported`; PushSolution is exercised with raw frames.

`fuzz/fuzz_targets/stratum_v2_message.rs` decodes every message and the Bitcoin structures
these roles parse, with count-bomb seeds; nothing recurses. It has run clean: 167,287 executions
over 301 seconds (current nightly, `-s none` on macOS), coverage 492 → 1426 edges. On this Mac
the fuzz build needed `RUSTFLAGS=-Clink-arg=-Wl,-undefined,dynamic_lookup`: `crc-fast` (under
the AWS SDK) links a dylib at build time, which fails against the sancov symbols only libFuzzer
provides; that affects every target, not this one. There is no pcap oracle: Wireshark
has no SV2 dissector and every frame after the handshake is ciphertext. Nobody has reviewed
beyond the evidence.
