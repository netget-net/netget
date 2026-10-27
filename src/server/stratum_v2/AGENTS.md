# Stratum V2 server: pool, template provider, job declarator

Stratum V2 over its Noise-encrypted transport, hand-rolled from
[sv2-spec](https://github.com/stratum-mining/sv2-spec). The `role` startup parameter chooses the
protocol: `pool` (default; the Mining Protocol, below), `template_provider` (the Template
Distribution Protocol, `template_provider.rs`), `job_declarator` (the Job Declaration
Protocol's server, `job_declarator.rs`) or `pool_and_job_declarator` (both on one port, with
work selection; see "Work selection"); all share the handshake, the certificate and the
framing, and `network` (default `mainnet`) names the chain heights, nbits and the subsidy are
checked against. `bitcoin_rpc_url` (with `bitcoin_rpc_user` and `bitcoin_rpc_password`,
redacted wherever parameters are shown) connects any role to a Bitcoin Core node (`node.rs`). Well-known port 3333: IANA assigns none, and SRI's pool documents 3333 in
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
  UpdateChannel(.Error), CloseChannel, SubmitShares{Standard,Extended}, SubmitShares.Success/.Error,
  SetCustomMiningJob(.Success/.Error) (and Reconnect, SetExtranoncePrefix, SetGroupChannel,
  ChannelEndpointChanged for the client).
  Decoding refuses fields that overrun the payload, leftover bytes, OPTION/B0_32 over their
  bound, and F32 that is NaN, infinite or negative.
- **Setup**: protocol must be 0 (Mining), versions must include 2, and flags other than
  `REQUIRES_STANDARD_JOBS` and `REQUIRES_VERSION_ROLLING` are refused with
  `SetupConnection.Error{flags: <those bits>, "unsupported-feature-flags"}` — on a plain `pool`
  that includes `REQUIRES_WORK_SELECTION`, since it has no job declarator whose tokens a custom
  job could redeem; `pool_and_job_declarator` accepts it. Anything before SetupConnection, a
  second SetupConnection, an unknown core message, one a device never sends, or
  SetCustomMiningJob on a connection that did not negotiate work selection ends the
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
  little-endian 256-bit number. Only a share that meets it reaches the model — except a share
  on a custom job that meets the job's nbits, which is a block and is never refused for missing
  the channel's target (see "Work selection").
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
  share_difficulty, difficulty, nonce, ntime, version, custom_job, solves_block, relay?,
  remote_addr}` → accept (credit) or reject.
- `stratum_v2_custom_job` (work selection, below) → accept or reject.
- Any answer may carry `stratum_v2_set_target`, `stratum_v2_new_job` and
  `stratum_v2_close_channel {reason_code}` for the channel in question. Codes are 1–64
  printable ASCII characters (§3.5).

## Failure

A failed model call, an invalid reply, silence, or both accept and reject refuse the request —
`SetupConnection.Error`, `OpenMiningChannel.Error`, `SetCustomMiningJob.Error` or
`SubmitShares.Error` with `service-unavailable` (or `service-overloaded` when the backend is at
capacity) — and never admit, open, take a custom job or credit anything. Decisions are logged
`decision=model_answer|model_reject|model_silent|fail_closed_*`.

## Bounds

16 KiB per inbound frame (80 KiB once a connection has negotiated work selection: a
SetCustomMiningJob with a full B0_64K of outputs and a 255-deep path is ~73 KiB); 10 s for the
device's half of the handshake; idle
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
  relayed to the node when `bitcoin_rpc_url` is set and logged in full either way (`… block
  <hash> at height H solved template N; B bytes: <hex>`) — to the operator for a template's
  first solution, to the file for the rest. Refusals are logged
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
  one's is spent too. The new token is also entered, with the accepted job, in a table every
  connection of the server shares (`Redeemable`, at most `MAX_REDEEMABLE` 1024, oldest
  evicted): that token is what a SetCustomMiningJob on the pool side redeems, once.
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
  a witness, its commitment must cover the declared wtxids (`invalid-job`). With a node, the
  height the coinbase commits to must be the node's next block (`stale-chain-tip`, logged
  `decision=refused_stale_chain_tip`; a node that cannot answer refuses with
  `service-unavailable`, `decision=fail_closed_node_error`), and that tip is kept with the job.
  The event says what the coinbase pays, by script type, whether it includes the token's
  required outputs, the height, the tip (with a node), the transaction count and the weight.
- **PushSolution** names no job: Rust rebuilds each accepted job's coinbase with the pushed
  extranonce (newest first, at most 16 jobs per connection, skipping jobs declared on another
  tip) and takes the one whose header meets nbits (which must itself be valid for `network`).
  The match is by content, so at regtest's nbits two jobs could both match; the tip filter is
  what keeps that from picking a job on the wrong chain. The block is relayed to the node if
  one is configured and logged to the file, the model is told (`stratum_v2_jd_solution`, no
  reply exists), and anything else is logged `decision=refused_invalid_solution`.
- **Failure**: a failed model, silence or both verdicts refuse — SetupConnection.Error or
  DeclareMiningJob.Error with `service-unavailable`/`service-overloaded`, or the connection ends
  for an allocation — and a job is never accepted without the model's yes.
- Bounds: 4 MiB per frame (ProvideMissingTransactions.Success carrying a block's worth),
  every SEQ0_64K count checked against the bytes left before allocation, every CompactSize
  count likewise and canonical.

## Work selection (`role: pool_and_job_declarator`)

One listener serves both the Mining Protocol and the Job Declaration Protocol: the session reads
the first frame, and a SetupConnection whose protocol byte is 1 is handed to the job declarator
(with its 4 MiB frame bound), anything else to the pool. One server, so one token table: the
alternative — two instances sharing state — would need a registry across instances in
`AppState`, two certificates and ports to configure, and a way for one instance's stop to
invalidate the other's tokens. SRI's pool embeds its JDS the same way, on two ports; SRI's
jd_client takes the same address for `pool_port` and `jds_port`.

- **Setup** accepts `REQUIRES_WORK_SELECTION`; such a connection's frame bound rises to 80 KiB.
- **SetCustomMiningJob** (sv2-spec §5.3, mining_sv2 12.0 as sv2-apps v0.8.0 sends it: the token
  is the one DeclareMiningJob.Success issued, `coinbase_prefix` is the scriptSig up to and
  including the push opcode of the full extranonce, `coinbase_tx_outputs` is the output vector
  with its count). Refused before the model, with SRI's codes: no such channel or a standard one
  (`invalid-channel-id`, the token not spent); a token this server's job declarator did not
  issue for an accepted job, or one already redeemed (`invalid-mining-job-token`) — the token is
  spent by asking, whatever follows; then, against the declaration: `invalid-version`,
  `stale-chain-tip` and `invalid-nbits` (against the node's tip when one was recorded, and nbits
  always against the network's limit), `invalid-min-ntime` (more than two hours ahead),
  `invalid-coinbase-tx-version`, `invalid-coinbase-prefix` (also when the declaration's
  extranonce space is not this channel's prefix plus its rollable part),
  `invalid-coinbase-tx-input-n-sequence`, `invalid-coinbase-tx-outputs`,
  `invalid-coinbase-tx-locktime`, `invalid-merkle-path` (the path of the declared transactions),
  and `invalid-coinbase-tx` if the coinbase the fields describe, around a zero extranonce, is
  not the declared one byte for byte. Logged `decision=refused_invalid_token` /
  `refused_invalid_custom_job`.
- **The model decides** `stratum_v2_custom_job {channel_id, request_id, user_identity,
  declaration_request_id, height, prev_hash, nbits, version, min_ntime, transactions,
  coinbase_outputs, coinbase_value_sats, tip_checked, remote_addr}` → `stratum_v2_accept`
  (SetCustomMiningJob.Success with a job id) or `stratum_v2_reject {error_code}`; a failure or
  silence answers `service-unavailable`/`service-overloaded`. An accepted job on a new prev hash
  retires the channel's other jobs.
- **Shares on a custom job** rebuild the declared coinbase (serialised as declared, segwit) around
  the channel's prefix and the share's extranonce, fold its txid up the custom job's path, and
  hash the header with the job's prev hash and nbits. A hash meeting nbits is a block: logged
  (the operator sees its hash, the file its bytes), relayed, and accepted even below the
  channel's target, because SRI's jd_client forwards every share that meets the network target
  whatever the channel's difficulty, and a pool that refused one would be refusing the block.
  The share event carries `custom_job`, `solves_block` and `relay`.
- **Where SRI v0.8.0 departs from the spec**: sv2-spec describes `coinbase_prefix` as up to 8
  bytes; SRI sends a B0_255 holding the BIP 34 push, its pool/miner tag and the extranonce push
  opcode, and NetGet decodes it as B0_255 and compares it to the declaration. jd_client also
  hands a block to its template provider before its pool has acknowledged the job (optimistic
  mining), so on regtest the tip can move while a declaration is checked; NetGet's
  `stale-chain-tip` is the answer jd_client treats as non-fatal.

## A Bitcoin Core node (`bitcoin_rpc_url`)

`node.rs` makes two JSON-RPC calls with basic auth, each with a 15 s deadline and a 64 KiB
response bound: `getmininginfo` (whose `next` gives the next block's height and nbits; Bitcoin
Core 29 or later) with `getblockhash` for the tip below it, and `submitblock`. Credentials in the
URL are refused; the password is never logged. The job declarator checks each declaration
against the tip; every role relays each block it verified, once per hash (`MAX_RELAYED` 1024
remembered; a failed relay is forgotten so a later report retries), logging
`decision=relayed|relay_refused|relay_failed` and telling the model what the node said in the
event's `relay` field (`accepted`, Bitcoin Core's reason such as `duplicate`, `already-relayed`
or `relay-failed`).

## Not built

- **Sigop accounting**: CoinbaseOutputConstraints' sigops are reported, not checked. A check on
  the template provider could never fire: the model's transactions carry no sigops (`OP_TRUE`
  and `OP_RETURN` outputs, empty scriptSigs) and the constraint is a U16 in cost units, below the
  80,000 a block allows on its own. On the job declarator it would need the spent outputs (P2SH
  and witness sigops), and NetGet keeps no UTXO set.
- **A chain without a node**: with no `bitcoin_rpc_url` nothing checks a declaration's height or
  a custom job's prev hash against a chain (`tip_checked: false`; nbits is still checked
  against the network's limit), and blocks are only logged.
- **Transactions beyond `OP_TRUE` and `OP_RETURN` outputs and empty scriptSigs** in templates
  the model writes; a JDS accepts any transaction a client supplies, and only a node (through
  the relay) judges them.
- **A full Job Declarator Client in NetGet**: the client role declares jobs but opens no mining
  channel to redeem its token (`src/client/stratum_v2/AGENTS.md`).

## Maturity: Experimental

**Pool.** SRI's `mining_device` — an independent implementation — completes the handshake
against the certificate, opens a standard channel, mines the model's job and has its shares
verified and credited, and prints hashes identical to NetGet's. SRI's `jd_client` drives the
extended-channel path and work selection: it opens an extended channel, redeems NetGet's JDS
tokens with SetCustomMiningJob, and sends SubmitSharesExtended that NetGet rebuilds into the
block Bitcoin Core has. Two SRI programs, but one implementation family, against Stable's two
independent clients.

**Template provider.** SRI's `pool_sv2` takes NetGet's templates over network TDP (pinning
NetGet's authority key), SRI's `mining_device` mines on the pool, the pool sends SubmitSolution,
and NetGet relays the block it assembles from its own template and SRI's coinbase to Bitcoin
Core 31.0, whose tip moves to it — merkle path (with an odd level), commitment, height, value
and two transactions. SRI's `jd_client` also takes NetGet's templates and asks for their
transactions. Two SRI programs, but one implementation of the template-receiving code
(`channels_sv2`).

**Job declarator.** SRI's `jd_client` sets up, takes tokens, declares its job, supplies the
missing transaction when asked and receives DeclareMiningJob.Success. With NetGet as its pool
too (`pool_and_job_declarator`), it redeems the token, mines and pushes the solution, and the
block NetGet's JDS rebuilds from PushSolution is the block in Bitcoin Core's chain. (SRI's own
pool v0.8.0 checks custom-job tokens only with its embedded JDS and answers `jd-not-supported`,
so with SRI's pool in front, PushSolution never follows.)

`fuzz/fuzz_targets/stratum_v2_message.rs` decodes every message and the Bitcoin structures
these roles parse, with count-bomb seeds; nothing recurses. It has run clean: 167,287 executions
over 301 seconds (current nightly, `-s none` on macOS), coverage 492 → 1426 edges; and again with
work selection's SetCustomMiningJob seeds (its output vector parsed with the pool's bound, a
2^32 − 1-output bomb and a 255-hash path carrying one), 168,717 executions over 301 seconds,
coverage 563 → 1524. The fuzz workspace's lockfile is gitignored, so a fresh fuzz build resolves
the newest versions — in October 2026 that was a `libc` nix 0.8.1 no longer compiles against on
macOS and AWS SDK crates that disagree with each other; copying the root lockfile into the fuzz
directory first builds.
`nightly-2025-12-04` is now too old for the AWS SDK (1.94.1 is required). On this Mac
the fuzz build needed `RUSTFLAGS=-Clink-arg=-Wl,-undefined,dynamic_lookup`: `crc-fast` (under
the AWS SDK) links a dylib at build time, which fails against the sancov symbols only libFuzzer
provides; that affects every target, not this one. There is no pcap oracle: Wireshark
has no SV2 dissector and every frame after the handshake is ciphertext. Nobody has reviewed
beyond the evidence.
