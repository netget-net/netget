# Stratum V2 server tests

`install_peers.py <dir>` installs the peers for every role, server and client — SRI's sv2-apps
v0.8.0 (commit 7f49074357e5, built with cargo) for `pool_sv2`, `mining_device` and
`jd_client_sv2`, Bitcoin Core 31.0 and sv2-tp 1.1.2 (both SHA-256 pinned, linux x86_64/aarch64 or
macOS arm64) — and prints `NETGET_SV2_POOL`, `NETGET_SV2_MINING_DEVICE`, `NETGET_SV2_JD_CLIENT`,
`NETGET_SV2_BITCOIN_NODE`, `NETGET_SV2_BITCOIN_CLI`, `NETGET_SV2_TP`. The tests fail without them.
No LLM calls: a python policy is the model (`support::policy`, `support::script`).
`peers.rs` starts the real peers, each in a temp dir of its own with its own ports and log
file, which a failing test prints; the client test binary compiles the same file.

The build needs the Cap'n Proto compiler **and its standard schemas**: on Ubuntu that is
`capnproto` *and* `libcapnp-dev`. `bitcoin-capnp-types` (the Bitcoin Core IPC schemas the pool
links) imports `/capnp/c++.capnp`, which only `libcapnp-dev` installs, so with `capnproto` alone
its build script fails with "Import failed: /capnp/c++.capnp". Homebrew's `capnp` ships both. A
failing build step prints cargo's output to stderr.

- `real_client_test::sri_mining_device_mines_against_netget`: SRI's `mining_device` pins
  NetGet's authority key (SRI's example pair, so the key NetGet derives from the secret is the
  one SRI publishes), sets up, opens a standard channel at difficulty 0.0005 on the model's job
  and prev hash, and mines. The policy credits odd sequence numbers and refuses even ones; the
  test waits for two `SubmitSharesSuccess` and one `policy-rejected`, fails on any other error
  code, and requires every share the model saw to carry a hash the device itself printed.
- `real_client_test::sri_mining_device_refuses_a_pool_its_key_did_not_sign`: pointed at the
  spec's example key, the device must exit with `InvalidCertificate` before SetupConnection.
- `wire_test`: raw frames from NetGet's own codec — an unauthenticated first frame, a tampered
  payload, a header declaring 16 KiB + 1 (and exactly 16 KiB, which is read), messages before
  setup, unknown and malformed messages, NaN hash rate, unsupported flags/version/protocol; the
  model refusing a device and a user; every share refusal code; duplicates; version rolling; an
  extended channel's coinbase rebuilt from the device's extranonce; UpdateChannel → SetTarget;
  stale shares after the model moves the prev hash; and a failed model admitting nobody and
  crediting nothing.
- `noise_test`: the spec's base58check vector, SRI's example key pair, both roles agreeing on
  keys, every way the initiator refuses a responder, replay/tamper, the ciphertext-length
  formula, codec round trips and malformed payloads, targets ↔ difficulty.
- `template_provider_test::sri_pool_mines_netget_templates_into_a_block_bitcoin_core_accepts`:
  Bitcoin Core regtest with 101 blocks to `OP_TRUE`; NetGet as template provider with
  `bitcoin_rpc_url` pointing at the node, whose model writes a template on the tip with two
  transactions spending the first two coinbases (three leaves, so the path pairs a hash with
  itself); SRI's `pool_sv2` with `[template_provider_type.Sv2Tp]` pinning NetGet's key; SRI's
  `mining_device` on the pool. The pool sends SubmitSolution, NetGet verifies, logs and relays
  the block, and Bitcoin Core must have it at the next height — the test submits nothing — with
  both transactions and a coinbase claiming exactly subsidy plus fees; the logged bytes, submitted
  again, are a `duplicate`. The model's next template (on the new block) must reach the pool.
  Prints what the pool sent: SetupConnection, CoinbaseOutputConstraints, SubmitSolution.
- `work_selection_test::sri_jd_client_pushes_a_block_through_netget_pool_and_jds`: one NetGet
  server in the `pool_and_job_declarator` role with `bitcoin_rpc_url`, as both the pool and the
  JDS of SRI's `jd_client` (FULLTEMPLATE, one port for both); templates from sv2-tp 1.1.2 over
  Bitcoin Core 31.0 regtest (IPC), whose wallet keeps transactions in the mempool; SRI's
  `mining_device` on the jd_client. jd_client declares (NetGet asks for the transactions and
  checks the height against the node), redeems the token with SetCustomMiningJob (checked
  against the declaration and the node's tip), mines, and on a block sends SubmitSolution to
  sv2-tp (which hands it to the node), PushSolution to NetGet's JDS and SubmitSharesExtended to
  its pool. The test waits for a block with transactions that is in Bitcoin Core's chain and
  that NetGet's JDS and pool each rebuilt with the same hash, and asserts it from jd_client's log
  (`SetCustomMiningJobSuccess`, `Block Found`, the solution propagated), NetGet's events
  (`stratum_v2_custom_job` with `tip_checked`, `stratum_v2_share` with `solves_block`,
  `stratum_v2_jd_solution`) and `getblockhash`/`getblock`. On regtest every share is a block
  and jd_client hands blocks to its template provider before its pool acknowledges the job, so
  the tip can move during a declaration and NetGet answers `stale-chain-tip`, which jd_client
  treats as non-fatal; the test tolerates that race rather than assuming the first template
  wins. Prints what jd_client sent each half of the server, what it received (from its log),
  NetGet's refusals and its relays (`duplicate` when sv2-tp got there first).
- `work_selection_test::custom_jobs_are_checked_against_their_declaration`: raw frames on both
  halves of one `pool_and_job_declarator` port (no node): a plain pool refusing work selection;
  an unknown token and an unknown channel; every field of a custom job that disagrees with its
  declaration refused with its own code, each spending its token; a declaration whose extranonce
  space is not the channel's; a failing model (`service-unavailable`) and a refusing one; a
  token another server's JDS issued; an accepted custom job whose token cannot be redeemed
  twice; a share below the job's nbits refused and one meeting it accepted as a block although
  the channel is at difficulty 1; PushSolution on the JDS side rebuilding the same block; and
  SetCustomMiningJob without work selection ending the session.
- `work_selection_test::declarations_and_custom_jobs_are_checked_against_the_node`: the same
  role with `bitcoin_rpc_url` on a Bitcoin Core regtest node and raw frames: a declaration at a
  height that is not the node's next block is `stale-chain-tip`; a custom job on another prev
  hash is `stale-chain-tip` and one with nbits the node's next block does not have is
  `invalid-nbits`; one on the tip is accepted (`tip_checked`), its first share is a block, and
  NetGet's pool relays it — the node's best block becomes NetGet's, with nobody else
  submitting — while the same block pushed to the JDS is rebuilt to the same hash and reported
  `already-relayed`.
- `job_declarator_test::sri_jd_client_declares_its_job_to_netget`: Bitcoin Core (IPC) feeding
  SRI's `pool_sv2`; NetGet as template provider for SRI's `jd_client` (FULLTEMPLATE) and NetGet as
  the JDS under test; a `mining_device` on the jd_client, which opens its upstream channel only
  once a miner connects. The jd_client must ask NetGet's provider for the template's
  transactions, declare, be asked for the missing transaction, supply it, and receive
  DeclareMiningJob.Success; the model is asked once per stage with what Rust already checked.
  Prints what the jd_client sent to each NetGet server.
- `tdp_jdp_wire_test`: raw frames for every rule Rust enforces in the two roles — protocol and
  flags, a message before setup, the model's templates refused for nbits easier than the
  network's or a coinbase a sat over subsidy plus fees, the height push with its sign byte, the
  merkle path folding to the full tree's root and the commitment covering the wtxids,
  RequestTransactionData's stale and unknown ids, solutions above the target, over-paying or
  without the height never reaching the model, duplicates, exactly the 66 KiB frame bound read
  and one more byte ending the session; for the JDS, unknown and spent tokens, the declared-count
  bound, transactions asked for and checked against their wtxids (and only the unknown ones asked
  for the second time), the commitment, the token table's bound, PushSolution matched to the job
  and verified, a refused allocation ending the connection, and a failing model never accepting a
  job.

There is no pcap oracle: tshark has no Stratum V2 dissector and every frame after the handshake
is ChaCha20-Poly1305 ciphertext. Bitcoin Core judging the assembled block is the oracle for the
bytes that matter.

Mutation-checked (each broke the named test, then was restored): skipping certificate
verification, signing a different digest, big-endian Noise nonces, swapped ECDH roles,
ignoring the target, ntime big-endian in the header, no duplicate check, a failed model
admitting a device or crediting a share, and the frame bound. For the template provider and
job declarator (October 2026): SubmitSolution's header not checked against the target and its
coinbase value not checked (`tdp_jdp_wire_test`); an odd merkle level paired with zeros rather
than itself (`template_provider_test` — Bitcoin Core refuses the block, `bad-txnmrklroot`);
PushSolution's header not checked, no token eviction past `MAX_TOKENS`, a failed model
accepting a declared job, and no bound on the declared transaction count (`tdp_jdp_wire_test`).
For work selection (October 2026), each failing `work_selection_test` unless named: the custom
job never compared with its declaration; only its merkle path not compared; only its scriptSig
prefix not compared (the byte-for-byte coinbase check then answers `invalid-coinbase-tx`, which
the test also refuses to accept); a redeemed token staying redeemable; a failed model taking the
custom job; PushSolution's header not checked against nbits (`tdp_jdp_wire_test`, which sees two
solutions); a custom job's block below the channel's target refused (both the raw test and the
SRI one fail — the second is how the rule was found: NetGet's pool rebuilt the very hash Bitcoin
Core had and answered `difficulty-too-low`); a declaration's height not checked against the
node; and no relay (the node-backed test and `template_provider_test`). Two things to know
about the mutation runs themselves: a restore that preserves the file's old mtime (`cp -p`,
Python's `copy2`) leaves cargo reusing the mutated build, so restore with a fresh mtime; and at
regtest's nbits every share is a block, so a raw test that wants a block below the channel's
difficulty needs a harder nbits (0x1f00ffff) and a channel at difficulty 1.
