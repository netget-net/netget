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
  Bitcoin Core regtest with 101 blocks to `OP_TRUE`; NetGet as template provider, whose model
  writes a template on the tip with two transactions spending the first two coinbases (three
  leaves, so the path pairs a hash with itself); SRI's `pool_sv2` with `[template_provider_type.
  Sv2Tp]` pinning NetGet's key; SRI's `mining_device` on the pool. The pool sends SubmitSolution,
  NetGet verifies and logs the block, and `bitcoin-cli submitblock` must accept it with both
  transactions and a coinbase claiming exactly subsidy plus fees. The model's next template (on
  the new block) must reach the pool. Prints what the pool sent: SetupConnection,
  CoinbaseOutputConstraints, SubmitSolution.
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
