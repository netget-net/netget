# Stratum V2 pool tests

`install_peers.py <dir>` installs the peers for both roles — SRI's sv2-apps v0.8.0 (commit
7f49074357e5, built with cargo) for `pool_sv2` and `mining_device`, and Bitcoin Core 31.0
(SHA-256 pinned, linux x86_64/aarch64 or macOS arm64) — and prints `NETGET_SV2_POOL`,
`NETGET_SV2_MINING_DEVICE`, `NETGET_SV2_BITCOIN_NODE`, `NETGET_SV2_BITCOIN_CLI`. The tests fail
without them. No LLM calls: a python policy is the model (`support::policy`).

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

Mutation-checked (each broke the named test, then was restored): skipping certificate
verification, signing a different digest, big-endian Noise nonces, swapped ECDH roles,
ignoring the target, ntime big-endian in the header, no duplicate check, a failed model
admitting a device or crediting a share, and the frame bound.
