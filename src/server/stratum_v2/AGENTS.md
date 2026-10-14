# Stratum V2 pool (server)

Stratum V2's Mining Protocol over its Noise-encrypted transport, hand-rolled from
[sv2-spec](https://github.com/stratum-mining/sv2-spec). Well-known port 3333: IANA assigns none,
and SRI's pool documents 3333 in its README and mainnet configurations (the spec's URL example
uses 34254, which SRI uses for its Job Declaration Server). Feature `stratum-v2`; the client role
shares `noise.rs` and `wire.rs`.

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

## Maturity: Experimental

SRI's `mining_device` — an independent implementation — completes the handshake against the
certificate, opens a standard channel, mines the model's job and has its shares verified and
credited, and prints hashes identical to NetGet's. That is one third-party client against
Stable's two, and the extended-channel path is driven only by NetGet's own client and raw
frames; there is no fuzz target and no pcap oracle (Wireshark has no SV2 dissector). Nobody has
reviewed beyond the evidence, and the pair job had not yet run in CI when this was written.
