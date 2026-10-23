# Stratum V2 client: mining device, job declarator, template client

The `role` startup parameter chooses the protocol: `mining` (default; a mining device on a
pool's Mining Protocol, below), `job_declarator` (a Job Declarator Client, `job_declarator.rs`)
or `template_client` (a Template Distribution client, `template_client.rs`). Every role connects
(`host:port`; a `stratum2+tcp://` prefix and a trailing `/<key>` path are tolerated), runs the
Noise NX initiator from `src/server/stratum_v2/noise.rs` and refuses the server unless its
certificate verifies against `authority_public_key` (required; base58check as pools publish it)
and is within its validity window (±10 s). Only then is SetupConnection sent (vendor `NetGet`,
version 2). A SetupConnection.Error, a foreign certificate or a malformed key fails the connect
itself, so the client never exists in a half-open state. Each role logs what the server sent, by
message, when its session ends (`… received: NewTemplate=3, …`; the setup answer, read before
the session, is not counted).

## Mining device (`role: mining`)

SetupConnection names protocol 0 and `REQUIRES_STANDARD_JOBS` for a standard channel. On success
one channel opens at once (`user_identity` default `netget`, `nominal_hash_rate` default 1e6,
`channel_kind` default `standard`, `max_target` all ones, extended asks for 8 bytes of
extranonce). The client tracks NewMiningJob, NewExtendedMiningJob (coinbase halves and merkle
path), SetNewPrevHash (only the job it names stays valid), SetTarget and SetExtranoncePrefix.

### Events

- `stratum_v2_channel {ok, request_id, channel_id?, channel_kind?, user_identity?, difficulty?,
  extranonce_size?, error_code?}`.
- `stratum_v2_job {channel_id, job_id, channel_kind, user_identity, prev_hash, ntime, nbits,
  version, difficulty, merkle_path_len?}` — when a job becomes the work, not for every future job.
- `stratum_v2_share_result {channel_id, sequence_number, job_id, nonce, ntime, hash,
  share_difficulty, accepted, error_code?, new_submits_accepted_count?, new_shares_sum?}`: the
  hash is Rust's own computation. A batched SubmitShares.Success resolves every pending share up
  to `last_sequence_number` and raises one event for the newest.
- `stratum_v2_mining_done {channel_id, hashes, best_difficulty, difficulty, reason}`.
- `stratum_v2_message {message, fields}` for CloseChannel, Reconnect, UpdateChannel.Error,
  SetExtranoncePrefix, SetGroupChannel, ChannelEndpointChanged. Reconnect is reported, not
  followed.

### Actions

- `stratum_v2_mine {max_hashes?, submit_best?, channel_id?}` — single-threaded on a blocking
  thread, at most `MAX_MINE_HASHES` (50M, default 1M), nonces from 0 at the job's ntime; extended
  channels roll a fresh extranonce counter per run.
- `stratum_v2_submit {nonce, ntime?, version?, job_id?, extranonce?, channel_id?}` — numbers;
  Rust writes the extranonce counter little-endian into the channel's extranonce size.
- `stratum_v2_open_channel {user_identity, nominal_hash_rate?, channel_kind?}`,
  `stratum_v2_update_channel {nominal_hash_rate, min_difficulty?, channel_id?}`,
  `stratum_v2_close_channel {reason_code, channel_id?}`, `disconnect`.

### Bounds

Frames over `MAX_INBOUND_PAYLOAD` (256 KiB — a NewExtendedMiningJob with two full coinbase
halves and a 255-deep path is ~136 KiB) end the session before the payload is read; 30 s for the
handshake and setup answer; `MAX_PENDING` 64 awaited answers, `MAX_CHANNELS` 16, `MAX_JOBS` 16 per
channel; a handler chain stops after `MAX_FOLLOWUP_DEPTH` (8) follow-ups.

## Job declarator client (`role: job_declarator`)

SetupConnection names protocol 1 with DECLARE_TX_DATA (SRI's JDS refuses
`missing-declare-tx-data-flag` without it), and one token is requested at once
(AllocateMiningJobToken as `user_identity`). Tokens are kept, at most 16, each used once.

- `stratum_v2_jd_token {request_id, coinbase_outputs, tokens_held}` → the model may answer
  `stratum_v2_declare_job {height, transactions?, coinbase_value_sats?, version?, message?}`.
  Rust refuses a coinbase value above the subsidy at that height (`network`) plus the
  transactions' fees before anything is sent, then builds the coinbase the way SRI's JDS splits
  one: a segwit serialisation, scriptSig = BIP 34 height, the message, 8 bytes of extranonce
  space; outputs = the token's required outputs with the coinbase value on the first (as SRI's
  jd_client does) and the witness commitment for the transactions' wtxids; the 32-byte zero
  witness reserved value. It declares the wtxids and answers ProvideMissingTransactions from the
  declaration (a position past the end ends the session).
- `stratum_v2_jd_declare_result {request_id, accepted, height, transaction_count, error_code?}`.
- `stratum_v2_push_solution {prev_hash, nbits, ntime?, request_id?, max_hashes?}` mines an
  accepted declaration on the tip the model names (the protocol tells a JDC no tip) and sends
  PushSolution if a header meets nbits; `stratum_v2_jd_solution_pushed` reports it.
- `stratum_v2_request_token {user_identifier?}`, `disconnect`.
- Bounds: 256 KiB per frame, 16 declarations remembered, 16 token outputs; answers continue the
  handler chain at the depth of the action that caused them, so `MAX_FOLLOWUP_DEPTH` holds.

## Template client (`role: template_client`)

SetupConnection names protocol 2, then CoinbaseOutputConstraints sized for NetGet's one coinbase
output (`OP_TRUE`, 10 bytes, no sigops). Templates (at most 16) and the tip are tracked; a
SetNewPrevHash activates the template it names and drops those on the old tip.

- `stratum_v2_template {template_id, future, version, height, coinbase_value_sats,
  merkle_path_len, coinbase_outputs, prev_hash?}` and `stratum_v2_template_prev_hash
  {template_id, prev_hash, ntime, nbits, target_matches_nbits}`.
- `stratum_v2_request_transactions {template_id?}` → `stratum_v2_template_transactions
  {template_id, transaction_count, segwit_transactions, weight, merkle_path_matches,
  witness_commitment_matches, error_code?}`: Rust parses every transaction and checks the
  provider's merkle path and commitment against them.
- `stratum_v2_mine_template {template_id?, max_hashes?, message?}` builds the coinbase the
  template describes (prefix, message, 8 bytes of extranonce, NetGet's `OP_TRUE` output for the
  remaining value, the template's outputs, the witness reserved value when the template commits
  to witnesses), hashes on the template's tip, sends SubmitSolution for the first header meeting
  the target, and reports `stratum_v2_template_solution`.
- `stratum_v2_set_coinbase_constraints {max_additional_size, max_additional_sigops}`,
  `disconnect`. Bounds: 8 MiB per frame (a block's transactions), 64 template outputs.

## Not built

- **SetCustomMiningJob**: the job declarator client declares jobs but does not open a mining
  channel to redeem the token at a pool; a full JDC is that plus the mining device.
- **Payout scripts other than `OP_TRUE`** for the template client's coinbase output.

## Maturity: Experimental

**Mining device.** SRI's `pool_sv2` over Bitcoin Core 31.0 (regtest, IPC) accepts its channel
and shares, and the block Bitcoin Core accepts has the hash NetGet computed. That is one
independent server, and the extended-channel path has only been exercised against NetGet's own
pool.

**Job declarator client.** The JDS embedded in SRI's `pool_sv2` v0.8.0 takes NetGet's token
requests, asks for the declared transaction, validates the assembled block with Bitcoin Core's
`checkBlock` over IPC and accepts it; a job spending a missing output is refused and the refusal
reaches the model; NetGet's PushSolution is received and logged (SRI v0.8.0 does nothing more
with one yet).

**Template client.** sv2-tp 1.1.2 (stratum-mining/sv2-tp, the C++ Template Provider derived
from Bitcoin Core) serves templates built from Bitcoin Core 31.0's mempool; NetGet checks the
merkle path and witness commitment against three real segwit transactions, mines the template
and submits it, and Bitcoin Core then has the block by the hash NetGet computed.

One independent server per role; no pcap oracle (Wireshark has no SV2 dissector and the
transport is ciphertext); the shared decoders are fuzzed by `stratum_v2_message`.
