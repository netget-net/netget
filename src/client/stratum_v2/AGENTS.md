# Stratum V2 mining device (client)

Connects (`host:port`; a `stratum2+tcp://` prefix and a trailing `/<key>` path are tolerated),
runs the Noise NX initiator from `src/server/stratum_v2/noise.rs` and refuses the pool unless its
certificate verifies against `authority_public_key` (required; base58check as pools publish it)
and is within its validity window (±10 s). Only then is SetupConnection sent (vendor `NetGet`,
protocol 0, version 2, `REQUIRES_STANDARD_JOBS` for a standard channel). A
SetupConnection.Error, a foreign certificate or a malformed key fails the connect itself, so the
client never exists in a half-open state.

On success one channel opens at once (`user_identity` default `netget`, `nominal_hash_rate`
default 1e6, `channel_kind` default `standard`, `max_target` all ones, extended asks for 8 bytes
of extranonce). The client tracks NewMiningJob, NewExtendedMiningJob (coinbase halves and merkle
path), SetNewPrevHash (only the job it names stays valid), SetTarget and SetExtranoncePrefix.

## Events

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

## Actions

- `stratum_v2_mine {max_hashes?, submit_best?, channel_id?}` — single-threaded on a blocking
  thread, at most `MAX_MINE_HASHES` (50M, default 1M), nonces from 0 at the job's ntime; extended
  channels roll a fresh extranonce counter per run.
- `stratum_v2_submit {nonce, ntime?, version?, job_id?, extranonce?, channel_id?}` — numbers;
  Rust writes the extranonce counter little-endian into the channel's extranonce size.
- `stratum_v2_open_channel {user_identity, nominal_hash_rate?, channel_kind?}`,
  `stratum_v2_update_channel {nominal_hash_rate, min_difficulty?, channel_id?}`,
  `stratum_v2_close_channel {reason_code, channel_id?}`, `disconnect`.

## Bounds

Frames over `MAX_INBOUND_PAYLOAD` (256 KiB — a NewExtendedMiningJob with two full coinbase
halves and a 255-deep path is ~136 KiB) end the session before the payload is read; 30 s for the
handshake and setup answer; `MAX_PENDING` 64 awaited answers, `MAX_CHANNELS` 16, `MAX_JOBS` 16 per
channel; a handler chain stops after `MAX_FOLLOWUP_DEPTH` (8) follow-ups.

## Maturity: Experimental

SRI's `pool_sv2` over Bitcoin Core 31.0 (regtest, IPC) accepts its channel and shares, and the
block Bitcoin Core accepts has the hash NetGet computed. That is one independent server, and
the extended-channel path has only been exercised against NetGet's own pool.
