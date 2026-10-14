# Stratum V2 mining device tests

Peers come from `tests/server/stratum_v2/install_peers.py` (`NETGET_SV2_POOL`,
`NETGET_SV2_BITCOIN_NODE`, `NETGET_SV2_BITCOIN_CLI`); the tests fail without them. No LLM
calls: a python chain or static handlers are the model.

- `real_server_test::netget_mines_blocks_on_sri_pool_work`: `bitcoin-node` 31.0 in regtest
  with `-ipcbind=unix` (16 blocks to `raw(51)` first, to leave initial block download), SRI's
  `pool_sv2` taking templates over IPC with SRI's example authority pair, and NetGet connecting
  with that public key at a declared 100 kH/s. The handler mines every job. The pool must open the
  channel, its prev hash must be a block the node has, the pool must credit a share, and — since
  on regtest that share is a block — `bitcoin-cli getblockheader` must find a block with the exact
  hash NetGet computed, above height 16. A submit by hand and one for a job that does not exist
  are checked, and a client pinning another authority key must fail to connect.
- `bounds_test`: a canned pool built from NetGet's codec — a refused SetupConnection, a foreign
  certificate and a malformed key each fail the connect; a ~128 KiB job is read but a header
  declaring 256 KiB + 1 ends the session with an error; a handler that mines on every job and
  every refused share stops after exactly `MAX_FOLLOWUP_DEPTH` (8) submissions.

Mutation-checked: skipping certificate verification, ntime big-endian in the header (SRI's
pool then refuses every share), the frame bound, the follow-up bound, and dropping the model's
actions (no share reaches the pool).
