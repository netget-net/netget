# Stratum V2 client tests

Peers come from `tests/server/stratum_v2/install_peers.py` (`NETGET_SV2_POOL`,
`NETGET_SV2_BITCOIN_NODE`, `NETGET_SV2_BITCOIN_CLI`, `NETGET_SV2_TP`); the tests fail without
them. The job declarator and template client tests compile `tests/server/stratum_v2/peers.rs`
for the regtest node and SRI peers. No LLM calls: a python chain or static handlers are the
model.

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
- `job_declarator_test::netget_declares_a_job_sri_jds_and_bitcoin_core_accept`: Bitcoin Core
  regtest (IPC, 101 blocks to `OP_TRUE`) and the JDS embedded in SRI's `pool_sv2` (`[jds]`). The
  chain declares the next height with a transaction spending the first coinbase; the JDS asks
  for it, Bitcoin Core's `checkBlock` passes, the declaration is accepted, and the chain mines it
  and pushes the solution, which the JDS logs. A second declaration spending a missing output is
  refused by the JDS and the refusal reaches the model; a coinbase over subsidy plus fees is
  refused before the wire. Prints what the JDS sent (two token successes, ProvideMissing-
  Transactions twice, one Success, one Error).
- `template_client_test::netget_mines_sv2_tp_templates_into_bitcoin_core`: Bitcoin Core regtest
  (IPC) whose wallet puts three segwit transactions in the mempool, and sv2-tp 1.1.2 serving
  templates from it; NetGet pins sv2-tp's authority key (read from its log). The chain answers
  SetNewPrevHash by asking for the transactions and mining the template: the merkle path and
  witness commitment must match the three transactions, and Bitcoin Core must then have NetGet's
  block, with the three transactions, as its tip. A foreign key is refused. Prints what sv2-tp
  sent.

Mutation-checked: skipping certificate verification, ntime big-endian in the header (SRI's
pool then refuses every share), the frame bound, the follow-up bound, and dropping the model's
actions (no share reaches the pool). Dropping the model's actions was checked again in October
2026 in all three roles — mining (`real_server_test`), job declarator (`job_declarator_test`)
and template client (`template_client_test`) — and fails each. The merkle path both new roles
compute is the server's, mutation-checked against Bitcoin Core there.
