# iSCSI initiator tests

Python script handlers play the client's model (and the target's, where NetGet's own target is
the peer); the LLM endpoint is unreachable, so an event no handler answers fails closed. LLM
calls: zero.

## `e2e_test.rs` — against NetGet's own target (regression of shapes, not evidence)

- `the_initiator_runs_the_models_session_against_netgets_target`: discover → login → REPORT
  LUNS → INQUIRY → READ CAPACITY → READ → WRITE → READ back → logout, every step the model's
  action and every result asserted from the event, and the target's own record of the login.
- `hex_reads_and_sense_reach_the_model`: CRC32C digests negotiated, a binary block read as hex,
  a medium error and an out-of-range write reported as sense text.
- `chap_and_mutual_chap_with_secrets_the_model_never_sees`: mutual CHAP succeeds; a target
  proving the wrong secret fails the login on the initiator's side; a wrong secret is 0x0201.
- `a_refused_login_injected_actions_and_the_chain_bound`: 0x0203 reported, the chain stops at
  `MAX_FOLLOWUP_DEPTH`, an operator's injected `iscsi_read` runs on the session.
- `a_model_that_cannot_answer_sends_nothing`: no handler, unreachable model → no login.

## `real_server_test.rs` — independent targets

- **gotgt 0.2.2** (`go install github.com/gostor/gotgt@v0.2.2`; `NETGET_GOTGT` names the
  binary when it is not on PATH or in `~/go/bin`), unprivileged, with a test-owned `HOME`
  holding its `config.json`: the model's session logs in, lists LUN 0, reads the backing file's
  first sector and writes block 100, which the test reads back from the file. gotgt has no
  discovery session (it closes a login without a TargetName unanswered), so this session logs
  straight in; it also finishes logins with TSIH 0, which the initiator reports.
- **tgtd** (Ubuntu `tgt`, Linux, as root in the `iscsi` pair job): `tgtd -f` on its own control
  port, a target with the backing file as LUN 1, CHAP and outgoing (mutual) accounts bound;
  discovery, login with CHAP + mutual CHAP + CRC32C, the same session against LUN 1 (LUN 0 is
  tgt's controller), the write found in the file, and a wrong secret refused with 0x0201.

Both fail, never skip, when their target is missing.
