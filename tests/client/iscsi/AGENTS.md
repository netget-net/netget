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
- `task_management_is_the_models_action_and_its_response_comes_back`: every function the
  model may send, in order (`support::tmf_steps`, driven by `stepping_policy`, which keeps its
  place in a file because each event runs the script afresh): ABORT TASK of the last command →
  task does not exist, the task sets and resets → complete, CLEAR ACA → not supported, the
  TEST UNIT READY after the LUN reset reports BUS DEVICE RESET FUNCTION OCCURRED once, the cold
  reset ends the session, and the target's model was asked about exactly the three resets.

## `real_server_test.rs` — independent targets

- **gotgt 0.2.2** (`go install github.com/gostor/gotgt@v0.2.2`; `NETGET_GOTGT` names the
  binary when it is not on PATH or in `~/go/bin`), unprivileged, with a test-owned `HOME`
  holding its `config.json`: the model's session logs in, lists LUN 0, reads the backing file's
  first sector and writes block 100, which the test reads back from the file. gotgt has no
  discovery session (it closes a login without a TargetName unanswered), so this session logs
  straight in; it also finishes logins with TSIH 0, which the initiator reports.
- **tgtd** (Ubuntu `tgt`, Linux, as root in the `iscsi` pair job): `tgtd -f -d 1` on its own
  control port, a target with the backing file as LUN 1, CHAP and outgoing (mutual) accounts
  bound, and the target's HeaderDigest/DataDigest set to CRC32C (tgt's default is None);
  discovery, login with CHAP + mutual CHAP, CRC32C asserted on the normal session (the client
  offers `None,CRC32C`, because tgt negotiates discovery from its global None), the same
  session against LUN 1 (LUN 0 is tgt's controller), the write found in the file, and a wrong
  secret refused with 0x0201. tgtd's debug output goes to a file in the test's temp dir and is
  printed with every failed assertion: tgtd says why it refused a login only there. Its
  `Login request (security negotiation): N` lines name the connection state (`iscsid.h`
  `STATE_*`); a security-stage PDU arriving in state 3 (`STATE_SECURITY_DONE`) is its 0x0200.
- **Task management against both** (`gotgt_answers_the_models_task_management`,
  `tgtd_answers_the_models_task_management`, tgtd on its own control port 18): the same
  `tmf_steps` sequence, asserting each target's own answers as its source has them. gotgt
  (`pkg/port/iscsit/iscsid.go`): ABORT TASK of a finished command → task does not exist, ABORT
  TASK SET and LUN RESET → complete (empty cases: nothing is done), CLEAR ACA, CLEAR TASK SET and
  both target resets → not supported, no unit attention anywhere, the session goes on. tgt
  (`usr/iscsi/iscsid.c` `iscsi_tm_execute`): the same codes, but its LUN RESET really aborts and
  sets POWER ON, RESET, OR BUS DEVICE RESET OCCURRED, which the next TEST UNIT READY reports
  (as the first one after login does).

Both fail, never skip, when their target is missing.
