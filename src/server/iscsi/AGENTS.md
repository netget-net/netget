# iSCSI target — Experimental

RFC 7143 iSCSI over TCP (well-known port 3260, unprivileged). Rust owns the wire; the model
owns three decisions: which targets discovery reveals (`iscsi_discovery` →
`iscsi_send_targets`), whether a login is admitted and what the target's LUNs contain
(`iscsi_login` → `iscsi_accept_login` / `iscsi_reject_login`). Every SCSI command is then
answered from that description without another model call.

| File | What it does |
|---|---|
| `pdu.rs` | BHS/AHS/data framing, padding, CRC32C digests (sent least significant byte first, as Linux, libiscsi and tgt do), `read_pdu` (async, bounded before allocation) and `decode` (the same over a buffer, for the fuzz target), opcodes, reject reasons, login status codes, serial-number comparison |
| `text.rs` | `key=value\0` parsing with bounds, the operational parameters, both roles' negotiation of every key |
| `chap.rs` | CHAP MD5, binary values in `0x` hex or `0b` base64, constant-time compare |
| `lun.rs` | `TargetDescription` from the model's answer; the session's write overlay |
| `mod.rs` | accept loop, login state machine, full feature phase, SCSI dispatch |
| `actions.rs` | events, actions, startup parameters, metadata |

The SCSI command set is `src/server/scsi_common.rs` (shared with the USB mass-storage device
and the initiator) and the disk model is `src/server/described_disk.rs` (shared with NBD).

## Login

Security stage then operational stage (or straight from security to full feature phase, which
libiscsi does in one round trip). Rust checks: version 0, InitiatorName present and an iSCSI
name, TargetName for a normal session, keys not repeated, at most 128 keys / 64 KiB of text
across C-bit continuations / 63-byte names / 8192-byte values, 64 login PDUs, 60 s for the
whole login. A login carrying a TSIH is taken as reinstatement: nothing of the old connection
survives at error recovery level 0, so it starts afresh under that TSIH (libiscsi reconnects
this way).

**CHAP.** With `chap_accounts` configured, every session (discovery included) must do CHAP MD5:
AuthMethod=CHAP, CHAP_A=5, our 16-byte challenge, the initiator's CHAP_N/CHAP_R checked against
every account (no early exit). Mutual CHAP is answered with `target_chap_name` /
`target_chap_secret`; a reflected challenge is refused. Any failure is status 0x0201 and the
model is never asked. Secrets are 12–255 bytes and appear in no event.

**The model.** For a normal session it is asked once, after authentication, when the initiator
asks to leave the security stage. Fail closed:

| Outcome | Login status | `decision=` |
|---|---|---|
| accepted, valid description | 0x0000 | `model_answer` |
| `iscsi_reject_login` not_found / unauthorized | 0x0203 / 0x0202 | `model_reject` |
| no answer | 0x0300 | `model_silent` |
| invalid answer (bad size, unknown field…) | 0x0300 | `fail_closed_invalid_reply` |
| backend failed / saturated | 0x0300 / 0x0301 | `fail_closed_llm_error` |

A refused login is answered once and closed; no LUN exists without an accepted description.
Discovery that fails lists no targets.

Negotiation: digests per the `digests` parameter (either / crc32c / none; the initiator's first
supported choice), InitialR2T OR'd with the `initial_r2t` parameter (default Yes, as LIO and tgt
declare), ImmediateData as the initiator says, MaxBurstLength ≤ 256 KiB, FirstBurstLength
≤ 64 KiB and ≤ MaxBurstLength, MaxRecvDataSegmentLength declared as 256 KiB (8 KiB until
declared), ErrorRecoveryLevel 0, MaxConnections 1, MaxOutstandingR2T 1, markers No, unknown keys
NotUnderstood. TargetPortalGroupTag in the first response, TargetAlias in the final one.

## Full feature phase

- **Sequence numbers.** A non-immediate command must carry ExpCmdSN; anything else is dropped
  silently (`decision=protocol_refusal`). MaxCmdSN = ExpCmdSN + 31 − writes waiting for data.
  Every status-bearing PDU consumes a StatSN; R2T and non-final Data-In carry it without.
- **Data-In** in PDUs ≤ the initiator's MaxRecvDataSegmentLength, sequences ≤ MaxBurstLength,
  GOOD collapsed into the last PDU, overflow/underflow residuals.
- **Writes.** Immediate data (≤ FirstBurstLength), unsolicited Data-Out (InitialR2T=No, ≤
  FirstBurstLength), then R2Ts of ≤ MaxBurstLength one at a time. DataSN, buffer offset and TTT
  are checked; a violation is Reject (protocol error) and the connection ends (ERL 0). An EDTL
  that disagrees with the CDB is CHECK CONDITION / INVALID FIELD IN INFORMATION UNIT with the
  residual named (what LIO does; libiscsi's residual tests accept it). Data-Out for a task that
  no longer exists is discarded.
- **Write handling (the storage question).** A LUN the model marks `writable` takes writes into
  an overlay owned by the connection: read back by that session, discarded when it ends, bounded
  at 64 MiB (then DATA PROTECT / SPACE ALLOCATION FAILED). Nothing touches a file and nothing
  outlives the session — it is the state a disk holds between a WRITE and the next READ while
  the initiator is attached, not storage the protocol keeps. A LUN not marked writable answers
  DATA PROTECT / WRITE PROTECTED. Error regions fail reads (UNRECOVERED READ ERROR) and writes
  (WRITE ERROR) with the first failing LBA in INFORMATION.
- **SCSI:** INQUIRY (standard, 96 bytes with SAM-5/iSCSI/SPC-4/SBC-3 version descriptors; VPD
  0x00, 0x80, 0x83 with NAA-6, T10 and SCSI name string designators, 0xB0, 0xB1; qualifier 3 for
  an absent LUN), READ CAPACITY(10)/(16), READ/WRITE 6/10/12/16 (RDPROTECT/WRPROTECT refused,
  DPO/FUA accepted and advertised), TEST UNIT READY, REQUEST SENSE, MODE SENSE(6)/(10) (caching
  and control pages, WP and DPOFUA bits), REPORT LUNS, SYNCHRONIZE CACHE(10)/(16), START STOP
  UNIT, PREVENT ALLOW MEDIUM REMOVAL. Anything else is INVALID COMMAND OPERATION CODE, which is
  what makes iscsi-test-cu skip the tests for it.
- **Task management:** ABORT TASK (a pending write → complete; a command not yet received but
  in the window → complete, and it is dropped when it arrives; an answered one → task does not
  exist), ABORT/CLEAR TASK SET and LUN RESET (pending writes of the LUN), TARGET WARM RESET,
  TARGET COLD RESET (answers, then closes), CLEAR ACA → not supported, TASK REASSIGN → not
  supported at ERL 0.
- **Text:** SendTargets only — All (the model's list in a discovery session, this session's
  target in a normal one), a target name, or empty; anything else is Reject (as LIO does).
  Answers longer than the initiator's MaxRecvDataSegmentLength continue with C bit and TTT.
- NOP-Out pings are echoed; Logout answers and closes (reason 2, recovery, is refused);
  SNACK is Reject at ERL 0; a data segment over MaxRecvDataSegmentLength or a bad header digest
  closes the connection; a bad data digest is Reject (data digest error) and the session goes
  on; a discovery session's SCSI command is Reject (command not supported).

## Not implemented

Error recovery levels 1–2, multiple connections per session, SNACK, ACA, persistent
reservations, protection information, UNMAP / WRITE SAME / COMPARE AND WRITE / VERIFY / WRITE
AND VERIFY / REPORT SUPPORTED OPERATION CODES, asynchronous messages, iSER, TLS. A session's
writes do not survive it (by design, above).

## Maturity

Experimental. libiscsi (one family) passes; the open-iscsi kernel initiator is the second family
and runs only as root in the `iscsi` pair job, which had not run in CI when this landed. The
fuzz target is `fuzz/fuzz_targets/iscsi_pdu.rs`. See `tests/server/iscsi/AGENTS.md` for the
evidence and the one iscsi-test-cu failure.
