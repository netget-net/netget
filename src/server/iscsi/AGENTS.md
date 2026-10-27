# iSCSI target — Experimental

RFC 7143 iSCSI over TCP (well-known port 3260, unprivileged). Rust owns the wire; the model
owns four decisions: which targets discovery reveals (`iscsi_discovery` →
`iscsi_send_targets`), whether a login is admitted and what the target's LUNs contain
(`iscsi_login` → `iscsi_accept_login` / `iscsi_reject_login`), and whether a reset may go
ahead (`iscsi_task_management` → `iscsi_allow_reset` / `iscsi_refuse_reset`). Every SCSI command
is then answered from the description without another model call.

| File | What it does |
|---|---|
| `pdu.rs` | BHS/AHS/data framing, padding, CRC32C digests (sent least significant byte first, as Linux, libiscsi and tgt do), `read_pdu` and `PduReader` (bounded before allocation; `PduReader::next` keeps partial PDUs between calls, so a `select!` can drop it without losing bytes), `decode` (the same over a buffer, for the fuzz target), opcodes, reject reasons, login status codes, TMF functions and responses, SNACK types and runs, logout reasons, serial-number comparison |
| `text.rs` | `key=value\0` parsing with bounds, the operational parameters, both roles' negotiation of every key, the leading-only keys |
| `chap.rs` | CHAP MD5, binary values in `0x` hex or `0b` base64, constant-time compare |
| `lun.rs` | `TargetDescription` from the model's answer; the session's write overlay |
| `session.rs` | what a session's connections share: the CmdSN window (`CommandWindow`), the in-order queue, tasks, unit attentions, task management fences, retention; the registry of sessions by TSIH |
| `mod.rs` | configuration, the accept loop and janitor, a connection's state, login, establishing or joining a session |
| `ffp.rs` | the full feature phase loop, CmdSN admission and in-order execution, NOP, Text, Logout, Reject |
| `scsi.rs` | SCSI dispatch, unit attentions, Data-In (kept at error recovery level ≥ 1), writes and their data, recovery R2T |
| `tmf.rs` | every task management function, the model's reset decision, TASK REASSIGN |
| `recovery.rs` | SNACK: Data/R2T, Status, DataACK, R-Data |
| `actions.rs` | events, actions, startup parameters, metadata |

The SCSI command set is `src/server/scsi_common.rs` (shared with the USB mass-storage device
and the initiator) and the disk model is `src/server/described_disk.rs` (shared with NBD).

## Sessions and connections

Each TCP connection runs in its own task. What a session's connections share lives in a
`session::Session` behind a `std::sync::Mutex` that is never held across an `.await`: a
connection locks it, changes it, builds the PDUs it owes its own peer, unlocks, then writes.
Another connection with work waiting is woken through its `Notify`; one that must stop (cold
reset, session logout, a reinstatement, a logout naming its CID) through its
`CancellationToken`. A janitor task (`JANITOR_TICK`, 1 s) ends retained sessions and tasks when
their retention runs out. Lock order is registry, then session, never the other way.

**MaxConnections** (`max_connections`, 1–8, default 4) is negotiated with the minimum function,
so libiscsi and open-iscsi (which offer 1) get 1. A login naming a session's TSIH joins it:
same InitiatorName, ISID and TargetName, the same CHAP user when CHAP is configured, and room
under MaxConnections (else 0x0206); the model is not asked again, and the leading-only keys are
answered with the session's values. A login naming a CID the session already has replaces that
connection (connection reinstatement: at error recovery level 2 its tasks wait for
reassignment, otherwise they end). A login with TSIH 0 from a nexus that already has a session
replaces the session (session reinstatement: its connections close, its tasks end). A TSIH this
target does not know is served as a new session under that TSIH (as before sessions existed).
At most 256 normal sessions (0x0302 past that).

**Command order.** A non-immediate command at ExpCmdSN joins the session's in-order queue; one
ahead of it inside the window is held until the gap fills; anything else is dropped
(`decision=protocol_refusal`). Only the connection a queued command came on runs it, and only
from the front, so CmdSN N on one connection runs before N+1 on another whichever arrived
first. Immediate commands run at once. MaxCmdSN = ExpCmdSN + 31 − writes waiting for data.

**Logout.** Reason 0 ends the session (every connection closes). Reason 1 closes the named CID —
this connection, or another of the session (closed from here) — and its tasks end, with
47h/7Fh (SOME COMMANDS CLEARED BY ISCSI PROTOCOL EVENT) on the remaining connections' next
command (RFC 7143 §11.14.5). Reason 2 (remove for recovery) is "not supported" below error
recovery level 2; at level 2 the CID's tasks become reassignable and the response carries
Time2Wait and what is left of Time2Retain. An unknown CID is response 1. The target answers,
then waits up to `LOGOUT_LINGER` (5 s) for the initiator to close before closing itself
(closing first made libiscsi log in again).

## Login

Security stage then operational stage (or straight from security to full feature phase, which
libiscsi does in one round trip). Rust checks: version 0, InitiatorName present and an iSCSI
name, TargetName for a normal session, keys not repeated, at most 128 keys / 64 KiB of text
across C-bit continuations / 63-byte names / 8192-byte values, 64 login PDUs, 60 s for the
whole login.

**CHAP.** With `chap_accounts` configured, every session (discovery included) and every
connection of a session must do CHAP MD5: AuthMethod=CHAP, CHAP_A=5, our 16-byte challenge, the
initiator's CHAP_N/CHAP_R checked against every account (no early exit). Mutual CHAP is answered
with `target_chap_name` / `target_chap_secret`; a reflected challenge is refused. Any failure is
status 0x0201 and the model is never asked. Secrets are 12–255 bytes and appear in no event.

**The model** is asked once per session, after authentication, when the leading login asks to
leave the security stage. Fail closed:

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
declared), ErrorRecoveryLevel the minimum of the initiator's and `error_recovery_level` (default
2; discovery sessions 0), MaxConnections as above, DefaultTime2Wait the maximum of the
initiator's and 2, DefaultTime2Retain the minimum of the initiator's and 20, MaxOutstandingR2T
1, markers No, unknown keys NotUnderstood. TargetPortalGroupTag in the first response,
TargetAlias in the final one.

## Full feature phase

- **Data-In** in PDUs ≤ the initiator's MaxRecvDataSegmentLength, sequences ≤ MaxBurstLength,
  GOOD collapsed into the last PDU, overflow/underflow residuals.
- **Writes.** Immediate data (≤ FirstBurstLength), unsolicited Data-Out (InitialR2T=No, ≤
  FirstBurstLength), then R2Ts of ≤ MaxBurstLength one at a time, each for the first range not
  yet received. A write's data is kept as received ranges (`session::Coverage`, at most 64
  pieces) and grown as it arrives, never allocated ahead. At error recovery level 0 the DataSN,
  buffer offset and TTT must be exactly the next expected; a violation ends its task with CHECK
  CONDITION (ABORTED COMMAND: DATA PHASE ERROR, or UNEXPECTED UNSOLICITED DATA), nothing
  written, and the connection goes on. Both louder answers hung libiscsi's iSCSIDataSnInvalid on
  Linux: closing the connection made it reconnect with its next WRITE queued ahead of its Login
  and wait forever, and a Reject for the Data-Out made it reset the connection itself, with the
  same result. A connection whose first PDU is not a Login Request is closed unanswered, as LIO
  does. An EDTL that disagrees with the CDB is CHECK CONDITION / INVALID FIELD IN INFORMATION
  UNIT with the residual named. Data-Out for a task that no longer exists, or on a connection the
  task is not allegiant to, is discarded. A new command under the ITT of a write still in
  progress is Reject (task in progress).
- **Write handling (the storage question).** A LUN the model marks `writable` takes writes into
  an overlay owned by the session: read back by every connection of that session, discarded
  when it ends, bounded at 64 MiB (then DATA PROTECT / SPACE ALLOCATION FAILED). Nothing touches
  a file and nothing outlives the session — it is the state a disk holds between a WRITE and the
  next READ while the initiator is attached, not storage the protocol keeps. Two sessions of one
  target do not see each other's writes (which is why libiscsi's `SCSI.MultipathIO.Simple`, a
  write on one path read back on the other, fails). A LUN not marked writable answers DATA
  PROTECT / WRITE PROTECTED. Error regions fail reads (UNRECOVERED READ ERROR) and writes (WRITE
  ERROR) with the first failing LBA in INFORMATION.
- **SCSI:** INQUIRY (standard, 96 bytes with SAM-5/iSCSI/SPC-4/SBC-3 version descriptors; VPD
  0x00, 0x80, 0x83 with NAA-6, T10 and SCSI name string designators, 0xB0, 0xB1; qualifier 3 for
  an absent LUN), READ CAPACITY(10)/(16), READ/WRITE 6/10/12/16 (RDPROTECT/WRPROTECT refused,
  DPO/FUA accepted and advertised), TEST UNIT READY, REQUEST SENSE, MODE SENSE(6)/(10) (caching
  and control pages, WP and DPOFUA bits), REPORT LUNS, SYNCHRONIZE CACHE(10)/(16), START STOP
  UNIT, PREVENT ALLOW MEDIUM REMOVAL. Anything else is INVALID COMMAND OPERATION CODE, which is
  what makes iscsi-test-cu skip the tests for it. A command with NACA set is INVALID FIELD IN
  CDB: there is no ACA (NormACA 0).
- **Unit attentions** are kept per LUN of each session (at most 8, deduplicated) and reported on
  the next command to that LUN, which does not run; INQUIRY and REPORT LUNS never report one,
  and REQUEST SENSE returns it as its sense data. Those owed to a nexus whose session ended (a
  cold reset) wait, at most 10 minutes and 1024 nexuses, for its next login.
- **Text:** SendTargets only — All (the model's list in a discovery session, this session's
  target in a normal one), a target name, or empty; anything else is Reject (as LIO does).
  Answers longer than the initiator's MaxRecvDataSegmentLength continue with C bit and TTT.
- NOP-Out pings are echoed; a data segment over MaxRecvDataSegmentLength or a bad header digest
  closes the connection; a bad data digest is Reject (data digest error) and the PDU is not
  taken (a command so rejected is not counted as received: the initiator sends it again); a
  discovery session's SCSI command is Reject (command not supported).

## Task management

| Function | What it does | Response |
|---|---|---|
| ABORT TASK (1) | a write waiting for data, or a command queued and not run, ends; a CmdSN in the window not yet received is taken as received and dropped when it comes; an ABORT TASK of itself is refused | 0, 1 (answered or never seen), 255 |
| ABORT TASK SET (2) | this session's tasks for the LUN, and its commands below the TMF's CmdSN still to come | 0 / 2 |
| CLEAR ACA (3) | there is no ACA | 5 / 2 |
| CLEAR TASK SET (4) | every session's tasks for the LUN (TST 0: one task set per LU); the other nexuses that lost tasks get 2Fh/00h | 0 / 2 |
| LOGICAL UNIT RESET (5) | the model decides; every session's tasks for the LUN; 29h/03h on every nexus | 0 / 2 / the model's refusal / 255 |
| TARGET WARM RESET (6) | the model decides; every session's tasks on the target; the CmdSN space below the TMF plugged (§4.2.3.3 b); 29h/00h on every LUN of every nexus | 0 / the model's refusal / 255 |
| TARGET COLD RESET (7) | the model decides; answered, then every session of the target ends (a power-on event, §11.5.1); 29h/01h owed to each nexus's next login | 0 / the model's refusal / 255 |
| TASK REASSIGN (8) | level 2 only: a task of a connection logged out for recovery (or reinstated) continues here — the response first, then read data from ExpDataSN and the status again, or an R2T for what a write lacks | 0, 1, 3 (still allegiant: its connection is up, or failed without a recovery logout), 4 (below level 2), 255 (retransmission bound spent) |
| 9–12 (RFC 7144 queries, I_T NEXUS RESET) | not implemented | 5 |
| anything else | | 255 |

ABORT TASK SET, CLEAR TASK SET and the two resets wait, before answering, for the data the
issuing session still owes on writes they ended (RFC 7143 §4.2.3.3 a): the write is kept,
marked aborted, its Data-Out taken and discarded until the sequence ends, then the response
goes (a "fence", at most `FENCE_WAIT`, 30 s). Third-party sessions' transfers are not waited
for. The model's reset decision fails closed:

| Outcome | Response | `decision=` |
|---|---|---|
| `iscsi_allow_reset` | 0 | `model_answer` |
| `iscsi_refuse_reset` rejected / not_supported / unauthorized | 255 / 5 / 6 | `model_reject` |
| no answer | 255 | `model_silent` |
| invalid answer | 255 | `fail_closed_invalid_reply` |
| backend failed | 255 | `fail_closed_llm_error` |

A refused reset changes nothing: no task ends, no unit attention.

## Error recovery

ErrorRecoveryLevel is the minimum of the initiator's and `error_recovery_level` (default 2).

**Level 0.** As before, plus: a Data-Out with a bad data digest is rejected and its write ends
with CHECK CONDITION (ABORTED COMMAND, PROTOCOL SERVICE CRC ERROR 47h/05h) once its sequence is
over (§7.8 b); SNACK is Reject (protocol error). A connection that ends takes its tasks with it;
the session ends with its last connection.

**Level 1** (digest failure recovery):
- A Data-Out with a bad data digest is rejected and counted as lost; a DataSN or offset ahead
  of the expected one means earlier PDUs were lost (§7.9). What arrives is kept, and once the
  sequence ends a recovery R2T (the next R2TSN, a new TTT) asks for the first missing range.
  Duplicates and data for a superseded R2T are dropped.
- Every status PDU is kept until acknowledged by ExpStatSN (at most 256 and 4 MiB per
  connection). A read's Data-In is kept until its status is acknowledged or a DataACK covers it
  (at most 256 completed tasks and 64 MiB of read data per session; past that the oldest go,
  and a SNACK for them is "SNACK reject"). The last Data-In of each burst that does not carry the
  status sets the A bit with a Target Transfer Tag for the DataACK.
- SNACK: Data/R2T (replicas of Data-In by DataSN, or the outstanding R2T by R2TSN), Status
  (replicas by StatSN), DataACK (frees acknowledged data; an unknown tag or a run outside what
  was sent is Reject 0x08), R-Data (the unacknowledged data again, segmented for the
  connection now, then a SCSI Response carrying the SNACK Tag under the status's original
  StatSN). A run naming a PDU not sent or acknowledged is Reject (protocol error). Each task may
  be asked for retransmission 8 times, each status 8 times; past that, Reject (SNACK reject).

**Level 2** (connection recovery): a connection that fails keeps its tasks (Time2Retain > 0)
until a recovery logout (reason 2) or a reinstatement makes them reassignable, then until
Time2Wait + Time2Retain from the failure (at most 120 s, `MAX_TASK_RETENTION`; Time2Wait's
result function is the maximum, so an initiator could name an hour). TASK REASSIGN continues a
task as above. A task nobody reassigns ends when its retention does, with 47h/7Fh on the
session's next command to its LUN (§11.14.5 c). A session whose connections have all failed
lives until the last retention ends. Time2Wait itself is the initiator's to honour; the target
does not refuse an early reassignment.

Immediate commands and commands queued but not run on a connection that fails are not
recovered (§7.14). The target sends no Asynchronous Message when it drops a connection (§7.1.4.3
makes that a SHOULD), no NOP-In pings and no Response Fence (only required when TaskReporting is
negotiated, and it is not).

## Not implemented

ACA, the RFC 7144 functions (QUERY TASK, QUERY TASK SET, I_T NEXUS RESET, QUERY ASYNC EVENT),
TaskReporting/FastAbort, asynchronous messages, persistent reservations, RESERVE/RELEASE,
removable media (PREVENT ALLOW is accepted and does nothing, so libiscsi's PreventAllow reset
tests skip themselves), protection information, UNMAP / WRITE SAME / COMPARE AND WRITE / VERIFY
/ WRITE AND VERIFY / REPORT SUPPORTED OPERATION CODES, MaxOutstandingR2T above 1, out-of-order
data (DataPDUInOrder / DataSequenceInOrder No), iSER, TLS. A session's writes do not survive it
and are not shared with other sessions (by design, above).

**iSER** needs RDMA. Soft-RoCE (`rdma_rxe`) and `ib_isert` load in the podman VM, and tgt and
Ubuntu's libiscsi are built with iSER, but GitHub's ubuntu-24.04 runner kernel (6.17 azure)
ships no `rdma_rxe` (only `siw`), Homebrew's libiscsi has no iSER, and NetGet would need an RDMA
verbs stack (libibverbs/librdmacm) it does not link. Not built.

## Maturity

Experimental. libiscsi passes its tools, the iscsi-test-cu subset and its task management
suites (see `tests/server/iscsi/AGENTS.md`); the open-iscsi kernel initiator (reads and
`sg_reset` LUN and target resets) runs only as root in the pair job. **No independent initiator
drives error recovery levels 1–2 or sessions of several connections**: libiscsi (`lib/login.c`)
and open-iscsi (`usr/login.c`) both hard-code ErrorRecoveryLevel=0 and MaxConnections=1 in their
login offer, neither sends SNACK, DataACK or TASK REASSIGN, and the kernel's iscsi_tcp
advertises only error recovery level 0. That surface rests on NetGet's own raw-PDU tests
(`tests/server/iscsi/recovery_test.rs`). The fuzz target is `fuzz/fuzz_targets/iscsi_pdu.rs`.
