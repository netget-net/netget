# iSCSI initiator client — Experimental

`initiator.rs` runs sessions (no model); `mod.rs` turns the model's actions into sessions and
commands and raises each result as an event; `actions.rs` holds the vocabulary. The PDU, text
and CHAP code is the target's (`src/server/iscsi/pdu.rs`, `src/server/iscsi/text.rs`,
`src/server/iscsi/chap.rs`) and the SCSI code is
`src/server/scsi_common.rs`.

**Lifecycle.** `connect()` opens nothing: it resolves the portal, registers the command channel
and raises `iscsi_connected`. The model then chooses:

| Action | Wire | Event |
|---|---|---|
| `iscsi_discover` | a separate discovery session: login, SendTargets=All (with continuation), logout | `iscsi_targets` |
| `iscsi_login` | a normal session to `target_name` (or the startup parameter) | `iscsi_login_result` (status class/detail when refused, negotiated parameters when not) |
| `iscsi_report_luns`, `iscsi_inquiry` (standard / supported_pages / serial / device_identification), `iscsi_read_capacity` (10, then 16 past 2 TiB), `iscsi_read`, `iscsi_write`, `iscsi_test_unit_ready` | one SCSI command | `iscsi_command_result` (status, sense as text, the decoded answer) |
| `iscsi_task_management` | a Task Management Function Request, immediate: `abort_task` (the last command sent, or `referenced_task_tag`), `abort_task_set`, `clear_task_set`, `clear_aca`, `logical_unit_reset` (for `lun`), `target_warm_reset`, `target_cold_reset` | `iscsi_task_management_result` (response by name and code; `session_ended` after a completed cold reset, whose target closes the session) |
| `iscsi_logout` | Logout Request | `iscsi_logged_out` |
| `disconnect` | logout if logged in, stop | — |

One normal session at a time; a second `iscsi_login` is refused until `iscsi_logout`. A
session the target closes raises `iscsi_logged_out` with the reason. A transport or protocol
error inside a command ends the session (error recovery level 0) and the result says so.

**Encodings.** Reads and writes move at most 8 KiB. Read data is shown as `utf8` when it is text
(no escapes, no controls but `\n`/`\t`; trailing zero bytes counted in `trailing_zero_bytes`,
not shown) and as `hex` otherwise or when asked; writes take `encoding` `utf8` (default) or `hex`
and are zero-padded to whole blocks, whose size comes from READ CAPACITY (asked once per LUN).

**Login.** InitiatorName (default `iqn.2026-10.net.netget:initiator`), AuthMethod CHAP,None when
`chap_name`/`chap_secret` are set; CHAP MD5; with `target_chap_secret` (and optionally
`target_chap_name`) the target is challenged back and must prove the secret, or the login is
abandoned. The PDU carrying CHAP_N/CHAP_R (and our CHAP_I/CHAP_C) also asks to transit to the
operational stage, as RFC 7143's own example does: tgt considers the security stage over once
CHAP_R verifies and answers any later security-stage PDU with 0x0200 (initiator error), so an
empty "now let me move on" PDU is refused there. The target's CHAP_R rides on its transit
response and is checked before the operational stage starts; a response without it ends the
login. Operational offer: digests per `digests` (either → `None,CRC32C`, crc32c, none),
InitialR2T No, ImmediateData Yes, bursts 256 KiB / 64 KiB, MaxRecvDataSegmentLength 256 KiB,
ERL 0. A digest answer outside what was offered is refused (tgt answers its own default, None,
to an offer of CRC32C alone — taking it would drop the digests the operator asked for); the
other keys are bounded by `apply_as_initiator`. A final response
without a TSIH (gotgt 0.2.2 sends 0) is accepted and reported as `tsih: 0`.

**Commands.** Immediate data and unsolicited Data-Out as negotiated, R2Ts answered within the
target's MaxRecvDataSegmentLength, Data-In checked for DataSN and buffer offset order and
never beyond the expected length, residuals recorded, NOP-In pings answered (also while idle,
from the session task's select), Reject reported.

**Fail closed.** A model call that fails sends nothing. A handler chain stops after
`MAX_FOLLOWUP_DEPTH` (16) follow-ups — a whole discover, log in, inspect, read, write, read back
and log out session is nine. CHAP secrets come from startup parameters, are redacted wherever
parameters are shown, and appear in no event.

**Task management.** Every function but TASK REASSIGN is the model's to send. A target's unit
attention after a reset reaches the model as the next command's sense ("POWER ON, RESET, OR BUS
DEVICE RESET OCCURRED" from tgt, "BUS DEVICE RESET FUNCTION OCCURRED" from NetGet's target). A
transport failure during the function ends the session.

**Not built: error recovery levels 1–2 and multiple connections per session.** The initiator
offers ErrorRecoveryLevel=0 and MaxConnections=1. Neither independent target could exercise
more: tgt (1.0.85) advertises ErrorRecoveryLevel=2 and MaxConnections=2 when configured with
tgtadm but implements no SNACK (it closes the connection on one), no connection recovery and no
TASK REASSIGN, and never enforces MaxConnections; gotgt 0.2.2 answers ErrorRecoveryLevel=0 and
MaxConnections=1 whatever is offered and finishes every login with TSIH 0, so no second
connection can name the session. Building recovery against NetGet's own target alone would be
circular.

**Evidence.** `tests/client/iscsi`: NetGet's own target (regression, not evidence), gotgt 0.2.2
(independent Go target, unprivileged) and tgtd (Linux SCSI target framework, root, with CHAP,
mutual CHAP and CRC32C), each read back through the backing file it serves, and each answering
every task management function (gotgt: ABORT TASK SET and LUN RESET "complete" without acting,
the rest "not supported", no unit attentions; tgt: CLEAR TASK SET and both target resets "not
supported", 29h/00h after login and after LUN RESET). Experimental: the tgtd half runs only in
the `iscsi` pair job.
