# iSCSI initiator client — Experimental

`initiator.rs` runs sessions (no model); `mod.rs` turns the model's actions into sessions and
commands and raises each result as an event; `actions.rs` holds the vocabulary. The PDU, text
and CHAP code is the target's (`src/server/iscsi/{pdu,text,chap}.rs`) and the SCSI code is
`src/server/scsi_common.rs`.

**Lifecycle.** `connect()` opens nothing: it resolves the portal, registers the command channel
and raises `iscsi_connected`. The model then chooses:

| Action | Wire | Event |
|---|---|---|
| `iscsi_discover` | a separate discovery session: login, SendTargets=All (with continuation), logout | `iscsi_targets` |
| `iscsi_login` | a normal session to `target_name` (or the startup parameter) | `iscsi_login_result` (status class/detail when refused, negotiated parameters when not) |
| `iscsi_report_luns`, `iscsi_inquiry` (standard / supported_pages / serial / device_identification), `iscsi_read_capacity` (10, then 16 past 2 TiB), `iscsi_read`, `iscsi_write`, `iscsi_test_unit_ready` | one SCSI command | `iscsi_command_result` (status, sense as text, the decoded answer) |
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
abandoned. Operational offer: digests per `digests` (either → `None,CRC32C`, crc32c, none),
InitialR2T No, ImmediateData Yes, bursts 256 KiB / 64 KiB, MaxRecvDataSegmentLength 256 KiB,
ERL 0. Values the target answers outside what was offered are refused. A final response
without a TSIH (gotgt 0.2.2 sends 0) is accepted and reported as `tsih: 0`.

**Commands.** Immediate data and unsolicited Data-Out as negotiated, R2Ts answered within the
target's MaxRecvDataSegmentLength, Data-In checked for DataSN and buffer offset order and
never beyond the expected length, residuals recorded, NOP-In pings answered (also while idle,
from the session task's select), Reject reported.

**Fail closed.** A model call that fails sends nothing. A handler chain stops after
`MAX_FOLLOWUP_DEPTH` (16) follow-ups — a whole discover, log in, inspect, read, write, read back
and log out session is nine. CHAP secrets come from startup parameters, are redacted wherever
parameters are shown, and appear in no event.

**Evidence.** `tests/client/iscsi`: NetGet's own target (regression, not evidence), gotgt 0.2.2
(independent Go target, unprivileged) and tgtd (Linux SCSI target framework, root, with CHAP,
mutual CHAP and CRC32C), each read back through the backing file it serves. Experimental: the
tgtd half runs only in the `iscsi` pair job, which had not run in CI when this landed.
