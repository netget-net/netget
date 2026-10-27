# iSCSI target tests

No LLM anywhere: `support::POLICY` (and `real_client_test::REAL_POLICY`) is a python script
handler playing the model, and the LLM endpoint is unreachable, so an event the policy does not
cover exercises the fail-closed path. LLM calls: zero.

## `e2e_test.rs` — a raw initiator from RFC 7143's offsets

`support::Raw` writes every PDU from literal offsets (not NetGet's encoder), computes CRC32C bit
by bit from the Castagnoli polynomial, checks the target's digests on everything it reads, and
keeps every byte for the pcap oracle (tshark's `iscsi` and `scsi` dissectors, port 3260 because
iSCSI is reached through its `iscsi.target_ports` preference, not a decode-as entry).

| Test | What it pins |
|---|---|
| `discovery_lists_the_models_targets_and_tshark_reads_the_session` | SendTargets=All answered from the model, default portal, Reject for SCSI in discovery, logout; tshark reads SendTargets and both TargetNames |
| `a_normal_session_serves_the_described_luns` | REPORT LUNS, INQUIRY + VPD 0x00/0x80/0x83, absent LUN, READ CAPACITY 10/16, reads of text/fill/hex, Data-In split under MaxRecvDataSegmentLength, medium error with INFORMATION, LBA out of range, write + read back, write-protected LUN, unsolicited Data-Out, MODE SENSE WP, NOP echo, one model call for the whole session; tshark reads the INQUIRY product id |
| `r2t_solicits_write_data_in_bursts` | R2Ts within MaxBurstLength, R2TSN and DataSN order; a skipped offset and a wrong DataSN → CHECK CONDITION (DATA PHASE ERROR) for that task, nothing written, the session goes on |
| `chap_is_checked_in_rust_before_the_model_is_asked` | wrong secret and wrong name → 0x0201 with no model call; mutual CHAP response verified; no secret in any event; CHAP required but not offered → 0x0201 |
| `logins_fail_closed_and_expose_nothing_the_model_did_not_describe` | backend down, silent, invalid → 0x0300; not_found → 0x0203; unauthorized → 0x0202; every refusal closes |
| `bounds_refuse_before_anything_is_buffered_or_asked` | login segment over 8 KiB closed unread; 129 keys, duplicate key, bad version refused; FFP segment over 256 KiB closed; immediate data over FirstBurstLength → Reject |
| `commands_out_of_cmdsn_order_are_dropped` | 32-command window; a command ahead of a gap is held (never run while the gap stays), a replayed CmdSN is dropped |
| `crc32c_digests_are_negotiated_and_checked` | digests both ways, bad data digest → Reject 0x02 and the session continues, bad header digest → close, crc32c-only target rejects None |
| `abort_task_ends_a_write_waiting_for_its_data` | ABORT TASK of a write awaiting R2T data; its late data ignored; unknown task → 1 |

## `recovery_test.rs` — task management, sessions of several connections, error recovery

The same raw initiator, now with an ISID, TSIH and CID of its own (`Raw::join` opens another
connection of a session) and TMF, SNACK and Logout-by-CID helpers. **No independent initiator
drives any of this** (libiscsi and open-iscsi hard-code ErrorRecoveryLevel=0 and
MaxConnections=1, and neither sends SNACK, DataACK or TASK REASSIGN), so these tests are the
whole evidence for it; tshark (4.2 and 4.6: `iscsi.taskmanfun.*`, `iscsi.snack.type`,
`iscsi.tsih`, `iscsi.cid`) reads the PDUs.

| Test | What it pins |
|---|---|
| `resets_are_the_models_decision_and_leave_a_unit_attention_on_every_nexus` | two nexuses; LUN RESET asks the model (function, LUN, 1 outstanding task, 2 sessions), ends the other session's write (its data then belongs to no task), 29h/03h once on each nexus, LUN 1 untouched; WARM RESET → 29h/00h on every LUN of both, REQUEST SENSE returns and clears it; the model's refusal (6), its silence and an invalid answer (255) change nothing; COLD RESET answers, closes both sessions, and 29h/01h waits for the nexus's next login (a new nexus owes nothing) |
| `a_reset_the_model_cannot_answer_fails_closed` | backend unreachable → 255 for LUN and cold reset, no unit attention, the write they would have ended still completes |
| `task_sets_wait_for_the_data_they_end_and_unsupported_functions_are_refused` | ABORT TASK SET with an R2T outstanding answers only after the R2T's data, the write is not answered; CLEAR TASK SET ends another session's write and leaves it 2Fh/00h; CLEAR ACA 5, unknown LUN 2, TASK REASSIGN at level 0 → 4, QUERY TASK 5, function 13 → 255; NACA → INVALID FIELD IN CDB |
| `a_session_of_two_connections_runs_commands_in_cmdsn_order_across_them` | MaxConnections the minimum (2 of 8); a second connection joins by TSIH without a model call, leading-only keys answered with the session's; a third → 0x0206; CmdSN N+1 (a READ) on one connection held until N (a WRITE of the block) runs on the other, then reads the written data; beyond the window dropped; logout of the other CID closes it; unknown CID → 1; recovery logout at level 0 → 2; session reinstatement closes the old session |
| `error_recovery_level_1_recovers_lost_data_and_answers_every_snack` | a Data-Out with a bad digest → Reject, then a recovery R2T (R2TSN 1, a new TTT) for exactly its range, the write completes; a read of 4 PDUs with the A bit at the burst's end; Data SNACK replicas, Status SNACK replica under the original StatSN, a never-sent StatSN and an unknown type → protocol error, DataACK then a SNACK for acknowledged data → protocol error, an unknown DataACK tag → 0x08, R-Data SNACK (data from the DataACK, then a SCSI Response with the SNACK Tag and the original StatSN), the 8-retransmission bound → SNACK reject, nothing kept once the status is acknowledged; at level 0 a bad Data-Out digest ends the write with 0Bh/47h/05h and SNACK is refused |
| `error_recovery_level_2_reassigns_a_failed_connections_tasks` | a read whose connection dies after one Data-In: TASK REASSIGN before the recovery logout → 3, the logout's Time2Wait/Time2Retain, then TASK REASSIGN with ExpDataSN 1 → the response, DataSN 1–3 and the status; a write whose connection died with an R2T outstanding continues with a new R2T on the new connection and reads back; a task nobody reassigns ends after Time2Wait + Time2Retain with 47h/7Fh, after which TASK REASSIGN → 1; connection reinstatement closes the replaced connection |

## `real_client_test.rs` — independent initiators

**libiscsi 1.20.3** (Homebrew `libiscsi`, Ubuntu `libiscsi-bin`), unprivileged: `iscsi-ls -s`
(discovery, login to every target, LUN listing), `iscsi-inq` (standard and VPD 0x80/0x83),
`iscsi-readcapacity16`, `iscsi-md5sum` (a read across the error region must fail), CHAP
through the URL's `user%secret` with a wrong secret refused and exactly one login reaching the
model, and **iscsi-test-cu** `--dataloss` over `TEST_CU_SUBSET`.

**iscsi-md5sum's digest is compared with MD5 only on Linux.** Homebrew's libiscsi 1.20.3 bottle
(arm64) prints digests that are not MD5 at all — `75733c3b…` for 512 zero bytes, where MD5 is
`bf619eac…` — while a loopback capture of the same session shows the target sending exactly the
described bytes (measured 19 October 2026). On macOS the test compares libiscsi's digests with
each other instead (the same range twice agrees, two zero ranges agree, ranges whose described
bytes differ do not); on Linux, against the source build of `scripts/test-peers/build-libiscsi.sh`,
the digests of LUN 0's first 64 KiB and all of LUN 1 must equal the MD5 of the description.

**The CHAP test found a real defect.** The target closed its end straight after the Logout
Response; libiscsi saw the hang-up before it had finished with the response, took it for a
dropped connection, and logged in again — so the model was asked twice. The target now waits
(up to `LOGOUT_LINGER`, 5 s) for the initiator to close, as RFC 7143 §11.15 has the initiator
do.

iscsi-test-cu census (every SCSI and iSCSI suite, measured 19 October 2026 on macOS): 224
tests, all pass but one. About 145 of the passes are the suite skipping itself because the
target answers INVALID COMMAND OPERATION CODE (persistent reservations, COMPARE AND WRITE,
EXTENDED COPY, GET LBA STATUS, ORWRITE, PREFETCH, READ DEFECT DATA, RECEIVE COPY RESULTS,
REPORT SUPPORTED OPCODES, RESERVE(6), SANITIZE, UNMAP, VERIFY, WRITE ATOMIC, WRITE SAME, WRITE
AND VERIFY, REPORT TARGET PORT GROUPS) or the LUN is not removable / not write-protected. The
~65 that exercise the target are the subset's suites.

**Task management (`iscsi_test_cu_task_management_and_unit_attentions`).** `TEST_CU_TMF` runs
`iSCSI.iSCSITMF.AbortTaskSimpleAsync`, `LUNResetSimpleAsync`, `LogoutDuringIOAsync` and
`SCSI.MultipathIO.Reset` (two URLs: two I_T nexuses, as `-i`/`-I` initiator names), and checks
the model decided at least three LUN resets. MultipathIO.Reset resets LUN 0 on each path in turn
and requires a unit attention on *every* path afterwards — the per-nexus unit attention of
SAM-5 §6.3.3. The two async tests each fail one assertion that is about libiscsi, not the
target: `test_async_*.c:132`, `iscsi_out_queue_length(…) == 1` right after queuing the WRITE.
With `-V` the run shows "dispatching out queue… dispatched" with no service call between:
libiscsi has already sent the WRITE, so the queue is empty — Homebrew's bottle on macOS and the
source build of `build-libiscsi.sh` on Linux (ubuntu:24.04, measured 26 October 2026) alike.
Every assertion about what
the target answered passes (the WRITE completes GOOD and the ABORT TASK is answered "task does
not exist", one of its two accepted outcomes; the LUN RESET completes). The test accepts that
one assertion and nothing else (`only_libiscsi_queue_assert`). libiscsi's other reset tests
(`PreventAllow.*Reset`, `Reserve6.*Reset`, `Sanitize.Reset`) skip themselves: the LUN is not
removable and RESERVE(6) and SANITIZE are not implemented. `SCSI.MultipathIO.Simple` fails
by design: a session's writes are its own, so a write on one path does not read back on the
other.

**open-iscsi** (Linux, as root, the `iscsi` pair job): `iscsiadm` discovery and login, then
the first 8 KiB of LUN 0 read through `/dev/disk/by-path/ip-127.0.0.1:<port>-iscsi-<iqn>-lun-0`
after `udevadm settle`, retried until a read succeeds (the node can exist while the kernel is
still probing the disk, and opening it then fails with ENXIO) for up to 30 s, and compared
with the described bytes. The test never names an sdX device: the first CI run assumed
`/dev/sdb` and failed with ENXIO. On failure it prints `iscsiadm -m session -P 3`, the by-path
links and the tail of `dmesg`.

**sg_reset** (sg3-utils, `the_linux_kernel_initiator_resets_the_lun_and_the_target_through_sg_reset`):
`sg_reset -N -d` on the by-path link makes the kernel's SCSI error handler send LOGICAL UNIT
RESET (`iscsi_eh_device_reset`), `-N -t` TARGET WARM RESET (`iscsi_eh_recover_target`); `-N`
stops the ioctl escalating. Each must reach the target's model (and nothing else may: one
decision per reset), and the disk must still read the described bytes afterwards, the kernel
having retried through the unit attention. The kernel never sends ABORT TASK SET, CLEAR TASK
SET, CLEAR ACA, COLD RESET or TASK REASSIGN, and its ABORT TASK comes only from a command
timeout, which a target answering at once never causes. Both kernel tests passed on 26 October
2026 against podman's machine (Fedora CoreOS, Linux 7.2, Fedora's iscsid), run as root from an
aarch64 cross-build. There iscsid is confined by SELinux to iSCSI's own ports, so it times out
against an ephemeral one (`name_connect … ephemeral_port_t` denials):
`NETGET_ISCSI_KERNEL_PORT=3260` makes the tests listen on 3260, and they must then run one at a
time. Each test deletes its node and discovery records afterwards.

**tshark versions.** The discovery test reads SendTargets and the TargetNames through
`iscsi.login.*` fields where tshark has them (4.6) and through `iscsi.keyvalue` ("Key=Value"
strings) where it does not (4.2, Ubuntu 24.04's, which refuses the 4.6 names).

**iSCSIDataSnInvalid on Linux** hung for 300 s in the first CI run and was reproduced in an
ubuntu:24.04 amd64 container against a Linux build of the target, through a relay logging
every PDU: after the target closed the connection on the bad DataSN, libiscsi reconnected with
the test's next WRITE queued ahead of its Login, then sent a WRITE on a new connection with no
Login at all and waited forever. Replacing the close with a Reject of the Data-Out was tried
and hung the same way: libiscsi reset the connection itself on the Reject. The target now
answers the task alone with CHECK CONDITION and keeps the connection.

Every peer test fails, never skips, when its initiator is missing.
