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
| `r2t_solicits_write_data_in_bursts` | R2Ts within MaxBurstLength, R2TSN and DataSN order, a skipped offset → Reject and close |
| `chap_is_checked_in_rust_before_the_model_is_asked` | wrong secret and wrong name → 0x0201 with no model call; mutual CHAP response verified; no secret in any event; CHAP required but not offered → 0x0201 |
| `logins_fail_closed_and_expose_nothing_the_model_did_not_describe` | backend down, silent, invalid → 0x0300; not_found → 0x0203; unauthorized → 0x0202; every refusal closes |
| `bounds_refuse_before_anything_is_buffered_or_asked` | login segment over 8 KiB closed unread; 129 keys, duplicate key, bad version refused; FFP segment over 256 KiB closed; immediate data over FirstBurstLength → Reject |
| `commands_out_of_cmdsn_order_are_dropped` | 32-command window; ahead-of-window and replayed CmdSN not executed |
| `crc32c_digests_are_negotiated_and_checked` | digests both ways, bad data digest → Reject 0x02 and the session continues, bad header digest → close, crc32c-only target rejects None |
| `abort_task_ends_a_write_waiting_for_its_data` | ABORT TASK of a write awaiting R2T data; its late data ignored; unknown task → 1 |

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
~65 that exercise the target are the subset's suites. **The one failure is
`iSCSI.iSCSITMF.AbortTaskSimpleAsync`**: 16 of its 17 asserts pass (the WRITE completes GOOD and
the ABORT TASK is answered "task does not exist", one of its two accepted outcomes); the
failing assert is `test_async_abort_simple.c:132`, libiscsi's own out-queue length checked
right after queuing, before any byte reaches the target. A pcap of the run shows one WRITE(10)
PDU carrying all 4096 bytes as immediate data and nothing else queued on the wire, so the
suite is left out of the subset rather than chased.

**open-iscsi** (Linux, as root, the `iscsi` pair job): `iscsiadm` discovery and login, then
`dd` with `iflag=direct` from the block device the kernel made, compared with the described
bytes.

Every peer test fails, never skips, when its initiator is missing.
