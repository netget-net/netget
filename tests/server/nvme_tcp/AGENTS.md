# NVMe/TCP target tests

No LLM anywhere: `support::POLICY` (and `real_client_test`'s `REAL_POLICY`) is a python script
handler playing the model, and the LLM endpoint is unreachable, so an event the policy does not
cover exercises the fail-closed path. LLM calls: zero.

## `e2e_test.rs` — a raw host from the specifications' offsets

`support::Raw` writes every PDU from literal offsets (not NetGet's encoder), builds SQEs and
Connect data by hand, computes CRC32C bit by bit from the Castagnoli polynomial, checks the
target's HDGSTF/DDGSTF flags and digests on everything it reads, and keeps the conversation in
the order it crossed for the pcap oracle (tshark's `nvme-tcp` and `nvme` dissectors, decode-as
`tcp.port==4420,nvme-tcp`). Every field the tests read through tshark was checked to exist in
Ubuntu 24.04's tshark 4.2.2 as well as 4.6.

| Test | What it pins |
|---|---|
| `discovery_log_lists_the_models_subsystems_and_tshark_reads_it` | ICResp fields, discovery Connect, COMMAND SEQUENCE ERROR before CC.EN, CAP and VS, Identify (CNTRLTYPE 2, CNTLID = Connect's), the discovery log header and both entries (default address = the listener, explicit address), LPO reads and past-the-end, the generation, one model call per discovery controller, what a discovery controller refuses, CC.SHN → SHST; tshark reads the Connect SUBNQN, both discovery records and MAXH2CDATA |
| `an_association_serves_the_described_namespaces` | one model call per association; Identify Controller fields the Linux host checks (CNTLID, MDTS, SQES/CQES, NN, SGLS incl. offsets, IOCCSZ/IORCSZ, KAS, SUBNQN), CNS 02h/00h/03h/06h, inactive and invalid NSIDs; Number of Queues, Get Features, saving refused; reads of text/fill/hex, a 256 KiB read in two C2HData PDUs, medium error, LBA range, INVALID NAMESPACE, SGL length, MDTS, in-capsule SGL on a read; writes in the capsule and by R2T (R2TL = MAXH2CDATA, two H2CData per R2T), write-protected namespace, write fault, Write Zeroes, Flush, Dataset Management, unknown opcode; a second I/O queue reads the first's writes; SMART counts; AERs held and the fifth refused; tshark reads the model number, NSZE, R2TL and SLBA; the admin queue closing takes its I/O queues and its writes, and the old CNTLID is gone |
| `connects_fail_closed_and_expose_no_controller` | backend failure → INTERNAL ERROR without DNR; silent, invalid → INTERNAL ERROR; not found → INVALID PARAMETERS naming SUBNQN; denied host → CONNECT INVALID HOST naming HOSTNQN; after each, no controller exists |
| `io_queue_connects_are_checked_against_the_association` | admin CNTLID ≠ FFFFh, RECFMT, SQSIZE 0/8/128, a malformed HOSTNQN (none of which reach the model); second Connect; I/O queue before CC.EN, past the grant, another host or host ID, SQSIZE > MQES, twice; Number of Queues after an I/O queue; admin and I/O opcodes on the wrong queue; a reset closes the I/O queue; no I/O queue on a discovery controller |
| `bounds_refuse_before_anything_is_buffered` | first PDU not ICReq, ICReq PLEN/PFV/HPDA, a capsule declaring 1 GiB (refused from its header, the offending header returned), 8 KiB + 4 of in-capsule data, wrong HLEN, an R2T from the host, H2CData over MAXH2CDATA (FES 05h), for no command (FEI 8), wrong TTAG (FEI 10), wrong offset (FES 04h); COMMAND ID CONFLICT; nothing written by any refused transfer |
| `crc32c_digests_are_negotiated_and_checked` | both digests both ways (on a solicited write too), a bad data digest fails only that command, a bad header digest is fatal, HDGSTF when none was negotiated, `digests=crc32c` refuses a host that does not ask (FEI 11), `digests=none` enables none |
| `keep_alive_expiry_ends_the_controller` | I/O-queue traffic keeps an association with KATO 1 s alive for 3.5 s; silence ends both queues after KATO + grace, and the controller is gone |
| `disabled_sq_flow_control_ends_reads_with_success` | CATTR bit 2: SQHD FFFFh, C2HData LAST_PDU\|SUCCESS and no CapsuleResp; failures still complete; tshark reads the SUCCESS flag |
| `sq_head_advances_and_wraps` | SQHD after the Connect and around a four-entry queue |

## `real_client_test.rs` — the Linux kernel host

Linux, as root, in the `nvme-tcp` pair job (nvme-cli from Ubuntu, the runner kernel's
`nvme-tcp`): `nvme discover` (the subsystem listed at this listener), `nvme connect` (one model
call for the association; the kernel's admin and I/O queues, Identify, CNS 06h, namespace scan),
the block devices found from `/sys/class/nvme-subsystem/*/subsysnqn` —
never a guessed `/dev/nvme0n1` — read with O_DIRECT off the runtime the target runs on and
retried until a read succeeds (30 s), compared with the description; namespace 2 read-only
(`/sys/block/*/ro`) with 4096-byte logical blocks; an 8 KiB O_DIRECT write read back; `nvme
id-ctrl`, `nvme id-ns`, `nvme smart-log` against the description; `nvme disconnect` and the
subsystem gone. A second test has the kernel refused a subsystem the model does not know. On
failure each prints `nvme list -v`, `nvme list-subsys`, the sysfs subsystems and controllers
(state, transport, address) and the tail of `dmesg`.

Every peer test fails, never skips, when nvme-cli, root or the module is missing.
