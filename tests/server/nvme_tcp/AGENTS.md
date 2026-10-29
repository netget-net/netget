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

## `auth_test.rs` — DH-HMAC-CHAP against the raw host

The raw host does its side of DH-HMAC-CHAP from `support.rs`, not from NetGet: the HMAC
straight from the `hmac`/`sha2` crates, the CRC-32 of the `DHHC-1` text bit by bit, the
ffdhe2048 prime copied from RFC 7919 into the test, every message from its offsets. The policy
requires authentication of `…:secure` subsystems.

| Test | What it pins |
|---|---|
| `a_host_that_does_not_authenticate_gets_nothing` | ATR (DW0 bit 17) and no ASCR; Property Get/Set, Identify, Keep Alive are AUTHENTICATION REQUIRED with DNR; a Receive before a Negotiate is AUTH_Failure1 INCORRECT MESSAGE; an `:open` subsystem has no ATR, gates nothing, and still lets a host prove itself; the connect event says `authentication_available` and holds no secret |
| `unidirectional_authentication_with_each_hash_and_the_null_group` | SHA-256, -384, -512 each chosen; the challenge's TID, HL, hash, group, empty DH value, non-zero S1, random C1; Success1 without RVALID; the controller comes up; an I/O queue joins without ATR, authenticates voluntarily (as SPDK does) and reads |
| `bidirectional_authentication_over_ffdhe2048` | the target's first choices (sha384 over sha256, ffdhe2048); its public value in 2..p-2; R1 over the augmented challenge; R2 equal to the raw host's own computation; nothing runs before Success2; tshark reads fctype 05h/06h and SECP E9h (the messages themselves it does not dissect) |
| `wrong_responses_and_unusable_offers_fail_closed` | a wrong key; HASH UNUSABLE; DHGROUP UNUSABLE; the fifth negotiation fails even with the right key and takes the authentication away; a Reply out of order; a changed transaction (INCORRECT PAYLOAD); bidirectional with no controller secret; a DH value of 1 (DHGROUP UNUSABLE) and of the wrong length (INCORRECT PAYLOAD); AUTH_Failure2 leaves the queue shut |
| `authentication_commands_are_checked_and_bounded` | SECP, SPSP0, SPSP1; TL 0 and 4097; TL against the capsule; a Negotiate by R2T; AL 0, 8193, and too small for the challenge (which then stays owed) |
| `the_model_cannot_require_what_is_not_configured` | no secret: `authentication_available` false, a requiring answer is INTERNAL ERROR, DNR, no controller, and Authentication Send is COMMAND SEQUENCE ERROR; a controller secret alone, a secret whose CRC does not match, an unknown hash refuse to start, and no error repeats the secret |

## `commands_test.rs` — Compare, Verify, Copy and reservations against the raw host

| Test | What it pins |
|---|---|
| `compare_verify_and_copy_are_answered_from_the_namespace` | ONCS, OCFS, RESCAP, MSSRL, MCL, MSRC; Compare match and COMPARE FAILURE (DNR), by R2T, over a medium error, after a write; a fused command refused; Verify over good blocks, a medium error, past the end; Copy of two ranges, an overlapping copy, by R2T, to a read-only namespace, past MSSRL, MCL and MSRC, from a medium error, past the end both ways, descriptor format 1; tshark reads opcodes 05h, 0Ch, 19h |
| `reservations_follow_the_rules_and_the_models_decisions` | two hosts: register (again, and with another key), acquire with the wrong and right key and again; the other host reads and compares but may not write, zero, copy or flush; the report (EDS 0 refused; generation, type, REGCTL, the entry); preempt-and-abort refused by the model changes nothing, preempt allowed; Write Exclusive - Registrants Only; release with the wrong type (INVALID FIELD) and the right one; replace, unregister with the wrong key, clear; exactly the changes reached the model, in order; a silent model and a non-decision answer are INTERNAL ERROR and change nothing; the table goes with the subsystem's last controller |
| `the_registrant_table_is_bounded` | 64 registrants, the 65th RESERVATION CONFLICT |

## `kernel_auth_test.rs` — the Linux kernel host, authenticating and running the new commands

Linux, as root, in the `nvme-tcp` pair job, every test with its own host NQN, host ID (the kernel
refuses one host ID under two host NQNs) and subsystem NQN. The secrets come from nvme-cli's own
`gen-dhchap-key`; what the kernel concluded is read from its log after a marker written to
/dev/kmsg; what each queue received is the target's own count (`Started::commands`).

| Test | What it pins |
|---|---|
| `the_kernel_host_authenticates_with_every_hash_and_dh_group` | `nvme connect --dhchap-secret` with sha256/null, sha384/ffdhe2048, sha512/ffdhe3072, sha256/ffdhe4096, sha384/ffdhe6144, sha512/ffdhe8192 and keys of 32/48/64 bytes under transformations 00–03; the kernel logs `qid 0: authenticated with hash hmac(…) dhgroup …` and `qid 0: authenticated`; the namespace reads; two Authentication Sends and two Receives on the admin queue |
| `the_kernel_host_and_netget_authenticate_each_other` | `--dhchap-ctrl-secret` too: `qid 0: controller authenticated`; three Authentication Sends |
| `the_kernel_host_is_refused_with_the_wrong_secret_and_refuses_the_wrong_controller` | a secret NetGet does not hold: the connect fails, the kernel logs `authentication failed`, NetGet `does not match`; a controller secret the kernel does not hold: the kernel logs `controller authentication failed` and NetGet sees AUTH_Failure2; no secret: the connect fails; no secret in any log line |
| `nvme_cli_compares_verifies_copies_and_reserves_through_the_kernel` | `nvme compare` (match, and a miscompare named), `nvme verify` (good, and over a medium error), `nvme copy` read back through the block device, `resv-register`/`resv-acquire`/`resv-report --eds -o json` (type, REGCTL, key, held), `resv-report` without `--eds` refused; the raw host as a second host reads but may not write under the kernel's Write Exclusive; the raw host's Exclusive Access shuts out `nvme read` (`Reservation Conflict` named); the model refuses the kernel's preempt-and-abort and allows its preempt; clear; the eight decisions in order; the kernel's commands summed over its queues (Compare 2, Verify 2, Copy 1, Register 1, Acquire 3, Release 2, Report 2) |

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

## `spdk_host_test.rs` — SPDK's userspace host

Linux, in the `nvme-tcp` pair job, SPDK v26.09 built by `scripts/test-peers/build-spdk.sh`
(`NETGET_SPDK_DIR`), every tool with `--no-huge`: `spdk_nvme_identify` reads the discovery log
and identifies the controller (model, serial, subsystem NQN) and both namespaces' sizes;
`spdk_dd` reads the first 8 KiB of namespace 1 through `bdev_nvme_attach_controller` over TCP,
compared with the description; `spdk_nvme_perf` runs 8 KiB random reads and writes, 16
outstanding, for 2 s, and nothing fails during the run. The target's own `decision=` lines go to
stderr, so a failure shows both sides.

`spdk_perf_authenticates_to_netget_one_way_and_both_ways`: `spdk_nvme_perf --dhchap-key`
(SPDK's file keyring, a 0600 file holding a secret from `nvme gen-dhchap-key`) against a
subsystem the model protects, then with `--dhchap-ctrlr-key` too, then with a key NetGet does not
hold — SPDK logs `received AUTH_failure1 … (authentication failed)` and fails to attach. NetGet
chose sha512 and ffdhe3072 from its preference; the run prints what each SPDK queue sent (two
Authentication Sends one way, three both ways) and asserts no secret is in NetGet's log.

**SPDK found a second gap.** With a controller key SPDK authenticates its I/O queue too, although
the I/O Connect did not ask; the target answered COMMAND SEQUENCE ERROR and SPDK logged
`AUTH_negotiate failed: sc=12` and dropped the qpair. nvmet runs the exchange on any queue, and so
does NetGet now (`unidirectional_authentication_with_each_hash_and_the_null_group` pins it).

`spdk_perf_runs_inside_a_tls_secure_channel`: `spdk_nvme_perf -S ssl --psk-path` (a 0600 file
holding an `NVMeTLSkey-1` key) runs a mixed load inside TLS. SPDK parses the key, derives the
retained and TLS PSKs and offers a version 0 identity itself; the target logs that identity as
accepted. A key the target does not hold fails at the handshake (`fail_closed_tls`).

## `tls_psk_test.rs` — the key derivations against libnvme

No network. The vector is libnvme 3.1's from a CI run (nvme-cli built from source): the
configured key, the version 1 identity `nvme check-tls-key --identity=1` printed, and the TLS PSK
`nvme keys insert-tls-psk` put in the kernel keyring, read back with `keyctl pipe`. The kernel's
own host and target connected with that key. Also the interchange text's CRC and length checks,
and every way the target refuses an identity.

## `tls_test.rs` — the target's secure channel, against NetGet's own TLS host (regression)

Raw PDUs inside a TLS session opened by `netget::server::nvme_tcp::tls::connect`, so the TLS end
is NetGet's own; what is asserted is the target's behaviour. A whole admin session and Identify
inside TLS; the discovery log's TREQ (01b) and SECTYPE (2); a Connect under another host
(CONNECT INVALID HOST) or to another subsystem (INVALID PARAMETERS on SUBNQN) than the identity
names, neither reaching the model; a plain ICReq, another key under version 1 (digest mismatch)
and version 0 (handshake failure), and a silent host closed at the 10 s bound; SHA-384
(TLS_AES_256_GCM_SHA384, which the legacy PSK callbacks cannot carry) under both identity
versions; a malformed `tls_key` refused at startup. Unix only.

## `kernel_tls_test.rs` — the Linux kernel host over TLS

Linux, as root, in the `nvme-tcp` pair job, with nvme-cli 3.1 and tlshd from ktls-utils 1.5.0
built by `scripts/test-peers/build-nvme-tls.sh` (`NETGET_NVME_CLI`, tlshd started with
`keyrings=.nvme`). `nvme gen-tls-key` makes the key; `tls_support::insert` first checks libnvme's
version 1 identity equals NetGet's (so an old nvme-cli fails saying why — see the target's
AGENTS.md on Ubuntu 24.04's 2.8), then `nvme keys insert-tls-psk` puts it in `.nvme` for the
subsystem and the discovery NQN, and widens its permissions so tlshd can search for it (that
takes possession of the key: the shell links `.nvme` into its session keyring first). `nvme
discover --tls` and `nvme connect --tls` hand their handshakes to tlshd (GnuTLS); the namespace's
block device is read with O_DIRECT and compared with the description, and the target logs each
queue's accepted identity. A host holding another key is refused with the digest mismatch, and
no Connect reaches the model.

**SPDK found a defect.** Shutting a controller down, SPDK completes its outstanding
Asynchronous Event Requests itself and reuses their CIDs for the Property Get/Set of CC.SHN; the
target answered COMMAND ID CONFLICT and SPDK logged "Failed to read the CC register". A held
AER's CID coming back now drops that AER (`an_association_serves_the_described_namespaces`
pins it).

**One SPDK log line is not a fault.** After perf's totals SPDK logs "CQ transport error -6" for
its own I/O qpair. A loopback capture shows SPDK sending its FIN first and the target answering
with its own 50 µs later, so the line is SPDK's teardown; the test allows exactly that line after
the totals and nothing else. Against the kernel target SPDK does not log it.

Running these in a rootless container needs `--security-opt seccomp=unconfined`: spdk_dd's AIO
output was refused with EPERM under the default profile.

Every peer test fails, never skips, when nvme-cli, root, the module or SPDK is missing.
