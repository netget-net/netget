# NVMe/TCP host client — Experimental

`host.rs` runs queues (no model); `mod.rs` turns the model's actions into queues and commands
and raises each result as an event; `actions.rs` holds the vocabulary. The PDU and NVMe code is
the target's (`src/server/nvme_tcp/pdu.rs`, `src/server/nvme_tcp/nvme.rs`).

**Lifecycle.** `connect()` opens nothing: it resolves the target, registers the command channel
and raises `nvme_tcp_connected`. The model then chooses:

| Action | Wire | Event |
|---|---|---|
| `nvme_tcp_discover` | a queue to the discovery NQN: ICReq, Connect, CAP/VS, CC.EN, CSTS.RDY, Identify, Get Log Page 70h (header, the whole log in pieces of at most 64 KiB and MDTS, the header again to check the generation), CC.SHN, close | `nvme_tcp_discovery_log` (entries: subsystem NQN, transport, address family, address, port, subsystem type, port ID, controller ID, admin queue size, TREQ) |
| `nvme_tcp_connect` | an admin queue (Connect with KATO, enable, Identify, Number of Queues = 1) and one I/O queue (Connect with the CNTLID, in-capsule data per IOCCSZ), then the active namespace list | `nvme_tcp_connect_result` (the Connect status by name and the field it names when refused; the controller's model, serial, firmware, version, MDTS, MAXCMD, NN and the namespaces when not) |
| `nvme_tcp_identify_controller`, `nvme_tcp_identify_namespace` (with its identification descriptors), `nvme_tcp_list_namespaces`, `nvme_tcp_read`, `nvme_tcp_write`, `nvme_tcp_write_zeroes`, `nvme_tcp_flush`, `nvme_tcp_get_log_page` (smart, error, firmware_slot, changed_namespaces) | one command | `nvme_tcp_command_result` (the NVMe status by name and the decoded answer) |
| `nvme_tcp_compare` (data like a write), `nvme_tcp_verify` (≤ 65536 blocks), `nvme_tcp_copy` (format 0, 1–128 ranges of ≤ 65536 blocks to `destination_lba`) | one I/O command | `nvme_tcp_command_result` (`matches` for a compare; COMPARE FAILURE, COMMAND SIZE LIMIT EXCEEDED, INVALID COMMAND OPCODE by name) |
| `nvme_tcp_reservation_register` (register / unregister / replace, `current_key`, `new_key`, `ignore_existing_key`), `nvme_tcp_reservation_acquire` (acquire / preempt / preempt_and_abort, `reservation_type`, `current_key`, `preempt_key`), `nvme_tcp_reservation_release` (release / clear), `nvme_tcp_reservation_report` | one I/O command (the report extended, 4 KiB) | `nvme_tcp_command_result` (the status; the report's generation, type, registrants with key, host ID and who holds it) |
| `nvme_tcp_disconnect` | CC.SHN normal, CSTS.SHST complete (5 s), close both queues | `nvme_tcp_disconnected` |
| `disconnect` | the same, then stop | — |

**DH-HMAC-CHAP.** With `dhchap_secret` (and `dhchap_ctrl_secret` to make the controller prove
itself too), a Connect whose completion sets AUTHREQ.ATR — the admin queue's, or an I/O queue's
when a target asks it there — is followed by the exchange before anything else: AUTH_Negotiate
offering SHA-256/384/512 and NULL plus ffdhe2048–8192, the challenge answered with R1 (and the
host's DH value), and with a controller secret C2/S2 sent and the controller's R2 checked in
constant time before Success2; a missing or wrong R2 is AUTH_Failure2. The connect result names
the hash, group and direction; a refusal is `connected: false` with `AUTHENTICATION FAILED: …`
saying who refused what. ATR with no secret, or ASCR (secure channel concatenation, which needs
TLS), is refused the same way. The secrets are startup parameters `src/utils/redact.rs` masks,
parsed (`DHHC-1`, CRC-32 checked) before anything connects, and never in an event; a controller
secret without a host secret refuses to start.

**TLS.** With `tls_key` (an `NVMeTLSkey-1` configured PSK) every queue — the discovery
controller's, the admin queue and each I/O queue — opens a TLS 1.3 session before its ICReq,
offering a retained PSK identity for this host and the subsystem that queue then connects to
(`tls_identity_version`, 1 by default: the version carrying the PSK digest, which the Linux host
offers first; 0 is SPDK's form). The keys and the OpenSSL callbacks are the target's
(`src/server/nvme_tcp/tls_psk.rs` and `tls.rs`, see its AGENTS.md); the handshake is bounded by
the same 10 s. A target that does not hold the key fails the handshake, and the connect result is
`connected: false` with the TLS error. Discovery entries say what each port requires:
`secure_channel` (TREQ: required, not_required, not_specified) and `security` (TSAS SECTYPE: none,
tls1.2, tls1.3). Unix builds only.

One controller at a time; a second `nvme_tcp_connect` is refused until `nvme_tcp_disconnect`.
Keep Alive goes out on the admin queue every third of KATO (`keep_alive_ms`, default 30 s),
also while the model is thinking. A queue the target closes or ends with C2HTermReq, or a Keep
Alive that fails, raises `nvme_tcp_disconnected` with the reason. A transport or protocol
error inside a command ends the controller (both queues are dropped) and the result says so.

**ICReq.** PFV 0, HPDA 0, MAXR2T 0 (one R2T at a time); digests `none` (ask for none, and
refuse a target that enables any) or `crc32c` (ask for both, and refuse a target that does
not enable both). ICResp: PFV 0, CPDA ≤ 31 (honoured for the data this host sends), MAXH2CDATA
≥ 4096.

**Commands.** One at a time per queue, CIDs from 0 upward. Data the host sends goes in the
capsule when it fits the queue's in-capsule size (8 KiB on the admin queue, IOCCSZ × 16 − 64
on the I/O queue), otherwise it waits for the target's R2Ts, each answered within R2TO/R2TL in
H2CData PDUs of at most MAXH2CDATA with LAST_PDU on the last. C2HData must be for the command,
continue at the expected offset and stay within the length asked for (1 MiB at most, decided
from PLEN before the data is read); SUCCESS (only with LAST_PDU) completes the command without a
CapsuleResp. A completion for another CID, an R2T outside the write, or any other PDU ends the
controller.

**Encodings.** Reads and writes move at most 8 KiB. Read data is shown as `utf8` when it is text
(no escapes, no controls but `\n`/`\t`; trailing zero bytes counted in `trailing_zero_bytes`,
not shown) and as `hex` otherwise or when asked — the iSCSI initiator's `render_data`; writes
take `encoding` `utf8` (default) or `hex` and are zero-padded to whole blocks, whose size comes
from Identify Namespace (asked once per NSID).

**Fail closed.** A model call that fails sends nothing. A handler chain stops after
`MAX_FOLLOWUP_DEPTH` (16) follow-ups — a whole discover, connect, identify, read, write, read
back, health log, flush and disconnect session is nine.

**Evidence.** `tests/client/nvme_tcp`: NetGet's own target (regression, not evidence), the
Linux kernel target (`nvmet` + `nvmet-tcp` configured through configfs, a file-backed namespace
read back from the file, as root) and SPDK v26.09's `nvmf_tgt` (configured through `rpc.py`, an
AIO bdev over a file, without hugepages), both in the `nvme-tcp` pair job. DH-HMAC-CHAP passes
against both — nvmet configured with sha256/null, sha512/ffdhe4096 and sha384/ffdhe8192, SPDK
choosing sha512/ffdhe8192, both ways — and each refuses a wrong host secret while the host
refuses each when given a controller secret it does not hold. Reservations pass against both
(nvmet's `resv_enable`, Linux 6.13+). Compare and Copy pass against `nvmf_tgt` (within its own
Copy limits: one source range, 263 blocks, which `nvme_tcp_identify_namespace` now reports);
nvmet implements neither, nor Verify, and neither does `nvmf_tgt` Verify — the host reports
their INVALID COMMAND OPCODE, so Verify's only target is NetGet's own. Experimental: all of it
passes on a Linux 7.2 aarch64 kernel, and the pair job had not run in CI when this landed.
