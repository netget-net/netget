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
| `nvme_tcp_disconnect` | CC.SHN normal, CSTS.SHST complete (5 s), close both queues | `nvme_tcp_disconnected` |
| `disconnect` | the same, then stop | — |

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
AIO bdev over a file, without hugepages), both in the `nvme-tcp` pair job. Experimental: both
pass on a Linux 7.2 aarch64 kernel, and the pair job had not run in CI when this landed.
