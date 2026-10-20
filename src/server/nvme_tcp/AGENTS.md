# NVMe/TCP target — Experimental

NVMe over TCP (NVMe/TCP Transport Specification 1.0, NVMe over Fabrics, NVMe Base 1.4 as
reported in VS), well-known port 4420, unprivileged. Rust owns the wire; the model owns three
decisions, each asked once and never per I/O command:

- `nvme_tcp_connect` (an admin queue Connect to a subsystem) → `nvme_tcp_accept_connect` with
  the subsystem's namespaces and controller identity, or `nvme_tcp_reject_connect`;
- `nvme_tcp_discovery` (a discovery controller's first Get Log Page 70h) →
  `nvme_tcp_discovery_entries`, cached for that controller.

| File | What it does |
|---|---|
| `pdu.rs` | The common header, PDU types, flags, Fatal Error Status; `check_header` decides a PDU from its eight bytes (type legal in this direction, HLEN, PDO, PLEN, digest flags, data length against the bound for that type) before anything else is read; `read_rest`/`read_pdu` (async, deadline after the first byte) and `decode` (the same over a buffer, for the fuzz target); CRC32C digests sent least significant byte first; the receiver's data alignment; TermReq |
| `nvme.rs` | SQE/CQE, status codes, opcodes, properties, SGL types, Connect decoding (NQNs validated, the offending field's offset kept), discovery log entries, and the decoders the host and fuzz target use (Identify Controller/Namespace, namespace lists and descriptors, SMART) |
| `ns.rs` | `SubsystemDescription` from the model's answer (namespaces described through `src/server/described_disk.rs`, the disk model NBD and iSCSI share); Identify Namespace and descriptors; the controller's write overlay |
| `mod.rs` | accept loop (and an optional second listener, `discovery_port`), one connection per queue, ICReq/ICResp, Connect and the dynamic controller model, properties, admin and I/O commands, R2T/H2CData, C2HData, keep-alive |
| `actions.rs` | events, actions, startup parameters, metadata |

## Queues and controllers

Every TCP connection is one queue. ICReq must arrive within 30 s (PFV 0, HPDA ≤ 31 —
answered with C2HTermReq FES 06h naming the byte otherwise), and the first command within 30 s
of the ICResp; anything before Connect is COMMAND SEQUENCE ERROR. ICResp: CPDA 0, MAXH2CDATA
128 KiB, digests per the `digests` parameter (either: what the host asked; none; crc32c: a host
that does not ask for both is refused with FES 06h, FEI 11).

**Admin queue Connect (QID 0)** creates a controller — the dynamic model, so CNTLID must be
FFFFh — after checking RECFMT 0, both NQNs (`nqn.` form, printable, ≤223 bytes, NUL
terminated) and SQSIZE 31–127. The discovery NQN `nqn.2014-08.org.nvmexpress.discovery` makes a
discovery controller without asking the model; any other NQN asks it. At most 64 controllers.

| Outcome | Connect status (DW0) | `decision=` |
|---|---|---|
| accepted, valid description | SUCCESS, DW0 = CNTLID | `model_answer` |
| `nvme_tcp_reject_connect` not_found | CONNECT INVALID PARAMETERS (SUBNQN: 256, data) | `model_reject` |
| `nvme_tcp_reject_connect` invalid_host | CONNECT INVALID HOST (HOSTNQN: 512, data) | `model_reject` |
| no answer | INTERNAL ERROR, DNR | `model_silent` |
| invalid answer | INTERNAL ERROR, DNR | `fail_closed_invalid_reply` |
| backend failed / saturated | INTERNAL ERROR (no DNR) / CONNECT CONTROLLER BUSY | `fail_closed_llm_error` |

A refused Connect leaves the queue unconnected: no controller exists and no namespace was
described. **I/O queue Connect (QID ≥ 1)** is decided in Rust: the CNTLID must name a live
controller of the same host NQN, subsystem NQN and host ID (else INVALID PARAMETERS, CNTLID),
not a discovery controller (QID), the controller must be enabled (COMMAND SEQUENCE ERROR), QID
within the Number of Queues granted (8 at most; QID), not already connected (COMMAND SEQUENCE
ERROR), SQSIZE ≤ MQES 127. CATTR bit 2 disables SQ flow control for that queue: SQHD FFFFh,
and a successful read ends with C2HData LAST_PDU|SUCCESS and no CapsuleResp.

**A controller lives as long as its admin queue.** When that connection ends — the host
closes it, sends H2CTermReq, breaks a bound, or KATO (+2 s) passes with no command on any of
its queues — the controller is forgotten, its I/O queues are told to close, and its writes are
discarded. CC.EN 1→0 (a reset) closes the I/O queues and keeps the admin queue. CC.SHN sets
CSTS.SHST complete at once.

## Commands

- **Properties:** CAP (MQES 127, CQR, TO 7.5 s, CSS NVM, 4 KiB pages), VS 1.4.0, CC (EN checks
  IOSQES 6 / IOCQES 4 / MPS / CSS / AMS on I/O controllers; a bad CC sets CSTS.CFS), CSTS, NSSR
  reads 0. Anything else INVALID FIELD.
- **Admin:** Identify CNS 00h/01h/02h/03h (an inactive NSID reads as zeroes; a discovery
  controller answers only 01h), Get Log Page 01h/02h/03h/04h on I/O controllers and 70h/01h on
  discovery controllers (NUMDL/NUMDU, LPO, past the end INVALID FIELD; other LIDs INVALID LOG
  PAGE), Set/Get Features 07h (once, before any I/O queue), 0Fh, 0Bh, 06h (and SEL 0–3, read-only
  01h/02h/04h/05h/0Ah), saving refused, Keep Alive, Abort (DW0 bit 0: not aborted),
  Asynchronous Event Request held (AERL 3, the fifth is AER LIMIT EXCEEDED; none is ever
  completed, because nothing here changes).
- **I/O:** Read, Write, Flush (NSID or FFFFFFFFh), Write Zeroes, Dataset Management (ranges
  checked; deallocate is advisory and changes nothing, so Identify Namespace reports DLFEAT 0).
  Unknown NSID → INVALID NAMESPACE OR FORMAT; past the end → LBA OUT OF RANGE; PRINFO ≠ 0 or
  over MDTS (1 MiB) → INVALID FIELD; SGL type or length that does not match the command → SGL
  DESCRIPTOR TYPE INVALID / DATA SGL LENGTH INVALID; failing regions → UNRECOVERED READ ERROR /
  WRITE FAULT (medium_error) or INTERNAL ERROR (hardware_error).
- **Data:** C2HData in PDUs of ≤128 KiB at the host's HPDA alignment; writes take in-capsule
  data (≤8 KiB, IOCCSZ 516) or are solicited with one R2T at a time of ≤MAXH2CDATA, at most four
  commands with an R2T open per queue (the rest wait). H2CData must name an open R2T (CCCID: FES
  01h FEI 8; TTAG: FEI 10), continue at the expected offset and stay inside it (FES 04h), carry
  no more than MAXH2CDATA (FES 05h, decided from PLEN), and LAST_PDU only on the R2T's last.
- **Digests:** a header digest mismatch is fatal (C2HTermReq FES 03h); a data digest mismatch
  fails that command with TRANSIENT TRANSPORT ERROR and the queue goes on (the PDU was read
  whole). HDGSTF/DDGSTF that disagree with what was negotiated: FES 01h FEI 1.
- A command ID already outstanding is COMMAND ID CONFLICT; more commands outstanding than the
  queue holds is fatal (FES 02h).

## Write handling (the storage question)

A namespace the model marks `writable` takes writes into an overlay owned by the controller:
every I/O queue of that association reads it back, it is bounded at 64 MiB (then CAPACITY
EXCEEDED), and it is discarded when the controller goes. Nothing touches a file and nothing
outlives the association — it is the state a drive holds between a Write and the next Read
while the host is attached, which is the iSCSI target's choice too. A namespace not marked
writable answers NAMESPACE IS WRITE PROTECTED and sets NSATTR bit 0, so the Linux host makes its
block device read-only.

## Not implemented

In-band authentication (DH-HMAC-CHAP: no AUTHREQ is ever set, and Authentication Send/Receive
are INVALID OPCODE), TLS, reservations, ANA, namespace management, Compare, Write Uncorrectable,
Verify, Copy, protection information, asynchronous event completions, the static controller
model, more than one R2T outstanding per command, the Command Supported and Effects log.

## Maturity

Experimental: one independent host family (the Linux kernel's nvme-tcp, driven by nvme-cli) and
it runs only as root in the `nvme-tcp` pair job. See `tests/server/nvme_tcp/AGENTS.md`. The fuzz
target is `fuzz/fuzz_targets/nvme_tcp_pdu.rs`.
