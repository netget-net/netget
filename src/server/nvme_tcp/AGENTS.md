# NVMe/TCP target — Experimental

NVMe over TCP (NVMe/TCP Transport Specification 1.0, NVMe over Fabrics, NVMe Base 1.4 as
reported in VS, with NVMe Base 2.x DH-HMAC-CHAP), well-known port 4420, unprivileged. Rust
owns the wire; the model owns three decisions, each asked once and never per read or write:

- `nvme_tcp_connect` (an admin queue Connect to a subsystem) → `nvme_tcp_accept_connect` with
  the subsystem's namespaces, controller identity and whether the host must authenticate
  (`require_authentication`), or `nvme_tcp_reject_connect`;
- `nvme_tcp_discovery` (a discovery controller's first Get Log Page 70h) →
  `nvme_tcp_discovery_entries`, cached for that controller;
- `nvme_tcp_reservation` (a Reservation Register, Acquire or Release that would change a
  namespace's reservations, after Rust has found it valid and worked out its effect) →
  `nvme_tcp_allow_reservation` or `nvme_tcp_refuse_reservation`.

| File | What it does |
|---|---|
| `pdu.rs` | The common header, PDU types, flags, Fatal Error Status; `check_header` decides a PDU from its eight bytes (type legal in this direction, HLEN, PDO, PLEN, digest flags, data length against the bound for that type) before anything else is read; `read_rest`/`read_pdu` (async, deadline after the first byte) and `decode` (the same over a buffer, for the fuzz target); CRC32C digests sent least significant byte first; the receiver's data alignment; TermReq |
| `nvme.rs` | SQE/CQE, status codes (`describe_io` names the I/O command set's own 80h–83h), opcodes and command names, properties, SGL types, Connect decoding (NQNs validated, the offending field's offset kept), discovery log entries, Copy source ranges, and the decoders the host and fuzz target use (Identify Controller/Namespace, namespace lists and descriptors, SMART) |
| `auth.rs` | DH-HMAC-CHAP for both roles: the six messages, `DHHC-1` secrets and their transformation, R1/R2, the SHA-2 HMACs, the RFC 7919 groups (`ffdhe.rs`, the primes as the RFC prints them) and the session key that augments both challenges |
| `resv.rs` | A namespace's registrant and holder table, the rules Register/Acquire/Release follow, which commands a reservation lets a host run, and the extended Reservation Report |
| `ns.rs` | `SubsystemDescription` from the model's answer (namespaces described through `src/server/described_disk.rs`, the disk model NBD and iSCSI share); Identify Namespace (with RESCAP and the Copy limits) and descriptors; the controller's write overlay |
| `mod.rs` | accept loop (and an optional second listener, `discovery_port`), one connection per queue, ICReq/ICResp, Connect and the dynamic controller model, properties, admin and I/O commands, R2T/H2CData, C2HData, keep-alive, and a per-queue count of the commands received, logged when the queue ends |
| `target_auth.rs` | the target's side of DH-HMAC-CHAP on an admin queue |
| `target_io.rs` | Compare, Verify, Copy, the reservation commands and the reservation check on every I/O command |
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
  checked; deallocate is advisory and changes nothing, so Identify Namespace reports DLFEAT 0),
  Compare, Verify, Copy and the four reservation commands (below). ONCS says so (Compare, DSM,
  Write Zeroes, Reservations, Verify, Copy) and OCFS bit 0 (Copy format 0).
  Unknown NSID → INVALID NAMESPACE OR FORMAT; past the end → LBA OUT OF RANGE; PRINFO ≠ 0 or
  over MDTS (1 MiB) → INVALID FIELD; a fused command (FUSE ≠ 0) → INVALID FIELD; SGL type or
  length that does not match the command → SGL DESCRIPTOR TYPE INVALID / DATA SGL LENGTH
  INVALID; failing regions → UNRECOVERED READ ERROR / WRITE FAULT (medium_error) or INTERNAL
  ERROR (hardware_error).
- **Compare** takes its data like a Write (in the capsule or by R2T, ≤ MDTS) and compares it
  with the namespace's bytes — the description with the controller's writes over it; any
  difference is COMPARE FAILURE (media error 85h). A failing region in the range is the read
  error, before any comparison. **Verify** moves no data: the range must exist and be readable.
  **Copy** (descriptor format 0 only, PRINFOR/PRINFOW 0) needs a writable namespace, at most
  128 source ranges (MSRC 127), none longer than MSSRL and all together no more than MCL — both
  4 MiB of blocks (8192 at 512 bytes) — else COMMAND SIZE LIMIT EXCEEDED; every source is read
  before the destination is written, so overlapping ranges copy what was there, into the same
  bounded overlay a Write uses.
- **Data:** C2HData in PDUs of ≤128 KiB at the host's HPDA alignment; writes take in-capsule
  data (≤8 KiB, IOCCSZ 516) or are solicited with one R2T at a time of ≤MAXH2CDATA, at most four
  commands with an R2T open per queue (the rest wait). H2CData must name an open R2T (CCCID: FES
  01h FEI 8; TTAG: FEI 10), continue at the expected offset and stay inside it (FES 04h), carry
  no more than MAXH2CDATA (FES 05h, decided from PLEN), and LAST_PDU only on the R2T's last.
- **Digests:** a header digest mismatch is fatal (C2HTermReq FES 03h); a data digest mismatch
  fails that command with TRANSIENT TRANSPORT ERROR and the queue goes on (the PDU was read
  whole). HDGSTF/DDGSTF that disagree with what was negotiated: FES 01h FEI 1.
- A command ID a write waiting for its data still holds is COMMAND ID CONFLICT. One a held
  Asynchronous Event Request holds drops that AER and runs: SPDK, shutting a controller down,
  completes its AERs itself and reuses their CIDs for the Property Get/Set that follow, and a
  conflict there failed its shutdown. More commands outstanding than the queue holds is fatal
  (FES 02h).

## Write handling (the storage question)

A namespace the model marks `writable` takes writes into an overlay owned by the controller:
every I/O queue of that association reads it back, it is bounded at 64 MiB (then CAPACITY
EXCEEDED), and it is discarded when the controller goes. Nothing touches a file and nothing
outlives the association — it is the state a drive holds between a Write and the next Read
while the host is attached, which is the iSCSI target's choice too. A namespace not marked
writable answers NAMESPACE IS WRITE PROTECTED and sets NSATTR bit 0, so the Linux host makes its
block device read-only.

## In-band authentication (DH-HMAC-CHAP)

The operator configures the secrets (`dhchap_secret`, the host secret every host the model
requires to authenticate must prove; `dhchap_ctrl_secret`, for a host that asks the controller
to prove itself), as `DHHC-1:<hh>:<base64 of key ‖ CRC-32>:` text — what `nvme gen-dhchap-key`
prints, transformation hash 00–03, keys of 32, 48 or 64 bytes. They are startup parameters
whose names `src/utils/redact.rs` masks; their `Debug` shows only a length, and nothing about a
secret, a challenge or a response reaches an event, the model or a log line. The connect event
says only `authentication_available`. A controller secret without a host secret refuses to
start; an `nvme_tcp_accept_connect` with `require_authentication` when no secret is configured
is `fail_closed_invalid_reply` (INTERNAL ERROR, DNR, no controller).

When the model requires it, the admin Connect completes with AUTHREQ.ATR (DW0 bit 17) and,
until the host authenticates, every command on that queue but Authentication Send/Receive is
AUTHENTICATION REQUIRED (1h/91h, DNR) — Property Get/Set included, so the controller cannot be
enabled and no I/O queue can join it. I/O queues are not asked to authenticate (nvmet does the
same), but a host may prove itself on any queue when a secret is configured, and the exchange
runs there without gating anything: **SPDK found this** — its host authenticates every I/O queue
whenever it holds a key, and a target that answered COMMAND SEQUENCE ERROR there failed its
I/O qpair. With no secret configured, Authentication Send/Receive is COMMAND SEQUENCE ERROR.

The exchange follows nvmet: AUTH_Negotiate (NAPD 1, DH-HMAC-CHAP, SC_C 0 — secure channel
concatenation needs TLS) picks the first of `dhchap_hashes` (SHA-256/384/512) and of
`dhchap_dhgroups` (NULL, ffdhe2048…8192) the host offers; the next Authentication Receive is the
challenge (random C1, non-zero S1, the controller's public value); the Reply's R1 is checked in
constant time against the host secret transformed with the host NQN, with the challenge
augmented by H(g^xy mod p) under an ffdhe group (the host's value must be the group's length and
lie in 2..p-2); a Reply carrying C2 and a non-zero S2 gets R2 in Success1 (from the controller
secret transformed with the subsystem NQN), and the queue is authenticated on Success2 — on
delivering Success1 when one-way. Anything that fails (a wrong response, an unusable hash or
group, a step or transaction out of order, a bidirectional request with no controller secret)
completes its Authentication Send successfully and makes the next Authentication Receive an
AUTH_Failure1 with the reason; the queue stays unauthenticated. AUTH_Failure2 from the host
(it did not accept R2) takes the authentication away. Bounds: four negotiations per queue (each
challenge costs an exponentiation), the whole within 30 s of the Connect (the queue closes),
TL ≤ 4096, AL ≤ 8192 (and at least the message, else INVALID FIELD with the exchange where it
was), the message zero-padded to AL. Private exponents are twice the group's strength
(224–400 bits); `num-bigint`'s modular exponentiation is not constant-time.

## Reservations

Register, Acquire, Release and Report over a table per (subsystem NQN, NSID), shared by every
controller of the subsystem: registrants are host identifiers (Connect's HOSTID), at most 64 per
namespace and 1024 tables; RESCAP 0xFE (types 1–6, IEKEY as NVMe 1.3; no persistence through
power loss, and CPTPL other than "no change" or "clear" is INVALID FIELD). Rust applies the
specification's rules first — the rules nvmet applies, except that under an all-registrants
reservation every registrant holds it, and releasing with the wrong type is INVALID FIELD as the
specification says — and a refusal there (wrong key, held by another, …) is answered at once. A
command that would change nothing (registering the same key, acquiring what is held, releasing
nothing) succeeds without asking. Every change is then the model's: `nvme_tcp_reservation`
carries the operation, type, host NQN and ID, the effect Rust worked out, and the holder and
registrant count before it; `nvme_tcp_allow_reservation` applies it (to the table as it is then:
another host may have changed it meanwhile), `nvme_tcp_refuse_reservation` is RESERVATION
CONFLICT (`model_reject`), no answer or the wrong answer is INTERNAL ERROR with DNR
(`model_silent`/`fail_closed_invalid_reply`), a backend failure INTERNAL ERROR without it; none
of them changes anything. Keys are not in the event.

Every I/O command is checked against the holder: Read, Compare and Verify are the read group;
Write, Write Zeroes, Dataset Management, Copy and Flush (of one namespace) the write group. A host
other than the holder gets RESERVATION CONFLICT for the write group under Write Exclusive, for
both under Exclusive Access, and for the write group (Write Exclusive) or both (Exclusive Access)
under the registrants-only and all-registrants types unless it is registered. The report is the
extended structure only (EDS; fabrics host identifiers are 128 bits, so EDS 0 is HOST
IDENTIFIER INCONSISTENT FORMAT, as nvmet answers): generation, type, REGCTL counting every
registrant, one 64-byte entry per registrant that fits (CNTLID FFFFh — controllers are dynamic —
held, key, host ID). The table lives as long as some controller of the subsystem does: when the
last one goes, its registrations go too, as they would on a target that persists nothing through
a power loss. The generation counts register, unregister, replace, preempt and clear.

## Not implemented

TLS (TP 8011 secure channels, and so secure channel concatenation: a Negotiate asking for it is
AUTH_Failure1 CONCAT_MISMATCH) — the rustls the tree uses has no TLS 1.3 external pre-shared
keys, which NVMe/TCP TLS is built on, and the test VM's kernel would need `tlshd` (ktls-utils),
which it does not have; authentication of I/O queues; re-authentication requested by the
controller; reservation notifications (log page 80h, Set Features 82h/83h) and persistence
through power loss; preempt-and-abort aborts nothing (every command completes as it arrives, so
there is nothing outstanding to abort); fused Compare and Write; ANA, namespace management, Write
Uncorrectable, protection information, asynchronous event completions, the static controller
model, more than one R2T outstanding per command, the Command Supported and Effects log.

## Maturity

Experimental. Two independent hosts pass — the Linux kernel's nvme-tcp (driven by nvme-cli)
and SPDK v26.09's userspace host — and the pcap oracle (tshark 4.6 and Ubuntu's 4.2.2) is clean,
all measured on a Linux 7.2 aarch64 kernel in the podman VM. DH-HMAC-CHAP has both: the kernel
host one way with every hash and group and both ways, SPDK's `spdk_nvme_perf --dhchap-key
[--dhchap-ctrlr-key]` one way and both ways (and on its I/O queues), each refused with a wrong
key. Compare, Verify, Copy and reservations have the kernel host through nvme-cli; SPDK's tools
issue none of them. tshark dissects the Authentication Send/Receive commands (FCTYPE, SECP,
SPSP0/1, AL — present in 4.2.2) but not the messages they carry, and reads the Compare, Verify
and Copy opcodes. In CI the peers run only in the `nvme-tcp` pair job, which had not run when
this landed (and needs a runner kernel with CONFIG_NVME_HOST_AUTH and CONFIG_NVME_TARGET_AUTH,
which the job checks), so the rating waits for it. See `tests/server/nvme_tcp/AGENTS.md`. The
fuzz target is `fuzz/fuzz_targets/nvme_tcp_pdu.rs`; it covers the authentication messages, the
secret text, the reservation data and rules, and Copy's ranges, and ran 383 182 inputs clean in
ten minutes on Linux.
