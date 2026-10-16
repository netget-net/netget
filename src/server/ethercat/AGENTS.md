# EtherCAT slave (server) — and the codec both roles share

NetGet as one EtherCAT SubDevice, or a chain of up to eight: an emulated EtherCAT Slave
Controller (ESC) that a master scans, configures and runs to OP, with the slave firmware's
decisions put to the model. The master side is `src/client/ethercat/`, which uses this
directory's codec.

**State**: `Experimental` — see [Maturity](#maturity). **Privilege**: `PacketCapture` for the
raw transport (`startup_privilege_requirement` drops it for `transport: "udp"`).
**Stack**: `ETH>EtherCAT` (EtherType `0x88A4`; EtherCAT-in-UDP is UDP 34980, the declared
`well_known_udp_port`). **Failure mode**: `answers_on_failure`.

## Division of labour

Rust is the ESC and the slave firmware's protocol work: every datagram and its working
counter, auto-increment / station / alias / logical addressing, the 4 KiB register space, the
SII and its EEPROM interface, SyncManagers (mailbox and buffered, direction, enable, the
PDI-deactivate a firmware sets per state, the mailbox repeat request), FMMUs with bit
granularity, the AL state machine's checks, the SyncManager watchdog, the mailbox, and CoE SDO
transfer mechanics. The model decides what a device application decides: whether an upward
state transition is taken (and the AL status code it is refused with), what a declared object
reads as and whether a write to it is accepted (or its SDO abort code), and the input process
data. Output process data arrives as typed values. Values are named, typed fields
(`device.rs`); the model never sees octets.

## Files

| File | What it is |
|---|---|
| `frame.rs` | The EtherCAT frame header and datagram chain, parsed as offsets into the caller's buffer so processing is in place; Ethernet framing; the source-address bit an ESC sets |
| `esc.rs` | The emulated ESC: registers, SyncManagers, FMMUs, SII interface, AL state machine, working counters, and `process_frame` over a chain |
| `sii.rs` | The SII image built from a device description (identity, mailbox, strings, General, FMMU, SyncM, TxPDO/RxPDO, CRC-8 of the configuration area) and the parser a master reads it with |
| `coe.rs` | Mailbox header and CoE SDO codec in both directions (expedited, normal, segmented, abort), abort codes |
| `sdo.rs` | A slave's SDO server: the objects Rust answers, the ones the model answers, segmented-transfer state |
| `device.rs` | Device descriptions, typed values, bit-packed little-endian process data images |
| `link.rs` | The two transports (below) |
| `actions.rs` | Events, actions, metadata, startup parameters |
| `mod.rs` | The engine: frame processing, the model's queue, master rows, the tick |

The codec files are pure and are what `tests/server/ethercat/codec_test.rs` and
`fuzz/fuzz_targets/ethercat_frame.rs` exercise.

## Transports

- **`raw`** (default): Ethernet frames with EtherType 0x88A4 on the server's `interface`,
  through the packet socket PROFINET also uses (`server::profinet::l2::open_packet_socket`:
  `AF_PACKET` on Linux, BPF on macOS). A reply keeps the frame's destination and length and
  sets the locally administered bit of the source address, as an ESC does — ethercrab drops a
  returned frame whose source is still its own.
- **`udp`**: EtherCAT-in-UDP — the frame header and datagrams as one UDP datagram to port
  34980, the encapsulation ETG.1000.4 defines and tshark's `ecatf` dissects. It needs no
  privilege. Replies go to the sender's address.

A packet socket on macOS sees its own transmissions; `link.rs` drops a received frame identical
to one sent in the last second, so neither role reads its own frame back. Linux never loops
them back.

## The AL state machine

Upward transitions are one step at a time (INIT → PRE-OP → SAFE-OP → OP); a skip is refused
with `0x0011`, BOOT with `0x0013`, an unknown state with `0x0012`. Before the model is asked,
Rust checks what a firmware checks: PRE-OP needs the mailbox SyncManagers exactly as the SII
says (`0x0016`), SAFE-OP the process data SyncManagers (`0x001D` outputs, `0x001E` inputs), OP
an output frame received in SAFE-OP (`0x0019`). The model then accepts or refuses
(`ethercat_state_change_request`); the AL status stays at the old state while it decides and
the master polls. An accepted SAFE-OP with inputs never set is refused `0x0018`. Downward
requests are followed at once. An error indication must be acknowledged (bit 4 of AL control)
before any request is followed. In OP, outputs stopping for the SyncManager watchdog time
(default 100 ms) drop the slave to SAFE-OP with `0x001B`.

## Working counters

Read +1, write +1, read-write +3 (1 + 2); a broadcast read ORs every slave's data; ARMW/FRMW: the
addressed slave reads, the others write. A logical datagram counts once per slave for its read
FMMUs and once (LWR) or twice (LRW) for its write FMMUs. A SyncManager-guarded access that is
refused (wrong direction, deactivated, full receive mailbox, empty send mailbox) adds nothing and
leaves the data as it came. Writes to read-only registers are ignored but counted.

## Fail closed

| Question | No usable answer |
|---|---|
| State transition | refused: AL status error bit, code `0x0001` |
| SDO read / write of a declared object | aborted `0x08000020` |
| Inputs | never invented: SAFE-OP is refused (`0x0018`) until the model sets them |

Each question logs one `decision=`: `model_accept`, `model_reject`, `model_answer`,
`model_silent`, `fail_closed_bad_action`, `fail_closed_llm_error`, `fail_closed_llm_overloaded`,
`fail_closed_queue_full`, or `protocol_reject` (the slave refused without asking).

## Bounds

Frames: payload ≤ 1498 octets after the header, ≤ 64 datagrams, every datagram inside the
declared length, Ethernet frames ≤ 1522. Slaves ≤ 8 per segment; per slave ≤ 32 process data
entries and ≤ 128 octets per direction, ≤ 128 declared objects, strings ≤ 64 octets; mailboxes
64-512 octets, ≤ 4 replies queued behind a full send mailbox (drops counted); SDO transfers ≤ 512
octets; SII walk ≤ 64 categories and 8 KiB. Masters tracked ≤ 8. ≤ 32 decisions pending, ≤ 32
events queued for the model. Nothing recurses.

## Maturity

`Experimental`. Two independent masters drive it: ethercrab 0.7 (in every environment, over
EtherCAT-in-UDP through a bridge that only re-encapsulates, and on its own raw socket on a veth)
and SOEM 2.0.1 (`slaveinfo -map`, `simple_ng`) on a veth, with tshark reading both directions.
The raw-socket evidence needs CAP_NET_RAW and runs only in the `ethercat` pair job. No TwinCAT
or IgH EtherLab master has been pointed at it (IgH is a kernel module, too heavy for CI). See
`metadata().notes` for what is not implemented: distributed clocks, bootstrap and FoE/EoE/SoE/AoE,
SDO information, complete access, emergencies, PDO remapping, SII writes, redundancy.
