# PROFINET IO device (server) — and the codec both roles share

NetGet as a PROFINET IO **device**: an IO controller (a PLC) finds it with DCP, connects with
PNIO-CM over DCE/RPC, and exchanges cyclic RT_CLASS_1 data with it. The controller side is
`src/client/profinet/`, which uses this directory's codec.

**State**: `Experimental` — see [Maturity](#maturity). **Privilege**: `PacketCapture` for the
raw transport (`startup_privilege_requirement` drops it for `transport: "udp"`).
**Stack**: `ETH>PROFINET` (DCP and cyclic frames are Ethernet, EtherType `0x8892`; PNIO-CM is
UDP 34964, the declared `well_known_udp_port`). **Failure mode**: `answers_on_failure`.

## Division of labour

Rust owns every byte and every timer: DCP framing and filters, the RPC header in both dreps,
NDR, every PNIO block, the AR state machine, FrameID assignment, the frame layout, IOPS/IOCS,
DataStatus, cycle counter, the provider timer, the consumer watchdog, ApplicationReady
retransmission, the replay cache, and every bound. The model decides what PROFINET leaves to
the application: whether to take a DCP Set (name, IP, LED signal, reset), whether to accept a
Connect, every input value and its IOPS, what an I&M or user record says, whether a write is
accepted, and when to abort an AR. Values are typed fields (`values.rs`) — the model never sees
or writes octets.

## Files

| File | What it is |
|---|---|
| `dcp.rs` | DCP PDU codec: Identify/Get/Set, BlockInfo vs BlockQualifier vs bare Get pairs, NameOfStation rules, IP parameter checks, the identity the device reports, what a controller reads from responses |
| `rpc.rs` | Connectionless DCE/RPC header (both byte orders, UUID field swapping), PNIO object/interface UUIDs, NDR request/response headers, PNIOStatus and its error codes |
| `blocks.rs` | PNIO-CM blocks: AR, IOCR, AlarmCR, ExpectedSubmodule, ModuleDiff, ARServer, IOD/IOX Control and Release, Read/Write headers, I&M0-3 |
| `rt.rs` | Ethernet/802.1Q framing, RT_CLASS_1 frames, DataStatus, and `CrLayout` — where each submodule's data, IOPS and IOCS sit, built by a controller or checked from a request |
| `values.rs` | Typed fields (`bool u8 i8 u16 i16 u32 i32 f32`, big-endian), the module/submodule layout, the default layout |
| `l2.rs` | The two transports (below) |
| `gsdml.rs` | A minimal GSDML for a layout, for controllers configured from GSDML (pure function, nothing is written) |
| `actions.rs` | Events, actions, metadata, startup parameters |
| `mod.rs` | The engine: DCP responder, RPC endpoint, ARs, providers, worker |

The codec files are pure and are what `tests/server/profinet/codec_test.rs` and
`fuzz/fuzz_targets/profinet_frame.rs` exercise.

## Transports, and why these two

- **`raw`** (default): `pnet`'s datalink channel on the server's `interface` — `AF_PACKET` on
  Linux, BPF on macOS — so no system library is linked and the protocol builds wherever pnet
  does (`unix`; on other platforms `open_raw` returns an error naming the lab transport). libpcap
  was the alternative (`lldp`, `arp`); it would tie PROFINET to the `libpcap` feature for no gain,
  since PROFINET needs capture *and* injection at millisecond rates, which a packet socket does
  directly. A packet socket sees its own transmissions, so frames from our MAC are dropped on
  receive; only EtherType `0x8892` (after any VLAN tags — Linux usually strips them into
  metadata) reaches the engine.
- **`udp`** (lab): each whole Ethernet frame is one UDP datagram to a peer. No real PROFINET node
  speaks it; it exists so the whole DCP → model → Connect → cyclic path runs unprivileged, which
  is how every macOS test runs. Sends go through a plain `std::net::UdpSocket`: tokio's
  `try_send_to` on a socket the reactor has not polled yet reports WouldBlock, and that silently
  lost a controller's first Identify.

PNIO-CM's RPC is real UDP in both. In raw mode the device refuses to start bound to loopback
while DCP would report a link address controllers cannot reach — bind the interface's address or
`0.0.0.0` (an explicit host is bound as given, per the root `AGENTS.md`). An accepted DCP Set of
the IP changes what DCP *reports*; NetGet does not reconfigure the host.

## The AR

1. **Connect** — every block is checked by Rust and a malformed request is refused without asking
   the model, with the PNIO status naming the block (`ErrorCode1` = AR/IOCR/AlarmCR/Expected,
   `CMRPC` for resources): one IOCARSingle (input + output IOCR, RT_CLASS_1, LT 0x8892,
   SendClockFactor 1-128, ReductionRatio a power of two ≤512, a cycle of 1 ms-2 s, WatchdogFactor
   1-7680, input FrameID in 0xC000-0xF7FF, output FrameID 0xFFFF → assigned) or one IOSAR
   (device access, records only). Each IOCR's frame layout is checked against the expected
   submodules' data lengths: inside DataLength (40-1440), no overlaps. Unsupported blocks
   (MCR, IR info, parameter server) are refused, not ignored. The expected layout is compared
   with the device's; mismatches become a ModuleDiffBlock and those submodules' IOPS stay BAD.
   Then the model is asked (`profinet_connect_request`).
2. **Accept** → ARBlockRes, IOCRBlockRes ×2, AlarmCRBlockRes, ModuleDiff when needed, ARServer
   when the AR asks for advanced start-up; the AR becomes a connection in `AppState` with a peer
   handle (`send_to_peer` takes `profinet_set_inputs` and `profinet_abort_ar`); the input
   provider starts with DataStatus STOP.
3. **PrmEnd** → Done; the device then sends its own CControl **ApplicationReady** request to the
   controller (interface `DEA00002`, to the controller's 34964 on a real link, to the Connect's
   source address in the lab), retransmitted every second up to five times.
4. **Confirmed** → DataStatus RUN, IOCS good, `profinet_ar_established`. Output changes arrive as
   `profinet_outputs_changed` — at most one per 200 ms per AR, carrying the latest values.
5. **Release** → Done, AR removed, `profinet_ar_closed`. The watchdog (WatchdogFactor × cycle)
   closes an AR whose output frames stop; one that never sends any gets 10 s after
   ApplicationReady. An IOSAR expires after its CMInitiatorActivityTimeoutFactor of RPC silence.

Retransmitted RPC requests are answered from a replay cache (32 entries); one still waiting for
the model is not asked twice; PING gets WORKING or NOCALL.

## Fail closed

| Question | No usable answer |
|---|---|
| DCP Set | every block answered "set not possible"; identity unchanged |
| Connect | PNIO error `DB 81 40 02` (RMPM) |
| Record read | `DE 80 C3 00` (resource unavailable) |
| Record write | `DF 80 C3 00` |
| Inputs | IOPS BAD and zero data until `profinet_set_inputs` — the provider never claims good data the model did not give |

Each question logs one `decision=`: `model_accept`, `model_reject`, `model_answer`,
`model_silent`, `fail_closed_bad_action`, `fail_closed_llm_error`, `fail_closed_llm_overloaded`,
`fail_closed_queue_full`, or `protocol_reject` (Rust refused without asking).

## Bounds

DCP: DCPDataLength ≤ 1488 and inside the frame, every block length inside what is left, ≤ 32
blocks, NameOfStation ≤ 240. RPC: 80-octet header, body ≤ 1392 (one datagram), no fragments
(REJECT), NDR ArgsLength = ActualCount ≤ ArgsMaximum and inside the body. Blocks: ≤ 64 per body,
each length inside the data; ≤ 4 IOCRs, ≤ 4 APIs, ≤ 64 IO data objects / IOCS / expected
submodules (a declared count is checked before anything is allocated for it); records ≤ 1024
octets. Frames ≤ 1522 octets; a bounded receive queue (1024, drops counted). ≤ 2 ARs (one IO, one
supervisor); ≤ 32 decisions pending; ≤ 32 events queued for the model; ≤ 64 delayed Identify
answers. Nothing recurses.

## Maturity

`Experimental`. One independent IO controller (profinet-py) and one independent DCP
implementation (pnio_dcp) drive the raw transport in `tests/server/profinet/real_peer_test.rs`,
with tshark reading a live capture — that is condition 1's "one" not "two" for a full controller,
no PLC (Siemens or CODESYS) has been pointed at it, and the evidence runs only in the `profinet`
pair job (it needs CAP_NET_RAW). See `metadata().notes` for what is not implemented: alarms,
RT_CLASS_2/3, RT over UDP, multicast CRs, MRP, diagnosis records, WriteMultiple, fragmented RPC.
