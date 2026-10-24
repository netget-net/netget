# Zigbee — NetGet as a coordinator's network co-processor (EZSP or Z-Stack MT, TCP)

NetGet plays the network co-processor (NCP) a Zigbee host talks to, on a TCP socket, the way
network-attached coordinators (SMLIGHT SLZB-06/07, TubesZB, ser2net-bridged sticks) are used,
in one of two firmware dialects chosen by the `dialect` startup parameter:

- **`ezsp`** (default) — Silicon Labs EmberZNet: EZSP carried by ASH. Hosts: zigpy's
  `bellows` (ZHA), zigbee-herdsman's `ember` adapter (Zigbee2MQTT).
- **`znp`** — TI Z-Stack 3.x.0: the Monitor and Test (MT) API. Hosts: `zigpy-znp` (ZHA),
  zigbee-herdsman's `zstack` adapter (Zigbee2MQTT).

The host forms or resumes a network through it and talks to the devices behind it. The
network — the devices, who joins, how they answer, what the dashboard injects — is one
(`network.rs`); only the host link differs.

**Why a parameter and not detection from the first bytes.** A stick runs one firmware: an
SLZB-06 flashed with EmberZNet does not answer MT, and the NV memory a Z-Stack host writes
(the NIB, OSAL items) has no meaning to EmberZNet. Detection would let one server be both,
which no device is, and it would have to guess on a host that waits for the NCP (neither
host speaks first in a way the other dialect could not also begin). A host of the wrong
dialect is told so in the log (`the host is speaking ASH/EZSP; this co-processor runs
Z-Stack`), and gets what that firmware would give it: nothing it can parse.

**This is the host-to-co-processor link, not Zigbee over the air.** No open Zigbee stack runs
on Linux's `mac802154_hwsim`, so there is no radio-level peer; there is no 802.15.4 MAC, no NWK
or APS security, no routing. The devices are simulated behind the NCP: every frame one sends is
built from its description or from the model's answer.

**Server only.** A client role (NetGet as the host) needs an independent NCP to test against:
an EZSP or Z-Stack firmware simulator not written here. None exists, so none was built — a
client tested against this server would prove only that the two agree.

## Files

- `ash.rs` — ASH (UG101): stuffing of the six reserved bytes, CANCEL/SUBSTITUTE/XON/XOFF, the
  LFSR data randomisation (seed 0x42, feedback 0xB8), CRC-CCITT (0x1021, init 0xFFFF, sent
  high byte first), DATA/ACK/NAK/RST/RSTACK/ERROR control bytes, and `Link`: the NCP's frame
  and acknowledgement numbers, a 3-frame transmit window, UG101's adaptive acknowledgement
  timer (1.6 s initially, 0.4–3.2 s), NAK-driven and timeout-driven retransmission with reTx
  set, the reject condition (one NAK until a good frame), and the failed state — an ERROR
  frame with 0x51 after 4 consecutive timeouts, then nothing but RST is heard. An RST within
  250 ms of the last one is lost as it would be on a rebooting chip (bellows sends three back
  to back and expects one RSTACK).
- `ezsp.rs` — frame ids, `sl_status_t` codes, the legacy and extended (format version 1)
  headers, and a bounded little-endian reader.
- `legacy.rs` — EZSP 8–13 on top of the 14+ command set (below).
- `mt.rs` — MT framing: SOF 0xFE, length (≤ 250), Cmd0 (type in bits 7–5, subsystem in
  4–0), Cmd1, data, FCS (XOR of length through data); the deframer, which hunts for SOF and
  holds at most one 255-byte frame; the RPC error SRSP; a bounded reader.
- `znp.rs` — the Z-Stack firmware: every command the two Z-Stack hosts send and its answer,
  the NV memory (`Flash`: OSAL items by id, extended items by system/item/sub-item), the
  aligned NIB, reset with `STARTUP_OPTION`, BDB formation, and the indications (`up_frames`).
- `zstack.rs` — one Z-Stack host's session (frames in, SRSP then indications out, the census).
- `network.rs` — what both dialects share: joins, leaves, the unicast/broadcast delivery that
  answers from the description or asks the model, the model's answers applied, injected
  actions, the coordinator's own ZDO (including the energy-scan `Mgmt_NWK_Update_req`).
- `ncp.rs` — the command set: RAM (negotiated version, configuration values, values, policies,
  host endpoints, initial security state, multicast table, extended timeouts — cleared by a
  reset) and NVRAM (`Nvram`: the formed network and its keys and frame counters, the joined and
  waiting devices, the link-key table — kept across resets and host connections).
- `device.rs` — device descriptions, ZDO and ZCL.
- `mod.rs` — settings (`dialect`), the accept loop (one host at a time), model questions
  (`ask`), and the EZSP session (link + EZSP + callbacks).
- `actions.rs` — the protocol: events, actions, startup parameters, metadata.

## EZSP versions and the command set

Versions **8 to 17**, default 17 (`ezsp_version`). bellows asks for version 4 in the legacy
header and switches to the NCP's, and has a command table for every version from 4; herdsman
asks for 19 and switches to anything from 13 (its `EZSP_MIN_PROTOCOL_VERSION`), refusing 12
and below. The stack version reported is the EmberZNet release each version shipped in
(`ncp::stack_release`: 8 → 6.10.3, 13 → 7.4.3, 17 → 8.1.0).

`ncp.rs` speaks 14–17. **8–13 go through `legacy.rs`**, which turns the older host's command
into the v14 one, lets `ncp::handle` answer, and turns the answer and every callback back:

- statuses narrowed to one byte — `EmberStatus` for the stack commands, `EzspStatus` for the
  configuration ones (`legacy::status_kind`), the security manager (12+) already
  `sl_status_t`; the mapping is bellows' `SL_STATUS_MAP` inverted;
- moved layouts rebuilt: `sendUnicast`/`sendBroadcast`/`sendMulticast` (8-bit tags, no alias
  or NWK sequence), `messageSentHandler` (status after the tag), `incomingMessageHandler`
  (LQI, RSSI, sender, binding and address index — no EUI-64, no timestamp), `exportKey` and
  `exportLinkKeyByIndex` (status last), `setExtendedTimeout` (no status), `getChildData` and
  `setChildData` (the 14-byte `EmberChildData` of 8 and 9), `scanCompleteHandler`;
- what only older versions have, answered there: `getKey`, `getKeyTableEntry`,
  `addOrUpdateKeyTableEntry`, `addTransientLinkKey`, `becomeTrustCenter` (0x0077 until
  `tokenFactoryReset` took it in 13), `getAddressTableRemoteEui64`/`NodeId` (0x005E until
  `getAddressTableInfo` took it in 14), `overrideCurrentChannel` and
  `setGpioCurrentConfiguration` (8's 0x0095 and 0x00AC);
- what a version does not have yet gets `invalidCommand` as its firmware answers:
  `getNetworkKeyInfo` before 13, the security manager before 12, tokens before 9.

What bellows does at each version, and what decided the range: at **8–13 it completes a whole
session** (`ezsp_legacy_test`: start, permit, interview, On, report, read at every one, and
forming at 8 and 13), reading the network key through `getKey` before 13 and `exportKey` +
`getNetworkKeyInfo` from 13. At **4–7** bellows uses other frame headers (`[seq, 0, id]` at 4,
`[seq, fc, 0xFF, 0, id]` at 5–7) and `networkInitExtended`; those are EmberZNet 5.x–6.3
releases, nobody runs them on a network-attached coordinator, and herdsman never spoke them,
so they are refused at startup (`ezsp_version is 8 to 17`).

Implemented: every command either host sent in the captures below, plus
`getPolicy`, `replaceAddressTableEntry`, `setTokenData`, `setChildData`, `setSourceRoute`,
`removeDevice`, `setRadioPower`, `setLogicalAndRadioChannel` and `lookupEui64ByNodeId`, which
they send on paths the tests do not take. Anything else is answered
`invalidCommand` with `EzspStatus` ERROR_INVALID_FRAME_ID (0x31) in a four-byte
`sl_status_t` — herdsman reads the low byte as an `EzspStatus`, bellows the four bytes as a
status; both raise "invalid command" as they would on firmware. A command before the version is
negotiated gets ERROR_VERSION_NOT_SET (0x30); one whose parameters end early gets
ERROR_INVALID_VALUE (0x36). Two hosts disagree about one v14 encoding: bellows appends a flags
byte to `importTransientKey` and herdsman does not, so it is read when present. Trailing bytes
are ignored everywhere, as firmware does.

What each host sent (frame census logged when a host disconnects, `EZSP commands: …`):

- **bellows `info`** — version ×2, addEndpoint ×2, getMfgToken ×2, networkInit, networkState,
  getEui64, getNodeId, getNetworkParameters, customFrame, getConfigurationValue ×15,
  setConfigurationValue ×12, getCurrentSecurityState, getValue ×2, setValue.
- **bellows `form` + application startup** — adds formNetwork, setInitialSecurityState,
  tokenFactoryReset, clearKeyTable, getTokenData ×6, exportKey ×4, getNetworkKeyInfo ×2,
  exportLinkKeyByIndex ×4, getChildData ×256, getAddressTableInfo ×116,
  getMulticastTableEntry ×16, setPolicy ×3, setConcentrator, setSourceRouteDiscoveryMode,
  readCounters, sendUnicast and sendBroadcast (the coordinator interviewing itself).
- **bellows `permit` + interview** — adds permitJoining ×2, importTransientKey,
  findKeyTableEntry, lookupNodeIdByEui64 ×3, getExtendedTimeout ×5, setExtendedTimeout ×3.
- **herdsman** — version ×2, getValue, setPolicy ×7, setValue ×2, setManufacturerCode,
  setConfigurationValue ×9, getExtendedValue ×2, addEndpoint ×2, setMulticastTableEntry ×3,
  networkInit, getNetworkParameters ×4, getEui64 ×3, exportKey ×5, getNetworkKeyInfo ×2,
  setConcentrator, setSourceRouteDiscoveryMode, importTransientKey, permitJoining ×2,
  clearTransientLinkKeys, sendUnicast ×16, sendBroadcast ×4; forming adds leaveNetwork,
  setInitialSecurityState, clearKeyTable and formNetwork.

Neither host sent a command NetGet answers `invalidCommand` except bellows' `customFrame`
(XNCP), which is answered NOT_SUPPORTED as stock firmware does. A host forming without a
channel configured (zigpy's auto-form) first runs `startScan` (energy scan): every channel
asked is reported at the noise floor (−100 dBm) and the scan completes — there is no radio.

## Z-Stack (ZNP): the firmware emulated, and the command set

**Z-Stack 3.x.0 as Koenkk's CC2652/CC1352 coordinator firmware builds it**: `SYS_VERSION`
transport 2, product 1, release 2.7.1, build 20240710; aligned structs (CC26xx: `NWKKEY` 24
bytes, an associated device 36 — the probes herdsman and zigpy-znp use); the extended NV
system; `APP_CNF` BDB commissioning. zigpy-znp calls it "3.30+", herdsman `ZStack3x0`. Why
this one: it is the firmware the TI coordinators that sit on a network (SLZB-06 in Z-Stack
mode, TubesZB CC2652, ser2net-bridged ZBDongle-P) run; Z-Stack 3.0.x and 1.2 are CC2530/
CC2531 firmwares on USB sticks, and both hosts give 3.x.0 their full path (herdsman's
16-request queue, LED handling, association recovery).

**NV memory is the source of truth**, as on the chip. Both hosts read the network from it
(zigpy-znp: `NIB`, `BDBNODEISONANETWORK`, `NWK_ACTIVE_KEY_INFO`, the `NWK_SEC_MATERIAL_TABLE`
entry, `TCLK_SEED`; herdsman: `HAS_CONFIGURED_ZSTACK3`, `NIB`, `PRECFGKEY`, both key infos)
and form one by writing commissioning items (`PANID`, `EXTENDED_PAN_ID`, `APS_USE_EXT_PANID`,
`PRECFGKEY`, `CHANLIST`) and asking for BDB formation. `Flash` keeps every item a host
writes, answers lengths (0 for a missing item), reads, writes (never past an item's end) and
deletes (only at its length) as Z-Stack does; OSAL ids above 0x03FF cannot be created over MT,
as on Z-Stack 3. A reset applies `STARTUP_OPTION` (0x02 clears the network state, 0x01 the
configuration), clears it, and recreates every item Z-Stack initialises at boot. The shared
network (`Nvram::network`) is derived from the NIB whenever the firmware would read it — at
a reset, a formation, a startup — and a different network erases the joined devices.
A `network` startup parameter is written as the NV a commissioned stick has, including the
`HAS_CONFIGURED_ZSTACK3` flag both hosts leave.

Formation (`APP_CNF_BDB_START_COMMISSIONING` with the formation bit, or `ZDO_STARTUP_FROM_APP`
with no network): the lowest channel of the BDB primary mask (else `CHANLIST`), `PANID`
(random when 0xFFFF), the extended PAN from `APS_USE_EXT_PANID`, else `EXTENDED_PAN_ID`, else
the chip's address, `PRECFGKEY` as the network key; then `ZDO_STATE_CHANGE_IND` 8 and 9 and
the BDB notification SUCCESS. On a formed network the same request brings the node up and
notifies FORMATION_FAILURE, which is what Z-Stack does and what zigpy-znp expects.

What each host sent (census logged when a host disconnects, `MT commands: …`):

- **zigpy-znp, resuming** — SYS_PING×2, SYS_VERSION×2, SYS_OSAL_NV_ITEM_INIT, SYS_OSAL_NV_LENGTH×18,
  SYS_OSAL_NV_READ_EXT×15, SYS_OSAL_NV_WRITE_EXT×2, SYS_NV_LENGTH×3, SYS_NV_READ, AF_REGISTER×2,
  AF_DATA_REQUEST_EXT (ZDO to endpoint 0 and ZCL), ZDO_MGMT_PERMIT_JOIN_REQ×3,
  ZDO_MSG_CB_REGISTER (0xFFFF), ZDO_EXT_ROUTE_DISC, ZDO_EXT_ROUTE_CHK, UTIL_LED_CONTROL,
  UTIL_ASSOC_FIND_DEVICE, APP_CNF_BDB_START_COMMISSIONING, SYS_RESET_REQ×3.
- **zigpy-znp, forming** — adds SYS_OSAL_NV_DELETE, many more NV reads and writes,
  SYS_NV_WRITE, APP_CNF_BDB_SET_CHANNEL×4, BDB commissioning ×4 and SYS_RESET_REQ×7 (it forms a
  temporary network, rewrites the NIB and keys, and resets), after a ZDO energy scan.
- **herdsman zstack, resuming** — SYS_PING×2, SYS_VERSION×3, SYS_GET_EXTADDR×3, OSAL NV
  length/read, SYS_NV_LENGTH/READ (its backup), AF_REGISTER×15, AF_DATA_REQUEST,
  AF_DATA_REQUEST_EXT, ZDO_NODE_DESC_REQ, ZDO_SIMPLE_DESC_REQ (the coordinator's 15 endpoints
  and the device's), ZDO_ACTIVE_EP_REQ, ZDO_MGMT_PERMIT_JOIN_REQ×2, ZDO_STARTUP_FROM_APP,
  ZDO_EXT_FIND_GROUP, ZDO_EXT_ADD_GROUP, ZDO_EXT_NWK_INFO, UTIL_GET_DEVICE_INFO×2,
  UTIL_LED_CONTROL.
- **herdsman zstack, forming** — adds SYS_OSAL_NV_ITEM_INIT, NV writes, APP_CNF_BDB_SET_CHANNEL×2,
  APP_CNF_BDB_START_COMMISSIONING and SYS_RESET_REQ.

Implemented: exactly those, plus what the hosts send on paths the tests do not take —
`SYS_SET_TX_POWER` (zigpy-znp with a TX power configured), `SYS_OSAL_NV_READ` (zigpy-znp's
proxied ids), `SYS_NV_CREATE`/`SYS_NV_DELETE` (zigpy-znp rewriting an extended item),
`AF_DATA_REQUEST_SRC_RTG` (zigpy-znp with a source route), `UTIL_ASSOC_GET_WITH_ADDRESS`
(herdsman's delivery recovery) and the whole `ZDO_*_REQ` family herdsman's generic `sendZdo`
maps onto (address, descriptors, match, bind/unbind, management LQI/routing/binding/leave).
Anything else: an SREQ gets the RPC error SRSP (`[MT_RPC_ERR_SUBSYSTEM | COMMAND_ID | LENGTH,
Cmd0, Cmd1]`, subsystem 0) as the firmware answers a command it was not built with; an AREQ
gets nothing. Neither host sent anything refused (`znp_hosts_test` fails on an `unknown` in the
census).

How the network reaches each host: a device's ZDO answer is the `ZDO_*_RSP` indication
(source address, then the ZDO payload without its sequence number; `ZDO_NWK_ADDR_RSP` and
`ZDO_IEEE_ADDR_RSP` without the source) and, for the clusters the host registered with
`ZDO_MSG_CB_REGISTER`, `ZDO_MSG_CB_INCOMING`; a ZCL frame is `AF_INCOMING_MSG`; a join is
`ZDO_TC_DEV_IND` then `ZDO_END_DEVICE_ANNCE_IND`; a leave `ZDO_LEAVE_IND`. A data request is
answered SRSP SUCCESS, then `AF_DATA_CONFIRM` (SUCCESS when the device exists, NWK_NO_ROUTE
0xCD when not; none for ZDO sent to endpoint 0, as Z-Stack), then the device's answer.
A broadcast `ZDO_MGMT_PERMIT_JOIN_REQ` is applied by the coordinator, which answers its own
`ZDO_MGMT_PERMIT_JOIN_RSP` (zigpy-znp waits for it) and asks the model once.

## The network and the devices — what the model decides

- **The network** is a startup decision: `network` (`channel`, `pan_id`, `extended_pan_id`,
  most significant byte first as zigpy prints it) and `network_key` describe a network already
  in the NCP's flash — it comes up on the host's `networkInit`; without them the NCP has none
  and the host forms one with `formNetwork` (an NCP obeys; it does not choose). A host whose
  configuration differs leaves and re-forms, as herdsman does. Forming or leaving erases the
  joined devices, which go back to waiting.
- **The devices** are described once (`devices`, or inline in `zigbee_join_device`): IEEE and
  NWK address, router/end device/sleepy end device, power source, manufacturer code, endpoints
  with profile, device type, in/out clusters and attribute values; `manufacturer` and `model`
  become Basic attributes 0x0004/0x0005, with ZCL version and power source added. Bounds: 32
  devices, 8 endpoints, 32 clusters per list, 64 attributes per endpoint, 64-byte strings.
- **Joining** — `permitJoining` (EZSP) or a `ZDO_MGMT_PERMIT_JOIN_REQ` the coordinator
  applies (Z-Stack) raises `zigbee_permit_joining` (one model call per opening); each
  `zigbee_join_device` in the answer makes a device join while the network is open:
  `childJoinHandler` for an end device, `trustCenterJoinHandler` (unsecured join,
  preconfigured key) and the device's Device_annce broadcast (Z-Stack: `ZDO_TC_DEV_IND` and
  `ZDO_END_DEVICE_ANNCE_IND`). The host then interviews it.
- **Answered from the description, no model call** — ZDO NWK/IEEE address, Node, Power and
  Simple Descriptor, Active Endpoints, Match Descriptor, Bind/Unbind, Mgmt_Lqi/Rtg (empty),
  Mgmt_Leave (the device answers, then leaves) and Mgmt_Permit_Joining; NOT_SUPPORTED (0x84)
  for any other ZDO request. ZCL Read Attributes (UNSUPPORTED_ATTRIBUTE for what is not
  described, cut to the records one 82-byte frame carries), Configure Reporting, Discover
  Attributes; UNSUPPORTED_CLUSTER (0xC3) for a cluster the endpoint does not serve and
  UNSUP_GENERAL_COMMAND (0x82) for other general commands. The coordinator answers ZDO about
  itself from the endpoints the host registered. Free answers are recorded in the access log as
  `zigbee_zdo_from_description` / `zigbee_zcl_from_description`.
- **The model's** — `zigbee_zcl_request` for cluster commands, attribute writes and
  manufacturer-specific frames. Answers: `zigbee_set_attributes` (stores values; `report: true`
  also sends Report Attributes), `zigbee_default_response` (the status; for a write, the Write
  Attributes Response, and success stores what the host wrote), `zigbee_cluster_response` (a
  response command, payload hex with `encoding: "hex"`), `zigbee_no_response`. Every action is
  checked before any state changes.
- **On request** (dashboard or MCP `send_to_peer`, which reach the session through its peer
  handle): `zigbee_report_attributes`, `zigbee_send_command` (a button press, sent as a client
  command), `zigbee_join_device`, `zigbee_leave_device`.

## Failing closed

Every model failure — backend error, `decision_timeout_secs` (10 s) passing, an answer that is
silent, invalid or of the wrong type, or `MAX_MODEL_CALLS` (8) already in flight — is logged
`decision=fail_closed_llm_error | fail_closed_deadline | model_silent |
fail_closed_invalid_reply | fail_closed_overloaded`, and the device answers as a device whose
application rejected the command: the APS acknowledgement already went out (`messageSentHandler`
SUCCESS, Z-Stack `AF_DATA_CONFIRM` SUCCESS), then **ZCL Default Response with status FAILURE
(0x01)** — sent whatever the
request's disable-default-response bit says, as ZCL requires for errors. A Write Attributes No
Response stays silent. A permit-joining question that fails admits nobody
(`decision=model_reject` when the model chose that).

## Secrets

`network_key` is masked by `src/utils/redact.rs` (`network_key`, `link_key`); keys reach no
event — the permit event carries channel and PAN, never a key. The host's own keys
(`setInitialSecurityState`) stay in the NCP and are given back only to the host
(`exportKey`), as firmware does.

## Bounds

One host connection (`MAX_CONNECTIONS` 1: the NCP has one UART; a second is closed without a
word, neither ASH nor MT having a "busy" frame). MT frames ≤ 250 data bytes (255 whole): an SOF
followed by a larger length is not a frame and is skipped, a frame with a bad FCS is dropped,
neither executed, both counted and only the first eight described in the log. NV: ≤ 512 items
of ≤ 1024 bytes (NV_OPER_FAILED past either), 32 registered endpoints, 16 groups, 64 ZDO
callback registrations. `max_inbound_bytes` declares the larger of the two dialects' frames
(255). ASH frames ≤ 223 bytes unstuffed (`MAX_FRAME`, reported the
moment a frame passes it; before the first RST that closes the connection — the peer is not a
host — afterwards it is NAKed and discarded). EZSP frames ≤ 220 bytes. APS payloads ≤ 82 bytes:
`sendUnicast` of more answers MESSAGE_TOO_LONG. 64 queued callbacks (more sets the response's
overflow bit). One model call at a time, and at most 8 running or waiting. A host silent for an hour is disconnected;
a write the host does not read in 10 s ends the session.

## Not implemented

- EZSP 4–7 (other frame headers, EmberZNet 5.x–6.3; above) and 18+ (bellows has no table past
  17; herdsman's are the same commands for this set).
- Z-Stack 1.2 and 3.0.x (CC2530/CC2531): unaligned structs, the legacy NV tables and SAPI
  reads. Z-Stack's `UTIL_ASSOC_ADD`/`REMOVE` (Koenkk additions both hosts use only to recover
  an end device that changed parent), `ZDO_MGMT_NWK_UPDATE_REQ` over MT (channel change),
  install codes (`APP_CNF_BDB_ADD_INSTALLCODE`) and inter-PAN: RPC error.
- XNCP custom frames, active scans find nothing (no radio), mfglib, Green Power, ZLL/touchlink,
  fragmentation (`AF_INCOMING_MSG_EXT`/`AF_DATA_RETRIEVE`), group membership of devices
  (multicasts are acknowledged and reach nobody), sleepy-device polling behaviour.
- No tshark dissector reads ASH, EZSP or MT/ZNP: checked in 4.2.2 (Ubuntu 24.04, what CI
  installs) and 4.6.9 — `tshark -G protocols` has `zbee_*` over the air, `zep` and
  `silabs-dch`, nothing for a host link — so there is no pcap oracle; the ZCL inside could be
  wrapped in ZEP for `zbee_zcl`, which would be inventing a capture the link never carries.

## Maturity

Experimental: two independent hosts per dialect complete real sessions
(`tests/server/zigbee/AGENTS.md`), but there is no oracle, the Z-Stack dialect and EZSP 8–13
were added after the pair job last ran, and the fuzz targets (`zigbee_ash_ezsp`,
`zigbee_mt`) have not been run at length.
