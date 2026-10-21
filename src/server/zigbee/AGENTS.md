# Zigbee — NetGet as a coordinator's network co-processor (EZSP over ASH, TCP)

NetGet plays the network co-processor (NCP) a Zigbee host talks to: Silicon Labs EZSP carried
by ASH, on a TCP socket, the way network-attached coordinators (SMLIGHT SLZB-06/07, TubesZB,
ser2net-bridged sticks) are used. A host — zigpy's `bellows`, or zigbee-herdsman's `ember`
adapter under Zigbee2MQTT — forms or resumes a network through it and talks to the devices
behind it.

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
- `ncp.rs` — the command set: RAM (negotiated version, configuration values, values, policies,
  host endpoints, initial security state, multicast table, extended timeouts — cleared by a
  reset) and NVRAM (`Nvram`: the formed network and its keys and frame counters, the joined and
  waiting devices, the link-key table — kept across resets and host connections).
- `device.rs` — device descriptions, ZDO and ZCL.
- `mod.rs` — settings, the accept loop (one host at a time), the session (link + EZSP +
  callbacks), model questions, joins and leaves, injected actions.
- `actions.rs` — the protocol: events, actions, startup parameters, metadata.

## EZSP versions and the command set

Versions **14 to 17**, default 17 (`ezsp_version`). Both open hosts accept them: bellows asks
for version 4 in the legacy header and switches to the NCP's; herdsman asks for 19 and switches
to anything from 13. Version 13 is not spoken: it is the last with one-byte EmberStatus results
and the pre-14 layouts of `incomingMessageHandler`, `messageSentHandler`, `exportKey` and the
send commands, a second encoding of a third of the command set. The stack version reported is
the EmberZNet release each version shipped in (`ncp::stack_release`: 17 → 8.1.0).

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
(XNCP), which is answered NOT_SUPPORTED as stock firmware does.

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
- **Joining** — `permitJoining` raises `zigbee_permit_joining` (one model call per opening);
  each `zigbee_join_device` in the answer makes a device join while the network is open:
  `childJoinHandler` for an end device, `trustCenterJoinHandler` (unsecured join, preconfigured
  key) and the device's Device_annce broadcast. The host then interviews it.
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
SUCCESS), then **ZCL Default Response with status FAILURE (0x01)** — sent whatever the
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
word, ASH having no "busy" frame). ASH frames ≤ 223 bytes unstuffed (`MAX_FRAME`, reported the
moment a frame passes it; before the first RST that closes the connection — the peer is not a
host — afterwards it is NAKed and discarded). EZSP frames ≤ 220 bytes. APS payloads ≤ 82 bytes:
`sendUnicast` of more answers MESSAGE_TOO_LONG. 64 queued callbacks (more sets the response's
overflow bit). One model call at a time, and at most 8 running or waiting. A host silent for an hour is disconnected;
a write the host does not read in 10 s ends the session.

## Not implemented

- TI Z-Stack MT (zigpy-znp, herdsman's `zstack`): EZSP took the time.
- EZSP 13 and older (above), and 18+ (bellows has no table past 17; herdsman's are the same
  commands for this set).
- XNCP custom frames, scans (`startScan`), mfglib, Green Power, ZLL/touchlink, source routes,
  fragmentation, group membership of devices (multicasts are acknowledged and reach nobody),
  sleepy-device polling behaviour.
- No tshark dissector reads ASH, EZSP or ZNP (4.6.8 has `zbee_*` over the air, `zep`, and
  `silabs-dch`), so there is no pcap oracle; the ZCL inside could be wrapped in ZEP for
  `zbee_zcl`, which would be inventing a capture the link never carries.

## Maturity

Experimental: two independent hosts complete real sessions (`tests/server/zigbee/AGENTS.md`),
but the pair job had not run in CI when it landed, there is no oracle, and the fuzz target had
not been run at length.
