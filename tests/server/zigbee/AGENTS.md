# Zigbee co-processor tests

No LLM: every suite starts the server in-process with a python script handler
(`support::POLICY`) as the model and an unreachable LLM endpoint. The policy joins the lamps
when the host permits joining, switches On/Off and reports it, accepts writes, says nothing for
`silent-lamp` and answers `invalid-lamp` with a value NetGet must refuse. What each operation
cost the model is read from the access log: `zigbee_permit_joining` and `zigbee_zcl_request`
are model calls; `zigbee_zdo_from_description` and `zigbee_zcl_from_description` are answers
that cost none. Every host suite asserts the bill: the permit 1, the On command 1, the
interview and the reads 0.

## EZSP (default dialect)

- `codec_test.rs` — ASH against bytes bellows 0.46.2 put on the wire (four DATA frames, ACKs)
  and UG101's RST, decoded and re-encoded byte for byte; CRC and the randomisation sequence;
  the deframer's bound (reported at once, nothing held, a megabyte without a flag), CANCEL,
  SUBSTITUTE, bad escapes, XON/XOFF; EZSP headers; ZDO and ZCL layouts; description bounds.
- `wire_test.rs` — a raw host (`support::Host`, NetGet's own frame builders, assertions on the
  server's bytes): version negotiation in both headers, ERROR_VERSION_NOT_SET,
  ERROR_INVALID_FRAME_ID and ERROR_INVALID_VALUE; a bad CRC NAKed and not executed;
  out-of-sequence NAK, a duplicate re-ACKed and not re-run, retransmission with reTx and the
  ERROR frame after four timeouts; the frame-length bound before and after RST and the one-host
  cap; the interview answered from the description (and the coordinator's own ZDO), DELIVERY_FAILED,
  MESSAGE_TOO_LONG; a cluster command answered by the model with a report, the stored value
  read back free, a report injected through `send_to_peer`; FAILURE for a silent and an
  invalid answer, the invalid one changing nothing; startup-parameter bounds (EZSP 7 and 18
  refused).
- `bellows_test.rs` — bellows' CLI: `info` on a network the model formed, `form` on an empty
  NCP and `info` after it, `permit` with the model's device joining and being interviewed into
  bellows' database, read back with `zigpy_devices.py` (bellows 0.46.2's own `devices` command
  fails under zigpy 0.84 by validating its configuration twice; the script is its body with the
  configuration validated once). Then `zigpy_host.py`, a zigpy application: start, permit,
  interview (model, manufacturer, endpoints, clusters), Basic reads, On, the report, a read
  bypassing the cache.
- `herdsman_test.rs` — `herdsman_host.js` with zigbee-herdsman's `ember` adapter: resuming the
  network the model formed (its configuration matches), and forming one on an empty NCP (its
  open-coordinator backup checked), each through permit, interview, On, report and read.
- `ezsp_legacy_test.rs` — EZSP 8–13 through `legacy.rs`: the zigpy application on bellows at
  every version from 8 to 13 (resuming; the census must show `getKey`/`addTransientLinkKey`
  below 13 and `exportKey`/`getNetworkKeyInfo`/`importTransientKey` at 13), forming on an empty
  NCP at 13 and 8 (after `startScan`), herdsman's `ember` adapter at 13 (its floor), and the
  encodings on raw bytes — one-byte `EzspStatus`/`EmberStatus`, `EMBER_NETWORK_UP` 0x90, the
  v13 `incomingMessageHandler` (no EUI-64) and `messageSentHandler` (8-bit tag, then status),
  v8's `getKey` and its lack of `getNetworkKeyInfo`.

## Z-Stack (`dialect: znp`)

- `mt_codec_test.rs` — MT framing on literal bytes (TI's `SYS_RESET_REQ` example, the PING
  both hosts send, the RPC error), the deframer (bootloader-skip bytes, split reads, a bad
  FCS, the length bomb, a megabyte of SOFs and of noise, one maximal frame held whole), the
  aligned 116-byte NIB at zigpy-znp's offsets, SRSP-for-SREQ-only on `znp::handle`; and the
  EZSP 13 status and layout translations.
- `znp_wire_test.rs` — a raw MT host (`support::MtHost`): identity (`SYS_VERSION`, the EUI,
  device state) after bootloader-skip bytes; the RPC error for a command, a subsystem and a
  truncated SREQ, silence for an unknown AREQ; a bad FCS and an impossible length dropped and
  not executed (and counted in the census); five pipelined SREQs answered in order; NV
  semantics (length, init, write past the end, delete at the wrong length, the 0x03FF OSAL
  limit, the extended security-material entry, reset with STARTUP_OPTION clearing the NIB);
  startup on a formed network, a join (`ZDO_TC_DEV_IND`, `ZDO_END_DEVICE_ANNCE_IND`), the
  interview through ZDO SREQs answered by `ZDO_*_RSP` and `ZDO_MSG_CB_INCOMING` from the
  description, a Basic read over AF, the On command answered by the model with a report, a
  frame to nobody confirmed NWK_NO_ROUTE, a report injected through `send_to_peer`; FAILURE for
  a silent and an invalid answer; a host forming through BDB and the model seeing that
  network; the `dialect` parameter refused when wrong, and an ASH host on a Z-Stack
  co-processor told so in the log.
- `znp_hosts_test.rs` — the two independent Z-Stack hosts: `zigpy_host.py` on zigpy-znp
  0.14.2 resuming the model's network (zigpy-znp must detect Z-Stack 3.30+, a CC2652) and
  forming one on an empty co-processor (after the coordinator answers its energy scan), and
  `herdsman_host.js` with herdsman's `zstack` adapter resuming (`resumed`, `ZStack3x0`, build
  20240710) and forming (`reset`, its backup checked). Each prints the host's MT census and
  fails if the host sent anything the firmware refuses.

All the hosts are required: the tests fail, naming
`sh scripts/test-peers/install-zigbee-hosts.sh <dir>`, when `NETGET_ZIGBEE_BELLOWS_VENV` (the
venv with bellows and zigpy-znp) or `NETGET_ZIGBEE_HERDSMAN` is unset or lacks its host. Every
peer runs with a private HOME and database directory under a per-test temp dir, and prints its
own output when an assertion fails.

Run: `NETGET_ZIGBEE_BELLOWS_VENV=… NETGET_ZIGBEE_HERDSMAN=… ./cargo-isolated.sh test --test server -- zigbee::`
