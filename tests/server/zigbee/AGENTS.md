# Zigbee co-processor tests

No LLM: every suite starts the server in-process with a python script handler
(`support::POLICY`) as the model and an unreachable LLM endpoint. The policy joins the lamps
when the host permits joining, switches On/Off and reports it, accepts writes, says nothing for
`silent-lamp` and answers `invalid-lamp` with a value NetGet must refuse. What each operation
cost the model is read from the access log: `zigbee_permit_joining` and `zigbee_zcl_request`
are model calls; `zigbee_zdo_from_description` and `zigbee_zcl_from_description` are answers
that cost none.

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
  invalid answer, the invalid one changing nothing; startup-parameter bounds.
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

Both peers are required: the tests fail, naming
`sh scripts/test-peers/install-zigbee-hosts.sh <dir>`, when `NETGET_ZIGBEE_BELLOWS_VENV` or
`NETGET_ZIGBEE_HERDSMAN` is unset. Every peer runs with a private HOME and database directory
under a per-test temp dir, and prints its own output when an assertion fails.

Run: `NETGET_ZIGBEE_BELLOWS_VENV=… NETGET_ZIGBEE_HERDSMAN=… ./cargo-isolated.sh test --test server -- zigbee::`
