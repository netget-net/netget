# LoRaWAN server tests

No LLM: every suite starts the server with a python script handler (`support::POLICY`) and an
unreachable model, so an event the script does not answer is the fail-closed path. Zero model
calls.

- `codec_test.rs` — AES-CMAC against RFC 4493's four vectors; lora-packet's README uplink
  (MIC, decryption, and NetGet re-encoding it byte for byte); Join Request/Accept round trips
  and tampering; FCnt reconstruction across the wrap and past MAX_FCNT_GAP; MAC command
  decoding; the EU868 table; packet-forwarder bounds (depth bomb, size, rxpk count, base64
  length, versions, TX_ACK with and without JSON).
- `e2e_test.rs` — a raw packet forwarder (`support::Forwarder`, one socket up and one down as
  `lora_pkt_fwd`) against the server: join and RX1 timing, uplink → downlink, replay, confirmed
  + LinkCheckReq + DevStatusReq, DevStatusAns decoded, the downlink queue and FPending,
  silent and invalid model answers, forged MIC, counter gap, DevNonce reuse, re-join ending the
  old session; refused/silent/invalid/unknown/forged/wrong-AppEUI joins; a model failure;
  datagram bounds (16 vs 17 rxpk, 8 KiB, depth, version, DR0 payload limit, CRC-bad, the
  64-gateway cap); and the tshark oracle — LoRaTap (linktype 270) records of the four frames
  and a forged control, dissected with the keys passed as `uat:root_keys_lorawan` and
  `uat:session_keys_lorawan`.
- `lwn_test.rs` — LWN Simulator against the server (see `src/server/lorawan/AGENTS.md`). It
  fails, naming `scripts/test-peers/build-lwn-simulator.sh`, when `NETGET_LWN_SIMULATOR` is
  unset and `lwnsimulator` is not on PATH. LWN numbers EU868 as region 1, reads `config.json`
  from its working directory, and logs to stderr; the test asserts on that log ("Joined",
  "Downlink Received", none of brocaar/lorawan's refusals) and on the events NetGet raised.

Run: `./cargo-isolated.sh test --no-default-features --test server -- lorawan::`
