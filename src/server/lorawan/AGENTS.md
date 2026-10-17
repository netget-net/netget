# LoRaWAN network server

A LoRaWAN 1.0.x network server that gateways reach over the **Semtech UDP packet-forwarder
protocol** (UDP 1700). No radio: the packet forwarder owns the radio and NetGet speaks to the
forwarder, so NetGet works with real gateways running `lora_pkt_fwd`, with ChirpStack's
packet-forwarder simulators, and with NetGet's own gateway client.

Everything is hand-written:

- `semtech.rs` — PROTOCOL.TXT v1/v2: PUSH_DATA → PUSH_ACK, PULL_DATA → PULL_ACK (the
  gateway's downlink path), PULL_RESP (`txpk`, a random token in v2, 0 in v1), TX_ACK and its
  error codes. `rxpk`/`stat`/`txpk` are typed serde structs; the JSON's depth is scanned
  iteratively before serde sees it.
- `mac.rs` — PHYPayload framing; AES-CMAC (RFC 4493, on the `aes` crate) for every MIC; Join
  Request MIC; Join Accept built, MIC'd and *AES-decrypted* (the device encrypts to recover
  it), both lengths (17 and 33 bytes with a CFList); NwkSKey/AppSKey derivation; data MIC
  with the B0 block and the full 32-bit FCnt; FRMPayload keystream; FCnt reconstruction from
  16 bits with MAX_FCNT_GAP; every 1.0.x MAC command decoded by name in both directions.
- `region.rs` — EU868: DR0..DR6 (DR7/FSK refused), the per-DR MACPayload maximum, RX1 (same
  channel, DR − offset) and RX2 (869.525 MHz, DR0), the demodulation floor per SF for
  LinkCheckAns. Only EU868; another region is another table.

## What the model decides, and what it never sees

- `lorawan_join_request {dev_eui, app_eui, dev_nonce, device, gateway, gateways, rssi, snr,
  frequency_mhz, data_rate}` → `lorawan_accept_join` or `lorawan_reject_join`. It is raised
  only after the MIC verified under the configured AppKey, the AppEUI matched and the
  DevNonce was not used before. On accept NetGet assigns a DevAddr (NwkID from `net_id`),
  draws an AppNonce, sends the Join Accept and creates the session.
- `lorawan_uplink {dev_addr, dev_eui, device, confirmed, f_cnt, f_port, payload,
  payload_encoding, mac_commands, ack, max_downlink_payload, gateway, …}` →
  `lorawan_send_downlink {f_port, payload, encoding, confirmed}`,
  `lorawan_request_device_status`, `lorawan_ignore`. Raised only after the MIC verified with
  the full counter and the counter is fresh; the payload is decrypted (text, or hex when it is
  not clean UTF-8).

Keys are configuration (`devices`) and stay in Rust: they are never in an event, and
`src/utils/redact.rs` masks them (`app_key`, `nwk_s_key`, `app_s_key`) wherever startup
parameters are displayed. No base64 reaches the model either way.

The network's own part of the answer is not the model's: a confirmed uplink gets ACK, a
LinkCheckReq gets LinkCheckAns (margin from SNR and SF, gateway count from deduplication), and
a DevStatusReq the model asked for rides the next downlink's FOpts.

## Scheduling

A downlink goes back through the gateway that heard the uplink first, to the address of its
latest PULL_DATA, at that uplink's `tmst` + RECEIVE_DELAY1 (1 s; 5 s for a Join Accept) on
the uplink's channel and data rate. If the model answered too late for RX1 (with a 250 ms
margin) it goes in RX2 (+2 s / +6 s, 869.525 MHz, DR0); later than that, an application
payload stays queued for the device's next uplink and a Join Accept is not sent at all (the
device retries). A real model is often slower than a class A window: queueing is what a real
network server does with an application's late answer too.

Several downlinks in one answer queue (at most 8 per device); each class A window carries
one, with FPending set while more wait. A payload too big for the RX window's data rate waits.

## Failure modes

Deliberately silent: every downlink is a positive assertion — a Join Accept admits a device,
a data downlink speaks for the application — and LoRaWAN has no refusal frame. A model that
fails (`decision=fail_closed_llm_error`), answers with an action NetGet refuses
(`fail_closed_invalid_reply`) or answers nothing (`model_silent`) admits nobody and sends
nothing, not even the network ACK: the device retransmits, as it would through any network
outage. Refusals before the model are tagged too: `fail_closed_unknown_device`,
`fail_closed_bad_mic`, `fail_closed_wrong_app_eui`, `fail_closed_dev_nonce_reused`,
`fail_closed_unknown_dev_addr`, `fail_closed_repeated_fcnt`, `fail_closed_fcnt_replay`,
`fail_closed_busy`, `fail_closed_too_late`, `fail_closed_no_downlink_path`.

PUSH_ACK and PULL_ACK are transport acknowledgements and are sent before anything else.

## Bounds

Datagram ≤ 8 KiB (`lora_pkt_fwd` sends ≤ ~4.6 KiB); ≤ 16 rxpk per PUSH_DATA; JSON depth ≤ 8;
frame data ≤ a 255-byte PHYPayload by its base64 length, then ≤ the data rate's maximum;
≤ 256 devices; ≤ 64 gateways (a gateway silent for 90 s is dropped); ≤ 8 queued downlinks per
device; ≤ 16 model calls in flight (a frame past that is dropped and tagged); 256 DevNonces
remembered per device; copies of one frame within 200 ms are one uplink.

## Not implemented

LoRaWAN 1.1 (separate network keys, JoinNonce rules, rejoin), class B and C, ADR, FSK, any
region but EU868, the Join Server/AS split, Basic Station. A TX_ACK error is logged, not
retried.

## Connections and history

One connection row per gateway (its first datagram's address); the server reaps it, so the
protocol is in `CONNECTIONLESS_EXCEPTIONS`. `call_llm` gets the gateway's connection id, so
`HistoryMode::Last` keeps the recent uplinks of the devices that gateway carries.

## Maturity: Experimental

Evidence (tests/server/lorawan): RFC 4493 and lora-packet vectors; raw packet-forwarder
datagrams for every refusal, bound and fail-closed path; tshark's LoRaWAN dissector verifying
the MIC of the Join Request, the Join Accept, an uplink and a downlink, decrypting both
payloads, with a forged-MIC control; and LWN Simulator (Go, on ChirpStack's `brocaar/lorawan`)
as gateway and device: it joins, decrypts the Join Accept and checks its MIC, sends confirmed
uplinks NetGet decrypts, accepts NetGet's downlink (MIC and counter checked) and answers its
DevStatusReq. It stays Experimental until a person has reviewed it and the `lorawan` pair job has run
green in CI, which had not happened when it landed; the queue and in-flight bounds have no
test of their own yet. Fuzz target: `fuzz/fuzz_targets/lorawan_semtech.rs` (with a depth bomb).
