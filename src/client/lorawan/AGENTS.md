# LoRaWAN gateway client

A Semtech UDP packet forwarder (the server's `semtech.rs`, `mac.rs` and `region.rs`) carrying
simulated LoRaWAN 1.0.x devices from the `devices` startup parameter to a network server.
No radio: the devices are simulated, the gateway forwards their frames.

Gateway side: PULL_DATA on connect (connecting fails unless it is acknowledged) and every
`keepalive_secs`; PUSH_DATA with one `rxpk` per device frame and a `stat` every
`stat_interval_secs`; every PULL_RESP is answered with a TX_ACK whose error a concentrator
would give: `TX_FREQ` off the EU868 band, `TX_POWER` above 27 dBm, `TOO_LATE` for a `tmst`
behind the gateway's own microsecond counter, `GPS_UNLOCKED` for a GPS-timed one. A refused
downlink is not delivered to its device.

Device side, per configured device: a Join Request with a fresh DevNonce (never reused),
the Join Accept decrypted and its MIC checked under the device's AppKey (both 17 and 33 byte
forms), session keys derived; uplinks numbered, encrypted, signed; downlinks checked (MIC,
fresh counter within MAX_FCNT_GAP), decrypted and raised. A confirmed downlink makes the next
uplink carry ACK; a DevStatusReq makes it carry DevStatusAns (battery from the action, margin
from its `snr`). ABP devices start with their session.

Actions: `lorawan_send_join_request {device}`, `lorawan_send_uplink {device, f_port, payload,
encoding, confirmed, link_check, battery}` (both with optional radio metadata
`frequency_mhz`, `data_rate`, `rssi`, `snr`), `disconnect`. Events:
`lorawan_gateway_connected`, `lorawan_join_accepted`, `lorawan_downlink`. Keys never reach
the model. The command channel takes the same actions (`send_to_client`).

The chain bound counts across the air: a device's frame records how deep in a handler chain
it was sent, and the network's answer to it continues that depth, so a device and a network
that answer each other forever stop after 8 follow-ups. A handler that fails sends nothing.

Bounds: datagrams ≤ 8 KiB, JSON depth ≤ 8, payloads by the data rate's maximum, ≤ 256
devices, 256 DevNonces per device.

Evidence: tests/client/lorawan — NetGet's own network server (join, confirmed uplink with
LinkCheckReq, ACK and DevStatusAns, ABP, refusals), a raw network server written in the test
(TX_ACK codes, forged Join Accept, forged/replayed/far-ahead downlinks, the follow-up bound),
and ChirpStack v4 with its Gateway Bridge, Mosquitto and Redis (real_server_test.rs, Linux):
ChirpStack accepts the join, decrypts the uplink into its MQTT application events, sends a
downlink queued through its API that NetGet verifies and decrypts, and records NetGet's
TX_ACK. Experimental: one independent network server, and the pair job had not run in CI
when it landed.
