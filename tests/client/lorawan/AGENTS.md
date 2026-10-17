# LoRaWAN client tests

No LLM: static handlers drive the gateway, and NetGet's network server (when used) runs a
python policy.

- `e2e_test.rs` — against NetGet's own network server: join, confirmed uplink with
  LinkCheckReq answered by ACK + LinkCheckAns + DevStatusReq, the next uplink carrying ACK and
  DevStatusAns, an ABP device, and actions refused before sending. Against a raw network
  server in the test: TX_ACK `TX_FREQ`, `TX_POWER`, `TOO_LATE`, a Join Accept under the wrong
  key ignored, a 33-byte Join Accept accepted, forged / replayed / far-ahead downlinks
  dropped. And the follow-up bound with a network and a device answering each other forever.
- `real_server_test.rs` — ChirpStack v4 (SQLite build) with its Gateway Bridge, Mosquitto
  and Redis, provisioned with `chirpstack_peer.py` (the official `chirpstack-api` gRPC
  client). Linux only (ChirpStack ships Linux binaries); it fails, naming
  `scripts/test-peers/install-chirpstack.sh`, when `NETGET_CHIRPSTACK`,
  `NETGET_CHIRPSTACK_GATEWAY_BRIDGE` or `NETGET_CHIRPSTACK_PYTHON` is unset. ChirpStack reads
  every `*.toml` in its config directory, so the bridge's config lives in a directory of its
  own.

Run: `./cargo-isolated.sh test --no-default-features --test client -- lorawan::`
