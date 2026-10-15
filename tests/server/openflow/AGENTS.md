# OpenFlow controller tests

| File | What it proves |
|---|---|
| `codec_test.rs` | The codec alone: spec bytes for the table-miss FLOW_MOD, match round trips with masks and completed prerequisites, refusals, every list bound, the header-length bound, version negotiation, the connection-cap refusal, packet build/describe, and tshark's `openflow_v4` over every message type NetGet encodes (ICMP/ICMPv6 checksums verified inside a PACKET_OUT). |
| `e2e_test.rs` | The controller from a raw switch socket (`support::RawSwitch`): handshake, the model's flows and PACKET_OUTs byte for byte, drop, xid matching and two-part multipart reassembly, error attribution, the follow-up depth (exactly 8 FLOW_MODs), bounds (short header, too many OXMs, echo timeout, oversized multipart), operator injection, the fail-closed paths, and a mocked LLM through the binary (2 calls). |
| `real_peer_test.rs` | **Open vSwitch** (ovsdb-server + ovs-vswitchd with the dummy datapath, unprivileged in a temp dir): the model's flows read back with `ovs-ofctl dump-flows`, packets injected with `netdev-dummy/receive`, transmitted frames read from `tx_pcap` files with tshark, flow statistics, OVS's own `BAD_INSTRUCTION/BAD_TABLE_ID`, the fail-closed path, and tshark over the relay. |

A python policy (`support::POLICY`) plays the model everywhere except the mocked test.

Peers fail rather than skip: `apt-get install openvswitch-switch tshark`. OVS has no Homebrew
formula, so `real_peer_test` fails on macOS; run it on Linux (the `openflow` job in
`.github/workflows/protocol-pairs.yml`, or an `ubuntu:24.04` container).

```bash
./cargo-isolated.sh test --test server -- server::openflow:: --test-threads=8
```
