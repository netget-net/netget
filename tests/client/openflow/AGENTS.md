# OpenFlow switch tests

| File | What it proves |
|---|---|
| `e2e_test.rs` | The switch against a raw controller: FEATURES, ECHO, config, ROLE, DESC/PORT_DESC, BAD_MULTIPART; FLOW_MOD validation (BAD_PREREQ, BAD_OUT_PORT, BAD_TABLE_ID), the flow table and non-strict delete; TABLE_FULL at `MAX_FLOWS` and FLOW replies split under 64 KiB; PACKET_OUT checks (BUFFER_UNKNOWN, BAD_PORT) and reporting; the model's PACKET_IN and PORT_STATUS on the wire; the model's answer acted on, and nothing sent when it cannot answer; a 1.0-only controller refused. |
| `real_server_test.rs` | **os-ken 4.2.2** running a learning switch on its OpenFlow 1.3 API, and **Open vSwitch's `ovs-testcontroller`**: the table-miss FLOW_MOD arrives, the model's ping is flooded, its reply is sent to the learned port with a learned flow; os-ken's own log shows what it decoded from NetGet's FEATURES, PORT_DESC and PACKET_INs; tshark reads both directions; with an unreachable model os-ken sees no PACKET_IN. |

`support::POLICY` (python) plays the model. Peers fail rather than skip:
`pip install 'os-ken==4.2.2'` and `apt-get install openvswitch-testcontroller tshark`
(`ovs-testcontroller` has no Homebrew formula; run on Linux).

```bash
./cargo-isolated.sh test --test client -- client::openflow:: --test-threads=8
```
