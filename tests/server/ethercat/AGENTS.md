# EtherCAT slave tests

No LLM calls: python script handlers stand in for the model.

| File | Runs on | What |
|---|---|---|
| `codec_test.rs` | everywhere | frames and datagrams against literal IEC 61158 layouts; working counters of every command; position, station and alias addressing; read-only registers; the SII through the EEPROM registers and its parser; the AL state machine's refusals and codes; FMMU mapping down to single bits; mailbox SyncManager rules and the repeat request; CoE SDO layouts, the SDO server, segmented transfers; every declared bound |
| `e2e_test.rs` | everywhere | ethercrab 0.7 over EtherCAT-in-UDP (`support::crab` re-encapsulates its Ethernet frames and changes nothing else): scan, identity and name from the SII, SDOs answered by Rust and by the model, a write the model aborts, a 58-octet string in one normal transfer, SAFE-OP, working counter 3, the model's inputs, OP, the model answering the outputs; an unreachable model (state change refused 0x0001, SDO aborted 0x08000020); frames over the 64-datagram bound and with a lying header get no answer. tshark's ecatf/ecat/ecat_mailbox read every payload both ways |
| `real_peer_test.rs` | Linux, root | SOEM 2.0.1 `slaveinfo -map` and `simple_ng`, and ethercrab on its own raw socket, against the raw transport on a veth; a live tshark capture judges every frame NetGet sent |

`real_peer_test.rs` needs root (raw sockets, `ip link`), iproute2, tshark, and SOEM's
`slaveinfo` and `simple_ng` on `PATH` (`scripts/test-peers/build-soem.sh`); it fails naming what
is missing. CI runs it in the `ethercat` job of `protocol-pairs.yml`, with the test binary run as
root through a cargo target runner.
