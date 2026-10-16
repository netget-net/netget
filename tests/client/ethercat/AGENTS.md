# EtherCAT master tests

No LLM calls: python script handlers stand in for the model.

| File | Runs on | What |
|---|---|---|
| `e2e_test.rs` | everywhere | the master against NetGet's own slave over EtherCAT-in-UDP — scan, SII, CoE PDO layout, SAFE-OP, outputs, OP, the slave's model answering the outputs through the inputs, SDO reads (one segmented) and writes (one aborted); with an unreachable model nothing moves, and OP is refused until outputs are set. Self-served: plumbing, not independent evidence |
| `real_server_test.rs` | Linux, root | KickCAT's `network_simulator` running its emulated CiA 402 drive on a veth: scan (identity from its SII), CoE PDO layout, SAFE-OP, OP, 0x1018 over SDO, and the CiA 402 enable sequence driven by the model until the drive's statusword reports operation enabled; a live tshark capture judges every frame NetGet sent |

The support module is the server suite's (`tests/server/ethercat/support.rs`, included by path).
`real_server_test.rs` needs root, tshark, `network_simulator` on `PATH` and `KICKCAT_CONFIGS`
naming KickCAT's `simulation/slave_configs` — `scripts/test-peers/build-kickcat.sh` builds and
prints both. CI runs it in the `ethercat` job of `protocol-pairs.yml`.
