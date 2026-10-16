# PROFINET device tests

No LLM calls: python script handlers stand in for the model.

| File | Runs on | What |
|---|---|---|
| `codec_test.rs` | everywhere | DCP, RPC, blocks, I&M0, RT frames, layouts and typed values against literal IEC 61158-6-10 layouts; every declared length/count bound |
| `e2e_test.rs` | everywhere | the device over the lab transport, driven by a hand-built controller (`support::LabPeer` frames, `support::RpcPeer` RPC): DCP Identify/Get/Set through the model, Connect (little-endian NDR) → PrmEnd → the device's ApplicationReady → cyclic data → I&M0 read → write → Release; an unreachable model (Set, Connect and Read refused); an accepted AR whose inputs nobody set (IOPS BAD). tshark's pn_dcp/pn_rt read every frame; pn_io's fields are asserted on every RPC datagram (it is a DCE/RPC interface, so `frame.protocols` stops at `dcerpc`) |
| `real_peer_test.rs` | Linux, root | profinet-py (controller) and pnio_dcp (DCP) in a network namespace against the raw transport on a veth; a live tshark capture judges every frame NetGet sent |

`real_peer_test.rs` needs root (CAP_NET_RAW, `ip netns`), tshark, and `python3` on `PATH` with
`profinet-py==0.6.6` and `pnio-dcp==1.2.0`; it fails naming what is missing. CI runs it in the
`profinet` job of `protocol-pairs.yml`, with the test binary run as root through a cargo target
runner (`sudo -E env PATH=…`).
