# PROFINET controller tests

No LLM calls: python script handlers stand in for the model.

| File | Runs on | What |
|---|---|---|
| `e2e_test.rs` | everywhere | the controller against NetGet's own device over the lab transport — discovery, Connect with a parameter write, cyclic data both ways, I&M0, Release, DCP rename and re-identify; and with an unreachable model, that nothing is sent and the device sees the outputs BAD. Self-served: plumbing, not independent evidence |
| `real_server_test.rs` | Linux, root | rt-labs' p-net sample device (`pn_dev`) in a network namespace: DCP rename and re-identify, Connect with its DAP, DI, DO and echo modules writing the echo gain before PrmEnd, its counter input, its data LED file lit by output bit 7, the echo module answering output × gain, I&M0, Release; a live tshark capture judges every frame NetGet sent |

`real_server_test.rs` needs root, tshark, and `pn_dev` on `PATH` with its two scripts beside it —
`scripts/test-peers/build-pnet.sh` builds it (pinned p-net tree, two patches it explains). CI runs
it in the `profinet` job of `protocol-pairs.yml`.
