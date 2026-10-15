# H.323 client tests

`real_server_test.rs` points NetGet's H.323 client at third-party servers; a python policy
stands in for the model (LLM calls: zero).

- **GNU Gatekeeper** 5.16 (H323Plus 1.28.0): GRQ/GCF, RRQ/RCF — and NetGet in GnuGk's own
  `PrintAllRegistrations` on its status port — ARQ/ACF to H323Plus `simph323` registered as
  `bob`, a fastStart call simph323 auto-answers, Release Complete, DRQ/DCF, URQ/UCF and NetGet
  gone from the table. An alias nobody registered: ARJ, reported as `h323_call_failed`.
- **Asterisk 20 `chan_ooh323`** (ooh323c), no gatekeeper: NetGet calls it directly, Asterisk
  answers from its dialplan and plays a 4 s tone, then releases (cause 16). The tone's RTP
  arrives at the address NetGet's fastStart offer named (`rtp_packets_received`).

Every message NetGet sent is read by tshark from a live capture (`assert_clean_towards`). The
harness is `tests/helpers/h323.rs` and `tests/helpers/h323_peers.rs`; how to install the peers,
and why tshark must be 4.4 or newer, is in `tests/server/h323/AGENTS.md`.

```bash
cargo test --no-default-features --features tcp,h323 --test client -- h323:: --test-threads=4
```
