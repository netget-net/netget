# H.323 server tests

Python policies (`event_handlers` scripts) stand in for the model almost everywhere, and the
fail-closed cases point NetGet at `http://127.0.0.1:1`, where nothing answers. One test,
`e2e_test::a_mocked_model_registers_and_refuses_admission`, runs the NetGet binary against the
mocked LLM (`tests/helpers/mock_ollama.rs`) so the model's own path — `call_llm`, the action
schema, the executor — is exercised: three model calls (open_server, RRQ, ARQ).

| File | What it proves |
|---|---|
| `codec_test.rs` | PER and Q.931 against tshark's h225 dissector (field values, not just "no expert info"); round trips; every peer-controlled bound: a 100 000-level H.245 GenericParameter depth bomb, declared lengths past the data, fragmented lengths, normally-small > 63, oversized TPKT, truncated IEs, too many IEs |
| `e2e_test.rs` | NetGet's own client against its gatekeeper and endpoint, with a live capture: register → admit → fastStart call → tunnelled H.245 → hang up → DRQ; refusals (RRJ, ARJ, busy, forward) reach the client decoded; a model that is down or silent never registers or connects anyone; RAS bookkeeping without the model (retransmission, keep-alive, ARQ from an unregistered endpoint, DRQ, URQ, garbage); a mocked model registering an endpoint on its own terms and refusing its ARQ |
| `real_peer_test.rs` | H323Plus `simph323` registers with NetGet's gatekeeper, is admitted and calls NetGet's endpoint, with fastStart and without it (tunnelled H.245 only), and its console shows the call up and the logical channels; a refused registration and a busy rejection in its own words. Asterisk's `chan_ooh323` (ooh323c) registers, shows itself registered (`ooh323 show gk`), originates a call NetGet admits and answers, and its 4 s tone arrives at NetGet's RTP address; a refused registration appears in ooh323c's own log |

`support.rs` re-exports `tests/helpers/h323.rs` (in-process nodes, `LiveCapture`, frame
assertions); the peers are in `tests/helpers/h323_peers.rs`.

## The capture

`LiveCapture` runs `dumpcap` on loopback (`lo` / `lo0`), then tshark with `-d
udp.port==N,h225` for each RAS port. Call signalling needs no decode-as: Wireshark finds Q.931
in TPKT on any TCP port, and `-d tcp.port==N,tpkt` picks the TPKT heuristic meant for RDP, after
which nothing is dissected as H.225.0. Capture needs permission: root, `setcap
cap_net_raw,cap_net_admin=eip` on dumpcap, or `access_bpf` on macOS. Missing is a failure.
`NETGET_H323_PCAP_DIR=<dir>` keeps every capture for Wireshark.

Against third-party peers only NetGet's own frames are judged (`assert_netget_clean`): the peer's
frames are dissected — they are what NetGet decoded — but Wireshark's own defects on them are not
NetGet's.

**Use tshark 4.4 or newer.** Ubuntu 24.04's 4.2.2 trips its own `recursion_depth <= 100`
assertion in the h225 and h245 dissectors on ordinary messages from both H323Plus and NetGet;
4.6 dissects the same captures cleanly. CI takes tshark from the Wireshark stable PPA.

## Running

The peers are Linux-only in practice (Asterisk's packages; GnuGk and simph323 built from source):

```bash
sudo apt-get install asterisk asterisk-ooh323 tshark   # tshark >= 4.4 (ppa:wireshark-dev/stable)
python3 tests/server/h323/install_peers.py /opt/h323    # gnugk + simph323 → /opt/h323/bin
export PATH=/opt/h323/bin:$PATH
cargo test --no-default-features --features tcp,h323 --test server -- h323:: --test-threads=4
```

`codec_test` and `e2e_test` need only tshark and capture rights, and run on macOS too.

Asterisk's gatekeeper client always talks to port 1719, so the two Asterisk-gatekeeper tests
bind NetGet's gatekeeper there and take turns (`PORT_1719`). chan_ooh323 needs a few modules an
`autoload=no` Asterisk does not load by itself: `res_pjproject` (for `res_rtp_asterisk`),
`res_clioriginate` (`channel originate`), `func_timeout`, and `res_timing_timerfd` — without a
timing source Milliwatt generates nothing and no RTP is sent.
