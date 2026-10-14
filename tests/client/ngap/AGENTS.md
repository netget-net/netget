# NGAP tests (gNB role)

Shares `support.rs` with the server suite (`#[path]` in `mod.rs`).

- `real_server_test` (Linux only) — Open5GS's `open5gs-amfd` (Ubuntu: `open5gs-amf` from
  `ppa:open5gs/latest`; 2.8.0 at the time of writing) runs **alone** on probed ports with its NRF
  pointed at nothing: NG Setup needs no other network function. NetGet's gNB sets up N2, the
  model's Initial UE Message carries a 5G-GUTI the AMF never issued, the AMF answers with an
  Identity Request (decoded for the model), the model answers with a SUCI, and the AMF's own log
  names that SUCI (`suci-0-001-01-0000-0-0-0000000123`) as the UE it then handles — authentication
  stops there because there is no AUSF. A gNB with PLMN 999-70 is refused NG Setup and the
  connect fails with the AMF's cause. The live capture is read by tshark as in the server suite.
  Fails, not skips, without `open5gs-amfd`, SCTP, dumpcap or tshark.
- `bounds_test` — a canned AMF written with NetGet's own codec over the lab transport: NG Setup
  built from the startup parameters, the identity the AMF receives is the one the model wrote
  (condition 4 of the client bar, asserted on the wire), a refused NG Setup fails the connect
  with the cause and Time to Wait, an AMF that answers forever stops at `MAX_FOLLOWUP_DEPTH`,
  garbage gets an Error Indication and never reaches the model, an oversized frame ends the
  association. NetGet's PDUs go through the pcap oracle.

Mutation-checked: the follow-up bound, the client ignoring the model's NAS, the lab frame bound,
and PPID 0 (the Open5GS capture then has nothing NetGet sent that dissects as NGAP).

No LLM calls.
