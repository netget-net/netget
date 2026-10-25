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
- `real_server_test::open5gs_registers_netgets_ue_and_creates_its_pdu_session` (Linux only) —
  a whole Open5GS 2.8 core on 127.0.20.x: MongoDB (`mongod`, the subscriber provisioned with
  `mongosh` in Open5GS's UDR schema, as `open5gs-dbctl` writes it), NRF, AUSF, UDM, UDR, PCF,
  NSSF, BSF, UPF, SMF and AMF, each started with its own config in a temp dir and waited for by
  its own log line (`initialize...done`, `PFCP associated`, `ngap_server()`). NetGet's gNB holds
  the subscriber's K and OPc; the model brings the UE in and, on `ngap_ue_registered`, asks for
  an internet session. Open5GS sends the Registration Accept in a Downlink NAS Transport (its
  TAI list is type 10) and K_gNB later, in the Initial Context Setup that carries the first PDU
  session, so NetGet's gNB answers that ICS with PDUSessionResourceSetupListCxtRes. Asserted:
  `k_gnb_verified` on the session (Open5GS's K_gNB is the UE's own), the AMF's
  `[imsi-001010000000003] Registration complete`, the session `accepted` with a 10.45/16
  address and the UPF's tunnel, the SMF's `UE SUPI[...] DNN[internet] IPv4[<that address>]`, and
  tshark's ngap and nas-5gs dissectors over the capture (NetGet's Authentication Response,
  Security Mode Complete with header type 4, Registration Complete, the 5GSM request; Open5GS's
  Authentication Request, Security Mode Command, Registration Accept and 5GSM accept).
  The same test then runs the rest of the UE's life against Open5GS (the SMF and UPF also have
  `2001:db8:cafe::/48`): the model releases session 1 (`requested_by: ue`; the AMF logs
  `[imsi-001010000000003:1] Receive Update SM context(N2-RELEASED)` and `(N1-RELEASED)`, the
  SMF `Removed Session: UE IMSI:[imsi-001010000000003] DNN:[internet:1]`); asks for an IPv4v6
  session 2 (the SMF logs `UE SUPI[...] DNN[internet] IPv4[<v4>] IPv6[<v6>]` — e.g.
  `2001:db8:cafe:1::2` — and the event's `ue_ipv6_interface_identifier` is the low 64 bits of
  that address); asks the AMF to release the UE's context (`cm_state: idle`; the AMF logs
  `UE Context Release [Action:2]`); and the model's `ngap_service_request` brings it back —
  the AMF logs `5G-S_TMSI[AMF_ID:0x20040,M_TMSI:0x<the 5G-TMSI it assigned>]` and
  `Service request`, its K_gNB equals the one the UE derived from the Service Request's COUNT
  (`k_gnb_verified: true`) and session 2's user plane is set up again. Finally the UE asks for
  5QI 8 on session 2: **Open5GS 2.8.0 accepts the request but does not grant the 5QI** —
  `gsm_handle_pdu_session_modification_qos_flow_descriptions` finds QFI 1 and treats the 5QI
  parameter as "Nothing", the SMF modifies the UPF over PFCP and answers with a PDU Session
  Resource Modify Request whose Modification Command restates QFI 1 with the subscribed 5QI 9,
  no QoS rule and no session AMBR; NetGet answers the Modify Response and Modification Complete
  and raises `ngap_pdu_session_modified {result: modified, requested_five_qi: 8, five_qi: 9}`,
  which is asserted exactly. The capture additionally holds the Release and Modify Responses,
  the UE Context Release Request and Complete, the Service Request (header type 1) and Service
  Accept, and the 5GSM Release Request/Command/Complete and Modification
  Request/Command/Complete, all dissected without a warning. The model's events: 1 connected,
  1 registered, 2 sessions, 1 release, 1 context release, 1 service accept, 1 modification —
  eight model calls for the whole life, none per NAS message. Needs
  root or `cap_net_admin` on `open5gs-upfd` (it creates a TUN). Every network function's output
  is printed when it fails. One full-core test: the fixed 127.0.20.x addresses are its own.
- `lifecycle_lab_test` (macOS and Linux) — NetGet's gNB against **NetGet's own AMF** in-process
  over the lab TCP transport, a relay between them keeping every PDU. Circular: logic, not
  interoperability. A python policy per side: registration, session 1, the UE's release of it
  (`requested_by: ue`, #36), an IPv4v6 session 2 (`::3`), the UE's request for 5QI 8 granted
  by the AMF's model with a new session AMBR, the model's `ngap_ue_context_release_request` →
  `cm_state: idle` → `ngap_service_request` → `ngap_service_accepted` (`k_gnb_verified`, the
  session's user plane back); then the operator's injected context release and the AMF's
  injected `send_paging`, which the UE answers by itself (`trigger: paging`, mobile terminated).
  Run three times: the AMF's default NIA2/NEA0, `nia1`/`nea1` and `nia3`/`nea3`. Asserted: each
  event's fields, the events per type on both sides (the model-call budget: gNB 10 — 1
  connected, 1 registered, 2 established, 1 released, 1 modified, 2 context releases, 2
  service accepts; AMF 6 — NG Setup, registration, 2 sessions, the release and the
  modification request; none for either Service Request or the paging), on the wire the
  Release and Modify Responses, two UE Context Release Requests, one Paging, and two Initial
  UE Messages with FiveG-S-TMSI whose NAS is header type 1 with only cleartext IEs and a NAS
  message container; every PDU through tshark's ngap dissector. The second context release is
  injected because the per-UE follow-up bound (8) would otherwise stop the chain — that is the
  bound working, not a gap.
- `bounds_test` — a canned AMF written with NetGet's own codec over the lab transport: NG Setup
  built from the startup parameters, the identity the AMF receives is the one the model wrote
  (condition 4 of the client bar, asserted on the wire), a refused NG Setup fails the connect
  with the cause and Time to Wait, an AMF that answers forever stops at `MAX_FOLLOWUP_DEPTH`,
  garbage gets an Error Indication and never reaches the model, an oversized frame ends the
  association. NetGet's PDUs go through the pcap oracle.

Mutation-checked: the K_gNB derivation (one off in the uplink COUNT: Open5GS's key differs and
`k_gnb_verified` is false), the UE's RES* (one bit flipped: Open5GS's AUSF rejects and the UE
never registers), the follow-up bound, the client ignoring the model's NAS, the lab frame bound,
and PPID 0 (the Open5GS capture then has nothing NetGet sent that dissects as NGAP).

No LLM calls: python policies stand in for the model.
