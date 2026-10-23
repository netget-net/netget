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
  Authentication Request, Security Mode Command, Registration Accept and 5GSM accept). Needs
  root or `cap_net_admin` on `open5gs-upfd` (it creates a TUN). Every network function's output
  is printed when it fails. One full-core test: the fixed 127.0.20.x addresses are its own.
- `bounds_test` — a canned AMF written with NetGet's own codec over the lab transport: NG Setup
  built from the startup parameters, the identity the AMF receives is the one the model wrote
  (condition 4 of the client bar, asserted on the wire), a refused NG Setup fails the connect
  with the cause and Time to Wait, an AMF that answers forever stops at `MAX_FOLLOWUP_DEPTH`,
  garbage gets an Error Indication and never reaches the model, an oversized frame ends the
  association. NetGet's PDUs go through the pcap oracle.

Mutation-checked: the K_gNB derivation (Open5GS's key then differs and `k_gnb_verified` is false), the RES* computation (Open5GS's AUSF rejects), the follow-up bound, the client ignoring the model's NAS, the lab frame bound,
and PPID 0 (the Open5GS capture then has nothing NetGet sent that dissects as NGAP).

No LLM calls: python policies stand in for the model.
