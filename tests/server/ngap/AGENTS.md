# NGAP tests (AMF role)

`install_peers.py <dir>` builds UERANSIM v3.2.7 (`nr-gnb`, `nr-ue`, `nr-cli`) (tarball SHA-256 pinned; needs cmake, g++,
libsctp-dev) and prints `NETGET_UERANSIM_DIR`. The real-peer tests also need a kernel with SCTP
(`sudo modprobe sctp`), and `dumpcap`/`tshark` allowed to capture on loopback (root, or
`sudo setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)`). They **fail**, not skip,
without any of them. `real_client_test.rs` is compiled on Linux only (`mod.rs`): UERANSIM is
Linux software and macOS has no SCTP.

- `real_client_test::ueransim_sets_up_n2_and_its_ue_is_challenged_and_rejected` — `nr-gnb` sets
  up N2 with NetGet's AMF over SCTP; `nr-ue` registers with a null-scheme SUCI; the policy (a
  python handler standing in for the model) sends an Authentication Request whose AUTN the UE
  cannot verify; the UE logs `Sending Authentication Failure with cause [MAC_FAILURE]`, then
  `Initial Registration failed [ILLEGAL_UE]` from the model's reject; the gNB logs the release.
  `ignoreStreamIds` is left false, so UERANSIM also checks NetGet's stream selection. The model's
  events are asserted to carry UERANSIM's gNB id and the UE's SUCI fields decoded. A live capture
  is read by tshark: no Warn expert info, PPID 60 on every chunk, each procedure present in both
  directions.
- `real_client_test::ueransim_registers_gets_a_pdu_session_and_pings_through_the_tunnel` — the
  AMF holds the subscriber's K/OPc and the TS 33.501 C.4.3 home network key; UERANSIM's UE
  conceals its SUCI with ECIES Profile A, verifies NetGet's AUTN, accepts the Security Mode
  Command, logs `Initial Registration is successful` and `PDU Session establishment is
  successful`, brings `uesimtun*` up with the model's 10.60.0.2, and `ping -I uesimtun*` to the
  model's 10.60.0.1 gets three replies from NetGet's user plane through nr-gnb's GTP-U (an
  address the model did not choose gets none). `nr-cli ... deregister normal` then deregisters
  it under security. The model's events are exactly one NG Setup, one registration decision
  and one PDU session decision. The capture is read by tshark's ngap dissector (Initial
  Context Setup and PDU Session Resource Setup both ways) and nas-5gs dissector with
  `null_decipher` (every 5GMM message of the procedure, header types 3 and 4, the 5GSM accept).
  `nr-ue` builds its TUN only when `geteuid()` is 0 — UERANSIM checks that itself, so a
  capability cannot stand in (the first CI run proved it: CAP_NET_ADMIN on nr-ue, then
  `TUN interface could not be setup. Permission denied`). Root runs it directly, anyone else
  through `sudo -n` (passwordless on GitHub runners), killed afterwards by its config path.
  A failure prints `id`, `sudo -n true`, `getcap` of nr-ue and ip, `/dev/net/tun` and the
  mount options of nr-ue's directory.
- `real_client_test::ueransim_reports_the_models_ng_setup_failure` — the model's
  `misc/unknown-PLMN-or-SNPN` is what `nr-gnb` logs (asn1c calls the Rel-15 value
  `unknown-PLMN`).
- `security_test` — Milenage (TS 35.208 set 1), NIA2 and NEA2 (TS 33.401 Annex C), SUCI
  Profiles A and B (TS 33.501 C.4.3/C.4.4) against published vectors; the 5G-AKA round trip and
  the shape of each KDF output; the protected-message rules (header 3 never ciphered, NEA0
  readable, NEA2 not, replay and MAC refusal without advancing the COUNT, sequence wrap); the
  ICMP echo reply.
- `security_e2e_test` — the AMF with credentials over the lab transport with a scripted UE (from
  NetGet's own `security`, so not interoperability evidence): the whole registration, PDU
  session, echo through the GTP-U user plane and deregistration with a mocked model held to
  **three calls**; NEA2; a forged MAC, an unprotected message after security and a replayed
  COUNT discarded with their tags; no user plane → #26; silent and failed models → protected
  Registration Reject and 5GSM #31; wrong RES* and the UE's MAC failure → Authentication
  Reject without a model call; a stale SQN resynchronised from AUTS; an unknown subscriber
  left to the model; K and OPc in no event and no status line. tshark reads every PDU.
- `codec_test` — UERANSIM's captured NG Setup Request, decoded and re-encoded octet for octet;
  hand-derived X.691 vectors (comment per field); the 5GMM subset against TS 24.501 literals;
  every decode bound; NetGet's PDUs through the pcap oracle inside SCTP DATA chunks with PPID 60.
- `e2e_test` — the AMF over the lab TCP transport, in-process: a scripted policy end to end, the
  mocked model (2 LLM calls), every fail-closed path (failed model, silent policy, no policy, for
  NG Setup and for a UE), protocol refusals without the model, the oversized lab frame, the UE
  table cap (all 4096 contexts filled).
- `transport_test` — SCTP binds or is refused by name; where it exists, whole messages and an
  oversized one drained without losing the next boundary.

Mutation-checked in the NAS-security pass, each a run-time switch built once and run against
the suites in the Linux container: accepting any RES* (`a_wrong_res_star…` fails); skipping
uplink MAC verification and accepting a replayed COUNT (`nea2_ciphers…` and
`security_test::nas_protection…` fail); a silent model's registration left unrejected
(`a_silent_model…` fails); dropping the model's PDU session accept (`a_subscriber_registers…`
and UERANSIM's `ueransim_registers…`, "got no PDU session", fail); corrupting every downlink
MAC (UERANSIM logs `Security Mode Command integrity check failed` and never registers);
redaction without the `subscriber_*` parts (`secret_redaction_test` fails). A wrong K_gNB is
**not** caught here: UERANSIM implements no AS security and never checks it — Open5GS's
K_gNB, compared on the client side, is the check. Earlier: the IE-count, list-budget and NAS-PDU bounds; the UE cap; the lab frame
bound; both fail-closed paths turned fail-open; the Cause CHOICE encoded with an extension bit
(UERANSIM reads the cause as `nas/authentication-failure`); UE-associated signalling on stream 0
(UERANSIM drops it); PPID 0 (the capture stops dissecting as NGAP — neither peer checks it).
Each fails a test here.
