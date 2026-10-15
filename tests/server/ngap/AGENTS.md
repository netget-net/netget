# NGAP tests (AMF role)

`install_peers.py <dir>` builds UERANSIM v3.2.7 (tarball SHA-256 pinned; needs cmake, g++,
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
- `real_client_test::ueransim_reports_the_models_ng_setup_failure` — the model's
  `misc/unknown-PLMN-or-SNPN` is what `nr-gnb` logs (asn1c calls the Rel-15 value
  `unknown-PLMN`).
- `codec_test` — UERANSIM's captured NG Setup Request, decoded and re-encoded octet for octet;
  hand-derived X.691 vectors (comment per field); the 5GMM subset against TS 24.501 literals;
  every decode bound; NetGet's PDUs through the pcap oracle inside SCTP DATA chunks with PPID 60.
- `e2e_test` — the AMF over the lab TCP transport, in-process: a scripted policy end to end, the
  mocked model (2 LLM calls), every fail-closed path (failed model, silent policy, no policy, for
  NG Setup and for a UE), protocol refusals without the model, the oversized lab frame, the UE
  table cap (all 4096 contexts filled).
- `transport_test` — SCTP binds or is refused by name; where it exists, whole messages and an
  oversized one drained without losing the next boundary.

Mutation-checked: the IE-count, list-budget and NAS-PDU bounds; the UE cap; the lab frame
bound; both fail-closed paths turned fail-open; the Cause CHOICE encoded with an extension bit
(UERANSIM reads the cause as `nas/authentication-failure`); UE-associated signalling on stream 0
(UERANSIM drops it); PPID 0 (the capture stops dissecting as NGAP — neither peer checks it).
Each fails a test here.
