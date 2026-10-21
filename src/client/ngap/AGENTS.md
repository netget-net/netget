# NGAP client — a gNB

NetGet as a **gNB** on one N2 association with one AMF (TS 38.413 over SCTP, TS 38.412). The
codec, 5GMM subset and transport are the server's (`src/server/ngap/`, read its `AGENTS.md` for
APER, bounds and the transport); this directory is the gNB's session and its actions.

**Status**: `Experimental` — one independent AMF (Open5GS, as a whole core), runnable only where SCTP exists.

## What Rust does and what the model does

- **Connect** opens the association (`transport: "sctp"` default, refused by name without SCTP;
  `"tcp"` is the labelled non-standard lab framing) and performs **NG Setup from the startup
  parameters** — `mcc`, `mnc`, `gnb_id` (`gnb_id_bits` wide), `tac`, `sst`/`sd`,
  `ran_node_name` — the way a real gNB does from its configuration. An NG Setup Failure fails
  the connect with the AMF's cause and Time to Wait in the error; a Response raises
  `ngap_connected` with the AMF's name, GUAMIs and supported PLMNs/slices.
- **The model brings UEs in** with `ngap_initial_ue_message`: a NAS message built from fields —
  usually a Registration Request with a null-scheme SUCI (`plmn`, `routing_indicator`, `msin`)
  or a 5G-GUTI. Rust allocates the RAN UE NGAP ID (or takes the model's), adds the UE security
  capability (5G-EA0-3/5G-IA0-3 unless narrowed) and the cell/TAI from the startup parameters.
- **The model answers the AMF's NAS** (`ngap_downlink_nas_transport`, decoded) with
  `ngap_uplink_nas_transport` for a UE without credentials: Identity Response, Authentication
  Failure, Registration Complete, Deregistration Request, Security Mode Reject, 5GMM Status.
- **A UE with credentials is Rust's** (`ue.rs`): given `supi`, `subscriber_key` and
  `subscriber_opc` (or `subscriber_op`), the UE whose null-scheme SUCI names that subscriber
  verifies the AMF's AUTN (MAC, separation bit, SQN freshness within 2^28 — a stale SQN answers
  Authentication Failure #21 with AUTS), answers RES*, checks the Security Mode Command's MAC
  with the new context and the replayed capabilities against its own, answers Security Mode
  Complete (header 4, IMEISV when asked, the Registration Request retransmitted), answers the
  Initial Context Setup and compares the AMF's K_gNB with its own (`k_gnb_verified`), sends
  Registration Complete, acknowledges a Configuration Update Command that asks, and raises
  `ngap_ue_registered`. The model then asks for sessions with `ngap_pdu_session_request`; Rust
  sends the protected 5GSM request, answers the AMF's PDU Session Resource Setup with a downlink
  tunnel (this gNB's N2 address, a random TEID) and raises `ngap_pdu_session_established`.
  The model's own uplink NAS for a secured UE is protected for it; a downlink message whose MAC
  or COUNT does not verify is discarded with its `decision=` tag. Keys never reach an event.
- **Rust answers without asking**: UE Context Release Command → Release Complete (and
  `ngap_ue_context_release` tells the model), NG Reset → Acknowledge, a PDU that does not decode
  → Error Indication `protocol/transfer-syntax-error` (never shown to the model), an
  unimplemented initiating procedure with criticality reject → Error Indication.

## Bounds

| Bound | Value |
|---|---|
| NG Setup answer | 15 s (`NG_SETUP_TIMEOUT`) |
| Idle association | 3600 s |
| Inbound PDU | 65535 octets; over the lab framing an oversized frame ends the association |
| UEs | 1024 (`MAX_UES`) |
| Model turns | `MAX_FOLLOWUP_DEPTH` 8, **per UE**: each UE remembers how deep the action that last spoke for it was, and the AMF's next answer about that UE is raised at that depth, so a model and an AMF that keep answering each other stop |

## Command channel

Registered after NG Setup; injected actions run in the session task, so they share the UE table
and the RAN UE NGAP ID allocator with the model's.

## Verification

`tests/client/ngap/`: a whole Open5GS 2.8 core over SCTP (Linux) registers the model's UE after
5G-AKA — Open5GS's UDM built the AUTN the UE verified, its AUSF checked the UE's RES*, its AMF
logs `Registration complete` and hands the gNB a K_gNB equal to the UE's own — and its SMF logs
the PDU session it created with the address it gave. Open5GS's `open5gs-amfd` alone accepts NG
Setup, asks an unknown 5G-GUTI for its identity and refuses a foreign PLMN. A canned AMF over
the lab transport covers the follow-up bound, malformed and oversized PDUs, the refused NG
Setup, and asserts on the wire that the identity the AMF receives is the one the model wrote.

Not implemented: a user plane (the gNB names a downlink tunnel but carries no packets), SUCI
concealment on the UE side (null scheme only, though `suci.rs` can conceal), NIA1/NIA3/NEA1/NEA3,
EAP-AKA', handover, paging, service request, UE context modification, PDU session release, RAN
configuration update, more than one AMF per client.
