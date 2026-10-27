# NGAP client — a gNB

NetGet as a **gNB** on one N2 association with one AMF (TS 38.413 over SCTP, TS 38.412). The
codec, 5GMM subset and transport are the server's (`src/server/ngap/`, read its `AGENTS.md` for
APER, bounds and the transport); this directory is the gNB's session and its actions.

**Status**: `Beta` — all four conditions of the client bar in the root `AGENTS.md`: a third-party
server (a whole Open5GS 2.8 core), a test that fails rather than skips without it, a real session
(5G-AKA, registration, a PDU session), and the model's actions asserted from Open5GS's own logs
(the AMF registers the model's SUCI; the SMF creates the session the model asked for). It runs
only where SCTP exists, in the `ngap` pair job. One AMF implementation; not reviewed beyond its
tests.

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
  The Security Mode Command may select 128-NIA1/2/3 with NEA0/1/2/3 (SNOW 3G, AES, ZUC from
  `security`); NIA0 is refused (#24). `ngap_ue_registered.nas_security` names the pair.
  `ngap_pdu_session_request` takes `pdu_session_type` (`ipv4` default, `ipv6`, `ipv4v6`) and
  `ngap_pdu_session_established` reports `ue_ipv4` and/or `ue_ipv6_interface_identifier`
  (the IID as the low half of an IPv6 address, `::3`; the prefix would come in a Router
  Advertisement on a user plane this gNB does not run).
- **The rest of the UE's life** (`procedures.rs`), one event per outcome:
  - `ngap_pdu_session_release {ran_ue_ngap_id, pdu_session_id, cause?}` → protected 5GSM
    Release Request (#36 default) in a UL NAS Transport with no request type. The AMF's PDU
    Session Resource Release Command is answered with a Release Response for the sessions it
    lists (their tunnels dropped), and the Release Command it carries — or one in a plain
    Downlink NAS Transport, network-requested with PTI 0 — with Release Complete:
    `ngap_pdu_session_released {result: released, requested_by: ue|network, cause}`. A Release
    Reject is the same event with `result: rejected`.
  - `ngap_pdu_session_modification {ran_ue_ngap_id, pdu_session_id, five_qi?}` → protected
    Modification Request with a requested QoS flow description (modify, the session's QFI,
    the 5QI). The PDU Session Resource Modify Request is answered with a Modify Response
    naming the QFIs of each session this gNB has (unknown sessions fail with
    `radioNetwork/unknown-PDU-session-ID`), the Modification Command with Modification
    Complete: `ngap_pdu_session_modified {result: modified, requested_by, requested_five_qi,
    five_qi, session_ambr_kbps}`; a Modification Reject is `result: rejected` with the cause.
  - `ngap_ue_context_release_request {ran_ue_ngap_id, cause?}` (default
    `radioNetwork/user-inactivity`) → UE Context Release Request. When a UE Context Release
    Command arrives for a registered UE with credentials and a 5G-S-TMSI (from the
    Registration Accept's 5G-GUTI), its `UeSec` — NAS context, sessions, 5G-S-TMSI, and the
    depth of the last model turn for it — moves to the idle store keyed by SUPI, and
    `ngap_ue_context_release` says `cm_state: idle` with `supi` and `pdu_sessions`. NG Reset
    idles registered UEs the same way.
  - `ngap_service_request {supi, service_type?, pdu_session_ids?}` (`data` default with every
    session in the Uplink data status; `signalling`, `mobile_terminated`) → a new RAN UE NGAP
    ID and an Initial UE Message with the FiveG-S-TMSI IE. The NAS is TS 24.501 4.4.6 as
    UERANSIM v3.2.7 sends it: the whole Service Request (Uplink data status, PDU session
    status) ciphered with the current context **at the COUNT of the outer message** in the
    NAS message container (IEI 0x71); the outer message keeps the cleartext IEs only and goes
    with security header type 1. K_gNB is derived from that COUNT. The Initial Context Setup
    that answers it is compared (`k_gnb_verified`), its sessions set up, and the protected
    Service Accept's PDU session status applied (a session the network no longer has is
    released locally): `ngap_service_accepted {service_type, trigger: ue|paging,
    pdu_session_status, user_plane_sessions, released_locally, k_gnb_verified}`. A Service
    Reject (accepted unprotected while a Service Request is in flight, TS 24.501 4.4.4.2) is
    `ngap_service_rejected`; #9/#10 drop the UE's registration.
  - **Paging** is Rust's: an NGAP Paging whose 5G-S-TMSI is an idle UE's, in a tracking area
    this gNB serves, is answered with that UE's Service Request (mobile terminated) — the
    outcome is `ngap_service_accepted` with `trigger: paging`. Paging for nobody here is logged
    (`decision=paging_not_here`) and ignored.
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
| UEs | 1024 (`MAX_UES`) connected, and 1024 idle (a UE that cannot be kept idle is dropped, `decision=idle_store_full`) |
| Model turns | `MAX_FOLLOWUP_DEPTH` 8, **per UE**: each UE remembers how deep the action that last spoke for it was, and the AMF's next answer about that UE is raised at that depth, so a model and an AMF that keep answering each other stop |

## Command channel

Registered after NG Setup; injected actions run in the session task, so they share the UE table
and the RAN UE NGAP ID allocator with the model's.

## Verification

`tests/client/ngap/`: a whole Open5GS 2.8 core over SCTP (Linux) registers the model's UE after
5G-AKA — Open5GS's UDM built the AUTN the UE verified, its AUSF checked the UE's RES*, its AMF
logs `Registration complete` and hands the gNB a K_gNB equal to the UE's own — and its SMF logs
the PDU session it created with the address it gave. The same core then removes the session
the model releases, gives an IPv4v6 session (the IID matches the SMF's IPv6 address),
releases the UE's context on the gNB's request, accepts the model's Service Request with a
K_gNB equal to the UE's, and answers the UE's modification request — accepted, but with the
subscribed 5QI 9 rather than the 8 asked for (Open5GS 2.8.0 ignores a requested 5QI). Open5GS's `open5gs-amfd` alone accepts NG
Setup, asks an unknown 5G-GUTI for its identity and refuses a foreign PLMN. A canned AMF over
the lab transport covers the follow-up bound, malformed and oversized PDUs, the refused NG
Setup, and asserts on the wire that the identity the AMF receives is the one the model wrote.

NetGet's own AMF over the lab transport (`lifecycle_lab_test`, circular) runs the whole life —
release, an IPv4v6 session, modification, idle, Service Request, paging — under NIA2/NEA0,
NIA1/NEA1 and NIA3/NEA3; it is the only place paging is exercised.

Not implemented: a user plane (the gNB names a downlink tunnel but carries no packets, so no
Router Solicitation and no IPv6 prefix), SUCI concealment on the UE side (null scheme only,
though `suci.rs` can conceal), EAP-AKA', handover, UE context modification, RAN configuration
update, requested QoS rules or packet filters in a modification request, emergency and
high-priority service types, the Service Request timer T3517 and its retries, more than one
AMF per client.
