# NGAP client — a gNB

NetGet as a **gNB** on one N2 association with one AMF (TS 38.413 over SCTP, TS 38.412). The
codec, 5GMM subset and transport are the server's (`src/server/ngap/`, read its `AGENTS.md` for
APER, bounds and the transport); this directory is the gNB's session and its actions.

**Status**: `Experimental` — one independent AMF (Open5GS), runnable only where SCTP exists.

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
  `ngap_uplink_nas_transport`: Identity Response, Authentication Failure, Registration Complete,
  Deregistration Request, Security Mode Reject, 5GMM Status. It cannot answer an Authentication
  Request successfully: RES* needs the subscriber key and the AKA derivations, which are out of
  scope (see the server's `AGENTS.md`).
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

`tests/client/ngap/`: Open5GS 2.8.0's `open5gs-amfd` alone over SCTP (Linux) accepts NG Setup,
decodes the model's Initial UE Message, asks the model's unknown 5G-GUTI for its identity, and
logs the model's SUCI as the UE it then handles; a gNB with a PLMN it does not serve is refused
and the connect fails with that cause. A canned AMF over the lab transport covers the follow-up
bound, malformed and oversized PDUs, the refused NG Setup, and asserts on the wire that the
identity the AMF receives is the one the model wrote.

Not implemented: PDU session resource procedures and the user plane (GTP-U), handover, paging,
UE context modification, RAN configuration update, more than one AMF per client.
