# NGAP (5G N2) — AMF

NG Application Protocol, [3GPP TS 38.413](https://www.3gpp.org/DynaReport/38413.htm), over
SCTP per TS 38.412. NetGet plays the **AMF**; the peer is a **gNB**. The gNB role is
`src/client/ngap/`, which shares everything in this directory except `mod.rs` and `actions.rs`.

**Status**: `Experimental` — see [Maturity](#maturity).

**Port**: SCTP 38412, PPID 60. Above 1023 and SCTP is an ordinary kernel transport, so
`PrivilegeRequirement::None`.

## Layout

| File | Role |
|---|---|
| `aper.rs` | ALIGNED PER (X.691) reader and writer: constrained whole numbers, length determinants, open types, extension skipping. Bounded, non-recursive. |
| `codec.rs` | NGAP PDU framing, every IE of the procedures implemented, Cause, message builders and parsers. Shared with the client. |
| `nas.rs` | 5GMM (TS 24.501): decode for the model, encode from structured actions, and the structured parsers/builders the security procedures use. Shared with the client. |
| `sm.rs` | 5GSM: PDU Session Establishment, Modification and Release messages, PDU addresses (IPv4, IPv6 interface identifier, both), causes. Shared with the client. |
| `security.rs` | Milenage, the 5G-AKA key hierarchy, NIA1/2/3 and NEA0/1/2/3, protected-message framing with COUNTs. Shared with the client. |
| `snow3g.rs`, `zuc.rs` | SNOW 3G (128-EIA1/EEA1) and ZUC (128-EIA3/EEA3), from the ETSI/SAGE specifications, checked against their published test sets. |
| `suci.rs` | SUCI concealment and deconcealment, ECIES Profiles A and B. |
| `subscribers.rs` | The AMF's credential store (K, OPc/OP, AMF field, SQN) and SUCI keys, from startup parameters. |
| `amf.rs` | The secured UE procedures: 5G-AKA, Security Mode, registration, PDU session establishment, deregistration. |
| `sessions.rs` | PDU session release and modification, UE- and network-requested. |
| `idle.rs` | CM-IDLE: the idle store, Service Request, paging, the inactivity timer. |
| `upf.rs` | The minimal GTP-U user plane: TEIDs, ICMP and ICMPv6 echo for the model's addresses, Router Advertisement for an IPv6 session's prefix. |
| `transport.rs` | SCTP (probe, PPID 60, stream 0/1, `MSG_EOR`) and the labelled lab TCP framing. Shared with the client. |
| `mod.rs` | The AMF: accept loop, association session, UE table, fail-closed rules. |
| `actions.rs` | Actions, events, metadata, startup parameters. |

## Why APER is hand-written

There is no maintained Rust NGAP codec that fits. The `hampi` project publishes an ASN.1
*compiler* (`asn1-compiler`, `asn1-codecs`) but no `ngap` crate; using it means vendoring the
38.413 ASN.1 module and generating code for all of it in `build.rs`. `oxirush-ngap` (rasn-based,
generated from the 3GPP ASN.1) existed in October 2026 but was weeks old, single-maintainer, and
would add a second `rasn` (the tree has 0.18 for SNMP) and roughly 1500 derived types to every
`all-protocols` build.

The subset is small because of how NGAP is built: every IE value is an **open type** — a
length-prefixed, independently encoded octet string. So `decode_pdu` frames *any* NGAP message
and names its IEs, and only the IEs of the implemented procedures are decoded; the rest are
reported to the model by id (`uninterpreted_ies`) and stepped over by length. That is honest
partial support rather than a guess.

### The rule that is easy to get wrong, and that the oracle caught

**38.413's CHOICE types have no extension marker.** They end with a `choice-Extensions`
alternative (a ProtocolIE-SingleContainer), which is a *root* alternative. So `Cause` has six
root alternatives and its index is three bits with **no** leading extension bit; the same holds
for `GlobalRANNodeID` (4), `GNB-ID` (2), `UserLocationInformation` (4), `UE-NGAP-IDs` (3) and
`ResetType` (3). The NGAP-PDU CHOICE itself *does* have `...` and does take the bit.

The first version wrote an extension bit everywhere. For `GlobalRANNodeID`, `GNB-ID`,
`UE-NGAP-IDs` and `ResetType` that happened to produce identical octets for the alternatives in
use — the decode of UERANSIM's NG Setup Request matched byte for byte — so round trips and a
real gNB's request were all green. `Cause` and `UserLocationInformation` were off by one bit,
and tshark's ngap dissector reported the Error Indication and Uplink NAS Transport as malformed
in `tests/server/ngap/codec_test.rs` before any peer saw them. `codec::choice`/`put_choice`
encode the rule in one place. Restoring the extension bit on `Cause` makes UERANSIM read
NetGet's `misc/unknown-PLMN-or-SNPN` as `nas/authentication-failure` (mutation-checked).

Other alignment facts the literal vectors pin: a size or range of 1..256 is one *aligned* octet,
1..1024 two aligned octets, up to 255 a minimal *unaligned* bit field; `PrintableString(SIZE(1..150,
...))` is an extension bit, the length as eight unaligned bits, then aligned characters (alignment
follows the upper bound, not the string); INTEGER ranges beyond 64K carry a 2- or 3-bit octet
count before aligned octets.

## Bounds

All are refused **before the model** with an Error Indication carrying a protocol cause.

| Bound | Value | Where |
|---|---|---|
| PDU | 65535 octets (`codec::MAX_PDU_LEN`) | decoder and both transports; over SCTP an oversized message is drained to `MSG_EOR` and the association continues, over the lab framing the connection closes (the next boundary is lost) |
| IEs per container | 64 (`MAX_IES`) | the constraint allows 65535 |
| NAS-PDU | 8192 octets (`MAX_NAS_PDU_LEN`) | decode and encode |
| List elements | 1024 per PDU across every nested `SEQUENCE OF` (`MAX_LIST_ITEMS`) | so 256 TAs × 12 PLMNs × 1024 slices cannot reach the model however a peer nests them |
| Length determinants | no fragmentation (≥ 16384) | refused, never buffered |
| Duplicate IE | refused | `abstract-syntax-error-falsely-constructed-message` |
| Missing mandatory IE | refused | `abstract-syntax-error-reject` |
| UE contexts per association | 4096 (`MAX_UE_CONTEXTS`) | an Initial UE Message beyond it gets `misc/control-processing-overload` |
| Associations | 256 (`accept_bounded`) | closed without a message (see `CONNECTION_CAP_REFUSAL`) |
| SQN resynchronisations | 1 per registration (`amf::MAX_RESYNCS`) | a second synch failure is an Authentication Reject |
| PDU sessions per UE | 8 established or pending (`amf::MAX_PDU_SESSIONS_PER_UE`) | the ninth is 5GSM #26 before the model |
| Release or modification requests | one in flight per session | a second is Release/Modification Reject #101 before the model |
| Idle UEs | 4096 per server (`idle::MAX_IDLE_UES`) | a UE that cannot be kept idle loses its context; its next Service Request is #9 |
| Decisions queued for an idle UE | 8 (`idle::MAX_QUEUED_PER_UE`) | the ninth is refused to the model with the reason |
| Paging | answered within 30 s (`idle::PAGING_TIMEOUT`), repeated at most every 5 s | the queue is dropped (`decision=paging_unanswered`) |
| `ue_inactivity_timeout_secs` | at most 86400 | refused at startup |
| Subscribers / SUCI keys | 1024 / 16 (`subscribers::MAX_*`) | refused at startup |
| 5GMM optional IEs, S-NSSAIs, TAIs | 64 / 16 / 16 per message | parse errors, never the model |
| First message | 30 s | NG Setup Request is sent as soon as the association is up |
| Idle | 3600 s | N2 has no application keepalive; SCTP HEARTBEAT covers a dead peer |

Nothing in the decoder recurses, so there is no depth to bound; nested open types are skipped by
length.

## Transport

SCTP is the default and is a **probe, not a `cfg`** (the `m3ua` design): the socket is requested,
and a host without SCTP — macOS, or Linux without `modprobe sctp` — refuses at startup with a
message naming SCTP, TS 38.412 and the escape hatch. The SCTP code compiles on every unix.

Once open, the one-to-one SCTP socket is driven through a `tokio::net::TcpStream` on its
descriptor, plus `sendmsg`/`recvmsg`:

- every message carries **PPID 60** in an `SCTP_SNDRCV` control message — Wireshark keys its
  NGAP dissector on it; neither UERANSIM nor Open5GS checks it, but with PPID 0 the live capture
  stops dissecting as NGAP (mutation-checked);
- **stream 0** for non-UE-associated signalling, **stream 1** for UE-associated (TS 38.412
  section 7). The writer decodes the PDU to decide; UERANSIM refuses UE-associated signalling on
  stream 0 (mutation-checked: its UE never receives the Authentication Request);
- message boundaries from `MSG_EOR`.

`transport: "tcp"` prefixes each PDU with a 4-octet big-endian length — a NetGet invention, since
NGAP has no framing of its own. `Transport::label()` says NON-STANDARD in the startup log, the
connection's `protocol_info`, and every event's `transport` field.

## Session

```text
accept                         -> awaiting NG Setup
NGSetupRequest   -> ngap_ng_setup_request    -> Response (setup complete) | Failure
InitialUEMessage -> AMF UE NGAP ID allocated; then either
   Registration Request whose SUCI names a subscriber with credentials -> 5G-AKA (Rust, below)
   anything else -> ngap_initial_ue_message -> model's NAS / release
UplinkNASTransport -> ids checked against the UE table first; then
   UE in the security procedure -> Rust (below), never the model per message
   Identity Response naming a subscriber with credentials -> 5G-AKA (Rust)
   anything else -> ngap_uplink_nas_transport
UEContextReleaseComplete -> context and its user-plane tunnels dropped  (Rust, no model)
UEContextReleaseRequest  -> UE Context Release Command with the gNB's cause (Rust)
NGReset          -> NGResetAcknowledge, contexts cleared         (Rust, no model)
ErrorIndication  -> ngap_error_indication                       (observational)
anything else before NG Setup -> Error Indication protocol/message-not-compatible-with-receiver-state
unimplemented initiating procedure -> Error Indication by its criticality (reject/notify), or nothing (ignore)
```

The secured procedure (`amf.rs`), all Rust except the two marked:

```text
Registration Request (plain)     -> Authentication Request (RAND, AUTN = SQN^AK|AMF|MAC, ngKSI, ABBA 0000)
Authentication Response          -> HRES* = HXRES* and RES* = XRES*? K_SEAF, K_AMF;
                                    Security Mode Command (header 3: NIA2, NEA0|NEA2, replayed
                                    capabilities, IMEISV request, RINMR)
Authentication Failure #21+AUTS  -> MAC-S verified, SQN resynchronised, one new Authentication Request
Authentication Failure #20/#26/#71, wrong RES* -> Authentication Reject, release
Security Mode Complete (header 4, MAC verified) -> security active;
                                    ngap_registration_request -> MODEL: send_registration_accept | reject
send_registration_accept         -> 5G-GUTI under the announced GUAMI; Registration Accept (header 2)
                                    inside Initial Context Setup with K_gNB (A.9, uplink COUNT of
                                    Security Mode Complete) and the UE security capabilities
Registration Complete            -> registered
UL NAS Transport (5GSM PDU Session Establishment Request)
                                 -> ngap_pdu_session_establishment_request -> MODEL: accept | reject
send_pdu_session_accept          -> 5GSM accept (default QoS rule, flow, AMBR, PDU address, S-NSSAI,
                                    DNN) inside PDU Session Resource Setup Request with a UL GTP-U
                                    tunnel on this server's user plane and one QoS flow
PDU Session Resource Setup Response -> the gNB's DL tunnel recorded; ICMP echo now answered
Deregistration Request           -> Deregistration Accept (unless switch-off), release (nas/deregister)
```

The rest of the UE's life (`sessions.rs`, `idle.rs`), the model asked only where marked:

```text
UL NAS Transport (5GSM Release Request)
                                 -> ngap_pdu_session_release_request -> MODEL: release | release reject
send_pdu_session_release         -> 5GSM Release Command (the request's PTI, or 0 when the model
                                    releases on its own) inside PDU Session Resource Release Command;
                                    the uplink TEID leaves the user plane at once
Release Complete                 -> the session is forgotten                 (decision=pdu_session_released)
UL NAS Transport (5GSM Modification Request)
                                 -> ngap_pdu_session_modification_request -> MODEL: modification | reject
send_pdu_session_modification    -> 5GSM Modification Command (session AMBR; the default QoS rule
                                    restated and its flow's 5QI) inside PDU Session Resource Modify
                                    Request; applied on the UE's Modification Complete, dropped on
                                    its Command Reject
UE Context Release Complete for a registered UE
                                 -> CM-IDLE: NAS context and sessions kept by 5G-TMSI, the gNB's
                                    downlink tunnels forgotten                       (decision=ue_idle)
Initial UE Message (Service Request, header type 1, 5G-S-TMSI of an idle UE)
                                 -> MAC and COUNT checked with the UE's context, the NAS message
                                    container deciphered at that COUNT; Initial Context Setup with
                                    K_gNB (A.9, the Service Request's uplink COUNT), the protected
                                    Service Accept (PDU session status) and the sessions in the
                                    Uplink data status (all of them when paged)  (decision=service_accept)
send_paging, or a release/modification addressed by supi to an idle UE
                                 -> NGAP Paging (5G-S-TMSI, the UE's last TAI); a queued decision
                                    runs, re-addressed, once the UE is back       (decision=paging)
ue_inactivity_timeout_secs       -> UE Context Release Command radioNetwork/user-inactivity for a
                                    registered UE silent that long (no NAS, no G-PDU)
```

A Service Request that does not verify is answered Service Reject #9 and the idle context is
kept (`decision=nas_integrity_failure`), so a forged one cannot evict the real UE; one naming a
5G-TMSI nobody holds is #9 too (`decision=service_request_unknown_ue`). Sessions the UE's PDU
session status no longer lists are released locally (TS 24.501 5.6.1.4.1). Registered UEs go
idle when the gNB's release completes, when NG Reset clears them and when the association
closes; the idle store is the server's, so a UE may come back through another association.

The association's peer channel (MCP `send_to_peer`, the dashboard's "message this peer") is
served inside the session task between messages — not beside it as `peer_support` does for
other protocols — so an injected `send_paging`, `send_pdu_session_release` or
`send_ue_context_release_command {supi}` acts on the same UE table, keys and COUNTs as the
model's answers. A refused decision answers the injection with its reason.

Once Security Mode Complete verifies, an uplink message is processed only if its MAC verifies
at a COUNT above every one accepted before; anything else is discarded and logged
(`decision=nas_integrity_failure`, `nas_count_replay`, `nas_unprotected_refused`,
`nas_header_refused`, `nas_malformed`). The model writes plain 5GMM in
`send_downlink_nas_transport`; to a secured UE the session re-encodes it protected.

The model's actions are encoded statelessly and the session reads each PDU back off its own
octets (procedure, kind, AMF UE NGAP ID) to apply the fail-closed rule — the `m3ua` design. The
three decisions that need the UE's keys (`send_registration_accept`, `send_pdu_session_accept`,
`send_pdu_session_reject`) are validated by `execute_action` and carried out by the session,
which refuses one that does not fit the UE's state (`decision=refused_decision`).

## Fail closed

| Situation | NG Setup | Initial UE Message | Registration decision | PDU session decision | Log tag |
|---|---|---|---|---|---|
| model answered | its Response or Failure | its NAS / release | its accept or reject | its accept or reject | — |
| model refused | its Failure | its reject | its reject | its 5GSM cause | `decision=model_reject` |
| model said nothing | Failure `misc/unspecified` | Registration/Service Reject #111, release | Registration Reject #111 (protected), release | 5GSM reject #31 | `decision=model_silent` |
| model could not run | Failure `misc/control-processing-overload` + v5s, or `misc/unspecified` + v10s | Reject #22 or #111, release | Reject #22 or #111, release | #26 or #31 | `decision=fail_closed_llm_error` |
| no policy | Failure `misc/om-intervention` | Reject #111, release | Reject #111, release | #31 | `decision=no_policy_configured` |

The decisions the rest of the UE's life adds:

| Situation | UE asks to release a session | UE asks to modify a session |
|---|---|---|
| model answered | its release or Release Reject | its Modification Command or Modification Reject |
| model said nothing (`model_silent`), could not run (`fail_closed_llm_error`), no policy (`no_policy_configured`) | **released** (#36): a release keeps nothing open, so it is the closed direction, like NG Reset | Modification Reject #31, or #26 when the model was overloaded: nothing changes |

Rust's own refusals: wrong RES* (`auth_res_mismatch`), the UE's MAC failure
(`auth_mac_failure`), an AUTS whose MAC-S fails or a second synch failure
(`auth_auts_invalid`, `auth_resync_exhausted`) — each an Authentication Reject and a release; a UE
without 128-5G-IA2 is Registration Reject #23 (`ue_security_capabilities_mismatch`); an accepted
PDU session with no user plane configured, or one the user plane cannot hold, is 5GSM #26
(`no_user_plane`, `up_refused`). A subscriber is never registered and a session never accepted
because nothing answered.

An Uplink NAS Transport the model stays silent on sends nothing (a UE's Registration Complete
needs no answer); one it cannot evaluate is rejected the same way. Nothing derived from an
error reaches the peer: the wire carries a Cause or a 5GMM/5GSM cause.

## NAS security

Implemented: 5G-AKA per TS 33.501 Annex A (Milenage f1-f5* with OPc or OP; RES*/XRES*, HXRES*,
K_AUSF, K_SEAF, K_AMF with ABBA 0x0000, K_NASint/K_NASenc, K_gNB), 128-NIA1/128-NEA1 (SNOW 3G,
`snow3g.rs`), 128-NIA2 (AES-CMAC), 128-NEA2 (AES-CTR), 128-NIA3/128-NEA3 (ZUC, `zuc.rs`) and
NEA0, selected by the operator's preference (`nas_integrity`, `nas_ciphering`): the first the
UE offers; NEA0 when it offers none of the ciphering list, Registration Reject #23 when it offers
none of the integrity list; BEARER 1 for 3GPP access (what UERANSIM, Open5GS and free5GC
use); header types 1-4; per-direction NAS COUNT with an 8-bit sequence number estimated into a
24-bit COUNT and replays refused. SUCI: null scheme, and ECIES Profiles A (X25519) and B
(secp256r1, compressed points) with `suci_keys`; a SUCI whose key id has no configured key is
left to the model, unread. The NAS message container of an initial NAS message (a Service
Request from CM-IDLE) is deciphered at the COUNT of the message that carries it (TS 24.501
4.4.6). Not implemented: EAP-AKA', horizontal K_AMF derivation, NAS COUNT wrap-around rekeying.

Checked against: TS 35.208 test set 1 (Milenage), TS 33.401 Annex C (EIA2 and EEA2 sets, which
TS 33.501 Annex D reuses), the ETSI/SAGE implementers' test data for UEA2/UIA2 and 128-EEA3/EIA3
and ZUC (`tests/server/ngap/cipher_vectors_test.rs`), UERANSIM's UE selecting NIA1+NEA1 and
NIA3+NEA3 live, TS 33.501 Annex C.4.3 and C.4.4 (SUCI), and live: UERANSIM's UE
verifies every AUTN and MAC the AMF produces; on the client side Open5GS's AUSF verifies the
UE's RES* and its AMF's K_gNB equals the UE's own. TS 33.501 publishes no vectors for the KDF
derivations; tshark's nas-5gs dissector cannot verify MACs (it has no key preferences), so the
peers are the check there.

Where the keys are: `subscribers` and `suci_keys` startup parameters, held in `Core`'s
`Credentials` (one per server, shared by associations so SQNs advance once), and each UE's
`NasContext`. `src/utils/redact.rs` masks `subscriber_key`, `subscriber_op`/`subscriber_opc` and
`home_network_private_key` wherever parameters are shown; no event, log line or prompt carries
them (`security_e2e_test` asserts K and OPc appear in no event and no status line).

## NAS (5GMM) for the model

Decoded for the model: Registration Request (type, follow-on, ngKSI, the 5GS mobile identity —
a SUCI's PLMN, routing indicator, protection scheme, key id and, for the null scheme, MSIN; a
5G-GUTI; an IMEI — UE security capability, requested NSSAI, names of other IEs), Identity
Response, Authentication Failure (cause, AUTS present), Authentication Response (RES* length),
Deregistration Request, Service Request, Security Mode Command/Complete, Registration Accept,
UL/DL NAS Transport with their 5GSM payloads, the rejects and 5GMM Status.

Encoded from structured actions, downlink: Registration Reject, Identity Request,
Authentication Request, Authentication Reject, Service Reject, 5GMM Status — protected by the
session for a secured UE. For a UE with no credentials on this AMF an Authentication Request
carries the model's RAND and AUTN (random by default), and a real UE answers MAC failure #20.

## User plane

`user_plane_address` binds a GTP-U socket (UDP 2152, or IP:port) and is the address in every
UL tunnel. A G-PDU on a session's TEID whose inner packet is an ICMP echo request (IPv4) or
ICMPv6 echo request (IPv6, directly after the fixed header) from the UE's own address — its
IPv4 address, or for IPv6 any address in its /64 or the link-local address of its interface
identifier — to one of the session's `reachable_addresses` is answered: addresses swapped,
TTL/hop limit 64, checksums recomputed (ICMPv6 over the RFC 8200 pseudo-header), sent to the
gNB's DL tunnel on port 2152 with a PDU Session Container carrying the QFI. A Router
Solicitation from an IPv6 session is answered with a Router Advertisement from fe80::1 (hop
limit 255) carrying the session's prefix with the on-link and autonomous flags: the PDU address
gives an IPv6 UE only its interface identifier (TS 23.501 5.8.2.2.3). Everything else is dropped
and counted (`up_no_session`, `up_spoofed_source`, `up_not_answered`, `up_no_downlink_tunnel`
for an idle UE, …). A released session's TEID is removed when the release command goes out.
GTP-U Echo Request is answered. Nothing is routed: no N6, no NAT. Bounds: 4096 sessions per
server, 16 answering addresses per session, one IPv4 address and one /64 per session.

## Events and actions

| Event | Useful replies |
|---|---|
| `ngap_ng_setup_request` | `send_ng_setup_response`, `send_ng_setup_failure` |
| `ngap_initial_ue_message` (UEs without credentials) | `send_downlink_nas_transport` (identity / authentication request, registration reject), `send_ue_context_release_command` |
| `ngap_uplink_nas_transport` (same) | the same, or `wait_for_more` |
| `ngap_registration_request` (authenticated subscriber) | `send_registration_accept`, or `send_downlink_nas_transport` with registration_reject then a release |
| `ngap_pdu_session_establishment_request` | `send_pdu_session_accept` (IPv4, IPv6 prefix + interface identifier, or both), `send_pdu_session_reject` |
| `ngap_pdu_session_release_request` | `send_pdu_session_release`, `send_pdu_session_release_reject` |
| `ngap_pdu_session_modification_request` | `send_pdu_session_modification` (session AMBR, 5QI), `send_pdu_session_modification_reject` |
| `ngap_error_indication` | observational; `send_ue_context_release_command` |

Also `send_error_indication`, `send_ng_reset`, and — unprompted, from any answer or injected
through the peer channel — `send_pdu_session_release`, `send_pdu_session_modification`,
`send_paging {supi}` and `send_ue_context_release_command {supi}` (CM-IDLE for a registered UE). `close_connection` is executable but not
advertised (the dashboard's disconnect). There are no async actions: every verb addresses one
association, and the dashboard's "message this peer" runs the sync actions through the peer
command channel. PLMNs are `{"mcc": "001", "mnc": "01"}` (or `"001-01"`), causes `group/value`
with 38.413's names, 5GMM and 5GSM causes by name.

Model-call budget: one call per NG Setup; per subscriber with credentials, one for registration,
one per PDU session establishment, one per UE-requested release and one per UE-requested
modification — none per NAS message, none for a Service Request, paging, an idle transition or
a network-requested release or modification (`security_e2e_test` asserts three calls for a whole
registration with a session; `lifecycle_test` seven for registration, three sessions, a
modification and a release through two idle periods; `real_client_test` the same events for
UERANSIM).

## Startup parameters

`transport`: `"sctp"` (default) or `"tcp"` (non-standard lab framing). `subscribers`:
`[{"supi", "subscriber_key", "subscriber_opc" | "subscriber_op", "amf_field", "sqn"}]`.
`suci_keys`: `[{"key_id", "scheme": "profile_a" | "profile_b", "home_network_private_key"}]`.
`nas_integrity`: a comma-separated preference of `nia1`, `nia2`, `nia3` (default `"nia2"`,
`DEFAULT_NAS_INTEGRITY`; `nia0` refused). `nas_ciphering`: a preference of `nea0`-`nea3` (default
`"nea0"`, `DEFAULT_NAS_CIPHERING`). `ue_inactivity_timeout_secs`: idle a silent registered UE
(omitted or 0: never; at most 86400). `user_plane_address`: an IP (port 2152) or IP:port; without
it PDU sessions are refused with #26.

## Verification

- `tests/server/ngap/real_client_test.rs` (Linux): UERANSIM v3.2.7's `nr-gnb` and `nr-ue` over
  SCTP — the secured registration, PDU session, ping through the tunnel and deregistration;
  registration and a ping under NIA1+NEA1 and under NIA3+NEA3; a UE-requested release (the TUN
  goes), a new session, CM-IDLE and paging the UE recognises; the pre-security challenge; the NG
  Setup failure. Live captures through tshark's ngap and nas-5gs dissectors. See that
  directory's `AGENTS.md`.
- `lifecycle_test.rs`: modification, UE- and network-requested release, CM-IDLE, Service
  Request (forged and unknown ones refused), paging with a queued decision, IPv6 and IPv4v6 with
  ICMPv6 echo and Router Advertisement checked by tshark, the algorithm preference, the
  inactivity timer, and the fail-closed answers to the two new decisions — scripted UE, mocked
  model, seven calls.
- `cipher_vectors_test.rs`, `procedures_codec_test.rs`: SNOW 3G and ZUC against every
  ETSI/SAGE and TS 33.401 set; the release, modify and paging APER.
- `security_test.rs`: the published vectors and the protection rules.
- `security_e2e_test.rs`: the secured flow in-process over the lab transport with a scripted
  UE, a mocked model and every refusal above.
- `codec_test.rs`, `e2e_test.rs`, `transport_test.rs`: the codec against literal vectors, the
  pre-security session and its fail-closed paths, the SCTP transport.
- `fuzz/fuzz_targets/ngap_nas.rs`: every NGAP procedure decoder, the 5GMM/5GSM parsers
  (Service Request and Accept round-trip, the release/modification parser), the protected-NAS
  path under every algorithm pair with the Service Request container, and the user plane's
  echo and Router Advertisement builders (their checksums must verify), with nesting and
  length-bomb corpus entries.

What UERANSIM v3.2.7 cannot show, and so rests on the lab tests and on NetGet's gNB against
Open5GS (`tests/client/ngap/`): a Service Request reaching an AMF — its gNB chooses the AMF for
an initial NAS message by the slice in a Registration Request and drops a Service Request,
which has none (`gnb/ngap/nas.cpp`, `nnsf.cpp`); PDU session modification — neither its UE nor
its gNB implements it; IPv6 and IPv4v6 sessions — its UE refuses to request them.

## Maturity

`Experimental`. Against the six conditions in the root `AGENTS.md`: one independent client
(UERANSIM; condition 1 needs two — Open5GS's gNB-side tools do not exist and srsRAN/OAI gNBs are
not in the tree), the oracle is green over real and lab traffic (2), a fuzz target exists
and has run clean (`ngap_nas`, 3: 27,849 executions over four minutes on 25 October 2026,
built as `fuzz.yml` builds it — `--dev --sanitizer none`, the root lockfile seeded, the current
nightly; on macOS crc-fast's cdylib needs `-Wl,-undefined,dynamic_lookup` to link under
sanitizer coverage), bounds are tested (4), these files were written
against the source in this pass (5), no `#[ignore]` or skip gate — but the evidence runs only
where SCTP exists, i.e. the `ngap` pair job.

Not implemented: EAP-AKA'; handover, AMF/RAN configuration update, AMF status indication,
UE Context Modification; more than one QoS flow per session (modification changes the default
flow's 5QI and the session AMBR, nothing else), any routing beyond the echo and Router
Advertisement answers; a UE-initiated or network-initiated deregistration while idle;
connected UE state shared across associations (the idle store is shared, the connected UE
table is per association); IPv6 SCTP multi-homing.
