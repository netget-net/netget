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
| `sm.rs` | 5GSM: PDU Session Establishment Request/Accept/Reject, causes. Shared with the client. |
| `security.rs` | Milenage, the 5G-AKA key hierarchy, NIA2/NEA2/NEA0, protected-message framing with COUNTs. Shared with the client. |
| `suci.rs` | SUCI concealment and deconcealment, ECIES Profiles A and B. |
| `subscribers.rs` | The AMF's credential store (K, OPc/OP, AMF field, SQN) and SUCI keys, from startup parameters. |
| `amf.rs` | The secured UE procedures: 5G-AKA, Security Mode, registration, PDU sessions, deregistration. |
| `upf.rs` | The minimal GTP-U user plane: TEIDs, ICMP echo for the model's addresses. |
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
K_AUSF, K_SEAF, K_AMF with ABBA 0x0000, K_NASint/K_NASenc, K_gNB), 128-NIA2 (AES-CMAC),
128-NEA2 (AES-CTR) and NEA0; BEARER 1 for 3GPP access (what UERANSIM, Open5GS and free5GC
use); header types 1-4; per-direction NAS COUNT with an 8-bit sequence number estimated into a
24-bit COUNT and replays refused. SUCI: null scheme, and ECIES Profiles A (X25519) and B
(secp256r1, compressed points) with `suci_keys`; a SUCI whose key id has no configured key is
left to the model, unread. Not implemented: NIA1/NEA1 (SNOW 3G), NIA3/NEA3 (ZUC), EAP-AKA',
horizontal K_AMF derivation, NAS COUNT wrap-around rekeying.

Checked against: TS 35.208 test set 1 (Milenage), TS 33.401 Annex C (EIA2 and EEA2 sets, which
TS 33.501 Annex D reuses), TS 33.501 Annex C.4.3 and C.4.4 (SUCI), and live: UERANSIM's UE
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
UL tunnel. A G-PDU on a session's TEID whose inner packet is an IPv4 ICMP echo request from the
UE's own address to one of the session's `reachable_addresses` is answered: addresses swapped,
TTL 64, both checksums recomputed, sent to the gNB's DL tunnel on port 2152 with a PDU Session
Container carrying the QFI. Everything else is dropped and counted (`up_no_session`,
`up_spoofed_source`, `up_not_answered`, …). GTP-U Echo Request is answered. Nothing is routed:
no N6, no NAT. Bounds: 4096 sessions per server, 16 answering addresses per session, one UE
address per session.

## Events and actions

| Event | Useful replies |
|---|---|
| `ngap_ng_setup_request` | `send_ng_setup_response`, `send_ng_setup_failure` |
| `ngap_initial_ue_message` (UEs without credentials) | `send_downlink_nas_transport` (identity / authentication request, registration reject), `send_ue_context_release_command` |
| `ngap_uplink_nas_transport` (same) | the same, or `wait_for_more` |
| `ngap_registration_request` (authenticated subscriber) | `send_registration_accept`, or `send_downlink_nas_transport` with registration_reject then a release |
| `ngap_pdu_session_establishment_request` | `send_pdu_session_accept`, `send_pdu_session_reject` |
| `ngap_error_indication` | observational; `send_ue_context_release_command` |

Also `send_error_indication` and `send_ng_reset`. `close_connection` is executable but not
advertised (the dashboard's disconnect). There are no async actions: every verb addresses one
association, and the dashboard's "message this peer" runs the sync actions through the peer
command channel. PLMNs are `{"mcc": "001", "mnc": "01"}` (or `"001-01"`), causes `group/value`
with 38.413's names, 5GMM and 5GSM causes by name.

Model-call budget: one call per NG Setup; per subscriber with credentials, one for registration
and one per PDU session — none per NAS message (`security_e2e_test` asserts three calls for a
whole registration with a session; `real_client_test` asserts the same three events for
UERANSIM).

## Startup parameters

`transport`: `"sctp"` (default) or `"tcp"` (non-standard lab framing). `subscribers`:
`[{"supi", "subscriber_key", "subscriber_opc" | "subscriber_op", "amf_field", "sqn"}]`.
`suci_keys`: `[{"key_id", "scheme": "profile_a" | "profile_b", "home_network_private_key"}]`.
`nas_ciphering`: `"nea0"` (default, `DEFAULT_NAS_CIPHERING`) or `"nea2"`. `user_plane_address`:
an IP (port 2152) or IP:port; without it PDU sessions are refused with #26.

## Verification

- `tests/server/ngap/real_client_test.rs` (Linux): UERANSIM v3.2.7's `nr-gnb` and `nr-ue` over
  SCTP — the secured registration, PDU session, ping through the tunnel and deregistration; the
  pre-security challenge; the NG Setup failure. Live captures through tshark's ngap and nas-5gs
  dissectors. See that directory's `AGENTS.md`.
- `security_test.rs`: the published vectors and the protection rules.
- `security_e2e_test.rs`: the secured flow in-process over the lab transport with a scripted
  UE, a mocked model and every refusal above.
- `codec_test.rs`, `e2e_test.rs`, `transport_test.rs`: the codec against literal vectors, the
  pre-security session and its fail-closed paths, the SCTP transport.
- `fuzz/fuzz_targets/ngap_nas.rs`: every NGAP procedure decoder, the 5GMM/5GSM parsers and the
  protected-NAS path, with nesting and length-bomb corpus entries.

## Maturity

`Experimental`. Against the six conditions in the root `AGENTS.md`: one independent client
(UERANSIM; condition 1 needs two — Open5GS's gNB-side tools do not exist and srsRAN/OAI gNBs are
not in the tree), the oracle is green over real and lab traffic (2), a fuzz target exists
and has run clean (`ngap_nas`, 3: 39,178 executions over three minutes on 22 October 2026 with
the seeded lockfile and the current nightly — `nightly-2025-12-04` is now too old for the AWS
crates in the lockfile), bounds are tested (4), these files were written
against the source in this pass (5), no `#[ignore]` or skip gate — but the evidence runs only
where SCTP exists, i.e. the `ngap` pair job.

Not implemented: NIA1/NEA1, NIA3/NEA3, EAP-AKA'; handover, paging, service request under
security, PDU session release and modification, AMF/RAN configuration update, AMF status
indication; IPv6 PDU sessions, more than one QoS flow per session, any routing beyond the ICMP
echo answer; shared UE state across associations (one AMF for several gNBs: each association
has its own UE table, though credentials and the user plane are shared); IPv6 SCTP
multi-homing.
