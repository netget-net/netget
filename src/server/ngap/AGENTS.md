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
| `nas.rs` | Plain 5GMM (TS 24.501): decode for the model, encode from structured actions. Shared with the client. |
| `transport.rs` | SCTP (probe, PPID 60, stream 0/1, `MSG_EOR`) and the labelled lab TCP framing. Shared with the client. |
| `mod.rs` | The AMF: accept loop, association session, UE table, fail-closed rules. |
| `actions.rs` | Actions, events, metadata, startup parameter. |

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
InitialUEMessage -> ngap_initial_ue_message  -> AMF UE NGAP ID allocated; model's NAS / release
UplinkNASTransport -> ngap_uplink_nas_transport (ids checked against the UE table first)
UEContextReleaseComplete -> context dropped                    (Rust, no model)
NGReset          -> NGResetAcknowledge, contexts cleared         (Rust, no model)
ErrorIndication  -> ngap_error_indication                       (observational)
anything else before NG Setup -> Error Indication protocol/message-not-compatible-with-receiver-state
unimplemented initiating procedure -> Error Indication by its criticality (reject/notify), or nothing (ignore)
```

The model's actions are encoded statelessly and the session reads each PDU back off its own
octets (procedure, kind, AMF UE NGAP ID) to apply the fail-closed rule — the `m3ua` design.

## Fail closed

| Situation | NG Setup | Initial UE Message | Log tag |
|---|---|---|---|
| model answered | its Response or Failure | its NAS / release | — |
| model refused | its Failure | its reject | `decision=model_reject` |
| model said nothing | Failure `misc/unspecified` | Registration/Service Reject #111, then release | `decision=model_silent` |
| model could not run | Failure `misc/control-processing-overload` + Time to Wait v5s, or `misc/unspecified` + v10s | Reject #22 (overloaded) or #111, then release | `decision=fail_closed_llm_error` |
| no policy | Failure `misc/om-intervention` | Reject #111, then release | `decision=no_policy_configured` |

An Uplink NAS Transport the model stays silent on sends nothing (a UE's Registration Complete
needs no answer); one it cannot evaluate is rejected the same way. Nothing derived from an
error reaches the peer: the wire carries a Cause or a 5GMM cause.

## NAS (5GMM)

Decoded for the model: Registration Request (type, follow-on, ngKSI, the 5GS mobile identity —
a SUCI's PLMN, routing indicator, protection scheme, key id and, for the null scheme, MSIN; a
5G-GUTI; an IMEI — UE security capability, requested NSSAI, names of other IEs), Identity
Response, Authentication Failure (cause, AUTS present), Authentication Response (RES* length),
Deregistration Request, Service Request, the rejects and 5GMM Status. Integrity-protected,
unciphered messages are decoded through the header with `mac_verified: false`.

Encoded from structured actions, downlink: only what TS 24.501 section 4.4.4.2 lets a UE process
before security — Registration Reject, Identity Request, Authentication Request, Authentication
Reject, Service Reject, 5GMM Status.

**NAS security is not implemented**: no 5G-AKA derivation (RES*, K_AUSF, K_SEAF, K_AMF), no
Security Mode Command, no integrity or ciphering, so Registration Accept cannot be sent. An
Authentication Request carries the model's RAND and AUTN (random by default); a real UE computes
the MAC from its own key and answers Authentication Failure #20. The tests use exactly that.

## Events and actions

| Event | Useful replies |
|---|---|
| `ngap_ng_setup_request` | `send_ng_setup_response`, `send_ng_setup_failure` |
| `ngap_initial_ue_message` | `send_downlink_nas_transport` (identity / authentication request, registration reject), `send_ue_context_release_command` |
| `ngap_uplink_nas_transport` | the same, or `wait_for_more` |
| `ngap_error_indication` | observational; `send_ue_context_release_command` |

Also `send_error_indication` and `send_ng_reset`. `close_connection` is executable but not
advertised (the dashboard's disconnect). There are no async actions: every verb addresses one
association, and the dashboard's "message this peer" runs the sync actions through the peer
command channel. PLMNs are `{"mcc": "001", "mnc": "01"}` (or `"001-01"`), causes `group/value`
with 38.413's names, 5GMM causes by Annex A name.

## Startup parameters

`transport`: `"sctp"` (default) or `"tcp"` (non-standard lab framing).

## Verification

- `tests/server/ngap/real_client_test.rs` (Linux): UERANSIM v3.2.7's `nr-gnb` and `nr-ue` over SCTP,
  with a live capture through tshark's ngap dissector. See that directory's `AGENTS.md`.
- `codec_test.rs`: UERANSIM's captured NG Setup Request decoded and re-encoded octet for octet;
  hand-derived NG Setup Request, NG Setup Failure and Downlink NAS Transport vectors; 5GMM
  literals; every bound; NetGet's PDUs through the pcap oracle in SCTP DATA chunks.
- `e2e_test.rs`: the session over the lab transport with a mocked model and python policies,
  every fail-closed row above, the protocol refusals, the UE table cap.
- `transport_test.rs`: SCTP binds or is refused by name; on Linux, one association carries whole
  messages and an oversized one is drained without losing the next boundary.

## Maturity

`Experimental`. Against the six conditions in the root `AGENTS.md`: one independent client
(UERANSIM; condition 1 needs two), the oracle is green over real and lab traffic (2), no fuzz
target (3), bounds are tested (4), these files were written against the source in this pass
(5), no `#[ignore]` or skip gate — but the evidence runs only where SCTP exists, i.e. the `ngap`
pair job, which has not yet run in CI. Not reviewed beyond its tests.

Not implemented: NAS security; PDU sessions and the whole of the user plane; handover, paging,
AMF/RAN configuration update, AMF status indication; multiple associations' shared state (each
association is independent); IPv6 SCTP multi-homing.
