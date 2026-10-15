# GTP client (an SGSN, SGW or MME)

The near end of one mobile-core path to one peer (`remote_addr`, port 2123 by default), with
a GTP-U endpoint for the sessions it creates. Built on the server's codec
(`src/server/gtp/codec.rs`); `msg.rs` adds the request side and the inner packet, and is pure.

**Status**: Experimental (see "Maturity").
**Feature**: `gtp`, shared with the server.

## Roles (`interface` startup parameter)

| `interface` | Version | This client is | Peer is | F-TEIDs it advertises |
|---|---|---|---|---|
| `s5` (default) | GTPv2 | SGW | PGW | S5/S8 SGW GTP-C (6), S5/S8 SGW GTP-U (4) in the bearer context |
| `s11` | GTPv2 | MME | SGW | S11 MME GTP-C (10), the PGW's S5/S8 GTP-C (7, from `pgw_address`); Modify Bearer carries this client's GTP-U as the eNodeB's S1-U (0) |
| `gn` | GTPv1 | SGSN | GGSN | TEID Data I / TEID Control Plane, two GSN Address IEs |

## Actions

- `gtp_echo{plane}`: Echo Request on the control plane (in the control version) or the
  user plane (always GTPv1).
- `gtp_create_session{imsi, apn, msisdn, mei, pdn_type, ebi, rat_type, mcc, mnc,
  selection_mode, qos, ambr_*, request_dns, pgw_address}`: Create Session Request (v2) or
  Create PDP Context Request (v1). Rust picks two random TEIDs and a session number.
- `gtp_modify_bearer{session}`: Modify Bearer Request (v2) or Update PDP Context Request (v1),
  to the peer's control TEID.
- `gtp_delete_session{session}`: Delete Session Request with the EBI (v2), or Delete PDP
  Context Request with Teardown Ind (v1).
- `gtp_send_gpdu{session, destination, source, protocol, identifier, sequence, source_port,
  destination_port, ttl, payload, encoding}`: one IPv4 ICMP-echo or UDP packet, built in
  Rust with its checksums, as a G-PDU to the peer's data TEID. The payload is text, or hex
  when `encoding` is `hex`.
- `gtp_send_end_marker{session}`.
- `gtp_send_error_indication{teid}`: only for a TEID a G-PDU arrived on that is not one of
  this client's. It goes back to where that G-PDU came from.
- `gtp_respond{sequence, cause}`: answers a `gtp_peer_request` with a Cause.

## Events

`gtp_client_ready`, `gtp_response` (cause by name and number, `accepted`, UE address, the
peer's TEIDs and data address, DNS servers from the PCO, AMBR, the bearer context, Recovery),
`gtp_timeout`, `gtp_tunnel_packet` (decoded inner packet with checksum verdicts),
`gtp_tunnel_notification` (Error Indication, End Marker) and `gtp_peer_request`.

## Behaviour

- An answer must match a pending request by sequence number **and** message type (or be
  Version Not Supported). Anything else is refused (`decision=refused_unexpected_type`) and
  the request stays pending.
- An unanswered request is resent after T3-RESPONSE (`t3_response_ms`, default 3 s) up to
  N3-REQUESTS times (`n3_requests`, default 3). The resend is the same datagram. After that
  the request is reported as `gtp_timeout`, and a session that was never created is dropped.
- Echo Requests on either plane are answered in Rust with Recovery 0. Path management is
  mechanical and there is nothing to decide.
- Fail closed: when the model cannot be asked (`decision=fail_closed_llm_error`), nothing is
  sent. No path synthesises a request or an acceptance on the model's behalf.
- Refused before the model: datagrams that fill the 64 KiB buffer, malformed headers or IEs,
  more than 256 IEs, GTP', unknown versions, a GTPv1-C message with no sequence number, and
  user-plane datagrams from an address that is neither the peer nor a session's data address.
- Bounds: 64 pending requests, 64 sessions, 64 remembered peer requests and unknown TEIDs,
  chains of model turns stop at `MAX_FOLLOWUP_DEPTH` (8). A received G-PDU payload reaches
  the model cut at 1024 octets, with its full length.
- GTP-U listens on 2152 by default, because peers address G-PDUs to 2152 whatever the F-TEID
  says (osmo-ggsn does). If 2152 is taken and the port was not given explicitly, an
  ephemeral port is used and a warning says so. G-PDUs are sent to `peer_user_plane_port`
  (2152) on the peer's data address.
- The control plane always talks to `remote_addr`. On S11 a control F-TEID that names a
  different address is reported but not followed.

## Wire details worth knowing

- GTPv2 spare bits are zero and GTPv1's are one. The GTPv2 Selection Mode is `000000mm`,
  the GTPv1 one is `111111mm`. go-gtp caught the first version of this client sending the
  GTPv1 form in GTPv2.
- GTPv1 TV IEs go in ascending type order. IMSI and IMEI(SV) are fixed at 8 octets, padded
  with `F`.
- The GTPv1 QoS Profile is the ARP octet plus the R97 best-effort profile `0B 92 1F`
  (sgsnemu's default). Only the ARP comes from the model.
- Bearer QoS PCI/PVI are *disable* bits. `pre_emption_capability: true` writes PCI 0.

## Maturity

Experimental. The client Beta bar's evidence exists: two independent peers, wmnsk/go-gtp
(a PGW decoding every message, in `tests/client/gtp/peer`) and Osmocom osmo-ggsn (a real
GGSN whose kernel tun answers a tunnelled ping). Both tests fail rather than skip, and
both drive model-chosen actions asserted on the wire. osmo-ggsn needs Linux and a tun
device, so its half runs only in the `gtp-client` job of `protocol-pairs.yml`, which is
dispatched by hand. Not implemented: IPv6 inner packets, dedicated bearers and secondary
PDP contexts, handover (Modify Bearer carries only the user-plane F-TEID), GTP', GTPv0,
and following a control F-TEID to a different address.
