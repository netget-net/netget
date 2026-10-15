# GTP client tests

No LLM calls. Script handlers play the model, and each step of every chain is an action the
script returned for the previous step's event.

## `real_server_test.rs`: wmnsk/go-gtp as a PGW (S5/S8, GTPv2-C and GTP-U)

The peer is `tests/client/gtp/peer` (go-gtp v0.8.12, go.sum-pinned), built by
`python3 tests/client/gtp/install_peers.py <dir>`. `NETGET_GTP_GO_PEER` names the binary.
The peer parses every datagram with go-gtp and prints what it decoded, with NetGet's raw
octets. Every reply it sends is go-gtp's encoding.

The chain: Echo, then Create Session (the PGW drops the first copy), then an ICMP echo
through the tunnel and a user-plane Echo. The echo reply coming back leads to Modify Bearer,
and that leads to End Marker and Delete Session. A G-PDU to a TEID NetGet never gave out leads
to an Error Indication.

What is asserted:

- Every Create Session IE as go-gtp read it: IMSI, MSISDN, MEI, serving network, RAT,
  APN, selection mode, PDN type, PAA, AMBR, PCO, Recovery, sender F-TEID, and the bearer
  context's EBI, S5/S8-U F-TEID and Bearer QoS.
- The retransmission is byte-identical to the first copy.
- NetGet's reading of go-gtp's answer: cause, UE address, the PGW's TEIDs and data
  address, DNS, AMBR, charging id and Recovery.
- The inner packet as a host would read it (go-side checksums). The echo reply came back
  on NetGet's TEID with good checksums.
- NetGet answers both of the PGW's Echo Requests.
- Modify Bearer, End Marker and Delete Session are addressed to the PGW's TEIDs.
- Error Indication carries the stray TEID and NetGet's address.
- Injected actions on a deleted session, and with a bad IMSI, are refused.
- tshark's `gtpv2` and `gtp` dissectors read both directions of both planes cleanly.

## `osmo_ggsn_test.rs`: Osmocom osmo-ggsn as a GGSN (Gn, GTPv1-C and GTP-U)

Needs Linux, `osmo-ggsn` (Ubuntu 24.04 ships 1.9.0) and CAP_NET_ADMIN for its tun device:
`sudo setcap cap_net_admin+ep "$(command -v osmo-ggsn)"`, or run as root. The test writes
its own config: GTP on 127.0.0.2, VTY and CTRL on 127.0.0.2 as well, pool 10.233.0.0/24, and
two DNS servers. It reads the tun's address back with `ip`. NetGet's GTP-U endpoint takes
127.0.0.1:2152, because osmo-ggsn sends G-PDUs to port 2152.

The chain: Echo, then Create PDP Context. The test then injects one ICMP echo to the tun
address. The kernel answers it, and osmo-ggsn tunnels the reply back. The model answers the
reply with Update PDP Context, and that with Delete PDP Context.

What is asserted: the cause, the allocated address in the pool, the GGSN's TEIDs and data
address, the DNS servers from the PCO, and the echo reply (addresses, id, sequence,
checksums, payload) on NetGet's TEID. Update and Delete are both accepted.

## `bounds_test.rs`: a peer written in the test

This is not interoperability evidence. It shows the following:

- A wrong-type answer, a wrong-sequence answer, a wrong-version answer and a truncated
  answer are each refused.
- The request is sent 1 + N3 times, byte-identical, then reported as `gtp_timeout`.
- A peer-started Delete Bearer Request reaches the model, and `gtp_respond` answers it.
- A model that keeps asking stops at `MAX_FOLLOWUP_DEPTH`.

## `msg_test.rs`

Literal octets (PLMN, Bearer QoS, the GTPv1 QoS profile, IMSI TBCD, TV IE order), RFC 1071
checksums of the inner packet, the decode refusals (oversized, IE count, truncation, unknown
fixed IE, missing sequence, GTP', bad version), PCO/IPCP DNS parsing with bad lengths, and
the action validation.

## Mutation-checked

Each mutation makes a test fail:

- Accepting any message type as an answer.
- One more retransmission than N3.
- One more model turn than the depth bound.
- One more IE than `MAX_IES`.
- Not retransmitting at all.
- Discarding the model's actions, which stalls the go-gtp chain at its first step.
