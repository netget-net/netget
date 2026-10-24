# GRE server (tunnel endpoint on IP protocol 47)

A GRE tunnel endpoint whose hosts the model plays. Peers are a Linux `gre` or `gretap` link, a
router's GRE tunnel, or a firewall's. GRE-in-UDP (RFC 8086, a gretap over fou) is the `vxlan`
protocol's `gretap` encapsulation instead, which needs no privilege.

## Why it is a protocol of its own

GRE directly on IP needs a raw socket, and `PrivilegeRequirement` is declared per protocol.
Built into `vxlan`, it would have made that protocol claim raw sockets for its unprivileged
VXLAN, Geneve and GRE-in-UDP modes too. Here the protocol declares `RawSockets`, and the
startup gate refuses it without root (or `CAP_NET_RAW` on Linux).

## Platform

It is gated `unix` (`src/server/mod.rs`): it uses a raw IPv4 socket through `socket2` and
tokio's `AsyncFd`, both available on macOS and Linux, and no Linux-only API.

- **Linux** delivers a copy of every protocol-47 packet for the bound address to each raw
  socket *and* to its own GRE module (`ip_gre`). A kernel `gre`/`gretap` link on the same local
  address would therefore see the same packets as NetGet. Put NetGet and any kernel tunnel on
  different addresses, or in different namespaces, as the tests do. With no matching kernel
  tunnel, the host kernel also answers each packet with an ICMP port unreachable. That is
  harmless, because a GRE sender ignores it.
- **macOS**: XNU has no GRE in the kernel, so raw sockets get every protocol-47 packet. The
  received IPv4 header's total length is in host order there, which is why `raw.rs` takes the
  payload to run to the end of what was received. The macOS path compiles but **has not been
  run as root**: no passwordless root was available where it was written.

## Socket

`raw.rs` holds the socket, shared with the client:

- A raw IPv4 socket for protocol 47, bound to the server's host address (default
  `127.0.0.1`; a host that is not an IPv4 address is refused). There is no port, so the
  registry records `<host>:0`.
- On receive the kernel hands over the whole IP packet. The outer header is checked (version 4,
  header length, protocol 47) and the GRE packet is what follows it.
- On send, `IP_HDRINCL` is off, so the kernel writes the IP header with the bound address as its
  source.

## GRE

`src/utils/gre.rs` is the codec, shared with `vxlan`. It refuses the following before anything
else is done:

- a version other than 0 (1 is PPTP's enhanced GRE);
- RFC 1701's routing, strict-source-route or recursion bits;
- a packet that ends inside any field its flags announce (checksum, key, sequence number);
- a checksum that does not verify over the GRE header and payload (a zero checksum is a
  checksum).

Sequence numbers are accepted in any order on input.

### Order of checks

Each packet goes through these checks in order, and anything refused is dropped before the
model:

1. **The allowlist.** The `peers` startup parameter is a list of IPv4 addresses. A packet
   from any other source is dropped. With no `peers`, every endpoint that sends to the address
   is answered.
2. **The codec.** Each refusal above is logged at WARN.
3. **The key.** With the `key` startup parameter, only packets carrying that key are taken.
   Keyless packets are dropped too.
4. **The payload size.** More than `MAX_INNER_BYTES` (9216, a jumbo frame) is refused. The
   receive buffer holds a whole IPv4 packet (65535 bytes), so nothing is cut short to fit, and
   a fragmented packet arrives reassembled by the kernel.
5. **The protocol type.** 0x6558 (Transparent Ethernet Bridging) is gretap, and its payload
   goes through `src/server/vxlan/frame.rs`'s Ethernet/ARP/IPv4/ICMP/UDP parser. 0x0800
   (IPv4) is gre, parsed as a bare IPv4 packet (`frame::parse_ipv4_packet`). Anything else is
   logged at DEBUG and dropped.
6. **The rate.** `max_packets_per_second` (default 100, at most 10000) applies to what reaches
   the model or is reflected as a keepalive. It is a token bucket with a one-second burst, and
   a flood is logged once a second with `decision=rate_limited`.
7. **Answers in flight.** At most `MAX_IN_FLIGHT` (64) answers are worked on at once. Beyond
   that, packets are dropped.

### Keepalives

Cisco-style keepalives are reflected in Rust. The model is not asked.

A keepalive is a gre (0x0800) packet whose inner IPv4 packet carries GRE and is addressed from
this endpoint back to its sender. A tunnel endpoint answers it by forwarding it, so NetGet
sends the inner GRE packet to its destination. It reflects only when all of these hold:

- the inner header checksum verifies;
- the inner destination is the outer source (the peer);
- the inner source is the server's own address;
- the inner GRE decodes.

Any other inner protocol-47 packet would let a stranger use the endpoint to send GRE
elsewhere, so it is not forwarded.

## Who answers

The model gets three events. Each carries `tunnel` (`gretap` or `gre`), `key` (null when
none), `peer` (the outer source) and `src_mac` (null for gre).

| Event | Answer |
|---|---|
| `gre_arp_request` (gretap only) | `gre_arp_reply{mac}` (default `overlay_mac`). The MAC is remembered as that IP's (at most 4096 IPs) and used as the source of its later frames. |
| `gre_icmp_echo_request` | `gre_icmp_echo_reply`: identifier, sequence and data mirrored. |
| `gre_udp_datagram` | `gre_udp_reply{data, encoding}`: from the port it was sent to, back to the sender. |

The packet is built from the request in `GreProtocol::for_packet`, and the registry instance
only validates.

**Replies mirror the request's header.** A reply carries:

- the same key, or none;
- a checksum when the request had one;
- a sequence number when the request had one.

The sequence number is the server's own counter, written as each reply leaves under a lock
that also covers the `try_send_to`. A peer with `iseq` drops a number that goes backwards. The
lock is never held across an await.

**Deliberately silent.** An IP with no host never answers. GRE has no error message of its
own, and every ARP, echo or UDP reply asserts that a host exists. A backend failure is the
same silence, with `decision=fail_closed_llm_error` in the log. The other decisions are
`model_silent`, `model_answered` and `fail_closed_action_error`.

`.connectionless()`: each packet is answered alone. What carries across packets is the reply
sequence counter and the MAC table, which are per server, not per peer. Nothing is interpreted
in the light of a previous packet, so the 10-second idle sweep is right for its entries.

## Not implemented

- IPv6, outer or inner.
- PPTP's enhanced GRE (version 1), and WCCP, ERSPAN or any other protocol type.
- TCP, IP fragmentation of the inner packet, VLAN tags, and MAC learning.
- Originating keepalives. The client does that.

## Maturity

Experimental. The peers are the Linux kernel's `ip_gre` and scapy, and both are measured only
in a Linux container as root (`tests/server/gre/AGENTS.md`). The `gre` pair job had not run in
CI when this landed. macOS has never been run as root.
