# VXLAN / Geneve / GRE server (tunnel endpoint)

A tunnel endpoint whose overlay hosts the model plays, chosen by `encapsulation`:

- `vxlan`: RFC 7348, port 4789 (the default, and the port the server takes when given none).
- `geneve`: RFC 8926, port 6081, options skipped.
- `gretap`: Ethernet over GRE (RFC 2784, with RFC 2890's key and sequence number, protocol
  type 0x6558) carried in UDP per RFC 8086, port 4754. Its Linux peer is a `gretap` link with
  `encap fou encap-dport 4754`, beside `ip fou add port 4754 ipproto 47` to take GRE-in-UDP
  back off that port.

Pass the port for geneve and gretap: the server's well-known port is VXLAN's.

All framing is hand-rolled in `frame.rs`, shared with the client:

- Ethernet and ARP.
- IPv4: the header checksum is checked, and fragments are reported but not reassembled.
- ICMP echo and errors.
- UDP: checksums are checked on input and written on output.

## GRE

`frame::decap` refuses, before anything reaches the model (the header checks are the shared
GRE codec, `src/utils/gre.rs`, which the `gre` protocol uses too; the protocol type check is
this protocol's own):

- a version other than 0 (1 is PPTP's enhanced GRE);
- RFC 1701's routing, strict-source-route or recursion bits (RFC 2784's "bits 1-5", less K
  and S), which RFC 2784 receivers discard;
- a protocol type other than 0x6558 (Transparent Ethernet Bridging);
- a datagram that ends inside any field its flags announce (checksum, key, sequence);
- a checksum that does not verify over the GRE header and payload.

The key is the GRE overlay's VNI: it is the event's `vni` (null when the frame has none), and
`vni` set on the server means "only this key", so keyless frames are dropped too. Sequence
numbers are accepted in any order on input; nothing is reordered or dropped for them.

**Replies mirror the request's header**: the same key (or none), a checksum when the request
had one, and a sequence number when the request had one. A Linux gretap with `icsum` or `iseq`
drops frames without them. The sequence number is the server's own counter, written in
`send()` as the reply leaves, under a lock that also covers the `try_send_to`: a peer with
`iseq` drops a number that goes backwards, and two answers built concurrently could otherwise
leave in the wrong order. The lock is never held across an await.

## Who answers

The model gets three events, each with `vni` (the VNI, or the GRE key), `vtep` and `src_mac`:

- `vxlan_arp_request` → `vxlan_arp_reply{mac}` (default `overlay_mac`). The MAC is
  remembered as that IP's, and used as the source of its later frames.
- `vxlan_icmp_echo_request` → `vxlan_icmp_echo_reply` (identifier, sequence and data
  mirrored).
- `vxlan_udp_datagram` → `vxlan_udp_reply{data, encoding}`, from the port it was sent to,
  back to the sender.

The frame is built from the request in `VxlanProtocol::for_frame`; the registry instance only
validates. Everything else that decodes (IPv6, TCP, other ICMP, ARP replies) is logged at
DEBUG and dropped. Malformed datagrams and frames are dropped with a WARN. With `vni` set,
other VNIs (or GRE keys) are dropped.

Replies go to the sending endpoint's IP **at the server's port**, not to the datagram's source
port. Tunnel endpoints listen on the port they send to; Linux sends from a hash-chosen source
port (fou's `encap-sport auto` too).

**Deliberately silent.** An IP with no host never answers. A backend failure is the same
silence, with `decision=fail_closed_llm_error` in the log.

## Not implemented

- TCP, IPv6, IP fragmentation, VLAN tags.
- MAC learning, and flooding to other VTEPs: one answering endpoint, not a switch.
- Geneve options (skipped on input, none sent).
- **GRE directly on IP protocol 47** is the separate `gre` protocol (`src/server/gre/`,
  `src/client/gre/`). It needs a raw socket, and privilege is declared per protocol
  (`PrivilegeRequirement`), so building it here would have made this protocol claim raw
  sockets for its unprivileged VXLAN, Geneve and GRE-in-UDP modes too. Both share the GRE
  header codec (`src/utils/gre.rs`) and this directory's `frame.rs`.
- GRE-in-UDP over IPv6, and RFC 8086's congestion-control and checksum-zero rules: what is
  sent is plain UDP with a checksum.
- Interop with a kernel Geneve peer is unverified here: the test kernel has no geneve module.
  tshark's dissector checks the framing.
