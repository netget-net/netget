# VXLAN / Geneve / GRE client (a host on the overlay)

One host (`overlay_ip`, `overlay_mac`) behind a tunnel to one remote endpoint (`remote_addr`),
on one `vni`. `encapsulation` is `vxlan` (4789), `geneve` (6081) or `gretap` (Ethernet over
GRE in UDP, 4754: a Linux `gretap` link with `encap fou`). It uses the server's framing
(`src/server/vxlan/frame.rs`); `src/server/vxlan/AGENTS.md` has what GRE input is refused.

## GRE

- `vni` is the GRE key. Unlike VXLAN and Geneve, which default to VNI 1, gretap with no `vni`
  sends and accepts frames **without** a key, as a Linux gretap without `key` does.
- `gre_checksum` puts a checksum on every frame, and `gre_sequence` numbers every frame from 0
  (what a Linux gretap with `icsum` / `iseq` demands; it drops frames without them). Both are
  refused with any other encapsulation. Every frame leaves from the host's one task, so the
  numbers go out in order.
- Incoming checksums are verified when present; incoming sequence numbers are accepted in
  any order.

## Sockets

It binds `local_address:<tunnel port>`, because the remote endpoint sends there. It sends
encapsulated frames from that socket to `remote_addr`. `local_address` defaults to the source
of the route to the remote.

## What runs in Rust

Like any host's stack: ARP and echo requests for `overlay_ip` are answered without the model,
and the ARP cache learns from replies and from requests aimed at us.

## What the model does

- `vxlan_resolve{ip}`, `vxlan_ping{ip, data}` and `vxlan_send_udp{ip, port, source_port, data,
  encoding}`.
- These wait on ARP when the MAC is unknown: one request per IP, at most `MAX_PENDING` (32)
  waiting, for `ARP_TIMEOUT` (2 s). After that the action is reported as
  `vxlan_unreachable`, and an injected caller gets `Rejected`.
- Events: `vxlan_ready`, `vxlan_arp_resolved`, `vxlan_icmp_echo_reply` (with `rtt_ms` for
  our own pings), `vxlan_udp_datagram`, and `vxlan_icmp_error` (e.g. `port_unreachable`
  with the original destination port).
- Chains are bounded at `MAX_FOLLOWUP_DEPTH` (8).

Only frames from the remote endpoint's IP on our VNI (or GRE key, or keyless when we have
none) are considered.

## Not implemented

GRE directly on IP protocol 47 (a raw socket: the separate `gre` protocol, `src/client/gre/`),
and GRE-in-UDP over IPv6.
