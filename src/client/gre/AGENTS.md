# GRE client (a host behind a tunnel on IP protocol 47)

One host (`overlay_ip`, plus `overlay_mac` on gretap) sits behind a GRE tunnel to one remote
endpoint (`remote_addr`, an IPv4 address or a name; any port is ignored).

- `tunnel` is `gre` (IPv4 in GRE, protocol type 0x0800; the default) or `gretap` (Ethernet in
  GRE, 0x6558).
- The client uses the server's raw socket (`src/server/gre/raw.rs`), the shared GRE codec
  (`src/utils/gre.rs`) and the vxlan framing (`src/server/vxlan/frame.rs`).
- It declares `RawSockets` and is gated `unix`, for the reasons given in
  `src/server/gre/AGENTS.md`.

## GRE header

- `key`: every packet carries it, and only packets with it are accepted back. With no `key`,
  packets are sent and accepted without one.
- `gre_checksum` puts a checksum on every packet, and `gre_sequence` numbers every packet from
  0. A Linux tunnel with `icsum` or `iseq` drops packets without them.
- Every packet leaves from the host's one task, so the numbers go out in order.
- Incoming checksums are verified when present. Incoming sequence numbers are accepted in any
  order.

## Sockets

It binds a raw protocol-47 socket to `local_address`, which defaults to the source of the route
to the remote. That address must be the one the remote endpoint is configured to send to.
Only packets from the remote's IP are considered.

## What runs in Rust

Like any host's stack, these are answered without the model:

- ARP for `overlay_ip` (gretap);
- echo requests for `overlay_ip`.

The ARP cache learns from replies, and from requests aimed at us.

## What the model does

| Action | Tunnel | What happens |
|---|---|---|
| `gre_ping{ip, data}` | both | On gretap it waits on ARP when the MAC is unknown. |
| `gre_send_udp{ip, port, source_port, data, encoding}` | both | On gretap it waits on ARP when the MAC is unknown. |
| `gre_resolve{ip}` | gretap only | ARP, answered by `gre_arp_resolved` or `gre_unreachable`. |
| `gre_send_ethernet{dst_mac, ethertype, data, encoding}` | gretap only | One frame from this host's MAC. Broadcast and multicast destinations are allowed. The EtherType is 0x0600 to 0xffff, and at most 1400 bytes of data. |
| `gre_send_keepalive` | gre only | A Cisco-style keepalive. See below. |

**ARP waits.** One request goes out per IP, at most `MAX_PENDING` (32) sends wait at once, and
each waits for `ARP_TIMEOUT` (2 s). After that the action is reported as `gre_unreachable`,
and an injected caller gets `Rejected`.

**Keepalives.** The client sends an IPv4 packet from the remote back to itself, carrying a bare
GRE header (protocol type 0), through the tunnel. The remote decapsulates it, routes it, and
so sends that GRE packet back. Linux does this with `ip_forward=1`, `accept_local=1` and
`rp_filter=0`. The reflection arrives as `gre_keepalive_reply`, with `rtt_ms` measured from the
oldest unanswered keepalive. It has no key, by construction, so the key check does not apply
to it. On a gretap tunnel a keepalive is refused: the remote's gretap would not route it.

**Refusals.** An action that does not apply to the tunnel is refused with a reason, and is not
sent.

**Events.** These come back to the model:

- `gre_ready`
- `gre_arp_resolved`
- `gre_unreachable`
- `gre_icmp_echo_reply`, with `rtt_ms` for our own pings
- `gre_udp_datagram`
- `gre_icmp_error`, for example `port_unreachable` with the original destination port
- `gre_keepalive_reply`

**Chain bound.** A chain is bounded at `MAX_FOLLOWUP_DEPTH` (8).

**Command channel.** Injected actions (`send_to_client`) go through the same checks.

## Not implemented

- TCP, IPv6, and IP fragmentation.
- More than one remote endpoint.
- Keepalives on gretap.
