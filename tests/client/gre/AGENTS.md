# GRE client tests

No LLM calls. `kernel_peer_test.rs` needs **Linux and root**: NetGet opens a raw socket in the
test process. It also needs iproute2, ethtool, ping, python3, tshark and the ip_gre module, and
fails rather than skips without them. It runs in CI in the `gre` job of `protocol-pairs.yml`.
Locally it was run in a rootful privileged container on Linux 7.2 (see
`tests/server/gre/AGENTS.md`).

## The peer

The Linux kernel's `ip_gre` runs in a network namespace, as a `gre` link (gr0) and as a
`gretap` link (gt0), each with `key 42 csum seq`. The namespace is 10.99.0.1/24, with a python
UDP service on 9999. NetGet is 10.99.0.2, with `gre_checksum` and `gre_sequence` on. The kernel
drops a packet without the key, with a missing or wrong checksum, or with a missing or
backwards sequence number, so step 1 is already the evidence for all three.

## The chain

Both links run this chain:

1. On `gre_ready` the model pings 10.99.0.1. On gretap the kernel first ARPs for 10.99.0.2,
   and NetGet answers in Rust.
2. On the echo reply the model sends `echo <seq> <data>` to the service, and `nobody` to the
   closed port 9998.
3. The service's `ack:…` arrives as `gre_udp_datagram`, and the kernel's port unreachable
   arrives as `gre_icmp_error`.
4. The namespace's own `ping 10.99.0.2` is answered.
5. tshark on the veth reads every GRE packet both ways clean: the pcap oracle. NetGet's packets
   carry key 0x0000002a and a good checksum, numbered 0, 1, 2 and on.

**gre link.** The model also sends a keepalive on `gre_ready`, and one is injected later. The
kernel reflects both as `gre_keepalive_reply` once the namespace has `ip_forward=1`,
`accept_local=1` and `rp_filter=0`, the known Linux recipe for answering Cisco keepalives.
`gre_resolve` and `gre_send_ethernet` are refused as gretap-only.

**gretap link.**

- An injected `gre_send_ethernet` (EtherType 0x88b5) is read by a packet socket on gt0, from
  NetGet's MAC with the data intact.
- A resolve of an absent IP is Rejected after the ARP wait, with `gre_unreachable`.
- A resolve of 10.99.0.1 is Executed.
- A keepalive is refused as gre-only.

## Mutation-checked

Discarding the model's actions in `run_turns` fails both tests at the first echo reply.
