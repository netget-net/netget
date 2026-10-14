# VXLAN / GRE client tests

No LLM calls. `kernel_peer_test.rs` (Linux; root or passwordless sudo, plus iproute2 and
ethtool, and the vxlan, ip_gre and fou modules) runs the kernel's own tunnel driver in a
network namespace: 10.99.0.1/24 on VNI (or GRE key) 42, with a python UDP service on 9999.
NetGet is 10.99.0.2. Two peers run the same chain:

- the vxlan driver (`vx0`, VNI 42);
- the gretap driver over fou (`gt0`: `ip fou add port 4754 ipproto 47`, then a gretap with
  `key 42 csum seq encap fou encap-sport auto encap-dport 4754`), with NetGet's
  `gre_checksum` and `gre_sequence` on. The kernel drops a frame without the key, with a
  missing or wrong checksum, or with a missing or backwards sequence number, so step 1 is
  already the evidence for all three.

1. On `vxlan_ready` the model pings 10.99.0.1. The kernel ARPs for 10.99.0.2 before it
   answers, and NetGet answers that ARP in Rust.
2. On the echo reply the model sends `echo <seq> <data>` to the service and `nobody` to the
   closed port 9998.
3. The service prints what it got and answers `ack:…`, which arrives as
   `vxlan_udp_datagram`. The kernel's port unreachable arrives as `vxlan_icmp_error`.
4. The namespace's own `ping 10.99.0.2` is answered.
5. An injected resolve of an absent IP is Rejected after the ARP wait, with
   `vxlan_unreachable`.

Mutation-checked: discarding the model's actions fails at the first echo reply; for gretap,
never advancing the client's sequence number, or not writing its GRE checksum, fails the same
way (the kernel drops the frames). The tunnel link's tx checksum offload is off, and for gretap
the veth's too, for the reasons given in `tests/server/vxlan/AGENTS.md`.
