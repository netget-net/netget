# VXLAN / Geneve / GRE server tests

No LLM calls; a python policy makes NetGet host 10.99.0.2 on VNI (or GRE key) 42.

- `kernel_peer_test.rs` (Linux; root or passwordless sudo, plus iproute2 and ethtool, and the
  vxlan, ip_gre and fou modules): the kernel's own tunnel driver in a network namespace
  (`tests/helpers/netns.rs`), 10.99.0.1/24. Two peers run the same exchange:
  - the vxlan driver (`vx0`, VNI 42, port 4789);
  - the gretap driver over fou (`gt0`: `ip fou add port 4754 ipproto 47`, then a gretap with
    `key 42 csum seq encap fou encap-sport auto encap-dport 4754`). The kernel drops any
    frame from NetGet without the key, with a missing or wrong GRE checksum, or with a missing
    or backwards sequence number, so the ping passing is the evidence for all three.

  For each:
  - `ping` exits 0 only on valid echo replies.
  - `ip neigh` holds the MAC from the model's ARP reply.
  - A python UDP socket in the namespace reads `pong:hello`.
  - 10.99.0.3 has no host, so ping fails.
- `raw_vtep_test.rs` (Linux in practice: it binds 127.0.0.9, which macOS does not route): the
  test is the remote endpoint, for VXLAN, Geneve and GRE (with key, checksum and sequence
  number; and with none of them). It runs ARP, ping and UDP, checks each reply mirrors the
  request's header (the GRE replies number themselves 0, 1, 2), and tshark's vxlan, geneve and
  gre dissectors (the pcap oracle; `gre` is reached by `-d udp.port==4754,gre`) read every
  frame. Refusals before the model:
  - VXLAN: the I flag clear, another VNI, a truncated inner frame, a bad IPv4 header checksum.
  - GRE (`gre_refusals_before_the_model`): version 1, protocol type 0x0800, the RFC 1701
    routing bit, a checksum that no longer matches, another key, no key, a datagram ending
    inside the sequence number, one ending inside the checksum, and a truncated inner frame.
    Each is an ARP request the policy would otherwise answer, so a check that stops refusing
    shows up as a reply (or, for the truncations, as a dead receive loop).

  An IP with no host is silence. `gre_header_round_trip_and_sequence_stamping` checks the GRE
  codec alone, every combination of the optional fields.

**The namespace's tunnel link has tx checksum offload turned off** (`ethtool -K <dev> tx off`).
Across a veth nothing completes a CHECKSUM_PARTIAL inner UDP checksum, so without it NetGet
would (rightly) drop every UDP datagram as having a bad checksum. A physical NIC fills the
checksum in. ICMP is unaffected, because the kernel always checksums it in software.

**For gretap the namespace's veth has tx offload off too.** The kernel hands the GRE checksum
to the underlay device, and across a veth nothing computes it: every frame leaves with GRE
checksum 0 (tshark: "Incorrect GRE Checksum"), and NetGet refuses all of them. Measured on a
7.0 kernel: off on `gt0` alone changes nothing; off on the veth gives correct checksums.

Mutation-checked (each check removed, the named tests seen to fail, then restored): the GRE
version, RFC 1701 bits, protocol type, field-length and checksum-verify checks
(`gre_refusals_before_the_model`, and the round-trip test for the checksum); the key filter
(both refusal tests); replying without the request's sequence number, and never advancing the
reply counter (the raw gretap test and the kernel gretap test); and not writing the checksum
in the encoder (the round-trip and raw gretap tests, and the client's kernel test).
