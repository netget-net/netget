# GRE server tests

No LLM calls. A python policy makes NetGet host 10.99.0.2, with MAC 02:4e:47:00:00:02 on
gretap. NetGet's raw socket is bound to the host end of a veth, and every peer lives in a
network namespace (`tests/helpers/netns.rs`) at the other end, so the kernel's own GRE module
and NetGet never see the same packets.

## Running these

- `codec_test.rs` runs anywhere, unprivileged. It covers the shared codec
  (`netget::utils::gre`): every combination of key, checksum and sequence number round-trips,
  and the RFC 2784/2890 layout is checked against hand-computed bytes. Each refusal is a packet
  that would otherwise decode: version 1, each RFC 1701 bit, truncation inside each field, a
  checksum one bit off, a payload changed under its checksum, and a zero checksum. It also
  covers sequence stamping (the checksum is redone), and the server's keepalive check.
- The other two files need **Linux and root**: NetGet opens a raw socket in the test process.
  They also need iproute2 and the ip_gre module, and fail rather than skip without them.
- In CI they run in the `gre` job of `protocol-pairs.yml`, with the test binary run through
  `sudo -E`.
- Locally they were run in a rootful privileged container (Ubuntu 24.04, tshark 4.2.2, scapy
  2.5.0) on a Linux 7.2 aarch64 kernel. A rootless container cannot do it: `ip netns exec`
  mounts sysfs, which rootless podman refuses.

## `kernel_peer_test.rs`

The peer is the Linux kernel's `ip_gre`. Both the `gre` link (gr0, IPv4 in GRE) and the
`gretap` link (gt0, Ethernet in GRE) are configured with `key 42 csum seq`. The kernel drops a
packet from NetGet that lacks the key, has a missing or wrong checksum, or has a missing or
backwards sequence number, so every reply it accepts is evidence for all three.

For each link:

- `ping -c 2` exits 0 on the kernel's own validation.
- On gretap, the neighbour table holds the model's MAC, and `arping` (iputils) hears it.
- `printf hello | nc -u` prints `pong:hello`.
- The event names the tunnel, key 42, the peer and the inner addresses.
- 10.99.0.3 has no host, so the ping to it fails, and the event shows the model was asked.
- tshark captures the veth (`ip proto 47` only, because the host kernel answers each GRE
  packet with an ICMP port unreachable) and reads every GRE packet from both sides with no
  Warn-level expert info: the pcap oracle.
- NetGet's packets are dissected as `gre:ip` or `gre:eth`. They carry `gre.key` 0x0000002a and
  `gre.checksum.status` 1 (good), and their `gre.sequence_number` goes up. The fields used all
  exist in tshark 4.2.2.

**Offload.** The namespace's veth and tunnel link have tx checksum offload off. Across a veth
nothing computes an offloaded GRE or inner UDP checksum (see `tests/server/vxlan/AGENTS.md`).

**IPv6 noise.** The kernel also sends IPv6 through the tunnel (protocol type 0x86dd).
NetGet drops it, and tshark reads it clean.

## `scapy_peer_test.rs`

The peer is scapy (`scapy_peer.py`, run inside the namespace), a second GRE implementation
independent of both NetGet and the kernel. scapy builds each request, parses each reply with
its own GRE layer, and recomputes the reply's checksum over the bytes as they crossed the wire.

`scapy_reads_mirrored_headers_keepalives_and_refusals` covers mirroring and keepalives. Each
reply mirrors its own request:

- key 7 with a checksum and a sequence number gives a gretap ARP reply with key 7, a checksum
  that verifies, and sequence 0;
- a bare gre ping gives an echo reply with no key, no checksum and no sequence number;
- key 9 with a sequence number gives a UDP reply with key 9 and sequence 1;
- a checksum and a sequence number again give an ARP reply numbered 2 whose checksum still
  verifies. The number is written as the reply leaves, so the checksum has to be redone over
  it; the first reply's number is 0, the placeholder, and cannot show that.

A Cisco-style keepalive comes back as the bare 4-byte GRE header it carried.

It then sends packets that must be refused. Each is a request the policy would otherwise
answer, so a check that stops refusing shows up as a reply:

- a bad checksum;
- version 1;
- the RFC 1701 routing bit;
- a packet ending inside the sequence number;
- a packet ending inside the checksum;
- a truncated inner frame;
- protocol type 0x86dd;
- a keepalive addressed to someone other than the sender;
- a keepalive not from NetGet's address.

There must be no reply, and no new event reaches the model. tshark reads NetGet's five packets
clean, with the keys, checksum status, sequence numbers and protocol types scapy saw.

`key_peers_rate_size_and_backend_failure_are_bounded_before_the_model` starts one server after
another on the same address. Two raw sockets on one address would both answer.

- With `key: 7`, key 8 and keyless packets are dropped.
- With `peers` naming another address, there is no reply and no event.
- With `max_packets_per_second: 3`, a burst of ten gets three answers.
- A payload of exactly `MAX_INNER_BYTES` (9216, fragmented on the veth and reassembled by the
  kernel) is answered, and one byte more is not.
- With no script and a model backend that does not exist, there is silence and a
  `decision=fail_closed_llm_error` status line.

## Mutation-checked

Each of these was broken, the named test was seen to fail, and the change was restored:

| Broken | Failed |
|---|---|
| Checksum verification removed in `utils::gre::decode` | `codec_test::malformed_packets_are_refused`, and the refusal run of the scapy test |
| The key filter removed | The bounds test |
| The peer allowlist removed | The bounds test |
| The size bound made off by one | The bounds test |
| Answering with a default ARP reply when the model fails (fail-open) | The bounds test |
| `stamp_sequence` no longer redoing the checksum | The codec stamping test; both kernel tests (the kernel drops the replies); the scapy test at its second checksummed reply. With scapy's own checksum assertions relaxed, the same test fails in the pcap oracle instead: tshark reports "Incorrect GRE Checksum" |
