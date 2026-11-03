# DataLink Protocol Implementation

## Overview

Layer 2 (Data Link) packet capture and injection using libpcap. Allows the LLM to observe and respond to Ethernet frames
directly, bypassing IP/TCP/UDP layers. Primary use cases: ARP monitoring, custom layer 2 protocols, network packet
analysis, and honeypot operations at the lowest network level.

**Status**: Experimental (Layer 2 Protocol)
**Layer**: OSI Layer 2 (Data Link)
**Interface**: Any network interface (eth0, en0, wlan0, etc.)
**Privilege**: `PrivilegeRequirement::PacketCapture`

### Why not Beta

It was `Beta` until August 2026, on a suite that asserted nothing: three mocked E2E tests with
zero `assert!` and zero `verify_mocks()` calls, whose own comment conceded that "mock
verification is not possible in subprocess tests"; plus one `#[ignore]`d test that printed
*"No ARP reply received (this is expected if server isn't fully implemented)"* on failure and
returned `Ok(())`. Its `e2e_testing` metadata read "libpcap for packet validation", which
described no test in the tree. Beta means *works against a real client*, and nothing here had
ever demonstrated that a single frame reached the LLM.

**The capture path is no longer unproven, and the rating still does not move.**
`datalink_captures_a_real_loopback_frame` was run on 2026-09-08 (macOS 27, user in the
`access_bpf` group, `cargo test … --ignored`) and passed, along with
`datalink_invalid_bpf_filter_is_refused` — so a UDP datagram put on loopback really is captured
by libpcap, really does reach the event path, and its bytes really do appear in what the model
would be shown. The `UNVERIFIED` wording that used to sit in `metadata().notes` was true when
written and is gone.

It stays `Experimental` because the test that demonstrates this is `#[ignore]`d, and this repo
does not count an ignored test as evidence for a rating — that rule is what keeps `bluetooth_ble`
and `tor_relay` where they are, and DataLink gets no exemption. Note also that "works against a
real client" does not translate cleanly here: DataLink answers nothing, so the nearest thing to
an independent peer is the host's own network stack emitting a frame, which is exactly what the
ignored test uses. **What would move it**: a capture test that runs unprivileged in the ordinary
suite. There is no such thing on macOS or Linux — the handle needs the privilege — so the honest
position is that this protocol's central function is only ever exercised deliberately.

## Testing

`tests/server/datalink/e2e_test.rs` drives `DataLinkServer::spawn_with_llm` **in process** (no
subprocess, no mock Ollama; capture events are answered by a static handler and the LLM endpoint
is an unroutable address, so reaching a model would itself be a failure):

| Test | Privilege | Asserts |
|---|---|---|
| `datalink_unknown_interface_is_refused` | none | `spawn` returns `Err` naming the device |
| `datalink_startup_outcome_matches_capture_privilege` | none | `Ok` **iff** the pcap handle really opened; the unprivileged branch asserts the refusal text names `/dev/bpf*` or `CAP_NET_RAW` |
| `datalink_event_payload_reports_the_frame_and_any_truncation` | none | `packet_event_data` against literal ARP bytes: a short frame whole, a long one cut with `truncated`/`captured_length` set, and every field it emits declared on the event |
| `datalink_event_payload_decodes_a_loopback_frame_for_its_link_type` | none | `packet_event_data_for_link` on a `DLT_NULL` SYN-ACK: `link_type`, `family`, null MACs, decoded IPv4/TCP with MP_CAPABLE, the loopback zero-checksum note, every field declared |
| `datalink_invalid_bpf_filter_is_refused` | capture | an uncompilable BPF expression fails startup |
| `datalink_captures_a_real_loopback_frame` | capture | a UDP datagram put on loopback appears byte-for-byte in the captured hex **and** reaches the event path |

`tests/server/datalink/test.rs` covers the declarations with no privileges at all: the default
binding is this platform's loopback name, the privilege requirement is `PacketCapture` and
`is_met_by` agrees with the probe, `filter` is the only startup parameter and undeclared keys are
refused by name, and the action set is observation-only with every event carrying actions.

The two privileged tests are `#[ignore]`d, so cargo reports them as *ignored* and never as
passed - an unprivileged run cannot be mistaken for evidence that capture works. Run them with:

```bash
sudo -E ./cargo-isolated.sh test --no-default-features --features datalink \
    --test server -- server::datalink --ignored --test-threads=100
```

## Library Choices

### Core Packet Capture

- **pcap v2.2** - Rust bindings to libpcap
    - Low-level packet capture at data link layer
    - Promiscuous mode support (capture all packets on interface)
    - BPF (Berkeley Packet Filter) for packet filtering
    - Blocking API (wrapped in tokio::task::spawn_blocking)

- **libpcap** (system library, required dependency)
    - Industry-standard packet capture library (used by tcpdump, Wireshark)
    - Cross-platform (Linux, macOS, Windows with WinPcap)
    - Requires elevated privileges (root/admin)

- **Link-aware decoding, shared with the DataLink client** (`src/client/datalink/packet.rs`)
    - the link header is read for the handle's real link type, then IPv4 and TCP / UDP / ICMP
    - `packet_hex` stays beside the decoded fields, so anything not decoded is still there

**Rationale**: libpcap is the de facto standard for packet capture. The pcap crate provides thin
Rust bindings. The decoder is small and hand-written (no pnet) because what the model is shown
has to be spelled the way the DataLink client's actions accept it.

### Link type: what the first bytes of a frame are

`spawn_with_llm` reads the handle's DLT when it opens (`Capture::get_datalink`,
`packet::LinkType::from_dlt`) and logs it. **This server's default interface is loopback, and on
macOS `lo0` is `DLT_NULL`**: a 4-byte address family in host byte order and no MACs at all. The
event used to carry only `packet_hex`, which a model then read as Ethernet — six bytes of
"destination MAC" made of the family word and the start of the IP header. Every event now
carries, from `packet_event_data_for_link(frame, link_type, loopback)`:

| field | meaning |
|---|---|
| `link_type` | `"EN10MB"`, `"NULL"`, `"LOOP"`, `"RAW"`, `"LINUX_SLL"`, or `"DLT_<n>"` — always |
| `dst_mac` / `src_mac` | Ethernet only; `null` on a link with no MACs and for a runt |
| `ethertype` | `"0x0800"`; on NULL/LOOP the one the family means; `null` when unreadable |
| `family` | NULL/LOOP only: `"AF_INET"` / `"AF_INET6"` (or the number) |
| `ip`, `tcp`, `udp`, `icmp` | decoded headers, **absent** when the frame does not carry them |

The `tcp` object includes flags by name, sequence numbers and every TCP option in the DataLink
client's `send_ipv4_tcp` spelling, MPTCP subtypes named (`mp_capable` with version, flags and
keys). On a loopback interface a `0x0000` TCP/UDP checksum is `checksum_ok: null` with a
`checksum_note` saying it is checksum offload — the kernel never computes it for traffic that
never crosses a wire — rather than a failure. See `src/client/datalink/AGENTS.md` for the full
field list; `packet_event_data(frame)` is the Ethernet, non-loopback case.

## Architecture Decisions

### 1. Blocking I/O with Tokio Bridge

pcap has blocking API, Tokio is async:

**Solution**:

- Spawn packet capture in `tokio::task::spawn_blocking()`
- Blocking task runs pcap capture loop
- For each packet, spawn async task via `runtime.spawn()` for LLM processing
- This allows LLM processing to be async while pcap is blocking

**Tradeoff**: Extra task spawning overhead, but necessary for pcap API compatibility.

### 2. No Packet Injection (Yet)

Current implementation is **capture-only**:

- LLM can observe packets (receive events)
- LLM cannot inject packets (no send capability)
- Actions limited to: `notify_operator`, `ignore_packet`

**Why?**:

1. Packet injection requires root/admin privileges (same as capture)
2. Injection API in pcap crate is less mature
3. Raw socket creation is platform-specific
4. Focus on monitoring/honeypot use cases first

**Future Enhancement**: Add `send_frame` action that:

- Takes hex-encoded Ethernet frame from LLM
- Converts to bytes
- Injects via `pcap::Capture::sendpacket()`
- Allows LLM to respond to ARP, implement custom protocols

### 3. Interface Selection

User specifies network interface in prompt:

- Example: "listen on interface eth0 via datalink"
- Server uses `Device::list()` to find interface by name
- Fails if interface doesn't exist or lacks permissions

**Common Interfaces**:

- Linux: eth0, eth1, wlan0, lo
- macOS: en0, en1, lo0
- Windows: "\Device\NPF_{GUID}"

### 4. Promiscuous Mode

Capture is always in **promiscuous mode**:

- Captures all packets on network segment (not just packets addressed to this host)
- Requires elevated privileges
- Essential for network monitoring and honeypot scenarios

**Security**: Only works on same network segment (same switch/hub). Can't capture packets on other segments without
physical access.

### 5. BPF Filtering

Optional packet filtering via Berkeley Packet Filter:

- Example filter: "arp" (only ARP packets)
- Example filter: "tcp port 80" (only HTTP packets)
- Filter applied at kernel level (efficient, no user-space overhead)

**Prompt Format**:

```
listen on interface eth0 via datalink with filter "arp"
```

**Common Filters**:

- `arp` - Only ARP requests/responses
- `icmp` - Only ICMP (ping) packets
- `tcp port 80` - Only HTTP traffic
- `host 192.168.1.1` - Only packets to/from specific IP

### 6. Hex Encoding, and the cap on it

Packets are passed to the LLM as hex strings:

- Binary data (MAC addresses, EtherType, payload) not human-readable
- Hex format: "00112233445566778899aabbccddeeff..."
- LLM must parse hex to understand packet structure

**`packet_hex` is the first `MAX_HEX_BYTES_TO_MODEL` (2048) bytes, not the whole frame.** The
snaplen is 65535, and all of that as hex is 131070 characters of prompt for one packet — which
is both unaffordable and useless, since nothing a model decides about a frame depends on its
1400th byte. The event therefore carries four fields, not two: `packet_length` (the true
length, always), `packet_hex` (the prefix), `captured_length` (how much of it that is) and
`truncated`. A model told a 9000-byte frame was 2048 bytes long would draw wrong conclusions
from it, so the length and the prefix are reported separately.

`packet_event_data()` builds this and is pure and public, which is what lets
`datalink_event_payload_reports_the_frame_and_any_truncation` assert it against literal frame
bytes with no capture handle. The TRACE line is capped separately and much lower (512 bytes),
because the status channel is unbounded and a per-packet full hex dump is exactly the
high-frequency message the repo's logging rule forbids on it.

**Example ARP Request Hex**:

```
ffffffffffff     <- Destination MAC (broadcast)
001122334455     <- Source MAC
0806             <- EtherType (ARP)
0001             <- Hardware type (Ethernet)
0800             <- Protocol type (IPv4)
06               <- Hardware address length
04               <- Protocol address length
0001             <- Operation (ARP request)
...              <- Sender/target MAC/IP addresses
```

### 7. No Connection Concept

DataLink is stateless:

- No connections (unlike TCP)
- No sessions (unlike HTTP)
- Each packet is independent event
- LLM processes each packet separately

`metadata()` declares `.connectionless()`, as `arp`, `icmp` and `isis` do. It changes nothing
today — this server registers no connections for `cleanup_old_connections` to sweep — but the
flag is a statement about the protocol, and the four capture protocols should not disagree
about what they are.

**UI Display**: "Connection" in UI is just placeholder (not protocol requirement).

### 8. Dual Logging

All operations use **dual logging**:

- **DEBUG**: Packet summary (length, source interface)
- **TRACE**: Full packet hex dump
- **INFO**: LLM messages and high-level analysis
- **ERROR**: Capture errors, pcap failures, permission issues
- All logs go to both `netget.log` (via tracing) and TUI Status panel (via status_tx)

## LLM Integration

### Action-Based Response Model

The LLM responds to DataLink events with actions:

**Events**:

- `datalink_packet_captured` - Ethernet frame captured from interface
    - Parameters: `packet_length`, `packet_hex`, `captured_length`, `truncated`, `link_type`,
      `dst_mac`, `src_mac`, `ethertype`, and when present `family`, `ip`, `tcp`, `udp`, `icmp`
      (see **Link type** above)

**Available Actions**:

- `notify_operator` - Display analysis of packet (e.g., "ARP request from 192.168.1.1")
- `ignore_packet` - Don't process packet (no action)
- Common actions: `update_instruction`, etc.

**Future Actions** (not yet implemented — and note that neither is advertised anywhere, which
is the point; an action named in a doc but absent from `get_sync_actions()` is a wish, not a
capability):

- `send_frame` - Inject Ethernet frame (hex-encoded)
- `log_packet` - Log packet to file for later analysis

### Failure semantics: silence on the wire, `decision=` in the log

DataLink is one of the deliberately silent protocols, and for the strongest possible reason —
it is **capture-only**. There is no injection action, so there is no reply it *could* fabricate
when the model fails. The distinction the wire cannot carry lives in the log instead, one tag
per captured packet (grep `decision=`):

| tag | meaning |
|---|---|
| `decision=model_analysed` | the model answered with actions (a `notify_operator`, typically) |
| `decision=model_ignore` | the model explicitly chose `ignore_packet` — an analysis result |
| `decision=model_silent` | the model was asked and returned no actions |
| `decision=fail_closed_llm_error` | the LLM call errored; also logs `category=overloaded` vs `category=unavailable` from `WireFailure::classify`, and the full error |

The error text goes to the log and the status stream and nowhere else. Nothing is written to
the interface in any of the four cases, so the tags are the only way to tell a working
observation from a broken backend.

### Example LLM Responses

**ARP Request Analysis**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "ARP request: Who has 192.168.1.1? Tell 192.168.1.100"
    }
  ]
}
```

**Ignore Non-ARP**:

```json
{
  "actions": [
    {
      "type": "ignore_packet"
    }
  ]
}
```

**Custom Protocol Detection**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Unknown EtherType 0x88B5 - possibly proprietary protocol"
    }
  ]
}
```

## Connection Management

### No Connection State

DataLink has no connection concept:

- Each packet is independent event
- No handshake, no teardown
- No state persistence between packets

### Packet Processing Flow

1. pcap captures packet from interface
2. Packet data copied to `Bytes` buffer
3. Convert to hex string
4. Create `datalink_packet_captured` event
5. Spawn async task to call LLM
6. LLM analyzes packet and returns actions
7. Actions executed (notify_operator, ignore_packet, etc.)
8. Loop continues for next packet

### Concurrent Packet Processing, and the bound on it

- Each packet is handled in its own tokio task; packets from different sources run in parallel
- **At most `MAX_INFLIGHT_LLM_PACKETS` (32) at once.** A semaphore permit is taken in the
  capture loop and released when the turn ends; a frame that cannot get one is **dropped**, with
  a WARN on the first and every hundredth. libpcap delivers frames as fast as the link does and
  an LLM turn takes seconds, so the previous unconditional `runtime.spawn` grew the heap by a
  copy of every frame plus its hex for as long as the traffic lasted. Dropping is what a capture
  tool does under load.
- There is still no *queue*: a dropped frame is gone, deliberately. Narrow the BPF filter, or
  answer `datalink_packet_captured` with a script or static handler, if you need to keep up.
- The real serialisation is `--llm-max-concurrent` / `--llm-queue-timeout` / `--llm-max-queued`.
  (`--ollama-lock` is inert and its plumbing is deleted — do not reason about concurrency from
  it, as an earlier version of this file did.)

## Known Limitations

### 1. Requires Root/Admin Privileges

**Why**: libpcap needs a capture handle on the interface. One code path on all platforms
(`pcap::Capture::open()`), but different requirements:

- **Linux**: root, or `sudo setcap cap_net_raw,cap_net_admin+ep /path/to/netget`.
- **macOS / BSD**: root, **or** read/write access to `/dev/bpf*`. Stock macOS ships those as
  `crw------- root:wheel`, so an unprivileged user fails even when in the `access_bpf` group
  (Wireshark's *ChmodBPF* daemon is what usually loosens them). `pcap::Device::list()` succeeds
  without privileges, so enumeration says nothing about whether capture will work.
- **Windows**: `datalink` is not built into the `dist-windows` feature set.

**Failure mode**: startup is *not* fire-and-forget. `spawn_with_llm` awaits a `oneshot` readiness
signal from the blocking pcap task, so a permission failure, an unknown device, or an invalid BPF
filter all propagate out of `Server::spawn()` and land in `ServerStatus::Error(..)`. An
unprivileged MCP caller sees:

```
Failed to start server: failed to open pcap capture on 'en0' (needs root, or read access to
/dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux)
```

**Default interface**: `default_binding()` resolves to `lo` on Linux/Windows, `lo0` on macOS/BSD
(`DEFAULT_LOOPBACK_INTERFACE` in `actions.rs`).

**Test Impact**: E2E tests may fail if not run with privileges.

### 2. No Packet Injection

- LLM can observe packets but not send responses
- Can't implement ARP responder, custom protocols, etc.
- Actions limited to analysis and logging

**Future Enhancement**: Add `send_frame` action (see Architecture Decisions).

### 3. Performance Impact of LLM Processing

- Each packet triggers LLM call (~5s)
- High-traffic networks generate many packets
- pcap capture may drop packets if LLM too slow

**Workaround**: Use BPF filters to reduce packet volume (e.g., "arp" instead of capturing all traffic).

### 4. Partial decoding

- The link header (per link type), IPv4, TCP (with options), UDP and ICMP are decoded
- ARP, IPv6 and everything else are left to `packet_hex`; the model still parses those itself

### 5. Platform-Specific Interface Names

- Interface names vary by OS (eth0 vs en0 vs \Device\...)
- User must know correct interface name
- No interface discovery UI

**Workaround**: Use `Device::list()` to list available interfaces (could be exposed as command).

### 6. Capture Loop Blocks Tokio Thread

- pcap capture loop is blocking
- Runs in `spawn_blocking()` which uses separate thread pool
- May exhaust blocking thread pool under high load

**Rationale**: pcap API is inherently blocking - no async alternative without rewriting pcap.

## Example Prompts

### ARP Monitor

```
listen on interface eth0 via datalink with filter "arp"
For each ARP packet, analyze and display:
- Request type (ARP request or reply)
- Source IP and MAC address
- Target IP and MAC address
Log any unusual ARP patterns (ARP spoofing, gratuitous ARP, etc.)
```

### Packet Analyzer

```
listen on interface en0 via datalink
For each packet, identify:
- EtherType (IPv4, IPv6, ARP, custom)
- Source and destination MAC addresses
- If IPv4: source and destination IP
- If ARP: operation and addresses
Display summary for each packet
```

### Layer 2 Honeypot

```
listen on interface eth0 via datalink
Monitor for suspicious activity:
- ARP requests for non-existent IPs (network scanning)
- Unusual EtherTypes (custom protocols)
- Broadcast storms (repeated broadcast packets)
Log all suspicious packets with timestamp and details
```

### Custom Protocol Monitor

```
listen on interface eth0 via datalink with filter "ether proto 0x88B5"
Monitor for custom protocol (EtherType 0x88B5)
Parse payload as:
- Byte 0: Command type
- Bytes 1-4: Sequence number
- Bytes 5+: Data
Display command type and sequence number for each packet
```

## Performance Characteristics

### Latency

- Packet capture: <1ms (kernel-level)
- Hex encoding: <1ms
- LLM processing: 2-5s (typical)
- Total: ~2-5s per packet (LLM dominates)

**Impact**: On high-traffic networks (>1 packet/sec), pcap may drop packets.

**Solution**: Use BPF filters to reduce volume.

### Throughput

- **Low traffic** (<1 pkt/sec): All packets processed
- **Medium traffic**: up to 32 frames can be in front of the model at once
- **High traffic**: frames over that are dropped at the capture loop and counted in a WARN —
  they are not queued, and the log says how many went

**Best Use Cases**: Low-traffic protocols (ARP, custom protocols), not high-traffic (HTTP, streaming).

### Concurrency

- Each packet processed in its own task, at most 32 concurrently (semaphore)
- LLM concurrency is bounded by `--llm-max-concurrent` and the queue flags, not by
  `--ollama-lock`, which does nothing
- pcap capture runs in dedicated blocking thread and is stopped through `StopSignal`
- No CPU bottleneck (LLM API is bottleneck)

### Memory

- Each packet allocates buffer (~1500 bytes typical, 65535 max)
- Hex encoding allocates a string of 2× the *shown* bytes, capped at 2048 bytes (4096 chars)
- Bounded overall by the 32-permit semaphore: 32 × (frame + its hex prefix), not "however many
  frames arrive before the model catches up"

## Security Considerations

### Privilege Escalation

- Requires root/admin for promiscuous mode
- Security risk: running untrusted code with elevated privileges
- **Mitigation**: NetGet itself is open-source and auditable

### Privacy

- Promiscuous mode captures ALL packets on network segment
- May capture sensitive data (passwords, credentials if sent in cleartext)
- **Compliance**: May violate privacy laws in some jurisdictions without consent

### Network Impact

- Promiscuous mode doesn't inject traffic (passive observation)
- No impact on network performance (listening only)
- Future injection capability could disrupt network

### Honeypot Usage

DataLink is excellent for honeypots:

- Detect network scanning (ARP sweeps)
- Log attack patterns (custom protocol probes)
- Identify attacker MAC addresses
- Monitor lateral movement within network segment

## Use Cases

### 1. ARP Monitoring

- Detect ARP spoofing attacks
- Monitor ARP cache behavior
- Track IP-to-MAC mappings
- Identify network topology changes

### 2. Custom Protocol Development

- Test custom layer 2 protocols
- Debug protocol implementations
- Monitor protocol behavior
- Analyze protocol efficiency

### 3. Network Forensics

- Capture packets for later analysis
- Identify protocol usage patterns
- Detect anomalies (unusual EtherTypes)
- Track device behavior (MAC address tracking)

### 4. Educational

- Learn packet structure
- Understand Ethernet framing
- Study protocol behavior
- Experiment with BPF filters

### 5. Honeypot Operations

- Detect reconnaissance (ARP scanning)
- Log attack traffic
- Identify attacker devices
- Monitor malicious behavior

## References

- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [pcap crate Documentation](https://docs.rs/pcap/latest/pcap/)
- [Berkeley Packet Filter (BPF) Syntax](https://biot.com/capstats/bpf.html)
- [Ethernet Frame Format](https://en.wikipedia.org/wiki/Ethernet_frame)
- [ARP Protocol (RFC 826)](https://datatracker.ietf.org/doc/html/rfc826)
- [EtherType List](https://en.wikipedia.org/wiki/EtherType)
- [Wireshark](https://www.wireshark.org/) - For manual packet analysis and testing
