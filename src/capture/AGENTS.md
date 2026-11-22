# Packet capture (`src/capture/`)

**Packet capture: NetGet writes the pcap itself** (`src/capture/`), with no libpcap and no
privilege, because it owns the sockets. `capture` on an instance (`ServerForm`/`ClientForm`, MCP
`start_*`/`update_*`, `.netget` files) is `true` (`netget-<server|client>-<id>-<protocol>.pcap` in
the capture directory), a file name, or `false`; `--capture <dir>` records every instance the
process starts. Hot-applied: a connection already open is opened in the file (SYN, SYN-ACK, ACK) at
its next byte. The file is classic pcap, `LINKTYPE_RAW`, with IP/TCP/UDP headers synthesised from
the real 4-tuple and sequence numbers that advance by exactly the bytes carried, so "Follow TCP
Stream" reassembles it; a FIN per side closes it. Writes go through a bounded queue to a writer
thread (a full queue drops and counts, never blocks), and a file rotates to `<path>.1` at 256 MiB.
There is **no central seam carrying payloads** (`update_connection_stats` sees counts only), so a
protocol adopts it: wrap the stream in `capture::tcp::CapturedStream` before splitting it, or call a
`capture::udp::UdpTap` after each `recv_from`/`send_to`. Adopted today: servers `tcp`, `telnet`,
`http`, `redis`, `dns` (UDP and TCP), `udp`; client `tcp` (`capture::adopted` is the list; any
other protocol's file stays empty and `server_status` says so). Two guards: an existing file that
is not a pcap is never overwritten, and a `capture` read from an *action* (the model's
`open_server`, a `.netget` file, a replayed session) may only name a file inside the capture
directory. `tests/capture_pcap_test.rs` reads NetGet's files back with `tshark`.

The dashboard's `[ wireshark ]` modal (`src/tui/wireshark.rs`, described in
`src/tui/AGENTS.md`) offers the file this module writes; MCP's `capture` parameter is in
`src/mcp_stdio/AGENTS.md`.
