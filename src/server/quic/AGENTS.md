# Raw QUIC server

Feature `quic`, protocol `QUIC`, default UDP/443. This is raw RFC 9000/9001
bidirectional stream I/O. ALPN is `netget-quic`; it never advertises `h3` and does
not parse HTTP/3 HEADERS/DATA or QPACK. The HTTP3 protocol is separate.

Events are `quic_connection_opened` (notification without stream actions),
`quic_stream_opened` and `quic_data_received`. Stream actions are `send_quic_data`,
`wait_for_more`, `close_this_stream`. No async server-send action is advertised:
responses belong to the stream which generated the event. Client injection is
available through the separate raw QUIC client.

Payloads have explicit encoding: utf8 by default, hex or base64. Received printable
ASCII is represented as utf8; other bytes use hex. Echo scripts must preserve both
`data` and `encoding`. Encoded action text is capped at 4 MiB before cleaning or
decoding; each decoded response action is capped at 1 MiB. Decode errors do not
include the full submitted payload. `wait_for_more`
does not replay its input; a handler can retain partial application messages in
memory. Stream data events follow transport reads, not application records.

The registered accept task owns all connection futures, which own all stream
futures. Endpoint and connection guards close transport state on abort. Limits
are 64 connections including pending handshakes, 32 streams per connection,
10-second handshakes, 30-second whole stream lifetimes and 300-second connection
idle timeout. Receive credit is bounded; unidirectional streams and migration are
disabled. Client STOP_SENDING cancels pending stream work. FIN or close_this_stream
finishes the response and releases the stream. Removing the server releases its
UDP endpoint and all owned sessions. Counters update against the actual connection.
Stream IDs are allocated inside their owned futures: the accept branch must keep
polling older streams which may already be queued for the fair AppState lock.

TLS 1.3 is mandatory. Existing TLS parameters are supported: cert_path/key_path,
common_name, san_dns_names, validity_days, organization, organizational_unit.
There is no tls_enabled switch. Default generated localhost certificates must be
explicitly trusted by clients, or supply your own certificate/key pair.

Backend errors reset streams with application-local codes: unavailable 0x0102,
overload 0x0107. These numeric values preserve existing raw peer compatibility;
they do not imply HTTP/3 semantics. Internal error strings are only logged.
Cancellation uses application code 3. No request_filter, server-initiated streams,
unidirectional streams, 0-RTT, or HTTP/3 framing is implemented.

The server retains its existing Beta rating. Existing Quinn tests cover text and
binary echo, custom responses, concurrent streams and backend failure. An
additional independent aioquic 1.3.0 client checks certificate authentication,
binary payloads and concurrent streams. See `tests/server/quic/AGENTS.md`.

## Shared certificate validation

QUIC uses `extract_required_tls_config_from_params`, the mandatory-TLS form of
the shared certificate extractor. SAN arrays must contain strings; malformed
entries fail with their index before binding. Certificate lifetime and
certificate/key pairing use the same checks as the other TLS protocols.

## DATAGRAM (RFC 9221)

`utils::quic::transport` advertises datagram support (Quinn's `max_datagram_frame_size`)
with a 64 KiB receive and send buffer (`DATAGRAM_BUFFER_BYTES`). A DATAGRAM frame from the
peer raises `quic_datagram_received` with `data`, `encoding` (utf8 for printable text,
otherwise hex — the same pair `send_quic_data` uses), `bytes` and `max_datagram_size`, the
largest payload the peer accepts. Its only action is `send_quic_datagram`, which executes to
`ActionResult::Custom { name: "quic_datagram", data: <hex> }`; `QuicServer::handle_datagram`
sends that as a DATAGRAM on the same connection and logs, rather than sends, one over the
peer's limit. The executor refuses a payload over 1500 bytes outright (`MAX_DATAGRAM_BYTES`).

Each connection runs **one datagram turn at a time**: `read_datagram` is not polled while a
turn is in flight, so a fast sender's datagrams wait in Quinn's bounded buffer and the oldest
are dropped there. That is RFC 9221's own semantics for an unreliable frame, and it is the only
bound a sender cannot outrun. A datagram the backend could not answer is silence, logged with
`decision=fail_closed_llm_error` / `_overloaded` / `fail_closed_timeout`: answering a datagram
is optional, so there is no wire refusal to send.

Evidence: `tests/server/quic/datagram_test.rs` — aioquic 1.3.0 and quic-go 0.54 each send a
text and a binary datagram and receive the handler's answers. See `tests/server/quic/AGENTS.md`.
