# Raw QUIC client

Feature `quic`, protocol `QUIC`; distinct from `HTTP3`. Default ALPN is
`netget-quic`. `alpn` can select a peer's other raw application token. The client
always verifies certificate and hostname against public WebPKI roots plus the
optional `ca_cert_path` PEM file. `server_name` overrides authentication/SNI.

`send_quic_data` opens one bidirectional stream, sends the decoded payload and
FIN, and reads until the peer's FIN. Every action opens a new stream. Payload
encoding is explicit: utf8 (default), hex or base64. Response events use utf8 for
printable ASCII and hex for other bytes. No application framing is added.
`wait_for_more` waits and `disconnect` cancels all streams and closes the endpoint.

Events `quic_connected`, `quic_data_received`, `quic_stream_error` use the standard
budgeted event dispatcher, including static/script/manual handlers, memory and
memory updates. Injected actions report completion after the wire response. A
parked handler does not block injected commands or concurrent streams.

Limits: 4 MiB encoded action text (including whitespace), rejected before decoding;
1 MiB decoded bytes per direction, 32 active exchanges and 32 event handlers, 32 actions
per result, and four exchanges per automatic chain. Resolution/handshake defaults
to 10s (range 1..60), each stream to 30s (1..300), connection idle to 300s
(1..3600). Timeouts/removal stop and reset streams. One registered owner polls all
stream and event futures, then closes its endpoint on removal. Connect returns
the actual owned local UDP socket address.

Not implemented: appending to an existing stream, incoming server streams,
unidirectional streams, DATAGRAM, reconnect, 0-RTT or a connection migration
policy. This finite request/response API is suitable for peers that end their
response with FIN; it is not an interactive append API.

Maturity: Experimental. See `tests/client/quic/AGENTS.md` for independent aioquic
1.3.0 evidence and setup. The Rust transport is quinn 0.11/rustls.

## DATAGRAM (RFC 9221)

`send_quic_datagram` (data + encoding, at most 1500 bytes and the connection's limit) sends an
unreliable DATAGRAM frame; the outcome is `Executed` once Quinn queued it, or an error naming
the peer's limit. Incoming DATAGRAM frames raise `quic_datagram_received` (data, encoding,
bytes) as a new handler turn — a datagram cannot be correlated with anything sent, so the
follow-up depth of streams does not apply. Instead, datagrams sent in answer to a received
datagram are counted, and past `MAX_FOLLOWUP_DEPTH` (4) consecutive ones they are dropped with
a warning until the operator or a non-datagram event sends something; an echoing peer and a
handler that answers every datagram therefore stop after four replies
(`tests/client/quic/datagram_depth_test.rs`). While the 32 handler slots are full, the
run loop stops reading datagrams and Quinn's 64 KiB buffer drops the oldest.
`quic_connected` carries `max_datagram_size` (null when the server did not negotiate RFC 9221).
