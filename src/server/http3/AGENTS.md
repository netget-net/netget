# HTTP/3 server

Feature `http3` registers HTTP3 client and server separately from raw QUIC.
Default UDP/443, ALPN exactly `h3`, TLS 1.3, RFC 9114 HEADERS/DATA/control/QPACK
framing implemented by h3 0.0.8 and h3-quinn 0.0.10 over quinn 0.11/rustls 0.23.
This is a native feature; browser feature sets do not enable it.

`http3_request_received` carries method, path with query, header object (repeated
values use arrays), UTF-8 body, trailer object, stream index and peer address.
`send_http3_response` supplies final status 200..599, headers, UTF-8 body and
trailers. `cancel_http3_request` resets this request, without closing unrelated
streams. HEAD suppresses the response body; 204/205/304 require an empty body.
No filesystem, database, routes or response store is implemented in the protocol.
Static handlers, scripts, manual decisions and model actions supply responses.
TE is accepted only in request headers with the token `trailers`; responses and
both trailer sections reject TE before handlers or writes.

Both PEM `cert_path` and `key_path` must be supplied together, or a localhost
certificate is generated. Clients must explicitly trust self-signed certificates.
Bounds: 32 KiB decoded header/trailer field sections including pseudo-fields, 8 MiB UTF-8 bodies,
64 connections including pending TLS (max_connections 1..256), 32 concurrent
requests per connection (max_streams 1..32), 10-second handshake (1..60),
30-second whole request/handler/write deadline (1..300), 300-second QUIC idle
(1..3600). Receive credit is bounded. Migration and 0-RTT are disabled.

The registered endpoint task owns connection futures; each owns request futures.
The HTTP/3 connection accept/control path remains polled while RequestResolvers,
body reads and handlers are pending. Over-capacity incoming connections are
refused. Removal drops every owned request and closes the endpoint, including
pending reads or handlers. Stream guards reset unfinished responses and stop
receives on timeout/cancellation. No detached task retains a socket.

A failed handler produces generic 503; no usable response or invalid individual action produces
500. Multiple final responses reset the request. Decision tags distinguish model_answer/model_reject/model_silent from
fail_closed_llm_error (with shared WireFailure category), action/request failures
and timeout. Optional GREASE frames are disabled for tested aioquic interoperability. Internal
errors stay in logs. Malformed/oversize bodies and aborted exchanges reset their
request streams. h3 enforces HTTP/3 frame and field section validation. Connection
counters count semantic message bodies, not encrypted UDP datagrams.

Experimental: independent pinned aioquic 1.3.0 coverage exists in both directions,
plus NetGet pairing and lifecycle/bounds tests. No second independent HTTP/3
implementation, pcap oracle or fuzz target is claimed. No server push, HTTP
DATAGRAM, WebTransport, 0-RTT, migration, binary-body action or priority scheduler.
Client urgency is passed as an ordinary `priority` header for handlers to inspect.

The local h3-quinn pending-read cancellation patch retains original MIT licensing
and upstream provenance. See the `netget-h3-quinn` fork, github.com/netget-net/h3 (NETGET.md) and
`tests/http3_cancellation_test.rs` (failed upstream, passes patched).
