# WebTransport server — Experimental

WebTransport over HTTP/3 (draft-ietf-webtrans-http3, the draft-02 wire Chrome and aioquic
speak) on NetGet's fork of `wtransport` 0.7.2 over quinn. The fork (`netget-wtransport`,
github.com/netget-net/wtransport) lists what it changes in NETGET.md: an owned driver that closes on drop, bounded readers,
checked SETTINGS and bounded QPACK.

`mod.rs` owns the endpoint and admission: every incoming connection that completes the QUIC
and H3 handshake and sends its extended CONNECT within 10 s raises
`webtransport_session_request` (path, authority, origin, every header, peer address). The answer
must be `webtransport_accept` (optional extra response headers) or `webtransport_reject`
(403, 404 or 429 — the statuses wtransport can send); later actions in the same answer run on
the new session. A handler that answers neither is 404 (`decision=model_silent`); a failed
handler is 429 (`decision=fail_closed_llm_error`). `max_sessions` (64) bounds sessions; more
are refused at the QUIC layer.

`session.rs` runs an admitted session and is shared with the client:
- Streams are read whole, to FIN: 1 MiB and 30 s each. Past either, the stream is stopped and,
  if bidirectional, its sending side reset (code 1, `decision=protocol_refusal`); the handler
  never sees it.
- Each stream raises `webtransport_stream` (stream id, direction, data as text or hex), each
  datagram `webtransport_datagram`. A bidirectional stream is answered with
  `webtransport_reply`; with no reply it is finished empty, and a failed handler resets it
  (code 2).
- `webtransport_open_uni` writes and finishes a new stream; `webtransport_open_bi` does the
  same and waits for the peer's answer, which raises `webtransport_stream_reply`. That chain
  stops at depth 4.
- `webtransport_close` closes the QUIC connection with the code and reason (a session is its
  connection here). `webtransport_send_datagram` is limited by the path's datagram size.
- 32 streams, datagrams and injected actions in flight per session; handler turns on one
  session never overlap.

The certificate is `cert_path`/`key_path`, or a self-signed ECDSA P-256 certificate valid 14
days for localhost, 127.0.0.1 and ::1. Its SHA-256 is logged and published as
`protocol_data.certificate_sha256`, which a page passes as `serverCertificateHashes`.

Every session has a peer handle: `send_to_peer` accepts the four session actions.

Not implemented: other HTTP/3 requests (a GET never reaches the handler), several sessions on
one connection, the CLOSE_WEBTRANSPORT_SESSION and DRAIN capsules, flow-control capsules,
stream priorities, 0-RTT and migration.
