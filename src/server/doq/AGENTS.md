# DNS over QUIC (DoQ)

Feature `doq` registers a distinct server and client, default UDP/853. UDP/53 is
refused as required by RFC 9250. Stack: ETH > IP > UDP > QUIC > DNS.

The server uses existing quinn 0.11, rustls 0.23 and hickory-proto 0.26 dependencies.
There is no HTTP/3 or raw-QUIC compatibility alias. ALPN is exactly `doq`.

## Implemented scope

A client opens one bidirectional stream per question. Both endpoints require one
2-byte-length-prefixed DNS message followed by FIN. IDs are always zero. Incoming
nonzero IDs, malformed framing, extra messages, oversize messages, and EDNS TCP
keepalive cause DOQ_PROTOCOL_ERROR (2) connection closure. Datagram DNS and
unidirectional/server-initiated streams are not permitted.

The server accepts single-question IN-class QUERY operations for A, AAAA, CNAME,
MX, TXT and ANY. It delegates the existing typed DNS actions and combines multiple
record actions into one response. It echoes the wire question and recursion flag
and sets ID zero independently of the action. Raw hexadecimal `send_dns_response`
is deliberately absent and rejected. Handlers can return NXDOMAIN or ignore a
query; ignore resets that stream with DOQ_NO_ERROR, releasing its resources.
Failed handlers and invalid actions produce SERVFAIL, with internal error details confined to logs.
Terminal logs identify `decision=model_answer`, `model_reject` (explicit NXDOMAIN or
REFUSED negative answer), `model_silent` (no usable response), `fail_closed_llm_error`
(with `category=overloaded` or `unavailable` from shared WireFailure),
`fail_closed_action_error`, `fail_closed_response_error`, `fail_closed_send_error`,
`fail_closed_timeout`, and `peer_cancelled`. Negative DNS answers are distinguished
from backend failures; these tags do not claim authorization semantics.

Other record types (including NS, SOA, PTR, SRV, CAA, DS, DNSKEY, RRSIG, NSEC,
AXFR and IXFR), non-IN classes and non-QUERY operations (UPDATE, NOTIFY, etc.)
receive NOTIMP. A question count other than one receives FORMERR. Unsupported
opcodes rejected by hickory parsing are protocol errors. There is no recursive
resolver, DNSSEC validation/signing, zone data store, EDNS option negotiation,
automatic padding, mTLS, 0-RTT, connection migration or transport fallback.

## TLS and startup

Supply both `cert_path` and `key_path` for a PEM certificate chain/private key.
Supplying only one fails startup. Otherwise a localhost self-signed certificate is
generated. To connect with netget's authenticated client, use an explicit server
certificate and pass its CA/certificate to `ca_cert_path` on the client.

Parameters are validated before binding. Limits (default; accepted range):

- `handshake_timeout_secs`: 10; 1..60.
- `exchange_timeout_secs`: 30; 1..300, including query body, FIN, handler and write.
- `idle_timeout_secs`: 300; 1..3600, enforced by QUIC.
- `max_connections`: 64; 1..256, including pending handshakes.
- `max_streams`: 32; 1..32 per connection, with matching QUIC stream credit.
- DNS message 65535 bytes plus its 2-byte length prefix.

The registered accept task owns all connection futures, which own their stream
futures. None spawn detached tasks. Endpoint/connection drop guards close QUIC on
abort. Client STOP_SENDING cancels its handler future; deadlines stop and reset
incomplete streams. The accept future refuses excess connections before TLS.
Server connection state and byte/packet counters update around DNS frames.

There is no generic peer injection handle: responses must belong to an existing
client stream and include DNS framing. Unsolicited DNS replies are not a DoQ
operation. Client command injection is implemented separately.

## Evidence

State remains Experimental. `tests/server/doq/` contains both a genuine independent
Knot `kdig +quic` test with certificate/hostname verification and transport-fixture
bounds/framing tests. The fixture uses Quinn/Hickory and is not a second independent
DNS implementation. See the test directory documentation for actual run commands.
Reference: https://www.rfc-editor.org/rfc/rfc9250.html
