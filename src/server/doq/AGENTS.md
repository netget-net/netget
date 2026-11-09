# DNS over QUIC (DoQ) server

RFC 9250 on UDP, default port 853 (`well_known_udp_port`), with `PrivilegedPort(853)`; UDP/53
is refused, as §4.1.1 requires. Stack: ETH > IP > UDP > QUIC > DNS. quinn 0.11 and rustls 0.23
carry QUIC and TLS; ALPN is exactly `doq` (no draft ALPNs, no HTTP/3 alias); 0-RTT is off
(`max_early_data_size = 0`) and so is connection migration. Every DNS message is decoded,
answered and encoded by the DNS server's own code (hickory-proto 0.26).

## Files

- `mod.rs` — the accept loop, one future per connection, one per stream; `transaction` →
  `exchange` (read the query) → `answer` (ask the model through `dns::StreamQuery`).
- `wire.rs` — RFC 9250 framing (`encode`, `frame`, `decode`), the DoQ error codes, the
  bounds and the QUIC transport config. Shared with the DoQ client.
- `actions.rs` — `DoqProtocol`: the `doq_query` event, the startup parameters, and actions
  delegated to `DnsProtocol`.

## One transaction per stream

A client opens one client-initiated bidirectional stream per query and sends one 2-octet
length-prefixed DNS message followed by FIN (§4.2). The server reads the stream to its FIN
(`read_to_end`) before decoding — it may defer processing until FIN, §4.2 — and answers on the
same stream, then FINs it. Unidirectional streams get no credit, so a client cannot open one.

`decode` is where §4.3.3's protocol errors are detected, and each **closes the connection with
DOQ_PROTOCOL_ERROR (2)** (`decision=fail_closed_protocol_error`): a non-zero message id, a
length that disagrees with the bytes before FIN (short, or a second message after the first,
or trailing bytes inside the declared length), a message that is not a query, a message the
compression-pointer screen (`utils::dns_screen`) or hickory refuses, and EDNS TCP keepalive
(§5.5.2).

## How a query is answered

The DNS server's rules, through `dns::StreamQuery` — the same path DNS-over-TCP, DoT and DoH
answer through, so a fix there is a fix here:

- **Without the model** (`decision=spec_reply`): no question → FORMERR; more than one question
  → FORMERR (RFC 9619 allows it; a stream answers one); an opcode other than QUERY, a class other
  than IN, and AXFR/IXFR → NOTIMP. The reply echoes the question, the opcode and RD, carries an
  OPT when the query did, and has id 0.
- **Every other question goes to the model**, whatever its type — SRV, NS, SOA, PTR and the rest
  are answered with `send_dns_records`. The `doq_query` event carries `domain`, `query_type`,
  `query_class`, `recursion_desired`, `stream_id`, `peer_addr` and `query_id` (always 0).
- **The model's answer** (`StreamQuery::answer`): the first DNS message an action produced is
  the answer, finished as the DNS server finishes it — an OPT echoed for an EDNS query, and
  SERVFAIL (`decision=fail_closed_oversize_answer`) for an answer past 65535 octets, which
  hickory's encoder would otherwise cut short and mark TC. Further messages are dropped; one
  answer carrying several records is `send_dns_records`. Before that, `bind_to_query` copies the
  stream's question, opcode and RD into every message and sets its id to 0, so an action written
  for another name or type still answers this stream's question.
- `ignore_query` (`decision=model_silent`) resets the stream with **DOQ_NO_ERROR (0)**: the
  transaction ends instead of dangling, and nothing is said.
- **SERVFAIL on the stream** (§4.3.2: a server failure is a response, not a reset) for an
  answer with nothing sendable in it — no actions, only common actions such as
  `notify_operator`, or a DNS action the executor refused (`decision=fail_closed_no_action`) —
  for a backend failure (`fail_closed_llm_error`, `fail_closed_llm_overload`), and for an answer
  not ready when the exchange deadline passes (`fail_closed_timeout`). The peer gets the rcode;
  the error stays in the log.

`send_dns_response` (hex bytes) is not offered and `execute_action` refuses it; every other
DNS query action is, with `query_id` forced to 0 whatever the model wrote.

## Cancellation and resets

- A client's STOP_SENDING at any point before the answer is written drops the work, model call
  included (§4.3.1; `decision=peer_cancelled`); quinn resets the send side with the client's code.
- A client's RESET_STREAM before its FIN abandons the transaction; the server resets its side
  with DOQ_NO_ERROR.
- No complete query and FIN within the exchange deadline: the stream is stopped and reset with
  DOQ_UNSPECIFIED_ERROR (5) (`decision=fail_closed_read_timeout`). Other streams go on.
- An answer the peer's flow control does not take within `RESPONSE_WRITE_TIMEOUT` (5 s), or one
  that cannot be framed: reset with DOQ_INTERNAL_ERROR (1) (`decision=fail_closed_send_error`).

## Bounds

Parameters are validated before binding; 0 or a value past the maximum refuses to start.

| Bound | Default | Range | Enforced by |
|---|---|---|---|
| `handshake_timeout_secs` | 10 | 1..60 | the connection future; a stalled handshake holds a connection slot until then |
| `exchange_timeout_secs` | 30 | 1..300 | query read to FIN, then the answer: reset (still arriving) or SERVFAIL (being answered) |
| `idle_timeout_secs` | 300 | 1..3600 | QUIC's `max_idle_timeout`; the effective value is the lower of the two endpoints' (§4.4) |
| `max_connections` | 64 | 1..256 | the accept loop; counts pending handshakes; past it the Initial is refused before TLS |
| `max_streams` | 32 | 1..32 | QUIC bidirectional stream credit, and the accept loop's own count |
| frame | 65537 | — | `read_to_end(MAX_FRAME_BYTES)` (2 + 65535): a stream carrying more closes the connection with DOQ_PROTOCOL_ERROR |
| `RESPONSE_WRITE_TIMEOUT` | 5 s | — | the answer's write |

## Lifecycle

The registered accept task owns every connection future, which owns its stream futures; none
spawn detached tasks. `EndpointGuard` and `ConnectionGuard` close QUIC when the task is
aborted, so `stop_server` releases the UDP port and ends every open stream. Connection state
and byte/packet counters update around each DNS frame. There is no peer handle: an answer must
belong to a client's stream, so unsolicited DNS messages are not a DoQ operation.

## Not implemented

Zone transfer over DoQ (RFC 9250 §4.2 allows several responses on one stream), DNSSEC
signing, a recursive resolver, a zone store, EDNS padding (§5.4 asks implementations to pad;
neither the messages nor the QUIC packets are padded), mTLS, 0-RTT, session-resumption policy,
connection migration and transport fallback.

## TLS

Supply both `cert_path` and `key_path` (PEM chain and key); one without the other refuses to
start. Without them a self-signed `localhost` certificate is generated, which no validating
client accepts — give a client the certificate (`ca_cert_path` on NetGet's DoQ client,
`+tls-ca` on kdig).

## Maturity: Experimental

What holds against the six Stable conditions (root `AGENTS.md`), as of 8 November 2026:

1. Two independent clients — **yes**: Knot `kdig +quic` (libngtcp2, Knot's codec; certificate
   and hostname verified) and AdGuard `dnsproxy` as a DoQ upstream client (quic-go,
   miekg/dns), in `tests/server/doq/real_client_test.rs`, both failing when absent.
2. pcap oracle — **no**. NetGet's capture writer has no QUIC adoption, and the oracle would need
   the TLS keys (`SSLKEYLOGFILE`) to see the DNS inside.
3. Fuzz target — **partly**: the DNS message decoder is `fuzz_targets/dns_message.rs`; `decode`'s
   framing and the keepalive check have no target of their own.
4. A test per declared bound — **yes**, `tests/server/doq/bounds_test.rs` and `e2e_test.rs`.
5. Both AGENTS.md files verified against source — this pass.
6. No `#[ignore]` and no skip gate — **yes**.

Beta asks for human review of real-client evidence that now exists; Stable needs conditions 2
and 3 as well. The rating is left for the maintainer.

Reference: <https://www.rfc-editor.org/rfc/rfc9250.html>
