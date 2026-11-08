# DoQ client

Compiled into every native build (no Cargo feature); reusable authenticated QUIC connection with ALPN `doq`, zero DNS IDs,
length-prefixed DNS messages, and one FIN-terminated bidirectional stream per query.
The client accepts structured `send_dns_query` (domain, query_type,
recursion_desired), `wait_for_more` and `disconnect` actions.

Certificate and hostname validation are always enabled. Public WebPKI roots are
augmented by `ca_cert_path` (PEM). `server_name` overrides the hostname derived from
`remote_addr` for authentication/SNI. Both IPv4 and bracketed IPv6 addresses and
hostname:port are accepted; the first resolved address is used. UDP/53 is refused.
There is no implicit insecure mode or fallback to unencrypted DNS.

All ordinary record types accepted by Hickory's RecordType parser can be queried
against an external resolver. AXFR and IXFR are rejected before writing because
multiple-response streams are not implemented. Responses are represented as
structured arrays (name, type, class, ttl, textual record data), with answer,
authority, additional and response-code fields. Malformed frames, nonzero IDs,
TCP keepalive, oversized messages and question mismatches close the connection
with DOQ_PROTOCOL_ERROR. Missing FIN is bounded by the query deadline.

Startup limits: resolution/handshake 10 seconds (1..60), whole query 30 seconds
(1..300), QUIC idle timeout 300 seconds (1..3600). The client admits at most 32
concurrent queries and 32 active event-handler futures; overload returns a busy
error or logs the handler limit. Each automatic handler chain performs at most
four queries, including its initial query. The final response still reaches the
handler; its further query actions are discarded. Disconnect is always honoured.
At most 32 actions per handler result are accepted.

Events `doq_connected`, `doq_response_received`, `doq_query_error` all go through
`call_llm_for_client`, including script/static/manual dispatch and memory updates.
Injected commands use the same action executor and exchange path, reply with a
truthful outcome after the response, and log outcomes. Invalid commands fail
without writing. A parked event handler does not block the command queue.

One registered task owns event and query futures. Removing the client aborts it,
drops streams (sending cancellation), and closes the endpoint. Normal disconnect
removes the command handle and marks the client disconnected. There are no
unregistered child tasks, automatic reconnect, persistence, 0-RTT, zone transfers,
automatic EDNS padding or session resumption policy.

Experimental maturity: the independent server test drives official AdGuard
dnsproxy (Go/quic-go/miekg-dns), with an isolated hosts file and no external
resolver; other tests exercise netget's own server and explicit malformed QUIC
peers. See `tests/client/doq/AGENTS.md` for commands and evidence.
