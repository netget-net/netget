# Raw QUIC server tests

`e2e_test.rs`: existing text/binary echo, custom response, simultaneous stream,
keyword and encoding regressions, using a Quinn client and mock model.
`llm_failure_test.rs`: backend failure resets with application-local 0x0102.
These peers now negotiate `netget-quic`; `h3` is reserved for HTTP/3.

`independent_peer_test.rs`: an independent aioquic 1.3.0 client authenticates the
certificate/hostname, opens concurrent streams, exchanges binary and text bytes,
and verifies endpoint cleanup. It requires the pinned external Python dependency.
See `tests/client/quic/AGENTS.md` for its small isolated setup and combined command.
No real model or public network is used by the tests. Server maturity remains
Beta based on the existing evidence; the new client remains Experimental.

Verified during the expansion: combined `--features quic --test server --test
client -- quic:: --test-threads=4` passed 10 server and 4 client tests, zero ignored.
The server suite includes a 32-stream credit/cancellation/active-removal test and
an explicit close_this_stream-on-open regression with client FIN withheld.

The existing mocked three-stream test deliberately makes all three stream-open
model replies take six seconds and gives the concurrent exchange group the receiver's
thirty-second bound plus five seconds of scheduling margin. All three notifications
and data replies remain required. JoinSet owns the client tasks so any failed assertion
or whole-group timeout cancels the remaining work. No runtime protocol timeout is widened.

A 32-worker native run exposed a fair-lock scheduling deadlock: the accept branch
awaited AppState to allocate a stream ID behind an older stream's queued write,
while that branch stopped polling the older stream. ID allocation now runs inside
the stream future, so the collection keeps polling all state waiters.

`state_contention_test.rs` deterministically holds AppState when the first real
stream queues its model feedback write, accepts another stream, then releases
state. Both authenticated Quinn streams must receive their replies within the
existing five-second deadline. The rendezvous uses a thread-local trace subscriber
and bounded channels, so it does not depend on sleeps or interfere with other tests.

## Certificate parameter regression

`certificate_validation_test.rs` verifies that numeric, null and object SAN
entries are rejected before binding. It uses no peer or model. This audit
regression runs alongside the existing stream and independent-peer suites.

## DATAGRAM: `datagram_test.rs`

Two independent RFC 9221 implementations drive the server, each through the same command
line so one test body serves both: **aioquic 1.3.0** (`tests/helpers/quic_datagram_peer.py`)
and **quic-go 0.54** (`tests/helpers/quic_go_peer/`, Go, pinned by its `go.sum`). Each sends
the text datagram `ping` and the binary `00 ff 10`; the script handler answers `pong:ping` and
`ff 00 ff 10` (the hex path), and the peer reports both as received. The access log shows the
binary one reached the handler as hex with the negotiated `max_datagram_size`. A third test
refuses a `send_quic_datagram` larger than a packet. No LLM calls.

Peers: `NETGET_AIOQUIC_PYTHON` as above, and `NETGET_QUIC_GO_PEER`, built with
`go build -o <dir>/quic-go-peer ./tests/helpers/quic_go_peer` (Go 1.24). Both fail rather
than skip. The `stream-pairs` job in `protocol-pairs.yml` builds the Go peer.

Mutation-checked: sending an empty datagram instead of the handler's bytes fails both peers'
tests on each side.

`quic_datagram_peer.py` opens an IPv4 UDP endpoint itself rather than calling aioquic's
`connect()`, which opens a dual-stack IPv6 socket and fails on a host without IPv6. The older
`quic_peer.py` still calls `connect()`, so `independent_peer_test` and the client's
`real_server_test` fail with `EAFNOSUPPORT` on such a host; GitHub's runners have IPv6.
