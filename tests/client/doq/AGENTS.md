# DoQ client tests

Registered by `tests/client/mod.rs`; all traffic stays on loopback. Static/script
event handlers drive requests and follow-ups. One memory regression test uses two
local mocked Ollama calls; no real model is needed.

`real_server_test.rs` uses the official AdGuard dnsproxy executable. Its temporary
hosts file resolves `independent.example` to 192.0.2.61 and 2001:db8::61. Plain UDP
and TCP listeners are disabled. Its required fallback upstream is loopback port 9,
so the test never queries an external resolver. The actual DoQ server, TLS stack
and DNS codec are Go/quic-go/miekg-dns, independent of netget's Rust libraries.

The test validates the client command channel, authenticated certificate/hostname,
A response event, a script-generated AAAA follow-up, and that follow-up's response.
It fails if dnsproxy is absent; set NETGET_DNSPROXY_BIN or install it on PATH.

Test-peer provenance used in the expansion:
https://github.com/AdguardTeam/dnsproxy/releases/tag/v0.85.0
Asset: dnsproxy-darwin-arm64-v0.85.0.tar.gz (4.24 MB).
SHA-256: 64c2a6c2645745e24369f21c9e22661a18bfcfdcbdd8ff54af0d37328b3ea9e6.
The downloaded archive hash is checked before extraction. The binary is kept only
in the programme-owned temporary peers directory and is not committed.

`e2e_test.rs` additionally exercises the netget pair, response-driven follow-up
limits, invalid certificates/hostnames, query timeout/cancellation, removal,
question/opcode mismatch, nonzero response IDs and missing FIN. It also checks
shared memory propagation and that connect returns an owned local UDP address. Its fake Quinn server is
transport testing, not independent interoperability evidence.

```
NETGET_DNSPROXY_BIN=/tmp/netget-peers/dnsproxy/darwin-arm64/dnsproxy ./cargo-isolated.sh test \
  --no-default-features --features mcp-stdio,mcp-http,sqlite --test client -- client::doq:: --test-threads=8
```

`scripts/test-peers/install-dnsproxy.sh <dir>` installs the pinned release and checks its digest.
Client maturity remains Experimental; no public network, zone-transfer or resumption coverage is
claimed.

Reproduce the small macOS arm64 peer installation in a temporary directory (no Go
build cache). Use another official platform asset and its published hash elsewhere:

```sh
mkdir -p /tmp/netget-doq-peer
/usr/bin/curl --fail --location --output /tmp/netget-doq-peer/dnsproxy.tar.gz https://github.com/AdguardTeam/dnsproxy/releases/download/v0.85.0/dnsproxy-darwin-arm64-v0.85.0.tar.gz
printf '%s\n' '64c2a6c2645745e24369f21c9e22661a18bfcfdcbdd8ff54af0d37328b3ea9e6  /tmp/netget-doq-peer/dnsproxy.tar.gz' | shasum -a 256 --check
tar -xzf /tmp/netget-doq-peer/dnsproxy.tar.gz -C /tmp/netget-doq-peer
export NETGET_DNSPROXY_BIN=/tmp/netget-doq-peer/darwin-arm64/dnsproxy
```

The server's own suite is `tests/server/doq/` (see its AGENTS.md).
