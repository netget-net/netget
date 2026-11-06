# RadSec client (RFC 6614)

The RADIUS client over one TLS connection: `RadiusClient::run` with a `Link::Stream`, so its
actions, events, signing and reply verification are exactly the RADIUS client's
(`radius_access_request` → `radius_access_accept` / `_reject` / `_challenge`,
`radius_accounting_request` → `radius_accounting_response`, `radius_error`). See
`src/client/radius/AGENTS.md`.

- `ca_file` is **required**: the server is always verified, against `server_name` (default:
  the host of `remote_addr`). There is no option to skip verification.
- `certificate_file` + `private_key_file`: the client certificate RadSec servers normally
  require.
- `shared_secret` defaults to `radsec`; `timeout_ms` (default 10 000) per request. Nothing is
  retransmitted over the stream.
- One connection carries authentication and accounting. If it closes, the client ends.

## Tests

`tests/client/radsec/`: NetGet's own RadSec server, FreeRADIUS's TLS listener, and radsecproxy
in front of FreeRADIUS. See its AGENTS.md.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/radsec/`:

1. the peer is FreeRADIUS 3's TLS listener and radsecproxy — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: FreeRADIUS's own `detail` file holds the accounting session the chain named after FreeRADIUS's Reply-Message. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The radsecproxy test did not run here (not installed); FreeRADIUS's did. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
