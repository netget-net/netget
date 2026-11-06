# Docker Engine read-only client

Selected Engine API1.24..1.47 over HTTP TCP (`127.0.0.1:2375` or an `http://` origin) and native Unix sockets (`unix:///absolute/docker.sock`). Browser supports HTTP TCP. No HTTPS/TLS, Windows named pipes, proxy, redirects, Docker context/credential auto-selection, image pulls, lifecycle mutations, attach/exec/log streams, or private Docker database. The existing Docker server remains read-only and refuses mutations with501.

Startup `api_version` defaults to1.47 (preferred ceiling1.24..1.47), `request_timeout_secs` to15 (1..30). HEAD `/_ping` must return200 and exactly one syntactically valid `API-Version`. Select min(daemon maximum, preference); versions below1.24 are refused. Ping advertises maximum, not daemon minimum. A daemon with a newer minimum can refuse a low preference with a normal typed HTTP error. Native Unix has no IP peer address: connection metadata is0.0.0.0:0, and the connected event retains the actual socket URI.

`docker_request` requires `operation`:

| Operation | Native request | Optional fields |
|---|---|---|
| ping | GET /_ping | none |
| version | GET /vX.Y/version | none |
| info | GET /vX.Y/info | none |
| containers | GET /vX.Y/containers/json | all, limit1..1000, size, filters |
| container | GET /vX.Y/containers/{container_id}/json | required bounded ID/name, size |
| images | GET /vX.Y/images/json | all, digests, filters |
| networks | GET /vX.Y/networks | filters |
| volumes | GET /vX.Y/volumes | filters |

Filters are objects mapping Docker filter names to string arrays, bounded64 names/64 values, names64 bytes, values1024 bytes without controls, serialized JSON8192 bytes. The client JSON-serializes and percent-encodes them. Unknown fields, raw URLs/methods/body/query passthrough, invalid boolean/integer values, and container IDs with slash/control characters are rejected before I/O. `all`, `size`, `digests` are booleans; omitted values use daemon defaults. `disconnect` cancels pending I/O.

Events:

- `docker_connected`: endpoint, selected api_version, daemon ping maximum and optional OS/experimental metadata.
- `docker_response`: originating request, operation, selected api_version, status200, typed `data` with snake case names. Version and info objects; container/image/network arrays; container inspect has state/config/host_config/network_settings/mounts; volumes is an object with nullable volumes/warnings. Unknown extension fields are omitted, not passed through. See schema.rs for selected fields. Config environment is returned only by explicit inspect; no local container discovery/automatic inspect.
- `docker_request_error`: request, selected version, HTTP status or null for transport failures, category http/schema/transport, and Docker `message` or diagnostic. No partial response is accepted; errors leave the client ready for another request.

Container/image `created` is Unix seconds. Inspect/network/volume dates retain native date strings. Native optional nulls remain null. Image shared_size/containers and volume usage_data ref_count/size accept Docker's -1 unknown sentinel. Container summaries and inspect use distinct schemas. Ports are integer1..65535 and protocol tcp/udp/sctp. Container state has the native seven allowed statuses; server fixture IDs are bounded printable ID/name tokens, not restricted to64 hex characters. The client does not repair inconsistent JSON, missing required fields, count errors, or malformed primitive types.

Whole negotiation/request deadlines include DNS/connect/head/body. Hyper HTTP1 connection driver is an owned future inside each exchange; no driver task survives timeout/cancel. Send identity encoding and refuse compressed200 responses. HTTP errors use bounded native JSON message; no redirect is followed. Body4MiB (advertised Content-Length and streaming bound), arrays4096, object fields256, field names256 bytes, text16KiB, nesting32, total nodes65536. Streaming JSON visitor bounds collections during decoding and rejects duplicate fields/trailing content.

Two registered owned tasks: session and event dispatcher. Command channel precedes connected event/manual handler. One request at a time; injected overlap gets a clear pending refusal. Action/event queues8, handler followups4, fresh injection resets depth. Generic AppState instruction/memory and LLM/static/script/manual dispatch only; no per-protocol domain state. A parked event queue overflow ends the client with an explicit error. Client removal and disconnect drop request socket and abort the dispatcher.

Primary wire schema: https://docs.docker.com/reference/api/engine/version/v1.47/ and https://docs.docker.com/reference/api/engine/version/v1.52/ (selected fields compatible with1.47; newer extensions omitted). Official API negotiation: https://docs.docker.com/reference/api/engine/ . Tests are in tests/client/docker and explicitly registered in tests/client/mod.rs. No complete Engine API, TLS, browser runtime, Docker Desktop administration, packet capture or conformance claim.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/docker/`:

1. the peer is the local Docker Engine over its Unix socket — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: the engine's answer to the read the mocked model chose matches what Docker's own CLI reports for the same engine; the client is read-only, so the effect of its action is the answer. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
