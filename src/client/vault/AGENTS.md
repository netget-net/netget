# Vault selected client

HTTP(S) client for public system reads, KV v2 and selected userpass authentication. Native HTTPS verifies certificates with the normal Rustls/WebPKI roots; no custom trust or client certificate support. Browser transport supports HTTP. The existing programmable KV v2 server still refuses auth/login, token lookup, administrative routes, deletion and patching.

There is no Vault secret database. Generic AppState memory, event routing and access logs remain available. KV secret data is intentionally visible to the selected handler; login passwords and session tokens are omitted from events and incidental diagnostics. One validated token supplies X-Vault-Token. The latest bounded login password is retained solely to redact later reflections and is forgotten on replacement/clear. Reflected free-form strings and keys containing a known credential are omitted as a whole, including escaped forms and overlapping password/token values; fixed schema names remain intact. Neither credential is written to a file. Authentication policy remains active on every Vault event, including response, authentication and error followups. Credential-bearing handler access-log action copies retain only recognized action names; original actions still execute with their real values.

Startup: optional token (nonempty printable ASCII, at most8192 bytes); kv_mount=secret, auth_mount=userpass; request_timeout_secs=15, range1..30. Endpoint must be an HTTP(S) origin without URL credentials, path, query or fragment. Startup probes public seal status without sending a token. vault_connected reports token_present and authentication_verified=false; connectivity is not token authentication.

| Action / operation | Native exchange | Selected semantics |
|---|---|---|
| vault_request seal_status / health / leader | GET /v1/sys/seal-status, /health, /leader | Typed initialized/sealed/threshold/progress, standby and HA metadata. Health preserves200/429/472/473/474/501/503/530 as legitimate health results. |
| vault_request read | GET /v1/{mount}/data/{path}?version=N | Nonnegative version; omitted/0 selects latest. data and version metadata remain separate. Success cannot name a deleted/destroyed version. |
| vault_request write | PUT /v1/{mount}/data/{path} | Required data object becomes native data envelope; optional nonnegative cas becomes options.cas. cas0 is create-only. Positive version acknowledgement with RFC3339 creation/deletion times. |
| vault_request list | GET /v1/{mount}/metadata/{path}?list=true | Empty path lists mount root; folder keys retain trailing slash. |
| vault_request metadata | GET /v1/{mount}/metadata/{path} | Current/oldest/max version, retention/CAS settings, custom metadata and native version map including deletion/destruction state. |
| vault_userpass_login | POST /v1/auth/{auth_mount}/login/{username} | Bounded username and password. An attempt discards the prior token before I/O. Complete validated auth alone installs a token; MFA, wrapping or incomplete auth refuse without partial authentication. |
| vault_clear_token | Local | Forget token and retained password; no revocation or backend lease action. |
| disconnect | Local | Cancel pending I/O and stop this client. |

Paths have at most32 nonempty ASCII name segments,256 bytes each,4096 total; dot segments, percent encoding and arbitrary URL/method/body/query fields are refused. List alone accepts one trailing folder slash; mount-root list uses the empty string. Mounts are at most256 bytes and exclude sys. Login usernames use native alphanumeric/underscore/hyphen/period syntax, excluding leading hyphen/period and trailing period. Password is nonempty UTF8, at most16KiB.

vault_response carries originating credential-redacted request, operation, native status and typed data. vault_authentication carries login/clear receipt, token presence, verified flag and auth metadata: accessor, policies, metadata, lease_duration seconds, renewable, entity_id, token_type service/batch, optional orphan/num_uses. client_token and MFA challenge never enter it. Clear uses null HTTP status and null auth. vault_request_error reports request, native status when available, http/schema/transport category and redacted errors. Failures preserve session availability; failed login leaves no token.

Body1MiB, arrays10000, object fields256, field names256 bytes, strings16KiB, nesting32, total nodes65536. In-memory actions receive an iterative depth32/node65536/retained-content8MiB preflight before copying or serialization; injection moves the original Value, and over-budget owned actions are discarded iteratively even while a request is pending. Streaming JSON decoding rejects duplicate fields and trailing content. Decoder and display redactor share the depth32 limit; over-depth display subtrees are omitted and discarded iteratively, including programmatically constructed values. Startup resolution and public probe are separately bounded; each later HTTP request has one whole DNS/connect/head/body deadline. Identity encoding only, no redirects/proxies/cookie state. Two registered owned tasks (session and event dispatcher), queues8, one request at a time, handler followups4. Injection overlap refuses as pending. External command channel exists before connected/manual dispatch. Removal aborts owned tasks; disconnect drops pending transport. Browser HTTP connection driver is an owned future inside its exchange.

No KV v1, namespaces, token helpers, automatic login/renewal/retry, OAuth/OIDC/AppRole, wrapping/MFA continuation, dynamic-secret engines, lease administration, delete/undelete/destroy/patch/config or metadata writes. No complete Vault API, browser runtime, packet capture or conformance claim.

Primary specifications: [KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2), [userpass](https://developer.hashicorp.com/vault/api-docs/auth/userpass), [health](https://developer.hashicorp.com/vault/api-docs/system/health). Tests live under tests/client/vault and are explicitly registered in tests/client/mod.rs. Native Vault daemon/CLI peers are required and never skipped.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/vault/`:

1. the peer is HashiCorp Vault in dev mode — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: HashiCorp's `vault` CLI reads back, with the root token, the KV v2 secret the mocked model wrote through its userpass login. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
