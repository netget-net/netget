# openid — OpenID Connect provider simulator

Serves the five OIDC endpoints over hyper HTTP/1.1 and asks the model what each should answer.
`DevelopmentState::Experimental`, group `Authentication`, keywords `openid` / `oidc` /
`openid connect` / `sso` / `authentication`. Feature `openid = ["urlencoding"]`.

**Read this first: NetGet holds no signing key and performs no cryptography.** An `id_token`
is whatever string the model returns — it is not signed here, and NetGet cannot tell a real
JWT from `"hello"`. The JWKS served at `/jwks.json` is whatever keys the model invented; it has
no relationship to any signature, because there are no signatures. No access token is ever
verified, and no user exists. This is a simulator for exercising OIDC *relying parties* and for
honeypots.

That is a deliberate design, not a gap: it lets you hand a relying party an expired token, a
token signed with the wrong key, a token with a mismatched `aud`, or a deliberately malformed
one, just by asking. But it means the protocol must never be described as "issuing signed ID
tokens", and `metadata()` says so.

## Files

| File | Contents |
|---|---|
| `mod.rs` | `OpenIdServer::spawn_with_llm_actions`, `classify_endpoint`, `parse_urlencoded`, `handle_llm_response`, `build_safe_response` |
| `actions.rs` | `OpenIdProtocol` (`Protocol` + `Server`), one async and six sync actions, `OPENID_REQUEST_EVENT` |

## Endpoints

One event, `openid_request`, fires for every request. `classify_endpoint` sets `endpoint_type`
so the model knows which endpoint it is answering:

| Path | `endpoint_type` | Expected answer |
|---|---|---|
| `/.well-known/openid-configuration` | `discovery` | `send_discovery_document` |
| `/authorize` | `authorization` | `send_authorization_response` (302) |
| `/token` | `token` | `send_token_response` |
| `/userinfo` | `userinfo` | `send_userinfo_response` |
| `/jwks.json`, `/jwks` | `jwks` | `send_jwks_response` |
| anything else | `unknown` | `send_error_response` |

The event carries `method`, `path`, `query_params`, `headers`, `body`, `form_data` and
`endpoint_type`. `form_data` is the body parsed as `application/x-www-form-urlencoded` when the
Content-Type says so — that is where `/token` parameters (`grant_type`, `code`, `client_id`,
`client_secret`) arrive, and it must stay declared in the event's `parameters`: the model
cannot use a field it was never told about.

Unlike `oauth2`, routing is advisory. The server does not enforce that a `token` request is
answered with `send_token_response`; whatever action the model returns is rendered. That is
what makes the deliberate-misbehaviour scenarios above possible.

## The event must carry the action list

`call_llm` builds the model's tool list from `event.event_type.actions`, **not** from
`get_sync_actions()`. `OPENID_REQUEST_EVENT` had no `.with_actions(...)` at all, so the prompt
said "No specific actions available for this event", the model got only
`set_memory` / `notify_operator` / `append_to_log`, and every OIDC action it produced was
rejected as unknown, retried twice, and failed — leaving the server to answer every request
with its `500 server_error` no-answer fallback. In debug builds it also tripped the
`debug_assert!` in `action_helper.rs`.

It now carries `.with_actions(OpenIdProtocol.get_sync_actions())`. Since every endpoint shares
one event, the full sync set is correct here; do not narrow it without a reason, and if you
ever do want an event with no protocol actions, say so with `.with_no_actions()`.

`get_event_types()` is implemented so `get_protocol_docs` and the script-template prompt can
see `openid_request`. It used to fall back to the trait's empty default while
`get_startup_examples()` advertised an `openid_request` script handler.

## Discovery document

`send_discovery_document` requires `issuer` and the four endpoint URLs. Optional
`supported_scopes`, `supported_response_types` and `id_token_signing_alg_values_supported` are
merged in **only when present** — the executor previously wrote `action.get(k)` straight into
the payload, which serializes an absent key as JSON `null`, so the downstream
`.unwrap_or(default)` never fired and a document that omitted `supported_response_types` went
out with `"response_types_supported": null`. That field is REQUIRED and an array; relying
parties reject `null`. Both the executor and `handle_llm_response` now filter nulls.

`id_token_signing_alg_values_supported` defaults to `["RS256"]` for compatibility with
relying parties that refuse `"none"`. It is an **advertisement only** — nothing signs. If you
tell the model to return unsigned tokens, tell it to advertise `["none"]` too, or the RP will
reject the mismatch.

## Backend failure — three distinguishable outcomes

Every request is answered; none of the three answers carries an internal error string.

| Outcome | Wire | Log token |
|---|---|---|
| The LLM call returned `Err` and the backend is saturated | `503` + `temporarily_unavailable` | `decision=llm_error overload=true` |
| The LLM call returned `Err` otherwise | `500` + `server_error` | `decision=llm_error overload=false` |
| The model answered with nothing renderable | `500` + `server_error` | `decision=no_answer` |
| The model deliberately refused (`send_error_response`) | the model's own code/status | `decision=model_reject` |

Both failure paths are 5xx on purpose: a 4xx would tell the relying party its own request was
at fault and stop it retrying. `temporarily_unavailable` versus `server_error` is the split
that makes an RP back off rather than record a permanent fault, so keep them distinct.

`error_description` is `crate::utils::WireFailure::…prefixed_text()` — a `&'static str`
category, never the error. The error goes to `tracing` and the status stream through `Log`.
Do not interpolate it into the response; `tests/wire_failure_test.rs` scans for exactly that.

## Nothing here may panic

`build_safe_response` is the only place a `Response` is constructed: an out-of-range status
becomes 500 and a header hyper rejects is dropped with a warning.

The previous `.body(..).unwrap()` was reachable from model output. `send_authorization_response`
puts `redirect_uri` into the `Location` header; a value containing CR/LF makes hyper refuse the
header, `.body()` return `Err`, and the `unwrap()` kill the connection task. (Had hyper
accepted it, the same input would have been response splitting.) Local copy of
`http_common::handler::build_safe_response`, which the `openid` feature cannot reach because
`http_common` is gated on `feature = "http"`.

`send_authorization_response` percent-encodes `code`, `state`, `error` and `error_description`
into the redirect URL; `redirect_uri` itself is used as given.

## Parsing

`parse_urlencoded` serves both the query string and form bodies. It decodes `+` as space (a
`scope=openid+profile` body used to reach the model as `openid+profile`) and skips pairs with
invalid percent-encoding rather than collapsing them to an empty-string key.

## Startup parameters and `configure_provider`

`issuer` (string) and `supported_scopes` (array), both stored in `OpenIdState`. They reach the
model as `configured_issuer` / `configured_scopes` on **every** `openid_request`, so a
discovery document and the `iss` claims in later tokens can agree without the instruction
repeating the issuer.

They were dead until this was wired: `handle_openid_request` took the state as
`_openid_state`, so both were advertised knobs that did nothing when turned. That is what
`tests/server/openid/configuration_test.rs` pins — its mock rule matches on
`configured_issuer`, so if the value stops reaching the model the rule stops matching and the
request falls through to an unmocked LLM call.

`configure_provider` sets the same two values at runtime. It is a **sync** action, offered on
`openid_request`. It used to be an async action and could never take effect from there: an
async action's `ActionResult` never reaches `handle_llm_response`, and `execute_action` is a
`&self` method on a unit struct with no access to `OpenIdState`, so the issuer it "set" was
discarded. It produces no HTTP response of its own — deliberately, so a request answered with
*only* a `configure_provider` still falls into the fail-closed 500 below rather than an empty
200. Pair it with the action that answers the request.

`get_async_actions()` is consequently empty, which is correct for a request/response server
(`oauth2` is the same).

## Hostile input

- **`MAX_REQUEST_BYTES` = 64 KiB.** Every endpoint is reachable before any credential is
  checked and the body is handed to the model as prompt text, so the previous unbounded
  `req.into_body().collect()` let one anonymous POST grow the process without limit and drive
  an LLM call with megabytes of attacker-chosen prompt. Over the limit is `413` — and a
  refusal, not an empty body: substituting `Bytes::new()` on failure, as the old code did,
  turned an over-limit POST into a well-formed request with no parameters at all, which the
  model then answered as one.
- **`status_or` narrows a model-supplied `status_code` with `u16::try_from`.** `65736 as u16`
  is `200`, so a `send_error_response` the model meant as a refusal arrived at the relying
  party as the status it reads as success. Anything outside 100–599 falls back to 400.
- **`send_authorization_response` must carry a verdict.** Only `redirect_uri` is required, so
  an action with no `code`, `error`, `id_token` or `access_token` used to produce a bare 302
  to the client's callback — which set `redirect_location` and therefore *passed* the
  fail-closed check below while saying nothing at all. Such an action is now skipped and
  logged `decision=fail_closed_empty_authorization`, so the request falls through to the 500.

## Storage

None, per the project rule. Authorization codes, tokens and sessions live in the model's memory
or in a rule stated in the instruction, never in Rust. Do not add a token table.

## Not implemented

Signing or verification of anything, PKCE validation, device flow, dynamic client
registration, token introspection/revocation (use the `oauth2` protocol), session management,
and TLS.

**Request-only.** `metadata()` declares `.request_only(…)`: "OpenID Connect is HTTP
request/response; a server cannot send a peer anything unprompted". The dashboard's
`[ send message ]` on a peer is disabled and shows that reason, and MCP `send_to_peer` refuses
with it.

## Examples

```text
Start an OpenID Connect provider on port 8080 with issuer http://localhost:8080.
Serve discovery, then accept any client_id at /authorize and redirect with a code.
At /token, return an id_token whose claims are sub=user123, email=test@example.com,
aud=<the client_id>, and a matching userinfo response.
```

Deterministic equivalent — no LLM call per request:

```json
"event_handlers": [{"event_pattern": "openid_request", "handler": {"type": "script",
  "language": "python", "code":
  "e = event.get('endpoint_type','')\nif e == 'discovery':\n    action('send_discovery_document', issuer='http://localhost:8080', authorization_endpoint='http://localhost:8080/authorize', token_endpoint='http://localhost:8080/token', userinfo_endpoint='http://localhost:8080/userinfo', jwks_uri='http://localhost:8080/jwks.json')\nelif e == 'userinfo':\n    action('send_userinfo_response', sub='user123', email='test@example.com')\nelse:\n    action('send_error_response', error='invalid_request')"}}]
```

## Tests

`tests/server/openid/` exists and is declared in `tests/server/mod.rs`. See
`tests/server/openid/AGENTS.md`.

## References

OpenID Connect Core 1.0, OpenID Connect Discovery 1.0, RFC 7517 (JWK), RFC 6749 (the OAuth2
layer underneath — see the `oauth2` protocol).

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever,
pre-authentication, and a hundred of them was a free denial of service on a server that would
happily accept a hundred more. It now declares both halves; the constants and the argument for
each live beside them in `src/server/openid/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has completed the handshake and sent no byte has asked nothing and negotiated nothing — the state carries no protocol yet, which is why this number is the same across netget's HTTP family. Apache's `mod_reqtimeout` gives the request header 20s and nginx's `client_header_timeout` 60s. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 60s | These endpoints are reached two ways and the two pull in opposite directions: a **browser** does one redirect round and never comes back on that connection (Apache's `KeepAliveTimeout` of 5s is tuned for exactly that), while a **relying party's back-channel** client — token exchange, introspection, a JWKS or metadata fetch — reuses a pooled connection (nginx's 75s is tuned for that). 60s is comfortably past any pooled back-channel round trip and does not let a browser that navigated away hold a slot for minutes. Nothing here streams or long-polls. **The five-minute numbers these specifications do quote are not this number**: an assertion's `NotOnOrAfter` and an `id_token`'s `exp` bound how long a *credential* may be presented, not how long a socket may be silent. |
| `MAX_CONNECTIONS` | 256 | The shared default. Each admitted connection may buffer one body of up to 64 KiB, well inside the ~1 GiB ceiling netget's HTTP family is held to; a protocol declares a smaller number only when its per-connection cost is larger. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After`**, written straight onto the socket — the peer has sent no request line for hyper to answer — and logged `decision=fail_closed_connection_cap`. Fixed bytes, so nothing derived from an error can reach the wire. |

**NetGet's own OpenID Connect client *speaks inside `connect()`*, so it is never the silent
peer this bound closes:** `src/client/openidconnect/mod.rs` awaits
`CoreProviderMetadata::discover_async`, a real GET of `/.well-known/openid-configuration`,
before its first model turn — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** hyper owns every read once `serve_connection`
starts, and it keeps polling the connection for more input *while a request is being answered* —
so a deadline on those reads would be wrong here, not merely awkward. The idle bound is a
watchdog over `ConnectionActivity` instead, which reports a connection with work in flight as not
idle at all. The model round-trip, and an event a `manual` rule parked for a human
(`src/state/intercepts.rs`, 300s by default), are therefore outside every deadline by
construction: an answer that takes minutes can never close the connection it is an answer for.
That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse — TFTP evicted
live transfers because "idle" was measured wrongly.

**hyper's own `header_read_timeout` is not this bound.** Its 30-second default is inert unless
`http1::Builder::timer` is also set, which nothing here does: hyper downgrades a defaulted
duration to `None` when no timer is present and applies no deadline at all. That is why the
`peek` is not redundant.

`tests/server/openid/connection_bounds_test.rs` drives all three from the wire, with three
sockets on one server whose only rule is `*` → `manual`: a silent peer must be closed after the
first-byte bound, a peer that sends a request line and then stalls (slowloris) after the idle
bound, and a peer whose request is parked for a human must **not** be closed at all. The shared
driver and the removal-verification notes are in `tests/helpers/http_bounds.rs`.
`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound disappears.
