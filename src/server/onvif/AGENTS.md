# ONVIF device — Experimental

SOAP 1.2 over HTTP/1.1 (hyper). ONVIF has no port of its own (devices use their web port, 80 by
convention), so `well_known_port_declaration_test` lists it in `NO_WELL_KNOWN_PORT`. `wire.rs`
is shared with the client: envelopes are read with quick-xml's `NsReader` into a bounded,
namespace-resolved element tree (`MAX_REQUEST` 256 KiB, `MAX_RESPONSE` 1 MiB for the client,
`MAX_DEPTH` 32, `MAX_ELEMENTS` 20 000, no DOCTYPE so no entity expansion) and written by NetGet
with every value XML-escaped.

## Requests

Operations are dispatched on the Body element's **namespace and name**, not the URL path, so
any path works; `GetCapabilities` and `GetServices` advertise `/onvif/device_service` and
`/onvif/media_service` on the scheme and authority of the request's `Host` header.

| Operation | Answered by |
|---|---|
| GetSystemDateAndTime | Rust, from the host clock, **never authenticated** (clients read it first to sign with the device's time) |
| GetCapabilities (Category All/Device/Media; others fault `ActionNotSupported/NoSuchService`), GetServices | Rust |
| GetDeviceInformation, GetScopes, GetNetworkInterfaces | the model: `onvif_get_*` event → `onvif_device_information` / `onvif_scopes` / `onvif_network_interfaces` |
| GetProfiles, GetVideoSources, GetStreamUri, GetSnapshotUri (Media ver10) | the model: `onvif_get_*` event → `onvif_profiles` / `onvif_video_sources` / `onvif_stream_uri` / `onvif_snapshot_uri` |
| anything else, in any namespace | `env:Receiver` / `ter:ActionNotSupported`, HTTP 500 |

Every model event carries `operation`, `username` (the authenticated user, or null) and
`remote_addr`; GetStreamUri adds `profile_token`, `stream` and `protocol`, GetSnapshotUri
`profile_token`. Each event also offers `onvif_fault {subcode, detail?, reason}`, which goes out
as `env:Sender` (or `env:Receiver` for `ActionNotSupported`) with `ter:<subcode>[/ter:<detail>]`.
Rust builds the schema's required structure around what the model gives (a profile's video
source and encoder configurations, multicast block, session timeout) in XSD order, because zeep
reads strictly.

## Authentication

Startup parameters `username` and `password` (together or neither; with neither, every
operation is open and the log says so) and `max_clock_skew_secs` (default `MAX_CLOCK_SKEW`,
300). Every operation but GetSystemDateAndTime needs a WS-Security UsernameToken with a
**PasswordDigest**: `Base64(SHA-1(nonce ‖ Created ‖ password))`, the nonce base64, Created
RFC 3339 within the skew of the device's clock, the configured user. Comparisons are
constant-time. Accepted nonces are remembered (`MAX_NONCES`, for twice the skew) so a captured
token cannot be replayed. PasswordText is refused: over plain HTTP it is the password.

Every refusal is `env:Sender` / `ter:NotAuthorized`, HTTP 400 — the peer never learns which
check failed. The log and the access log (`onvif_not_authorized {operation, reason}`) do:
`no_username_token`, `password_not_digest`, `nonce_not_base64`, `bad_nonce_length`,
`no_created`, `bad_created`, `stale_created`, `unknown_user`, `bad_digest`, `replayed_nonce`.
Unknown operations are refused before authentication (`ActionNotSupported` says nothing an
attacker could use).

## Failure

Malformed envelopes are `env:Sender` / `ter:WellFormed` (400); SOAP 1.1 is
`env:VersionMismatch` (400); a body over `MAX_REQUEST` is HTTP 413 before it is parsed. A model
that fails, answers nothing, or answers with an action for another operation or one that fails
validation is `env:Receiver` with a `WireFailure` category and no subcode (500, or 503 with
`Retry-After` when overloaded); nothing of the model's answer is sent. Decisions are logged
`decision=model_answer|model_reject|model_silent|fail_closed_llm_error|fail_closed_invalid_reply|fail_closed_not_authorized|action_not_supported`.

## Not implemented

Media2 (ver20) — neither test client's bundled WSDL has it; PTZ, Imaging, Events, Recording;
every Set* operation; more than one user and user levels; HTTP Digest authentication; TLS. The
device does not stream: the URIs are whatever the model says. WS-Discovery is the separate
`wsdiscovery` protocol: point its `xaddrs` at `http://<host>:<port>/onvif/device_service`.

## Maturity: Experimental

Two independent clients drive it in `tests/server/onvif/real_client_test.rs` and fail when
absent — python onvif-zeep-async 4.3.0 (zeep over ONVIF's WSDL) and Go use-go/onvif v0.0.9 —
each computing its own digest. That is the evidence Beta asks for, but no person has reviewed
the protocol beyond it, and the pair job has not yet run in CI. No pcap oracle: Wireshark's
http/xml dissectors would only re-read what the clients already parsed.
