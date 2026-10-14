# ONVIF client — Experimental

Talks SOAP 1.2 to a device's Device and Media services (ver10) with the server's codec
(`src/server/onvif/wire.rs`; see that AGENTS.md for the bounds and the digest).

## Connect

`remote_addr` is the device's `host:port`; `device_path` defaults to `/onvif/device_service`.
Startup parameters `username`/`password` sign every request but GetSystemDateAndTime with a
WS-Security PasswordDigest UsernameToken (fresh 16-byte nonce per request).

1. GetSystemDateAndTime, unauthenticated. The device's UTC clock minus ours becomes the offset
   every later Created is shifted by — cameras refuse tokens far from their own clock. A device
   that will not say is warned about and our clock is used.
2. GetCapabilities, authenticated. A fault here (wrong credentials are `ter:NotAuthorized`)
   **fails the connection** with the fault in the error. The media service's XAddr is followed
   **by path only**, on the host and port the client was given: a device behind NAT reports its
   inner address, and the client must not be redirected to a host the operator never named.
3. `onvif_connected {device_time, clock_offset_secs, services, authenticated}`.

## Actions and events

`onvif_get_device_information`, `_scopes`, `_network_interfaces`, `_capabilities`,
`_services`, `_system_date_and_time`, `_profiles`, `_video_sources`, `onvif_get_stream_uri
{profile_token, stream?, protocol?}`, `onvif_get_snapshot_uri {profile_token}`, `disconnect`.
Each request produces one `onvif_response {operation, request, ok, result | fault | error}`:
`result` is structured per operation (`wire::result_json`), `fault` is `{code, subcodes,
reason}` from SOAP 1.2 (or 1.1) faults on any HTTP status, `error` is a transport or parse
failure.

Three tasks, as in the WS-Discovery client: the session (one request at a time), the dispatcher
(model turns through `call_llm_for_client`) and the connect handshake. Chains are bounded at
`MAX_FOLLOWUP_DEPTH` (8): the model's answer to an event `n` turns deep is not asked about once
`n` reaches it. Injected actions (`send_to_client`) run through the same session and are
answered `Executed` with the response JSON.

## Not implemented

https, HTTP Digest, PTZ/Imaging/Events/Media2 and every Set* operation.
