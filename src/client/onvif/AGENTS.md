# ONVIF client — Experimental

Talks SOAP 1.2 to a device's Device, Media, Media2, PTZ, Events and Imaging services with the
server's codec (`src/server/onvif/wire.rs`; see that AGENTS.md for the bounds and the digest).
`ops.rs` holds every action's operation, service, request body and how its answer is read.

## Connect

`remote_addr` is the device's `host:port`; `device_path` defaults to `/onvif/device_service`.
Startup parameters `username`/`password` sign every request but GetSystemDateAndTime with a
WS-Security PasswordDigest UsernameToken (fresh 16-byte nonce per request).

1. GetSystemDateAndTime, unauthenticated. The device's UTC clock minus ours becomes the offset
   every later Created is shifted by — cameras refuse tokens far from their own clock. A device
   that will not say is warned about and our clock is used.
2. GetCapabilities, authenticated. A fault here fails the connection with the fault in the
   error. (Some devices answer it unauthenticated — ONVIF puts it in the pre-authentication
   class — so a wrong password may only show on the next request, as `NotAuthorized`.)
3. GetServices, authenticated, best effort (older devices have none): it is where Media2
   lives, since GetCapabilities predates it.
4. `onvif_connected {device_time, clock_offset_secs, services, authenticated}`.

Every XAddr — the services' and a pull-point subscription's — is followed **by path (and
query) only**, on the host and port the client was given: a device behind NAT reports its inner
address, and the client must not be redirected to a host the operator never named.

## Actions and events

| Service | Actions |
|---|---|
| Device | `onvif_get_device_information`, `_scopes`, `_network_interfaces`, `_capabilities`, `_services`, `_system_date_and_time` |
| Media | `onvif_get_profiles`, `onvif_get_video_sources`, `onvif_get_stream_uri {profile_token, stream?, protocol?}`, `onvif_get_snapshot_uri {profile_token}` |
| Media2 | `onvif_media2_get_profiles` (Type All), `_get_stream_uri {profile_token, protocol?}`, `_get_snapshot_uri`, `_get_video_source_configurations {profile_token?}`, `_get_video_encoder_configurations {profile_token?}` |
| PTZ | `onvif_ptz_get_nodes`, `_get_configurations`, `_get_status`, `_continuous_move {pan?, tilt?, zoom?, timeout_secs?}`, `_relative_move`, `_absolute_move`, `_stop {pan_tilt?, zoom?}`, `_get_presets`, `_set_preset {preset_name?, preset_token?}`, `_goto_preset`, `_remove_preset`, `_goto_home` — each with `profile_token` |
| Events | `onvif_get_event_properties`, `onvif_create_pull_point {termination_secs?, topic_filter?}`, then on that subscription `onvif_pull_messages {timeout_secs?, message_limit?}`, `onvif_renew_subscription`, `onvif_set_synchronization_point`, `onvif_unsubscribe` |
| Imaging | `onvif_imaging_get_settings`, `_set_settings {brightness?, color_saturation?, contrast?, sharpness?, ir_cut_filter?, auto_focus_mode?}`, `_get_options`, `_get_move_options`, `_move {kind, position \| distance \| speed}`, `_get_status`, `_stop` — each with `video_source_token` |
| | `disconnect` |

Every value is checked before it is written (tokens 1..64 bytes without spaces, vectors inside
their generic space, durations bounded, a topic filter through the device side's own parser)
and written escaped. Each request produces one `onvif_response {operation, service, request,
ok, result | fault | error}`: `result` is structured per operation (`wire::result_json` for
Device and Media, `ops::result_json` for the rest — a pulled notification is `{topic, utc_time,
property_operation, source, data}`, read from its `tt:Message` without recursion), `fault` is
`{code, subcodes, reason}` from SOAP 1.2 (or 1.1) faults on any HTTP status, `error` is a
transport or parse failure or a missing service or subscription.

The client keeps **one** pull-point subscription (the last `onvif_create_pull_point`'s,
forgotten on `onvif_unsubscribe`). PullMessages waits up to `timeout_secs` (1..`MAX_PULL_SECS`
60); its HTTP request is given that long plus the usual 30 s. The session sends one request at
a time, so a long poll holds the others back. Events requests carry WS-Addressing headers
(`wsa:MessageID`, `To`, `Action`): the Events bindings are WS-Addressing ones, and
onvif_simple_server refuses a Renew without a MessageID.

Three tasks, as in the WS-Discovery client: the session (one request at a time), the dispatcher
(model turns through `call_llm_for_client`) and the connect handshake. Chains are bounded at
`MAX_FOLLOWUP_DEPTH` (8): the model's answer to an event `n` turns deep is not asked about once
`n` reaches it. Injected actions (`send_to_client`) run through the same session and are
answered `Executed` with the response JSON.

## Not implemented

Basic Notification (no consumer endpoint), more than one subscription at a time, Device Set*
operations, Recording/Replay/Search, Media2 configuration changes, https and HTTP Digest.
