# ONVIF client — Experimental

Talks SOAP 1.2 to a device's Device, Media, Media2, PTZ, Events, Imaging, Recording, Search and
Replay services with the server's codec (`src/server/onvif/wire.rs`; see that AGENTS.md for the
bounds and the digest). `ops.rs` holds every action's operation, service, request body and how
its answer is read; `consumer.rs` is the Basic Notification consumer endpoint.

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
   lives, since GetCapabilities predates it. Recording, Search and Replay are taken from
   GetCapabilities' `Extension` and from GetServices.
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
| Basic Notification | `onvif_subscribe {termination_secs?, topic_filter?}`, then on that subscription `onvif_renew_push_subscription {termination_secs?}`, `onvif_unsubscribe_push` |
| Recording | `onvif_get_recordings`, `onvif_get_recording_configuration {recording_token}`, `onvif_get_recording_jobs` |
| Search | `onvif_get_recording_summary`, `onvif_get_recording_information {recording_token}`, `onvif_find_recordings {recording_tokens?, max_matches?, keep_alive_secs?}`, `onvif_find_events {start, end?, recording_tokens?, topic_filter?, include_start_state?, max_matches?, keep_alive_secs?}`, `onvif_get_recording_search_results` / `onvif_get_event_search_results {search_token, max_results?, wait_secs?}`, `onvif_end_search {search_token}` |
| Replay | `onvif_get_replay_uri {recording_token, protocol?}`, `onvif_get_replay_configuration` |
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

### Basic Notification

`onvif_subscribe` starts the client's **own consumer endpoint** the first time (`consumer.rs`)
and names it in a `wsnt:Subscribe` — the consumer address is always the client's, never one the
model or an injected action supplies (`ops::CONSUMER_KEY` is overwritten by the session). The
consumer binds the startup parameter `notify_bind` (default `DEFAULT_BIND`, 127.0.0.1; any IP
of this host the operator names) on a port the OS picks, and serves one path,
`/netget/onvif/notify/<128-bit random>`; anything else is 404, a method other than POST 405.
Bounded like a server: at most `MAX_CONNECTIONS` (8) device connections at once (the next is
answered 503), headers within `HEADER_TIMEOUT` (10 s), a body of at most `wire::MAX_REQUEST`
(413 past it) read into the same bounded tree (depth, element count, no DOCTYPE; 400 if
unreadable or not a `wsnt:Notify`), at most `wire::MAX_ITEMS` notifications taken from one
Notify. HTTP/1 half-close is on, because onvif_simple_server's notify daemon shuts its socket
down the moment it has written; eleven runs with it off also delivered every Notify, so it is
hardening rather than a demonstrated fix. Each notification becomes an
`onvif_notification {topic, utc_time, property_operation, source, data, subscription,
producer}` event for the model, through the same bounded turn queue as every other event (a
full queue drops it and logs `decision=turn_queue_full`). The client keeps **one** push
subscription (the last `onvif_subscribe`'s, forgotten on `onvif_unsubscribe_push`), followed by
path on the host it was given; the consumer stays up for the life of the client. A device that
refuses loopback consumers (onvif_simple_server does) needs `notify_bind` set to an address of
this host it can reach.

### Recording, Search, Replay

Every value is checked before it is written: tokens, times (`start`/`end` as UTC xsd:dateTime),
counts 1..`MAX_RESULTS`, keep-alives 1..`MAX_KEEP_ALIVE_SECS`, a Get*SearchResults wait
0..`MAX_SEARCH_WAIT_SECS` (its HTTP request is given that long plus the usual 30 s), a topic
filter through the device side's parser. Answers are read into `{recordings: [...]}`,
`{jobs}`, `{data_from, data_until, number_recordings}`, a recording's `{token, source_id, name,
earliest, latest, content, status, tracks}`, `{search_token}`, `{search_state, recordings |
results}` (an event result is `{recording_token, track_token, time, start_state, topic,
property_operation, source, data}`), `{endpoint}`, `{uri}`, `{session_timeout}`.

Three tasks, as in the WS-Discovery client: the session (one request at a time), the dispatcher
(model turns through `call_llm_for_client`) and the connect handshake. Chains are bounded at
`MAX_FOLLOWUP_DEPTH` (8): the model's answer to an event `n` turns deep is not asked about once
`n` reaches it. Injected actions (`send_to_client`) run through the same session and are
answered `Executed` with the response JSON.

## Not implemented

More than one pull-point or push subscription at a time, Device Set* operations, recording
changes (CreateRecording, DeleteRecording, tracks and jobs), metadata and PTZ-position search,
following a replay URI (the client hands it to the model; it streams nothing), Media2
configuration changes, https and HTTP Digest.

## Evidence

RPOS (Device, Media, PTZ, Imaging) and onvif_simple_server (Media2, pull-point Events, and Basic
Notification: the client's consumer receives the daemon's Initialized and Changed motion alarms)
— see `tests/client/onvif/AGENTS.md`. **No independent device implementing Recording, Search or
Replay was found that runs on Linux in CI**: RPOS and onvif_simple_server, read at their pinned
commits, implement none of the three services, and no other open device implementation with
them turned up. Those actions are checked only against a canned device in `bounds_test`, which
is not evidence. They must not be tested against NetGet's own device.
