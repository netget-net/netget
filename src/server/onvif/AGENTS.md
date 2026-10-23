# ONVIF device — Experimental

SOAP 1.2 over HTTP/1.1 (hyper). ONVIF has no port of its own (devices use their web port, 80 by
convention), so `well_known_port_declaration_test` lists it in `NO_WELL_KNOWN_PORT`. `wire.rs`
is shared with the client: envelopes are read with quick-xml's `NsReader` into a bounded,
namespace-resolved element tree (`MAX_REQUEST` 256 KiB, `MAX_RESPONSE` 1 MiB for the client,
`MAX_DEPTH` 32, `MAX_ELEMENTS` 20 000, no DOCTYPE so no entity expansion) and written by NetGet
with every value XML-escaped.

| File | What |
|---|---|
| `mod.rs` | listener, `Device` (credentials and all volatile state), authentication, `ask` |
| `handlers.rs` | every operation, by service, and who answers it (the table at its top) |
| `wire.rs` | the tree, WS-Security digests, Device/Media ver10 bodies, capabilities, durations |
| `ptz.rs`, `events.rs`, `media2.rs`, `imaging.rs` | each service's state and bodies |
| `actions.rs` | the model's actions and events |

## Services

Operations are dispatched on the Body element's **namespace and name**, not the URL path, so any
path works — except a pull-point subscription's, whose path names it. GetCapabilities
advertises Device, Events, Imaging, Media and PTZ (in the schema's order; Analytics is
`ActionNotSupported/NoSuchService`); GetServices lists those and Media2 (`wire::SERVICES`), each
at `/onvif/<service>_service` on the scheme and authority of the request's `Host` header. Any
other operation in any namespace is `env:Receiver` / `ter:ActionNotSupported`, HTTP 500.

| Service | Rust answers | The model answers (event → action) |
|---|---|---|
| Device | GetSystemDateAndTime (never authenticated), GetCapabilities, GetServices; GetHostname once a SetHostname was accepted | GetDeviceInformation, GetScopes (its Fixed scopes; Rust appends the Configurable ones), GetNetworkInterfaces, GetHostname (`onvif_get_hostname` → `onvif_hostname`); allow/deny (`onvif_accept` or `onvif_fault`) on SetSystemDateAndTime, SetScopes/AddScopes/RemoveScopes (`onvif_set_scopes`), SetHostname, SystemReboot |
| Media ver10 | — | GetProfiles, GetVideoSources, GetStreamUri, GetSnapshotUri |
| Media2 ver20 | GetServiceCapabilities | the **same events** as Media: GetProfiles, GetVideoSourceConfigurations and GetVideoEncoderConfigurations render one `onvif_get_profiles` answer, GetStreamUri/GetSnapshotUri ask the URI events (`service: media2`; a Media2 Protocol is mapped onto ver10's stream and transport, RTSPS and unknown ones are `InvalidArgVal/InvalidStreamSetup`) — so both services describe the same profiles with the same configuration tokens (`vsc_<source>`, `vec_<profile>`, `ptz_config`) |
| PTZ ver20 | GetServiceCapabilities, GetNodes, GetNode, GetConfigurations, GetConfiguration, GetStatus, GetPresets, SetPreset, RemovePreset, Stop | ContinuousMove, RelativeMove, AbsoluteMove, GotoPreset, GotoHomePosition (`onvif_ptz_move` → `onvif_ptz_position {pan, tilt, zoom}`) |
| Events ver10 | GetServiceCapabilities, GetEventProperties, PullMessages, Renew, Unsubscribe, SetSynchronizationPoint | CreatePullPointSubscription (`onvif_create_subscription` → `onvif_accept`, optionally with `onvif_raise_event`s) |
| Imaging ver20 | GetServiceCapabilities, GetImagingSettings, GetOptions, GetMoveOptions, GetStatus, Stop | SetImagingSettings (`onvif_set_imaging_settings` → `onvif_accept`), Move (`onvif_imaging_move` → `onvif_focus_position`) |

Every model event carries `operation`, `username` (the authenticated user, or null) and
`remote_addr`, and offers `onvif_fault {subcode, detail?, reason}`, which goes out as
`env:Sender` (or `env:Receiver` for `ActionNotSupported` and `Action`) with
`ter:<subcode>[/ter:<detail>]`. A refused change or move changes nothing. Rust builds each
response's required structure in XSD order, because zeep reads strictly.

### The device's volatile state

Like a camera, the device holds state in memory for the life of the server; it is not storage
(nothing is written, a restart forgets it):

- **Clock.** An accepted SetSystemDateAndTime (Manual with a UTCDateTime, or NTP — the host
  clock) sets the offset GetSystemDateAndTime reports **and** WS-Security Created is checked
  against. Its DateTimeType, TZ (a POSIX string, `InvalidTimeZone` otherwise) and
  DaylightSavings are reported back.
- **Scopes.** At most `MAX_SCOPES` (16) configurable ones. RemoveScopes of a Fixed scope (as the
  model last named them) is `OperationProhibited/FixedScope`, of an unknown one
  `InvalidArgVal/NoScope`, both without asking the model; SetScopes naming a Fixed one is
  `OperationProhibited/ScopeOverwrite`; past the cap `Action/TooManyScopes`.
- **Hostname.** RFC 1123 labels (`InvalidHostname` otherwise).
- **Profiles and sources the model described** (`Catalog`): a PTZ or Imaging request naming a
  profile or video source not yet described asks the model for its profiles (or sources) once;
  then `InvalidArgVal/NoProfile`, `NoPTZProfile` (a profile without `ptz: true`) or `NoSource`.
- **PTZ.** One node (`ptz_node`) in ONVIF's generic spaces — pan and tilt −1..1, zoom 0..1 — and
  one configuration (`ptz_config`) that every profile the model marks `ptz: true` carries.
  Vectors are checked against their space and range before the model is asked
  (`InvalidPosition`, `InvalidTranslation`, `InvalidVelocity`, `InvalidSpeed`; a Timeout past
  `MAX_TIMEOUT` 600 s is `TimeoutNotSupported`). The event carries the current position and a
  `proposed` one (plain arithmetic; a continuous move covers a tenth of the space per second at
  full velocity); the model's position is where the head ends up. A ContinuousMove leaves the
  axes it moves `MOVING` until its Timeout (default `DEFAULT_TIMEOUT` 10 s) or a Stop. Presets:
  at most `MAX_PRESETS` (32; `Action/TooManyPresets`), names 1..`MAX_PRESET_NAME` (64) bytes
  (`InvalidPresetName`), unique (`PresetExist`); an unknown token is `NoToken`. SetPreset
  stores the current position without asking the model; GotoPreset asks with the preset's
  position proposed. SetHomePosition is not implemented (the home is fixed at 0, 0, 0).
- **Imaging.** Per video source (at most `MAX_ITEMS`): brightness, colour saturation, contrast,
  sharpness (0..100), IR-cut filter (ON/OFF/AUTO), autofocus mode (AUTO/MANUAL), focus position
  (0..1). A SetImagingSettings naming any other element (exposure, white balance, wide dynamic
  range, backlight compensation) or a value outside the options is `InvalidArgVal/SettingsInvalid`
  before the model is asked — use-go/onvif writes every element, so its SetImagingSettings is
  always refused. Move takes the first of Absolute, Relative, Continuous present; a continuous
  focus move is `MOVING` until Stop or `MAX_CONTINUOUS` (60 s).
- **Events** (`events.rs`). Four fixed topics, all properties: `tns1:VideoSource/MotionAlarm`
  (Source; State), `tns1:RuleEngine/CellMotionDetector/Motion` and
  `tns1:RuleEngine/TamperDetector/Tamper` (VideoSourceConfigurationToken,
  VideoAnalyticsConfigurationToken, Rule; IsMotion / IsTamper), `tns1:Device/Trigger/DigitalInput`
  (InputToken; LogicalState). `onvif_raise_event` — an async action (the model or an operator,
  at any time) and a sync one (in the model's answer to a subscription, or to any event) — puts
  a notification on every live subscription whose filter matches and remembers it as the
  property's value (`MAX_PROPERTIES` 64). A new subscription and SetSynchronizationPoint queue
  every remembered value as `Initialized`. At most `MAX_SUBSCRIPTIONS` (16; the next is
  `env:Receiver/ter:Action` with a `SubscribeCreationFailedFault` detail), each living until its
  termination time — InitialTerminationTime as a duration or a dateTime, default
  `DEFAULT_TERMINATION` 60 s, cut to `MAX_TERMINATION` 1 h; one in the past is refused
  `UnacceptableInitialTerminationTimeFault` — and holding at most `MAX_QUEUED` (256)
  notifications, the oldest dropped. Topic filters: the ConcreteSet, Concrete, Full (`*`) and
  Simple dialects, `|` alternatives, `//.` descendants, any prefix on the root; bounded at
  `MAX_TOPIC_EXPRESSION` bytes, `MAX_TOPIC_ALTERNATIVES` and `MAX_TOPIC_DEPTH` and parsed
  without recursion; an empty expression is no filter (use-go/onvif always sends one); an
  unknown dialect, a malformed expression, one matching no topic, or a MessageContent filter
  is refused with the WS-BaseNotification fault as Detail. The subscription address is
  `/onvif/events/subscription/<128-bit id>`; PullMessages, Renew, Unsubscribe and
  SetSynchronizationPoint find it by path (or by `wsa:To`), and an unknown or expired one is
  `env:Sender/ter:InvalidArgVal` with a `ResourceUnknownFault` detail. use-go/onvif's Renew and
  Unsubscribe carry no namespace and are accepted at a subscription's address. PullMessages
  answers at once when something is queued, else **long-polls** up to its Timeout, cut to the
  startup parameter `max_pull_timeout_secs` (1..60, default `MAX_PULL_TIMEOUT` 60);
  MessageLimit is clamped to 1..`MAX_MESSAGE_LIMIT` (100). It does not extend the subscription;
  Renew does (cut to `MAX_TERMINATION`).

## Authentication

Startup parameters `username` and `password` (together or neither; with neither, every
operation is open and the log says so) and `max_clock_skew_secs` (default `MAX_CLOCK_SKEW`,
300). Every operation but GetSystemDateAndTime — on every service — needs a WS-Security
UsernameToken with a **PasswordDigest**: `Base64(SHA-1(nonce ‖ Created ‖ password))`, the nonce
base64, Created RFC 3339 within the skew of the **device's** clock, the configured user.
Comparisons are constant-time. Accepted nonces are remembered (`MAX_NONCES`, for twice the skew)
so a captured token cannot be replayed. PasswordText is refused: over plain HTTP it is the
password.

Every refusal is `env:Sender` / `ter:NotAuthorized`, HTTP 400 — the peer never learns which
check failed. The log and the access log (`onvif_not_authorized {operation, reason}`) do:
`no_username_token`, `password_not_digest`, `nonce_not_base64`, `bad_nonce_length`,
`no_created`, `bad_created`, `stale_created`, `unknown_user`, `bad_digest`, `replayed_nonce`.
Unknown operations are refused before authentication (`ActionNotSupported` says nothing an
attacker could use).

Every request is logged to the status stream as `ONVIF connection <id> request
<service>:<Operation>` (service `device`, `media`, `media2`, `ptz`, `events`, `imaging`, or
`other` for an unqualified body) — that is where the tests read what each client actually sent.

## Failure

Malformed envelopes are `env:Sender` / `ter:WellFormed` (400); SOAP 1.1 is
`env:VersionMismatch` (400); a body over `MAX_REQUEST` is HTTP 413 before it is parsed. A model
that fails, answers nothing, or answers with an action for another operation or one that fails
validation is `env:Receiver` with a `WireFailure` category and no subcode (500, or 503 with
`Retry-After` when overloaded); nothing of the model's answer is sent and nothing changes — a
subscription the model did not accept is removed again. Decisions are logged
`decision=model_answer|model_reject|model_silent|fail_closed_llm_error|fail_closed_invalid_reply|fail_closed_not_authorized|action_not_supported`.

## Not implemented

Recording, Replay, Search, Analytics, DeviceIO; WS-BaseNotification Subscribe (Basic
Notification, the device POSTing Notify to a consumer — onvif-zeep-async can drive it through
its NotificationManager, but nothing here does, and the device making outbound requests to a
client-chosen address wants its own bounds); PTZ SetHomePosition, SetConfiguration, preset
tours, GeoMove, auxiliary commands; Imaging presets and the settings listed above; Media2
Add/RemoveConfiguration, CreateProfile and the audio, metadata, OSD and mask operations;
Device Set* beyond the six above (SetNTP, SetNetworkInterfaces, users, …); more than one user
and user levels; HTTP Digest authentication; TLS. The device does not stream: the URIs are
whatever the model says. WS-Discovery is the separate `wsdiscovery` protocol: point its
`xaddrs` at `http://<host>:<port>/onvif/device_service`.

## Maturity: Experimental

Device and Media ver10: python onvif-zeep-async 4.3.0 (zeep over ONVIF's WSDL) and Go
use-go/onvif v0.0.9 (`tests/server/onvif/real_client_test.rs`). PTZ, Events, Imaging and the
Set* operations: the same two (`services_test.rs`), each moving the head and reading the status
back, setting/going to/removing a preset, a refused move leaving the position, a pull-point
subscription receiving the model's notification and a long poll woken by an event raised while
it waits. Media2: python onvif2-zeep 0.3.4 (zeep over the ver20 Media WSDL in its own source
distribution) and Go IOTechSystems/onvif v1.3.0 — onvif-zeep-async and use-go bundle no Media2.
All fail when absent. `pcap_oracle_test.rs` has tshark read every new service's exchange both
ways. `fuzz/fuzz_targets/onvif_request.rs` drives the topic-filter, duration, PTZ-vector and
imaging parsers behind the tree; it has run clean (168,703 executions over 301 seconds on 23
October 2026, seeded lockfile, current nightly, `-s none` on macOS — and on this machine a
linker wrapper adding `-Wl,-undefined,dynamic_lookup`, because the `crc-fast` cdylib in the
lockfile will not link with sanitizer coverage and no sanitizer runtime). Two independent clients per service is the evidence Beta asks
for; it stays Experimental because no person has reviewed the services beyond it and the pair
job has not run them in CI.
