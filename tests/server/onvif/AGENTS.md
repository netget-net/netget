# ONVIF tests (device role)

`install_peers.py <dir>` installs every peer both roles use and prints their variables:
`NETGET_ONVIF_PYTHON` (a venv with onvif-zeep-async 4.3.0 and onvif2-zeep 0.3.4, the latter from
its SHA-256-checked source distribution), `NETGET_ONVIF2_WSDL` (onvif2-zeep's ver20 WSDL tree from
that archive — the wheel's copy is flattened and does not load), `NETGET_ONVIF_GO_CLIENT` (built
from `peer/go`, use-go/onvif v0.0.9, go.sum pinned; x/net and x/sys raised so it links on current
Go), `NETGET_ONVIF_GO_MEDIA2` (built from `peer/go-media2`, IOTechSystems/onvif v1.3.0, go 1.25),
`NETGET_ONVIF_GO_PROFILE_G` (built from `peer/go-profile-g`, github.com/videonext/onvif at a pinned
pseudo-version, go.sum pinned, x/net and x/text held at versions go 1.24 builds),
`NETGET_RPOS` and, on Linux, `NETGET_ONVIF_SIMPLE_SERVER` (the client tests' devices). The tests
fail, not skip, without them.

Every test that drives a peer runs on a multi-threaded runtime with the peer as a subprocess, and
the services tests print the operations the client actually sent, read from the device's
`request <service>:<Operation>` status lines.

- `real_client_test::onvif_zeep_async_reads_what_the_model_supplied` — `peer/zeep_client.py`
  connects as Home Assistant does (clock, then GetServices, digests shifted by the clock
  difference) and reads device information, scopes, network interfaces, profiles, video
  sources and the stream and snapshot URIs `POLICY` (a python handler standing in for the model)
  supplied; GetUsers comes back `ActionNotSupported`. With the wrong password zeep is refused
  `NotAuthorized` and the access log says `bad_digest`.
- `real_client_test::use_go_onvif_reads_what_the_model_supplied` — the same through the Go
  library's `NewDevice` and request types; a profile the model does not have is its
  `InvalidArgVal` fault. The library cannot decode the encoder configuration (its tags are
  `onvif:Encoding`, which encoding/xml never matches on read), so only tokens and names of
  profiles are compared.
- `services_test::onvif_zeep_async_drives_ptz_events_imaging_and_device_settings` —
  `peer/zeep_services.py`: GetServices names all six services; PTZ nodes, configurations, an
  absolute and a relative move each read back through GetStatus, a continuous move `MOVING`
  then Stop `IDLE`, a preset set/listed/gone to/removed, home, a move `POLICY` refuses
  (`InvalidPosition`) leaving the position, `NoPTZProfile` for the profile without PTZ, and the
  sequence of moves the model was asked about; Events through the library's PullPointManager
  as Home Assistant uses it — the MotionAlarm the model raised in answer to the subscription
  (topic, source, data, a UTC time within two minutes), a long poll woken by a DigitalInput the
  test raises through `onvif_raise_event` when zeep prints that it is waiting (answered in under
  20 s of a 30 s Timeout), both properties resent `Initialized` after SetSynchronizationPoint,
  Renew, Unsubscribe and a pull on the ended subscription refused; Imaging settings, options,
  a SetImagingSettings read back, a refused one changing nothing, a focus Move read back,
  `NoSource`; SetHostname/GetHostname, SetScopes/AddScopes/RemoveScopes each read back,
  `FixedScope` and a refused AddScopes, SystemReboot's message, SetSystemDateAndTime read back
  in TZ and time. 34 distinct operations.
- `services_test::use_go_onvif_drives_ptz_events_imaging_and_device_settings` — the same
  through use-go's own `ptz`, `event`, `Imaging` and `device` request types (`peer/go`, mode
  `services`). CallMethod cannot address a subscription, so PullMessages, Renew, Unsubscribe and
  SetSynchronizationPoint go through the library's own SOAP builder posted to the
  subscription's address. Several of its response types tag fields `onvif:…` and never decode
  (positions, imaging settings, addresses), so those are read with small structs; its
  SetImagingSettings writes every ImagingSettings20 element and is refused `SettingsInvalid`;
  its Renew and Unsubscribe go out unqualified (`other:Renew`). 37 distinct operations.
- `services_test::media2_through_onvif2_zeep_and_iotech_onvif_reads_the_media_description` —
  onvif2-zeep (`peer/onvif2_media2.py`) reads every profile with all configurations, the same
  tokens Media ver10 gives, profiles without Type carrying none, both URIs, source and encoder
  configurations narrowed by profile, `NoProfile` and `InvalidStreamSetup`, and the stream event
  asked in ver10 terms; IOTechSystems/onvif (`peer/go-media2`) reads profiles and encoder
  configurations through its `media2` types, sent to the Media XAddr as that library does.
- `profile_g_test::onvif_zeep_async_reads_searches_and_replays_what_the_model_described` —
  `peer/zeep_recording.py`: GetServices names the recording, search and replay XAddrs; the
  recording capabilities; GetRecordings (sources, contents, retention as zeep's timedelta,
  tracks), GetRecordingConfiguration, GetRecordingJobs; a CreateRecording the model allows
  (`rec_1`, three empty tracks, read back) then deletes, its configuration `NoRecording` after;
  a CreateRecording and a DeleteRecording the model refuses (`OperationProhibited`), nothing
  changed; GetRecordingSummary, GetRecordingInformation (range from the tracks, status Recording
  from the job), `NoRecording`; FindRecordings paged one at a time (Searching, then Completed)
  and ended, one narrowed by IncludedRecordings; FindEvents over a day with a topic filter paged
  two at a time, GetSearchState, EndSearch's endpoint and the ended token `InvalidToken`;
  FindEvents backwards (newest first) and with IncludeStartState (the alarm's value at the start,
  then the door event); the replay capabilities, GetReplayUri, GetReplayConfiguration,
  `NoRecording`. The model was asked to describe the recordings exactly once. 20 distinct
  operations.
- `profile_g_test::videonext_onvif_reads_searches_and_replays_what_the_model_described` — Go
  videonext/onvif (`peer/go-profile-g`): one signed GetRecordings, refused `NotAuthorized` with
  the access log saying `bad_digest` (the library digests the nonce's base64 text), then the
  sequence unsigned through the library's devicemgmt, recording, search and replay ports:
  GetServices, capabilities, recordings, configuration, jobs, a create and delete, a refused
  delete, summary, information, FindRecordings paged, FindEvents across both recordings oldest
  first, GetSearchState, EndSearch and the ended token, replay URI and configuration,
  `NoRecording`. GetEventSearchResults and Replay's capabilities are read as they arrived (the
  library cannot decode those two types at all). 18 distinct operations.
- `notify_test::onvif_zeep_async_notification_manager_receives_the_notify` —
  `peer/zeep_notify.py` runs its own aiohttp consumer on a loopback port and creates the
  library's NotificationManager on it (Subscribe), prints that it is subscribed, and the test
  raises a DigitalInput through `onvif_raise_event`: the manager's own `process()` reads both
  Notifies — the MotionAlarm the model raised in its answer (topic, source, data, Changed, the
  subscription's address) and the DigitalInput. Renew, Unsubscribe (the manager's shutdown), a
  Renew after it refused; Subscribes naming 192.0.2.1 and an https consumer refused
  `InvalidArgVal`, recorded `not_allowlisted` and `https_refused`, the model asked only about the
  allowed one; deliveries recorded, none dropped.
- `notify_test::use_go_onvif_subscribe_receives_the_notify` — the same through use-go's
  `event.Subscribe` (`peer/go`, mode `notify`, a net/http consumer it binds): every POST carries
  the Notify Action and `To`, the messages the subscription and producer addresses; Renew and
  Unsubscribe go out unqualified (`other:Renew`).
- `pcap_oracle_test` — ten exchanges (CreatePullPointSubscription, PullMessages with a
  notification, Renew, GetEventProperties, ContinuousMove, GetStatus, SetPreset, Media2
  GetProfiles, GetImagingSettings, SetHostname) handed to tshark's HTTP and XML dissectors: no
  Expert Info at Warn, the URI, a 200, and the SOAP body element tshark read in each direction.
  `tshark_reads_recording_search_replay_subscribe_and_the_devices_notify` does the same for
  GetRecordings, GetRecordingJobs, GetRecordingInformation, GetEventSearchResults (its
  `tt:Result` and `tt:Event`), GetReplayUri and Subscribe, then hands tshark the Notify the device
  POSTed to a consumer the test runs: a POST to the consumer's path whose body is `wsnt:Notify`
  with the model's notification, answered 200.
- `wire_test` — raw HTTP: the anonymous clock; each refusal reason (no token, wrong password,
  wrong user, PasswordText, Created an hour either side, unparseable Created, a replayed token)
  and that none reached the model; unknown operations (`ActionNotSupported`, before and after
  authentication), `NoSuchService`, GetCapabilities and GetServices naming exactly the
  services the device has; malformed XML, DOCTYPE, nesting past `MAX_DEPTH` (all `WellFormed`),
  SOAP 1.1 (`VersionMismatch`), `MAX_REQUEST` and one byte past it (413), GET (405); a failed
  backend, a wrong action and an invalid URI all failing closed; the digest against
  UsernameToken Profile's own example.
- `notify_bounds_test` — Basic Notification's bounds over raw HTTP and consumers written in the
  test (not evidence): nine consumer addresses refused before the model (not allowlisted, https,
  a host name, userinfo, ftp, 0.0.0.0, IPv4-mapped 192.0.2.1, malformed, empty) and one past
  `MAX_CONSUMER_URL`, each with its recorded reason and no subscription; loopback (also as
  `::ffff:127.0.0.1`) allowed by default; `subscriber` admitting the client's own address only;
  a /32 exact. `MAX_PUSH_SUBSCRIPTIONS` and one more refused, a pull point unaffected,
  PullMessages on a push subscription `ActionNotSupported`, Unsubscribe ending the delivery task
  and making room. A consumer that never answers: with `notify_timeout_secs` 1 and
  `notify_retries` 2, exactly three requests, then `onvif_notify_dropped` with `attempts` 3,
  between 3.6 s and 15 s after the Subscribe. A 307 is not followed (the redirect's target never
  contacted) and is dropped after one attempt with `notify_retries` 0. A consumer holding the
  first Notify while `MAX_PUSH_QUEUED` + 6 events are raised receives exactly the newest
  `MAX_PUSH_QUEUED`, at most `MAX_NOTIFY_BATCH` per Notify, and the device logs the six dropped.
  An https consumer with `notify_allow_https`; a model that cannot answer a Subscribe leaves no
  subscription and contacts nobody.
- `recording_bounds_test` — Recording, Search and Replay's bounds over raw HTTP (not evidence):
  with `MAX_ARCHIVE_EVENTS` described events every one matching, a search keeps
  `MAX_SEARCH_RESULTS` and hands out at most `MAX_RESULTS_PAGE` at a time (Searching, Searching,
  Completed) whatever MaxResults asks; MaxMatches 3; MaxResults 0 read as 1; a token paged by the
  other kind of request refused; `MAX_SEARCHES` and one more refused (`ResourceProblem`), room
  after EndSearch; a KeepAliveTime of an hour cut to `MAX_KEEP_ALIVE` (an accepted
  SetSystemDateAndTime moves the device clock past it and every search is gone); one of a second
  gone 1.5 s later; all from one description. Descriptions past `MAX_RECORDINGS`,
  `MAX_RECORDED_EVENTS` or `MAX_ARCHIVE_EVENTS` fail closed and are asked for again; at the bounds
  they are served. A model that cannot answer CreateRecording or DeleteRecording changes nothing;
  an unknown recording and a full device are refused without asking; an accepted create has no
  replay URI and its GetReplayUri is `ActionNotSupported`. Ten requests the device cannot run
  (XPath filter, an oversized scope, no or bad StartPoint, a MessageContent filter, a years
  KeepAliveTime, a bad stream setup, an oversized SourceId, unknown search tokens) refused before
  the recordings are described. WS-Security on every Recording, Search and Replay operation and
  on Subscribe.
- `bounds_test` — the new services' bounds and failure paths over raw HTTP (not evidence):
  `MAX_SUBSCRIPTIONS` and one past it refused, room again after an Unsubscribe; a PullMessages
  Timeout of an hour cut to `max_pull_timeout_secs` (1 s: it waits that long, no less, no more);
  MessageLimit 2, 0 (read as 1) and 1000; a queue past `MAX_QUEUED` keeping the newest; a
  subscription past its termination time gone, one renewed for 20 h cut to `MAX_TERMINATION`, a
  past InitialTerminationTime refused, a filter of `MAX_TOPIC_ALTERNATIVES + 1` refused;
  `MAX_PRESETS` presets and one more refused, `MAX_PRESET_NAME` + 1 and a duplicate name
  refused; a model that is unreachable failing three PTZ moves, SetHostname, AddScopes,
  SetSystemDateAndTime, SetImagingSettings and a subscription closed — status, hostname, scopes,
  clock, imaging and the subscription count all unchanged; a model position outside the space
  not applied; WS-Security required on PTZ, Events (a subscription's address included), Media2,
  Imaging and the Device Set* operations.

Mutation-checked: skipping the digest comparison, dropping the replay check, the clock check,
the depth check and the size limit each fail a test here. For the new services, each of
these fails `bounds_test`: applying a PTZ move before the model answers (it once did not —
the failing-model test compared the status only after its last move, a GotoHomePosition that
undid the others; it now checks after each), applying a SetHostname whatever the model says,
dropping the subscription cap, the PullMessages Timeout cut (the pull then outlives the
client's 120 s) or the MessageLimit clamp, and exempting PTZ from authentication. Applying a
move the model refused fails both `services_test` PTZ checks (zeep's and Go's
`status_refused`).

Mutation-checked for Basic Notification, Recording, Search and Replay (each change made, the
suite run, the change reverted): dropping the consumer allowlist check (`notify_bounds_test`'s
192.0.2.1 and 0.0.0.0 consumers accepted, and both peers' `subscribe_outside_allowlist`), the
push-subscription cap, the per-attempt timeout (the batch never dropped), the retry bound (no
drop record), the search result bound and the page bound, exempting the Recording service from
WS-Security, applying a CreateRecording or DeleteRecording the model did not accept, and dropping
the queue cap.

No LLM calls.
