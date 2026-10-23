# ONVIF tests (device role)

`install_peers.py <dir>` installs every peer both roles use and prints their variables:
`NETGET_ONVIF_PYTHON` (a venv with onvif-zeep-async 4.3.0 and onvif2-zeep 0.3.4, the latter from
its SHA-256-checked source distribution), `NETGET_ONVIF2_WSDL` (onvif2-zeep's ver20 WSDL tree from
that archive — the wheel's copy is flattened and does not load), `NETGET_ONVIF_GO_CLIENT` (built
from `peer/go`, use-go/onvif v0.0.9, go.sum pinned; x/net and x/sys raised so it links on current
Go), `NETGET_ONVIF_GO_MEDIA2` (built from `peer/go-media2`, IOTechSystems/onvif v1.3.0, go 1.25),
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
- `pcap_oracle_test` — ten exchanges (CreatePullPointSubscription, PullMessages with a
  notification, Renew, GetEventProperties, ContinuousMove, GetStatus, SetPreset, Media2
  GetProfiles, GetImagingSettings, SetHostname) handed to tshark's HTTP and XML dissectors: no
  Expert Info at Warn, the URI, a 200, and the SOAP body element tshark read in each direction.
- `wire_test` — raw HTTP: the anonymous clock; each refusal reason (no token, wrong password,
  wrong user, PasswordText, Created an hour either side, unparseable Created, a replayed token)
  and that none reached the model; unknown operations (`ActionNotSupported`, before and after
  authentication), `NoSuchService`, GetCapabilities and GetServices naming exactly the
  services the device has; malformed XML, DOCTYPE, nesting past `MAX_DEPTH` (all `WellFormed`),
  SOAP 1.1 (`VersionMismatch`), `MAX_REQUEST` and one byte past it (413), GET (405); a failed
  backend, a wrong action and an invalid URI all failing closed; the digest against
  UsernameToken Profile's own example.
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
the depth check and the size limit each fail a test here. For the new services: applying a PTZ
move before the model answers, applying a SetHostname whatever the model says, dropping the
subscription cap, the Timeout cut or the MessageLimit clamp, and exempting PTZ from
authentication each fail `bounds_test` (and the first two `services_test`).

No LLM calls.
