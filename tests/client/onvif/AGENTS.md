# ONVIF client tests

The devices come from `tests/server/onvif/install_peers.py`, and the tests fail, not skip,
without them:

- `NETGET_RPOS` — RPOS (BreeeZe/rpos) at a pinned commit, SHA-256 checked, `npm install
  --ignore-scripts` (its native serial-port and Raspberry Pi modules are never loaded) and
  compiled with `tsc` (its gulp build does not run on current Node). Device, Media, PTZ and
  Imaging; no Events service (its GetServices names one that is not there) and no Media2.
- `NETGET_ONVIF_SIMPLE_SERVER` (Linux only) — a launcher for onvif_simple_server
  (roleoroleo/onvif_simple_server) at a pinned commit, SHA-256 checked, built with its own
  Makefile: its CGI under lighttpd for every service, and its onvif_notify_server daemon, which
  turns files appearing in /tmp/onvif_notify_server into notifications. The launcher runs
  `peer/onvif_simple_server.py`, which writes the configuration, starts both, and takes
  `on NAME` / `off NAME` / `log` on stdin. Both programs log to fixed files in /var/log and share
  fixed System V names, so one test uses it; the CI step creates the two log files writable.

Every test runs on a multi-threaded runtime with the device as a subprocess, and prints the
device's own log or record on failure.

- `real_server_test::netget_reads_rpos_with_a_digest_rpos_verifies` — RPOS on a free port
  (`NetworkAdapters` empty so it advertises 127.0.0.1; its RTSP server off, handing out the URI
  of an external one). RPOS checks every PasswordDigest itself and answers a bad one
  `NotAuthorized`. A python chain asks for device information, scopes, interfaces, sources and
  profiles on connect, then the stream and snapshot URIs of the profile RPOS listed; RPOS's
  answers are asserted in NetGet's events and the profile token in RPOS's own log of what it
  received (`logSoapCalls`). An injected action is answered with the result.
- `real_server_test::rpos_refuses_the_wrong_password_and_the_connection_fails` — RPOS logs the
  refusal and connect fails naming `NotAuthorized`.
- `real_server_test::netget_drives_rpos_ptz_head_and_imaging` — RPOS with its `rposascii` PTZ
  driver writing every PTZ and imaging command it executes to a TCP listener in the test. The
  chain reads nodes and configurations, the status, then makes an absolute, a relative and a
  continuous move, a stop, sets and lists a preset, goes home, goes to and removes the preset,
  and on the video sources reads and changes imaging settings and moves and stops focus — 20
  operations. Each accepted command is asserted in RPOS's own driver output
  (`absolute-ptz 0.5 -0.25 0.1`, `setpreset Door 1`, `brightness 70`, `focusstop`, …).
- `simple_server_test::netget_reads_media2_and_pulls_events_from_onvif_simple_server` — the
  chain reads the event properties and the Media2 profiles and opens a pull point, then asks
  Media2 for the first profile's URIs and configurations; the test makes the device raise its
  motion alarm and injects PullMessages through the command channel until it comes back as
  `{topic: tns1:VideoSource/MotionAlarm, property_operation: Changed, data: {State: "true"}}`;
  Renew, SetSynchronizationPoint (its properties resent `Initialized`) and Unsubscribe follow,
  then a pull with no subscription is the client's own error. Then Basic Notification: the
  client's `onvif_subscribe` starts its consumer on `notify_bind`, an address of this host that
  is not loopback (`NETGET_ONVIF_NOTIFY_BIND`, or the address the host would send from), because
  onvif_simple_server refuses loopback consumers; the device's CGI log names the consumer it
  accepted, its notify daemon sends the subscription's Initialized values, and once the alarm's
  has arrived switching it on is a Changed `{State: "true"}` `onvif_notification`; renew and
  unsubscribe follow, and the daemon's log shows each Notify it sent. With the wrong password
  onvif_simple_server still answers GetCapabilities (ONVIF's pre-authentication class), so the
  client connects, and every request after is refused `NotAuthorized` — its log says
  `Authentication error`. The test prints what the chain and the injections sent.
- `bounds_test` — a canned device written in the test (not evidence): a Subscribe names the
  client's own consumer (loopback, `/netget/onvif/notify/<32 hex>`, the model's topic filter); a
  Notify posted there with other prefixes becomes one `onvif_notification` the model answers by
  reading the recordings; a wrong path (404), GET (405), a body past `MAX_REQUEST` (413), a
  non-Notify, malformed XML and a depth bomb (400) reach nobody; `MAX_CONNECTIONS` held open and
  the next answered 503; renew and unsubscribe at the subscription's path, then no subscription.
  Recording, Search and Replay against canned answers: GetRecordings, GetRecordingSummary,
  FindEvents carrying the model's start, end, recordings, topic filter, MaxMatches and
  KeepAliveTime, its results read, EndSearch, GetReplayUri, the three services found in
  GetCapabilities' Extension and reached by path. And, as before: a reply nested past
  `MAX_DEPTH` and one past `MAX_RESPONSE` refuse the connection, exactly `MAX_RESPONSE` does
  not; a chain that never stops stops at `MAX_FOLLOWUP_DEPTH`; every signed request (the
  connect handshake's GetCapabilities and GetServices included) carries the device's clock (two
  hours ahead here) and verifies; the media service is reached by path on the given host
  though the capabilities named another.

Mutation-checked: dropping the model's actions fails `real_server_test`, the chain test and the
notification test (the Subscribe the model asks for is never sent, so no notification
arrives); removing the depth bound, the reply depth check or the reply size limits fails `bounds_test`.

No LLM calls.
