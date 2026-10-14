# ONVIF tests (device role)

`install_peers.py <dir>` installs every peer both roles use and prints `NETGET_ONVIF_PYTHON`
(a venv with onvif-zeep-async 4.3.0), `NETGET_ONVIF_GO_CLIENT` (built from `peer/go`, use-go/onvif
v0.0.9, go.sum pinned; x/net and x/sys raised so it links on current Go) and `NETGET_RPOS` (the
client tests' device). The tests fail, not skip, without them.

- `real_client_test::onvif_zeep_async_reads_what_the_model_supplied` — `peer/zeep_client.py`
  connects as Home Assistant does (clock, then GetServices, digests shifted by the clock
  difference) and reads device information, scopes, network interfaces, profiles, video
  sources and the stream and snapshot URIs `POLICY` (a python handler standing in for the model)
  supplied; GetHostname comes back `ActionNotSupported`. With the wrong password zeep is refused
  `NotAuthorized` and the access log says `bad_digest`.
- `real_client_test::use_go_onvif_reads_what_the_model_supplied` — the same through the Go
  library's `NewDevice` and request types; a profile the model does not have is its
  `InvalidArgVal` fault. The library cannot decode the encoder configuration (its tags are
  `onvif:Encoding`, which encoding/xml never matches on read), so only tokens and names of
  profiles are compared.
- `wire_test` — raw HTTP: the anonymous clock; each refusal reason (no token, wrong password,
  wrong user, PasswordText, Created an hour either side, unparseable Created, a replayed token)
  and that none reached the model; unknown operations (`ActionNotSupported`, before and after
  authentication), `NoSuchService`, malformed XML, DOCTYPE, nesting past `MAX_DEPTH` (all
  `WellFormed`), SOAP 1.1 (`VersionMismatch`), `MAX_REQUEST` and one byte past it (413), GET
  (405); a failed backend, a wrong action and an invalid URI all failing closed; the digest
  against UsernameToken Profile's own example.

Mutation-checked: skipping the digest comparison, dropping the replay check, the clock check,
the depth check and the size limit each fail a test here.

No LLM calls.
