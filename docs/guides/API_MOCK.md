# Quickstart: NetGet as an API mock in your tests

Stand up a fake HTTP API (or Redis, DNS, SMTP, … — anything NetGet serves) for a test suite,
on a port the OS picks, answered by fixed rules so no model is involved and every run gives
the same answers.

Everything below was run against this repository's `netget` (see [INSTALL.md](INSTALL.md)).
`jq` and `curl` are used to look at the results.

## 1. Describe the mock in a `.netget` file

A `.netget` file is a list of the actions NetGet would otherwise ask a model for. This one
starts an HTTP server on port `0` (the OS picks a free port) with three static rules. A rule's
`match` narrows it to events whose fields have exactly those values; rules are tried in order
and the first that matches answers:

```bash
mkdir -p /tmp/netget-api-mock && cd /tmp/netget-api-mock
cat > users.netget <<'EOF'
{"actions": [{
  "type": "open_server", "protocol": "http", "port": 0, "instruction": "user API",
  "event_handlers": [
    {"event_pattern": "http_request", "match": {"method": "GET", "path": "/users/7"},
     "handler": {"type": "static", "actions": [{"type": "send_http_response", "status": 200,
       "headers": {"Content-Type": "application/json"}, "body": "{\"id\": 7, \"name\": \"Ada\"}"}]}},
    {"event_pattern": "http_request", "match": {"method": "POST", "path": "/users"},
     "handler": {"type": "static", "actions": [{"type": "send_http_response", "status": 201,
       "headers": {"Location": "/users/8"}, "body": "{{event.body}}"}]}},
    {"event_pattern": "http_request",
     "handler": {"type": "static", "actions": [{"type": "send_http_response", "status": 404,
       "body": "no route for {{event.method}} {{event.path}}"}]}}
  ]
}]}
EOF
```

`{{event.body}}` and friends quote the request into the answer. When the answer needs logic
(compute something from the request, keep state), use a `script` handler instead — see
`src/scripting/AGENTS.md`. `netget --docs` lists each protocol's events, their fields and the
actions that answer them.

## 2. Run it and find the port

`--ready-file` makes NetGet write a JSON report once every server is listening. The file is
written atomically and removed at startup if stale, so its appearance means "ready":

```bash
rm -f ready.json   # a stale report would read as "ready" before NetGet removes it
netget --load users.netget --ready-file ready.json --ollama-url http://127.0.0.1:1 \
  --run-for 60 > netget.out 2>&1 &
until [ -s ready.json ]; do sleep 0.1; done
cat ready.json
PORT=$(jq -r '.servers[0].port' ready.json)
curl -s "http://127.0.0.1:$PORT/users/7"; echo                       # {"id": 7, "name": "Ada"}
curl -si -X POST -d '{"name": "Grace"}' "http://127.0.0.1:$PORT/users" | head -1   # HTTP/1.1 201 Created
curl -s "http://127.0.0.1:$PORT/users/8"; echo                       # no route for GET /users/8
kill %1
```

```json
{
  "version": 1,
  "pid": 41234,
  "servers": [
    {"id": 1, "protocol": "HTTP", "host": "127.0.0.1", "port": 54321,
     "address": "127.0.0.1:54321", "status": "Running"}
  ],
  "clients": []
}
```

`--ollama-url http://127.0.0.1:1` points the model at a closed port: an event no rule matches
fails closed (the peer gets an error) instead of reaching a model that happens to be running.
`--run-for 60` is a backstop so a forgotten mock does not outlive the shell. If a server cannot
start (port taken, a malformed rule), NetGet exits non-zero and never writes the file.

## 3. From pytest

`sdk/python/netget_fixture` is a standard-library-only helper that does the above: starts
NetGet, waits for the ready file, gives you the addresses, and stops it afterwards. It is not on
PyPI; install it from a checkout of this repository (into a virtualenv):

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install pytest /path/to/netget/sdk/python
cat > test_users.py <<'EOF'
import json, urllib.request

def test_get_user(netget):          # the fixture comes from the installed plugin
    mock = netget(config="users.netget", no_model=True)
    with urllib.request.urlopen(mock.url("http") + "/users/7") as reply:
        assert json.load(reply) == {"id": 7, "name": "Ada"}
EOF
NETGET_BIN=$(command -v netget) python3 -m pytest -q test_users.py
```

Installing the package registers the `netget` fixture with pytest. Without installing, put
`sdk/python` on `PYTHONPATH` and pass `-p netget_fixture.pytest_plugin`. Outside pytest, use the
context manager:

```python
from netget_fixture import NetGet

with NetGet(config="users.netget", no_model=True) as mock:
    host, port = mock.address("http")
```

`NetGet(actions=[...])` takes the actions inline instead of a file; `mock.stdout()` and
`mock.log()` return what NetGet printed and logged, for asserting on what the mock was sent.

## 4. From a Rust test

`crates/netget-fixture` is the same helper for Rust — synchronous, fine inside
`#[tokio::test]`, and dependent only on `serde_json`, not on NetGet. It is not on crates.io;
use a path dependency:

```toml
[dev-dependencies]
netget-fixture = { path = "/path/to/netget/crates/netget-fixture" }
```

```rust
use netget_fixture::NetGet;

#[test]
fn get_user() {
    let mock = NetGet::builder()
        .config_file("users.netget")
        .no_model()
        .start()
        .expect("netget starts");
    let addr = mock.addr("http"); // std::net::SocketAddr
    // ... point the code under test at http://{addr}
}
```

The binary is `.binary(path)` if given, else `$NETGET_BIN`, else `netget` on `PATH`. The
process is killed and its working directory removed when the `NetGet` value is dropped.

## 5. Let a model write the rules once

Writing rules by hand is the deterministic way. The other is to let a model improvise the API
while you exercise it, then freeze what it said. Over MCP (`netget --mcp`, see the README), with
a local Ollama:

1. `start_server` with `protocol: "http"`, `port: 0` and an `instruction` such as
   *"A REST API for users. GET /users/{id} returns {id, name} as JSON; anything else 404."*
2. Send it the requests your tests will send (`curl`, or the test suite itself).
3. `export_rules` with that `server_id` and `save_to: "users-recorded.netget"`.

`export_rules` keys each rule on the event fields that explain why the model's answers differed
(method and path), replays every rule against the requests it was derived from, and reports the
requests it could not turn into a rule rather than guessing — a path the model answered
differently on two requests is left to the fallback, which with no model fails closed.

It also adds to each `match` every field that never varied in the recording, request headers
included. `Host` carries the port, so a recording made on port 0 matches nothing once it is
replayed on another port. Narrow the conditions to method and path before replaying:

```bash
jq '(.actions[].event_handlers[] | select(.match) | .match) |= {method, path}' \
  users-recorded.netget > users-replay.netget
netget --load users-replay.netget --ready-file ready.json --ollama-url http://127.0.0.1:1
```

This step was checked with `llama3.1:8b` (`netget --mcp --ollama-url http://127.0.0.1:11434
--model llama3.1:8b`); with a model the answers in step 2 vary from run to run, which is exactly
why the recording, not the model, belongs in the test.
