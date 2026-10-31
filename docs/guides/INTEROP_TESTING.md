# Quickstart: interop-test a client against many protocols

One NetGet process can serve many protocols at once. Start a handful of servers from one
file, each on an OS-assigned port and answered by a fixed rule, then run the clients you care
about against all of them and check what came back. Because nothing is real behind the
servers, every answer is exactly the one you wrote, so a mismatch is the client's.

Everything below was run against this repository's `netget` with Homebrew's `curl`,
`redis-cli`, `dig` and `mosquitto_pub` as the clients under test.

## 1. Four servers in one file

```bash
mkdir -p /tmp/netget-interop && cd /tmp/netget-interop
cat > interop.netget <<'EOF'
{"actions": [
  {"type": "open_server", "protocol": "http", "port": 0, "instruction": "fixed",
   "event_handlers": [{"event_pattern": "http_request", "handler": {"type": "static", "actions": [
     {"type": "send_http_response", "status": 200,
      "headers": {"Content-Type": "application/json"}, "body": "{\"ok\": true}"}]}}]},
  {"type": "open_server", "protocol": "redis", "port": 0, "instruction": "fixed",
   "event_handlers": [{"event_pattern": "redis_command", "handler": {"type": "static", "actions": [
     {"type": "redis_bulk_string", "value": "hello from netget"}]}}]},
  {"type": "open_server", "protocol": "dns", "port": 0, "instruction": "fixed",
   "event_handlers": [{"event_pattern": "dns_query", "handler": {"type": "static", "actions": [
     {"type": "send_dns_a_response", "query_id": "{{event.query_id}}",
      "domain": "{{event.domain}}", "ip": "192.0.2.7", "ttl": 60}]}}]},
  {"type": "open_server", "protocol": "mqtt", "port": 0, "instruction": "fixed",
   "event_handlers": [
     {"event_pattern": "mqtt_connect", "handler": {"type": "static", "actions": [
       {"type": "mqtt_connack", "return_code": 0}]}},
     {"event_pattern": "mqtt_publish", "handler": {"type": "static", "actions": [
       {"type": "mqtt_puback", "packet_id": "{{event.packet_id}}"}]}},
     {"event_pattern": "*", "handler": {"type": "static", "actions": []}}]}
]}
EOF
netget --load interop.netget --ready-file ready.json --ollama-url http://127.0.0.1:1 \
  --run-for 120 > netget.out 2>&1 &
until [ -s ready.json ]; do sleep 0.1; done
jq -r '.servers[] | "\(.protocol) \(.address)"' ready.json
```

`dns_query` echoes the client's `query_id` back with `{{event.query_id}}` — a fixed id would
make every resolver discard the answer. `netget --docs` lists each protocol's events and the
actions that answer them; the static examples there are the quickest starting point.

## 2. Run the clients and check the answers

```bash
port() { jq -r --arg p "$1" '.servers[] | select(.protocol == $p) | .port' ready.json; }
curl -s "http://127.0.0.1:$(port HTTP)/anything"; echo            # {"ok": true}
redis-cli -p "$(port Redis)" GET some-key                           # hello from netget
dig +short @127.0.0.1 -p "$(port DNS)" printer.example.test A       # 192.0.2.7
mosquitto_pub -p "$(port MQTT)" -q 1 -t sensors/1 -m 21.5 && echo published
kill %1
```

`netget.out` shows each event as NetGet decoded it, which is the other half of an interop
test — what the client actually put on the wire:

```
INFO 127.0.0.1 GET /anything ->  (84B, 19ms)
INFO Redis: GET some-key
INFO DNS A printer.example.test. from 127.0.0.1
INFO MQTT CONNECT from client 'anon-8' (MQTT 3.1.1, user=-, clean_session=true)
INFO MQTT PUBLISH sensors/1 from anon-8
```

## 3. Making it a test suite

- **Many protocols, one fixture.** `sdk/python/netget_fixture` and `crates/netget-fixture`
  take the same file and return every server's address
  (`mock.address("redis")`, `netget.addr("dns")`), so one fixture can back a whole
  parametrised suite. See [API_MOCK.md](API_MOCK.md).
- **Edge cases, not just the happy path.** Swap a rule's action for an error answer
  (`redis_error`, `send_dns_nxdomain`, an HTTP 503) and assert the client reports it;
  see [FUZZ_A_CLIENT.md](FUZZ_A_CLIENT.md) for invalid framing.
- **Which protocols exist.** `netget --docs`, or `list_protocols` over `netget --mcp`. Each
  protocol's maturity says how much real-client evidence stands behind its server; prefer
  `Beta` and `Stable` ones as interop references.
