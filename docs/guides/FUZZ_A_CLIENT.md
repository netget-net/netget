# Quickstart: abuse a client with malformed responses

Point the client you are testing at a server that answers with the responses real servers
almost never send — truncated bodies, absurd lengths, broken framing, binary junk — and watch
whether it errors cleanly, hangs or crashes. NetGet's raw `tcp` server puts exactly the bytes
you specify on the wire, so the protocol on top is whatever you write, malformed included.

Everything below was run against this repository's `netget`; the client being abused here is
`curl`, standing in for yours.

## 1. A server with one bad answer per path

A Python script handler reads the HTTP request line out of the raw bytes and picks a case from
the path, so each case is reproducible (`/3` is always case 3). `encoding: "hex"` is how a
handler sends bytes that are not text.

```bash
mkdir -p /tmp/netget-fuzz && cd /tmp/netget-fuzz
cat > cases.py <<'EOF'
import json, sys
data = json.load(sys.stdin)
request = data["event"].get("data", "")
path = request.split(" ")[1] if " " in request else "/"
case = path.strip("/") or "0"
H = "HTTP/1.1 200 OK\r\n"
cases = {
    "1": H + "Content-Length: 100\r\n\r\nonly ten b",                    # truncated body
    "2": H + "Content-Length: 99999999999999999999999\r\n\r\nx",         # overflowing length
    "3": H + "Content-Length: -1\r\n\r\nx",                              # negative length
    "4": H + "this header has no colon\r\n\r\n",                         # malformed header
    "5": "HTTP/1.1 9999 Whatever\r\nContent-Length: 0\r\n\r\n",          # impossible status
    "6": H + "X-Big: " + "A" * 200000 + "\r\n\r\n",                      # 200 KB header
    "7": H + "Transfer-Encoding: chunked\r\n\r\nZZZ\r\nnope\r\n0\r\n\r\n", # bad chunk size
    "8": H + "Content-Length: 5\r\nContent-Length: 50\r\n\r\nhello",     # conflicting lengths
}
if case == "9":   # NUL and 0xFF bytes in the status line, sent as hex
    actions = [{"type": "send_tcp_data", "encoding": "hex",
                "data": (b"HTTP/1.1 200 \x00\xff\r\n\r\n").hex()}]
elif case == "10":  # hang up without a byte
    actions = []
else:
    actions = [{"type": "send_tcp_data", "data": cases.get(case, H + "Content-Length: 2\r\n\r\nok")}]
actions.append({"type": "close_this_connection"})
print(json.dumps({"actions": actions}))
EOF
python3 - <<'EOF'
import json
code = open("cases.py").read()
json.dump({"actions": [{
    "type": "open_server", "protocol": "tcp", "port": 0, "instruction": "fuzz",
    "event_handlers": [{"event_pattern": "tcp_data_received",
                        "handler": {"type": "script", "language": "python", "code": code}}]
}]}, open("fuzz.netget", "w"))
EOF
rm -f ready.json   # a stale report would read as "ready" before NetGet removes it
netget --load fuzz.netget --ready-file ready.json --ollama-url http://127.0.0.1:1 \
  --run-for 120 > netget.out 2>&1 &
until [ -s ready.json ]; do sleep 0.1; done
PORT=$(jq -r '.servers[0].port' ready.json)
```

## 2. Run the client against every case

```bash
for c in 1 2 3 4 5 6 7 8 9 10; do
  printf 'case %-2s ' "$c"
  curl -s -o /dev/null -m 5 -w 'http=%{http_code} ' "http://127.0.0.1:$PORT/$c"
  echo "exit=$?"
done
kill %1
```

curl 8.23 gives:

```
case 1  http=200 exit=18     # partial file: the length promised more than arrived
case 2  http=200 exit=0      # a length that overflows 64 bits, then EOF: accepted
case 3  http=200 exit=8      # weird server reply
case 4  http=200 exit=8
case 5  http=999 exit=0      # status 9999 reported as 999, and accepted
case 6  http=200 exit=100    # header too large
case 7  http=200 exit=56     # bad chunk size
case 8  http=200 exit=8      # conflicting Content-Length
case 9  http=200 exit=8
case 10 http=000 exit=52     # empty reply
```

Cases 2 and 5 are the interesting kind of result: curl reports success for an answer no
server should send. The other kind is a timeout (`-m 5`, exit 28): a client that hangs on a
malformed answer. Swap `curl` for your client's test harness and assert on how it fails.

## 3. Going further

- **Other protocols.** The same `tcp` server can speak broken SMTP, Redis (RESP), or any
  line protocol; most NetGet protocol servers also have actions that send protocol errors
  (`redis_error`, `send_dns_refused`, HTTP status codes) when you want *valid* edge cases
  rather than invalid framing.
- **Rotate instead of routing.** A client that always requests the same path can be served a
  different case each connection with a resident script (`"resident": true`), which keeps a
  counter between events — see `src/scripting/AGENTS.md`.
- **Let a model improvise.** Drop the handler and give an instruction instead; that needs a
  model and is not reproducible run to run, which is why the deterministic version is above:

  ```bash
  rm -f ready.json   # a stale report would read as "ready" before NetGet removes it
  netget --server tcp --port 0 --ready-file ready.json --run-for 120 \
    --ollama-url http://127.0.0.1:11434 --model llama3.1:8b \
    'Answer every HTTP request with a subtly malformed HTTP/1.1 response, then close the connection. Vary the defect.' \
    > model.out 2>&1 &
  until [ -s ready.json ]; do sleep 0.1; done
  curl -sv -m 60 "http://127.0.0.1:$(jq -r '.servers[0].port' ready.json)/"
  kill %1
  ```
