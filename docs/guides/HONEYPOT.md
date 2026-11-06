# Quickstart: a logging honeypot (SSH, Telnet, HTTP)

Three fake services that accept whatever an attacker tries, answer plausibly, and write every
attempt to log files — with static handlers, so nothing costs a model call and nothing an
attacker sends reaches an LLM prompt.

Everything below was run against this repository's `netget` on macOS.

## 1. The configuration

```bash
mkdir -p /tmp/netget-honeypot && cd /tmp/netget-honeypot
cat > honeypot.netget <<'EOF'
{"actions": [
  {"type": "open_server", "protocol": "ssh", "port": 2222, "instruction": "honeypot",
   "event_handlers": [
     {"event_pattern": "ssh_auth", "handler": {"type": "static", "actions": [
       {"type": "append_to_log", "output_name": "ssh", "content": "auth {{event}}"},
       {"type": "ssh_auth_decision", "allowed": true}]}},
     {"event_pattern": "ssh_banner", "handler": {"type": "static", "actions": [
       {"type": "ssh_send_banner", "banner": "Ubuntu 22.04.4 LTS\n"}]}},
     {"event_pattern": "ssh_shell_command", "handler": {"type": "static", "actions": [
       {"type": "append_to_log", "output_name": "ssh", "content": "cmd {{event.command}}"},
       {"type": "ssh_shell_response", "response": "bash: permission denied\n"}]}},
     {"event_pattern": "*", "handler": {"type": "static", "actions": []}}]},
  {"type": "open_server", "protocol": "telnet", "port": 2323, "instruction": "honeypot",
   "event_handlers": [
     {"event_pattern": "telnet_message_received", "handler": {"type": "static", "actions": [
       {"type": "append_to_log", "output_name": "telnet", "content": "line {{event.message}}"},
       {"type": "send_telnet_line", "line": "Login incorrect"},
       {"type": "send_telnet_prompt", "prompt": "login: "}]}},
     {"event_pattern": "*", "handler": {"type": "static", "actions": []}}]},
  {"type": "open_server", "protocol": "http", "port": 8088, "instruction": "honeypot",
   "event_handlers": [
     {"event_pattern": "http_request", "handler": {"type": "static", "actions": [
       {"type": "append_to_log", "output_name": "http", "content": "{{event.method}} {{event.path}} {{event.headers}}"},
       {"type": "send_http_response", "status": 401,
        "headers": {"WWW-Authenticate": "Basic realm=\"router\"", "Server": "lighttpd/1.4.59"},
        "body": "Unauthorized"}]}}]}
]}
EOF
netget --load honeypot.netget --ollama-url http://127.0.0.1:1
```

Each `append_to_log` appends to `netget_<output_name>_<start time>_s<server id>.log` in the
working directory; NetGet's own `netget.log` and its stdout record every connection and event
as well. The `"*"`
rule answers any other event (connection opened, SFTP, …) with nothing, and
`--ollama-url http://127.0.0.1:1` makes anything unmatched fail closed rather than reach a
model.

## 2. Poke it

In a second terminal:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password root@127.0.0.1 'cat /etc/shadow'
# any password is accepted; the command prints "bash: permission denied"
printf 'admin\r\nhunter2\r\n' | nc -w 2 127.0.0.1 2323
curl -si http://127.0.0.1:8088/cgi-bin/luci -H 'User-Agent: masscan'
cd /tmp/netget-honeypot && cat netget_*.log
```

With `letmein` typed at the password prompt, the three logs
(`netget_ssh_<time>_s1.log`, `netget_telnet_…_s2.log`, `netget_http_…_s3.log`) hold:

```
GET /cgi-bin/luci {"host":"127.0.0.1:8088","accept":"*/*","user-agent":"masscan"}
auth {"username":"root","auth_type":"password","password":"letmein"}
cmd cat /etc/shadow
line admin
line hunter2
```

## 3. Exposure — read before putting this on a network

- **NetGet binds `127.0.0.1` unless you give a host.** Add `"host": "0.0.0.0"` (or `"::"`) to
  each `open_server` to listen on every interface. An explicit host is bound exactly as given;
  there is no confirmation step.
- **Ports below 1024 need root** (or `CAP_NET_BIND_SERVICE`). Do not run NetGet as root: it
  also executes `script` handlers as whatever user it runs as, unsandboxed. Keep it on high
  ports and forward 22/23/80 to them with the firewall (`pf` on macOS, `iptables`/`nft`
  `REDIRECT` on Linux), ideally on a disposable VM.
- **Static handlers keep attacker input away from the model.** If you switch a rule to the LLM
  (drop the handler and write an `instruction`), everything the attacker types becomes part of
  a prompt, and the model may follow instructions embedded in it. Every model call also costs
  money or GPU time per connection.
- **Credentials are logged in clear.** The SSH `password` field is exactly what the client
  sent. Treat the log directory as sensitive.
- The SSH host key is generated per run, so a returning scanner sees a different key each time
  NetGet restarts.
