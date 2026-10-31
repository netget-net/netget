"""Tests for netget_fixture against a real netget binary ($NETGET_BIN).

Standard library only: ``python3 -m unittest discover -s tests`` from ``sdk/python``.
Every server is answered by a static or script handler and the model points at a closed
port, so nothing here reaches an LLM.
"""

import json
import os
import socket
import tempfile
import unittest
import urllib.error
import urllib.request

from netget_fixture import NetGet, NetGetError

ECHO = {
    "type": "open_server",
    "protocol": "tcp",
    "port": 0,
    "instruction": "echo",
    "event_handlers": [
        {
            "event_pattern": "tcp_data_received",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_tcp_data", "data": "{{event.data}}"}],
            },
        }
    ],
}

# Routes on the path with a Python script handler: still no model.
ROUTES = r"""import json, sys
data = json.load(sys.stdin)
path = data["event"].get("path", "/")
if path == "/users/7":
    actions = [{"type": "send_http_response", "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"id": 7, "name": "Ada"})}]
else:
    actions = [{"type": "send_http_response", "status": 404, "body": "no such user"}]
print(json.dumps({"actions": actions}))
"""

API = {
    "type": "open_server",
    "protocol": "http",
    "port": 0,
    "instruction": "user API",
    "event_handlers": [
        {
            "event_pattern": "http_request",
            "handler": {"type": "script", "language": "python", "code": ROUTES},
        }
    ],
}


def start(**kwargs):
    kwargs.setdefault("no_model", True)
    kwargs.setdefault("max_lifetime", 120)
    kwargs.setdefault("args", ["--log-level", "error"])
    return NetGet(**kwargs)


def echo(address, payload):
    with socket.create_connection(address, timeout=10) as conn:
        conn.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = conn.recv(4096)
            if not chunk:
                break
            received += chunk
        return received


class NetGetFixtureTest(unittest.TestCase):
    def test_inline_actions_report_bound_addresses(self):
        with start(actions=[ECHO, API]) as netget:
            self.assertEqual(len(netget.servers), 2, netget.servers)
            host, port = netget.address("tcp")
            self.assertEqual(host, "127.0.0.1")
            self.assertNotEqual(port, 0)
            self.assertEqual(echo((host, port), b"hello\n"), b"hello\n")

            with urllib.request.urlopen(netget.url("http") + "/users/7", timeout=10) as reply:
                self.assertEqual(reply.status, 200)
                self.assertEqual(json.loads(reply.read()), {"id": 7, "name": "Ada"})
            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(netget.url("http") + "/users/8", timeout=10)
            self.assertEqual(missing.exception.code, 404)

    def test_config_file_and_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "echo.netget")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"actions": [ECHO]}, handle)
            netget = start(config=path).start()
            address = netget.address("TCP")
            work_dir = netget.work_dir
            pid = netget.pid
            self.assertTrue(os.path.exists(os.path.join(work_dir, "ready.json")))
            self.assertEqual(netget.report["pid"], pid)
            netget.stop()
            self.assertFalse(os.path.exists(work_dir), "working directory removed")
            with self.assertRaises(OSError):
                socket.create_connection(address, timeout=2).close()

    def test_failed_start_raises_with_netget_stderr(self):
        with socket.socket() as taken:
            taken.bind(("127.0.0.1", 0))
            taken.listen()
            port = taken.getsockname()[1]
            busy = dict(ECHO, port=port)
            with self.assertRaises(NetGetError) as failure:
                start(actions=[busy], ready_timeout=60).start()
            self.assertIn("failed to start", failure.exception.stderr)

    def test_unknown_protocol_lookup(self):
        with start(actions=[ECHO]) as netget:
            with self.assertRaises(LookupError):
                netget.address("redis")


if __name__ == "__main__":
    unittest.main()
