#!/usr/bin/env python3
"""Recording proxy between NetGet and Ollama.

usage: recproxy.py <listen_port> <record_dir> [upstream]

Forwards every request to upstream (default http://127.0.0.1:11434) and writes
each POST body and the response body to <record_dir>/NNNN-<path>.req.json /
.resp.json. The whole response is buffered, which is fine for non-streamed calls.
"""
import http.server
import itertools
import os
import sys
import threading
import urllib.request

PORT = int(sys.argv[1])
DIR = sys.argv[2]
UP = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:11434"
os.makedirs(DIR, exist_ok=True)
counter = itertools.count(1)
lock = threading.Lock()


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _fwd(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        with lock:
            n = next(counter)
        tag = f"{n:05d}-{self.path.strip('/').replace('/', '_')}"
        if body is not None and method == "POST":
            with open(os.path.join(DIR, tag + ".req.json"), "wb") as f:
                f.write(body)
        req = urllib.request.Request(UP + self.path, data=body, method=method)
        for k in ("Content-Type", "Accept"):
            if self.headers.get(k):
                req.add_header(k, self.headers[k])
        try:
            with urllib.request.urlopen(req, timeout=900) as r:
                data = r.read()
                status = r.status
                ctype = r.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as e:
            data = e.read()
            status = e.code
            ctype = e.headers.get("Content-Type", "application/json")
        if method == "POST":
            with open(os.path.join(DIR, tag + ".resp.json"), "wb") as f:
                f.write(data)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._fwd("GET")

    def do_POST(self):
        self._fwd("POST")


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
