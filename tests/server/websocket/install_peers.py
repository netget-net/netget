#!/usr/bin/env python3
"""Install the RFC 7692 permessage-deflate peers the WebSocket tests drive.

    python3 tests/server/websocket/install_peers.py <dir>

Creates <dir>/venv with Python websockets and <dir>/js/node_modules with the ws package,
pinned, and prints the two variables the tests read:

    NETGET_WS_PYTHON=<dir>/venv/bin/python
    NETGET_WS_NODE_MODULES=<dir>/js/node_modules

Node itself and websocat come from the system. The tests fail rather than skip without them.
"""
import os
import subprocess
import sys

WEBSOCKETS = "websockets==15.0.1"
WS = "ws@8.18.3"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = os.path.abspath(sys.argv[1])
    venv = os.path.join(root, "venv")
    python = os.path.join(venv, "bin", "python")
    if not os.path.exists(python):
        subprocess.run([sys.executable, "-m", "venv", venv], check=True)
    subprocess.run(
        [python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", WEBSOCKETS],
        check=True,
    )
    js = os.path.join(root, "js")
    os.makedirs(js, exist_ok=True)
    if not os.path.exists(os.path.join(js, "package.json")):
        with open(os.path.join(js, "package.json"), "w") as f:
            f.write('{"name": "netget-ws-peers", "private": true}\n')
    subprocess.run(["npm", "install", "--silent", "--no-audit", "--no-fund", WS], cwd=js, check=True)
    print(f"NETGET_WS_PYTHON={python}")
    print(f"NETGET_WS_NODE_MODULES={os.path.join(js, 'node_modules')}")


if __name__ == "__main__":
    main()
