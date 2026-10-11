"""Install the SSE tests' peers into an owned ROOT:

- eventsource 3.0.5 (npm): the WHATWG EventSource for Node, which reconnects with Last-Event-ID.
- httpx-sse 0.4.0 on httpx 0.28.1: a Python event-stream reader.
- sse-starlette 2.2.1 under uvicorn 0.34.0, and aiohttp-sse 2.2.0 on aiohttp 3.11.11: two
  independent event-stream servers for the client tests.

Usage: python3 install_peers.py /absolute/owned/root
Prints NETGET_SSE_NODE_MODULES and NETGET_SSE_PYTHON.
"""
import json, pathlib, subprocess, sys

root = pathlib.Path(sys.argv[1]).resolve()
js = root / "js"
js.mkdir(parents=True, exist_ok=True)
(js / "package.json").write_text(json.dumps(
    {"name": "netget-sse-peers", "private": True, "dependencies": {"eventsource": "3.0.5"}}))
subprocess.run(["npm", "install", "--silent", "--no-audit", "--no-fund", "--prefix", str(js)],
               check=True, timeout=900)
venv = root / "venv"
subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
python = venv / "bin" / "python"
subprocess.run([str(python), "-m", "pip", "install", "-q", "httpx==0.28.1", "httpx-sse==0.4.0",
                "sse-starlette==2.2.1", "uvicorn==0.34.0", "aiohttp==3.11.11", "aiohttp-sse==2.2.0"],
               check=True, timeout=900)
print(f"export NETGET_SSE_NODE_MODULES={js / 'node_modules'}")
print(f"export NETGET_SSE_PYTHON={python}")
