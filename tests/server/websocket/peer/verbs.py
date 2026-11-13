"""Every verb NetGet's WebSocket server implements, driven by Python `websockets` (its own
framing, no compression). One JSON report on stdout; `real_client_test.rs` asserts on it.

    verbs.py PORT

The server's handler (in the test) accepts `/session` with the subprotocol `chat` when it is
offered and the greeting `welcome`, echoes text as `echo:<text>` and binary unchanged, answers
`close please` with close 4002 "asked to", and refuses `/reject` with 403.
"""
import asyncio
import json
import sys

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus


async def main(port):
    base = f"ws://127.0.0.1:{port}"
    report = {}
    async with connect(
        base + "/session",
        subprotocols=["v2.chat.example", "chat"],
        compression=None,
        ping_interval=None,
    ) as ws:
        report["subprotocol"] = ws.subprotocol
        report["greeting"] = await ws.recv()
        await ws.send("héllo ✓")
        report["text"] = await ws.recv()
        await ws.send(bytes([0x00, 0xFF, 0xFE, 0x01, 0x80, 0x7F, 0xC3, 0x28]))
        report["binary"] = (await ws.recv()).hex()
        # One text message in two frames: FIN clear, then a continuation with FIN set.
        await ws.send(["frag", "ment"])
        report["fragmented"] = await ws.recv()
        pong = await ws.ping(b"p1")
        report["pong_latency_ok"] = (await asyncio.wait_for(pong, 5)) >= 0
        # Silent past the server's 2 s idle bound: the server's keepalive Ping at 1 s is
        # answered by websockets itself, so the connection is still open afterwards.
        await asyncio.sleep(3)
        await ws.send("after the keepalive")
        report["after_keepalive"] = await ws.recv()
        await ws.send("close please")
        try:
            await ws.recv()
            report["server_close"] = "no close"
        except ConnectionClosed as e:
            report["server_close"] = {"code": e.rcvd.code, "reason": e.rcvd.reason}

    async with connect(base + "/session", compression=None, ping_interval=None) as ws:
        report["no_subprotocol"] = ws.subprotocol
        await ws.recv()  # the greeting
        await ws.close(4001, "bye")
        report["client_close_echo"] = {"code": ws.close_code, "reason": ws.close_reason}

    try:
        async with connect(base + "/reject", compression=None):
            report["reject"] = "opened"
    except InvalidStatus as e:
        report["reject"] = e.response.status_code

    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1])))
