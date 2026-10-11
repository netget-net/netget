"""aiocoap peer for NetGet's CoAP Observe (RFC 7641) and Block-wise (RFC 7959) tests.

aiocoap is a CoAP implementation in Python with its own codec, message layer, observation
and block-wise machinery; it shares nothing with NetGet's codec, libcoap or coap-lite.

    client PORT      against NetGet's server: observe /temp, PUT /temp twice (the handler
                     answers each PUT and notifies the observers), GET the 3000-byte /big
                     (Block2) and PUT 3000 bytes to /upload (Block1). One JSON report.
    server           a resource /upload that takes PUT (aiocoap reassembles Block1 itself)
                     and serves the last body back on GET. Prints {"ready": true, "port": N},
                     then {"put": {"size": N, "body": "...", "content_format": N}} per PUT.

The container this is developed in has no IPv6 at all, and aiocoap's default transports
open AF_INET6 sockets, so the IPv4-capable simple transports are selected before import.
"""
import os

os.environ.setdefault("AIOCOAP_CLIENT_TRANSPORT", "simple6")
os.environ.setdefault("AIOCOAP_SERVER_TRANSPORT", "simplesocketserver")

import asyncio  # noqa: E402
import json  # noqa: E402
import socket  # noqa: E402
import sys  # noqa: E402

import aiocoap  # noqa: E402
import aiocoap.resource as resource  # noqa: E402


def block(n=3000):
    """n pseudo-random lowercase letters (an LCG). The Rust tests build the same string."""
    x, out = 1, []
    for _ in range(n):
        x = (x * 1103515245 + 12345) % 2**31
        out.append(chr(97 + (x >> 16) % 26))
    return "".join(out)


BODY = block()


async def run_client(port):
    base = f"coap://127.0.0.1:{port}"
    ctx = await aiocoap.Context.create_client_context()
    report = {}

    # Observe /temp. The registration's response is the first value; every notification after
    # it is one the handler pushed with coap_notify in reply to a PUT below.
    observe = ctx.request(aiocoap.Message(code=aiocoap.GET, uri=f"{base}/temp", observe=0))
    first = await asyncio.wait_for(observe.response, 15)
    report["registration"] = {
        "code": str(first.code),
        "payload": first.payload.decode(),
        "observe": first.opt.observe,
    }
    notifications = []

    async def collect():
        async for n in observe.observation:
            notifications.append({"payload": n.payload.decode(), "observe": n.opt.observe})
            if len(notifications) == 2:
                observe.observation.cancel()
                break

    collector = asyncio.ensure_future(collect())
    for value in ("21", "22"):
        put = await asyncio.wait_for(
            ctx.request(
                aiocoap.Message(code=aiocoap.PUT, uri=f"{base}/temp", payload=value.encode())
            ).response,
            15,
        )
        assert put.code.is_successful(), put
        await asyncio.sleep(0.3)
    await asyncio.wait_for(collector, 15)
    report["notifications"] = notifications

    # Block2: aiocoap continues the transfer itself and hands back the whole representation.
    big = await asyncio.wait_for(
        ctx.request(aiocoap.Message(code=aiocoap.GET, uri=f"{base}/big")).response, 30
    )
    report["big"] = {
        "code": str(big.code),
        "size": len(big.payload),
        "matches": big.payload.decode() == BODY,
        "etag": big.opt.etag.hex() if big.opt.etag else None,
    }

    # Block1: a payload over aiocoap's 1024-byte maximum is sent in blocks.
    up = await asyncio.wait_for(
        ctx.request(
            aiocoap.Message(
                code=aiocoap.PUT,
                uri=f"{base}/upload",
                payload=BODY.encode(),
                content_format=0,
            )
        ).response,
        30,
    )
    report["upload"] = {"code": str(up.code), "payload": up.payload.decode()}
    await ctx.shutdown()
    print(json.dumps(report), flush=True)


class Upload(resource.Resource):
    def __init__(self):
        super().__init__()
        self.body = b""

    async def render_get(self, request):
        return aiocoap.Message(payload=self.body, content_format=0)

    async def render_put(self, request):
        self.body = request.payload
        print(
            json.dumps(
                {
                    "put": {
                        "size": len(request.payload),
                        "body": request.payload.decode(errors="replace"),
                        "content_format": request.opt.content_format,
                    }
                }
            ),
            flush=True,
        )
        return aiocoap.Message(code=aiocoap.CHANGED, payload=f"stored {len(request.payload)}".encode())


async def run_server():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    site = resource.Site()
    site.add_resource(["upload"], Upload())
    await aiocoap.Context.create_server_context(site, bind=("127.0.0.1", port))
    print(json.dumps({"ready": True, "port": port}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    if sys.argv[1] == "client":
        asyncio.run(run_client(int(sys.argv[2])))
    else:
        asyncio.run(run_server())
