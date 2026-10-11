"""RFC 7692 permessage-deflate peer for NetGet's WebSocket tests: the `websockets` library
(Python, its own framing, CPython's zlib), with a TCP relay in front that records every
frame's RSV1 bit and payload length as it crosses the wire. The relay is what shows NetGet
compressed a message rather than only negotiating the extension: an uncompressed frame is
legal on a deflate connection, so the library alone could not tell.

    client PORT              connect to NetGet through the relay; one JSON report on stdout
    server                   echo server behind the relay; prints {"ready": true, "port": N}
                             then {"message": ...}, {"frame": ...} lines as they happen
"""
import asyncio
import json
import sys

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.extensions.permessage_deflate import ClientPerMessageDeflateFactory



def block(n=5000):
    """n pseudo-random lowercase letters with no short period (an LCG), so the only way to
    compress a repetition of it is a back-reference n bytes long. The Rust tests make the
    same string."""
    x, out = 1, []
    for _ in range(n):
        x = (x * 1103515245 + 12345) % 2**31
        out.append(chr(97 + (x >> 16) % 26))
    return "".join(out)


# Repeating at a distance of 5000 bytes: past a 12-bit (4 KiB) window, so a sender that
# ignores a negotiated window size produces back-references the receiver cannot follow.
LONG = block() * 3


def frames(buf, masked):
    """Parse WebSocket frame headers from bytes after the HTTP head."""
    out, pos = [], 0
    while pos + 2 <= len(buf):
        b0, b1 = buf[pos], buf[pos + 1]
        n, at = b1 & 0x7F, pos + 2
        if n == 126:
            if at + 2 > len(buf):
                break
            n, at = int.from_bytes(buf[at:at + 2], "big"), at + 2
        elif n == 127:
            if at + 8 > len(buf):
                break
            n, at = int.from_bytes(buf[at:at + 8], "big"), at + 8
        if b1 & 0x80:
            at += 4
        if at + n > len(buf):
            break
        out.append({"fin": bool(b0 & 0x80), "rsv1": bool(b0 & 0x40), "opcode": b0 & 0x0F, "len": n})
        pos = at + n
    return out


class Relay:
    """Forward one TCP connection, keeping each direction's bytes."""

    def __init__(self, target_port):
        self.target_port = target_port
        self.to_server = bytearray()
        self.to_client = bytearray()

    async def handle(self, reader, writer):
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.target_port)

        async def pump(src, dst, record):
            try:
                while data := await src.read(65536):
                    record.extend(data)
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                dst.close()

        await asyncio.gather(
            pump(reader, up_writer, self.to_server), pump(up_reader, writer, self.to_client)
        )

    def frames(self, direction):
        data = bytes(self.to_server if direction == "to_server" else self.to_client)
        head_end = data.find(b"\r\n\r\n")
        return frames(data[head_end + 4:], direction == "to_server") if head_end >= 0 else []


async def run_client(port):
    relay = Relay(port)
    server = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    relay_port = server.sockets[0].getsockname()[1]
    report = {}
    async with connect(
        f"ws://127.0.0.1:{relay_port}/deflate",
        extensions=[ClientPerMessageDeflateFactory(client_max_window_bits=True)],
        compression=None,
    ) as ws:
        report["extensions"] = ws.response.headers.get("Sec-WebSocket-Extensions")
        report["negotiated"] = [e.name for e in ws.protocol.extensions]
        replies = []
        await ws.send("hello " * 100)
        replies.append(await ws.recv())
        await ws.send(LONG)
        replies.append(await ws.recv())
        # A fragmented message: one compressed message across three frames.
        await ws.send(["part one, ", "part two, ", "part three"])
        replies.append(await ws.recv())
        await ws.send(b"\x00\xff" * 300)
        replies.append(await ws.recv())
        report["replies"] = [r if isinstance(r, str) else {"binary": r.hex()} for r in replies]
    await asyncio.sleep(0.2)
    report["server_frames"] = relay.frames("to_client")
    report["client_frames"] = relay.frames("to_server")
    server.close()
    print(json.dumps(report), flush=True)


async def run_server():
    async def echo(ws):
        print(json.dumps({"extensions": ws.request.headers.get("Sec-WebSocket-Extensions"),
                          "negotiated": ws.response.headers.get("Sec-WebSocket-Extensions")}),
              flush=True)
        async for message in ws:
            print(json.dumps({"message": message if isinstance(message, str) else message.hex()}),
                  flush=True)
            await ws.send("echo:" + message if isinstance(message, str) else message)

    inner = await serve(echo, "127.0.0.1", 0)
    inner_port = inner.sockets[0].getsockname()[1]
    relay = Relay(inner_port)

    async def handle(reader, writer):
        await relay.handle(reader, writer)
        for f in relay.frames("to_server"):
            print(json.dumps({"frame": f}), flush=True)

    outer = await asyncio.start_server(handle, "127.0.0.1", 0)
    print(json.dumps({"ready": True, "port": outer.sockets[0].getsockname()[1]}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    if sys.argv[1] == "client":
        asyncio.run(run_client(int(sys.argv[2])))
    else:
        asyncio.run(run_server())
