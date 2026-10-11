"""Independent aioquic 1.3.0 RFC 9221 DATAGRAM peer for the raw QUIC tests.

aioquic owns TLS, QUIC and the DATAGRAM frame; this wrapper only maps the test's
requests onto its public API. The quic-go peer in quic_go_peer/ speaks the same
command line, so one Rust test drives either.

    server --port 0 --cert C --key K   prints {"ready": true, "port": N}, then one
                                       {"datagram": hex} line per datagram received,
                                       answering each with b"echo:" + payload
    client --port N --ca C --send '["hex", ...]' --expect K
                                       sends each datagram, prints
                                       {"received": [hex, ...], "max_datagram_size": n}
                                       once K datagrams arrived
"""
import argparse
import asyncio
import json
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import DatagramFrameReceived

ALPN = "netget-quic"
MAX_FRAME = 65536


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = []
        self.arrived = asyncio.Event()

    def quic_event_received(self, event):
        if not isinstance(event, DatagramFrameReceived):
            return
        if self._quic.configuration.is_client:
            self.received.append(event.data.hex())
            self.arrived.set()
        else:
            print(json.dumps({"datagram": event.data.hex()}), flush=True)
            self._quic.send_datagram_frame(b"echo:" + event.data)
            self.transmit()


async def main(args):
    config = QuicConfiguration(
        is_client=args.mode == "client",
        alpn_protocols=[ALPN],
        server_name="localhost",
        idle_timeout=15,
        max_datagram_frame_size=MAX_FRAME,
    )
    if args.mode == "server":
        config.load_cert_chain(args.cert, args.key)
        server = await serve("127.0.0.1", args.port, configuration=config, create_protocol=Peer)
        port = server._transport.get_extra_info("sockname")[1]
        print(json.dumps({"ready": True, "port": port}), flush=True)
        await asyncio.Event().wait()
    config.load_verify_locations(args.ca)
    # aioquic's connect() opens a dual-stack IPv6 socket, which fails on hosts without IPv6;
    # an IPv4 endpoint built from the same public pieces does not.
    loop = asyncio.get_running_loop()
    _, client = await loop.create_datagram_endpoint(
        lambda: Peer(QuicConnection(configuration=config)), local_addr=("127.0.0.1", 0)
    )
    client.connect(("127.0.0.1", args.port))
    await asyncio.wait_for(client.wait_connected(), 10)
    remote = client._quic._remote_max_datagram_frame_size
    for payload in json.loads(args.send):
        client._quic.send_datagram_frame(bytes.fromhex(payload))
    client.transmit()
    deadline = asyncio.get_running_loop().time() + 10
    while len(client.received) < args.expect:
        client.arrived.clear()
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            sys.exit(json.dumps({"timeout": True, "received": client.received}))
        try:
            await asyncio.wait_for(client.arrived.wait(), remaining)
        except asyncio.TimeoutError:
            pass
    print(json.dumps({"received": client.received, "max_datagram_size": remote}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--ca")
    parser.add_argument("--send", default="[]")
    parser.add_argument("--expect", type=int, default=0)
    asyncio.run(main(parser.parse_args()))
