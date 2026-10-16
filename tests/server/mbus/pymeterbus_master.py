"""An M-Bus master built from pyMeterBus (github.com/ganehag/pyMeterBus), pointed at an
M-Bus/IP gateway through pyserial's socket:// transport.

pyMeterBus 0.8.5 ships console scripts that import a `meterbus.tools` module the package does
not contain, so this drives the library itself: its own short and select frame builders
(send_ping_frame, send_request_frame, send_request_frame_multi, send_select_frame), its own
receive loop (recv_frame, which checks the checksum) and its own record decoder (load ->
to_JSON). It prints one JSON object describing what it saw; the Rust test asserts on it.

Usage: python3 -I pymeterbus_master.py <port> <heat secondary> <water secondary>
"""
import json
import sys

import meterbus
import serial


def frame_json(data):
    if not data:
        return None
    t = meterbus.load(data)
    return json.loads(t.to_JSON())


def main():
    port = int(sys.argv[1])
    heat, water = sys.argv[2], sys.argv[3]
    ser = serial.serial_for_url("socket://127.0.0.1:%d" % port, timeout=5)
    out = {}

    meterbus.send_ping_frame(ser, 1)
    out["ping"] = list(meterbus.recv_frame(ser, 1) or b"")

    # REQ_UD2 without FCB toggling (0x5B), then the multi-telegram form with FCB set (0x7B)
    # twice: the same FCB twice must get the same telegram back.
    meterbus.send_request_frame(ser, 1)
    first = meterbus.recv_frame(ser, 1)
    out["heat"] = frame_json(first)
    meterbus.send_request_frame_multi(ser, 1)
    a = meterbus.recv_frame(ser, 1)
    meterbus.send_request_frame_multi(ser, 1)
    b = meterbus.recv_frame(ser, 1)
    out["fcb_repeat_identical"] = bool(a) and a == b
    out["fcb_access_numbers"] = [frame_json(a)["body"]["header"]["access_no"],
                                 frame_json(b)["body"]["header"]["access_no"]]

    # Secondary addressing: select the water meter, then read it at 253.
    meterbus.send_select_frame(ser, water)
    out["select_water"] = list(meterbus.recv_frame(ser, 1) or b"")
    meterbus.send_request_frame(ser, meterbus.ADDRESS_NETWORK_LAYER)
    out["water"] = frame_json(meterbus.recv_frame(ser, 1))

    meterbus.send_select_frame(ser, heat)
    out["select_heat"] = list(meterbus.recv_frame(ser, 1) or b"")
    meterbus.send_request_frame(ser, meterbus.ADDRESS_NETWORK_LAYER)
    out["heat_secondary"] = frame_json(meterbus.recv_frame(ser, 1))

    print(json.dumps(out, default=str))


if __name__ == "__main__":
    main()
