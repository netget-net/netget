"""zigpy with bellows as the Zigbee host on NetGet's co-processor.

Starts a ControllerApplication on socket://127.0.0.1:<port> (forming a network if the NCP
has none), opens the network, waits for the device with <ieee> to join and be interviewed,
reads its Basic cluster, switches it on, waits for the attribute report, and reads on_off back
with the cache bypassed. Each step prints one JSON line; the exit status is 0 only when every
step held. Run with the bellows venv's python: python zigpy_host.py <port> <db> <ieee>
"""
import asyncio
import json
import logging
import sys

import zigpy.config as zc
import zigpy.types as zt
from bellows.zigbee.application import ControllerApplication

PORT, DB, IEEE = int(sys.argv[1]), sys.argv[2], sys.argv[3]
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)


def out(**kw):
    print(json.dumps(kw, default=str), flush=True)


class Listener:
    def __init__(self):
        self.initialized = asyncio.get_running_loop().create_future()
        self.joined = []

    def device_joined(self, device):
        self.joined.append(str(device.ieee))

    def device_initialized(self, device):
        if str(device.ieee) == IEEE and not self.initialized.done():
            self.initialized.set_result(device)


class Reports:
    def __init__(self):
        self.on_off = asyncio.get_running_loop().create_future()

    def attribute_updated(self, attrid, value, timestamp=None):
        if attrid == 0 and not self.on_off.done():
            self.on_off.set_result(value)


async def main():
    config = {
        zc.CONF_DEVICE: {zc.CONF_DEVICE_PATH: f"socket://127.0.0.1:{PORT}"},
        zc.CONF_DATABASE: DB,
        zc.CONF_NWK_BACKUP_ENABLED: False,
        zc.CONF_TOPO_SCAN_ENABLED: False,
        zc.CONF_OTA: {zc.CONF_OTA_ENABLED: False},
    }
    app = await ControllerApplication.new(config, auto_form=True, start_radio=True)
    try:
        info = app.state.network_info
        out(step="started", channel=info.channel, pan_id=f"0x{info.pan_id:04x}",
            coordinator=str(app.state.node_info.ieee), version=app.state.node_info.version)
        listener = Listener()
        app.add_listener(listener)
        await app.permit(30)
        out(step="permitted")
        device = await asyncio.wait_for(listener.initialized, 30)
        ep = device.endpoints[1]
        out(step="interviewed", nwk=f"0x{device.nwk:04x}", model=device.model,
            manufacturer=device.manufacturer, endpoints=sorted(e for e in device.endpoints if e),
            profile=ep.profile_id, device_type=int(ep.device_type),
            in_clusters=sorted(ep.in_clusters), out_clusters=sorted(ep.out_clusters),
            node_type=str(device.node_desc.logical_type))
        basic = await ep.basic.read_attributes(["zcl_version", "power_source"], allow_cache=False)
        out(step="basic", success={k: str(v) for k, v in basic[0].items()},
            failure={k: str(v) for k, v in basic[1].items()})
        reports = Reports()
        ep.on_off.add_listener(reports)
        rsp = await ep.on_off.on()
        out(step="on", response=str(rsp))
        reported = await asyncio.wait_for(reports.on_off, 15)
        out(step="reported", on_off=bool(reported))
        read = await ep.on_off.read_attributes(["on_off"], allow_cache=False)
        out(step="read", on_off=bool(read[0].get("on_off")))
        ok = (device.model == "Lamp-1" and device.manufacturer == "NetGet"
              and "SUCCESS" in str(rsp).upper() and bool(reported) and bool(read[0].get("on_off")))
        out(step="done", ok=ok)
        return 0 if ok else 1
    finally:
        await app.shutdown()


sys.exit(asyncio.run(main()))
