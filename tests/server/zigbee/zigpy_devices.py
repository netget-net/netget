"""What `bellows devices -D <db>` prints, from the database a bellows application wrote.

bellows 0.46.2's own `devices` command validates its configuration twice (CONFIG_SCHEMA, then
ControllerApplication.new applies SCHEMA again), which zigpy 0.84's OTA-provider validator
rejects; this is that command's body with the configuration validated once. It opens the
database without the radio, exactly as the command does. Usage: python zigpy_devices.py <db>
"""
import asyncio
import json
import sys

import zigpy.config as zc
import zigpy.endpoint
from bellows.zigbee.application import ControllerApplication


async def main():
    app = await ControllerApplication.new(
        {zc.CONF_DATABASE: sys.argv[1], zc.CONF_DEVICE: {zc.CONF_DEVICE_PATH: "/dev/null"}},
        start_radio=False,
    )
    devices = []
    for ieee, dev in app.devices.items():
        eps = []
        for epid, ep in dev.endpoints.items():
            if epid == 0 or ep.status == zigpy.endpoint.Status.NEW:
                continue
            eps.append({"id": epid, "profile": ep.profile_id, "device_type": int(ep.device_type),
                        "in_clusters": {str(c): cl.name for c, cl in sorted(ep.in_clusters.items())},
                        "out_clusters": {str(c): cl.name for c, cl in sorted(ep.out_clusters.items())}})
        devices.append({"ieee": str(ieee), "nwk": f"0x{dev.nwk:04x}", "model": dev.model,
                        "manufacturer": dev.manufacturer, "endpoints": eps})
    print(json.dumps(devices))
    await app.shutdown()


asyncio.run(main())
