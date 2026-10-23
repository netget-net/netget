"""An ONVIF client run through python onvif-zeep-async (Home Assistant's ONVIF library: zeep over
ONVIF's own WSDL and XSD files). It connects the way Home Assistant does — the clock first,
unauthenticated, then GetServices to find the media service, every later call signed with a
WS-Security PasswordDigest shifted by the clock difference — reads what the model supplied,
and prints one JSON object.

Usage: python zeep_client.py host port username password
"""
import asyncio
import json
import sys

import onvif
import zeep.exceptions


def fault(err):
    """A zeep Fault as code and the subcodes zeep parsed."""
    subcodes = [q.localname for q in (err.subcodes or [])]
    return {"fault": str(err.message), "code": str(err.code), "subcodes": subcodes}


async def main(host, port, user, password):
    out = {}
    cam = onvif.ONVIFCamera(host, int(port), user, password, adjust_time=True)
    try:
        await cam.update_xaddrs()
    except zeep.exceptions.Fault as err:
        out["connect"] = fault(err)
        print(json.dumps(out))
        return
    except Exception as err:  # noqa: BLE001 - reported to the test, which decides
        out["connect"] = {"error": f"{type(err).__name__}: {err}"}
        print(json.dumps(out))
        return
    out["xaddrs"] = cam.xaddrs
    out["dt_diff_secs"] = cam.dt_diff.total_seconds() if cam.dt_diff is not None else None
    device = await cam.create_devicemgmt_service()
    media = await cam.create_media_service()

    async def call(name, coro, convert):
        try:
            out[name] = convert(await coro)
        except zeep.exceptions.Fault as err:
            out[name] = fault(err)

    await call("device_information", device.GetDeviceInformation(), lambda r: {
        "manufacturer": r.Manufacturer, "model": r.Model, "firmware_version": r.FirmwareVersion,
        "serial_number": r.SerialNumber, "hardware_id": r.HardwareId})
    await call("scopes", device.GetScopes(), lambda r: [str(s.ScopeItem) for s in r])
    await call("network_interfaces", device.GetNetworkInterfaces(), lambda r: [{
        "token": i.token, "name": i.Info.Name, "mac": i.Info.HwAddress, "dhcp": i.IPv4.Config.DHCP,
        "address": (i.IPv4.Config.Manual[0].Address if i.IPv4.Config.Manual else i.IPv4.Config.FromDHCP.Address)}
        for i in r])
    await call("profiles", media.GetProfiles(), lambda r: [{
        "token": p.token, "name": p.Name, "encoding": p.VideoEncoderConfiguration.Encoding,
        "width": p.VideoEncoderConfiguration.Resolution.Width,
        "height": p.VideoEncoderConfiguration.Resolution.Height,
        "source": p.VideoSourceConfiguration.SourceToken} for p in r])
    await call("video_sources", media.GetVideoSources(), lambda r: [{
        "token": s.token, "width": s.Resolution.Width, "height": s.Resolution.Height} for s in r])
    tokens = [p["token"] for p in out.get("profiles", []) if isinstance(p, dict)] if isinstance(out.get("profiles"), list) else []
    if tokens:
        req = media.create_type("GetStreamUri")
        req.ProfileToken = tokens[0]
        req.StreamSetup = {"Stream": "RTP-Unicast", "Transport": {"Protocol": "RTSP"}}
        await call("stream_uri", media.GetStreamUri(req), lambda r: {"uri": r.Uri, "timeout": str(r.Timeout)})
        await call("snapshot_uri", media.GetSnapshotUri({"ProfileToken": tokens[0]}), lambda r: {"uri": r.Uri})
    await call("unsupported", device.GetUsers(), lambda r: {"users": str(r)})
    await cam.close()
    print(json.dumps(out, default=str))


asyncio.run(main(*sys.argv[1:5]))
