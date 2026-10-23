"""PTZ, Events, Imaging and the Device Set* operations through python onvif-zeep-async (Home
Assistant's ONVIF library, zeep over ONVIF's own WSDL). It connects as Home Assistant does,
then:

- PTZ: nodes, configurations, status; an absolute move and the status after it; a relative
  move; a continuous move, the status while moving, Stop, the status after; a preset set,
  listed, a move away, GotoPreset back, the preset removed; home; a move the device refuses and
  the status after it; PTZ on a profile without PTZ.
- Events: event properties; a pull-point subscription through the library's PullPointManager
  (CreatePullPointSubscription, as Home Assistant does it); a pull that receives what the
  device raised in answer to the subscription; then the line `{"step": "subscribed"}` and a
  long pull the test answers by raising an event on the device; SetSynchronizationPoint and a
  pull of the property values it resends; Renew; Unsubscribe; a pull on the ended subscription.
- Imaging: settings, options, move options; a SetImagingSettings and the settings after; a
  refused one and the settings after; a focus Move and the status after.
- Device: SetHostname then GetHostname; SetScopes, AddScopes, RemoveScopes, each followed by
  GetScopes; a refused AddScopes; SystemReboot; SetSystemDateAndTime then GetSystemDateAndTime.

Prints one JSON object as its last line. Usage: python zeep_services.py host port username password
"""
import asyncio
import datetime as dt
import json
import sys

import onvif
import zeep.exceptions

TT = "{http://www.onvif.org/ver10/schema}"


def fault(err):
    return {"fault": str(err.message), "subcodes": [q.localname for q in (err.subcodes or [])]}


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def position(p):
    if p is None:
        return None
    return {
        "pan": p.PanTilt.x if p.PanTilt is not None else None,
        "tilt": p.PanTilt.y if p.PanTilt is not None else None,
        "zoom": p.Zoom.x if p.Zoom is not None else None,
    }


def status(s):
    return {
        "position": position(s.Position),
        "pan_tilt": str(s.MoveStatus.PanTilt) if s.MoveStatus else None,
        "zoom": str(s.MoveStatus.Zoom) if s.MoveStatus else None,
        "utc": str(s.UtcTime),
    }


def notifications(result):
    """Each NotificationMessage as Home Assistant's parser reads it: topic, time, items."""
    out = []
    for n in result.NotificationMessage or []:
        # zeep types the tt:Message by onvif.xsd, as Home Assistant reads it.
        msg = n.Message._value_1
        items = lambda part: {i.Name: i.Value for i in (part.SimpleItem if part is not None else [])}
        out.append({
            "topic": n.Topic._value_1.strip(),
            "utc_time": msg.UtcTime.isoformat() if msg.UtcTime is not None else None,
            "property_operation": str(msg.PropertyOperation) if msg.PropertyOperation else None,
            "source": items(msg.Source),
            "data": items(msg.Data),
        })
    return out


async def main(host, port, user, password):
    out = {}

    async def call(name, coro, convert=lambda r: r):
        try:
            out[name] = convert(await coro)
        except zeep.exceptions.Fault as err:
            out[name] = fault(err)
        return out[name]

    cam = onvif.ONVIFCamera(host, int(port), user, password, adjust_time=True)
    await cam.update_xaddrs()
    out["xaddrs"] = cam.xaddrs

    # ---- PTZ -------------------------------------------------------------------------------
    ptz = await cam.create_ptz_service()
    await call("ptz_nodes", ptz.GetNodes(), lambda r: [{"token": n.token, "presets": n.MaximumNumberOfPresets, "home": n.HomeSupported} for n in r])
    await call("ptz_configurations", ptz.GetConfigurations(), lambda r: [{"token": c.token, "node": c.NodeToken, "timeout": str(c.DefaultPTZTimeout)} for c in r])
    await call("ptz_status_initial", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_absolute", ptz.AbsoluteMove({"ProfileToken": "main", "Position": {"PanTilt": {"x": 0.5, "y": 0.25}, "Zoom": {"x": 0.3}}}), lambda r: "ok")
    await call("ptz_status_absolute", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_relative", ptz.RelativeMove({"ProfileToken": "main", "Translation": {"PanTilt": {"x": 0.1, "y": -0.05}}}), lambda r: "ok")
    await call("ptz_status_relative", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_continuous", ptz.ContinuousMove({"ProfileToken": "main", "Velocity": {"PanTilt": {"x": -0.5, "y": 0.0}}, "Timeout": dt.timedelta(seconds=30)}), lambda r: "ok")
    await call("ptz_status_moving", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_stop", ptz.Stop({"ProfileToken": "main", "PanTilt": True, "Zoom": True}), lambda r: "ok")
    await call("ptz_status_stopped", ptz.GetStatus({"ProfileToken": "main"}), status)
    preset = await call("ptz_set_preset", ptz.SetPreset({"ProfileToken": "main", "PresetName": "Door"}), str)
    await call("ptz_presets", ptz.GetPresets({"ProfileToken": "main"}), lambda r: [{"token": p.token, "name": p.Name, "position": position(p.PTZPosition)} for p in r])
    await call("ptz_away", ptz.AbsoluteMove({"ProfileToken": "main", "Position": {"PanTilt": {"x": -0.8, "y": -0.8}, "Zoom": {"x": 0.0}}}), lambda r: "ok")
    await call("ptz_goto_preset", ptz.GotoPreset({"ProfileToken": "main", "PresetToken": preset}), lambda r: "ok")
    await call("ptz_status_preset", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_refused", ptz.AbsoluteMove({"ProfileToken": "main", "Position": {"PanTilt": {"x": 0.95, "y": 0.0}}}), lambda r: "ok")
    await call("ptz_status_refused", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_remove_preset", ptz.RemovePreset({"ProfileToken": "main", "PresetToken": preset}), lambda r: "ok")
    await call("ptz_presets_after", ptz.GetPresets({"ProfileToken": "main"}), lambda r: [p.token for p in r])
    await call("ptz_goto_removed", ptz.GotoPreset({"ProfileToken": "main", "PresetToken": preset}), lambda r: "ok")
    await call("ptz_home", ptz.GotoHomePosition({"ProfileToken": "main"}), lambda r: "ok")
    await call("ptz_status_home", ptz.GetStatus({"ProfileToken": "main"}), status)
    await call("ptz_no_ptz_profile", ptz.GetStatus({"ProfileToken": "sub"}), status)

    # ---- Events ----------------------------------------------------------------------------
    events = await cam.create_events_service()
    await call("event_properties", events.GetEventProperties(), lambda r: {
        "fixed": r.FixedTopicSet, "dialects": list(r.TopicExpressionDialect),
        "roots": [e.tag for e in r.TopicSet._value_1]})
    manager = await cam.create_pullpoint_manager(dt.timedelta(seconds=120), lambda: None)
    out["subscription_address"] = cam.xaddrs.get("http://www.onvif.org/ver10/events/wsdl/PullPointSubscription")
    pullpoint = manager.get_service()
    await call("pull_on_subscribe", pullpoint.PullMessages({"MessageLimit": 10, "Timeout": dt.timedelta(seconds=5)}), notifications)
    emit({"step": "subscribed"})
    started = asyncio.get_running_loop().time()
    await call("pull_raised", pullpoint.PullMessages({"MessageLimit": 10, "Timeout": dt.timedelta(seconds=30)}), notifications)
    out["pull_raised_secs"] = asyncio.get_running_loop().time() - started
    await manager.set_synchronization_point()
    await call("pull_after_sync", pullpoint.PullMessages({"MessageLimit": 10, "Timeout": dt.timedelta(seconds=5)}), notifications)
    subscription = await cam.create_subscription_service("PullPointSubscription")
    await call("renew", subscription.Renew(cam.get_next_termination_time(dt.timedelta(seconds=300))), lambda r: {"current": str(r.CurrentTime), "termination": str(r.TerminationTime)})
    await manager.shutdown()
    await call("pull_after_unsubscribe", pullpoint.PullMessages({"MessageLimit": 10, "Timeout": dt.timedelta(seconds=1)}), notifications)

    # ---- Imaging ---------------------------------------------------------------------------
    imaging = await cam.create_imaging_service()
    settings = lambda r: {"brightness": r.Brightness, "contrast": r.Contrast, "ir_cut_filter": str(r.IrCutFilter), "auto_focus": str(r.Focus.AutoFocusMode) if r.Focus else None}
    await call("imaging_settings", imaging.GetImagingSettings({"VideoSourceToken": "lobby_cam"}), settings)
    await call("imaging_options", imaging.GetOptions({"VideoSourceToken": "lobby_cam"}), lambda r: {"brightness": [r.Brightness.Min, r.Brightness.Max], "ir_cut": list(r.IrCutFilterModes)})
    await call("imaging_move_options", imaging.GetMoveOptions({"VideoSourceToken": "lobby_cam"}), lambda r: {"absolute": [r.Absolute.Position.Min, r.Absolute.Position.Max]})
    await call("imaging_set", imaging.SetImagingSettings({"VideoSourceToken": "lobby_cam", "ImagingSettings": {"Brightness": 70.0, "Contrast": 40.0}}), lambda r: "ok")
    await call("imaging_settings_after", imaging.GetImagingSettings({"VideoSourceToken": "lobby_cam"}), settings)
    await call("imaging_refused", imaging.SetImagingSettings({"VideoSourceToken": "lobby_cam", "ImagingSettings": {"Brightness": 10.0, "IrCutFilter": "OFF"}}), lambda r: "ok")
    await call("imaging_settings_refused", imaging.GetImagingSettings({"VideoSourceToken": "lobby_cam"}), settings)
    await call("imaging_move", imaging.Move({"VideoSourceToken": "lobby_cam", "Focus": {"Absolute": {"Position": 0.4}}}), lambda r: "ok")
    await call("imaging_status", imaging.GetStatus({"VideoSourceToken": "lobby_cam"}), lambda r: {"position": r.FocusStatus20.Position, "move_status": str(r.FocusStatus20.MoveStatus)})
    await call("imaging_no_source", imaging.GetImagingSettings({"VideoSourceToken": "nowhere"}), settings)

    # ---- Device Set* -----------------------------------------------------------------------
    device = await cam.create_devicemgmt_service()
    await call("hostname_initial", device.GetHostname(), lambda r: r.Name)
    await call("set_hostname", device.SetHostname({"Name": "lobby-cam-2"}), lambda r: "ok")
    await call("hostname_after", device.GetHostname(), lambda r: r.Name)
    scopes = lambda r: [[str(s.ScopeDef), str(s.ScopeItem)] for s in r]
    await call("set_scopes", device.SetScopes({"Scopes": ["onvif://www.onvif.org/location/floor1"]}), lambda r: "ok")
    await call("scopes_after_set", device.GetScopes(), scopes)
    await call("add_scopes", device.AddScopes({"ScopeItem": ["onvif://www.onvif.org/name/Annex"]}), lambda r: "ok")
    await call("scopes_after_add", device.GetScopes(), scopes)
    await call("remove_scopes", device.RemoveScopes({"ScopeItem": ["onvif://www.onvif.org/location/floor1"]}), lambda r: [str(s) for s in r])
    await call("scopes_after_remove", device.GetScopes(), scopes)
    await call("remove_fixed", device.RemoveScopes({"ScopeItem": ["onvif://www.onvif.org/name/LobbyCam"]}), lambda r: "ok")
    await call("add_refused", device.AddScopes({"ScopeItem": ["onvif://www.onvif.org/forbidden/x"]}), lambda r: "ok")
    await call("reboot", device.SystemReboot(), str)
    when = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=120)
    await call("set_date_time", device.SetSystemDateAndTime({
        "DateTimeType": "Manual", "DaylightSavings": False, "TimeZone": {"TZ": "CET-1CEST"},
        "UTCDateTime": {"Date": {"Year": when.year, "Month": when.month, "Day": when.day},
                        "Time": {"Hour": when.hour, "Minute": when.minute, "Second": when.second}}}), lambda r: "ok")
    out["date_time_asked"] = when.isoformat()
    await call("date_time_after", device.GetSystemDateAndTime(), lambda r: {
        "type": str(r.DateTimeType), "tz": r.TimeZone.TZ,
        "utc": dt.datetime(r.UTCDateTime.Date.Year, r.UTCDateTime.Date.Month, r.UTCDateTime.Date.Day,
                           r.UTCDateTime.Time.Hour, r.UTCDateTime.Time.Minute, r.UTCDateTime.Time.Second,
                           tzinfo=dt.timezone.utc).isoformat()})
    await cam.close()
    emit(out)


asyncio.run(main(*sys.argv[1:5]))
