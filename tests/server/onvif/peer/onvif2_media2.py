"""Media2 (ver20) through python onvif2-zeep 0.3.4: zeep over ONVIF's ver20 Media WSDL from the
package's own source distribution (`wsdl_dir`). The library connects its own way — the clock,
then GetServices with IncludeCapability, then a pull-point subscription it opens for itself —
and this reads every profile with all its configurations, the stream and snapshot URIs, the
video source and encoder configurations, and two refusals.

Prints one JSON object. Usage: python onvif2_media2.py host port username password wsdl_dir
"""
import json
import sys

import zeep.exceptions
from onvif2 import ONVIFCamera
from onvif2.exceptions import ONVIFError


def fault(err):
    return {"fault": str(err.message), "subcodes": [q.localname for q in (err.subcodes or [])]}


def main(host, port, user, password, wsdl_dir):
    out = {}

    def call(name, fn, convert=lambda r: r):
        try:
            out[name] = convert(fn())
        except zeep.exceptions.Fault as err:
            out[name] = fault(err)
        except ONVIFError as err:
            # onvif2 wraps the zeep Fault it caught; report the fault itself.
            cause = err.__context__
            out[name] = fault(cause) if isinstance(cause, zeep.exceptions.Fault) else {"error": str(err)}

    cam = ONVIFCamera(host, int(port), user, password, wsdl_dir, adjust_time=True)
    out["xaddrs"] = cam.xaddrs
    media2 = cam.create_media2_service()

    def profile(p):
        c = p.Configurations
        enc = c.VideoEncoder if c is not None else None
        return {
            "token": p.token, "name": p.Name,
            "source": c.VideoSource.SourceToken if c is not None and c.VideoSource is not None else None,
            "encoding": enc.Encoding if enc is not None else None,
            "width": enc.Resolution.Width if enc is not None else None,
            "height": enc.Resolution.Height if enc is not None else None,
            "ptz": c.PTZ.token if c is not None and c.PTZ is not None else None,
        }

    call("profiles", lambda: media2.GetProfiles({"Type": ["All"]}), lambda r: [profile(p) for p in r])
    call("profiles_bare", lambda: media2.GetProfiles(), lambda r: [{"token": p.token, "configurations": p.Configurations is not None} for p in r])
    call("stream_uri", lambda: media2.GetStreamUri({"Protocol": "RtspUnicast", "ProfileToken": "main"}), str)
    call("snapshot_uri", lambda: media2.GetSnapshotUri({"ProfileToken": "sub"}), str)
    call("source_configurations", lambda: media2.GetVideoSourceConfigurations(), lambda r: [{"token": c.token, "source": c.SourceToken} for c in r])
    call("encoder_configurations", lambda: media2.GetVideoEncoderConfigurations({"ProfileToken": "sub"}), lambda r: [{"token": c.token, "encoding": c.Encoding, "width": c.Resolution.Width} for c in r])
    call("missing_profile", lambda: media2.GetStreamUri({"Protocol": "RTSP", "ProfileToken": "nonexistent"}), str)
    call("bad_protocol", lambda: media2.GetStreamUri({"Protocol": "RtspsUnicast", "ProfileToken": "main"}), str)
    print(json.dumps(out, default=str))


main(*sys.argv[1:6])
