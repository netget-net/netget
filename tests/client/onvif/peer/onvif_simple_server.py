"""Run onvif_simple_server (roleoroleo/onvif_simple_server, C) as an ONVIF device for the client
tests: its CGI program under lighttpd for every service (Device, Media, Media2, PTZ, Events) and
its onvif_notify_server daemon, which turns files appearing in /tmp/onvif_notify_server into
event notifications. It verifies WS-Security PasswordDigest tokens itself.

The install (from tests/server/onvif/install_peers.py, Linux only: the notify daemon uses
inotify) holds `www/onvif` (the CGI and its templates), `bin/onvif_notify_server` and
`etc/onvif_notify_server` (its templates). Both programs log to fixed files in /var/log, which
must exist and be writable by this user, and share fixed System V names, so one instance runs at
a time.

Usage: python3 onvif_simple_server.py INSTALL WORKDIR PORT USER PASSWORD
Prints {"ready": true} once the device answers. Then reads commands on stdin:
  on NAME   create the event input file NAME (the notify daemon raises the event)
  off NAME  remove it
  log       print {"log": ...}: what the CGI and the daemon logged
EOF stops everything.
"""
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import time

INOTIFY_DIR = pathlib.Path("/tmp/onvif_notify_server")
LOGS = [pathlib.Path("/var/log/onvif_simple_server.log"), pathlib.Path("/var/log/onvif_notify_server.log")]

install, work, port, user, password = sys.argv[1:6]
install = pathlib.Path(install).resolve()
work = pathlib.Path(work).resolve()
work.mkdir(parents=True, exist_ok=True)

for log in LOGS:
    if not os.access(log, os.W_OK):
        sys.exit(f"{log} must exist and be writable: sudo install -m 666 /dev/null {log}")
shutil.rmtree(INOTIFY_DIR, ignore_errors=True)
INOTIFY_DIR.mkdir(parents=True)

conf = work / "onvif_simple_server.conf"
conf.write_text("\n".join([
    "model=OSS Evidence",
    "manufacturer=onvif_simple_server",
    "firmware_ver=40fd108",
    "hardware_id=OSS-HW",
    "serial_num=OSS-0001",
    "ifs=lo",
    f"port={port}",
    "scope=onvif://www.onvif.org/Profile/Streaming",
    "scope=onvif://www.onvif.org/name/OSS",
    f"user={user}",
    f"password={password}",
    "adv_enable_media2=1",
    "adv_fault_if_unknown=1",
    "adv_fault_if_set=0",
    "adv_synology_nvr=0",
    "name=Profile_0",
    "width=1920",
    "height=1080",
    "url=rtsp://%s/netget_main",
    "snapurl=http://%s/snapshot/main.jpg",
    "type=H264",
    "bitrate=4096",
    "framerate=25",
    "audio_encoder=NONE",
    "audio_decoder=NONE",
    "name=Profile_1",
    "width=640",
    "height=360",
    "url=rtsp://%s/netget_sub",
    "snapurl=http://%s/snapshot/sub.jpg",
    "type=H264",
    "bitrate=512",
    "framerate=10",
    "audio_encoder=NONE",
    "audio_decoder=NONE",
    "ptz=0",
    "events=1",
    "topic=tns1:VideoSource/MotionAlarm",
    "source_name=Source",
    "source_type=tt:ReferenceToken",
    "source_value=VideoSourceToken",
    f"input_file={INOTIFY_DIR}/motion_alarm",
    "topic=tns1:RuleEngine/MyRuleDetector/PeopleDetect",
    "source_name=VideoSourceConfigurationToken",
    "source_type=xsd:string",
    "source_value=VideoSourceToken",
    f"input_file={INOTIFY_DIR}/human_detection",
    "",
]))

cgi = work / "cgi.sh"
cgi.write_text(f"#!/bin/sh\nexec {install}/www/onvif/onvif_simple_server -c {conf} -d 5 \"$1\"\n")
cgi.chmod(0o755)
lighttpd_conf = work / "lighttpd.conf"
lighttpd_conf.write_text("\n".join([
    f'server.document-root = "{install}/www/"',
    f"server.port = {port}",
    # 127.0.0.1 unless told otherwise (a container's published port needs its outer address).
    f'server.bind = "{os.environ.get("ONVIF_SIMPLE_SERVER_BIND", "127.0.0.1")}"',
    f'server.errorlog = "{work}/lighttpd-error.log"',
    'server.modules = ( "mod_cgi" )',
    f'cgi.assign = ( "_service" => "{cgi}" )',
    "",
]))

children = []


def stop(*_):
    for c in children:
        if c.poll() is None:
            c.terminate()
    for c in children:
        try:
            c.wait(timeout=5)
        except subprocess.TimeoutExpired:
            c.kill()
    sys.exit(0)


signal.signal(signal.SIGTERM, stop)
notify_log = open(work / "notify.out", "w")
children.append(subprocess.Popen(
    [install / "bin" / "onvif_notify_server", "-c", conf, "-p", work / "notify.pid",
     "-t", install / "etc" / "onvif_notify_server", "-f", "-d", "5"],
    stdout=notify_log, stderr=subprocess.STDOUT))
children.append(subprocess.Popen(
    ["lighttpd", "-D", "-f", lighttpd_conf],
    stdout=notify_log, stderr=subprocess.STDOUT))

deadline = time.monotonic() + 30
while True:
    try:
        socket.create_connection(("127.0.0.1", int(port)), timeout=1).close()
        break
    except OSError:
        if time.monotonic() > deadline or any(c.poll() is not None for c in children):
            print(json.dumps({"ready": False, "out": (work / "notify.out").read_text(errors="replace")}), flush=True)
            stop()
        time.sleep(0.1)
print(json.dumps({"ready": True}), flush=True)

for line in sys.stdin:
    words = line.split()
    if len(words) == 2 and words[0] in ("on", "off") and words[1].isidentifier():
        target = INOTIFY_DIR / words[1]
        if words[0] == "on":
            target.touch()
        else:
            target.unlink(missing_ok=True)
        print(json.dumps({"done": line.strip()}), flush=True)
    elif words == ["log"]:
        text = "".join(
            f"==> {p} <==\n{p.read_text(errors='replace')}\n"
            for p in LOGS + [work / "notify.out", work / "lighttpd-error.log"] if p.exists())
        print(json.dumps({"log": text}), flush=True)
stop()
