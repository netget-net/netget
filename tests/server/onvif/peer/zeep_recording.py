"""Recording, Search and Replay (ONVIF Profile G) through python onvif-zeep-async (zeep over the
recording, search and replay WSDLs it bundles). It connects as Home Assistant does, finds the
three services through GetServices, then:

- Recording: the service capabilities; GetRecordings; GetRecordingConfiguration of one
  recording; GetRecordingJobs; CreateRecording, GetRecordings with it, DeleteRecording and its
  configuration refused after; a CreateRecording and a DeleteRecording the device refuses.
- Search: the capabilities; GetRecordingSummary; GetRecordingInformation; FindRecordings paged
  one result at a time (Searching, then Completed) and ended; a FindRecordings narrowed to one
  recording; FindEvents over a time range with a topic filter, paged; FindEvents backwards;
  FindEvents with IncludeStartState; GetSearchState; EndSearch and a page of the ended search
  refused.
- Replay: the capabilities; GetReplayUri; GetReplayConfiguration; a replay of a recording the
  device does not have refused.

Prints one JSON object as its last line. Usage: python zeep_recording.py host port username password
"""
import asyncio
import datetime as dt
import json
import sys

import onvif
import zeep.exceptions
from lxml import etree

CONCRETE_SET = "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet"
WSNT = "http://docs.oasis-open.org/wsn/b-2"
TNS1 = "http://www.onvif.org/ver10/topics"


def fault(err):
    return {"fault": str(err.message), "subcodes": [q.localname for q in (err.subcodes or [])]}


def iso(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t is not None else None


def topic_filter(expression):
    """A SearchFilter (wsnt:FilterType, xs:any content) holding one TopicExpression."""
    el = etree.Element(f"{{{WSNT}}}TopicExpression", nsmap={"wsnt": WSNT, "tns1": TNS1})
    el.set("Dialect", CONCRETE_SET)
    el.text = expression
    return {"_value_1": [el]}


def information(r):
    return {
        "token": r.RecordingToken,
        "source_id": r.Source.SourceId,
        "name": r.Source.Name,
        "earliest": iso(r.EarliestRecording),
        "latest": iso(r.LatestRecording),
        "content": r.Content,
        "tracks": [{"token": t.TrackToken, "type": str(t.TrackType), "from": iso(t.DataFrom), "to": iso(t.DataTo)} for t in r.Track],
        "status": str(r.RecordingStatus),
    }


def event_results(r):
    out = []
    for x in r.Result or []:
        msg = x.Event.Message._value_1
        items = lambda part: {i.Name: i.Value for i in (part.SimpleItem if part is not None else [])}
        out.append({
            "recording": x.RecordingToken,
            "track": x.TrackToken,
            "time": iso(x.Time),
            "topic": x.Event.Topic._value_1.strip(),
            "message_time": iso(msg.UtcTime),
            "source": items(msg.Source),
            "data": items(msg.Data),
            "start_state": x.StartStateEvent,
        })
    return {"state": str(r.SearchState), "results": out}


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

    # ---- Recording -------------------------------------------------------------------------
    rec = await cam.create_recording_service()
    await call("recording_capabilities", rec.GetServiceCapabilities(), lambda r: {
        "dynamic_recordings": r.DynamicRecordings, "max_recordings": r.MaxRecordings, "max_jobs": r.MaxRecordingJobs})
    recordings = lambda r: [{
        "token": i.RecordingToken, "source_id": i.Configuration.Source.SourceId, "content": i.Configuration.Content,
        "retention": str(i.Configuration.MaximumRetentionTime),
        "tracks": [{"token": t.TrackToken, "type": str(t.Configuration.TrackType)} for t in (i.Tracks.Track or [])]} for i in r]
    await call("recordings", rec.GetRecordings(), recordings)
    await call("configuration", rec.GetRecordingConfiguration({"RecordingToken": "rec_door"}), lambda c: {
        "source_id": c.Source.SourceId, "name": c.Source.Name, "content": c.Content, "retention": str(c.MaximumRetentionTime)})
    await call("jobs", rec.GetRecordingJobs(), lambda r: [{
        "token": j.JobToken, "recording": j.JobConfiguration.RecordingToken, "mode": j.JobConfiguration.Mode,
        "priority": j.JobConfiguration.Priority,
        "source": [s.SourceToken.Token for s in (j.JobConfiguration.Source or [])]} for j in r])
    new = lambda content: {"RecordingConfiguration": {
        "Source": {"SourceId": "annex_cam", "Name": "Annex", "Location": "Annex", "Description": "Annex camera", "Address": "http://192.0.2.50/onvif/device_service"},
        "Content": content, "MaximumRetentionTime": dt.timedelta(days=7)}}
    created = await call("create", rec.CreateRecording(new("Annex, on motion")), str)
    await call("recordings_after_create", rec.GetRecordings(), recordings)
    if isinstance(created, str):
        await call("delete", rec.DeleteRecording({"RecordingToken": created}), lambda r: "ok")
        await call("configuration_deleted", rec.GetRecordingConfiguration({"RecordingToken": created}), lambda c: "found")
    await call("create_refused", rec.CreateRecording(new("forbidden archive")), str)
    await call("delete_refused", rec.DeleteRecording({"RecordingToken": "rec_lobby"}), lambda r: "ok")
    await call("recordings_after", rec.GetRecordings(), lambda r: [i.RecordingToken for i in r])

    # ---- Search ----------------------------------------------------------------------------
    search = await cam.create_search_service()
    await call("search_capabilities", search.GetServiceCapabilities(), lambda r: {"metadata_search": r.MetadataSearch})
    await call("summary", search.GetRecordingSummary(), lambda s: {
        "from": iso(s.DataFrom), "until": iso(s.DataUntil), "count": s.NumberRecordings})
    await call("information", search.GetRecordingInformation({"RecordingToken": "rec_lobby"}), information)
    await call("information_missing", search.GetRecordingInformation({"RecordingToken": "rec_nowhere"}), information)
    token = await call("find_recordings", search.FindRecordings({"Scope": {}, "MaxMatches": 10, "KeepAliveTime": dt.timedelta(seconds=30)}), str)
    page = lambda r: {"state": str(r.SearchState), "tokens": [i.RecordingToken for i in (r.RecordingInformation or [])]}
    await call("recording_page_1", search.GetRecordingSearchResults({"SearchToken": token, "MaxResults": 1}), page)
    await call("recording_page_2", search.GetRecordingSearchResults({"SearchToken": token, "MaxResults": 1}), page)
    await call("end_recordings", search.EndSearch({"SearchToken": token}), iso)
    token = await call("find_door", search.FindRecordings({"Scope": {"IncludedRecordings": ["rec_door"]}, "KeepAliveTime": dt.timedelta(seconds=30)}), str)
    await call("door_page", search.GetRecordingSearchResults({"SearchToken": token}),
               lambda r: {"state": str(r.SearchState), "recordings": [information(i) for i in (r.RecordingInformation or [])]})
    await call("end_door", search.EndSearch({"SearchToken": token}), iso)

    day = lambda h, m: dt.datetime(2026, 10, 24, h, m, tzinfo=dt.timezone.utc)
    events = {"StartPoint": day(0, 0), "EndPoint": day(23, 0), "Scope": {"IncludedRecordings": ["rec_lobby"]},
              "SearchFilter": topic_filter("tns1:VideoSource/MotionAlarm"), "IncludeStartState": False,
              "MaxMatches": 50, "KeepAliveTime": dt.timedelta(seconds=30)}
    token = await call("find_events", search.FindEvents(events), str)
    await call("event_state", search.GetSearchState({"SearchToken": token}), str)
    await call("event_page_1", search.GetEventSearchResults({"SearchToken": token, "MaxResults": 2}), event_results)
    await call("event_page_2", search.GetEventSearchResults({"SearchToken": token, "MaxResults": 2}), event_results)
    await call("end_events", search.EndSearch({"SearchToken": token}), iso)
    await call("ended_page", search.GetEventSearchResults({"SearchToken": token}), event_results)
    backwards = dict(events, StartPoint=day(23, 0), EndPoint=day(8, 16), SearchFilter={})
    token = await call("find_backwards", search.FindEvents(backwards), str)
    await call("backwards_page", search.GetEventSearchResults({"SearchToken": token}), event_results)
    await call("end_backwards", search.EndSearch({"SearchToken": token}), iso)
    start_state = dict(events, StartPoint=day(10, 0), EndPoint=day(13, 0), SearchFilter={}, IncludeStartState=True)
    token = await call("find_start_state", search.FindEvents(start_state), str)
    await call("start_state_page", search.GetEventSearchResults({"SearchToken": token}), event_results)
    await call("end_start_state", search.EndSearch({"SearchToken": token}), iso)

    # ---- Replay ----------------------------------------------------------------------------
    replay = await cam.create_replay_service()
    await call("replay_capabilities", replay.GetServiceCapabilities(), lambda r: {
        "reverse": r.ReversePlayback, "rtsp_tcp": r.RTP_RTSP_TCP, "session_timeout_range": [float(x) for x in (r.SessionTimeoutRange or [])]})
    setup = {"Stream": "RTP-Unicast", "Transport": {"Protocol": "RTSP"}}
    await call("replay_uri", replay.GetReplayUri({"StreamSetup": setup, "RecordingToken": "rec_lobby"}), str)
    await call("replay_configuration", replay.GetReplayConfiguration(), lambda c: str(c.SessionTimeout))
    await call("replay_missing", replay.GetReplayUri({"StreamSetup": setup, "RecordingToken": "rec_nowhere"}), str)
    await cam.close()
    print(json.dumps(out, default=str), flush=True)


asyncio.run(main(*sys.argv[1:5]))
