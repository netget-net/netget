//! NetGet's ONVIF device as a Profile G device — Recording, Search and Replay — against two
//! independent ONVIF clients, each run as a subprocess:
//!
//! - **python onvif-zeep-async** 4.3.0 (zeep over the recording, search and replay WSDLs it
//!   bundles) through `peer/zeep_recording.py`;
//! - **Go github.com/videonext/onvif** (gowsdl-generated from ONVIF's WSDLs, encoding/xml,
//!   pinned in `peer/go-profile-g/go.sum`) through `peer/go-profile-g`.
//!
//! The model (`real_client_test::POLICY`) describes two recordings and a job once; every read,
//! search and replay URI after that is answered from the description, and the tests assert the
//! model was asked exactly once. CreateRecording and DeleteRecording are the model's decisions.
//! Each test prints the operations its client sent. The tests fail, not skip, without the
//! clients: `python3 tests/server/onvif/install_peers.py <dir>`. No LLM calls.
use super::real_client_test::{credentials, env, events, policy, start_logged, PASSWORD, USER};
use super::services_test::{run_streaming, sent};
use serde_json::{json, Value};

fn event(rec: &str, track: &str, time: &str, topic: &str, source: Value, data: Value) -> Value {
    json!({"recording": rec, "track": track, "time": time, "topic": topic, "source": source, "data": data})
}

/// An event search result as the zeep peer reports it, without the fields it repeats.
fn zeep_event(r: &Value) -> Value {
    event(
        r["recording"].as_str().unwrap_or_default(),
        r["track"].as_str().unwrap_or_default(),
        r["time"].as_str().unwrap_or_default(),
        r["topic"].as_str().unwrap_or_default(),
        r["source"].clone(),
        r["data"].clone(),
    )
}

fn motion(rec: &str, time: &str, source: &str, state: &str) -> Value {
    event(
        rec,
        "VIDEO001",
        time,
        "tns1:VideoSource/MotionAlarm",
        json!({"Source": source}),
        json!({"State": state}),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn onvif_zeep_async_reads_searches_and_replays_what_the_model_described() {
    let (state, id, port, log) = start_logged(policy(), credentials()).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/onvif/peer/zeep_recording.py"
    );
    let r = run_streaming(
        &env("NETGET_ONVIF_PYTHON"),
        &[
            "-I".into(),
            script.into(),
            "127.0.0.1".into(),
            port.to_string(),
            USER.into(),
            PASSWORD.into(),
        ],
        |_| Box::pin(async {}),
    )
    .await;
    sent(
        "onvif-zeep-async",
        &log,
        &[
            "device:GetServices",
            "recording:GetServiceCapabilities",
            "recording:GetRecordings",
            "recording:GetRecordingConfiguration",
            "recording:GetRecordingJobs",
            "recording:CreateRecording",
            "recording:DeleteRecording",
            "search:GetServiceCapabilities",
            "search:GetRecordingSummary",
            "search:GetRecordingInformation",
            "search:FindRecordings",
            "search:GetRecordingSearchResults",
            "search:FindEvents",
            "search:GetEventSearchResults",
            "search:GetSearchState",
            "search:EndSearch",
            "replay:GetServiceCapabilities",
            "replay:GetReplayUri",
            "replay:GetReplayConfiguration",
        ],
    );
    for (ns, path) in [
        (
            "http://www.onvif.org/ver10/recording/wsdl",
            "/onvif/recording_service",
        ),
        (
            "http://www.onvif.org/ver10/search/wsdl",
            "/onvif/search_service",
        ),
        (
            "http://www.onvif.org/ver10/replay/wsdl",
            "/onvif/replay_service",
        ),
    ] {
        assert_eq!(
            r["xaddrs"][ns],
            format!("http://127.0.0.1:{port}{path}"),
            "{r}"
        );
    }

    // ---- Recording ----
    assert_eq!(
        r["recording_capabilities"]["dynamic_recordings"], true,
        "{r}"
    );
    assert_eq!(r["recording_capabilities"]["max_recordings"], 32.0, "{r}");
    assert_eq!(
        r["recordings"],
        json!([
            {"token": "rec_lobby", "source_id": "lobby_cam", "content": "Continuous recording of the lobby",
             "retention": "7 days, 0:00:00",
             "tracks": [{"token": "VIDEO001", "type": "Video"}, {"token": "AUDIO001", "type": "Audio"}]},
            {"token": "rec_door", "source_id": "door_cam", "content": "Motion-triggered recording of the door",
             "retention": "0:00:00", "tracks": [{"token": "VIDEO001", "type": "Video"}]}
        ]),
        "{r}"
    );
    assert_eq!(
        r["configuration"],
        json!({"source_id": "door_cam", "name": "Door", "content": "Motion-triggered recording of the door", "retention": "0:00:00"}),
        "{r}"
    );
    assert_eq!(
        r["jobs"],
        json!([{"token": "job_lobby", "recording": "rec_lobby", "mode": "Active", "priority": 1, "source": ["main"]}]),
        "{r}"
    );
    assert_eq!(r["create"], "rec_1", "{r}");
    let created = r["recordings_after_create"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["token"] == "rec_1"))
        .cloned()
        .unwrap_or_else(|| panic!("{r}"));
    assert_eq!(created["source_id"], "annex_cam", "{r}");
    assert_eq!(created["content"], "Annex, on motion", "{r}");
    assert_eq!(created["retention"], "7 days, 0:00:00", "{r}");
    assert_eq!(
        created["tracks"],
        json!([{"token": "VIDEO001", "type": "Video"}, {"token": "AUDIO001", "type": "Audio"}, {"token": "META001", "type": "Metadata"}]),
        "{r}"
    );
    assert_eq!(r["delete"], "ok", "{r}");
    assert_eq!(
        r["configuration_deleted"]["subcodes"],
        json!(["InvalidArgVal", "NoRecording"]),
        "{r}"
    );
    assert_eq!(
        r["create_refused"]["subcodes"],
        json!(["OperationProhibited"]),
        "{r}"
    );
    assert_eq!(
        r["delete_refused"]["subcodes"],
        json!(["OperationProhibited"]),
        "{r}"
    );
    assert_eq!(
        r["recordings_after"],
        json!(["rec_lobby", "rec_door"]),
        "{r}"
    );
    let asked = events(&state, id, "onvif_create_recording").await;
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[0]["source"]["source_id"], "annex_cam", "{asked:?}");
    assert_eq!(asked[0]["maximum_retention_secs"], 604_800, "{asked:?}");
    let asked = events(&state, id, "onvif_delete_recording").await;
    assert_eq!(
        asked
            .iter()
            .map(|e| e["recording_token"].clone())
            .collect::<Vec<_>>(),
        vec![json!("rec_1"), json!("rec_lobby")]
    );

    // ---- Search ----
    assert_eq!(r["search_capabilities"]["metadata_search"], false, "{r}");
    assert_eq!(
        r["summary"],
        json!({"from": "2026-10-23T00:00:00Z", "until": "2026-10-25T00:00:00Z", "count": 2}),
        "{r}"
    );
    assert_eq!(
        r["information"],
        json!({"token": "rec_lobby", "source_id": "lobby_cam", "name": "Lobby",
               "earliest": "2026-10-24T00:00:00Z", "latest": "2026-10-25T00:00:00Z",
               "content": "Continuous recording of the lobby",
               "tracks": [{"token": "VIDEO001", "type": "Video", "from": "2026-10-24T00:00:00Z", "to": "2026-10-25T00:00:00Z"},
                          {"token": "AUDIO001", "type": "Audio", "from": "2026-10-24T00:00:00Z", "to": "2026-10-25T00:00:00Z"}],
               "status": "Recording"}),
        "{r}"
    );
    assert_eq!(
        r["information_missing"]["subcodes"],
        json!(["InvalidArgVal", "NoRecording"]),
        "{r}"
    );
    assert_eq!(
        r["recording_page_1"],
        json!({"state": "Searching", "tokens": ["rec_lobby"]}),
        "{r}"
    );
    assert_eq!(
        r["recording_page_2"],
        json!({"state": "Completed", "tokens": ["rec_door"]}),
        "{r}"
    );
    assert_eq!(r["door_page"]["state"], "Completed", "{r}");
    assert_eq!(r["door_page"]["recordings"][0]["status"], "Stopped", "{r}");
    assert_eq!(
        r["door_page"]["recordings"].as_array().map(Vec::len),
        Some(1),
        "{r}"
    );
    // A day of the lobby, motion only, two at a time: Searching, then Completed.
    assert_eq!(r["event_state"], "Searching", "{r}");
    assert_eq!(r["event_page_1"]["state"], "Searching", "{r}");
    assert_eq!(
        r["event_page_1"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(zeep_event)
            .collect::<Vec<_>>(),
        vec![
            motion("rec_lobby", "2026-10-24T08:15:00Z", "lobby_cam", "true"),
            motion("rec_lobby", "2026-10-24T08:16:30Z", "lobby_cam", "false")
        ],
        "{r}"
    );
    assert_eq!(r["event_page_2"]["state"], "Completed", "{r}");
    assert_eq!(
        r["event_page_2"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(zeep_event)
            .collect::<Vec<_>>(),
        vec![motion(
            "rec_lobby",
            "2026-10-24T20:45:00Z",
            "lobby_cam",
            "true"
        )],
        "{r}"
    );
    assert!(
        r["event_page_1"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["message_time"] == e["time"] && e["start_state"] == false),
        "{r}"
    );
    assert_eq!(r["end_events"], "2026-10-24T23:00:00Z", "{r}");
    assert_eq!(
        r["ended_page"]["subcodes"],
        json!(["InvalidArgVal", "InvalidToken"]),
        "{r}"
    );
    // Backwards (EndPoint before StartPoint), every topic: newest first.
    assert_eq!(
        r["backwards_page"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["time"].clone())
            .collect::<Vec<_>>(),
        vec![
            json!("2026-10-24T20:45:00Z"),
            json!("2026-10-24T12:00:00Z"),
            json!("2026-10-24T08:16:30Z")
        ],
        "{r}"
    );
    // IncludeStartState: the motion alarm's value at 10:00 (off since 08:16:30), then the door.
    let start = r["start_state_page"]["results"].as_array().unwrap();
    assert_eq!(start.len(), 2, "{r}");
    assert_eq!(start[0]["start_state"], true, "{r}");
    assert_eq!(start[0]["time"], "2026-10-24T10:00:00Z", "{r}");
    assert_eq!(start[0]["topic"], "tns1:VideoSource/MotionAlarm", "{r}");
    assert_eq!(start[0]["data"], json!({"State": "false"}), "{r}");
    assert_eq!(start[1]["start_state"], false, "{r}");
    assert_eq!(start[1]["topic"], "tns1:Device/Trigger/DigitalInput", "{r}");
    assert_eq!(
        start[1]["source"],
        json!({"InputToken": "door_contact"}),
        "{r}"
    );

    // ---- Replay ----
    assert_eq!(
        r["replay_capabilities"],
        json!({"reverse": false, "rtsp_tcp": true, "session_timeout_range": [60.0, 60.0]}),
        "{r}"
    );
    assert_eq!(
        r["replay_uri"], "rtsp://192.0.2.42:554/replay/rec_lobby",
        "{r}"
    );
    assert_eq!(r["replay_configuration"], "0:01:00", "{r}");
    assert_eq!(
        r["replay_missing"]["subcodes"],
        json!(["InvalidArgVal", "NoRecording"]),
        "{r}"
    );

    // The recordings were described once; nothing else about them reached the model.
    assert_eq!(
        events(&state, id, "onvif_describe_recordings").await.len(),
        1
    );
    assert!(events(&state, id, "onvif_not_authorized").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn videonext_onvif_reads_searches_and_replays_what_the_model_described() {
    // The library's own digest is computed over the nonce's base64 text, so a device that
    // checks digests refuses it: first that, then the whole sequence against a device without
    // credentials.
    let (state, id, port, _) = start_logged(policy(), credentials()).await;
    let r = run_streaming(
        &env("NETGET_ONVIF_GO_PROFILE_G"),
        &[format!("127.0.0.1:{port}"), USER.into(), PASSWORD.into()],
        |_| Box::pin(async {}),
    )
    .await;
    assert_eq!(
        r["signed_get_recordings"]["fault"], "env:Sender/ter:NotAuthorized",
        "{r}"
    );
    let refused = events(&state, id, "onvif_not_authorized").await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["reason"], "bad_digest", "{refused:?}");
    assert!(events(&state, id, "onvif_describe_recordings")
        .await
        .is_empty());

    let (state, id, port, log) = start_logged(policy(), json!({})).await;
    let r = run_streaming(
        &env("NETGET_ONVIF_GO_PROFILE_G"),
        &[format!("127.0.0.1:{port}")],
        |_| Box::pin(async {}),
    )
    .await;
    sent(
        "videonext/onvif",
        &log,
        &[
            "device:GetServices",
            "recording:GetServiceCapabilities",
            "recording:GetRecordings",
            "recording:GetRecordingConfiguration",
            "recording:GetRecordingJobs",
            "recording:CreateRecording",
            "recording:DeleteRecording",
            "search:GetRecordingSummary",
            "search:GetRecordingInformation",
            "search:FindRecordings",
            "search:GetRecordingSearchResults",
            "search:EndSearch",
            "search:FindEvents",
            "search:GetSearchState",
            "search:GetEventSearchResults",
            "replay:GetServiceCapabilities",
            "replay:GetReplayUri",
            "replay:GetReplayConfiguration",
        ],
    );
    assert_eq!(
        r["xaddrs"]["http://www.onvif.org/ver10/search/wsdl"],
        format!("http://127.0.0.1:{port}/onvif/search_service"),
        "{r}"
    );
    assert_eq!(
        r["recording_capabilities"]["value"]["MaxRecordings"], "32",
        "{r}"
    );
    assert_eq!(
        r["recordings"]["value"],
        json!([
            {"token": "rec_lobby", "source_id": "lobby_cam", "content": "Continuous recording of the lobby",
             "retention": "PT604800S", "tracks": ["VIDEO001:Video", "AUDIO001:Audio"]},
            {"token": "rec_door", "source_id": "door_cam", "content": "Motion-triggered recording of the door",
             "retention": "PT0S", "tracks": ["VIDEO001:Video"]}
        ]),
        "{r}"
    );
    assert_eq!(
        r["configuration"]["value"],
        json!({"source_id": "door_cam", "name": "Door", "content": "Motion-triggered recording of the door"}),
        "{r}"
    );
    assert_eq!(
        r["jobs"]["value"],
        json!([{"token": "job_lobby", "recording": "rec_lobby", "mode": "Active"}]),
        "{r}"
    );
    assert_eq!(r["create"]["value"], "rec_1", "{r}");
    assert!(r["delete"].get("error").is_none(), "{r}");
    assert_eq!(
        r["delete_refused"]["fault"], "env:Sender/ter:OperationProhibited",
        "{r}"
    );
    let asked = events(&state, id, "onvif_create_recording").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["source"]["source_id"], "gate_cam", "{asked:?}");
    assert_eq!(asked[0]["maximum_retention_secs"], 86_400, "{asked:?}");

    assert_eq!(
        r["summary"]["value"],
        json!({"from": "2026-10-23T00:00:00Z", "until": "2026-10-25T00:00:00Z", "count": 2}),
        "{r}"
    );
    let info = &r["information"]["value"];
    assert_eq!(info["source_id"], "door_cam", "{r}");
    assert_eq!(info["earliest"], "2026-10-23T00:00:00Z", "{r}");
    assert_eq!(info["latest"], "2026-10-24T06:00:00Z", "{r}");
    assert_eq!(info["status"], "Stopped", "{r}");
    assert_eq!(
        info["tracks"],
        json!(["VIDEO001 2026-10-23T00:00:00Z 2026-10-24T06:00:00Z"]),
        "{r}"
    );
    assert!(
        r["find_recordings"]["value"]
            .as_str()
            .is_some_and(|t| t.starts_with("search_")),
        "{r}"
    );
    assert_eq!(
        r["recording_pages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| json!({"state": p["state"], "recordings": p["recordings"]}))
            .collect::<Vec<_>>(),
        vec![
            json!({"state": "Searching", "recordings": ["rec_lobby:Recording"]}),
            json!({"state": "Completed", "recordings": ["rec_door:Stopped"]})
        ],
        "{r}"
    );
    assert!(r["end_recordings"]["value"].is_string(), "{r}");
    assert_eq!(r["search_state"]["value"], "Searching", "{r}");
    // Both recordings, from the 23rd to 09:00 on the 24th, oldest first.
    assert_eq!(r["events"]["value"]["state"], "Completed", "{r}");
    let got: Vec<Value> = r["events"]["value"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(zeep_event)
        .collect();
    assert_eq!(
        got,
        vec![
            motion("rec_door", "2026-10-23T22:10:00Z", "door_cam", "true"),
            motion("rec_lobby", "2026-10-24T08:15:00Z", "lobby_cam", "true"),
            motion("rec_lobby", "2026-10-24T08:16:30Z", "lobby_cam", "false")
        ],
        "{r}"
    );
    assert_eq!(r["end_events"]["value"], "2026-10-24T09:00:00Z", "{r}");
    assert_eq!(
        r["ended_events"]["fault"], "env:Sender/ter:InvalidArgVal/ter:InvalidToken",
        "{r}"
    );
    assert_eq!(
        r["replay_capabilities"]["value"]["RTP_RTSP_TCP"], "true",
        "{r}"
    );
    assert_eq!(
        r["replay_uri"]["value"], "rtsp://192.0.2.42:554/replay/rec_door",
        "{r}"
    );
    assert_eq!(r["replay_configuration"]["value"], "PT60S", "{r}");
    assert_eq!(
        r["replay_missing"]["fault"], "env:Sender/ter:InvalidArgVal/ter:NoRecording",
        "{r}"
    );
    assert_eq!(
        events(&state, id, "onvif_describe_recordings").await.len(),
        1
    );
}
