//! The bounds and failure paths of the ONVIF device's Recording, Search and Replay services, from
//! raw HTTP (not evidence of interoperability: `profile_g_test` is): the description asked once
//! and bounded (a description past a bound fails closed and is asked again), live searches, the
//! results a search keeps and hands out per request, the keep-alive cut, requests the device
//! cannot run refused before the model is asked, CreateRecording and DeleteRecording failing
//! closed and bounded, and WS-Security on every new service and on Subscribe. No LLM calls.
use super::bounds_test::{call, subcodes};
use super::real_client_test::{credentials, events, policy, start, POLICY};
use netget::server::onvif::{recording, wire};
use serde_json::{json, Value};
use std::time::Duration;

fn search_token(body: &str) -> String {
    body.split("<tse:SearchToken>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .unwrap_or_else(|| panic!("no search token in {body}"))
        .to_string()
}

fn results(body: &str, tag: &str) -> usize {
    body.matches(&format!("<tt:{tag}>")).count()
}

fn state_of(body: &str) -> String {
    body.split("<tt:SearchState>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .unwrap_or_else(|| panic!("no state in {body}"))
        .to_string()
}

async fn find_events(port: u16, extra: &str) -> (u16, String) {
    call(
        port,
        wire::SEARCH_PATH,
        &format!("<tse:FindEvents><tse:StartPoint>2000-01-01T00:00:00Z</tse:StartPoint><tse:Scope/><tse:SearchFilter/><tse:IncludeStartState>false</tse:IncludeStartState>{extra}</tse:FindEvents>"),
    )
    .await
}

async fn page(port: u16, op: &str, token: &str, max: &str) -> (u16, String) {
    call(
        port,
        wire::SEARCH_PATH,
        &format!("<tse:{op}><tse:SearchToken>{token}</tse:SearchToken>{max}</tse:{op}>"),
    )
    .await
}

/// A handler describing `recordings` recordings of `events` events each, accepting every change.
fn archive(recordings: usize, events: usize) -> Option<Vec<Value>> {
    let code = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
if t=='onvif_describe_recordings':
  R=[{{'token':'r%d'%n,'replay_uri':'rtsp://192.0.2.1/r%d'%n,
      'tracks':[{{'token':'V','type':'Video','from':'2026-10-01T00:00:00Z','to':'2026-10-02T00:00:00Z'}}],
      'events':[{{'time':'2026-10-01T%02d:%02d:%02dZ'%(e//3600,(e//60)%60,e%60),'topic':'tns1:Device/Trigger/DigitalInput','source':{{'InputToken':'i%d'%e}},'data':{{'LogicalState':True}}}} for e in range({events})]}}
     for n in range({recordings})]
  a=[{{'type':'onvif_recordings','recordings':R}}]
else:
  a=[{{'type':'onvif_accept'}}]
print(json.dumps({{'actions':a}}))"#
    );
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn searches_are_bounded_in_number_results_and_lifetime() {
    let per = recording::MAX_ARCHIVE_EVENTS / 4;
    let (state, id, port) = start(archive(4, per), json!({})).await;
    // Every event matches: the search keeps MAX_SEARCH_RESULTS, handed out MAX_RESULTS_PAGE at
    // a time whatever MaxResults asks.
    let (status, body) = find_events(port, "<tse:KeepAliveTime>PT60S</tse:KeepAliveTime>").await;
    assert_eq!(status, 200, "{body}");
    let token = search_token(&body);
    let mut got = 0;
    let mut states = Vec::new();
    loop {
        let (status, body) = page(
            port,
            "GetEventSearchResults",
            &token,
            "<tse:MaxResults>1000</tse:MaxResults>",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let n = results(&body, "Result");
        assert!(n <= recording::MAX_RESULTS_PAGE, "{n}");
        got += n;
        states.push(state_of(&body));
        if states.last().unwrap() == "Completed" {
            break;
        }
    }
    assert_eq!(got, recording::MAX_SEARCH_RESULTS);
    assert_eq!(states, vec!["Searching", "Searching", "Completed"]);
    // MaxMatches cuts it further, and MaxResults 0 is read as 1.
    let (_, body) = find_events(port, "<tse:MaxMatches>3</tse:MaxMatches>").await;
    let small = search_token(&body);
    let (_, body) = page(
        port,
        "GetEventSearchResults",
        &small,
        "<tse:MaxResults>0</tse:MaxResults>",
    )
    .await;
    assert_eq!(
        (results(&body, "Result"), state_of(&body).as_str()),
        (1, "Searching")
    );
    let (_, body) = page(port, "GetEventSearchResults", &small, "").await;
    assert_eq!(
        (results(&body, "Result"), state_of(&body).as_str()),
        (2, "Completed")
    );
    // A token is paged only by its own kind of request.
    let (status, body) = page(port, "GetRecordingSearchResults", &small, "").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(subcodes(&body), vec!["InvalidArgVal", "InvalidToken"]);

    // Live searches: MAX_SEARCHES, then refused; ending one makes room.
    let mut tokens = vec![token, small];
    while tokens.len() < recording::MAX_SEARCHES {
        let (status, body) = call(
            port,
            wire::SEARCH_PATH,
            "<tse:FindRecordings><tse:Scope/><tse:KeepAliveTime>PT60S</tse:KeepAliveTime></tse:FindRecordings>",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        tokens.push(search_token(&body));
    }
    let (status, body) = call(
        port,
        wire::SEARCH_PATH,
        "<tse:FindRecordings><tse:Scope/><tse:KeepAliveTime>PT60S</tse:KeepAliveTime></tse:FindRecordings>",
    )
    .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["Action", "ResourceProblem"], "{body}");
    let (status, body) = call(
        port,
        wire::SEARCH_PATH,
        &format!(
            "<tse:EndSearch><tse:SearchToken>{}</tse:SearchToken></tse:EndSearch>",
            tokens[0]
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = find_events(port, "<tse:KeepAliveTime>PT1H</tse:KeepAliveTime>").await;
    assert_eq!(status, 200, "{body}");
    let long = search_token(&body);
    let device = state
        .server_handle::<netget::server::onvif::Device>(id)
        .await
        .unwrap();
    assert_eq!(device.searches(), recording::MAX_SEARCHES);

    // A KeepAliveTime of an hour is cut to MAX_KEEP_ALIVE: once the device's clock is past it
    // (an accepted SetSystemDateAndTime moves it), every search is gone.
    let ahead = chrono::Utc::now()
        + chrono::Duration::from_std(recording::MAX_KEEP_ALIVE).unwrap()
        + chrono::Duration::seconds(5);
    use chrono::{Datelike, Timelike};
    let (status, body) = call(port, wire::DEVICE_PATH, &format!(
        "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType><tds:DaylightSavings>false</tds:DaylightSavings><tds:UTCDateTime><tt:Date><tt:Year>{}</tt:Year><tt:Month>{}</tt:Month><tt:Day>{}</tt:Day></tt:Date><tt:Time><tt:Hour>{}</tt:Hour><tt:Minute>{}</tt:Minute><tt:Second>{}</tt:Second></tt:Time></tds:UTCDateTime></tds:SetSystemDateAndTime>",
        ahead.year(), ahead.month(), ahead.day(), ahead.hour(), ahead.minute(), ahead.second())).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = page(port, "GetEventSearchResults", &long, "").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(subcodes(&body), vec!["InvalidArgVal", "InvalidToken"]);
    assert_eq!(device.searches(), 0);

    // A KeepAliveTime of a second: gone a moment later.
    let (_, body) = find_events(port, "<tse:KeepAliveTime>PT1S</tse:KeepAliveTime>").await;
    let short = search_token(&body);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (status, _) = page(port, "GetEventSearchResults", &short, "").await;
    assert_eq!(status, 400);
    // All of it from one description.
    assert_eq!(
        events(&state, id, "onvif_describe_recordings").await.len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_description_past_a_bound_fails_closed_and_is_asked_again() {
    for (recordings, per) in [
        (recording::MAX_RECORDINGS + 1, 0),
        (1, recording::MAX_RECORDED_EVENTS + 1),
        (5, recording::MAX_ARCHIVE_EVENTS / 4),
    ] {
        let (state, id, port) = start(archive(recordings, per), json!({})).await;
        for _ in 0..2 {
            let (status, body) = call(port, wire::RECORDING_PATH, "<trc:GetRecordings/>").await;
            assert!(status == 500 || status == 503, "{recordings}x{per}: {body}");
            assert!(
                body.contains("env:Receiver") && subcodes(&body).is_empty(),
                "{body}"
            );
        }
        assert_eq!(
            events(&state, id, "onvif_describe_recordings").await.len(),
            2,
            "{recordings}x{per}"
        );
    }
    // At the bounds it is served.
    let (_, _, port) = start(
        archive(
            recording::MAX_RECORDINGS,
            recording::MAX_ARCHIVE_EVENTS / recording::MAX_RECORDINGS,
        ),
        json!({}),
    )
    .await;
    let (status, body) = call(port, wire::RECORDING_PATH, "<trc:GetRecordings/>").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.matches("<trc:RecordingItem>").count(),
        recording::MAX_RECORDINGS
    );
}

/// The model describes the recordings (as POLICY does) and answers nothing else.
fn describing_recordings_only() -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "onvif_describe_recordings", "handler": {"type": "script", "language": "python", "code": POLICY}}),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_and_delete_fail_closed_and_are_bounded() {
    let (state, id, port) = start(describing_recordings_only(), json!({})).await;
    let create = "<trc:CreateRecording><trc:RecordingConfiguration><tt:Source><tt:SourceId>x</tt:SourceId><tt:Name>X</tt:Name><tt:Location/><tt:Description/><tt:Address/></tt:Source><tt:Content>x</tt:Content><tt:MaximumRetentionTime>PT0S</tt:MaximumRetentionTime></trc:RecordingConfiguration></trc:CreateRecording>";
    let (status, body) = call(port, wire::RECORDING_PATH, create).await;
    assert!(status == 500 || status == 503, "{body}");
    let (status, body) = call(
        port,
        wire::RECORDING_PATH,
        "<trc:DeleteRecording><trc:RecordingToken>rec_door</trc:RecordingToken></trc:DeleteRecording>",
    )
    .await;
    assert!(status == 500 || status == 503, "{body}");
    let (_, body) = call(port, wire::RECORDING_PATH, "<trc:GetRecordings/>").await;
    assert_eq!(body.matches("<trc:RecordingItem>").count(), 2, "{body}");
    assert!(body.contains("rec_door"), "{body}");
    let device = state
        .server_handle::<netget::server::onvif::Device>(id)
        .await
        .unwrap();
    assert_eq!(
        device.recording_tokens(),
        Some(vec!["rec_lobby".to_string(), "rec_door".to_string()])
    );
    // An unknown recording is refused without asking.
    let (status, body) = call(
        port,
        wire::RECORDING_PATH,
        "<trc:DeleteRecording><trc:RecordingToken>rec_nowhere</trc:RecordingToken></trc:DeleteRecording>",
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(subcodes(&body), vec!["InvalidArgVal", "NoRecording"]);
    assert_eq!(events(&state, id, "onvif_delete_recording").await.len(), 1);

    // A full device refuses CreateRecording without asking.
    let (state, id, port) = start(archive(recording::MAX_RECORDINGS, 0), json!({})).await;
    let (status, body) = call(port, wire::RECORDING_PATH, create).await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["Action", "MaxRecordings"], "{body}");
    assert!(events(&state, id, "onvif_create_recording")
        .await
        .is_empty());
    // With room, an accepted create is a new recording with one track of each type.
    let (state, id, port) = start(archive(1, 0), json!({})).await;
    let (status, body) = call(port, wire::RECORDING_PATH, create).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("<trc:RecordingToken>rec_1</trc:RecordingToken>"),
        "{body}"
    );
    assert_eq!(events(&state, id, "onvif_create_recording").await.len(), 1);
    // It has no replay URI: refused, not invented.
    let (status, body) = call(port, wire::REPLAY_PATH, "<trp:GetReplayUri><trp:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trp:StreamSetup><trp:RecordingToken>rec_1</trp:RecordingToken></trp:GetReplayUri>").await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["ActionNotSupported"], "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_the_device_cannot_run_are_refused_before_the_model() {
    let (state, id, port) = start(policy(), json!({})).await;
    let cases: Vec<(&str, String, Vec<&str>)> = vec![
        (wire::SEARCH_PATH, "<tse:FindRecordings><tse:Scope><tt:RecordingInformationFilter>boolean(//Track[TrackType = \"Video\"])</tt:RecordingInformationFilter></tse:Scope><tse:KeepAliveTime>PT10S</tse:KeepAliveTime></tse:FindRecordings>".into(), vec!["InvalidArgVal", "InvalidFilterFragment"]),
        (wire::SEARCH_PATH, format!("<tse:FindRecordings><tse:Scope>{}</tse:Scope><tse:KeepAliveTime>PT10S</tse:KeepAliveTime></tse:FindRecordings>", "<tt:IncludedRecordings>r</tt:IncludedRecordings>".repeat(recording::MAX_SCOPE_ITEMS + 1)), vec!["InvalidArgVal"]),
        (wire::SEARCH_PATH, "<tse:FindEvents><tse:Scope/><tse:KeepAliveTime>PT10S</tse:KeepAliveTime></tse:FindEvents>".into(), vec!["InvalidArgVal"]),
        (wire::SEARCH_PATH, "<tse:FindEvents><tse:StartPoint>yesterday</tse:StartPoint><tse:Scope/></tse:FindEvents>".into(), vec!["InvalidArgVal"]),
        (wire::SEARCH_PATH, "<tse:FindEvents><tse:StartPoint>2026-10-24T00:00:00Z</tse:StartPoint><tse:Scope/><tse:SearchFilter><wsnt:MessageContent Dialect=\"http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter\">boolean(//x)</wsnt:MessageContent></tse:SearchFilter></tse:FindEvents>".into(), vec!["InvalidArgVal"]),
        (wire::SEARCH_PATH, "<tse:FindEvents><tse:StartPoint>2026-10-24T00:00:00Z</tse:StartPoint><tse:Scope/><tse:KeepAliveTime>P2Y</tse:KeepAliveTime></tse:FindEvents>".into(), vec!["InvalidArgVal"]),
        (wire::REPLAY_PATH, "<trp:GetReplayUri><trp:StreamSetup><tt:Stream>RTP-Bogus</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trp:StreamSetup><trp:RecordingToken>rec_lobby</trp:RecordingToken></trp:GetReplayUri>".into(), vec!["InvalidArgVal", "InvalidStreamSetup"]),
        (wire::RECORDING_PATH, format!("<trc:CreateRecording><trc:RecordingConfiguration><tt:Source><tt:SourceId>{}</tt:SourceId></tt:Source><tt:Content>x</tt:Content></trc:RecordingConfiguration></trc:CreateRecording>", "x".repeat(recording::MAX_TEXT + 1)), vec!["InvalidArgVal"]),
        (wire::SEARCH_PATH, "<tse:GetEventSearchResults><tse:SearchToken>search_nowhere</tse:SearchToken></tse:GetEventSearchResults>".into(), vec!["InvalidArgVal", "InvalidToken"]),
        (wire::SEARCH_PATH, "<tse:EndSearch><tse:SearchToken>search_nowhere</tse:SearchToken></tse:EndSearch>".into(), vec!["InvalidArgVal", "InvalidToken"]),
    ];
    for (path, body, want) in cases {
        let (status, text) = call(port, path, &body).await;
        assert_eq!(status, 400, "{body}: {text}");
        assert_eq!(subcodes(&text), want, "{body}: {text}");
    }
    // None of it needed the recordings, so the model was never asked to describe them.
    assert!(events(&state, id, "onvif_describe_recordings")
        .await
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_profile_g_service_and_subscribe_need_a_digest() {
    let (state, id, port) = start(policy(), credentials()).await;
    let cases = [
        (wire::RECORDING_PATH, "<trc:GetRecordings/>"),
        (wire::RECORDING_PATH, "<trc:GetServiceCapabilities/>"),
        (wire::RECORDING_PATH, "<trc:DeleteRecording><trc:RecordingToken>rec_door</trc:RecordingToken></trc:DeleteRecording>"),
        (wire::RECORDING_PATH, "<trc:CreateRecording><trc:RecordingConfiguration><tt:Source/><tt:Content/></trc:RecordingConfiguration></trc:CreateRecording>"),
        (wire::SEARCH_PATH, "<tse:GetRecordingSummary/>"),
        (wire::SEARCH_PATH, "<tse:FindRecordings><tse:Scope/><tse:KeepAliveTime>PT10S</tse:KeepAliveTime></tse:FindRecordings>"),
        (wire::SEARCH_PATH, "<tse:GetEventSearchResults><tse:SearchToken>x</tse:SearchToken></tse:GetEventSearchResults>"),
        (wire::REPLAY_PATH, "<trp:GetReplayUri><trp:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream></trp:StreamSetup><trp:RecordingToken>rec_lobby</trp:RecordingToken></trp:GetReplayUri>"),
        (wire::REPLAY_PATH, "<trp:GetReplayConfiguration/>"),
        (wire::EVENTS_PATH, "<wsnt:Subscribe><wsnt:ConsumerReference><wsa:Address>http://127.0.0.1:9/c</wsa:Address></wsnt:ConsumerReference></wsnt:Subscribe>"),
    ];
    for (path, body) in cases {
        let (status, text) = call(port, path, body).await;
        assert_eq!(status, 400, "{body}: {text}");
        assert_eq!(subcodes(&text), vec!["NotAuthorized"], "{body}: {text}");
    }
    assert!(state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None
        )
        .await
        .iter()
        .all(|e| e.event_type == "onvif_not_authorized"));
}
