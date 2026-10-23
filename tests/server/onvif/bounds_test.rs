//! The ONVIF device's own bounds and failure paths on the services beyond Device and Media,
//! from raw HTTP (not evidence of interoperability — `services_test` is): the subscription cap,
//! a subscription's lifetime and queue, PullMessages' Timeout and MessageLimit bounds, the
//! preset cap and name bound; a model that fails a PTZ move, a Set* or a subscription failing
//! closed and changing nothing; a model answer outside the generic space refused; WS-Security
//! required on every new service. No LLM calls: events without a handler go to an unreachable
//! model and fail.
use super::real_client_test::{credentials, policy, start, PASSWORD, USER};
use netget::llm::actions::protocol_trait::Server;
use netget::server::onvif::actions::OnvifProtocol;
use netget::server::onvif::{events, ptz, wire, Device};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap()
}

async fn post(port: u16, path: &str, envelope: String) -> (u16, String) {
    let r = http()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .header("Content-Type", "application/soap+xml; charset=utf-8")
        .body(envelope)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap_or_default())
}

/// An unsigned request (the device under test is open unless the test configured credentials).
async fn call(port: u16, path: &str, body: &str) -> (u16, String) {
    post(port, path, wire::request_envelope(None, body)).await
}

fn subcodes(body: &str) -> Vec<String> {
    body.split("<env:Value>ter:")
        .skip(1)
        .filter_map(|s| s.split('<').next())
        .map(str::to_string)
        .collect()
}

async fn subscribe(port: u16, termination: &str) -> (u16, String) {
    call(
        port,
        wire::EVENTS_PATH,
        &format!("<tev:CreatePullPointSubscription><tev:InitialTerminationTime>{termination}</tev:InitialTerminationTime></tev:CreatePullPointSubscription>"),
    )
    .await
}

/// The path of the subscription a CreatePullPointSubscriptionResponse names.
fn address(body: &str) -> String {
    let start = body
        .find(wire::SUBSCRIPTION_PREFIX)
        .unwrap_or_else(|| panic!("no subscription address in {body}"));
    let end = body[start..].find('<').unwrap() + start;
    body[start..end].to_string()
}

async fn pull(port: u16, path: &str, timeout: &str, limit: u32) -> (u16, String) {
    call(
        port,
        path,
        &format!("<tev:PullMessages><tev:Timeout>{timeout}</tev:Timeout><tev:MessageLimit>{limit}</tev:MessageLimit></tev:PullMessages>"),
    )
    .await
}

async fn raise(state: &AppState, id: ServerId, input: &str) {
    OnvifProtocol
        .execute_action_with_state(
            json!({"type": "onvif_raise_event", "topic": "tns1:Device/Trigger/DigitalInput",
                   "source": {"InputToken": input}, "data": {"LogicalState": true}}),
            state.clone(),
            Some(id),
        )
        .await
        .unwrap();
}

async fn device(state: &AppState, id: ServerId) -> std::sync::Arc<Device> {
    state.server_handle::<Device>(id).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscriptions_are_bounded_in_number_lifetime_and_queue() {
    let (state, id, port) = start(policy(), json!({"max_pull_timeout_secs": 1})).await;
    let mut paths = Vec::new();
    for _ in 0..events::MAX_SUBSCRIPTIONS {
        let (status, body) = subscribe(port, "PT60S").await;
        assert_eq!(status, 200, "{body}");
        paths.push(address(&body));
    }
    // One past the cap: refused, and nothing created.
    let (status, body) = subscribe(port, "PT60S").await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["Action"], "{body}");
    assert!(body.contains("SubscribeCreationFailedFault"), "{body}");
    assert_eq!(
        device(&state, id).await.subscriptions(),
        events::MAX_SUBSCRIPTIONS
    );
    // Ending one makes room.
    let (status, body) = call(port, &paths[0], "<wsnt:Unsubscribe/>").await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = subscribe(port, "PT60S").await;
    assert_eq!(status, 200, "{body}");
    paths[0] = address(&body);

    // Drain what the model raised on each subscription (its answer raises a MotionAlarm).
    for p in &paths {
        pull(port, p, "PT0S", 100).await;
    }
    // A Timeout of an hour is cut to max_pull_timeout_secs (1): an empty pull waits that long
    // and answers with nothing.
    let started = Instant::now();
    let (status, body) = pull(port, &paths[1], "PT1H", 10).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.matches("<wsnt:NotificationMessage>").count(),
        0,
        "{body}"
    );
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(5),
        "{waited:?}"
    );

    // MessageLimit: 2 of 5 queued, then the next 3; 0 is read as 1.
    for i in 0..5 {
        raise(&state, id, &format!("in{i}")).await;
    }
    let (_, body) = pull(port, &paths[1], "PT1S", 2).await;
    assert_eq!(
        body.matches("<wsnt:NotificationMessage>").count(),
        2,
        "{body}"
    );
    let (_, body) = pull(port, &paths[1], "PT1S", 0).await;
    assert_eq!(
        body.matches("<wsnt:NotificationMessage>").count(),
        1,
        "{body}"
    );
    let (_, body) = pull(port, &paths[1], "PT1S", 1000).await;
    assert_eq!(
        body.matches("<wsnt:NotificationMessage>").count(),
        2,
        "{body}"
    );

    // The queue keeps the newest MAX_QUEUED; the oldest are dropped.
    for i in 0..events::MAX_QUEUED + 10 {
        raise(&state, id, &format!("q{i}")).await;
    }
    let mut got = Vec::new();
    loop {
        let (_, body) = pull(port, &paths[2], "PT0S", events::MAX_MESSAGE_LIMIT as u32).await;
        let n = body.matches("<wsnt:NotificationMessage>").count();
        assert!(n <= events::MAX_MESSAGE_LIMIT, "{n}");
        if n == 0 {
            break;
        }
        got.push(body);
    }
    let all = got.join("");
    assert_eq!(
        all.matches("<wsnt:NotificationMessage>").count(),
        events::MAX_QUEUED
    );
    assert!(!all.contains("Value=\"q9\"") && all.contains("Value=\"q10\""));

    // A subscription past its termination time is gone; a long one is cut to MAX_TERMINATION.
    let (_, body) = call(
        port,
        &paths[3],
        "<wsnt:Renew><wsnt:TerminationTime>PT1S</wsnt:TerminationTime></wsnt:Renew>",
    )
    .await;
    assert!(body.contains("RenewResponse"), "{body}");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (status, body) = pull(port, &paths[3], "PT0S", 1).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("ResourceUnknownFault"), "{body}");
    let (_, body) = call(
        port,
        &paths[4],
        "<wsnt:Renew><wsnt:TerminationTime>PT20H</wsnt:TerminationTime></wsnt:Renew>",
    )
    .await;
    let until = body
        .split("<wsnt:TerminationTime>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .unwrap_or_else(|| panic!("{body}"));
    let ahead = until.with_timezone(&chrono::Utc) - chrono::Utc::now();
    assert!(
        ahead.num_seconds() <= events::MAX_TERMINATION.as_secs() as i64,
        "{body}"
    );
    // A termination time in the past is refused.
    let (status, body) = subscribe(port, "2001-01-01T00:00:00Z").await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("UnacceptableInitialTerminationTimeFault"),
        "{body}"
    );
    // A filter of more alternatives than MAX_TOPIC_ALTERNATIVES is refused.
    let many = vec!["tns1:VideoSource/MotionAlarm"; events::MAX_TOPIC_ALTERNATIVES + 1].join("|");
    let (status, body) = call(
        port,
        wire::EVENTS_PATH,
        &format!("<tev:CreatePullPointSubscription><tev:Filter><wsnt:TopicExpression Dialect=\"{}\">{many}</wsnt:TopicExpression></tev:Filter></tev:CreatePullPointSubscription>", events::CONCRETE_SET),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("InvalidTopicExpressionFault"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presets_are_bounded_in_count_and_name() {
    let (_state, _id, port) = start(policy(), json!({})).await;
    let set = |name: String| {
        format!("<tptz:SetPreset><tptz:ProfileToken>main</tptz:ProfileToken><tptz:PresetName>{name}</tptz:PresetName></tptz:SetPreset>")
    };
    for i in 0..ptz::MAX_PRESETS {
        let (status, body) = call(port, wire::PTZ_PATH, &set(format!("P{i}"))).await;
        assert_eq!(status, 200, "{body}");
    }
    let (status, body) = call(port, wire::PTZ_PATH, &set("one more".into())).await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["Action", "TooManyPresets"], "{body}");
    let (_, body) = call(
        port,
        wire::PTZ_PATH,
        "<tptz:GetPresets><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GetPresets>",
    )
    .await;
    assert_eq!(
        body.matches("<tptz:Preset ").count(),
        ptz::MAX_PRESETS,
        "{body}"
    );
    // A name past MAX_PRESET_NAME, and a duplicate, are refused even with room.
    let (_, body) = call(port, wire::PTZ_PATH, "<tptz:RemovePreset><tptz:ProfileToken>main</tptz:ProfileToken><tptz:PresetToken>preset_1</tptz:PresetToken></tptz:RemovePreset>").await;
    assert!(body.contains("RemovePresetResponse"), "{body}");
    let (_, body) = call(
        port,
        wire::PTZ_PATH,
        &set("x".repeat(ptz::MAX_PRESET_NAME + 1)),
    )
    .await;
    assert_eq!(
        subcodes(&body),
        vec!["InvalidArgVal", "InvalidPresetName"],
        "{body}"
    );
    let (_, body) = call(port, wire::PTZ_PATH, &set("P2".into())).await;
    assert_eq!(
        subcodes(&body),
        vec!["InvalidArgVal", "PresetExist"],
        "{body}"
    );
    let (status, _) = call(port, wire::PTZ_PATH, &set("x".repeat(ptz::MAX_PRESET_NAME))).await;
    assert_eq!(status, 200);
}

/// A model that describes the camera (profiles, sources, hostname, scopes) and nothing else:
/// every other event goes to the unreachable model.
fn describing_only() -> Option<Vec<Value>> {
    let policy = super::real_client_test::POLICY;
    Some(
        [
            "onvif_get_profiles",
            "onvif_get_video_sources",
            "onvif_get_hostname",
            "onvif_get_scopes",
        ]
        .iter()
        .map(|e| json!({"event_pattern": e, "handler": {"type": "script", "language": "python", "code": policy}}))
        .collect(),
    )
}

fn status_of(body: &str) -> String {
    body.split("<tptz:PTZStatus>")
        .nth(1)
        .and_then(|s| s.split("<tt:UtcTime>").next())
        .unwrap_or_else(|| panic!("{body}"))
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_model_changes_nothing() {
    let (state, id, port) = start(describing_only(), json!({})).await;
    let get_status = "<tptz:GetStatus><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GetStatus>";
    let (_, before) = call(port, wire::PTZ_PATH, get_status).await;
    for body in [
        "<tptz:ContinuousMove><tptz:ProfileToken>main</tptz:ProfileToken><tptz:Velocity><tt:PanTilt x=\"0.5\" y=\"0.5\"/></tptz:Velocity></tptz:ContinuousMove>",
        "<tptz:AbsoluteMove><tptz:ProfileToken>main</tptz:ProfileToken><tptz:Position><tt:PanTilt x=\"0.5\" y=\"0.5\"/></tptz:Position></tptz:AbsoluteMove>",
        "<tptz:GotoHomePosition><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GotoHomePosition>",
    ] {
        let (status, text) = call(port, wire::PTZ_PATH, body).await;
        assert!(status == 500 || status == 503, "{status} {text}");
        assert!(text.contains("<env:Value>env:Receiver</env:Value>") && subcodes(&text).is_empty(), "{text}");
    }
    let (_, after) = call(port, wire::PTZ_PATH, get_status).await;
    assert_eq!(status_of(&after), status_of(&before));
    assert!(
        status_of(&after).contains("<tt:PanTilt>IDLE</tt:PanTilt>"),
        "{after}"
    );

    // Set*: the hostname, scopes, clock and imaging stay as they were.
    let (status, text) = call(
        port,
        wire::DEVICE_PATH,
        "<tds:SetHostname><tds:Name>renamed</tds:Name></tds:SetHostname>",
    )
    .await;
    assert!(status == 500 || status == 503, "{text}");
    let (_, text) = call(port, wire::DEVICE_PATH, "<tds:GetHostname/>").await;
    assert!(text.contains("<tt:Name>lobby-cam</tt:Name>"), "{text}");
    let (status, text) = call(port, wire::DEVICE_PATH, "<tds:AddScopes><tds:ScopeItem>onvif://www.onvif.org/name/X</tds:ScopeItem></tds:AddScopes>").await;
    assert!(status == 500 || status == 503, "{text}");
    let (_, text) = call(port, wire::DEVICE_PATH, "<tds:GetScopes/>").await;
    assert!(!text.contains("Configurable"), "{text}");
    let (status, text) = call(port, wire::DEVICE_PATH, "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType><tds:DaylightSavings>false</tds:DaylightSavings><tds:TimeZone><tt:TZ>CET-1</tt:TZ></tds:TimeZone><tds:UTCDateTime><tt:Date><tt:Year>2030</tt:Year><tt:Month>1</tt:Month><tt:Day>1</tt:Day></tt:Date><tt:Time><tt:Hour>0</tt:Hour><tt:Minute>0</tt:Minute><tt:Second>0</tt:Second></tt:Time></tds:UTCDateTime></tds:SetSystemDateAndTime>").await;
    assert!(status == 500 || status == 503, "{text}");
    let (_, text) = call(port, wire::DEVICE_PATH, "<tds:GetSystemDateAndTime/>").await;
    assert!(
        text.contains("<tt:TZ>UTC0</tt:TZ>") && !text.contains("<tt:Year>2030"),
        "{text}"
    );
    let (status, text) = call(port, wire::IMAGING_PATH, "<timg:SetImagingSettings><timg:VideoSourceToken>lobby_cam</timg:VideoSourceToken><timg:ImagingSettings><tt:Brightness>90</tt:Brightness></timg:ImagingSettings></timg:SetImagingSettings>").await;
    assert!(status == 500 || status == 503, "{text}");
    let (_, text) = call(port, wire::IMAGING_PATH, "<timg:GetImagingSettings><timg:VideoSourceToken>lobby_cam</timg:VideoSourceToken></timg:GetImagingSettings>").await;
    assert!(text.contains("<tt:Brightness>50</tt:Brightness>"), "{text}");
    // A subscription the model never accepted does not exist.
    let (status, text) = subscribe(port, "PT60S").await;
    assert!(status == 500 || status == 503, "{text}");
    assert_eq!(device(&state, id).await.subscriptions(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_position_outside_the_space_is_not_a_move() {
    let wrong = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
if t=='onvif_get_profiles':
  a=[{'type':'onvif_profiles','profiles':[{'token':'main','width':640,'height':480,'ptz':True}]}]
else:
  a=[{'type':'onvif_ptz_position','pan':3.0,'tilt':0.0,'zoom':0.5}]
print(json.dumps({'actions':a}))"#;
    let (_state, _id, port) = start(
        Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":wrong}})]),
        json!({}),
    )
    .await;
    let (status, text) = call(port, wire::PTZ_PATH, "<tptz:AbsoluteMove><tptz:ProfileToken>main</tptz:ProfileToken><tptz:Position><tt:PanTilt x=\"0.5\" y=\"0.5\"/></tptz:Position></tptz:AbsoluteMove>").await;
    assert_eq!(status, 500, "{text}");
    let (_, text) = call(
        port,
        wire::PTZ_PATH,
        "<tptz:GetStatus><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GetStatus>",
    )
    .await;
    assert!(text.contains("<tt:PanTilt x=\"0\" y=\"0\""), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_new_service_needs_a_digest() {
    let (state, id, port) = start(policy(), credentials()).await;
    let cases = [
        (wire::PTZ_PATH, "<tptz:GetStatus><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GetStatus>"),
        (wire::PTZ_PATH, "<tptz:AbsoluteMove><tptz:ProfileToken>main</tptz:ProfileToken><tptz:Position><tt:PanTilt x=\"0.5\" y=\"0.5\"/></tptz:Position></tptz:AbsoluteMove>"),
        (wire::EVENTS_PATH, "<tev:GetEventProperties/>"),
        (wire::EVENTS_PATH, "<tev:CreatePullPointSubscription/>"),
        ("/onvif/events/subscription/00", "<tev:PullMessages><tev:Timeout>PT1S</tev:Timeout><tev:MessageLimit>1</tev:MessageLimit></tev:PullMessages>"),
        (wire::MEDIA2_PATH, "<tr2:GetProfiles/>"),
        (wire::IMAGING_PATH, "<timg:GetOptions><timg:VideoSourceToken>lobby_cam</timg:VideoSourceToken></timg:GetOptions>"),
        (wire::DEVICE_PATH, "<tds:SetHostname><tds:Name>x</tds:Name></tds:SetHostname>"),
        (wire::DEVICE_PATH, "<tds:SystemReboot/>"),
    ];
    for (path, body) in cases {
        let (status, text) = call(port, path, body).await;
        assert_eq!(status, 400, "{body}: {text}");
        assert_eq!(subcodes(&text), vec!["NotAuthorized"], "{body}: {text}");
    }
    // None of it reached the model; with a digest the same GetStatus is answered.
    assert!(state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None
        )
        .await
        .iter()
        .all(|e| e.event_type == "onvif_not_authorized"));
    let nonce: [u8; 16] = rand::random();
    let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let (status, text) = post(
        port,
        wire::PTZ_PATH,
        wire::request_envelope(
            Some(&wire::security_header(USER, PASSWORD, &nonce, &created)),
            "<tptz:GetStatus><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GetStatus>",
        ),
    )
    .await;
    assert_eq!(status, 200, "{text}");
}
