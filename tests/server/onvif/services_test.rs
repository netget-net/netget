//! NetGet's ONVIF device beyond Device and Media ver10 — PTZ, Events (pull point), Imaging,
//! Media2 and the Device Set* operations — against independent ONVIF clients, each run as a
//! subprocess:
//!
//! - **python onvif-zeep-async** 4.3.0 (zeep over the WSDL it bundles: ptz, events, imaging;
//!   it has no Media2) through `peer/zeep_services.py`;
//! - **Go github.com/use-go/onvif** v0.0.9 (its `ptz`, `event`, `Imaging` and `device`
//!   request types) through `peer/go`, mode `services`;
//! - **python onvif2-zeep** 0.3.4 (zeep over ONVIF's ver20 Media WSDL from its own source
//!   distribution) through `peer/onvif2_media2.py`;
//! - **Go github.com/IOTechSystems/onvif** v1.3.0 (its `media2` package) through `peer/go-media2`.
//!
//! Every client signs with its own WS-Security digest. Each test prints the operations its
//! client actually sent, as the device logged them, and asserts the ones it must have. The tests
//! fail, not skip, without the clients: `python3 tests/server/onvif/install_peers.py <dir>`. The
//! model is `real_client_test::POLICY`; no LLM calls.
use super::real_client_test::{
    credentials, env, events, operations, policy, start_logged, StatusLog, PASSWORD, USER,
};
use netget::llm::actions::protocol_trait::Server;
use netget::server::onvif::actions::OnvifProtocol;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Run a peer, calling `on_line` with every line it prints as it prints it; the last line is its
/// JSON report. Fails with everything it printed when it fails or prints no JSON.
pub async fn run_streaming<F>(program: &str, args: &[String], mut on_line: F) -> Value
where
    F: FnMut(&str) -> futures::future::BoxFuture<'static, ()>,
{
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("{program}: {e}"));
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let err_task = tokio::spawn(async move {
        let mut s = String::new();
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut s).await;
        s
    });
    let mut lines = BufReader::new(stdout).lines();
    let mut seen = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(240), async {
        while let Ok(Some(line)) = lines.next_line().await {
            on_line(&line).await;
            seen.push(line);
        }
    })
    .await;
    let status = child.wait().await.ok();
    let err = err_task.await.unwrap_or_default();
    assert!(
        read.is_ok(),
        "{program} did not finish:\n{}\n{err}",
        seen.join("\n")
    );
    assert!(
        status.is_some_and(|s| s.success()),
        "{program} failed:\n{}\n{err}",
        seen.join("\n")
    );
    serde_json::from_str(seen.last().map(String::as_str).unwrap_or_default())
        .unwrap_or_else(|_| panic!("{program} printed no JSON:\n{}\n{err}", seen.join("\n")))
}

/// Raise an event on the running device as the model would, through `onvif_raise_event`.
pub async fn raise(state: &AppState, id: ServerId, action: Value) -> Value {
    match OnvifProtocol
        .execute_action_with_state(action, state.clone(), Some(id))
        .await
    {
        Ok(netget::llm::actions::protocol_trait::ActionResult::Custom { data, .. }) => data,
        other => panic!("raising the event: {other:?}"),
    }
}

/// Print what a client sent and assert it sent every operation in `must`.
pub fn sent(client: &str, log: &StatusLog, must: &[&str]) {
    let ops = operations(log);
    println!("{client} sent {} distinct operations:", ops.len());
    for (op, n) in &ops {
        println!("  {op} x{n}");
    }
    let missing: Vec<&&str> = must.iter().filter(|m| !ops.contains_key(**m)).collect();
    assert!(
        missing.is_empty(),
        "{client} never sent {missing:?}; it sent {ops:?}"
    );
}

fn pos(v: &Value) -> (f64, f64, f64) {
    (
        v["pan"].as_f64().unwrap_or(f64::NAN),
        v["tilt"].as_f64().unwrap_or(f64::NAN),
        v["zoom"].as_f64().unwrap_or(f64::NAN),
    )
}

fn close(a: (f64, f64, f64), b: (f64, f64, f64)) -> bool {
    (a.0 - b.0).abs() < 1e-6 && (a.1 - b.1).abs() < 1e-6 && (a.2 - b.2).abs() < 1e-6
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn onvif_zeep_async_drives_ptz_events_imaging_and_device_settings() {
    let (state, id, port, log) = start_logged(policy(), credentials()).await;
    let python = env("NETGET_ONVIF_PYTHON");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/onvif/peer/zeep_services.py"
    );
    let raised = std::sync::Arc::new(std::sync::Mutex::new(None));
    let r = {
        let (state, raised) = (state.clone(), raised.clone());
        run_streaming(
            &python,
            &[
                "-I".into(),
                script.into(),
                "127.0.0.1".into(),
                port.to_string(),
                USER.into(),
                PASSWORD.into(),
            ],
            move |line| {
                let (state, raised) = (state.clone(), raised.clone());
                let subscribed = line.contains("\"subscribed\"");
                Box::pin(async move {
                    if subscribed {
                        // zeep is now waiting in a long PullMessages: give it a moment to be
                        // held, then raise the event it should wake up with.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let d = raise(&state, id, json!({"type": "onvif_raise_event",
                            "topic": "tns1:Device/Trigger/DigitalInput",
                            "source": {"InputToken": "door_contact"}, "data": {"LogicalState": true}}))
                        .await;
                        *raised.lock().unwrap() = Some(d);
                    }
                })
            },
        )
        .await
    };
    sent(
        "onvif-zeep-async",
        &log,
        &[
            "ptz:GetNodes",
            "ptz:GetConfigurations",
            "ptz:GetStatus",
            "ptz:AbsoluteMove",
            "ptz:RelativeMove",
            "ptz:ContinuousMove",
            "ptz:Stop",
            "ptz:SetPreset",
            "ptz:GetPresets",
            "ptz:GotoPreset",
            "ptz:RemovePreset",
            "ptz:GotoHomePosition",
            "events:GetEventProperties",
            "events:CreatePullPointSubscription",
            "events:PullMessages",
            "events:SetSynchronizationPoint",
            "events:Renew",
            "events:Unsubscribe",
            "imaging:GetImagingSettings",
            "imaging:SetImagingSettings",
            "imaging:GetOptions",
            "imaging:GetMoveOptions",
            "imaging:Move",
            "imaging:GetStatus",
            "device:GetHostname",
            "device:SetHostname",
            "device:SetScopes",
            "device:AddScopes",
            "device:RemoveScopes",
            "device:SystemReboot",
            "device:SetSystemDateAndTime",
            "device:GetSystemDateAndTime",
            "device:GetServices",
        ],
    );

    // GetServices advertised every service, and zeep found each at this server.
    for (ns, path) in [
        ("http://www.onvif.org/ver20/ptz/wsdl", "/onvif/ptz_service"),
        (
            "http://www.onvif.org/ver10/events/wsdl",
            "/onvif/events_service",
        ),
        (
            "http://www.onvif.org/ver20/imaging/wsdl",
            "/onvif/imaging_service",
        ),
        (
            "http://www.onvif.org/ver20/media/wsdl",
            "/onvif/media2_service",
        ),
    ] {
        assert_eq!(
            r["xaddrs"][ns],
            format!("http://127.0.0.1:{port}{path}"),
            "{r}"
        );
    }

    // ---- PTZ ----
    assert_eq!(r["ptz_nodes"][0]["token"], "ptz_node", "{r}");
    assert_eq!(r["ptz_configurations"][0]["node"], "ptz_node", "{r}");
    assert!(
        close(pos(&r["ptz_status_initial"]["position"]), (0.0, 0.0, 0.0)),
        "{r}"
    );
    assert!(
        close(pos(&r["ptz_status_absolute"]["position"]), (0.5, 0.25, 0.3)),
        "{r}"
    );
    assert!(
        close(pos(&r["ptz_status_relative"]["position"]), (0.6, 0.2, 0.3)),
        "{r}"
    );
    assert_eq!(r["ptz_status_moving"]["pan_tilt"], "MOVING", "{r}");
    assert_eq!(r["ptz_status_stopped"]["pan_tilt"], "IDLE", "{r}");
    let stopped = pos(&r["ptz_status_stopped"]["position"]);
    let preset = r["ptz_set_preset"].as_str().unwrap_or_default().to_string();
    assert!(preset.starts_with("preset_"), "{r}");
    assert_eq!(r["ptz_presets"][0]["name"], "Door", "{r}");
    assert!(close(pos(&r["ptz_presets"][0]["position"]), stopped), "{r}");
    assert!(
        close(pos(&r["ptz_status_preset"]["position"]), stopped),
        "{r}"
    );
    // The move the model refused: its fault, and the head where it was.
    assert_eq!(
        r["ptz_refused"]["subcodes"],
        json!(["InvalidArgVal", "InvalidPosition"]),
        "{r}"
    );
    assert!(
        close(pos(&r["ptz_status_refused"]["position"]), stopped),
        "{r}"
    );
    assert_eq!(r["ptz_presets_after"], json!([]), "{r}");
    assert_eq!(
        r["ptz_goto_removed"]["subcodes"],
        json!(["InvalidArgVal", "NoToken"]),
        "{r}"
    );
    assert!(
        close(pos(&r["ptz_status_home"]["position"]), (0.0, 0.0, 0.0)),
        "{r}"
    );
    assert_eq!(
        r["ptz_no_ptz_profile"]["subcodes"],
        json!(["InvalidArgVal", "NoPTZProfile"]),
        "{r}"
    );
    let moves = events(&state, id, "onvif_ptz_move").await;
    assert_eq!(
        moves.iter().map(|m| m["kind"].clone()).collect::<Vec<_>>(),
        vec![
            json!("absolute"),
            json!("relative"),
            json!("continuous"),
            json!("absolute"),
            json!("preset"),
            json!("absolute"),
            json!("home")
        ],
        "{moves:?}"
    );

    // ---- Events ----
    assert_eq!(r["event_properties"]["fixed"], true, "{r}");
    // The model's answer to the subscription raised the motion alarm (a change, not a resend).
    let first = &r["pull_on_subscribe"];
    assert_eq!(first[0]["topic"], "tns1:VideoSource/MotionAlarm", "{r}");
    assert_eq!(first[0]["source"], json!({"Source": "lobby_cam"}), "{r}");
    assert_eq!(first[0]["data"], json!({"State": "true"}), "{r}");
    assert_eq!(first[0]["property_operation"], "Changed", "{r}");
    let utc =
        chrono::DateTime::parse_from_rfc3339(first[0]["utc_time"].as_str().unwrap_or_default())
            .unwrap_or_else(|e| panic!("{e}: {r}"));
    assert!(
        (chrono::Utc::now() - utc.with_timezone(&chrono::Utc))
            .num_seconds()
            .abs()
            < 120,
        "{r}"
    );
    // The event the test raised while zeep was waiting: it woke the long poll early.
    assert_eq!(
        raised.lock().unwrap().clone(),
        Some(json!({"delivered": 1}))
    );
    let woke = &r["pull_raised"];
    assert_eq!(woke[0]["topic"], "tns1:Device/Trigger/DigitalInput", "{r}");
    assert_eq!(woke[0]["data"], json!({"LogicalState": "true"}), "{r}");
    assert!(r["pull_raised_secs"].as_f64().unwrap_or(99.0) < 20.0, "{r}");
    // SetSynchronizationPoint resent both properties' current values as Initialized.
    let sync = r["pull_after_sync"].as_array().cloned().unwrap_or_default();
    let mut topics: Vec<&str> = sync.iter().filter_map(|n| n["topic"].as_str()).collect();
    topics.sort();
    assert_eq!(
        topics,
        vec![
            "tns1:Device/Trigger/DigitalInput",
            "tns1:VideoSource/MotionAlarm"
        ],
        "{r}"
    );
    assert!(
        sync.iter()
            .all(|n| n["property_operation"] == "Initialized"),
        "{r}"
    );
    assert!(r["renew"]["termination"].is_string(), "{r}");
    assert_eq!(
        r["pull_after_unsubscribe"]["subcodes"],
        json!(["InvalidArgVal"]),
        "{r}"
    );
    let subs = events(&state, id, "onvif_create_subscription").await;
    assert_eq!(subs.len(), 1, "{subs:?}");

    // ---- Imaging ----
    assert_eq!(r["imaging_settings"]["brightness"], 50.0, "{r}");
    assert_eq!(
        r["imaging_options"]["brightness"],
        json!([0.0, 100.0]),
        "{r}"
    );
    assert_eq!(r["imaging_settings_after"]["brightness"], 70.0, "{r}");
    assert_eq!(r["imaging_settings_after"]["contrast"], 40.0, "{r}");
    assert_eq!(
        r["imaging_refused"]["subcodes"],
        json!(["InvalidArgVal", "SettingsInvalid"]),
        "{r}"
    );
    assert_eq!(
        r["imaging_settings_refused"], r["imaging_settings_after"],
        "{r}"
    );
    assert_eq!(r["imaging_status"]["position"], 0.4, "{r}");
    assert_eq!(
        r["imaging_no_source"]["subcodes"],
        json!(["InvalidArgVal", "NoSource"]),
        "{r}"
    );

    // ---- Device Set* ----
    assert_eq!(r["hostname_initial"], "lobby-cam", "{r}");
    assert_eq!(r["hostname_after"], "lobby-cam-2", "{r}");
    let configurable = |k: &str| -> Vec<String> {
        r[k].as_array()
            .into_iter()
            .flatten()
            .filter(|s| s[0] == "Configurable")
            .map(|s| s[1].as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert_eq!(
        configurable("scopes_after_set"),
        vec!["onvif://www.onvif.org/location/floor1"],
        "{r}"
    );
    assert_eq!(
        configurable("scopes_after_add"),
        vec![
            "onvif://www.onvif.org/location/floor1",
            "onvif://www.onvif.org/name/Annex"
        ],
        "{r}"
    );
    assert_eq!(
        configurable("scopes_after_remove"),
        vec!["onvif://www.onvif.org/name/Annex"],
        "{r}"
    );
    assert_eq!(
        r["remove_fixed"]["subcodes"],
        json!(["OperationProhibited", "FixedScope"]),
        "{r}"
    );
    assert_eq!(
        r["add_refused"]["subcodes"],
        json!(["OperationProhibited", "ScopeOverwrite"]),
        "{r}"
    );
    assert_eq!(r["reboot"], "Rebooting in 30 seconds", "{r}");
    assert_eq!(r["date_time_after"]["tz"], "CET-1CEST", "{r}");
    let asked =
        chrono::DateTime::parse_from_rfc3339(r["date_time_asked"].as_str().unwrap_or_default())
            .unwrap();
    let got = chrono::DateTime::parse_from_rfc3339(
        r["date_time_after"]["utc"].as_str().unwrap_or_default(),
    )
    .unwrap();
    assert!((got - asked).num_seconds().abs() <= 5, "{r}");
    assert!(events(&state, id, "onvif_not_authorized").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn use_go_onvif_drives_ptz_events_imaging_and_device_settings() {
    let (state, id, port, log) = start_logged(policy(), credentials()).await;
    let raised = std::sync::Arc::new(std::sync::Mutex::new(None));
    let r = {
        let (state, raised) = (state.clone(), raised.clone());
        run_streaming(
            &env("NETGET_ONVIF_GO_CLIENT"),
            &[
                format!("127.0.0.1:{port}"),
                USER.into(),
                PASSWORD.into(),
                "services".into(),
            ],
            move |line| {
                let (state, raised) = (state.clone(), raised.clone());
                let subscribed = line.contains("\"subscribed\"");
                Box::pin(async move {
                    if subscribed {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let d = raise(&state, id, json!({"type": "onvif_raise_event",
                            "topic": "tns1:RuleEngine/CellMotionDetector/Motion",
                            "source": {"VideoSourceConfigurationToken": "vsc_lobby_cam",
                                       "VideoAnalyticsConfigurationToken": "analytics", "Rule": "MyMotionDetectorRule"},
                            "data": {"IsMotion": true}}))
                        .await;
                        *raised.lock().unwrap() = Some(d);
                    }
                })
            },
        )
        .await
    };
    sent(
        "use-go/onvif",
        &log,
        &[
            "ptz:GetNodes",
            "ptz:GetNode",
            "ptz:GetConfigurations",
            "ptz:GetConfiguration",
            "ptz:AbsoluteMove",
            "ptz:GetStatus",
            "ptz:SetPreset",
            "ptz:GetPresets",
            "ptz:RelativeMove",
            "ptz:GotoPreset",
            "ptz:ContinuousMove",
            "ptz:Stop",
            "ptz:RemovePreset",
            "ptz:GotoHomePosition",
            "events:GetEventProperties",
            "events:CreatePullPointSubscription",
            "events:PullMessages",
            "events:SetSynchronizationPoint",
            "other:Renew",
            "other:Unsubscribe",
            "imaging:GetImagingSettings",
            "imaging:GetOptions",
            "imaging:GetMoveOptions",
            "imaging:SetImagingSettings",
            "imaging:Move",
            "imaging:GetStatus",
            "imaging:Stop",
            "device:GetHostname",
            "device:SetHostname",
            "device:SetScopes",
            "device:AddScopes",
            "device:RemoveScopes",
            "device:GetScopes",
            "device:SystemReboot",
            "device:SetSystemDateAndTime",
            "device:GetSystemDateAndTime",
        ],
    );
    // GetCapabilities gave the library every endpoint it can address.
    for (k, path) in [
        ("ptz", "/onvif/ptz_service"),
        ("events", "/onvif/events_service"),
        ("imaging", "/onvif/imaging_service"),
    ] {
        assert_eq!(
            r["endpoints"][k],
            format!("http://127.0.0.1:{port}{path}"),
            "{r}"
        );
    }

    // ---- PTZ: the library's own move requests, and the device's answers ----
    assert_eq!(r["nodes"]["token"], "ptz_node", "{r}");
    assert_eq!(r["node"]["status"], 200, "{r}");
    assert_eq!(r["configurations"]["node_token"], "ptz_node", "{r}");
    assert_eq!(r["configuration"]["status"], 200, "{r}");
    assert!(
        close(pos(&r["status_absolute"]["position"]), (-0.4, 0.3, 0.6)),
        "{r}"
    );
    let token = r["set_preset"]["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(token.starts_with("preset_"), "{r}");
    assert_eq!(r["presets"]["presets"][0]["name"], "Gate", "{r}");
    assert!(
        close(
            pos(&r["presets"]["presets"][0]["position"]),
            (-0.4, 0.3, 0.6)
        ),
        "{r}"
    );
    // use-go writes every axis, so the translation's zoom is 0 and zoom stays.
    assert!(
        close(pos(&r["status_relative"]["position"]), (-0.2, 0.4, 0.6)),
        "{r}"
    );
    assert!(
        close(pos(&r["status_preset"]["position"]), (-0.4, 0.3, 0.6)),
        "{r}"
    );
    assert_eq!(r["status_moving"]["pan_tilt"], "MOVING", "{r}");
    assert_eq!(r["status_stopped"]["pan_tilt"], "IDLE", "{r}");
    assert_eq!(
        r["refused"]["fault"], "env:Sender/ter:InvalidArgVal/ter:InvalidPosition",
        "{r}"
    );
    assert_eq!(
        r["status_refused"]["position"], r["status_stopped"]["position"],
        "{r}"
    );
    assert_eq!(r["remove_preset"]["status"], 200, "{r}");
    assert!(
        close(pos(&r["status_home"]["position"]), (0.0, 0.0, 0.0)),
        "{r}"
    );

    // ---- Events: CreatePullPointSubscription through CallMethod, the rest at its address ----
    let address = r["create_pull_point"]["address"]
        .as_str()
        .unwrap_or_default();
    assert!(
        address.starts_with(&format!(
            "http://127.0.0.1:{port}/onvif/events/subscription/"
        )),
        "{r}"
    );
    assert_eq!(
        r["pull_on_subscribe"]["notifications"][0]["topic"], "tns1:VideoSource/MotionAlarm",
        "{r}"
    );
    assert_eq!(
        raised.lock().unwrap().clone(),
        Some(json!({"delivered": 1}))
    );
    let woke = &r["pull_raised"]["notifications"][0];
    assert_eq!(
        woke["topic"], "tns1:RuleEngine/CellMotionDetector/Motion",
        "{r}"
    );
    assert_eq!(woke["data"], json!({"IsMotion": "true"}), "{r}");
    assert_eq!(woke["source"]["Rule"], "MyMotionDetectorRule", "{r}");
    assert!(
        r["pull_raised"]["secs"].as_f64().unwrap_or(99.0) < 20.0,
        "{r}"
    );
    assert_eq!(
        r["pull_after_sync"]["notifications"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "{r}"
    );
    assert_eq!(r["renew"]["status"], 200, "{r}");
    assert_eq!(r["unsubscribe"]["status"], 200, "{r}");
    assert_eq!(
        r["pull_after_unsubscribe"]["fault"], "env:Sender/ter:InvalidArgVal",
        "{r}"
    );

    // ---- Imaging ----
    assert_eq!(r["imaging_settings"]["brightness"], 50.0, "{r}");
    // The library writes every ImagingSettings20 element, exposure and white balance included,
    // which this device does not have: refused, and nothing changed.
    assert_eq!(
        r["imaging_set"]["fault"], "env:Sender/ter:InvalidArgVal/ter:SettingsInvalid",
        "{r}"
    );
    assert_eq!(r["imaging_settings_after"]["brightness"], 50.0, "{r}");
    assert_eq!(r["imaging_move"]["status"], 200, "{r}");
    assert_eq!(r["imaging_status"]["position"], 0.7, "{r}");

    // ---- Device Set* ----
    assert_eq!(r["hostname_initial"]["name"], "lobby-cam", "{r}");
    assert_eq!(r["hostname_after"]["name"], "gate-cam", "{r}");
    assert_eq!(
        r["scopes"]["configurable"],
        json!(["onvif://www.onvif.org/name/Gate"]),
        "{r}"
    );
    assert_eq!(r["reboot"]["message"], "Rebooting in 30 seconds", "{r}");
    let asked =
        chrono::DateTime::parse_from_rfc3339(r["date_time_asked"].as_str().unwrap_or_default())
            .unwrap();
    let got = chrono::DateTime::parse_from_rfc3339(
        r["date_time_after"]["utc"].as_str().unwrap_or_default(),
    )
    .unwrap();
    assert!((got - asked).num_seconds().abs() <= 5, "{r}");
    assert!(events(&state, id, "onvif_not_authorized").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn media2_through_onvif2_zeep_and_iotech_onvif_reads_the_media_description() {
    let (state, id, port, log) = start_logged(policy(), credentials()).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/onvif/peer/onvif2_media2.py"
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
            env("NETGET_ONVIF2_WSDL"),
        ],
        |_| Box::pin(async {}),
    )
    .await;
    sent(
        "onvif2-zeep",
        &log,
        &[
            "device:GetServices",
            "media2:GetProfiles",
            "media2:GetStreamUri",
            "media2:GetSnapshotUri",
            "media2:GetVideoSourceConfigurations",
            "media2:GetVideoEncoderConfigurations",
        ],
    );
    assert_eq!(
        r["xaddrs"]["http://www.onvif.org/ver20/media/wsdl"],
        format!("http://127.0.0.1:{port}/onvif/media2_service"),
        "{r}"
    );
    // The same profiles Media ver10 describes, with the same configuration tokens.
    assert_eq!(
        r["profiles"],
        json!([
            {"token": "main", "name": "Main stream", "source": "lobby_cam", "encoding": "H264", "width": 1920, "height": 1080, "ptz": "ptz_config"},
            {"token": "sub", "name": "Sub stream", "source": "lobby_cam", "encoding": "JPEG", "width": 640, "height": 360, "ptz": null}
        ]),
        "{r}"
    );
    assert_eq!(
        r["profiles_bare"],
        json!([{"token": "main", "configurations": false}, {"token": "sub", "configurations": false}]),
        "{r}"
    );
    assert_eq!(r["stream_uri"], "rtsp://192.0.2.42:554/live/main", "{r}");
    assert_eq!(
        r["snapshot_uri"], "http://192.0.2.42/snapshot/sub.jpg",
        "{r}"
    );
    assert_eq!(
        r["source_configurations"],
        json!([{"token": "vsc_lobby_cam", "source": "lobby_cam"}]),
        "{r}"
    );
    assert_eq!(
        r["encoder_configurations"],
        json!([{"token": "vec_sub", "encoding": "JPEG", "width": 640}]),
        "{r}"
    );
    assert_eq!(
        r["missing_profile"]["subcodes"],
        json!(["InvalidArgVal", "NoProfile"]),
        "{r}"
    );
    assert_eq!(
        r["bad_protocol"]["subcodes"],
        json!(["InvalidArgVal", "InvalidStreamSetup"]),
        "{r}"
    );
    // The stream event the model answered was asked in ver10 terms, so one answer serves both.
    let asked = events(&state, id, "onvif_get_stream_uri").await;
    assert_eq!(asked[0]["service"], "media2", "{asked:?}");
    assert_eq!(asked[0]["stream"], "RTP-Unicast", "{asked:?}");
    assert_eq!(asked[0]["protocol"], "RTSP", "{asked:?}");

    // IOTechSystems/onvif: its media2 GetProfiles and GetVideoEncoderConfigurations, sent to the
    // Media XAddr (the library's choice; the device dispatches on the namespace).
    let (_state, _id, port, log) = start_logged(policy(), credentials()).await;
    let r = run_streaming(
        &env("NETGET_ONVIF_GO_MEDIA2"),
        &[format!("127.0.0.1:{port}"), USER.into(), PASSWORD.into()],
        |_| Box::pin(async {}),
    )
    .await;
    sent(
        "IOTechSystems/onvif",
        &log,
        &["media2:GetProfiles", "media2:GetVideoEncoderConfigurations"],
    );
    assert!(r.get("connect_error").is_none(), "{r}");
    assert_eq!(
        r["profiles"]["profiles"],
        json!([{"token": "main", "name": "Main stream", "fixed": true}, {"token": "sub", "name": "Sub stream", "fixed": true}]),
        "{r}"
    );
    assert_eq!(
        r["encoders"]["configurations"][0]["token"], "vec_main",
        "{r}"
    );
    assert_eq!(
        r["encoders"]["configurations"][0]["encoding"], "H264",
        "{r}"
    );
    assert_eq!(r["encoders"]["configurations"][0]["width"], 1920, "{r}");
    assert_eq!(
        r["encoders"]["configurations"].as_array().map(Vec::len),
        Some(1),
        "{r}"
    );
    assert_eq!(r["all_encoder_count"], 2, "{r}");
}
