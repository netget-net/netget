//! NetGet's ONVIF client against **onvif_simple_server** (roleoroleo/onvif_simple_server at a
//! pinned commit, C, run as CGI under lighttpd with its onvif_notify_server daemon) for the two
//! services RPOS does not have: Media2 and Events. onvif_simple_server verifies every WS-Security
//! PasswordDigest itself.
//!
//! A python chain is the model: on connect it reads the event properties and the Media2
//! profiles and opens a pull-point subscription; on the profiles it asks Media2 for the first
//! profile's stream and snapshot URIs and the source and encoder configurations. The test then
//! creates the file the device's notify daemon watches — the device raising its motion alarm —
//! and injects a PullMessages through the client's command channel; the notification comes back
//! structured. Renew, SetSynchronizationPoint and Unsubscribe follow the same way.
//!
//! `NETGET_ONVIF_SIMPLE_SERVER` is the launcher `tests/server/onvif/install_peers.py` writes on
//! Linux (the notify daemon uses inotify). The test fails, not skips, without it. No LLM calls.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='onvif_connected':
  a=[{'type':'onvif_get_event_properties'},{'type':'onvif_media2_get_profiles'},{'type':'onvif_create_pull_point','termination_secs':120}]
elif e.get('service')=='media2' and e.get('operation')=='GetProfiles' and e['ok']:
  p=e['result']['profiles'][0]['token']
  a=[{'type':'onvif_media2_get_stream_uri','profile_token':p},{'type':'onvif_media2_get_snapshot_uri','profile_token':p},
     {'type':'onvif_media2_get_video_source_configurations'},{'type':'onvif_media2_get_video_encoder_configurations','profile_token':p}]
print(json.dumps({'actions':a}))"#;

fn launcher() -> String {
    let v = std::env::var("NETGET_ONVIF_SIMPLE_SERVER").unwrap_or_default();
    assert!(
        !v.is_empty(),
        "NETGET_ONVIF_SIMPLE_SERVER is required: on Linux, python3 tests/server/onvif/install_peers.py <dir> builds onvif_simple_server and prints it"
    );
    v
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The running device, driven through its launcher's stdin.
struct Device {
    child: tokio::process::Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    port: u16,
    _dir: tempfile::TempDir,
    /// What the test injected through the client's command channel, as `service:Operation`.
    injected: Vec<String>,
}

impl Device {
    async fn command(&mut self, c: &str) -> Value {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(format!("{c}\n").as_bytes()).await.unwrap();
        stdin.flush().await.unwrap();
        let line = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
            .await
            .unwrap_or_else(|_| panic!("the launcher did not answer {c:?}"))
            .unwrap()
            .unwrap_or_default();
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("the launcher said {line:?}"))
    }

    /// What onvif_simple_server and its notify daemon logged.
    async fn log(&mut self) -> String {
        self.command("log").await["log"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}

async fn device() -> Device {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = tokio::process::Command::new(launcher())
        .arg(dir.path())
        .arg(port.to_string())
        .arg("admin")
        .arg("oss-secret")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("the onvif_simple_server launcher");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(Duration::from_secs(60), lines.next_line())
        .await
        .expect("onvif_simple_server never came up")
        .unwrap()
        .unwrap_or_default();
    assert!(
        ready.contains("\"ready\": true"),
        "onvif_simple_server: {ready}"
    );
    Device {
        child,
        lines,
        port,
        _dir: dir,
        injected: Vec::new(),
    }
}

async fn client(port: u16, password: &str) -> (AppState, anyhow::Result<ClientId>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "onvif".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Watch the camera".into()),
        startup_params: Some(json!({"username": "admin", "password": password})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await;
    (state, id)
}

async fn responses(state: &AppState, id: ClientId) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "onvif_response")
        .map(|e| e["request"].clone())
        .collect()
}

/// Inject an action and return the response event it produced.
async fn send(state: &AppState, id: ClientId, action: Value, device: &mut Device) -> Value {
    match state
        .send_to_client(id, action.clone(), Duration::from_secs(60))
        .await
    {
        Ok(ClientSendOutcome::Executed { detail }) => {
            let r: Value = serde_json::from_str(&detail).unwrap();
            device.injected.push(format!(
                "{}:{}",
                r["service"].as_str().unwrap_or("?"),
                r["operation"].as_str().unwrap_or("?")
            ));
            r
        }
        other => panic!("{action}: {other:?}\n{}", device.log().await),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_reads_media2_and_pulls_events_from_onvif_simple_server() {
    let mut device = device().await;
    let (state, id) = client(device.port, "oss-secret").await;
    let id = match id {
        Ok(id) => id,
        Err(e) => panic!("connect: {e:#}\n{}", device.log().await),
    };
    // 3 on connect, 4 on the Media2 profiles.
    let all = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let r = responses(&state, id).await;
            if r.len() >= 7 {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let all = match all {
        Ok(a) => a,
        Err(_) => panic!(
            "the chain did not finish: {:?}\n{}",
            responses(&state, id).await,
            device.log().await
        ),
    };
    for r in &all {
        assert_eq!(r["ok"], true, "{r}\n{}", device.log().await);
    }
    let by = |service: &str, op: &str| -> Value {
        all.iter()
            .find(|r| r["service"] == service && r["operation"] == op)
            .cloned()
            .unwrap_or_else(|| panic!("no {service}:{op} in {all:?}"))
    };
    let topics = by("events", "GetEventProperties")["result"]["topics"].clone();
    assert!(
        topics
            .as_array()
            .is_some_and(|t| t.iter().any(|t| t == "tns1:VideoSource/MotionAlarm")),
        "{topics}"
    );
    let profiles = by("media2", "GetProfiles")["result"]["profiles"].clone();
    assert_eq!(profiles[0]["encoding"], "H264", "{profiles}");
    assert_eq!(profiles[0]["width"], 1920, "{profiles}");
    assert_eq!(profiles[1]["width"], 640, "{profiles}");
    let uri = by("media2", "GetStreamUri")["result"]["uri"].clone();
    assert!(
        uri.as_str()
            .is_some_and(|u| u.starts_with("rtsp://") && u.ends_with("/netget_main")),
        "{uri}"
    );
    assert!(by("media2", "GetSnapshotUri")["result"]["uri"]
        .as_str()
        .is_some_and(|u| u.ends_with("/snapshot/main.jpg")));
    assert!(
        by("media2", "GetVideoSourceConfigurations")["result"]["configurations"][0]["token"]
            .is_string()
    );
    assert_eq!(
        by("media2", "GetVideoEncoderConfigurations")["result"]["configurations"][0]["encoding"],
        "H264"
    );
    let created = by("events", "CreatePullPointSubscription");
    assert!(
        created["result"]["address"]
            .as_str()
            .is_some_and(|a| a.contains("/onvif/events_service?sub=")),
        "{created}"
    );

    // The device raises its motion alarm; a PullMessages injected through the command channel
    // brings it back, structured.
    let first = send(
        &state,
        id,
        json!({"type": "onvif_pull_messages", "timeout_secs": 2}),
        &mut device,
    )
    .await;
    assert_eq!(first["ok"], true, "{first}\n{}", device.log().await);
    device.command("on motion_alarm").await;
    let mut pulled = Vec::new();
    for _ in 0..5 {
        let r = send(
            &state,
            id,
            json!({"type": "onvif_pull_messages", "timeout_secs": 10}),
            &mut device,
        )
        .await;
        assert_eq!(r["ok"], true, "{r}\n{}", device.log().await);
        pulled.extend(
            r["result"]["notifications"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        if pulled.iter().any(|n| {
            n["topic"] == "tns1:VideoSource/MotionAlarm" && n["property_operation"] == "Changed"
        }) {
            break;
        }
    }
    let alarm = pulled
        .iter()
        .find(|n| {
            n["topic"] == "tns1:VideoSource/MotionAlarm" && n["property_operation"] == "Changed"
        })
        .cloned()
        .unwrap_or_else(|| panic!("no motion alarm in {pulled:?}"));
    assert_eq!(alarm["data"]["State"], "true", "{alarm}");
    assert!(alarm["utc_time"].is_string(), "{alarm}");

    let renewed = send(
        &state,
        id,
        json!({"type": "onvif_renew_subscription", "termination_secs": 300}),
        &mut device,
    )
    .await;
    assert_eq!(renewed["ok"], true, "{renewed}\n{}", device.log().await);
    assert!(
        renewed["result"]["termination_time"].is_string(),
        "{renewed}"
    );
    let sync = send(
        &state,
        id,
        json!({"type": "onvif_set_synchronization_point"}),
        &mut device,
    )
    .await;
    assert_eq!(sync["ok"], true, "{sync}\n{}", device.log().await);
    let after_sync = send(
        &state,
        id,
        json!({"type": "onvif_pull_messages", "timeout_secs": 5}),
        &mut device,
    )
    .await;
    assert!(
        after_sync["result"]["notifications"]
            .as_array()
            .is_some_and(|n| n.iter().any(|n| n["property_operation"] == "Initialized")),
        "{after_sync}\n{}",
        device.log().await
    );
    let gone = send(
        &state,
        id,
        json!({"type": "onvif_unsubscribe"}),
        &mut device,
    )
    .await;
    assert_eq!(gone["ok"], true, "{gone}\n{}", device.log().await);
    // With the subscription ended the client has none to pull from, and says so.
    let none = send(
        &state,
        id,
        json!({"type": "onvif_pull_messages"}),
        &mut device,
    )
    .await;
    assert_eq!(none["ok"], false, "{none}");
    assert!(
        none["error"]
            .as_str()
            .is_some_and(|e| e.contains("no pull-point subscription")),
        "{none}"
    );

    let sent: Vec<String> = responses(&state, id)
        .await
        .iter()
        .map(|r| {
            format!(
                "{}:{}",
                r["service"].as_str().unwrap_or("?"),
                r["operation"].as_str().unwrap_or("?")
            )
        })
        .collect();
    println!(
        "NetGet sent onvif_simple_server, from the model's chain: {sent:?}; injected: {:?}",
        device.injected
    );
    // The device's log keeps its last request: an Unsubscribe whose digest it accepted.
    let log = device.log().await;
    assert!(log.contains("Authentication ok"), "{log}");

    // The wrong password. onvif_simple_server answers GetCapabilities without credentials (ONVIF
    // puts it in the pre-authentication access class), so the client connects; everything the
    // model then asks is refused NotAuthorized, the digest checked by the device itself. (One
    // device per test run: onvif_simple_server's daemon and CGI share fixed paths.)
    let (state, id) = client(device.port, "not-the-password").await;
    let id = id.unwrap_or_else(|e| panic!("connect: {e:#}"));
    let refused = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let r = responses(&state, id).await;
            if r.len() >= 3 {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the refused chain did not finish");
    let log = device.log().await;
    for r in &refused {
        assert_eq!(
            r["fault"]["subcodes"],
            json!(["NotAuthorized"]),
            "{r}\n{log}"
        );
    }
    assert!(log.contains("Authentication error"), "{log}");
}
