//! NetGet's ONVIF device against two independent ONVIF clients, each run as a subprocess:
//!
//! - **python onvif-zeep-async** 4.3.0, Home Assistant's ONVIF library (zeep over ONVIF's own
//!   WSDL and XSD), through `peer/zeep_client.py`;
//! - **Go github.com/use-go/onvif** v0.0.9 (encoding/xml and its own digest), through
//!   `peer/go`.
//!
//! Both authenticate with a WS-Security PasswordDigest — each computes it its own way — and
//! read the device information, scopes, profiles and stream URIs a python policy (the model)
//! supplied. With the wrong password both are refused with ter:NotAuthorized. The tests fail,
//! not skip, without the clients: `python3 tests/server/onvif/install_peers.py <dir>` prints
//! `NETGET_ONVIF_PYTHON` and `NETGET_ONVIF_GO_CLIENT`. No LLM calls.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

pub const USER: &str = "admin";
pub const PASSWORD: &str = "s3cret pass";

/// The model: a lobby camera with two profiles, `main` with the PTZ head. A stream for any other
/// profile is refused with InvalidArgVal/NoProfile; a pan past 0.9 is refused (the lobby wall);
/// turning the IR-cut filter OFF and any scope under `forbidden/` are refused; a new subscription
/// is accepted and told the motion alarm is on.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
P=[{'token':'main','name':'Main stream','encoding':'H264','width':1920,'height':1080,'framerate':25,'bitrate':4096,'video_source_token':'lobby_cam','ptz':True},
   {'token':'sub','name':'Sub stream','encoding':'JPEG','width':640,'height':360,'framerate':10,'video_source_token':'lobby_cam'}]
def refuse(sub,det,why): return [{'type':'onvif_fault','subcode':sub,'detail':det,'reason':why}]
a=[]
if t=='onvif_get_device_information':
  a=[{'type':'onvif_device_information','manufacturer':'NetGet Optics','model':'Lobby-9000','firmware_version':'4.2.1','serial_number':'NG-ONVIF-0042','hardware_id':'HW-7'}]
elif t=='onvif_get_scopes':
  a=[{'type':'onvif_scopes','scopes':['onvif://www.onvif.org/name/LobbyCam','onvif://www.onvif.org/location/lobby','onvif://www.onvif.org/Profile/Streaming']}]
elif t=='onvif_get_network_interfaces':
  a=[{'type':'onvif_network_interfaces','interfaces':[{'token':'eth0','name':'eth0','mac':'02:4e:47:00:00:42','ipv4_address':'192.0.2.42','prefix_length':24,'dhcp':False}]}]
elif t=='onvif_get_profiles':
  a=[{'type':'onvif_profiles','profiles':P}]
elif t=='onvif_get_video_sources':
  a=[{'type':'onvif_video_sources','sources':[{'token':'lobby_cam','width':1920,'height':1080,'framerate':25}]}]
elif t=='onvif_get_stream_uri':
  tok=e['profile_token']
  if tok in ('main','sub'):
    a=[{'type':'onvif_stream_uri','uri':'rtsp://192.0.2.42:554/live/'+tok,'timeout_secs':120}]
  else:
    a=[{'type':'onvif_fault','subcode':'InvalidArgVal','detail':'NoProfile','reason':'No such profile'}]
elif t=='onvif_get_snapshot_uri':
  a=[{'type':'onvif_snapshot_uri','uri':'http://192.0.2.42/snapshot/'+e['profile_token']+'.jpg'}]
elif t=='onvif_get_hostname':
  a=[{'type':'onvif_hostname','name':'lobby-cam'}]
elif t=='onvif_ptz_move':
  p=e['proposed']
  if e['kind']=='absolute' and (e['target']['pan'] or 0)>0.9:
    a=refuse('InvalidArgVal','InvalidPosition','The lobby wall is there')
  else:
    a=[{'type':'onvif_ptz_position','pan':p['pan'],'tilt':p['tilt'],'zoom':p['zoom']}]
elif t=='onvif_create_subscription':
  a=[{'type':'onvif_accept'},{'type':'onvif_raise_event','topic':'tns1:VideoSource/MotionAlarm','source':{'Source':'lobby_cam'},'data':{'State':True}}]
elif t=='onvif_set_imaging_settings':
  a=refuse('InvalidArgVal','SettingsInvalid','The IR-cut filter stays on') if e['requested']['ir_cut_filter']=='OFF' else [{'type':'onvif_accept'}]
elif t=='onvif_imaging_move':
  a=[{'type':'onvif_focus_position','position':e['proposed_position']}]
elif t=='onvif_set_scopes':
  a=refuse('OperationProhibited','ScopeOverwrite','Not that scope') if any('forbidden' in s for s in e['scopes']) else [{'type':'onvif_accept'}]
elif t=='onvif_system_reboot':
  a=[{'type':'onvif_accept','message':'Rebooting in 30 seconds'}]
elif t in ('onvif_set_hostname','onvif_set_system_date_and_time'):
  a=[{'type':'onvif_accept'}]
print(json.dumps({'actions':a}))"#;

pub fn env(var: &str) -> String {
    let v = std::env::var(var).unwrap_or_default();
    assert!(
        !v.is_empty(),
        "{var} is required: python3 tests/server/onvif/install_peers.py <dir> and export what it prints"
    );
    v
}

pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> (AppState, ServerId, u16) {
    let (state, id, port, _) = start_logged(handlers, params).await;
    (state, id, port)
}

/// The device's status lines, as they arrive.
pub type StatusLog = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// The operations clients sent, as the device logged them (`service:Operation`), with counts.
pub fn operations(log: &StatusLog) -> std::collections::BTreeMap<String, usize> {
    let mut out = std::collections::BTreeMap::new();
    for line in log.lock().unwrap().iter() {
        if let Some((_, op)) = line.split_once(" request ") {
            *out.entry(op.trim().to_string()).or_insert(0) += 1;
        }
    }
    out
}

pub async fn start_logged(
    handlers: Option<Vec<Value>>,
    params: Value,
) -> (AppState, ServerId, u16, StatusLog) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log: StatusLog = Default::default();
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    let id = ServerForm {
        protocol: "onvif".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a lobby camera".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port, log)
}

pub fn policy() -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
    ])
}

pub fn credentials() -> Value {
    json!({"username": USER, "password": PASSWORD})
}

pub async fn events(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    let mut v: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
    v.into_iter().map(|e| e["request"].clone()).collect()
}

async fn run(program: &str, args: &[String]) -> Value {
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{program} did not finish"))
    .unwrap_or_else(|e| panic!("{program}: {e}"));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{program} failed: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(text.lines().last().unwrap_or_default()).unwrap_or_else(|_| {
        panic!(
            "{program} printed no JSON: {text}{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

async fn zeep(port: u16, password: &str) -> Value {
    let python = env("NETGET_ONVIF_PYTHON");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/onvif/peer/zeep_client.py"
    );
    run(
        &python,
        &[
            "-I".into(),
            script.into(),
            "127.0.0.1".into(),
            port.to_string(),
            USER.into(),
            password.into(),
        ],
    )
    .await
}

async fn go(port: u16, password: &str) -> Value {
    run(
        &env("NETGET_ONVIF_GO_CLIENT"),
        &[format!("127.0.0.1:{port}"), USER.into(), password.into()],
    )
    .await
}

#[tokio::test]
async fn onvif_zeep_async_reads_what_the_model_supplied() {
    let (state, id, port) = start(policy(), credentials()).await;
    let r = zeep(port, PASSWORD).await;

    // It found both services through GetServices, at this server's address.
    assert_eq!(
        r["xaddrs"]["http://www.onvif.org/ver10/media/wsdl"],
        format!("http://127.0.0.1:{port}/onvif/media_service"),
        "{r}"
    );
    assert_eq!(
        r["device_information"],
        json!({"manufacturer": "NetGet Optics", "model": "Lobby-9000", "firmware_version": "4.2.1",
               "serial_number": "NG-ONVIF-0042", "hardware_id": "HW-7"}),
        "{r}"
    );
    assert_eq!(
        r["scopes"],
        json!([
            "onvif://www.onvif.org/name/LobbyCam",
            "onvif://www.onvif.org/location/lobby",
            "onvif://www.onvif.org/Profile/Streaming"
        ]),
        "{r}"
    );
    assert_eq!(
        r["network_interfaces"],
        json!([{"token": "eth0", "name": "eth0", "mac": "02:4e:47:00:00:42", "dhcp": false, "address": "192.0.2.42"}]),
        "{r}"
    );
    assert_eq!(
        r["profiles"],
        json!([
            {"token": "main", "name": "Main stream", "encoding": "H264", "width": 1920, "height": 1080, "source": "lobby_cam"},
            {"token": "sub", "name": "Sub stream", "encoding": "JPEG", "width": 640, "height": 360, "source": "lobby_cam"}
        ]),
        "{r}"
    );
    assert_eq!(
        r["video_sources"],
        json!([{"token": "lobby_cam", "width": 1920, "height": 1080}]),
        "{r}"
    );
    assert_eq!(
        r["stream_uri"]["uri"], "rtsp://192.0.2.42:554/live/main",
        "{r}"
    );
    assert_eq!(
        r["snapshot_uri"]["uri"], "http://192.0.2.42/snapshot/main.jpg",
        "{r}"
    );
    // An operation NetGet does not serve: a fault zeep reads, not silence.
    assert_eq!(
        r["unsupported"]["subcodes"],
        json!(["ActionNotSupported"]),
        "{r}"
    );

    // The model was asked with the authenticated user and the profile zeep chose.
    let asked = events(&state, id, "onvif_get_stream_uri").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["username"], USER);
    assert_eq!(asked[0]["profile_token"], "main");
    assert_eq!(asked[0]["protocol"], "RTSP");
    assert!(events(&state, id, "onvif_not_authorized").await.is_empty());

    // The wrong password: the clock is still readable (it is the one anonymous operation), and
    // every signed request is refused, so zeep cannot find the services.
    let r = zeep(port, "not the password").await;
    assert_eq!(r["connect"]["subcodes"], json!(["NotAuthorized"]), "{r}");
    let refused = events(&state, id, "onvif_not_authorized").await;
    assert!(
        !refused.is_empty() && refused.iter().all(|e| e["reason"] == "bad_digest"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn use_go_onvif_reads_what_the_model_supplied() {
    let (state, id, port) = start(policy(), credentials()).await;
    let r = go(port, PASSWORD).await;
    assert!(r.get("connect_error").is_none(), "{r}");
    assert_eq!(
        r["endpoints"]["media"],
        format!("http://127.0.0.1:{port}/onvif/media_service"),
        "{r}"
    );
    let info = &r["device_information"];
    assert_eq!(info["status"], 200, "{r}");
    assert_eq!(
        info["value"],
        json!({"Manufacturer": "NetGet Optics", "Model": "Lobby-9000", "FirmwareVersion": "4.2.1",
               "SerialNumber": "NG-ONVIF-0042", "HardwareId": "HW-7"}),
        "{r}"
    );
    assert_eq!(
        r["scopes"]["items"],
        json!([
            "onvif://www.onvif.org/name/LobbyCam",
            "onvif://www.onvif.org/location/lobby",
            "onvif://www.onvif.org/Profile/Streaming"
        ]),
        "{r}"
    );
    assert_eq!(
        r["profiles"]["items"],
        json!([{"token": "main", "name": "Main stream"}, {"token": "sub", "name": "Sub stream"}]),
        "{r}"
    );
    assert_eq!(
        r["stream_uri"]["uri"], "rtsp://192.0.2.42:554/live/main",
        "{r}"
    );
    assert_eq!(
        r["snapshot_uri"]["uri"], "http://192.0.2.42/snapshot/main.jpg",
        "{r}"
    );
    // The model refused a profile it does not have, and Go read the fault the SOAP 1.2 way.
    assert_eq!(r["missing_profile"]["status"], 400, "{r}");
    assert_eq!(
        r["missing_profile"]["fault"], "env:Sender/ter:InvalidArgVal",
        "{r}"
    );
    let asked = events(&state, id, "onvif_get_stream_uri").await;
    assert_eq!(
        asked
            .iter()
            .map(|e| e["profile_token"].clone())
            .collect::<Vec<_>>(),
        vec![json!("main"), json!("nonexistent")]
    );

    let r = go(port, "not the password").await;
    assert!(
        r["connect_error"]
            .as_str()
            .is_some_and(|e| e.contains("not available")),
        "use-go/onvif connected with the wrong password: {r}"
    );
    let refused = events(&state, id, "onvif_not_authorized").await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["operation"], "GetCapabilities");
    assert_eq!(refused[0]["reason"], "bad_digest");
}
