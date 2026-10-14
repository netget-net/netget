//! NetGet's ONVIF client against **RPOS** (BreeeZe/rpos at a pinned commit), the Node.js ONVIF
//! camera, run as a subprocess. RPOS verifies every WS-Security PasswordDigest itself
//! (`lib/SoapService.ts`: Base64(SHA-1(nonce + created + password))) and answers a wrong one
//! with ter:NotAuthorized, so a connection that works is RPOS accepting NetGet's digest, and the
//! wrong password is RPOS refusing it.
//!
//! A python chain is the model: on connect it asks for device information, scopes, network
//! interfaces, video sources and profiles; on the profiles it asks for the stream and snapshot
//! URIs of the profile RPOS listed. The profile token is asserted in RPOS's own log of the
//! request it received, and RPOS's answers in NetGet's events. `NETGET_RPOS` comes from
//! `tests/server/onvif/install_peers.py`; the test fails rather than skips without it. No LLM
//! calls.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='onvif_connected':
  a=[{'type':'onvif_get_device_information'},{'type':'onvif_get_scopes'},{'type':'onvif_get_network_interfaces'},
     {'type':'onvif_get_video_sources'},{'type':'onvif_get_profiles'}]
elif e.get('operation')=='GetProfiles' and e['ok']:
  tok=e['result']['profiles'][-1]['token']
  a=[{'type':'onvif_get_stream_uri','profile_token':tok,'protocol':'RTSP'},{'type':'onvif_get_snapshot_uri','profile_token':tok}]
print(json.dumps({'actions':a}))"#;

fn rpos_dir() -> String {
    let v = std::env::var("NETGET_RPOS").unwrap_or_default();
    assert!(
        !v.is_empty(),
        "NETGET_RPOS is required: python3 tests/server/onvif/install_peers.py <dir> and export what it prints"
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

struct Rpos {
    _child: tokio::process::Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Rpos {
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("rpos.log")).unwrap_or_default()
    }
}

/// RPOS on a free port with user admin, its own RTSP server off (it hands out the URI of an
/// external one), all its log output kept.
async fn rpos() -> Rpos {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = json!({
        "NetworkAdapters": [], "IpAddress": "127.0.0.1", "ServicePort": port,
        "Username": "admin", "Password": "rpos-secret",
        "CameraType": "testsrc", "CameraDevice": "",
        "RTSPAddress": "127.0.0.1", "RTSPPort": 8554, "RTSPName": "netget-evidence",
        "MulticastEnabled": false, "RTSPMulticastName": "h264m", "MulticastAddress": "224.0.0.1", "MulticastPort": "10001",
        "RTSPServer": 0, "PTZDriver": "none", "PTZOutput": "none", "PTZSerialPort": "",
        "PTZSerialPortSettings": {"baudRate": 2400, "dataBits": 8, "parity": "none", "stopBits": 1},
        "PTZOutputURL": "127.0.0.1:9999", "PTZCameraAddress": 1,
        "DeviceInformation": {"Manufacturer": "RPOS Evidence", "Model": "Peer", "HardwareId": "HW-RPOS", "SerialNumber": "RPOS-0001"},
        "logLevel": 4, "logSoapCalls": true
    });
    let config_path = dir.path().join("rposConfig.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let log = std::fs::File::create(dir.path().join("rpos.log")).unwrap();
    let home = rpos_dir();
    let child = tokio::process::Command::new("node")
        .arg(format!("{home}/rpos.js"))
        .arg("--config")
        .arg(&config_path)
        // RPOS reads its WSDL files relative to the working directory.
        .current_dir(&home)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .expect("node");
    let rpos = Rpos {
        _child: child,
        port,
        dir,
    };
    let up = tokio::time::timeout(Duration::from_secs(60), async {
        while !rpos.log().contains("media_service started")
            || tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(up.is_ok(), "RPOS never came up:\n{}", rpos.log());
    rpos
}

async fn client(rpos: &Rpos, password: &str) -> (AppState, anyhow::Result<ClientId>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "onvif".into(),
        remote_addr: Some(format!("127.0.0.1:{}", rpos.port)),
        instruction: Some("Find the camera's stream".into()),
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

#[tokio::test]
async fn netget_reads_rpos_with_a_digest_rpos_verifies() {
    let rpos = rpos().await;
    let (state, id) = client(&rpos, "rpos-secret").await;
    let id = id.unwrap_or_else(|e| panic!("connect: {e:#}\n{}", rpos.log()));

    // Five reads on connect, then the stream and snapshot URIs of the profile RPOS listed.
    let all = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let r = responses(&state, id).await;
            if r.len() >= 7 {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the chain did not finish\n{}", rpos.log()));
    let by_op = |op: &str| -> Value {
        all.iter()
            .find(|r| r["operation"] == op)
            .cloned()
            .unwrap_or_else(|| panic!("no {op} in {all:?}"))
    };
    for r in &all {
        assert_eq!(r["ok"], true, "{r}\n{}", rpos.log());
    }
    assert_eq!(
        by_op("GetDeviceInformation")["result"],
        json!({"manufacturer": "RPOS Evidence", "model": "Peer", "firmware_version": "2.1.0",
               "serial_number": "RPOS-0001", "hardware_id": "HW-RPOS"})
    );
    let profiles = by_op("GetProfiles");
    let token = profiles["result"]["profiles"][0]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(token, "profile_token", "{profiles}");
    assert_eq!(profiles["result"]["profiles"][0]["encoding"], "H264");
    let stream = by_op("GetStreamUri");
    assert_eq!(stream["request"]["profile_token"], token.as_str());
    assert_eq!(
        stream["result"]["uri"], "rtsp://127.0.0.1:8554/netget-evidence",
        "{stream}"
    );
    assert!(
        by_op("GetSnapshotUri")["result"]["uri"]
            .as_str()
            .is_some_and(|u| u.starts_with("http://")),
        "{all:?}"
    );
    assert!(
        by_op("GetScopes")["result"]["scopes"]
            .as_array()
            .is_some_and(|s| !s.is_empty()),
        "{all:?}"
    );
    assert!(
        by_op("GetVideoSources")["result"]["sources"][0]["token"].is_string(),
        "{all:?}"
    );
    assert!(by_op("GetNetworkInterfaces")["result"]["interfaces"].is_array());

    // What RPOS itself received: the model's profile token, under a digest it accepted.
    let log = rpos.log();
    assert!(
        log.contains(&format!("ProfileToken>{token}</")) && log.contains("GetStreamUri"),
        "RPOS never saw the model's GetStreamUri:\n{log}"
    );
    assert!(!log.contains("Invalid username/password"), "{log}");

    // An injected action runs through the same session and answers with the result.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "onvif_get_device_information"}),
            Duration::from_secs(30),
        )
        .await;
    match outcome {
        Ok(ClientSendOutcome::Executed { detail }) => {
            assert!(detail.contains("RPOS Evidence"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn rpos_refuses_the_wrong_password_and_the_connection_fails() {
    let rpos = rpos().await;
    let (_state, id) = client(&rpos, "not-the-password").await;
    let err = format!("{:#}", id.expect_err("connected with the wrong password"));
    assert!(err.contains("NotAuthorized"), "{err}");
    assert!(
        rpos.log().contains("Invalid username/password"),
        "RPOS did not check the digest:\n{}",
        rpos.log()
    );
}
