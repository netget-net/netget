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
    rpos_with(None).await
}

/// RPOS, with its `rposascii` PTZ driver writing every PTZ and imaging command it executes to
/// `ptz_output` (a TCP address) when one is given: RPOS's own record of what it did.
async fn rpos_with(ptz_output: Option<std::net::SocketAddr>) -> Rpos {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut config = json!({
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
    if let Some(out) = ptz_output {
        config["PTZDriver"] = json!("rposascii");
        config["PTZOutput"] = json!("tcp");
        config["PTZOutputURL"] = json!(out.to_string());
    }
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
    client_with(rpos, password, CHAIN).await
}

async fn client_with(
    rpos: &Rpos,
    password: &str,
    chain: &str,
) -> (AppState, anyhow::Result<ClientId>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "onvif".into(),
        remote_addr: Some(format!("127.0.0.1:{}", rpos.port)),
        instruction: Some("Find the camera's stream".into()),
        startup_params: Some(json!({"username": "admin", "password": password})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":chain}}),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

/// The model drives RPOS's PTZ head and imaging: moves, stop, a preset set, listed, gone to and
/// removed, home; imaging settings read and changed, a focus move and stop. Each request it
/// accepts is asserted in the command RPOS's rposascii PTZ driver wrote for it.
const PTZ_CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='onvif_connected':
  a=[{'type':'onvif_get_profiles'},{'type':'onvif_ptz_get_nodes'},{'type':'onvif_ptz_get_configurations'}]
elif e.get('operation')=='GetProfiles' and e['ok']:
  p=e['result']['profiles'][0]['token']
  a=[{'type':'onvif_ptz_get_status','profile_token':p},
     {'type':'onvif_ptz_absolute_move','profile_token':p,'pan':0.5,'tilt':-0.25,'zoom':0.1},
     {'type':'onvif_ptz_relative_move','profile_token':p,'pan':0.1,'tilt':0.2},
     {'type':'onvif_ptz_continuous_move','profile_token':p,'pan':-0.5,'tilt':0.0,'timeout_secs':5},
     {'type':'onvif_ptz_stop','profile_token':p},
     {'type':'onvif_ptz_set_preset','profile_token':p,'preset_name':'Door'},
     {'type':'onvif_ptz_get_presets','profile_token':p},
     {'type':'onvif_ptz_goto_home','profile_token':p},
     {'type':'onvif_get_video_sources'}]
elif e.get('operation')=='GetPresets' and e['ok'] and e['result']['presets']:
  p=e['request']['profile_token']; tok=e['result']['presets'][0]['token']
  a=[{'type':'onvif_ptz_goto_preset','profile_token':p,'preset_token':tok},
     {'type':'onvif_ptz_remove_preset','profile_token':p,'preset_token':tok}]
elif e.get('operation')=='GetVideoSources' and e['ok']:
  s=e['result']['sources'][0]['token']
  a=[{'type':'onvif_imaging_get_settings','video_source_token':s},
     {'type':'onvif_imaging_get_options','video_source_token':s},
     {'type':'onvif_imaging_set_settings','video_source_token':s,'brightness':70},
     {'type':'onvif_imaging_move','video_source_token':s,'kind':'continuous','speed':0.5},
     {'type':'onvif_imaging_stop','video_source_token':s},
     {'type':'onvif_imaging_get_status','video_source_token':s}]
print(json.dumps({'actions':a}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_drives_rpos_ptz_head_and_imaging() {
    // RPOS's rposascii driver connects here and writes one line per command it executed.
    let driver = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let driver_addr = driver.local_addr().unwrap();
    let commands = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = commands.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = driver.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await {
                    if n == 0 {
                        break;
                    }
                    sink.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            });
        }
    });
    let rpos = rpos_with(Some(driver_addr)).await;
    let (state, id) = client_with(&rpos, "rpos-secret", PTZ_CHAIN).await;
    let id = id.unwrap_or_else(|e| panic!("connect: {e:#}\n{}", rpos.log()));
    // 3 on connect, 9 on the profiles, 2 on the presets, 6 on the sources.
    let all = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let r = responses(&state, id).await;
            if r.len() >= 20 {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the chain did not finish:\n{}\nRPOS's driver got:\n{}",
            rpos.log(),
            commands.lock().unwrap()
        )
    });
    let sent: Vec<String> = all
        .iter()
        .map(|r| {
            format!(
                "{}:{}",
                r["service"].as_str().unwrap_or("?"),
                r["operation"].as_str().unwrap_or("?")
            )
        })
        .collect();
    println!("NetGet sent RPOS {} operations: {sent:?}", sent.len());
    for r in &all {
        assert_eq!(r["ok"], true, "{r}\n{}", rpos.log());
    }
    let by = |service: &str, op: &str| -> Value {
        all.iter()
            .find(|r| r["service"] == service && r["operation"] == op)
            .cloned()
            .unwrap_or_else(|| panic!("no {service}:{op} in {sent:?}"))
    };
    assert_eq!(
        by("ptz", "GetNodes")["result"]["nodes"][0]["token"],
        "ptz_node_token_0"
    );
    assert_eq!(
        by("ptz", "GetConfigurations")["result"]["configurations"][0]["node_token"],
        "ptz_node_token_0"
    );
    assert!(by("ptz", "GetStatus")["result"]["utc_time"].is_string());
    let presets = by("ptz", "GetPresets");
    assert_eq!(presets["result"]["presets"][0]["name"], "Door", "{presets}");
    assert_eq!(by("ptz", "SetPreset")["result"]["preset_token"], "1");
    let brightness = by("imaging", "GetOptions")["result"]["brightness"].clone();
    assert_eq!(
        (brightness["min"].as_f64(), brightness["max"].as_f64()),
        (Some(0.0), Some(100.0)),
        "{brightness}"
    );
    assert!(by("imaging", "GetImagingSettings")["result"]["brightness"].is_number());

    // What RPOS's PTZ driver executed, in RPOS's own words.
    let wrote = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let c = commands.lock().unwrap().clone();
            if c.contains("focusstop") && c.contains("clearpreset") {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| commands.lock().unwrap().clone());
    println!("RPOS's rposascii driver wrote:\n{wrote}");
    for line in [
        "absolute-ptz\t0.5\t-0.25\t0.1",
        "relative-ptz\t0.1\t0.2\t",
        "ptz\t-0.5\t0\t",
        "ptz\t0\t0\t0",
        "setpreset\tDoor\t1",
        "gotohome",
        "gotopreset\tDoor\t1",
        "clearpreset\tDoor\t1",
        "brightness\t70",
        "focus\t0.5",
        "focusstop",
    ] {
        assert!(
            wrote.contains(line),
            "RPOS never executed {line:?}; its driver wrote:\n{wrote}\n{}",
            rpos.log()
        );
    }
}
