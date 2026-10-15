//! NetGet's SPICE client against **QEMU's spice-server** (`qemu-system-x86_64 -spice`,
//! `apt-get install qemu-system-x86 qemu-system-modules-spice`), failing rather than skipping
//! when QEMU or its SPICE module is absent.
//!
//! The VM has no disk and no network: it is started paused, so the display is the blank
//! 640x480 surface the VGA device starts with, and resumed over QMP, after which SeaBIOS
//! switches to 80x25 text mode (a 720x400 surface) and writes on it. That is real display
//! content the client did not choose, and it changes under the client's feet, which is what
//! the test asserts. The model's keystrokes and click are read back from QEMU's own input trace
//! events (`input_event_key_qcode`, `input_event_btn`), on the far side of spice-server. A
//! wrong password is refused by spice-server itself.
//!
//! No LLM calls: a python script plays the model.
use crate::helpers::pcap_oracle::PcapOracle;
use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::recording_relay;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const QEMU: InstallHint = InstallHint {
    brew: "qemu (Homebrew's QEMU is built without SPICE; run this test on Linux)",
    apt: "qemu-system-x86 qemu-system-modules-spice",
};
const PASSWORD: &str = "qemu-Spice-7";

/// The model: once the screen it reads is SeaBIOS's 720x400 text mode, type `a1`, press
/// Escape and click.
const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='spice_screen' and e.get('width')==720 and e.get('height')==400 and e.get('distinct_colors',1)>1:
  a=[{'type':'spice_type','text':'a1'},{'type':'spice_keys','keys':['esc']},{'type':'spice_mouse','x':100,'y':100,'action':'click'}]
print(json.dumps({'actions':a}))"#;

async fn qemu() -> RealServer {
    let server = RealServer::builder("qemu-system-x86_64", QEMU)
        .extra_ports(1)
        .args([
            "-machine",
            "pc",
            "-m",
            "64",
            "-nodefaults",
            "-vga",
            "std",
            "-display",
            "none",
            "-nic",
            "none",
            "-S",
            "-object",
            &format!("secret,id=sec0,data={PASSWORD}"),
            "-spice",
            "port={port},addr=127.0.0.1,password-secret=sec0",
            "-qmp",
            "tcp:127.0.0.1:{port1},server=on,wait=off",
            // spice-server hands QEMU scancodes, which its input layer traces as qcodes.
            "-trace",
            "input_event_key_qcode",
            "-trace",
            "input_event_key_number",
            "-trace",
            "input_event_btn",
        ])
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await;
    match server {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    }
}

/// Resume the paused VM over QMP.
async fn cont(qmp_port: u16) {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", qmp_port))
        .await
        .expect("QMP");
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    let greeting = lines.next_line().await.unwrap().unwrap_or_default();
    assert!(greeting.contains("QMP"), "{greeting}");
    for cmd in [r#"{"execute":"qmp_capabilities"}"#, r#"{"execute":"cont"}"#] {
        w.write_all(format!("{cmd}\n").as_bytes()).await.unwrap();
        loop {
            let line = lines.next_line().await.unwrap().unwrap_or_default();
            if line.contains("\"return\"") {
                break;
            }
            assert!(!line.contains("\"error\""), "QMP: {line}");
        }
    }
}

async fn client(addr: &str, password: &str) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "SPICE".into(),
        remote_addr: Some(addr.into()),
        instruction: Some("Use the VM's console".into()),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": POLICY}
        })]),
        startup_params: Some(json!({"password": password})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok((state, id))
}

async fn read_screen(state: &AppState, id: ClientId) -> Value {
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "spice_read_screen", "grid": 4, "settle_ms": 500, "points": [[4, 4]]}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let ClientSendOutcome::Executed { detail } = outcome else {
        panic!("{outcome:?}")
    };
    serde_json::from_str(&detail).unwrap()
}

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .map(|e| e["request"].clone())
        .collect()
}

/// Wait until `kind` has been raised at least once.
async fn wait_events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    for _ in 0..600 {
        let v = events(state, id, kind).await;
        if !v.is_empty() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the client never raised {kind}");
}

#[tokio::test]
async fn qemu_display_is_read_and_the_models_keys_and_click_reach_the_guest() {
    let vm = qemu().await;
    let qmp = vm.extra_ports[0];
    let (relay, streams) = recording_relay::tcp_relay(([127, 0, 0, 1], vm.port).into()).await;
    let (state, id) = client(&relay.to_string(), PASSWORD)
        .await
        .unwrap_or_else(|e| panic!("{e:#}\n{}", vm.log()));
    let connected = wait_events(&state, id, "spice_connected").await;
    assert_eq!(connected.len(), 1);
    let channels = connected[0]["channels"].to_string();
    assert!(
        channels.contains("display") && channels.contains("inputs"),
        "{channels}"
    );
    assert!(connected[0]["name"]
        .as_str()
        .unwrap_or_default()
        .starts_with("QEMU"));

    // Paused: the VGA device's initial surface, before the guest has touched it.
    let paused = read_screen(&state, id).await;
    assert_eq!(paused["surface"], true, "{paused}");
    println!("paused: {paused}");
    cont(qmp).await;

    // SeaBIOS switches the VGA to 80x25 text mode, 720x400, and writes on it.
    let mut booted = Value::Null;
    for _ in 0..60 {
        booted = read_screen(&state, id).await;
        if booted["width"] == 720
            && booted["height"] == 400
            && booted["distinct_colors"].as_u64().unwrap_or(0) > 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    println!("booted: {booted}");
    assert_eq!(
        (booted["width"].clone(), booted["height"].clone()),
        (json!(720), json!(400))
    );
    assert!(booted["distinct_colors"].as_u64().unwrap() > 1, "{booted}");
    assert_ne!(
        booted["checksum"], paused["checksum"],
        "the screen never changed"
    );
    // The client asked for uncompressed images, and spice-server sent them, so the picture is
    // exact.
    assert_eq!(booted["exact"], true, "{booted}");
    assert!(
        booted["images"]["bitmap"].as_u64().unwrap_or(0) > 0,
        "{booted}"
    );
    assert!(booted["images"].get("lz_rgb").is_none(), "{booted}");
    // The surface SeaBIOS's text sits on is black.
    assert_eq!(booted["dominant_color"], "#000000");

    // The model saw that screen and typed `a1`, pressed Escape and clicked: QEMU's input layer
    // traced each key and the button.
    let want = [
        "key qcode a, down 1",
        "key qcode a, down 0",
        "key qcode 1, down 1",
        "key qcode esc, down 1",
        "key qcode esc, down 0",
    ];
    let mut log = String::new();
    for _ in 0..60 {
        log = vm.log();
        if want.iter().all(|w| log.contains(w)) && log.contains("input_event_btn") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    for w in want {
        assert!(
            log.contains(w),
            "QEMU never traced {w:?}:\n{log}\nclient errors: {:?}",
            events(&state, id, "spice_error").await
        );
    }
    assert!(
        log.contains("button left, down 1") && log.contains("button left, down 0"),
        "QEMU never traced the click:\n{log}"
    );

    // Both directions of every channel, through tshark's spice dissector.
    let _ = state
        .send_to_client(id, json!({"type": "disconnect"}), Duration::from_secs(10))
        .await;
    let streams = streams.lock().unwrap().clone();
    assert!(streams.len() >= 3, "main, display and inputs");
    for rec in streams {
        let chunks = rec.lock().unwrap().clone();
        let mut oracle = PcapOracle::tcp("spice");
        for (to_server, bytes) in &chunks {
            oracle = if *to_server {
                oracle.to_server(bytes)
            } else {
                oracle.from_server(bytes)
            };
        }
        oracle.assert_clean();
    }
}

#[tokio::test]
async fn qemu_refuses_a_wrong_password() {
    let vm = qemu().await;
    let err = client(&vm.addr(), "not-the-password")
        .await
        .err()
        .expect("QEMU admitted a wrong password");
    assert!(format!("{err:#}").contains("permission denied"), "{err:#}");
    // And with the right one it is admitted.
    let (_state, _id) = client(&vm.addr(), PASSWORD)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
}
