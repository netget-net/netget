//! NetGet's libp2p dialler against **go-libp2p** listening (TCP, Noise, yamux;
//! `libp2p-peer listen`, named by `NETGET_LIBP2P_GO_PEER`). go-libp2p identifies NetGet,
//! echoes what NetGet says on /netget/chat/1.0.0 and opens a stream of its own to NetGet.
//! Fails rather than skips without the peer. No LLM calls: a python chain is the model.
//!
//! The chain: on connecting, say hello on a new chat stream; once it is open, ping; answer
//! any message that is not an echo with an echo of it.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='libp2p_connected':
  a=[{'type':'libp2p_open_stream','protocol':'/netget/chat/1.0.0','data':'hello from netget'}]
elif t=='libp2p_response' and e['operation']=='libp2p_open_stream' and e['ok']:
  a=[{'type':'libp2p_ping'}]
elif t=='libp2p_message' and not e['data'].startswith('echo: '):
  a=[{'type':'libp2p_send','stream_id':e['stream_id'],'data':'echo: '+e['data']}]
print(json.dumps({'actions':a}))"#;

pub fn peer() -> String {
    let p = std::env::var("NETGET_LIBP2P_GO_PEER").unwrap_or_default();
    assert!(
        !p.is_empty() && std::path::Path::new(&p).exists(),
        "NETGET_LIBP2P_GO_PEER must name the go-libp2p peer: python3 tests/server/libp2p/install_peers.py <dir>"
    );
    p
}

async fn wait_event(state: &AppState, id: ClientId, pred: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| pred(e))
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no matching event")
}

#[tokio::test]
async fn netget_dials_go_libp2p() {
    let mut go = tokio::process::Command::new(peer())
        .arg("listen")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(go.stdout.take().unwrap()).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let addr = first["addr"].as_str().unwrap().to_string();

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "libp2p".into(),
        remote_addr: Some(addr.clone()),
        instruction: Some("Say hello and answer".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .expect("connect");

    // What go-libp2p saw: NetGet's identify, NetGet's message, and NetGet's echo of its own.
    let mut seen: Vec<Value> = Vec::new();
    let wanted = ["identify", "inbound", "outbound"];
    tokio::time::timeout(Duration::from_secs(60), async {
        while !wanted.iter().all(|w| seen.iter().any(|s| s["step"] == *w)) {
            let Ok(Some(l)) = lines.next_line().await else {
                break;
            };
            seen.push(serde_json::from_str(&l).unwrap_or_else(|e| panic!("{e}: {l}")));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("go-libp2p never saw everything: {seen:?}"));
    let step = |name: &str| {
        seen.iter()
            .find(|s| s["step"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name}: {seen:?}"))
    };
    let identify = step("identify");
    assert!(
        identify["agent"].as_str().unwrap().starts_with("netget/"),
        "{identify}"
    );
    assert!(
        identify["protocols"]
            .as_array()
            .unwrap()
            .contains(&json!("/netget/chat/1.0.0")),
        "{identify}"
    );
    assert_eq!(step("inbound")["body"], "hello from netget", "{seen:?}");
    assert_eq!(
        step("outbound")["replies"],
        json!(["echo: hi from go"]),
        "NetGet answered the stream go opened: {seen:?}"
    );

    // What NetGet saw.
    let connected = wait_event(&state, id, |e| e["event_type"] == "libp2p_connected").await;
    assert_eq!(
        connected["agent_version"], "netget-test-go-peer",
        "{connected}"
    );
    assert_eq!(
        connected["peer_id"].as_str(),
        addr.rsplit('/').next(),
        "{connected}"
    );
    let echo = wait_event(&state, id, |e| {
        e["event_type"] == "libp2p_message" && e["request"]["data"] == "echo: hello from netget"
    })
    .await;
    assert_eq!(echo["protocol"], "/netget/chat/1.0.0");
    let ping = wait_event(&state, id, |e| {
        e["event_type"] == "libp2p_response" && e["request"]["operation"] == "libp2p_ping"
    })
    .await;
    assert_eq!(ping["ok"], true, "{ping}");
    let from_go = wait_event(&state, id, |e| {
        e["event_type"] == "libp2p_message" && e["request"]["data"] == "hi from go"
    })
    .await;
    assert_eq!(
        from_go["stream_id"].as_u64().unwrap() % 2,
        0,
        "the listener's streams are even"
    );

    // Injected: identify again, a protocol go does not speak, a stream that does not exist.
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"libp2p_identify"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { detail } if detail.contains("/ipfs/ping/1.0.0")),
        "{outcome:?}"
    );
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"libp2p_open_stream","protocol":"/nope/1.0.0"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { detail } if detail.contains("\"ok\":false")),
        "{outcome:?}"
    );
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"libp2p_send","stream_id":999,"data":"x"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("no open stream 999")),
        "{outcome:?}"
    );
    drop(go);
}

#[tokio::test]
async fn a_wrong_peer_id_fails_the_connect() {
    let mut go = tokio::process::Command::new(peer())
        .arg("listen")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(go.stdout.take().unwrap()).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let addr = first["addr"].as_str().unwrap();
    let base = addr.rsplit_once("/p2p/").unwrap().0;
    let other = netget::server::libp2p::noise::Identity::from_seed([9; 32]).peer_id_string();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let err = ClientForm {
        protocol: "libp2p".into(),
        remote_addr: Some(format!("{base}/p2p/{other}")),
        instruction: Some("x".into()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await;
    let text = format!("{err:?}");
    assert!(text.contains("but the remote is"), "{text}");
    drop(go);
}
