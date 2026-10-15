//! The client's bounds and its refusal to believe a reply, against canned KDCs and NetGet's own
//! KDC (which here is a convenient peer, not evidence): an oversized declared reply, a DER depth
//! bomb, an AS-REP for a different request (wrong nonce), a service ticket asked for before any
//! TGT, and a model that asks for a TGT forever, stopped at `MAX_FOLLOWUP_DEPTH`.

use netget::cli::management::{ClientForm, ServerForm};
use netget::client::kerberos::MAX_FOLLOWUP_DEPTH;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const REALM: &str = "NETGET.TEST";

async fn client(kdc: SocketAddr, transport: &str, chain: &str) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "kerberos".into(),
        remote_addr: Some(kdc.to_string()),
        instruction: Some("Get tickets".into()),
        startup_params: Some(json!({
            "principal": format!("alice@{REALM}"),
            "password": "alice-pw",
            "transport": transport,
            "timeout_ms": 2000,
            "retries": 0
        })),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":chain}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap();
    (state, id)
}

const TGT_ONCE: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
print(json.dumps({'actions':[{'type':'kerberos_request_tgt'}] if t=='kerberos_client_ready' else []}))"#;

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

async fn first_failure(state: &AppState, id: ClientId) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(e) = events(state, id, "kerberos_request_failed")
                .await
                .into_iter()
                .next()
            {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("no kerberos_request_failed event")
}

/// A TCP "KDC" that answers every request with `reply` (already framed or not).
async fn canned_tcp(reply: Vec<u8>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut prefix = [0u8; 4];
                if s.read_exact(&mut prefix).await.is_ok() {
                    let mut body = vec![0u8; u32::from_be_bytes(prefix) as usize];
                    let _ = s.read_exact(&mut body).await;
                    let _ = s.write_all(&reply).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn an_oversized_reply_is_refused_before_it_is_read() {
    let kdc = canned_tcp(0x0010_0000u32.to_be_bytes().to_vec()).await;
    let (state, id) = client(kdc, "tcp", TGT_ONCE).await;
    let f = first_failure(&state, id).await;
    assert_eq!(f["kind"], "oversize", "{f}");
}

#[tokio::test]
async fn a_depth_bomb_reply_is_refused() {
    let mut bomb = vec![0x05, 0x00];
    for _ in 0..60 {
        let mut outer = vec![0x30, bomb.len() as u8];
        outer.extend_from_slice(&bomb);
        bomb = outer;
    }
    let mut reply = vec![0x6b, bomb.len() as u8];
    reply.extend_from_slice(&bomb);
    let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&reply);
    let kdc = canned_tcp(framed).await;
    let (state, id) = client(kdc, "tcp", TGT_ONCE).await;
    let f = first_failure(&state, id).await;
    assert_eq!(f["kind"], "malformed", "{f}");
    assert!(
        f["message"].as_str().unwrap().contains("nesting deeper"),
        "{f}"
    );
}

/// NetGet's KDC with alice exempt from pre-authentication and a rule that admits everything.
async fn open_kdc() -> (AppState, netget::state::ServerId, SocketAddr) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "kerberos".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        startup_params: Some(json!({
            "realm": REALM,
            "principal_passwords": {"alice": "alice-pw", "host/svc.netget.test": "svc"},
            "no_preauth_principals": ["alice"],
            "max_requests_per_minute_per_source": 100000
        })),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"kerberos_issue_ticket"}]}})]),
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
    (state, id, ([127, 0, 0, 1], port).into())
}

#[tokio::test]
async fn a_reply_to_a_different_request_is_not_believed() {
    let (_kdc_state, _, kdc) = open_kdc().await;
    // Record one genuine AS-REP (for some other request's nonce)...
    let recorded: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let rec = recorded.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 70_000];
        while let Ok((n, peer)) = front.recv_from(&mut buf).await {
            let held = rec.lock().unwrap().clone();
            let reply = match held {
                // ...and answer every later request with it.
                Some(r) => r,
                None => {
                    let up = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    up.send_to(&buf[..n], kdc).await.unwrap();
                    let mut b = vec![0u8; 70_000];
                    let (m, _) = up.recv_from(&mut b).await.unwrap();
                    *rec.lock().unwrap() = Some(b[..m].to_vec());
                    b[..m].to_vec()
                }
            };
            let _ = front.send_to(&reply, peer).await;
        }
    });
    let (state, id) = client(front_addr, "udp", TGT_ONCE).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while events(&state, id, "kerberos_tgt_obtained").await.is_empty() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the first, genuine exchange");
    let (state, id) = client(front_addr, "udp", TGT_ONCE).await;
    let f = first_failure(&state, id).await;
    assert_eq!(f["kind"], "integrity", "{f}");
    assert!(f["message"].as_str().unwrap().contains("nonce"), "{f}");
    assert!(events(&state, id, "kerberos_tgt_obtained").await.is_empty());
}

#[tokio::test]
async fn a_service_ticket_needs_a_tgt_first() {
    let (_kdc_state, _, kdc) = open_kdc().await;
    let chain = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
print(json.dumps({'actions':[{'type':'kerberos_request_service_ticket','service':'host/svc.netget.test'}] if t=='kerberos_client_ready' else []}))"#;
    let (state, id) = client(kdc, "udp", chain).await;
    let f = first_failure(&state, id).await;
    assert_eq!(f["kind"], "no_tgt", "{f}");
}

#[tokio::test]
async fn a_model_that_never_stops_is_stopped_at_the_depth_bound() {
    let (kdc_state, kdc_id, kdc) = open_kdc().await;
    let forever = r#"import json,sys
print(json.dumps({'actions':[{'type':'kerberos_request_tgt'}]}))"#;
    let (_state, _id) = client(kdc, "tcp", forever).await;
    // Counted where the requests land: the model is asked about the ready event (depth 0) and
    // about each TGT up to depth MAX_FOLLOWUP_DEPTH - 1, so the KDC sees exactly that many
    // AS-REQs and no more.
    let as_requests = || async {
        kdc_state
            .list_access_logs_for(Some(AccessLogOwner::Server(kdc_id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == "kerberos_as_request")
            .count()
    };
    let want = MAX_FOLLOWUP_DEPTH as usize;
    tokio::time::timeout(Duration::from_secs(60), async {
        while as_requests().await < want {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the chain never reached its bound");
    let settled = tokio::time::timeout(Duration::from_secs(2), async {
        while as_requests().await == want {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(settled.is_err(), "the chain went past MAX_FOLLOWUP_DEPTH");
}
