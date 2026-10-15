//! The cluster client's redirection bound, against two NetGet Redis servers that disagree about
//! who owns a slot — each answers `-MOVED` to the other, forever.
//!
//! A real cluster never does this for long, which is exactly why it needs a test of its own:
//! without `MAX_REDIRECTS` the client would bounce between the two until something else killed
//! it. With it, the command stops after five redirections and the model is shown the last
//! `MOVED` with `redirects_exhausted: true`. The same file checks the client fails closed on
//! the seed: a node that is not a cluster node is refused at connect.
//!
//! These servers are NetGet's own, so this is a test of the bound, not interoperability
//! evidence (that is `cluster_real_server_test.rs`). LLM calls: 2.

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::{ClientForm, ServerForm};
use netget::client::redis::cluster::MAX_REDIRECTS;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::utils::redis_keys::key_hash_slot;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Every slot but `slot` to `me`, `slot` to the other node.
fn split_topology(me: u16, other: u16, slot: u16) -> Value {
    let mut mine = Vec::new();
    if slot > 0 {
        mine.push(format!("0-{}", slot - 1));
    }
    if slot < 16383 {
        mine.push(format!("{}-16383", slot + 1));
    }
    json!([
        {"host":"127.0.0.1","port":me,"slots":mine,"myself":true},
        {"host":"127.0.0.1","port":other,"slots":[slot.to_string()]},
    ])
}

async fn port_of(state: &AppState, id: netget::state::ServerId) -> u16 {
    for _ in 0..1500 {
        if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
            return a.port();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server never bound");
}

#[tokio::test]
async fn redirections_stop_at_the_bound() {
    let shown: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let seen = shown.clone();
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("redis_connected")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("redirects_exhausted", "true")
            .respond_with_actions_from_event(move |e| {
                *seen.lock().unwrap() = Some(e.clone());
                json!([])
            })
            .expect_calls(1)
            .and()
            .build(),
    )
    .await
    .expect("mock");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;

    // Two free ports, then two servers that each say the slot is the other's.
    let slot = key_hash_slot(b"loop");
    let mut ports = Vec::new();
    {
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.push(a.local_addr().unwrap().port());
        ports.push(b.local_addr().unwrap().port());
    }
    for (me, other) in [(ports[0], ports[1]), (ports[1], ports[0])] {
        let (tx, _) = mpsc::unbounded_channel();
        let id = ServerForm {
            protocol: "redis".into(),
            port: Some(me),
            host: Some("127.0.0.1".into()),
            instruction: Some(String::new()),
            startup_params: Some(json!({"cluster_nodes": split_topology(me, other, slot)})),
            event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"redis_simple_string","value":"OK"}]}})]),
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .unwrap();
        assert_eq!(port_of(&state, id).await, me);
    }

    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "redis".to_string(),
        remote_addr: Some(format!("127.0.0.1:{}", ports[0])),
        instruction: Some("Report what happens.".to_string()),
        startup_params: Some(json!({"cluster": true})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await
    .expect("cluster client");
    for _ in 0..1200 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let sent = state
        .send_to_client(
            client_id,
            json!({"type": "execute_redis_command", "command": "GET loop"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.expect("mock expectations");
    let event = shown
        .lock()
        .unwrap()
        .clone()
        .expect("the model was shown the result");
    assert_eq!(
        event["redirects"].as_array().map(Vec::len),
        // The documented number, written out: comparing against the constant itself would
        // move with any change to it, and pass.
        Some(5),
        "{event}"
    );
    assert_eq!(
        MAX_REDIRECTS, 5,
        "the documented bound changed; update AGENTS.md too"
    );
    assert_eq!(event["reply_type"], json!("error"));
    assert!(
        event["value"]["error"]
            .as_str()
            .is_some_and(|e| e.starts_with(&format!("MOVED {slot} "))),
        "{event}"
    );

    // A seed that is not a cluster node is refused at connect, not treated as one.
    let (tx, _) = mpsc::unbounded_channel();
    let standalone = ServerForm {
        protocol: "redis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"redis_error","message":"ERR This instance has cluster support disabled"}]}})]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = port_of(&state, standalone).await;
    let (tx, _) = mpsc::unbounded_channel();
    let refused = ClientForm {
        protocol: "redis".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("x".to_string()),
        startup_params: Some(json!({"cluster": true})),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await;
    let failed = match refused {
        Err(_) => true,
        Ok(id) => {
            let mut failed = false;
            for _ in 0..1200 {
                let status = state
                    .get_client(id)
                    .await
                    .map(|c| format!("{:?}", c.status));
                if status.as_deref().is_some_and(|s| s.contains("Error")) {
                    failed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            failed
        }
    };
    assert!(
        failed,
        "a cluster client must refuse a seed that is not a cluster node"
    );
}
