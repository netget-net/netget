//! Constructed startup input is bounded before any copy, early failure or registration.

use netget::cli::{
    client_startup,
    management::{self, ClientForm, ServerForm},
    server_startup,
};
use netget::llm::OllamaClient;
use netget::state::{AppState, ClientId, ClientInstance, ServerId, ServerInstance};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

fn deep() -> Value {
    let mut value = Value::Null;
    for _ in 0..10_000 {
        value = Value::Array(vec![value]);
    }
    let mut params = serde_json::Map::new();
    params.insert("send_first".into(), value);
    Value::Object(params)
}

fn llm() -> OllamaClient {
    OllamaClient::new("http://127.0.0.1:1")
}

fn budget(error: anyhow::Error) {
    assert!(error.to_string().contains("budget"), "{error:#}");
}

async fn empty(state: &AppState) {
    assert!(state.get_all_servers().await.is_empty());
    assert!(state.get_all_clients().await.is_empty());
    assert!(state.get_all_tasks().await.is_empty());
    assert!(state.list_intercepts().await.is_empty());
}

#[tokio::test]
async fn owned_forms_and_direct_startups_refuse_deep_json_before_earlier_errors() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    for protocol in ["tcp", "unknown-protocol"] {
        let (tx, _rx) = mpsc::unbounded_channel();
        budget(
            ServerForm {
                protocol: protocol.into(),
                startup_params: Some(deep()),
                ..Default::default()
            }
            .create(&state, tx)
            .await
            .unwrap_err(),
        );
        let (tx, _rx) = mpsc::unbounded_channel();
        // Missing remote_addr must not recursively destroy unvalidated owned params.
        budget(
            ClientForm {
                protocol: protocol.into(),
                startup_params: Some(deep()),
                ..Default::default()
            }
            .create(&state, llm(), tx)
            .await
            .unwrap_err(),
        );
        let (tx, _rx) = mpsc::unbounded_channel();
        budget(
            server_startup::start_server_from_action(
                &state,
                None,
                None,
                None,
                None,
                protocol,
                true,
                None,
                String::new(),
                Some(deep()),
                None,
                None,
                None,
                tx,
            )
            .await
            .unwrap_err(),
        );
        budget(
            client_startup::start_client_from_action(
                &state,
                protocol,
                "bad-address",
                String::new(),
                Some(deep()),
                None,
                None,
                None,
                None,
                llm(),
                None,
            )
            .await
            .unwrap_err(),
        );
        empty(&state).await;
    }
}

#[tokio::test]
async fn startup_updates_preserve_running_resources_and_ordinary_values() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state.set_llm_client(llm()).await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server = ServerForm {
        protocol: "tcp".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some("original-server".into()),
        startup_params: Some(json!({"send_first": false})),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let address = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(address) = state.get_server(server).await.unwrap().local_addr {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (tx, _rx) = mpsc::unbounded_channel();
    let client = ClientForm {
        protocol: "tcp".into(),
        remote_addr: Some(address.to_string()),
        instruction: Some("original-client".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*", "handler":{"type":"static", "actions":[]}}),
        ]),
        ..Default::default()
    }
    .create(&state, llm(), tx)
    .await
    .unwrap();
    let server_tasks = state.server_task_count(server).await;
    let client_tasks = state.client_task_count(client).await;
    for id_exists in [true, false] {
        let (tx, _rx) = mpsc::unbounded_channel();
        budget(
            management::update_server(
                &state,
                if id_exists {
                    server
                } else {
                    ServerId::new(999999)
                },
                ServerForm {
                    startup_params: Some(deep()),
                    instruction: Some("must-not-apply".into()),
                    ..Default::default()
                },
                tx,
            )
            .await
            .unwrap_err(),
        );
        let (tx, _rx) = mpsc::unbounded_channel();
        budget(
            management::update_client(
                &state,
                if id_exists {
                    client
                } else {
                    ClientId::new(999999)
                },
                ClientForm {
                    startup_params: Some(deep()),
                    instruction: Some("must-not-apply".into()),
                    ..Default::default()
                },
                llm(),
                tx,
            )
            .await
            .unwrap_err(),
        );
    }
    assert_eq!(
        state.get_server(server).await.unwrap().instruction,
        "original-server"
    );
    assert_eq!(
        state.get_client(client).await.unwrap().instruction,
        "original-client"
    );
    assert_eq!(
        state.get_server(server).await.unwrap().startup_params,
        Some(json!({"send_first": false}))
    );
    assert_eq!(state.server_task_count(server).await, server_tasks);
    assert_eq!(state.client_task_count(client).await, client_tasks);
    let (tx, _rx) = mpsc::unbounded_channel();
    let outcome = management::update_server(
        &state,
        server,
        ServerForm {
            instruction: Some("valid-server".into()),
            ..Default::default()
        },
        tx,
    )
    .await
    .unwrap();
    assert!(!outcome.restarted);
    let (tx, _rx) = mpsc::unbounded_channel();
    let outcome = management::update_client(
        &state,
        client,
        ClientForm {
            instruction: Some("valid-client".into()),
            ..Default::default()
        },
        llm(),
        tx,
    )
    .await
    .unwrap();
    assert!(!outcome.restarted);
    assert_eq!(
        state.get_server(server).await.unwrap().instruction,
        "valid-server"
    );
    assert_eq!(
        state.get_client(client).await.unwrap().instruction,
        "valid-client"
    );
    state.remove_client(client).await;
    state.remove_server(server).await;
    empty(&state).await;
}

#[tokio::test]
async fn restarting_stored_instances_checks_before_snapshot_clone() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let mut server = ServerInstance::new(ServerId::new(0), 0, "tcp".into(), "original".into());
    server.startup_params = Some(deep());
    let server_id = state.add_server(server).await;
    let mut client = ClientInstance::new(
        ClientId::new(0),
        "unused".into(),
        "tcp".into(),
        "original".into(),
    );
    client.startup_params = Some(deep());
    let client_id = state.add_client(client).await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let error = server_startup::start_server_by_id(&state, server_id, &llm(), &tx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("budget"));
    let error = client_startup::start_client_by_id(&state, client_id, &llm(), &tx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("budget"));
    assert_eq!(state.server_task_count(server_id).await, 0);
    assert_eq!(state.client_task_count(client_id).await, 0);
    assert!(state
        .get_server(server_id)
        .await
        .unwrap()
        .startup_params
        .is_none());
    assert!(state
        .get_client(client_id)
        .await
        .unwrap()
        .startup_params
        .is_none());
    state.remove_client(client_id).await;
    state.remove_server(server_id).await;
    empty(&state).await;
}
