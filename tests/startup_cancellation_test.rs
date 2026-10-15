//! Startup ownership survives errors/cancellation before a caller receives its ID.

use netget::cli::management::ClientForm;
use netget::llm::OllamaClient;
use netget::state::{AppState, ClientId, ClientInstance, ScheduledTask, TaskId, TaskScope};
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpListener;

async fn state_with_unrelated_client() -> (AppState, ClientId, TaskId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            "unused".into(),
            "fixture".into(),
            "existing".into(),
        ))
        .await;
    let task = state
        .add_task(
            ScheduledTask::new_one_shot(
                TaskId::new(0),
                "existing".into(),
                TaskScope::Client(id),
                3600,
                "existing".into(),
                None,
            )
            .unwrap(),
        )
        .await;
    (state, id, task)
}

fn client_action(address: std::net::SocketAddr) -> serde_json::Value {
    json!({
        "type": "open_client", "protocol": "vnc", "remote_addr": address.to_string(),
        "scheduled_tasks": [{
            "task_id": "new-client-task", "recurring": false,
            "delay_secs": 3600, "instruction": "never execute during this test"
        }]
    })
}

async fn assert_only_existing_remains(state: &AppState, client: ClientId, task: TaskId) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let clients = state.get_all_clients().await;
            let tasks = state.get_all_tasks().await;
            if clients.len() == 1 && tasks.len() == 1 {
                assert_eq!(clients[0].id, client);
                assert_eq!(tasks[0].id, task);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("new registration and scoped task must be removed");
}

#[tokio::test]
async fn failed_client_handshake_cleans_registration_before_returning_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let form: ClientForm =
        serde_json::from_value(client_action(listener.local_addr().unwrap())).unwrap();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket); // EOF before RFB greeting: connect fails without any model request.
    });
    let (state, existing, task) = state_with_unrelated_client().await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        form.create(&state, OllamaClient::new("http://127.0.0.1:1"), tx),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    // Error returns only after explicit cleanup, without needing the drop worker.
    assert_eq!(state.get_all_clients().await.len(), 1);
    assert_eq!(state.get_all_tasks().await.len(), 1);
    assert_only_existing_remains(&state, existing, task).await;
    peer.await.unwrap();
}

#[tokio::test]
async fn cancelled_restore_cleans_client_that_has_not_returned_its_id() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let session = json!({
        "version": 2,
        "resources": [{"key": 19, "action": client_action(listener.local_addr().unwrap())}]
    });
    let (state, existing, task) = state_with_unrelated_client().await;
    let restore_state = state.clone();
    let restore = tokio::spawn(async move {
        netget::utils::save_load::restore_session(
            &restore_state,
            &OllamaClient::new("http://127.0.0.1:1"),
            &session,
        )
        .await
    });
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    // Keep the greeting pending. connect() cannot return an ID to restore_session.
    assert_eq!(state.get_all_clients().await.len(), 2);
    assert_eq!(state.get_all_tasks().await.len(), 2);
    assert!(!restore.is_finished());
    restore.abort();
    assert!(restore.await.unwrap_err().is_cancelled());
    assert_only_existing_remains(&state, existing, task).await;
    use tokio::io::AsyncReadExt;
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
