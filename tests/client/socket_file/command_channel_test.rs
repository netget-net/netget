//! The dashboard's `[ send ]` path on a Socket File (Unix domain socket) client:
//! `AppState::send_to_client` injects an action from outside the client's read loop and the
//! bytes reach the socket. Zero LLM calls — the client's LLM points at an unreachable URL
//! (its connected handling tolerates the error) and the injected send goes through the
//! protocol's own `execute_action`, never a model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features socket_file --test client -- socket_file::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "socket_file client #{} never registered a command handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_socket_file_data_reaches_the_unix_socket() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let socket_path = std::env::temp_dir().join(format!(
        "netget_cmdchan_socket_file_{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind unix listener");

    // Accept one connection and forward every byte the client writes to us.
    let (bytes_tx, mut bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = bytes_tx.send(buf[..n].to_vec());
                    }
                }
            }
        }
    });

    let client_id = ClientForm {
        protocol: "SocketFile".to_string(),
        remote_addr: Some(socket_path.to_string_lossy().to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create socket_file client");

    wait_for_client_handle(&state, client_id).await;

    // "Hello" as hex, injected from outside the loop.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_socket_file_data", "data_hex": "48656c6c6f"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 5 }),
        "expected Sent{{5}}, got {outcome:?}"
    );

    let received = tokio::time::timeout(Duration::from_secs(5), bytes_rx.recv())
        .await
        .expect("bytes within 5s")
        .expect("forwarding channel open");
    assert_eq!(received, b"Hello");

    // Unknown actions are rejected, not swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (bad action)");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Injected disconnect ends the read loop; the handle is dropped on exit.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (disconnect)");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            let _ = std::fs::remove_file(&socket_path);
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let _ = std::fs::remove_file(&socket_path);
    panic!("client handle still registered after disconnect");
}
