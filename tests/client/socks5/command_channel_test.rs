//! The dashboard's `[ send ]` path on a SOCKS5 client: `AppState::send_to_client` injects an
//! action from outside the client's read loop and the bytes reach the tunnel. Zero LLM calls —
//! a minimal in-test no-auth SOCKS5 proxy completes the handshake, the client's LLM points at
//! an unreachable URL (its connected-event call fails; the loop tolerates that), and the
//! injected send goes through the protocol's own `execute_action`, never a model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features socks5 --test client -- socks5::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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
        "socks5 client #{} never registered a command handle",
        id.as_u32()
    );
}

/// Minimal no-auth SOCKS5 proxy: complete the greeting + CONNECT handshake (enough for
/// `tokio-socks` to establish the tunnel), then forward every byte the tunneled client
/// writes over `bytes_tx`.
async fn run_socks5_proxy(listener: TcpListener, bytes_tx: mpsc::UnboundedSender<Vec<u8>>) {
    let mut sock = match listener.accept().await {
        Ok((s, _)) => s,
        Err(_) => return,
    };

    // Greeting: VER, NMETHODS, METHODS...
    let mut head = [0u8; 2];
    if sock.read_exact(&mut head).await.is_err() {
        return;
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if sock.read_exact(&mut methods).await.is_err() {
        return;
    }
    // Select method 0x00 (no auth).
    if sock.write_all(&[0x05, 0x00]).await.is_err() {
        return;
    }

    // CONNECT request: VER, CMD, RSV, ATYP, ADDR..., PORT(2).
    let mut req = [0u8; 4];
    if sock.read_exact(&mut req).await.is_err() {
        return;
    }
    let addr_len = match req[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            if sock.read_exact(&mut l).await.is_err() {
                return;
            }
            l[0] as usize
        }
        _ => return,
    };
    let mut addr_and_port = vec![0u8; addr_len + 2];
    if sock.read_exact(&mut addr_and_port).await.is_err() {
        return;
    }
    // Success reply, bound address 0.0.0.0:0.
    if sock
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .is_err()
    {
        return;
    }

    // Tunnel established: forward everything the client sends.
    let mut buf = vec![0u8; 4096];
    loop {
        match sock.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = bytes_tx.send(buf[..n].to_vec());
            }
        }
    }
}

#[tokio::test]
async fn injected_socks5_data_reaches_the_tunnel() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let (bytes_tx, mut bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_socks5_proxy(listener, bytes_tx));

    let client_id = ClientForm {
        protocol: "socks5".to_string(),
        remote_addr: Some(proxy_addr.to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "target_addr": "example.com:80" })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create socks5 client");

    wait_for_client_handle(&state, client_id).await;

    // "Hello" as hex, injected from outside the loop.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_socks5_data", "data_hex": "48656c6c6f"}),
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
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client handle still registered after disconnect");
}
