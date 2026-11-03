//! `close_this_connection` in an answer to a read hangs up on the peer.
//!
//! The answer is a static rule — send a line, then close — so no model is involved. The peer
//! must read the line and then EOF promptly; a server that only forgot the connection, leaving
//! the socket open, makes the peer's read run into its own timeout instead. Afterwards the
//! instance no longer counts the connection as open.
//!
//! Loopback only; the LLM endpoint is a dead port, and nothing may reach it.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[tokio::test]
async fn close_this_connection_sends_fin_after_the_answer() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "tcp_data_received",
            "handler": {"type": "static", "actions": [
                {"type": "send_tcp_data", "data": "bye\r\n"},
                {"type": "close_this_connection"}
            ]}
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tcp server");

    let mut port = None;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let port = port.expect("the server binds");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(b"hello\r\n").await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
        .await
        .expect("EOF arrives: the server hung up rather than leaving the socket open")
        .expect("read");
    assert_eq!(received, b"bye\r\n", "the answer precedes the close");

    let mut open = usize::MAX;
    for _ in 0..100 {
        let server = state.get_server(id).await.expect("server");
        open = server
            .connections
            .values()
            .filter(|c| !matches!(c.status, netget::state::server::ConnectionStatus::Closed))
            .count();
        if open == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(open, 0, "the closed connection is not still reported open");
}
