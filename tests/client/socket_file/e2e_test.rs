//! Socket File client E2E tests.
//!
//! The peer of a Unix-domain-socket client is a local descriptor, so there is no third-party
//! implementation to validate against — the strongest evidence this protocol admits is a real
//! `tokio::net::UnixListener` peer driven end to end. That is what
//! `client_speaks_first_and_answers_the_peer` does: a real socket, a real accept, real bytes in
//! both directions, and a mocked model that must be *asked* for each of them.
//!
//! It replaces a test that spawned a listener, never connected anything to it, and asserted
//! `protocol_name() == "SocketFile"`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features socket_file \
//!       --test client -- socket_file:: --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use crate::helpers::E2EResult;
use netget::cli::management::ClientForm;
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use netget::llm::actions::protocol_trait::Protocol;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

/// A real Unix socket peer: the client connects, the model is asked what to say on connect, the
/// peer answers, and the model is asked again with the peer's bytes.
///
/// Both LLM calls are pinned to `expect_calls(1)`, so a connected event that is never raised, or
/// a data event whose `data` field does not carry the peer's text, fails the test rather than
/// quietly falling through to a real model.
#[tokio::test]
async fn client_speaks_first_and_answers_the_peer() -> E2EResult<()> {
    let mock = MockLlmBuilder::new()
        // Speak first: the connect event must reach the model with a usable action.
        .on_event("socket_file_connected")
        .respond_with_actions(serde_json::json!([{
            "type": "send_socket_file_data",
            "data": "PING\n"
        }]))
        .expect_calls(1)
        .and()
        // And the peer's reply must come back as `data`, in plain text. Before this pass the
        // event carried `data_hex` only, so this match would have needed "504f4e470a".
        .on_event("socket_file_data_received")
        .and_event_data_contains("data", "PONG")
        .respond_with_actions(serde_json::json!([{
            "type": "send_socket_file_data",
            "data": "ACK\n"
        }]))
        .expect_calls(1)
        .and()
        .build();
    let mock_server = MockOllamaServer::start(mock).await?;

    let socket_path = std::env::temp_dir().join(format!(
        "netget_client_sf_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;

    // The peer: echo every chunk it saw to the test, and answer the first one with PONG.
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
        let mut answered = false;
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = seen_tx.send(buf[..n].to_vec());
                    if !answered {
                        answered = true;
                        let _ = stream.write_all(b"PONG\n").await;
                    }
                }
            }
        }
    });

    let state = AppState::new_with_options(false, mock_server.base_url());
    let llm = netget::llm::OllamaClient::new(mock_server.base_url());
    state.set_llm_client(llm.clone()).await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let _client_id = ClientForm {
        protocol: "SocketFile".to_string(),
        remote_addr: Some(socket_path.to_string_lossy().to_string()),
        instruction: Some("Say PING on connect, then acknowledge whatever comes back".to_string()),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create socket_file client");

    let first = tokio::time::timeout(Duration::from_secs(20), seen_rx.recv())
        .await
        .map_err(|_| "the client never sent its connect-time payload")?
        .ok_or("peer task ended before the client spoke")?;
    assert_eq!(
        String::from_utf8_lossy(&first),
        "PING\n",
        "the connect event's action should have put PING on the socket"
    );

    let second = tokio::time::timeout(Duration::from_secs(20), seen_rx.recv())
        .await
        .map_err(|_| "the client never answered the peer's PONG")?
        .ok_or("peer task ended before the client answered")?;
    assert_eq!(
        String::from_utf8_lossy(&second),
        "ACK\n",
        "the data-received event's action should have put ACK on the socket"
    );

    mock_server.verify_calls().await?;

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Metadata claims the registry and the docs both rely on.
#[test]
fn metadata_is_experimental_and_names_its_evidence() {
    let protocol = netget::client::socket_file::SocketFileClientProtocol::new();

    assert_eq!(protocol.protocol_name(), "SocketFile");
    assert_eq!(protocol.stack_name(), "UnixSocket");
    for kw in ["socket file", "unix socket", "domain socket"] {
        assert!(protocol.keywords().contains(&kw), "missing keyword {kw:?}");
    }
    assert!(!protocol.description().is_empty());
    assert!(!protocol.example_prompt().is_empty());

    let metadata = protocol.metadata();
    assert_eq!(
        metadata.state,
        netget::protocol::metadata::DevelopmentState::Experimental,
        "a local descriptor has no third-party peer, so nothing here supports a higher rating"
    );
}

/// The outbound payload shape: text by default, hex when asked, and the legacy `data_hex`.
#[test]
fn send_accepts_text_hex_and_the_legacy_field() {
    let protocol = netget::client::socket_file::SocketFileClientProtocol::new();

    let send = |v: serde_json::Value| match protocol.execute_action(v) {
        Ok(ClientActionResult::SendData(bytes)) => bytes,
        other => panic!("expected SendData, got {other:?}"),
    };

    // Text is sent as-is: the model never has to hex-encode a string.
    assert_eq!(
        send(serde_json::json!({"type": "send_socket_file_data", "data": "Hello"})),
        b"Hello"
    );
    // ...and the same string without `encoding: hex` is NOT interpreted as hex.
    assert_eq!(
        send(serde_json::json!({"type": "send_socket_file_data", "data": "48656c6c6f"})),
        b"48656c6c6f"
    );
    assert_eq!(
        send(serde_json::json!({
            "type": "send_socket_file_data",
            "data": "48656c6c6f",
            "encoding": "hex"
        })),
        b"Hello"
    );
    // The shape this client used to advertise still works.
    assert_eq!(
        send(serde_json::json!({"type": "send_socket_file_data", "data_hex": "48656c6c6f"})),
        b"Hello"
    );

    // Bad hex is an action error naming the field, not a panic and not silent truncation.
    let err = protocol
        .execute_action(serde_json::json!({
            "type": "send_socket_file_data",
            "data": "zz",
            "encoding": "hex"
        }))
        .expect_err("invalid hex must be rejected");
    assert!(
        err.to_string().contains("hex"),
        "error should name the encoding: {err}"
    );

    assert!(matches!(
        protocol.execute_action(serde_json::json!({"type": "disconnect"})),
        Ok(ClientActionResult::Disconnect)
    ));
    assert!(matches!(
        protocol.execute_action(serde_json::json!({"type": "wait_for_more"})),
        Ok(ClientActionResult::WaitForMore)
    ));
}

/// `get_event_types()` must describe the events the read loop actually raises.
///
/// It used to return two freshly built `EventType`s whose example action was
/// `{"type": "placeholder"}`, with no parameters and no attached actions — a description of the
/// protocol that matched nothing the client ever emitted.
#[test]
fn declared_events_match_the_emitted_ones() {
    let protocol = netget::client::socket_file::SocketFileClientProtocol::new();
    let events = protocol.get_event_types();
    assert_eq!(events.len(), 2);

    let connected = events
        .iter()
        .find(|e| e.id == "socket_file_connected")
        .expect("socket_file_connected");
    assert!(
        connected.parameters.iter().any(|p| p.name == "socket_path"),
        "connect event must carry the socket path"
    );

    let data = events
        .iter()
        .find(|e| e.id == "socket_file_data_received")
        .expect("socket_file_data_received");
    for field in ["data", "encoding", "data_length"] {
        assert!(
            data.parameters.iter().any(|p| p.name == field),
            "data event must declare {field:?}"
        );
    }
    assert!(
        !data.parameters.iter().any(|p| p.name == "data_hex"),
        "raw hex must not be the model-facing shape of the event"
    );

    for event in [connected, data] {
        assert!(
            event
                .actions
                .iter()
                .any(|a| a.name == "send_socket_file_data"),
            "{} must attach an action the model can answer with",
            event.id
        );
        assert_ne!(
            event.response_example.get("type").and_then(|v| v.as_str()),
            Some("placeholder"),
            "{} still advertises a placeholder example",
            event.id
        );
    }
}
