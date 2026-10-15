//! The peer is answered when the LLM backend fails — never left hanging, never told why.
//!
//! BitTorrent's peer wire protocol (BEP 3) has no error message and no free-text field, so a
//! backend failure can only be expressed with the protocol's own refusal: `choke`
//! (`00 00 00 01 00`). This test drives a real socket against a server whose LLM backend is a
//! closed port and asserts that the peer receives exactly that frame followed by EOF, with
//! nothing else on the wire — in particular nothing derived from the backend error.
//!
//! Zero mock LLM: the backend URL points at 127.0.0.1:1, so every `call_llm` errors.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-peer --test server -- torrent_peer::llm_failure --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    // Port 1 is closed: every LLM call fails with a connection error.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

fn handshake(info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Vec<u8> {
    let mut h = Vec::with_capacity(68);
    h.push(19u8);
    h.extend_from_slice(b"BitTorrent protocol");
    h.extend_from_slice(&[0u8; 8]);
    h.extend_from_slice(info_hash);
    h.extend_from_slice(peer_id);
    h
}

#[tokio::test]
async fn llm_failure_chokes_the_peer_and_closes_without_leaking_the_error() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A handler that matches nothing, so `peer_handshake` falls through to the LLM (which
    // cannot be reached) rather than being answered deterministically or parked.
    let server_id = ServerForm {
        protocol: "torrent-peer".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "no_such_event",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create torrent-peer server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    stream
        .write_all(&handshake(&[0xABu8; 20], b"-PC0001-peerpeerpeer"))
        .await
        .expect("send handshake");

    // The whole remainder of the stream: a choke frame, then EOF. Reading to end also proves
    // the connection does not sit open waiting for a response that will never come, which is
    // the failure mode this path exists to remove.
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), stream.read_to_end(&mut rest))
        .await
        .expect("server must answer and half-close within 60s")
        .expect("read_to_end");

    assert_eq!(
        rest,
        vec![0x00, 0x00, 0x00, 0x01, 0x00],
        "the peer must receive exactly one choke frame and nothing else; got {rest:?}"
    );

    // Belt and braces: no text of any kind reached the socket. A choke frame has no room for
    // one, but this is the assertion that fails loudly if someone later appends a diagnostic.
    let as_text = String::from_utf8_lossy(&rest);
    for token in [
        "LLM",
        "llm",
        "ollama",
        "Ollama",
        "http://",
        "127.0.0.1",
        "error",
        "Error",
        "retries",
    ] {
        assert!(
            !as_text.contains(token),
            "internal detail {token:?} reached the peer: {as_text:?}"
        );
    }
}
