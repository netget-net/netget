//! The read deadlines on a real, running RTSP server, driven from a raw socket.
//!
//! Two claims, and they are different claims, so each gets its own test.
//!
//! **A peer that has connected and said nothing must eventually be let go of.** Nothing else in
//! the process closes that socket: it holds a task, an `AppState` row and one of
//! `MAX_CONNECTIONS` slots, pre-authentication, so the server has to give up first. Remove the
//! deadline around `read_half.read(&mut chunk)` in `src/server/rtsp/mod.rs` and the first test
//! hangs until its own window expires.
//!
//! **Once a request has been answered the *idle* bound governs, not the first-byte one.** The
//! second test drives an OPTIONS through a static routing rule — so no model is involved — and
//! then goes quiet, with the two bounds set far apart and the wrong way round: if the read loop
//! kept using the first-byte bound after answering, that connection would live 60 seconds and
//! the assertion would time out.
//!
//! The values here are overrides, not the defaults. The shipped defaults are 30 seconds and 300
//! (argued beside `FIRST_BYTE_READ_TIMEOUT` and `IDLE_BETWEEN_REQUESTS_TIMEOUT`), and a test
//! that asserted them by waiting them out would be the slowest thing in the suite. That is why
//! both are declared startup parameters: what is asserted here is that each parameter is read
//! and applied to the read it names; the *values* are argued where they are declared.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on deadlines, not on
//! answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rtsp --test server -- \
//!       rtsp::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The first-byte bound the first test drives, as `first_byte_timeout_secs`.
const SHORT_FIRST_BYTE: Duration = Duration::from_secs(6);

/// The idle bound the second test drives, as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(3);

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("RTSP server #{} never bound a port", id.as_u32());
}

/// A model-free RTSP server: an empty instruction really is model-free, where `None` is
/// replaced by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "rtsp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create rtsp server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_sends_no_request_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
        })),
        None,
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline; what is asserted is that the
    // read ends at all, and that it ends on this bound rather than on the 300-second default.
    let read = tokio::time::timeout(
        SHORT_FIRST_BYTE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that connected and sent no request was still holding the socket, the connection \
         task and its AppState entry after {}s — either the first-byte deadline is not applied \
         at all, or `first_byte_timeout_secs` was declared and never read",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= SHORT_FIRST_BYTE / 2,
        "closed after only {}ms — that is not the declared {}s bound, it is something else \
         tearing the connection down, and this test would then pass without the bound existing",
        elapsed.as_millis(),
        SHORT_FIRST_BYTE.as_secs()
    );
    assert!(
        sink.is_empty(),
        "an RTSP server wrote {} bytes to a peer that had sent no request; it must not speak \
         first",
        sink.len()
    );
}

#[tokio::test]
async fn once_a_request_has_been_answered_the_idle_bound_governs_not_the_first_byte_one() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the read loop
    // kept using the first-byte bound after answering, this connection would live 60 seconds
    // and the assertion below would time out.
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        })),
        Some(vec![serde_json::json!({
            "event_pattern": "rtsp_options",
            "handler": {
                "type": "static",
                "actions": [{"type": "rtsp_options_response"}]
            }
        })]),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(b"OPTIONS rtsp://127.0.0.1/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        .await
        .expect("write OPTIONS");

    let mut reply = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer OPTIONS within 20s")
        .expect("read reply");
    let head = String::from_utf8_lossy(&reply[..n]);
    assert!(
        head.starts_with("RTSP/1.0 200"),
        "the static rule did not answer with 200, so what follows is not the post-answer state \
         this test is about; got: {head}"
    );

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "an answered connection that then went quiet was never closed — `idle_timeout_secs` was \
         declared and is not being read"
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= SHORT_IDLE / 2,
        "closed after only {}ms, which is below the declared {}s idle bound",
        elapsed.as_millis(),
        SHORT_IDLE.as_secs()
    );
    assert!(
        elapsed < Duration::from_secs(40),
        "closed after {}s, which is the 60-second first-byte bound rather than the {}s idle one \
         — the read loop never switched bounds",
        elapsed.as_secs(),
        SHORT_IDLE.as_secs()
    );
}
