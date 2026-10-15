//! The Prometheus exporter's bounds, driven from the wire.
//!
//! The first-byte deadline, the idle deadline, the parked-request guarantee and the connection
//! cap are the shared hyper-family checks in `tests/helpers/http_bounds.rs`, which states how
//! each fails without the bound it tests. The request-body cap is specific to this server and
//! is checked here: a scrape carries no body, so anything over `MAX_REQUEST_BODY_BYTES` is
//! refused with a 413 before routing and without asking the model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features prometheus --test server -- \
//!       prometheus::connection_bounds --test-threads=100


use crate::helpers::http_bounds::{assert_connection_cap, assert_read_deadlines, HttpBoundsCase};
use crate::server::helpers::E2EResult;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The numbers `src/server/prometheus/mod.rs` declares. Copied rather than imported: a changed
/// bound should make someone re-read this file, not be followed silently.
fn case() -> HttpBoundsCase {
    HttpBoundsCase {
        base_stack: "prometheus",
        label: "PROMETHEUS-BOUNDS",
        max_connections: 256,
        idle_secs: 120,
        startup_params: None,
        event_request: b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_and_the_slot_comes_back() -> E2EResult<()> {
    assert_connection_cap(&case()).await
}

#[tokio::test]
async fn silent_stalled_and_parked_peers_meet_their_own_deadlines() -> E2EResult<()> {
    assert_read_deadlines(&case()).await
}

/// `src/server/prometheus/mod.rs::MAX_REQUEST_BODY_BYTES`, copied on purpose.
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

async fn post_with_body(port: u16, len: usize) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut request = format!(
        "POST /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {len}\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes();
    request.resize(request.len() + len, b'A');
    // A refusal can close the socket while the body is still being written; what matters is
    // the status line that comes back.
    let _ = stream.write_all(&request).await;
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut reply)).await;
    String::from_utf8_lossy(&reply).into_owned()
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused_before_routing_and_one_at_the_cap_is_not() {
    // A dead model endpoint: neither request below may reach it, and nothing here needs it to.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "prometheus".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create prometheus server");
    let mut port = None;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let port = port.expect("prometheus never bound a port");

    // At the cap: read in full, then routed, and POST is not a method /metrics serves.
    let at_cap = post_with_body(port, MAX_REQUEST_BODY_BYTES).await;
    assert!(
        at_cap.starts_with("HTTP/1.1 405"),
        "a body exactly at the cap should be read and routed (405 for POST), got: {:?}",
        at_cap.lines().next()
    );

    // One byte over: refused as too large, before routing.
    let over = post_with_body(port, MAX_REQUEST_BODY_BYTES + 1).await;
    assert!(
        over.starts_with("HTTP/1.1 413"),
        "a body one byte over the cap must be refused with 413, got: {:?}",
        over.lines().next()
    );
}
