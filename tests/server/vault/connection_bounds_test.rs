//! Vault's bounds, driven from the wire.
//!
//! The first-byte deadline, the idle deadline, the parked-request guarantee and the connection
//! cap are the shared hyper-family checks in `tests/helpers/http_bounds.rs`, which states how
//! each fails without the bound it tests. The request-body cap is checked here: a KV write body
//! over `MAX_REQUEST_BODY_BYTES` is a 413 before routing and before any model call.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features vault --test server -- \
//!       vault::connection_bounds --test-threads=100

use crate::helpers::http_bounds::{assert_connection_cap, assert_read_deadlines, HttpBoundsCase};
use crate::server::helpers::E2EResult;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The numbers `src/server/vault/mod.rs` declares, copied on purpose.
fn case() -> HttpBoundsCase {
    HttpBoundsCase {
        base_stack: "vault",
        label: "VAULT-BOUNDS",
        max_connections: 256,
        idle_secs: 120,
        startup_params: None,
        event_request: b"GET /v1/secret/data/app/db HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                         X-Vault-Token: t\r\n\r\n",
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

/// `src/server/vault/mod.rs::MAX_REQUEST_BODY_BYTES`, copied on purpose.
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

async fn delete_with_body(port: u16, len: usize) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // DELETE is not implemented, so a body at the cap is read, routed and answered 405 without
    // a model; one byte over is refused before routing.
    let mut request = format!(
        "DELETE /v1/secret/data/app/db HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    request.resize(request.len() + len, b' ');
    let _ = stream.write_all(&request).await;
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut reply)).await;
    String::from_utf8_lossy(&reply).into_owned()
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused_before_routing_and_one_at_the_cap_is_not() {
    let (_state, port) =
        super::real_client_test::start_vault(Vec::new(), serde_json::json!({})).await;

    let at_cap = delete_with_body(port, MAX_REQUEST_BODY_BYTES).await;
    assert!(
        at_cap.starts_with("HTTP/1.1 405"),
        "a body at the cap is read and routed, got {:?}",
        at_cap.lines().next()
    );
    let over = delete_with_body(port, MAX_REQUEST_BODY_BYTES + 1).await;
    assert!(
        over.starts_with("HTTP/1.1 413"),
        "one byte over the cap must be refused with 413, got {:?}",
        over.lines().next()
    );
}
