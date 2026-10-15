//! The Docker Engine API's bounds, driven from the wire.
//!
//! The first-byte deadline, the idle deadline, the parked-request guarantee and the connection
//! cap are the shared hyper-family checks in `tests/helpers/http_bounds.rs`, which states how
//! each fails without the bound it tests. The request-body cap is checked here: every endpoint
//! served is a read with no body, so over `MAX_REQUEST_BODY_BYTES` is a 413 before routing.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features docker --test server -- \
//!       docker::connection_bounds --test-threads=100


use crate::helpers::http_bounds::{assert_connection_cap, assert_read_deadlines, HttpBoundsCase};
use crate::server::helpers::E2EResult;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The numbers `src/server/docker/mod.rs` declares, copied on purpose.
fn case() -> HttpBoundsCase {
    HttpBoundsCase {
        base_stack: "docker",
        label: "DOCKER-BOUNDS",
        max_connections: 256,
        idle_secs: 120,
        startup_params: None,
        event_request: b"GET /v1.47/containers/json HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
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

/// `src/server/docker/mod.rs::MAX_REQUEST_BODY_BYTES`, copied on purpose.
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

async fn post_with_body(port: u16, len: usize) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut request = format!(
        "POST /v1.47/containers/create HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
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
    let (_state, port) = super::real_client_test::start_docker(Vec::new()).await;

    let at_cap = post_with_body(port, MAX_REQUEST_BODY_BYTES).await;
    assert!(
        at_cap.starts_with("HTTP/1.1 501"),
        "a body at the cap is read and routed (501: mutating endpoint), got {:?}",
        at_cap.lines().next()
    );
    let over = post_with_body(port, MAX_REQUEST_BODY_BYTES + 1).await;
    assert!(
        over.starts_with("HTTP/1.1 413"),
        "one byte over the cap must be refused with 413, got {:?}",
        over.lines().next()
    );
}
