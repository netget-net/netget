//! The OTLP receiver's bounds, driven from the wire.
//!
//! The first-byte deadline, the idle deadline, the parked-request guarantee and the connection
//! cap are the shared hyper-family checks in `tests/helpers/http_bounds.rs`, which states how
//! each fails without the bound it tests. The body cap is this receiver's own and is checked
//! here, in both of its forms: 4 MiB as sent, and 4 MiB after gzip inflation — so a small
//! compressed body cannot expand past it. Neither refusal reaches the model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features otlp --test server -- \
//!       otlp::connection_bounds --test-threads=100

use super::common::{self, gzip, post, static_handler, GZIP, PROTOBUF};
use crate::helpers::http_bounds::{assert_connection_cap, assert_read_deadlines, HttpBoundsCase};
use crate::server::helpers::E2EResult;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;

/// The numbers `src/server/otlp/mod.rs` declares. Copied rather than imported: a changed bound
/// should make someone re-read this file, not be followed silently.
fn case() -> HttpBoundsCase {
    HttpBoundsCase {
        base_stack: "otlp",
        label: "OTLP-BOUNDS",
        max_connections: 256,
        idle_secs: 120,
        startup_params: None,
        event_request: b"POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1\r\n\
            Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    }
}

/// `src/server/otlp/codec.rs::MAX_BODY_BYTES`, copied on purpose.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_and_the_slot_comes_back() -> E2EResult<()> {
    assert_connection_cap(&case()).await
}

#[tokio::test]
async fn silent_stalled_and_parked_peers_meet_their_own_deadlines() -> E2EResult<()> {
    assert_read_deadlines(&case()).await
}

/// A valid protobuf traces export of exactly `len` bytes: one span whose name is sized to fit.
fn export_of_exactly(len: usize) -> Vec<u8> {
    let mut name_len = len - 32;
    loop {
        let body = common::traces_protobuf("s", &[&"n".repeat(name_len)]);
        match body.len().cmp(&len) {
            std::cmp::Ordering::Equal => return body,
            std::cmp::Ordering::Greater => name_len -= body.len() - len,
            std::cmp::Ordering::Less => name_len += len - body.len(),
        }
    }
}

#[tokio::test]
async fn a_body_of_exactly_the_cap_is_read_and_one_byte_more_is_refused() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        vec![static_handler(serde_json::json!([{"type": "accept_otlp"}]))],
    )
    .await;

    let exact = export_of_exactly(MAX_BODY_BYTES);
    assert!(ExportTraceServiceRequest::decode(&*exact).is_ok());
    let reply = post(port, "/v1/traces", &[PROTOBUF], &exact).await;
    assert_eq!(reply.status, 200, "4 MiB is read, decoded and answered");
    common::wait_for_log(&mut rx, "decision=model_answer", 30).await;

    let mut over = exact.clone();
    over.push(0);
    let reply = post(port, "/v1/traces", &[PROTOBUF], &over).await;
    assert_eq!(reply.status, 413, "one byte over the cap");
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_too_large", 30).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize export reached a handler: {log:#?}"
    );
}

#[tokio::test]
async fn a_gzip_body_is_held_to_the_same_cap_once_inflated() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        vec![static_handler(serde_json::json!([{"type": "accept_otlp"}]))],
    )
    .await;

    // Exactly the cap once inflated: accepted.
    let exact = gzip(&export_of_exactly(MAX_BODY_BYTES));
    assert!(exact.len() < 64 * 1024, "compresses well: {}", exact.len());
    let reply = post(port, "/v1/traces", &[PROTOBUF, GZIP], &exact).await;
    assert_eq!(reply.status, 200);
    common::wait_for_log(&mut rx, "decision=model_answer", 30).await;

    // A few kilobytes that inflate one byte past it: refused before decoding.
    let mut inflated = export_of_exactly(MAX_BODY_BYTES);
    inflated.push(0);
    let bomb = gzip(&inflated);
    let reply = post(port, "/v1/traces", &[PROTOBUF, GZIP], &bomb).await;
    assert_eq!(reply.status, 413);
    let log = common::wait_for_log(&mut rx, "inflates past", 30).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "{log:#?}"
    );
}
