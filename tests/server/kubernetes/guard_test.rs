//! Guards on the Kubernetes API server's two hostile-input surfaces, and on the one place a
//! narrowing cast could turn a refusal into an answer.
//!
//! Three defects, each with a test that fails without its fix:
//!
//! 1. **The request body was unbounded.** `hyper`'s `Incoming` has no limit and this server
//!    performs no authentication, so `collect()` buffered whatever an anonymous `POST` chose to
//!    send — and the body is then embedded whole in an LLM prompt. It is now capped at
//!    `MAX_REQUEST_BODY_BYTES` (3 MiB, the same `maxRequestBodyBytes` a real apiserver enforces)
//!    and refused with a `413` `Status`, **without** reaching the model.
//! 2. **`status_code as u16` truncated silently.** `65736 as u16 == 200`, so a status outside
//!    the HTTP range became a `200 OK`: the LDAP `result_code as u8` defect, in a different
//!    protocol. `model_status_code` range-checks *before* the cast and fails closed.
//! 3. **`restartCount` was summed with `sum()`.** The values come out of the model's object and
//!    `overflow-checks` is on in every debug and test build, so two containers claiming
//!    `i64::MAX` panicked the render.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features kubernetes-server \
//!       --test server -- --test-threads=100 kubernetes::guard


use crate::server::helpers::{self, E2EResult, NetGetConfig};
use netget::server::kubernetes::{model_status_code, table, MAX_REQUEST_BODY_BYTES};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// 1. The request body is bounded, and an over-cap body never reaches the model
// ---------------------------------------------------------------------------

/// A `POST` larger than the cap is answered `413 RequestEntityTooLarge` and costs no LLM call,
/// while a normal-sized one on the same server still goes through — a guard that refused
/// everything would pass the first assertion on its own.
///
/// LLM calls: 2 (startup, and the one legitimate write). The oversized request is the point:
/// the mock rule for `k8s_write_request` is `expect_calls(1)`, so if the huge body reached the
/// model the count would be 2 and `verify_mocks` would fail.
#[tokio::test]
async fn oversized_request_body_is_refused_before_the_model_sees_it() -> E2EResult<()> {
    println!("\n=== E2E Test: Kubernetes request body cap ===");

    let prompt = "Open a Kubernetes API server on port {AVAILABLE_PORT}";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Kubernetes API server")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "kubernetes",
                "instruction": "Kubernetes API server for the body-cap test"
            }]))
            .expect_calls(1)
            .and()
            .on_event("k8s_write_request")
            .respond_with_actions(json!([{
                "type": "k8s_object_response",
                "status_code": 201,
                "object": {
                    "kind": "Pod",
                    "apiVersion": "v1",
                    "metadata": {"name": "small-one", "namespace": "default"},
                    "status": {"phase": "Pending"}
                }
            }]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let base = format!("http://127.0.0.1:{}", server.port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let pods = format!("{base}/api/v1/namespaces/default/pods");

    // --- over the cap: refused, with a real Status, and no model call -------
    //
    // A JSON document, not random bytes: the point is that it is refused on *size*, before
    // anything tries to parse it or hand it to the model.
    let filler = "A".repeat(MAX_REQUEST_BODY_BYTES + 64 * 1024);
    let huge = json!({
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": "too-big", "namespace": "default", "annotations": {"pad": filler}}
    })
    .to_string();
    assert!(
        huge.len() > MAX_REQUEST_BODY_BYTES,
        "the test body must exceed the cap to prove anything"
    );

    let response = client
        .post(&pods)
        .header("Content-Type", "application/json")
        .body(huge)
        .send()
        .await?;
    assert_eq!(
        response.status().as_u16(),
        413,
        "an over-cap body must be refused, not buffered"
    );
    let status: Value = response.json().await?;
    assert_eq!(status.get("kind").and_then(Value::as_str), Some("Status"));
    assert_eq!(
        status.get("status").and_then(Value::as_str),
        Some("Failure")
    );
    assert_eq!(
        status.get("reason").and_then(Value::as_str),
        Some("RequestEntityTooLarge"),
        "the reason must be the one a real apiserver uses, so client-go does not retry"
    );
    assert_eq!(status.get("code").and_then(Value::as_u64), Some(413));
    // The peer gets a category, never netget's own error text.
    let message = status
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    for leak in ["hyper", "LengthLimitError", "netget.log", "anyhow"] {
        assert!(
            !message.contains(leak),
            "the Status message leaked internals ({leak}): {message}"
        );
    }

    // --- under the cap: the same server still serves a write ---------------
    let ok = client
        .post(&pods)
        .header("Content-Type", "application/json")
        .body(
            json!({
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": {"name": "small-one", "namespace": "default"}
            })
            .to_string(),
        )
        .send()
        .await?;
    assert_eq!(
        ok.status().as_u16(),
        201,
        "the cap must not break ordinary writes"
    );
    let created: Value = ok.json().await?;
    assert_eq!(
        created.pointer("/metadata/name").and_then(Value::as_str),
        Some("small-one")
    );

    server.wait_for_mocks(30).await;
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("✓ oversized body refused with 413 and no LLM call; normal write unaffected\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. A status code outside the HTTP range fails closed rather than narrowing
// ---------------------------------------------------------------------------

/// `model_status_code` is the whole guard, so it is tested directly.
///
/// The values are chosen to be the ones a cast would get wrong: `65736 as u16 == 200` and
/// `65739 as u16 == 203`, both of which `StatusCode::from_u16` then happily accepts. Range-check
/// first and they are `None`; cast first and a refusal has become a success.
#[test]
fn a_status_code_outside_the_http_range_never_narrows_into_success() {
    // Real codes pass through unchanged.
    for code in [100u64, 200, 201, 403, 404, 409, 413, 422, 500, 503, 599] {
        assert_eq!(
            model_status_code(Some(code), 500),
            Some(code as u16),
            "{code} is a real HTTP status and must be kept"
        );
    }

    // Absent means "the model did not say", which is the caller's default, not a narrowing.
    assert_eq!(model_status_code(None, 200), Some(200));
    assert_eq!(model_status_code(None, 500), Some(500));

    // The truncation cases. Each of these `as u16` to a value inside 1xx-5xx.
    for code in [65536u64, 65736, 65739, 66_036, 131_272] {
        assert_eq!(
            model_status_code(Some(code), 500),
            None,
            "{code} truncates to {} as a u16 — it must be refused, not narrowed",
            code as u16
        );
    }

    // Ordinary out-of-range values are refused too.
    for code in [0u64, 99, 600, 1000, u64::MAX] {
        assert_eq!(model_status_code(Some(code), 500), None, "{code}");
    }
}

// ---------------------------------------------------------------------------
// 3. Table rendering survives the numbers a model can put in an object
// ---------------------------------------------------------------------------

/// `restartCount` is model-supplied, and `overflow-checks` is on in debug and test builds, so
/// summing two `i64::MAX`es with `sum()` aborted the render — in the build where you find bugs,
/// and silently wrapped in the one that ships. Saturating is the right answer for a display
/// cell: the number is already meaningless at that magnitude.
#[test]
fn restart_counts_saturate_instead_of_overflowing() {
    let pod = json!({
        "metadata": {"name": "runaway", "namespace": "default"},
        "spec": {"containers": [{"name": "a"}, {"name": "b"}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"name": "a", "ready": true, "restartCount": i64::MAX},
                {"name": "b", "ready": true, "restartCount": i64::MAX}
            ]
        }
    });

    let rendered = table::table_from_items("Pod", std::slice::from_ref(&pod));
    let cells = rendered
        .pointer("/rows/0/cells")
        .and_then(Value::as_array)
        .expect("the Table must still have a row");
    // NAME, READY, STATUS, RESTARTS, AGE
    assert_eq!(cells[0].as_str(), Some("runaway"));
    assert_eq!(cells[1].as_str(), Some("2/2"));
    assert_eq!(cells[2].as_str(), Some("Running"));
    assert_eq!(
        cells[3].as_str(),
        Some(i64::MAX.to_string().as_str()),
        "the RESTARTS cell must saturate, not panic and not wrap negative"
    );

    // And an ordinary pod still renders the real total, so the guard is not just clamping
    // everything to i64::MAX.
    let normal = json!({
        "metadata": {"name": "web-0"},
        "spec": {"containers": [{"name": "a"}, {"name": "b"}]},
        "status": {
            "containerStatuses": [
                {"name": "a", "ready": true, "restartCount": 2},
                {"name": "b", "ready": false, "restartCount": 5}
            ]
        }
    });
    let rendered = table::table_from_items("Pod", std::slice::from_ref(&normal));
    let cells = rendered
        .pointer("/rows/0/cells")
        .and_then(Value::as_array)
        .expect("row");
    assert_eq!(cells[1].as_str(), Some("1/2"));
    assert_eq!(cells[3].as_str(), Some("7"));
}
