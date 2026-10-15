//! A model-supplied `status` on `openai_error_response` narrowed with `as u16` became a 200.
//!
//! `65736 as u16` is `200`. This action is the only way the model can return an OpenAI-shaped
//! error, so the wrap handed the caller a 200 whose body happens to carry an `error` object —
//! which an OpenAI SDK reads as a successful completion with unexpected fields, not as a
//! refusal. Fail-open by arithmetic.
//!
//! Out of range is refused rather than clamped, and the message names the range so the repair
//! loop can correct the call.

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::openai::actions::OpenAiProtocol;
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match OpenAiProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn out_of_range_status_is_refused_not_wrapped() {
    let with = |status: u64| {
        json!({
            "type": "openai_error_response",
            "message": "invalid api key",
            "error_type": "invalid_request_error",
            "status": status,
        })
    };

    assert!(
        run(with(65736)).is_none(),
        "status 65736 must be refused: `as u16` makes it 200, and an SDK reads a 200 as a \
         completed request however the body is shaped"
    );
    for bad in [0u64, 99, 600, 1000, 65535] {
        assert!(
            run(with(bad)).is_none(),
            "status {bad} is not an HTTP status code and must be refused"
        );
    }

    for good in [400u64, 401, 429, 500] {
        let data = run(with(good)).unwrap_or_else(|| panic!("{good} is a real HTTP status"));
        assert_eq!(data["status"].as_u64(), Some(good));
    }
}

#[test]
fn omitting_the_status_still_errors() {
    // The refusal must not become a success by another route.
    let data = run(json!({"type": "openai_error_response", "message": "backend down"}))
        .expect("omitting status must still answer");
    assert_eq!(
        data["status"].as_u64(),
        Some(500),
        "the default must stay a server error, got {data}"
    );
}
