//! A model-supplied `status_code` on `npm_error` narrowed with `as u16` became a 200.
//!
//! `65736 as u16` is `200`. `npm_error` is the only way the model can refuse a registry
//! request, so the single field carrying that refusal arrived at the npm CLI as a success —
//! with a body that is an error object rather than a packument. Fail-open by arithmetic.
//!
//! Out of range is refused rather than clamped, and the message names the range so the repair
//! loop can correct the call.


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::npm::actions::NpmProtocol;
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match NpmProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn out_of_range_status_code_is_refused_not_wrapped() {
    let with =
        |status: u64| json!({"type": "npm_error", "error": "not found", "status_code": status});

    assert!(
        run(with(65736)).is_none(),
        "status_code 65736 must be refused: `as u16` makes it 200, so npm read the error \
         object as a successful registry response"
    );
    for bad in [0u64, 99, 600, 1000, 65535] {
        assert!(
            run(with(bad)).is_none(),
            "status_code {bad} is not an HTTP status code and must be refused"
        );
    }

    // Real statuses still reach the wire unchanged.
    for good in [403u64, 404, 500] {
        let data = run(with(good)).unwrap_or_else(|| panic!("{good} is a real HTTP status"));
        assert_eq!(data["status_code"].as_u64(), Some(good));
    }
}

#[test]
fn omitting_the_status_code_still_errors() {
    // The refusal must not become a success by another route: with no status the action still
    // answers, and the default it answers with is a failure.
    let data = run(json!({"type": "npm_error", "error": "registry unavailable"}))
        .expect("omitting status_code must still answer");
    assert_eq!(
        data["status_code"].as_u64(),
        Some(500),
        "the default must stay a server error, got {data}"
    );
}
