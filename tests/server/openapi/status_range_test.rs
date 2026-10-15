//! A model-supplied `status_code` narrowed with `as u16` asserted the opposite outcome.
//!
//! Both executors read the field with `as_i64()` and then narrowed it, which wraps in both
//! directions: `65736 as u16` is `200`, and `-1 as u16` is `65535`. `send_validation_error`
//! is the model's way of saying a request failed schema validation, so the single field
//! carrying that refusal could reach the client as the success it was refusing.
//!
//! The executor refuses an out-of-range status rather than clamping it, and names the range
//! so the repair loop can correct the call.


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::openapi::actions::OpenApiProtocol;
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match OpenApiProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn out_of_range_status_is_refused_not_wrapped() {
    for action_type in ["send_openapi_response", "send_validation_error"] {
        let with = |status: serde_json::Value| {
            json!({
                "type": action_type,
                "status_code": status,
                "body": "{}",
                "message": "schema validation failed",
            })
        };

        // The wrap this exists for.
        assert!(
            run(with(json!(65736))).is_none(),
            "{action_type}: status_code 65736 must be refused. `as u16` makes it 200, so a \
             refusal reached the client as a success."
        );
        // `as_i64` accepts negatives, and `-1 as u16` is 65535.
        assert!(
            run(with(json!(-1))).is_none(),
            "{action_type}: a negative status_code must be refused, not narrowed to 65535"
        );
        // In range for the type, still not an HTTP status.
        for bad in [0i64, 99, 600, 65535] {
            assert!(
                run(with(json!(bad))).is_none(),
                "{action_type}: status_code {bad} is not an HTTP status and must be refused"
            );
        }
        // A missing field stays an error rather than becoming a default success.
        assert!(
            run(json!({"type": action_type, "body": "{}", "message": "m"})).is_none(),
            "{action_type}: an absent status_code must stay an error"
        );

        // The refusal must not cost the legitimate call: real statuses still pass through
        // unchanged at both ends of the range.
        for good in [100u64, 200, 422, 599] {
            let data = run(with(json!(good)))
                .unwrap_or_else(|| panic!("{action_type}: {good} is a real HTTP status"));
            assert_eq!(
                data["status_code"].as_u64(),
                Some(good),
                "{action_type}: {good} must reach the wire unchanged, got {data}"
            );
        }
    }
}
