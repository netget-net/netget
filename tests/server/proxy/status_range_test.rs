//! A model-supplied `status` narrowed with `as u16` turned a block into a success.
//!
//! `65736 as u16` is `200`. `handle_request_block` and `handle_response_block` are the only
//! two ways the model can refuse traffic, so the one field carrying the refusal wrapped into
//! the status that says the opposite — fail-open by arithmetic. `handle_response_modify` is
//! the same cast on an optional field.
//!
//! The executor refuses an out-of-range status rather than clamping it: a clamp to 599 is not
//! what the model asked for either, and the error text is what lets the repair loop fix the
//! call.

#![cfg(unix)]

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::proxy::actions::ProxyProtocol;
use serde_json::json;

/// The JSON the executor serialises, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match ProxyProtocol::new().execute_action(action) {
        Ok(ActionResult::Output(bytes)) => {
            Some(serde_json::from_slice(&bytes).expect("proxy actions serialise JSON"))
        }
        Ok(other) => panic!("expected Output, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn out_of_range_status_is_refused_not_wrapped() {
    for (action_type, refusal_default) in [
        ("handle_request_block", 403u64),
        ("handle_response_block", 502),
    ] {
        // The wrap that made this fail open.
        assert!(
            run(json!({"type": action_type, "status": 65736})).is_none(),
            "{action_type}: status 65736 must be refused. `as u16` makes it 200, so the one \
             field carrying the model's refusal asserted success to the client."
        );
        // In u16 range but still not an HTTP status.
        for bad in [0u64, 99, 600, 1000, 65535] {
            assert!(
                run(json!({"type": action_type, "status": bad})).is_none(),
                "{action_type}: status {bad} is not an HTTP status and must be refused"
            );
        }
        // The refusal must not become a success by another route: a real status still works,
        // and omitting the field still blocks.
        let explicit = run(json!({"type": action_type, "status": 451}))
            .unwrap_or_else(|| panic!("{action_type}: 451 is a real status and must be accepted"));
        assert_eq!(explicit["status"].as_u64(), Some(451));

        let omitted = run(json!({"type": action_type}))
            .unwrap_or_else(|| panic!("{action_type}: omitting status must still block"));
        assert_eq!(
            omitted["status"].as_u64(),
            Some(refusal_default),
            "{action_type}: the default must stay a refusal, got {omitted}"
        );
    }
}

#[test]
fn response_modify_status_is_optional_but_still_checked() {
    // Optional means absent stays absent, not "any number is fine".
    let untouched = run(json!({"type": "handle_response_modify"}))
        .expect("a modify that changes no status is legitimate");
    assert!(
        untouched.get("status").is_none() || untouched["status"].is_null(),
        "an absent status must stay absent, got {untouched}"
    );

    assert!(
        run(json!({"type": "handle_response_modify", "status": 65736})).is_none(),
        "handle_response_modify: status 65736 wraps to 200 under `as u16` and must be refused"
    );

    let ok = run(json!({"type": "handle_response_modify", "status": 404}))
        .expect("404 is a real status");
    assert_eq!(ok["status"].as_u64(), Some(404));
}
