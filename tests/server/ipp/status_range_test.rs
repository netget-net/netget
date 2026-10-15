//! A model-supplied `http_status` narrowed with `as u16` became a 200.
//!
//! `65736 as u16` is `200`. IPP rides on HTTP, and a CUPS-style client decides whether it has
//! a printer at all from the HTTP status before it ever looks at the IPP status inside — so
//! the wrap turned every refusal the model could express at that layer into an acceptance.
//!
//! `ipp_response` accepts the field under either `http_status` or `status`, so both spellings
//! are checked. Out of range is refused rather than clamped: 599 is not what the model asked
//! for either, and the message is what the repair loop reads.

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::ipp::actions::IppProtocol;
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match IppProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn out_of_range_http_status_is_refused_not_wrapped() {
    // Both spellings the action accepts.
    for key in ["http_status", "status"] {
        assert!(
            run(json!({"type": "ipp_response", key: 65736})).is_none(),
            "{key} 65736 must be refused: `as u16` makes it 200, so a refusal reached the \
             client as the acceptance it was refusing"
        );
        for bad in [0u64, 99, 600, 1000, 65535] {
            assert!(
                run(json!({"type": "ipp_response", key: bad})).is_none(),
                "{key} {bad} is not an HTTP status code and must be refused"
            );
        }
        // A real status still goes through unchanged under either spelling.
        let ok = run(json!({"type": "ipp_response", key: 401}))
            .unwrap_or_else(|| panic!("{key}: 401 is a real HTTP status"));
        assert_eq!(ok["http_status"].as_u64(), Some(401));
    }
}

#[test]
fn omitting_the_status_still_answers_200() {
    // The refusal must not have become a refusal of everything: IPP deliberately answers
    // HTTP 200 and carries its own outcome in `ipp_status`, so the default has to survive.
    let data = run(json!({"type": "ipp_response", "ipp_status": "server-error-internal-error"}))
        .expect("omitting http_status must still answer");
    assert_eq!(data["http_status"].as_u64(), Some(200));
    assert!(
        !data["body_hex"].as_str().unwrap_or("").is_empty(),
        "the IPP body must still be built: {data}"
    );
}
