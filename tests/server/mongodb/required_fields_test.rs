//! A write acknowledgement the model did not actually make must not be invented.
//!
//! `insert_response`, `update_response`, `delete_response` and `error_response` declare their
//! count and code parameters `required: true`. The executors used to substitute a default for
//! all of them but `inserted_count`, and every default is a claim about the data:
//!
//! * `matched_count: 0` / `deleted_count: 0` tell the driver "your filter matched nothing",
//!   which is a statement about a collection this server does not have.
//! * `modified_count: 0` reports a successful update that changed nothing.
//! * `error_response`'s `code: 0` is MongoDB's `OK`, so the refusal named success as its
//!   cause; `"Unknown error"` threw away the only thing the model knew.
//!
//! Refusing surfaces the malformed answer to the model for repair, and if that fails the
//! server's `decision=fail_closed_no_answer` path answers `{ok: 0}` — a failure, not a result.
//!
//! This is the shape `executable_examples_test` cannot catch: it sends each action's declared
//! example, which carries every field, so it can only find a *wrong* field, never a missing
//! one.

use netget::llm::actions::protocol_trait::Server;
use netget::server::connection::ConnectionId;
use netget::server::MongodbProtocol;
use netget::state::app_state::AppState;
use std::sync::Arc;

fn protocol() -> MongodbProtocol {
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    MongodbProtocol::new(ConnectionId::new(1), Arc::new(AppState::new()), status_tx)
}

#[test]
fn required_write_counts_are_not_defaulted() {
    let p = protocol();

    for action in [
        serde_json::json!({"type": "insert_response"}),
        serde_json::json!({"type": "update_response"}),
        serde_json::json!({"type": "update_response", "matched_count": 1}),
        serde_json::json!({"type": "update_response", "modified_count": 1}),
        serde_json::json!({"type": "delete_response"}),
    ] {
        let err = p
            .execute_action(action.clone())
            .expect_err(&format!("{action} must be refused, not defaulted"));
        let text = err.to_string();
        assert!(
            text.contains("_count"),
            "the refusal has to name the missing field so the model can repair it, got: {text}"
        );
    }
}

#[test]
fn error_response_requires_a_code_and_a_message() {
    let p = protocol();

    for action in [
        serde_json::json!({"type": "error_response", "message": "Namespace not found"}),
        serde_json::json!({"type": "error_response", "code": 26}),
        // An empty message is the same defect wearing a value: the driver raises with
        // nothing in `errmsg`.
        serde_json::json!({"type": "error_response", "code": 26, "message": "   "}),
    ] {
        p.execute_action(action.clone())
            .expect_err(&format!("{action} must be refused"));
    }

    p.execute_action(serde_json::json!({
        "type": "error_response", "code": 26, "message": "Namespace not found"
    }))
    .expect("a complete error_response is still accepted");
}

/// The counts that *are* supplied still reach the wire encoder unchanged.
#[test]
fn supplied_counts_are_carried_through() {
    let p = protocol();

    let result = p
        .execute_action(serde_json::json!({
            "type": "update_response", "matched_count": 3, "modified_count": 2
        }))
        .expect("a complete update_response is accepted");

    match result {
        netget::llm::actions::protocol_trait::ActionResult::Custom { name, data } => {
            assert_eq!(name, "mongodb_response");
            assert_eq!(data["matched_count"], 3);
            assert_eq!(data["modified_count"], 2);
        }
        other => panic!("expected a mongodb_response custom result, got {other:?}"),
    }
}
