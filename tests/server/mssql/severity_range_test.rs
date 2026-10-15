//! A model-supplied `severity` narrowed with `as u8` downgraded an error to a notice.
//!
//! `256 as u8` is `0`, and MS-TDS reserves severity 10-and-below for *informational*
//! messages. `mssql_error_response` is the model's only way to refuse a statement, so the one
//! field saying how badly it failed wrapped into the mildest thing the ERROR token can carry —
//! a model refusing at severity 20 (fatal, connection-terminating) delivering a note.
//!
//! `error_number` had the same cast through `as u32`: 4294967296 becomes 0, which is not a
//! SQL Server message id at all.
//!
//! Validating here rather than downstream is deliberate: `execute_action` is the only producer
//! of the `mssql_error` payload that `mod.rs` re-reads, so refusing at this choke point means
//! no out-of-range number ever reaches the token builder.


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::connection::ConnectionId;
use netget::server::MssqlProtocol;
use netget::state::app_state::AppState;
use serde_json::json;
use std::sync::Arc;

fn protocol() -> MssqlProtocol {
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    MssqlProtocol::new(ConnectionId::new(1), Arc::new(AppState::new()), status_tx)
}

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match protocol().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

fn error_with(severity: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "mssql_error_response",
        "error_number": 50000,
        "message": "permission denied",
        "severity": severity,
    })
}

#[test]
fn an_out_of_range_severity_is_refused_not_wrapped() {
    // The wrap this exists for: 256 -> 0, the informational band.
    for wrapping in [256u64, 512, 20 + 256] {
        assert!(
            run(error_with(json!(wrapping))).is_none(),
            "severity {wrapping} must be refused: `as u8` reduces it mod 256 to {}, and TDS \
             reads 10-and-below as an informational message rather than a failure",
            wrapping % 256
        );
    }
    // In u8 range but still not a TDS severity.
    for bad in [26u64, 100, 255] {
        assert!(
            run(error_with(json!(bad))).is_none(),
            "severity {bad} is outside the TDS range 0-25 and must be refused"
        );
    }

    // The refusal must not cost the legitimate call: the real severities still pass through
    // unchanged, including the fatal end the wrap was destroying.
    for good in [11u64, 16, 20, 25] {
        let data = run(error_with(json!(good)))
            .unwrap_or_else(|| panic!("severity {good} is a real TDS severity"));
        assert_eq!(
            data["severity"].as_u64(),
            Some(good),
            "severity {good} must reach the token unchanged, got {data}"
        );
    }

    // Omitting it still yields an error-band default, not an informational one.
    let mut omitted = error_with(json!(16));
    omitted.as_object_mut().unwrap().remove("severity");
    let data = run(omitted).expect("omitting severity must still answer");
    assert_eq!(data["severity"].as_u64(), Some(16));
}

#[test]
fn an_out_of_range_error_number_is_refused() {
    let with = |n: u64| {
        let mut v = error_with(json!(16));
        v["error_number"] = json!(n);
        v
    };

    assert!(
        run(with(4294967296)).is_none(),
        "error_number 4294967296 must be refused: `as u32` makes it 0, which is not a SQL \
         Server message id"
    );
    let data = run(with(4294967295)).expect("the top of the 32-bit range is legal");
    assert_eq!(data["error_number"].as_u64(), Some(4294967295));
}
