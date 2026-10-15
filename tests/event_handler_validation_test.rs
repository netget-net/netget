//! Parse-time validation of static event handlers, and access-log visibility of action
//! execution failures.
//!
//! Covers IMPROVEMENTS items 7 and 41: an `event_handlers` entry naming an action that
//! does not exist used to be accepted by `start_server` and then fail silently at the
//! first packet, and an action whose executor returned an error was dropped with only a
//! `warn!` while the access log recorded it as though it had run.

use netget::events::handler::EventHandler;
use serde_json::json;

/// Build a single `event_handlers` entry with a static handler.
fn static_handler(pattern: &str, actions: serde_json::Value) -> Vec<serde_json::Value> {
    vec![json!({
        "event_pattern": pattern,
        "handler": { "type": "static", "actions": actions }
    })]
}

#[test]
fn unknown_action_name_is_rejected_at_parse_time() {
    let err = EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([{ "type": "this_action_does_not_exist" }]),
    ))
    .expect_err("a nonexistent action name must not be accepted");

    let msg = err.to_string();
    assert!(
        msg.contains("this_action_does_not_exist"),
        "error must name the offending action, got: {msg}"
    );
    assert!(
        msg.contains("send_tcp_data"),
        "error must list the valid actions, got: {msg}"
    );
    assert!(
        msg.contains("tcp_data_received"),
        "error must name the event the handler was configured for, got: {msg}"
    );
}

#[test]
fn valid_action_name_is_accepted() {
    let config = EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([{ "type": "send_tcp_data", "data": "PONG", "encoding": "utf8" }]),
    ))
    .expect("a valid TCP action must still be accepted");
    assert_eq!(config.len(), 1);
}

#[test]
fn common_actions_are_accepted_for_any_protocol() {
    EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([
            { "type": "append_memory", "value": "seen a request" },
            { "type": "send_tcp_data", "data": "ok", "encoding": "utf8" }
        ]),
    ))
    .expect("common actions must be valid alongside protocol actions");
}

#[test]
fn action_valid_for_another_protocol_is_rejected() {
    // `send_dns_a_response` is a DNS action; on a TCP event it cannot execute.
    let err = EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([{ "type": "send_dns_a_response", "domain": "example.com", "ip": "1.2.3.4" }]),
    ))
    .expect_err("an action from a different protocol must not be accepted");
    assert!(err.to_string().contains("send_dns_a_response"));
}

#[test]
fn malformed_event_reference_is_rejected_at_parse_time() {
    // `EventHandlerType::validate()` detects a reference with an empty path.
    let err = EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([{ "type": "send_tcp_data", "data": "{{event.}}", "encoding": "utf8" }]),
    ))
    .expect_err("an empty {{event.}} path must be rejected");
    assert!(
        err.to_string().contains("{{event.}}"),
        "error must quote the offending reference, got: {}",
        err
    );

    // ... and one with a doubled separator.
    let err = EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([{ "type": "send_tcp_data", "data": "{{event..data}}", "encoding": "utf8" }]),
    ))
    .expect_err("a doubled `.` in an {{event.…}} path must be rejected");
    assert!(
        err.to_string().contains("empty path segment"),
        "error must explain the malformed path, got: {}",
        err
    );
}

#[test]
fn well_formed_event_reference_is_accepted() {
    EventHandler::parse_event_handlers(static_handler(
        "tcp_data_received",
        json!([{ "type": "send_tcp_data", "data": "PONG:{{event.data}}", "encoding": "utf8" }]),
    ))
    .expect("a well-formed reference must still be accepted");
}

#[test]
fn unknown_event_pattern_is_not_validated() {
    // No compiled protocol declares this event, so there is no catalog to check against;
    // the handler is accepted rather than rejected on a guess.
    EventHandler::parse_event_handlers(static_handler(
        "no_protocol_declares_this_event",
        json!([{ "type": "whatever_this_is" }]),
    ))
    .expect("an unknown event pattern must not cause a false rejection");
}

#[test]
fn script_handlers_are_not_action_validated() {
    // Script handlers produce their actions at runtime; there is nothing to validate.
    EventHandler::parse_event_handlers(vec![json!({
        "event_pattern": "tcp_data_received",
        "handler": { "type": "script", "language": "python", "code": "print('{}')" }
    })])
    .expect("script handlers must not be action-validated");
}

// ---------------------------------------------------------------------------
// Item 41: failed actions are distinguishable in the access log
// ---------------------------------------------------------------------------

#[test]
fn successful_actions_are_recorded_verbatim() {
    let mut result = netget::llm::ExecutionResult::new();
    result.raw_actions = vec![json!({ "type": "send_tcp_data", "data": "ok" })];

    assert!(!result.has_failures());
    assert!(result.failure_summary().is_none());
    assert_eq!(result.access_log_actions(), result.raw_actions);
}

#[test]
fn failed_actions_are_marked_in_the_access_log() {
    let mut result = netget::llm::ExecutionResult::new();
    result.raw_actions = vec![
        json!({ "type": "send_tcp_data", "encoding": "utf8" }),
        json!({ "type": "close_this_connection" }),
    ];
    result.add_failure(0, "send_tcp_data", "Missing 'data' parameter");

    assert!(result.has_failures());
    let logged = result.access_log_actions();
    assert_eq!(logged.len(), 2);

    // The failed action no longer looks like a successful one.
    assert_eq!(
        logged[0]["type"],
        json!(format!(
            "{}send_tcp_data",
            netget::llm::FAILED_ACTION_TYPE_PREFIX
        ))
    );
    assert_eq!(logged[0]["error"], json!("Missing 'data' parameter"));
    assert_eq!(logged[0]["action"], result.raw_actions[0]);

    // The action that did run is untouched: a failure does not abort the batch.
    assert_eq!(logged[1], result.raw_actions[1]);

    let summary = result
        .failure_summary()
        .expect("summary for a failed batch");
    assert!(summary.contains("send_tcp_data"));
    assert!(summary.contains("Missing 'data' parameter"));
}
