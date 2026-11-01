//! A static handler is validated against the protocol of the instance it is installed on —
//! never against every protocol in the build.
//!
//! The defect: a wildcard (`*`) pattern matches an event of every protocol, so the catalog a
//! wildcard handler was checked against was the union of all of them. A redis server started
//! with `send_http_response` as its catch-all, and every command was then answered
//! `ERR no response produced for this command`; and a typo (`send_redis_simple_string`) was
//! rejected with a message listing some two thousand actions from every protocol.
//!
//! `EventHandler::parse_event_handlers_for` takes the owner. Every start and update path calls
//! it; these tests call it directly, and `tests/mcp_handler_and_intercept_scope_test.rs` drives
//! the same refusal through `start_server` and `update_server`.

use netget::events::handler::{EventHandler, HandlerOwner};
use serde_json::json;

fn wildcard_static(actions: serde_json::Value) -> Vec<serde_json::Value> {
    vec![json!({
        "event_pattern": "*",
        "handler": { "type": "static", "actions": actions }
    })]
}

#[test]
fn a_wildcard_handler_may_not_name_another_protocols_action() {
    let err = EventHandler::parse_event_handlers_for(
        wildcard_static(json!([{ "type": "send_http_response", "status": 200, "body": "hi" }])),
        HandlerOwner::Server("redis"),
    )
    .expect_err("a redis server cannot execute an HTTP action, whatever the pattern");
    let msg = err.to_string();
    assert!(msg.contains("send_http_response"), "{msg}");
    assert!(
        msg.contains("Valid actions for Redis"),
        "the scope is the server's own protocol: {msg}"
    );
}

#[test]
fn the_rejection_lists_only_the_owning_protocols_actions() {
    let err = EventHandler::parse_event_handlers_for(
        wildcard_static(json!([{ "type": "send_redis_simple_string", "value": "OK" }])),
        HandlerOwner::Server("redis"),
    )
    .expect_err("a typo must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("redis_simple_string"),
        "the near-miss the caller meant is in the list: {msg}"
    );
    for foreign in ["send_tcp_data", "send_http_response", "send_dns_a_response"] {
        assert!(
            !msg.contains(foreign),
            "another protocol's action '{foreign}' must not be offered to a redis server: {msg}"
        );
    }
    assert!(
        !msg.contains("more)"),
        "redis's own vocabulary fits without truncation: {msg}"
    );
    assert!(
        msg.len() < 2_000,
        "the message is one protocol's list, not the build's ({} bytes): {msg}",
        msg.len()
    );
}

#[test]
fn the_owning_protocols_own_actions_and_the_common_ones_are_accepted() {
    EventHandler::parse_event_handlers_for(
        wildcard_static(json!([
            { "type": "append_memory", "value": "seen" },
            { "type": "redis_simple_string", "value": "OK" }
        ])),
        HandlerOwner::Server("redis"),
    )
    .expect("redis's own reply verb and a common action are valid on a redis server");

    EventHandler::parse_event_handlers_for(
        wildcard_static(json!([{ "type": "send_tcp_data", "data": "hi", "encoding": "utf8" }])),
        HandlerOwner::Server("tcp"),
    )
    .expect("tcp's own action is valid on a tcp server");
}

#[test]
fn a_client_handler_is_held_to_the_clients_vocabulary() {
    // `disconnect` is the TCP client's own (async-only) verb: accepted.
    EventHandler::parse_event_handlers_for(
        wildcard_static(json!([{ "type": "disconnect" }])),
        HandlerOwner::Client("tcp"),
    )
    .expect("a client's own verb is valid on that client");

    // `redis_simple_string` is a redis *server* reply: no TCP client can run it.
    let err = EventHandler::parse_event_handlers_for(
        wildcard_static(json!([{ "type": "redis_simple_string", "value": "OK" }])),
        HandlerOwner::Client("tcp"),
    )
    .expect_err("a server reply verb is not a TCP client action");
    assert!(err.to_string().contains("redis_simple_string"), "{err}");
}

/// The unscoped parser is what a caller with no instance gets, and it still refuses names
/// no protocol has — the typo case it exists for.
#[test]
fn without_an_owner_a_name_no_protocol_has_is_still_refused() {
    EventHandler::parse_event_handlers(wildcard_static(
        json!([{ "type": "no_protocol_has_this_action" }]),
    ))
    .expect_err("a name no protocol declares is refused even unscoped");
}
