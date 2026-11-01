//! `event_handlers` must reject configuration that cannot work, at parse time.
//!
//! Both shapes below were silently accepted, and both cost a full round of protocol-level
//! debugging before the real cause surfaced. They are exactly what an LLM writing handlers
//! gets wrong, because in both cases the configuration looks entirely reasonable.
//!
//! 1. **An unknown key.** Data-based matching is spelled `match` (exact values per field
//!    path) and nothing else. An `event_data_contains` key is a natural
//!    thing to assume exists, and it used to be accepted and ignored, so every rule
//!    registered against one event id matched every occurrence and first-match-wins picked
//!    the first. A zookeeper test wrote five such rules to answer five different requests;
//!    the `create` rule answered all of them, and the client failed with `MarshallingError`
//!    from a reply with the wrong body.
//!
//! 2. **A script whose entry point contradicts its `resident` flag.** A resident script
//!    defines `handle(event_type, event, message)`; a non-resident one reads stdin and
//!    prints its own output. Define `handle` without `resident: true` and the script
//!    produces nothing at all, the handler yields no actions, and the server fails closed --
//!    which the peer sees as a generic protocol error naming nothing.

use netget::scripting::{EventHandler, EventHandlerType};

#[test]
fn an_unknown_handler_key_is_rejected_rather_than_ignored() {
    let json = serde_json::json!({
        "event_pattern": "zookeeper_request",
        // No such thing. Rules match on the event id alone.
        "event_data_contains": { "operation": "getData" },
        "handler": { "type": "static", "actions": [] }
    });
    let err = serde_json::from_value::<EventHandler>(json)
        .expect_err("an unknown key must be rejected, not silently ignored");
    let msg = err.to_string();
    assert!(
        msg.contains("event_data_contains"),
        "the error must name the offending key so the author can find it, got: {msg}"
    );
}

#[test]
fn a_well_formed_handler_still_parses() {
    let json = serde_json::json!({
        "event_pattern": "*",
        "handler": { "type": "static", "actions": [{ "type": "send_tcp_data", "data": "hi" }] }
    });
    serde_json::from_value::<EventHandler>(json).expect("a valid handler must still parse");
}

#[test]
fn a_handle_defining_script_must_be_marked_resident() {
    let code = "def handle(event_type, event, message):\n    return []\n";

    let not_resident = EventHandlerType::Script {
        language: "python".to_string(),
        code: code.to_string(),
        resident: false,
        scope: None,
    };
    let err = not_resident
        .validate()
        .expect_err("defining handle() without resident must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("resident"),
        "the error must point at the resident flag, got: {msg}"
    );

    let resident = EventHandlerType::Script {
        language: "python".to_string(),
        code: code.to_string(),
        resident: true,
        scope: None,
    };
    resident
        .validate()
        .expect("the same script marked resident is correct and must pass");
}

/// A non-resident script that reads stdin is the correct non-resident shape and must not be
/// flagged. The check looks for a *definition* of `handle`, not the word.
#[test]
fn a_stdin_reading_script_is_not_flagged() {
    let handler = EventHandlerType::Script {
        language: "python".to_string(),
        code: "import sys, json\nevent = json.load(sys.stdin)\nprint('[]')\n".to_string(),
        resident: false,
        scope: None,
    };
    handler
        .validate()
        .expect("a stdin-reading non-resident script is correct");
}
