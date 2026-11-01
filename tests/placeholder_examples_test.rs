//! No registered protocol may show a model a `{"type": "placeholder"}` response example.
//!
//! `EventType::response_example` is rendered verbatim into the network-request prompt
//! (`src/llm/actions/tools.rs`) and into the MCP protocol docs (`src/mcp_stdio/docs.rs`). It is
//! the worked example of how to answer an event, so a placeholder teaches the model an action
//! type that does not exist — and the executor rejects it as unknown, which costs two retries
//! and then the request.
//!
//! 215 events across 92 files carry the literal `{"type": "placeholder", "event_id": "..."}`.
//! Rather than hand-write 215 examples, `EventType::effective_response_example()` derives one
//! from the event's first attached action, whose `example` is by construction a valid answer to
//! that event. This test pins the property that matters — nothing a model is shown is a
//! placeholder — rather than the literal field, so the remaining literals can be swept
//! protocol-by-protocol without a flag day.

use netget::protocol::server_registry::registry;
use netget::protocol::EventType;

#[test]
fn no_registered_protocol_renders_a_placeholder_example() {
    let mut offenders = Vec::new();

    for (name, protocol) in registry().all_protocols() {
        for event in protocol.get_event_types() {
            let rendered = event.effective_response_example();
            if EventType::is_placeholder(&rendered) {
                offenders.push(format!("{name} / {}", event.id));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{} event(s) still render a placeholder response example to the model.\n\
         Give the event a real response_example, or attach an action whose own example is \
         real — effective_response_example() falls back to the first attached action.\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// The derivation must not be vacuously true because nothing was inspected.
#[test]
fn the_placeholder_audit_has_something_to_inspect() {
    let events: usize = registry()
        .all_protocols()
        .iter()
        .map(|(_, p)| p.get_event_types().len())
        .sum();
    assert!(
        events > 0,
        "no event types were inspected — the audit proves nothing"
    );
}

/// A placeholder is repaired from the first attached action, and a real example is left alone.
#[test]
fn effective_response_example_repairs_only_placeholders() {
    use netget::llm::actions::{ActionDefinition, Parameter};

    let real = serde_json::json!({"type": "send_thing", "value": 1});
    let placeholder = serde_json::json!({"type": "placeholder", "event_id": "x"});

    let action = ActionDefinition {
        name: "send_thing".to_string(),
        description: "d".to_string(),
        parameters: Vec::<Parameter>::new(),
        example: real.clone(),
        log_template: None,
    };

    // Declared example is real: returned untouched, action or no action.
    let kept = EventType::new("x", "d", real.clone());
    assert_eq!(kept.effective_response_example(), real);

    // Declared example is a placeholder: repaired from the first action.
    let repaired = EventType::new("x", "d", placeholder.clone()).with_actions(vec![action]);
    assert_eq!(repaired.effective_response_example(), real);

    // Placeholder with no action to borrow from: falls back to a common action, never a
    // placeholder.
    let fallback = EventType::new("x", "d", placeholder).with_no_actions();
    let got = fallback.effective_response_example();
    assert!(!EventType::is_placeholder(&got));
    assert_eq!(got["type"], "notify_operator");
}
