//! Every event's documented example answer names only actions that event can be answered with,
//! and every event documents its fields — over the whole server and client registries.
//!
//! `get_protocol_docs tcp` showed the tcp **client**'s `tcp_connected` and
//! `tcp_data_received` with "(no documented fields)" and an example answer of `show_message`,
//! an action the client did not list: the client declared its events as fresh
//! `EventType::new(.., placeholder)` with no fields, and the example generator filled a
//! placeholder from the event's own (empty) action list and then fell back to a note to the
//! operator. A model or a handler author copies that example.
//!
//! What "valid" means differs by role, and this test computes it the way the runtime does:
//!
//! - a **server** event offers its own `actions` (`call_llm` narrows); one that forgot to
//!   attach any is repaired with the protocol's sync actions; the common actions are
//!   `network_event_common_actions_for` — `notify_operator` only where no protocol action is
//!   offered, the connection-memory pair only on a connection-oriented protocol;
//! - a **client** event offers every action the client declares, async and sync, plus the
//!   event's own (`client_llm_action_set`), and the client common actions
//!   (`set_memory`, `append_memory`, `notify_operator`).
//!
//! The example checked is the one the docs render (`effective_response_example_from` with
//! `protocol::docs::example_fallback_actions`), and every alternative example.
//!
//! The field check is a ratchet (AGENTS.md "Whole-tree source ratchets"): events that declare
//! no fields were counted when it was written, and the count may only go down.

use netget::llm::actions::client_trait::client_llm_action_set;
use netget::llm::actions::common::network_event_common_actions_for;
use netget::llm::actions::protocol_trait::Protocol;
use netget::llm::actions::ActionDefinition;
use netget::protocol::docs::{example_fallback_actions, fresh_state, Role};
use netget::protocol::server_registry::registry;
use netget::protocol::{EventType, CLIENT_REGISTRY};
use std::collections::BTreeSet;

/// Events, server and client, that declare no data fields. May only go down; when you document
/// some, lower it to the new count the failure message prints.
const EVENTS_WITHOUT_FIELDS_BASELINE: usize = 213;

/// Every top-level `type` an example answer names: a single action object, an envelope
/// `{"actions": [..]}` (no `type` of its own), or an array of either. An action's own fields
/// are not descended into — OpenFlow's `openflow_packet_out` carries a list of OpenFlow
/// `actions` (`{"type": "output", ..}`) that are packet actions, not NetGet actions.
fn action_types(example: &serde_json::Value, out: &mut Vec<String>) {
    match example {
        serde_json::Value::Array(items) => items.iter().for_each(|i| action_types(i, out)),
        serde_json::Value::Object(obj) => {
            if let Some(t) = obj.get("type").and_then(|t| t.as_str()) {
                out.push(t.to_string());
            } else if let Some(actions) = obj.get("actions") {
                action_types(actions, out);
            }
        }
        _ => {}
    }
}

fn names(actions: &[ActionDefinition]) -> BTreeSet<String> {
    actions.iter().map(|a| a.name.clone()).collect()
}

/// The action names the model is offered for a server event, as `call_llm` builds them.
fn server_offer<P: Protocol + ?Sized>(p: &P, event: &EventType) -> BTreeSet<String> {
    let mut protocol_actions = event.actions.clone();
    if event.has_no_usable_actions() {
        protocol_actions = p.get_sync_actions();
    }
    let mut out = names(&protocol_actions);
    out.extend(names(&network_event_common_actions_for(
        !protocol_actions.is_empty(),
        !p.metadata().connectionless,
    )));
    out
}

/// The action names the model is offered for a client event, as `call_llm_for_client` builds
/// them.
fn client_offer(
    p: &dyn netget::llm::actions::client_trait::Client,
    event: &EventType,
) -> BTreeSet<String> {
    let mut out = names(&client_llm_action_set(p, fresh_state(), None));
    out.extend(names(&event.actions));
    for common in ["set_memory", "append_memory", "notify_operator"] {
        out.insert(common.to_string());
    }
    out
}

fn check_examples<P: Protocol + ?Sized>(
    label: &str,
    p: &P,
    event: &EventType,
    role: Role,
    offered: &BTreeSet<String>,
    offenders: &mut Vec<String>,
) {
    let fallback = example_fallback_actions(p, fresh_state(), event, role);
    let mut examples = vec![event.effective_response_example_from(&fallback)];
    examples.extend(event.alternative_examples.iter().cloned());
    for example in &examples {
        let mut types = Vec::new();
        action_types(example, &mut types);
        for t in types {
            if !offered.contains(&t) {
                offenders.push(format!(
                    "{label} / {}: example answers with `{t}`, which this event does not offer \
                     (offered: {})",
                    event.id,
                    offered.iter().cloned().collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
}

#[test]
fn every_event_example_uses_only_actions_its_event_offers() {
    let mut offenders = Vec::new();
    let mut inspected = 0usize;

    let mut servers = registry().all_protocols();
    servers.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, p) in &servers {
        for event in p.get_event_types() {
            inspected += 1;
            let offered = server_offer(p.as_ref(), &event);
            check_examples(
                &format!("server {name}"),
                p.as_ref(),
                &event,
                Role::Server,
                &offered,
                &mut offenders,
            );
        }
    }

    let mut clients = CLIENT_REGISTRY.get_all();
    clients.sort_by(|a, b| a.protocol_name().cmp(b.protocol_name()));
    for p in &clients {
        for event in p.get_event_types() {
            inspected += 1;
            let offered = client_offer(p.as_ref(), &event);
            check_examples(
                &format!("client {}", p.protocol_name()),
                p.as_ref(),
                &event,
                Role::Client,
                &offered,
                &mut offenders,
            );
        }
    }

    assert!(
        inspected > 500,
        "only {inspected} events inspected — the audit proves nothing"
    );
    assert!(
        offenders.is_empty(),
        "{} event example(s) answer with an action the event does not offer:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

#[test]
fn events_document_their_fields_ratchet() {
    let mut missing = Vec::new();
    for (name, p) in registry().all_protocols() {
        for event in p.get_event_types() {
            if event.parameters.is_empty() {
                missing.push(format!("server {name} / {}", event.id));
            }
        }
    }
    for p in CLIENT_REGISTRY.get_all() {
        for event in p.get_event_types() {
            if event.parameters.is_empty() {
                missing.push(format!("client {} / {}", p.protocol_name(), event.id));
            }
        }
    }
    missing.sort();
    // The two events this audit was written for must stay documented outright.
    for fixed in [
        "client TCP / tcp_connected",
        "client TCP / tcp_data_received",
    ] {
        assert!(
            !missing.iter().any(|m| m == fixed),
            "{fixed} lost its fields"
        );
    }
    assert!(
        missing.len() <= EVENTS_WITHOUT_FIELDS_BASELINE,
        "{} event(s) declare no data fields, above the baseline of {}. Document the fields \
         (`EventType::with_parameters`) of the events you added:\n  {}",
        missing.len(),
        EVENTS_WITHOUT_FIELDS_BASELINE,
        missing.join("\n  ")
    );
    if missing.len() < EVENTS_WITHOUT_FIELDS_BASELINE {
        eprintln!(
            "events_document_their_fields_ratchet: {} events without fields; lower \
             EVENTS_WITHOUT_FIELDS_BASELINE to that",
            missing.len()
        );
    }
}
