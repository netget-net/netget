//! Tests that prompt-time and runtime tool classification agree (IMPROVEMENTS.md item 14).
//!
//! `build_actions_section_public` renders an action under one of two headings whose
//! boilerplate makes opposite promises: the "Available Tools" heading says the model will be
//! invoked again with the result, the "Available Actions" heading says it will not. Which
//! heading an action lands under is decided by `ActionDefinition::is_tool()`. Whether the
//! model *is actually* re-invoked is decided by `ToolAction::is_tool_action()`. If those two
//! disagree, the prompt states something false — which it did for `read_documentation`, the
//! primary discovery tool.

use netget::llm::actions::{is_tool_name, ActionDefinition, ToolAction, TOOL_ACTION_NAMES};
use netget::llm::PromptBuilder;
use netget::state::app_state::WebSearchMode;
use serde_json::json;

fn def(name: &str) -> ActionDefinition {
    ActionDefinition {
        name: name.to_string(),
        description: format!("{} description", name),
        parameters: vec![],
        example: json!({ "type": name }),
        log_template: None,
    }
}

/// The prompt-time classifier and the runtime router must never disagree.
#[test]
fn prompt_classifier_matches_runtime_router() {
    // Every name the runtime treats as a tool must be advertised as a tool.
    for name in TOOL_ACTION_NAMES {
        assert!(
            def(name).is_tool(),
            "'{}' is routed to the tool loop at runtime but is not advertised as a tool",
            name
        );
        assert!(
            ToolAction::is_tool_action(&json!({ "type": name })),
            "'{}' is in TOOL_ACTION_NAMES but is_tool_action() rejects it",
            name
        );
    }

    // And nothing else may be advertised as a tool.
    for name in [
        "send_http_response",
        "send_tcp_data",
        "open_server",
        "close_server",
        "set_memory",
        "notify_operator",
        "update_script",
        "schedule_task",
    ] {
        assert!(
            !def(name).is_tool(),
            "'{}' is advertised as a tool but the runtime will not re-invoke the model for it",
            name
        );
        assert!(!ToolAction::is_tool_action(&json!({ "type": name })));
    }
}

/// The regression itself: `read_documentation` used to be rendered under the heading that
/// promises no re-invocation.
#[test]
fn read_documentation_is_rendered_under_the_tools_heading() {
    let section = PromptBuilder::build_actions_section_public(&[
        def("read_documentation"),
        def("send_http_response"),
    ]);

    let tools_at = section
        .find("# Available Tools")
        .expect("tools heading missing");
    let actions_at = section
        .find("# Available Actions")
        .expect("actions heading missing");
    let doc_at = section
        .find("read_documentation")
        .expect("read_documentation missing from prompt");

    assert!(
        tools_at < doc_at && doc_at < actions_at,
        "read_documentation must appear under '# Available Tools', not under '# Available \
         Actions' whose text says 'you will not be invoked again if you only return actions'"
    );
}

/// Tools that were previously misclassified are all on the right side now.
#[test]
fn previously_misclassified_tools_are_tools() {
    for name in [
        "read_documentation",
        "read_server_documentation",
        "read_client_documentation",
        "list_tasks",
        "execute_sql",
        "list_databases",
    ] {
        assert!(is_tool_name(name), "'{}' should be a tool", name);
        assert!(def(name).is_tool(), "'{}' should be a tool", name);
    }
}

/// `from_json` accepts exactly the canonical list, so a name that is advertised as a tool can
/// always be parsed as one.
#[test]
fn from_json_accepts_exactly_the_canonical_names() {
    assert!(ToolAction::from_json(&json!({"type": "list_models"})).is_ok());
    assert!(ToolAction::from_json(&json!({"type": "list_tasks"})).is_ok());
    assert!(
        ToolAction::from_json(&json!({"type": "not_a_tool"})).is_err(),
        "unknown tool names must be rejected"
    );
    // `list_network_interfaces` was classified as a tool by the prompt but has no
    // ToolAction variant and no runtime handler; it must not be advertised as one.
    assert!(!is_tool_name("list_network_interfaces"));
}

/// Every real tool definition handed to the prompt builder classifies as a tool.
#[test]
fn shipped_tool_definitions_all_classify_as_tools() {
    for action in netget::llm::actions::get_all_tool_actions(WebSearchMode::On) {
        assert!(
            action.is_tool(),
            "tool definition '{}' is not classified as a tool",
            action.name
        );
    }
    for action in netget::llm::actions::get_network_event_tool_actions(WebSearchMode::On) {
        assert!(
            action.is_tool(),
            "network-event tool definition '{}' is not classified as a tool",
            action.name
        );
    }
}
