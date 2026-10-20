//! Model-facing text reaches prompts verbatim, including memory, instructions, and HTTP data.
//!
//! Memory is the one thing a model keeps between events, and it reads it back from the
//! prompt's "Current State" section. That section is a Handlebars partial, and a
//! double-brace `{{ }}` there HTML-escapes: memory the model wrote as `room: "Hall"` came back
//! as `room: &quot;Hall&quot;`, an apostrophe as `&#x27;`, and a model that copied its memory
//! forward turned `&` into `&amp;` a little more each event. The instruction's copy in the same
//! section showed the demo's `"play"` as `&quot;play&quot;`.

use netget::llm::actions::get_network_event_common_actions;
use netget::llm::PromptBuilder;
use netget::state::app_state::AppState;
use netget::state::server::{ServerInstance, ServerStatus};
use netget::state::ServerId;

#[tokio::test]
async fn user_instructions_are_verbatim_and_operator_tools_remain_available() {
    let state = AppState::new();
    let instruction = r#"Serve "quoted" text & keep <tags>; it's literal."#;
    let prompt = PromptBuilder::build_action_prompt(
        &state,
        None,
        instruction,
        netget::llm::actions::get_all_tool_actions(netget::state::app_state::WebSearchMode::Off),
        false,
        None,
    )
    .await;
    assert!(prompt.contains(instruction), "{prompt}");
    assert!(prompt.contains("read_file"), "operator tools disappeared");
    for escaped in ["&quot;", "&#x27;", "&amp;", "&lt;", "&gt;"] {
        assert!(!prompt.contains(escaped), "{escaped} in:\n{prompt}");
    }
}

#[tokio::test]
async fn feedback_without_tools_uses_the_actions_only_response_contract() {
    let state = AppState::new();
    let instruction = r#"Keep "quotes" & <tags> literal."#;
    let prompt = PromptBuilder::build_feedback_system_prompt(
        &state,
        None,
        None,
        instruction,
        instruction,
        instruction,
        &[],
        get_network_event_common_actions(),
    )
    .await;
    assert!(prompt.contains(instruction), "{prompt}");
    assert!(prompt.contains("No tools are available"), "{prompt}");
    assert!(!prompt.contains("generate_random"), "{prompt}");
    assert!(!prompt.contains("read_file"), "{prompt}");
}

#[test]
fn http_request_fields_reach_the_model_verbatim() {
    let path = r#"/search/"lamp"/it's<me>"#;
    let header = r#""Hall" & <Vault> isn't escaped"#;
    let prompt = netget::llm::template_engine::TemplateEngine::from_embedded()
        .unwrap()
        .render_json(
            "easy_request/http",
            &serde_json::json!({
                "user_instruction": "answer this request",
                "method": "GET", "path": path, "query_string": "a=1&b=2",
                "headers": [{"name": "X-Note", "value": header}],
                "body": "",
            }),
        )
        .unwrap();
    assert_eq!(prompt.matches(path).count(), 1, "{prompt}");
    assert_eq!(prompt.matches(header).count(), 1, "{prompt}");
    assert!(prompt.contains("a=1&b=2"), "{prompt}");
}

#[tokio::test]
async fn memory_and_instruction_are_not_html_escaped_in_the_event_prompt() {
    let state = AppState::new();
    let instruction = r#"Run a tiny adventure if they type "play" & keep it <short>; it's fine."#;
    let memory = "room: \"Hall\" & dark\nnote: it's <locked>";
    let mut server = ServerInstance::new(
        ServerId::new(1),
        2323,
        "Telnet".to_string(),
        instruction.to_string(),
    );
    server.status = ServerStatus::Running;
    server.memory = memory.to_string();
    let id = state.add_server(server).await;

    let prompt = PromptBuilder::build_network_event_action_prompt_for_server(
        &state,
        id,
        get_network_event_common_actions(),
    )
    .await;

    let current = &prompt[prompt
        .find("# Current State")
        .expect("the Current State section")..];
    // Memory is fenced so a multi-line value cannot break out of its bullet; inside the
    // fence it must still be the exact text, quotes, ampersands and angle brackets included.
    assert!(
        current.contains(&format!("- **Memory**:\n```text\n{memory}\n```")),
        "memory is not verbatim:\n{current}"
    );
    assert!(
        current.contains(&format!("- **Instruction**: {instruction}")),
        "the instruction is not verbatim:\n{current}"
    );
    for escaped in ["&quot;", "&#x27;", "&amp;", "&lt;", "&gt;"] {
        assert!(!current.contains(escaped), "{escaped} in:\n{current}");
    }
    assert!(!prompt.contains("# Available Tools"), "{prompt}");
    assert!(!prompt.contains("generate_random"), "{prompt}");
    assert!(!prompt.contains("read_documentation"), "{prompt}");
}
