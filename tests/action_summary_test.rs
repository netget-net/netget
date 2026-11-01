use netget::llm::actions::summary::{summarize_action, summarize_actions};
use serde_json::json;

#[test]
fn test_summarize_notify_operator() {
    let action = json!({
        "type": "notify_operator",
        "message": "Server started successfully"
    });
    assert_eq!(
        summarize_action(&action),
        "notify_operator: \"Server started successfully\""
    );
    // The former name is read as the same action.
    let legacy = json!({"type": "show_message", "message": "Server started successfully"});
    assert_eq!(summarize_action(&legacy), summarize_action(&action));
}

#[test]
fn test_summarize_open_server() {
    let action = json!({
        "type": "open_server",
        "port": 8080,
        "base_stack": "http",
        "instruction": "Act as REST API server"
    });
    assert_eq!(
        summarize_action(&action),
        "open_server: http port=8080 \"Act as REST API server\""
    );
}

#[test]
fn test_summarize_read_file() {
    let action = json!({
        "type": "read_file",
        "path": "schema.json",
        "mode": "full"
    });
    assert_eq!(summarize_action(&action), "read_file: schema.json (full)");
}

#[test]
fn test_summarize_actions() {
    let actions = vec![
        json!({"type": "notify_operator", "message": "Test"}),
        json!({"type": "read_file", "path": "test.txt", "mode": "head", "lines": 10}),
    ];
    let summary = summarize_actions(&actions);
    assert!(summary.starts_with("2 actions:"));
    assert!(summary.contains("notify_operator"));
    assert!(summary.contains("read_file"));
}
