//! Every protocol carries a scripting example and an LLM example via its
//! `get_startup_examples()` (`StartupExamples { llm_mode, script_mode, static_mode }`).
//! Those examples were defined but never reached the model: nothing rendered them
//! into any prompt. They are now emitted by the `read_documentation` tool, per
//! protocol, on demand — so they cost nothing on the always-on system prompt but
//! reach the model exactly when it is about to open that protocol.
//!
//! These tests prove the wiring end to end (the tool output actually contains the
//! protocol's own examples) rather than merely that the examples exist.

use netget::llm::actions::{execute_tool, ToolAction, ToolResult};
use netget::state::app_state::WebSearchMode;

async fn read_docs(protocol: &str) -> ToolResult {
    let action = ToolAction::ReadDocumentation {
        protocols: vec![protocol.to_string()],
        protocol: None,
    };
    execute_tool(&action, None, WebSearchMode::Off, None).await
}

/// The wiring itself: a protocol's own LLM-mode and Script-mode examples reach the
/// rendered `read_documentation` output, with a real protocol action in the script.
#[tokio::test]
async fn http_startup_examples_reach_read_documentation() {
    let doc = read_docs("http").await;
    assert!(doc.success, "read_documentation failed: {}", doc.result);

    // The StartupExamples section rendered by `to_prompt_text()`.
    assert!(
        doc.result.contains("Starting this Protocol"),
        "startup examples section missing from docs:\n{}",
        doc.result
    );
    assert!(doc.result.contains("LLM Mode"));
    assert!(doc.result.contains("Script Mode"));

    // The concrete script body — proving it is the protocol's OWN example, not a
    // generic stub, and that it uses the canonical stdin/switch-case convention.
    assert!(
        doc.result.contains("send_http_response"),
        "http's real action type should appear in its script example"
    );
    assert!(
        doc.result.contains("event_type_id"),
        "script example should use the canonical stdin convention"
    );

    // No dangling `<..._handler>` placeholder should survive into the prompt.
    assert!(
        !doc.result.contains("<http_handler>"),
        "placeholder script reference leaked into the rendered docs"
    );
}

/// The cloud family was the reported pain point; make sure each ships a real,
/// runnable script example (routed on the parsed operation) and a dynamic LLM
/// instruction — not a `<..._handler>` placeholder.
#[tokio::test]
async fn s3_examples_are_concrete() {
    let doc = read_docs("s3").await;
    assert!(doc.success, "{}", doc.result);
    assert!(doc.result.contains("Script Mode"));
    assert!(
        doc.result.contains("send_s3_bucket_list") || doc.result.contains("send_s3_object"),
        "s3 script example should use real s3 action types:\n{}",
        doc.result
    );
    assert!(!doc.result.contains("<s3_handler>"));
}

#[tokio::test]
async fn sqs_examples_are_concrete() {
    let doc = read_docs("sqs").await;
    assert!(doc.success, "{}", doc.result);
    assert!(doc.result.contains("send_sqs_response"));
    assert!(!doc.result.contains("<sqs_handler>"));
}

#[tokio::test]
async fn dynamo_examples_are_concrete() {
    let doc = read_docs("dynamo").await;
    assert!(doc.success, "{}", doc.result);
    assert!(doc.result.contains("send_dynamo_response"));
    assert!(!doc.result.contains("<dynamo_handler>"));
}

/// DNS and the other common servers had (or now have) inline script code in the
/// canonical stdin/switch-case style. Spot-check DNS, whose script must echo the
/// client's transaction id.
#[tokio::test]
async fn dns_script_example_echoes_query_id() {
    let doc = read_docs("dns").await;
    assert!(doc.success, "{}", doc.result);
    assert!(doc.result.contains("send_dns_a_response"));
    assert!(
        doc.result.contains("query_id"),
        "DNS script example must echo the transaction id"
    );
    // The old, unsupported `respond(...)` convention must be gone.
    assert!(!doc.result.contains("respond(["));
}
