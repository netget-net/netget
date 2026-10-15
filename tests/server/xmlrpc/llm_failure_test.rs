//! What an XML-RPC client gets when the LLM backend fails: a `<fault>`, carrying a category.
//!
//! XML-RPC is strictly request/response — the client blocks on a reply — so silence is never
//! the right answer here. The server already answered on this path; what it answered with was
//! `Internal error: <the anyhow chain>`, i.e. the backend URL, the model name and netget's own
//! retry text in the `faultString` a stranger's client prints. See `src/utils/wire_failure.rs`.
//!
//! Three cases stay apart:
//!   * the model *rejected* — it emits its own `xmlrpc_fault_response` and never reaches the
//!     failure path at all;
//!   * the model *answered nothing* — `faultCode -32603`, `decision=fail_closed_no_action`;
//!   * the LLM call *errored* — `faultCode -32603` (`decision=fail_closed_llm_error`), or
//!     `-32000` when the backend is merely saturated (`decision=fail_closed_llm_overloaded`),
//!     which is in the implementation-defined server-error range so a client can back off
//!     rather than record a permanent internal fault.
//!
//! This test drives the LLM-errored case, which is the one that leaked.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_xmlrpc_faults_with_a_category_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'greet'.";

    // Only the startup instruction is mocked. The `xmlrpc_method_call` event matches no rule,
    // so the mock backend answers HTTP 500 and `call_llm` returns `Err` — the branch under
    // test.
    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("xmlrpc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "XML-RPC",
                    "instruction": "Implement greet"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let xml_request = r#"<?xml version="1.0"?>
<methodCall>
  <methodName>greet</methodName>
  <params><param><value><string>world</string></value></param></params>
</methodCall>"#;

    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client
            .post(format!("http://127.0.0.1:{}/", server.port))
            .header("Content-Type", "text/xml")
            .body(xml_request)
            .send(),
    )
    .await
    .map_err(|_| {
        "XML-RPC neither answered nor failed within 25s — the server went silent on LLM \
         failure, which is the defect this test exists to catch"
    })??;

    // Faults ride on HTTP 200 in XML-RPC; the fault is in the body.
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    println!("XML-RPC failure response:\n{body}");

    assert!(
        body.contains("<fault>"),
        "the client must get a fault, not a value: {body}"
    );
    assert!(
        body.contains("-32603") || body.contains("-32000"),
        "the fault must carry netget's failure code: {body}"
    );
    assert!(
        body.contains("request could not be processed")
            || body.contains("backend at capacity, retry later"),
        "faultString must be a category from WireFailure, nothing else: {body}"
    );

    // Nothing derived from the error may reach the wire.
    for leak in [
        "http://",
        "ollama",
        "11434",
        "retries",
        ".rs:",
        "Internal error:",
        "anyhow",
        "/Users/",
    ] {
        assert!(
            !body.contains(leak),
            "internal detail `{leak}` reached the wire: {body}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
