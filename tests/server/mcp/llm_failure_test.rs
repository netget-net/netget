//! What an MCP caller gets when the LLM backend fails: a JSON-RPC error carrying its own id.
//!
//! JSON-RPC 2.0 requires the request id to come back on every reply, error or not - it is the
//! only way a client can match a failure to the call that caused it. `handle_jsonrpc` clones
//! the id before the request is consumed and re-attaches it to whatever the handler returns,
//! so this asserts the id as well as the code.
//!
//! Two calls are made, `tools/list` and `resources/list`, because those two used to be the
//! worst case: their handler loops matched one action name and fell through to a *success*
//! reply of `{"tools": []}` / `{"resources": []}`, so a failure was reported to the caller as
//! an empty-but-valid answer. An error that looks like success is worse than silence.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::time::Duration;

async fn post_jsonrpc(port: u16, method: &str, id: i64) -> E2EResult<Value> {
    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        client
            .post(format!("http://127.0.0.1:{port}"))
            .json(&json!({"jsonrpc": "2.0", "method": method, "id": id}))
            .send(),
    )
    .await
    .map_err(|_| format!("no HTTP response to {method} within 30s"))??;

    assert!(
        response.status().is_success(),
        "a JSON-RPC error is still HTTP 200; got {}",
        response.status()
    );
    Ok(response.json().await?)
}

#[tokio::test]
async fn test_mcp_returns_jsonrpc_error_when_llm_fails() -> E2EResult<()> {
    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. Serve one tool called echo";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via MCP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "Serve one tool called echo"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for any mcp_* event: the mock answers 500.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    for (method, id) in [("tools/list", 42i64), ("resources/list", 7i64)] {
        let body = post_jsonrpc(server.port, method, id).await?;
        println!("{method} -> {body}");

        assert_eq!(body["jsonrpc"], "2.0", "must be a JSON-RPC 2.0 envelope");
        assert_eq!(
            body["id"], id,
            "the request id must be echoed so the caller can correlate the failure"
        );
        assert!(
            body.get("result").is_none(),
            "an LLM failure must not be reported as a success: {body}"
        );
        assert_eq!(
            body["error"]["code"], -32603,
            "expected InternalError (-32603): {body}"
        );
        assert!(
            body["error"]["message"].is_string(),
            "the error must carry a message: {body}"
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
