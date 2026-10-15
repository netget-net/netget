//! What a JSON-RPC caller gets when netget itself cannot answer, and what it gets when its
//! request is refused before any model is consulted.
//!
//! Three things this pins, in one server so the suite costs one model call:
//!
//! * **An oversized body is refused.** `req.collect()` was unbounded — hyper imposes no limit
//!   of its own — so the whole body was buffered, parsed into a `serde_json::Value` and
//!   pretty-printed into the trace log. One client could grow the process without bound.
//! * **An oversized batch is refused.** Every batch member is a separate model call, run
//!   sequentially on one held-open connection, so batch length is a direct amplification
//!   factor on the LLM backend that the body cap does not bound: at forty bytes a member, the
//!   4 MiB body cap still allows a hundred thousand model calls from one POST.
//! * **A failed LLM call answers with a category, never the error.** The peer used to get
//!   `WireFailure::text()` under `-32603` whatever went wrong; overload now gets `-32000`
//!   instead, in JSON-RPC's implementation-defined server-error range, so a caller backs off
//!   rather than recording a permanent internal fault. Nothing derived from the error — the
//!   backend URL, the model name, netget's retry text, an `anyhow` chain — may reach the wire.
//!
//! LLM call budget: 1 (server startup). The two refusals never reach a model, and the third
//! request deliberately matches no mock rule so the mock backend answers HTTP 500 and
//! `call_llm` returns `Err` — the branch under test.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};

/// Must match `MAX_REQUEST_BODY_BYTES` in `src/server/jsonrpc/mod.rs`.
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Must match `MAX_BATCH_LEN` in `src/server/jsonrpc/mod.rs`.
const MAX_BATCH_LEN: usize = 128;

#[tokio::test]
async fn test_jsonrpc_refuses_oversized_input_and_fails_closed_with_a_category() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via jsonrpc stack. Implement method 'greet'.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("jsonrpc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "jsonrpc",
                    "instruction": "Implement greet"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/", server.port);
    let client = reqwest::Client::new();

    // --- an oversized body is refused, and the peer is told the limit ---------------------
    //
    // Comfortably over the cap, and valid JSON so nothing but the cap can reject it.
    let padding = "x".repeat(MAX_REQUEST_BODY_BYTES + 1024);
    let huge = serde_json::json!({
        "jsonrpc": "2.0", "method": "greet", "params": [padding], "id": 1
    })
    .to_string();

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(huge)
            .send(),
    )
    .await
    .map_err(|_| "JSON-RPC neither answered nor failed within 25s on an oversized body")??;

    // JSON-RPC always answers HTTP 200; the failure is in the body.
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await?;
    println!("oversized body response: {body}");
    assert_eq!(
        body["error"]["code"], -32600,
        "an oversized body must be an Invalid Request: {body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&MAX_REQUEST_BODY_BYTES.to_string()),
        "the peer should be told the limit it exceeded: {body}"
    );

    // --- an oversized batch is refused before any model call ------------------------------
    let batch: Vec<serde_json::Value> = (0..=MAX_BATCH_LEN)
        .map(|i| serde_json::json!({"jsonrpc": "2.0", "method": "greet", "id": i}))
        .collect();

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&batch)
            .send(),
    )
    .await
    .map_err(|_| {
        "JSON-RPC neither answered nor failed within 25s on an oversized batch — which is \
         itself the symptom, since an uncapped batch is 129 sequential model calls"
    })??;

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await?;
    println!("oversized batch response: {body}");
    assert_eq!(
        body["error"]["code"], -32600,
        "an oversized batch must be an Invalid Request: {body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&MAX_BATCH_LEN.to_string()),
        "the peer should be told the batch limit: {body}"
    );

    // --- a failed LLM call answers with a category, never the error -----------------------
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "method": "greet", "params": ["world"], "id": "abc-123"
            }))
            .send(),
    )
    .await
    .map_err(|_| {
        "JSON-RPC neither answered nor failed within 25s — the server went silent on LLM \
         failure, which is the defect this test exists to catch"
    })??;

    assert_eq!(response.status(), 200);
    let text = response.text().await?;
    println!("LLM failure response: {text}");
    let body: serde_json::Value = serde_json::from_str(&text)?;

    // The correlation id belongs to the request, preserving its JSON type, even on failure.
    assert_eq!(
        body["id"], "abc-123",
        "the request id must be echoed on the failure path too: {body}"
    );

    let code = body["error"]["code"].as_i64().unwrap_or_default();
    assert!(
        code == -32603 || code == -32000,
        "the caller must get netget's failure code, and -32000 when merely saturated: {body}"
    );
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message == "request could not be processed"
            || message == "backend at capacity, retry later",
        "the message must be a category from WireFailure, nothing else: {body}"
    );
    // -32000 and -32603 must not be interchangeable to a retry policy.
    assert_eq!(
        body["error"]["data"]["retryable"],
        serde_json::json!(code == -32000),
        "retryable must agree with the code the caller was given: {body}"
    );

    for leak in [
        "http://", "ollama", "11434", "retries", ".rs:", "anyhow", "/Users/",
    ] {
        assert!(
            !text.contains(leak),
            "internal detail `{leak}` reached the wire: {text}"
        );
    }

    // Wait for the exchange the mocks describe rather than trusting a fixed sleep; under load
    // the last event routinely lands after a sleep expires.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
