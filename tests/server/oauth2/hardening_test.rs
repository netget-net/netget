//! Two hostile-input paths that produced a *success* rather than a refusal.
//!
//! Both are instances of patterns this repo has hit repeatedly, and both are pre-auth: every
//! OAuth2 endpoint is reachable before any credential is checked.
//!
//! * **An unbounded request body.** `/token`, `/introspect`, `/revoke` and `POST /authorize`
//!   each buffered the whole body with `req.into_body().collect()` and then handed it to the
//!   model as prompt text. One anonymous POST could grow the process without limit and,
//!   worse, drive an LLM call with megabytes of attacker-chosen text in the prompt.
//! * **A model-supplied status narrowed with `as u16`.** `65736 as u16` is `200`. A refusal
//!   whose `status_code` wrapped therefore arrived at the client as a success carrying an
//!   error body — the shape a client reads as "token issued". This is the OCI-registry
//!   defect (`65536 + status` truncating into a `200`) in a protocol where the success is a
//!   credential.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

async fn post_form(url: &str, body: String) -> E2EResult<(u16, String)> {
    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send(),
    )
    .await
    .map_err(|_| "No OAuth2 response within 25s")??;

    let status = response.status().as_u16();
    let text = response.text().await?;
    Ok((status, text))
}

/// A body far larger than any conforming OAuth2 form is refused, and refused *before* the
/// model is consulted — the mock declares no `oauth2_*` rule, so a request that reached the
/// LLM would show up as an unmatched call.
#[tokio::test]
async fn test_oauth2_refuses_an_oversized_token_body() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("Open oauth2 on port {AVAILABLE_PORT}.").with_mock(|mock| {
            mock.on_instruction_containing("Open oauth2")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "OAuth2",
                        "instruction": "OAuth2 authorization server"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1 MiB of form data. The server's cap is 64 KiB.
    let huge = format!(
        "grant_type=password&username=u&password={}",
        "A".repeat(1024 * 1024)
    );
    let (status, body) =
        post_form(&format!("http://127.0.0.1:{}/token", server.port), huge).await?;
    println!("oversized /token -> {status} {body}");

    assert_eq!(
        status, 413,
        "an over-limit body must be refused outright, not buffered and prompted with: got \
         {status} {body}"
    );
    assert!(
        !body.contains("access_token"),
        "no branch of an over-limit request may issue a token: {body}"
    );

    server.verify_mocks().await?;
    Ok(())
}

/// A `status_code` the model gives that does not fit a `u16` must fall back to the RFC
/// default, never wrap into a 2xx. `65736 as u16 == 200`, so the old narrowing turned a
/// refusal into the exact status a client reads as "here is your token".
#[tokio::test]
async fn test_oauth2_error_status_cannot_wrap_into_a_success() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("Open oauth2 on port {AVAILABLE_PORT}.").with_mock(|mock| {
            mock.on_instruction_containing("Open oauth2")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "OAuth2",
                        "instruction": "OAuth2 authorization server"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("oauth2_token")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "oauth2_error_response",
                        "error": "invalid_client",
                        "error_description": "no such client",
                        "status_code": 65736
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, body) = post_form(
        &format!("http://127.0.0.1:{}/token", server.port),
        "grant_type=client_credentials&client_id=nobody&client_secret=wrong".to_string(),
    )
    .await?;
    println!("wrapping status_code -> {status} {body}");

    assert_ne!(
        status, 200,
        "a refusal must not arrive as 200; 65736 narrowed with `as u16` gives exactly that"
    );
    assert!(
        (400..600).contains(&status),
        "an out-of-range status_code should fall back to the RFC 6749 5.2 default, got {status}"
    );
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    assert_eq!(
        parsed["error"].as_str(),
        Some("invalid_client"),
        "the model's refusal itself must survive: {body}"
    );
    assert!(
        parsed.get("access_token").is_none(),
        "a refusal may not carry a token: {body}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
