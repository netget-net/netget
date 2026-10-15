//! Two ways the IDP could be made to answer `2xx` without a decision behind it.
//!
//! A `2xx` is the only thing an SP treats as a completed sign-in, so for an IDP the
//! "affirmative default" class of bug is the vulnerability rather than a cosmetic one.
//!
//! * **The request body was unbounded.** `/sso` takes an anonymous POST and the body goes to
//!   the model verbatim as prompt text, so one request could grow the process without limit
//!   and drive an LLM call with megabytes of attacker-chosen prompt.
//! * **A model-supplied `status` was narrowed with `as u16`.** `65736 as u16` is `200`, so a
//!   `send_error_response` — the model's only way to refuse to authenticate — arrived with
//!   the status that says the opposite.


use crate::server::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// An over-limit `/sso` body is refused before the model is consulted. The mock declares no
/// `saml_idp_request` rule, so an LLM call would surface as an unmatched request.
#[tokio::test]
async fn test_saml_idp_refuses_an_oversized_request_body() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a SAML Identity Provider on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("SAML Identity Provider")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "saml-idp",
                        "instruction": "SAML IDP"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1 MiB. The server's cap is 256 KiB.
    let huge = format!("SAMLRequest={}", "A".repeat(1024 * 1024));
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/sso", server.port))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(huge)
        .timeout(Duration::from_secs(25))
        .send()
        .await?;

    let status = response.status().as_u16();
    let body = response.text().await?;
    println!("oversized /sso -> {status}");

    assert_eq!(
        status, 413,
        "an over-limit body must be refused, not buffered and prompted with: {body}"
    );
    assert!(
        !body.contains("SAMLResponse"),
        "no branch of an over-limit request may emit an assertion form: {body}"
    );

    server.verify_mocks().await?;
    Ok(())
}

/// A refusal whose `status_code` cannot fit a `u16` must stay a refusal.
#[tokio::test]
async fn test_saml_idp_refusal_cannot_wrap_into_a_success() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a SAML Identity Provider on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("SAML Identity Provider")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "saml-idp",
                        "instruction": "SAML IDP that refuses every request"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("saml_idp_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_error_response",
                        "error_message": "unknown service provider",
                        "status_code": 65736
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/sso?SAMLRequest=abc",
            server.port
        ))
        .timeout(Duration::from_secs(25))
        .send()
        .await?;

    let status = response.status().as_u16();
    let body = response.text().await?;
    println!("wrapping status_code -> {status}");

    assert!(
        !(200..300).contains(&status),
        "65736 narrowed with `as u16` is 200 — the one status an SP treats as a completed \
         sign-in. A refusal must never arrive as one: got {status}"
    );
    assert!(
        (400..600).contains(&status),
        "an out-of-range status_code should fall back to 403, got {status}"
    );
    assert!(
        !body.contains("SAMLResponse"),
        "a refusal must not carry an assertion form: {body}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
