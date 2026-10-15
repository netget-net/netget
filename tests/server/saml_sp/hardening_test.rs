//! Two ways `/acs` could be made to answer `200` without a decision behind it.
//!
//! A `2xx` is the only thing a browser reads as a completed sign-in, so for an SP the
//! "affirmative default" class of bug is not cosmetic — it *is* the vulnerability.
//!
//! * **The request body was unbounded.** `/acs` takes an anonymous POST and the body goes to
//!   the model verbatim as prompt text, so one request could grow the process without limit
//!   and drive an LLM call with megabytes of attacker-chosen prompt.
//! * **A model-supplied `status` was narrowed with `as u16`.** `65736 as u16` is `200`. A
//!   `send_error_response` — the model's only way to refuse an assertion — therefore arrived
//!   as the status that admits the user.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// An over-limit `/acs` body is refused before the model is consulted. The mock declares no
/// `saml_sp_request` rule, so an LLM call would surface as an unmatched request.
#[tokio::test]
async fn test_saml_sp_refuses_an_oversized_assertion_body() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a SAML Service Provider on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("SAML Service Provider")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "saml-sp",
                        "instruction": "SAML SP"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1 MiB. The server's cap is 256 KiB.
    let huge = format!("SAMLResponse={}", "A".repeat(1024 * 1024));
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/acs", server.port))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(huge)
        .timeout(Duration::from_secs(25))
        .send()
        .await?;

    let status = response.status().as_u16();
    let had_cookie = response.headers().get("set-cookie").is_some();
    let body = response.text().await?;
    println!("oversized /acs -> {status} (cookie={had_cookie})");

    assert_eq!(
        status, 413,
        "an over-limit body must be refused, not buffered and prompted with: {body}"
    );
    assert!(
        !had_cookie,
        "no branch of an over-limit request may start a session"
    );

    server.verify_mocks().await?;
    Ok(())
}

/// A refusal whose `status_code` cannot fit a `u16` must stay a refusal.
#[tokio::test]
async fn test_saml_sp_refusal_cannot_wrap_into_a_sign_in() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a SAML Service Provider on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("SAML Service Provider")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "saml-sp",
                        "instruction": "SAML SP that rejects everything"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("saml_sp_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_error_response",
                        "error_message": "assertion is from an untrusted issuer",
                        "status_code": 65736
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/acs", server.port))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("SAMLResponse=PHNhbWw6QXNzZXJ0aW9uLz4=")
        .timeout(Duration::from_secs(25))
        .send()
        .await?;

    let status = response.status().as_u16();
    let had_cookie = response.headers().get("set-cookie").is_some();
    let body = response.text().await?;
    println!("wrapping status_code -> {status} (cookie={had_cookie})");

    assert!(
        !(200..300).contains(&status),
        "65736 narrowed with `as u16` is 200 — the one status a browser reads as a completed \
         sign-in. A refusal must never arrive as one: got {status}"
    );
    assert!(
        !had_cookie,
        "a refusal must never carry a session cookie: {body}"
    );
    assert!(
        (400..600).contains(&status),
        "an out-of-range status_code should fall back to 403, got {status}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
