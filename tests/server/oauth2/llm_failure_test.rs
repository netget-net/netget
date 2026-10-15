//! What an OAuth2 client gets when the LLM backend fails - and why the old codes were worse
//! than useless.
//!
//! Every endpoint here already refused; none of them issued a credential on failure. What they
//! did was lie about *whose* fault it was, and two of those lies do lasting damage:
//!
//! * `/token` answered `400 invalid_grant`. That code means "the grant you presented is bad",
//!   and a conforming client reacts by throwing away its refresh token and forcing the user to
//!   re-authenticate. A ten-second backend blip would have signed out every session
//!   permanently - damage that outlives the outage by design.
//! * `/introspect` answered `200 {"active": false}`. Fail-closed, but it is a *statement about
//!   the token*: it says the authorization server looked and the token is not valid. Nobody
//!   looked. A resource server had no way to tell a revoked token from a broken server, which
//!   is exactly the "a model's denial must stay distinguishable from a no-answer" rule.
//! * `/revoke` answered 200, telling the client the token was gone when nothing had processed
//!   the request. RFC 7009 2.2.1 anticipates this precisely: answer 503 and "the client must
//!   assume the token still exists and may retry".
//!
//! All four now answer 5xx with an RFC 6749 5.2 error code, which says only that the request
//! did not happen.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

fn startup_only(prompt: &str) -> NetGetConfig {
    NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
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
        // No rule for any oauth2_* event, so every endpoint fails.
    })
}

/// Every endpoint above answers 5xx on a backend outage — but a 5xx is also what a *model*
/// could in principle ask for, and nothing on the wire says which happened. The `decision=`
/// tag is the only place that distinction survives, so assert it: the line must name the
/// endpoint and carry a `fail_closed_` token, never `model_reject` or `model_silent`.
///
/// `grep decision=fail_closed` is the diagnostic the root CLAUDE.md teaches, and it is worth
/// nothing if the tag is absent on the one path that matters.
fn assert_fail_closed_tag(lines: &[String], endpoint: &str) {
    let tagged: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains(endpoint) && l.contains("decision=fail_closed_"))
        .collect();
    assert!(
        !tagged.is_empty(),
        "no `decision=fail_closed_*` line for {endpoint}: a backend outage and a model refusal \
         are indistinguishable without it. Output was:\n{}",
        lines.join("\n")
    );
    for line in &tagged {
        assert!(
            !line.contains("decision=model_"),
            "a line cannot be both fail-closed and a model decision: {line}"
        );
    }
}

async fn post_form(url: &str, body: &str) -> E2EResult<(u16, Value)> {
    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.to_string())
            .send(),
    )
    .await
    .map_err(|_| "No OAuth2 response within 25s - the server went silent on LLM failure")??;

    let status = response.status().as_u16();
    let text = response.text().await?;
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    println!("{url} -> {status} {text}");
    Ok((status, json))
}

/// `/token` must not blame the client's grant for our backend.
#[tokio::test]
async fn test_oauth2_token_reports_a_server_error_not_invalid_grant() -> E2EResult<()> {
    let server = start_netget_server(startup_only("Open oauth2 on port {AVAILABLE_PORT}.")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, body) = post_form(
        &format!("http://127.0.0.1:{}/token", server.port),
        "grant_type=refresh_token&refresh_token=rt_abc&client_id=testapp",
    )
    .await?;

    assert!(
        (500..600).contains(&status),
        "a backend failure is a server error, not a verdict on the client's request: {status}"
    );
    let error = body["error"].as_str().unwrap_or_default();
    assert_ne!(
        error, "invalid_grant",
        "invalid_grant makes a conforming client discard its refresh token and force a new \
         sign-in, so an outage would sign every session out permanently"
    );
    assert!(
        matches!(error, "server_error" | "temporarily_unavailable"),
        "expected an RFC 6749 5.2 server-side error code, got {error:?}"
    );
    assert!(
        body["access_token"].is_null(),
        "a failure must never hand out a token: {body}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    assert_fail_closed_tag(&server.get_output().await, "OAuth2 /token");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `/introspect` must not assert that the token is inactive when nothing checked it.
#[tokio::test]
async fn test_oauth2_introspect_reports_a_server_error_not_inactive() -> E2EResult<()> {
    let server = start_netget_server(startup_only("Open oauth2 on port {AVAILABLE_PORT}.")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, body) = post_form(
        &format!("http://127.0.0.1:{}/introspect", server.port),
        "token=at_abc",
    )
    .await?;

    assert!(
        (500..600).contains(&status),
        "an introspection that did not happen is a server error, not an answer about the \
         token: {status}"
    );
    assert_ne!(
        body["active"].as_bool(),
        Some(true),
        "a failure must never introspect a token as valid: {body}"
    );
    assert!(
        body["active"].is_null(),
        "reporting `active: false` states that the server looked and the token is bad, which \
         is indistinguishable from a real denial: {body}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    assert_fail_closed_tag(&server.get_output().await, "OAuth2 /introspect");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `/revoke` must not claim a revocation that never happened.
#[tokio::test]
async fn test_oauth2_revoke_reports_a_server_error_not_success() -> E2EResult<()> {
    let server = start_netget_server(startup_only("Open oauth2 on port {AVAILABLE_PORT}.")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, _body) = post_form(
        &format!("http://127.0.0.1:{}/revoke", server.port),
        "token=rt_abc",
    )
    .await?;

    assert!(
        (500..600).contains(&status),
        "RFC 7009 2.2.1: answer 503 so the client assumes the token still exists and retries. \
         A 200 says it is gone, and nothing processed the request: {status}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert_fail_closed_tag(&lines, "OAuth2 /revoke");
    // `decision=protocol_mandated_ok` is the tag on the *success* path, where RFC 7009 fixes
    // the reply at 200 whatever the model said. It must not appear when nothing was processed.
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("decision=protocol_mandated_ok")),
        "an outage must not be logged as the RFC-mandated 200: {}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `/authorize` must not hand out a code, and must not blame the client.
#[tokio::test]
async fn test_oauth2_authorize_reports_a_server_error() -> E2EResult<()> {
    let server = start_netget_server(startup_only("Open oauth2 on port {AVAILABLE_PORT}.")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let url = format!(
        "http://127.0.0.1:{}/authorize?response_type=code&client_id=testapp\
         &redirect_uri=http://127.0.0.1/cb&state=xyz",
        server.port
    );
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = tokio::time::timeout(Duration::from_secs(25), client.get(&url).send())
        .await
        .map_err(|_| "No OAuth2 /authorize response within 25s")??;

    let status = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let text = response.text().await?;
    println!("/authorize -> {status} location={location:?} body={text}");

    assert!(
        (500..600).contains(&status),
        "expected a server-side status, got {status}"
    );
    assert!(
        !location.contains("code="),
        "a failure must never redirect back with an authorization code: {location}"
    );
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    assert!(
        matches!(
            body["error"].as_str().unwrap_or_default(),
            "server_error" | "temporarily_unavailable"
        ),
        "expected an RFC 6749 5.2 server-side error code: {text}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    assert_fail_closed_tag(&server.get_output().await, "OAuth2 /authorize");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
