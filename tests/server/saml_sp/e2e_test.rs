//! End-to-end tests for the SAML 2.0 Service Provider
//!
//! # What these tests do and do not claim
//!
//! `saml_sp` **verifies nothing**. The `SAMLResponse` body is handed to the handler as text
//! and the handler decides who the user is. No XML signature is checked — there is no key
//! here to check one against — and neither are the issuer, the audience restriction,
//! `NotBefore`/`NotOnOrAfter`, nor assertion-ID replay. A forged or expired assertion is
//! accepted exactly as readily as a genuine one.
//!
//! Nothing below asserts that an assertion was *validated*. What is asserted is what the
//! code actually does: it turns a handler decision into a session cookie and a page, and it
//! escapes the attacker-controlled parts on the way. `test_saml_sp_accepts_a_forged_assertion`
//! states the absence of validation as a test, so that adding real validation later breaks
//! it deliberately instead of leaving a stale claim in the docs. See
//! `src/server/saml_sp/CLAUDE.md`.


use crate::server::helpers::{self, E2EResult, NetGetConfig};
use base64::Engine;
use std::time::Duration;

/// `/acs` turns the handler's decision into a session cookie and a welcome page.
#[tokio::test]
async fn test_saml_sp_processes_assertion() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML SP processes an assertion ===");

    let assertion = base64::engine::general_purpose::STANDARD.encode(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>john.doe</saml:NameID></saml:Subject></saml:Assertion>"#,
    );

    let prompt = "Start a SAML Service Provider on port {AVAILABLE_PORT}. \
        On /acs read the SAMLResponse and start a session for the NameID.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_sp_request")
            .and_event_data_contains("path", "/acs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "process_assertion",
                    "user_id": "john.doe",
                    "attributes": {
                        "email": "john.doe@example.com",
                        "role": "user"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Service Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-sp",
                    "instruction": "SAML SP starting a session for the assertion's NameID"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("SAML SP started on port {}", server.port);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/acs", server.port))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("SAMLResponse={assertion}"))
        .send()
        .await?;

    assert_eq!(response.status(), 200, "/acs must answer 200 on acceptance");

    // The session cookie is the user id and nothing else — there is no server-side session
    // store. Asserting the flags keeps the one hardening property the code does have.
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("a session cookie must be set")
        .to_string();
    assert!(
        cookie.starts_with("session_id=john.doe;"),
        "the cookie must carry the handler's user id, got {cookie:?}"
    );
    assert!(
        cookie.contains("HttpOnly"),
        "the session cookie must be HttpOnly, got {cookie:?}"
    );
    assert!(
        cookie.contains("SameSite=Lax"),
        "the session cookie must set SameSite, got {cookie:?}"
    );

    let body = response.text().await?;
    assert!(
        body.contains("Welcome, john.doe!"),
        "the welcome page must name the user:\n{body}"
    );
    // Attributes are rendered as `key: <json value>` and then HTML-escaped wholesale, so the
    // JSON string's own quotes arrive as `&quot;`. Asserting the escaped form is deliberate:
    // it pins both that the attributes are rendered and that they go through `escape_html`.
    assert!(
        body.contains("email: &quot;john.doe@example.com&quot;"),
        "the handler's attributes must be rendered and escaped:\n{body}"
    );
    assert!(
        body.contains("role: &quot;user&quot;"),
        "every attribute the handler supplied must be rendered:\n{body}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// A forged assertion is accepted. This is the documented behaviour, not a bug report: the
/// SP performs no cryptography, so "forged" and "genuine" are indistinguishable to it.
///
/// The test exists so that the absence of validation is *stated* rather than merely implied
/// by the absence of a test. If signature or issuer checking is ever implemented, this test
/// fails and must be rewritten alongside `src/server/saml_sp/CLAUDE.md`.
#[tokio::test]
async fn test_saml_sp_accepts_a_forged_assertion() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML SP performs no validation ===");

    // Not XML, not signed, not from any IDP: arbitrary bytes in the SAMLResponse field.
    let garbage = base64::engine::general_purpose::STANDARD.encode("this is not an assertion");

    let prompt = "Start a SAML Service Provider on port {AVAILABLE_PORT}. \
        On /acs start a session for whoever the assertion names.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_sp_request")
            .and_event_data_contains("path", "/acs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "process_assertion",
                    "user_id": "attacker"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Service Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-sp",
                    "instruction": "SAML SP starting a session for the assertion's subject"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/acs", server.port))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("SAMLResponse={garbage}"))
        .send()
        .await?;

    assert_eq!(
        response.status(),
        200,
        "the SP performs no cryptography, so an unsigned non-assertion is accepted \
         exactly as readily as a genuine one"
    );
    assert!(
        response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.starts_with("session_id=attacker;")),
        "the session is whatever the handler said, not what the assertion proved"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// `user_id` is lifted out of an attacker-supplied assertion and lands in both HTML and
/// `Set-Cookie`. Unescaped it was reflected XSS; raw in the header, a `;` could append
/// cookie attributes and CR/LF could split the response.
#[tokio::test]
async fn test_saml_sp_escapes_hostile_user_id() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML SP escapes a hostile user id ===");

    const HOSTILE: &str = r#"<script>alert(1)</script>; Path=/; Domain=evil"#;

    let prompt = "Start a SAML Service Provider on port {AVAILABLE_PORT}. \
        On /acs start a session for the NameID.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_sp_request")
            .and_event_data_contains("path", "/acs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "process_assertion",
                    "user_id": HOSTILE
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Service Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-sp",
                    "instruction": "SAML SP starting a session"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/acs", server.port))
        .body("SAMLResponse=irrelevant")
        .send()
        .await?;

    // A response at all means no panic and no split header — hyper would have rejected a
    // header value containing CR/LF, and the old code unwrapped that.
    assert_eq!(response.status(), 200);

    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("a session cookie must still be set")
        .to_string();
    // Exactly two ';' — the ones this server writes for HttpOnly and SameSite. Any more
    // means the user id injected cookie attributes of its own.
    assert_eq!(
        cookie.matches(';').count(),
        2,
        "the user id must not be able to append cookie attributes, got {cookie:?}"
    );
    assert!(
        !cookie.contains("Domain=evil"),
        "percent-encoding must neutralise the injected Domain attribute, got {cookie:?}"
    );

    let body = response.text().await?;
    assert!(
        !body.contains("<script>"),
        "a user id containing markup must not reach the page unescaped:\n{body}"
    );
    assert!(
        body.contains("&lt;script&gt;"),
        "the hostile user id must appear escaped, proving it was rendered *and* escaped \
         rather than dropped:\n{body}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// `/login` builds the AuthnRequest that starts the flow. NetGet owns the base64: the
/// handler supplies plain XML, and both bindings encode it.
#[tokio::test]
async fn test_saml_sp_builds_authn_request() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML SP AuthnRequest bindings ===");

    const AUTHN: &str = concat!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
        r#"ID="_r1" Version="2.0" Destination="http://127.0.0.1:8080/sso"/>"#
    );
    const IDP_SSO: &str = "http://127.0.0.1:8080/sso";

    let prompt = "Start a SAML Service Provider on port {AVAILABLE_PORT}. \
        On /login send an AuthnRequest to the IDP.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_sp_request")
            .and_event_data_contains("path", "/login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_authn_request",
                    "request_xml": AUTHN,
                    "idp_sso_url": IDP_SSO,
                    "binding": "HTTP-POST",
                    "relay_state": "https://sp.example.com/home"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Service Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-sp",
                    "instruction": "SAML SP sending an AuthnRequest"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let html = reqwest::get(format!("http://127.0.0.1:{}/login", server.port))
        .await?
        .text()
        .await?;
    println!("login response:\n{html}");

    // HTTP-POST binding: an auto-submitting form aimed at the IDP's SSO endpoint.
    assert!(
        html.contains(&format!(r#"<form method="post" action="{IDP_SSO}""#)),
        "the form must post to the IDP's SSO URL:\n{html}"
    );

    let marker = r#"name="SAMLRequest" value=""#;
    let start = html.find(marker).expect("form must carry SAMLRequest") + marker.len();
    let encoded = &html[start..start + html[start..].find('"').unwrap()];
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .expect("SAMLRequest must be valid standard base64");
    assert_eq!(
        String::from_utf8(decoded).expect("AuthnRequest must be UTF-8 XML"),
        AUTHN,
        "the decoded SAMLRequest must be exactly the XML the handler wrote"
    );

    assert!(
        html.contains(r#"name="RelayState" value="https://sp.example.com/home""#),
        "RelayState must be carried to the IDP:\n{html}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// When the model produces no usable answer, `/acs` must fail **closed**.
///
/// The dangerous shape here is not silence — it is a permissive default. The handler used to
/// initialise `status_code` to 200 and emit that whenever no action carried a parseable HTTP
/// response, so "the model said nothing" reached the browser as an empty `200 OK`. It carried
/// no `Set-Cookie`, so it was never a sign-in, but it told the peer the request had succeeded.
///
/// This pins all three properties of the fail-closed path: a 5xx, no session cookie, and a
/// body that is a *category* rather than netget's internals (no backend URL, no model name,
/// no `anyhow` chain — see `tests/wire_failure_test.rs`).
#[tokio::test]
async fn test_saml_sp_fails_closed_when_the_handler_answers_nothing() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML SP fails closed on a no-answer ===");

    let prompt = "Start a SAML Service Provider on port {AVAILABLE_PORT}. \
        On /acs read the SAMLResponse.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_sp_request")
            .and_event_data_contains("path", "/acs")
            // No actions at all: the model answered nothing usable.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Service Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-sp",
                    "instruction": "SAML SP reading the SAMLResponse"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/acs", server.port))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("SAMLResponse=irrelevant")
        .send()
        .await?;

    let status = response.status();
    assert!(
        status.is_server_error(),
        "a no-answer must be a 5xx, never a success: got {status}"
    );
    assert!(
        response.headers().get("set-cookie").is_none(),
        "a no-answer must never grant a session"
    );

    let body = response.text().await?;
    println!("fail-closed body: {body:?}");
    for leaked in [
        "http://",
        "ollama",
        "llama",
        "retries",
        "Error",
        "src/",
        "Caused by",
    ] {
        assert!(
            !body.contains(leaked),
            "the peer must get a category, not netget's internals; found {leaked:?} in:\n{body}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}
