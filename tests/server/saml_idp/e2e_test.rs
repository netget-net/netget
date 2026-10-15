//! End-to-end tests for the SAML 2.0 Identity Provider
//!
//! # What these tests do and do not claim
//!
//! `saml_idp` **signs nothing**. There is no key in the protocol: the handler writes the
//! assertion XML and NetGet only base64-encodes it into the HTTP-POST form. An assertion
//! carries a `<ds:Signature>` only if the handler invents one, and an invented signature
//! verifies against nothing.
//!
//! So these tests assert on the *binding* — that a well-formed, correctly base64-encoded
//! `SAMLResponse` is posted to the ACS URL the caller supplied, with `RelayState` echoed and
//! HTML-escaped — and never on authenticity. There is deliberately no assertion anywhere
//! below that a signature was produced or validated, because none is. See
//! `src/server/saml_idp/CLAUDE.md`.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use base64::Engine;
use std::time::Duration;

/// Pull the value of a hidden form input out of the auto-submitting POST form.
fn form_field(html: &str, name: &str) -> Option<String> {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The `action` attribute of the form — where the browser will post the assertion.
fn form_action(html: &str) -> Option<String> {
    let marker = r#"<form method="post" action=""#;
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The IDP's central operation: answer `/sso` with an HTTP-POST binding form carrying the
/// assertion, addressed to the ACS URL the handler named.
///
/// The `acs_url` parameter is the reason this test exists at all: the generated form's
/// action attribute used to be the literal string `{{ACS_URL}}`, which nothing substituted
/// and no action could supply, so every assertion this IDP produced was posted to a relative
/// path named `{{ACS_URL}}` and reached no SP.
#[tokio::test]
async fn test_saml_idp_sso_posts_assertion_to_acs_url() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML IDP SSO ===");

    const ACS_URL: &str = "http://127.0.0.1:8081/acs";
    const RELAY_STATE: &str = "https://sp.example.com/dashboard";
    const ASSERTION: &str = concat!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
        r#"ID="_a1" IssueInstant="2026-01-01T00:00:00Z" Version="2.0">"#,
        r#"<saml:Issuer>http://127.0.0.1/idp</saml:Issuer>"#,
        r#"<saml:Subject><saml:NameID>testuser</saml:NameID></saml:Subject>"#,
        r#"<saml:AttributeStatement><saml:Attribute Name="email">"#,
        r#"<saml:AttributeValue>test@example.com</saml:AttributeValue>"#,
        r#"</saml:Attribute></saml:AttributeStatement>"#,
        r#"</saml:Assertion>"#
    );

    let prompt = "Start a SAML Identity Provider on port {AVAILABLE_PORT}. \
        On /sso authenticate everyone as 'testuser' with email test@example.com and post \
        the assertion to the SP's AssertionConsumerService URL.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_idp_request")
            .and_event_data_contains("path", "/sso")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_saml_response",
                    "assertion_xml": ASSERTION,
                    "acs_url": ACS_URL,
                    "relay_state": RELAY_STATE
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Identity Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-idp",
                    "instruction": "SAML IDP authenticating everyone as testuser"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("SAML IDP started on port {}", server.port);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/sso", server.port))
        .query(&[
            ("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
            ("RelayState", RELAY_STATE),
        ])
        .send()
        .await?;

    assert_eq!(response.status(), 200, "the SSO endpoint must answer 200");
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "the HTTP-POST binding is an HTML form, got content-type {content_type:?}"
    );

    let html = response.text().await?;
    println!("SSO response body:\n{html}");

    // 1. The form must post to the ACS URL the handler supplied — not to a placeholder.
    let action = form_action(&html).expect("response must contain a POST form");
    assert_eq!(
        action, ACS_URL,
        "the form must post to the caller's acs_url; a literal placeholder here means the \
         assertion reaches no SP"
    );
    assert!(
        !html.contains("{{ACS_URL}}"),
        "no unsubstituted placeholder may remain in the form"
    );

    // 2. SAMLResponse must be base64 that decodes to the exact assertion XML. NetGet owns
    //    the encoding; the handler supplies plain XML.
    let saml_response =
        form_field(&html, "SAMLResponse").expect("the form must carry a SAMLResponse field");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(saml_response.as_bytes())
        .expect("SAMLResponse must be valid standard base64");
    let decoded = String::from_utf8(decoded).expect("the decoded assertion must be UTF-8 XML");
    assert_eq!(
        decoded, ASSERTION,
        "the decoded SAMLResponse must be exactly the assertion the handler wrote"
    );
    assert!(
        decoded.starts_with("<saml:Assertion"),
        "the decoded payload must be assertion XML"
    );
    assert!(
        decoded.contains("<saml:NameID>testuser</saml:NameID>"),
        "the subject must survive the round trip"
    );

    // 3. Nothing signed anything. Recorded as an assertion so that if signing is ever added,
    //    this test fails and is updated deliberately rather than silently becoming a claim
    //    the code does not support.
    assert!(
        !decoded.contains("ds:Signature") && !decoded.contains("<Signature"),
        "saml_idp holds no key and must not appear to sign; if this changes, update \
         src/server/saml_idp/CLAUDE.md and this test together"
    );

    // 4. RelayState is echoed back, HTML-escaped, so an SP can resume where it left off.
    assert_eq!(
        form_field(&html, "RelayState").as_deref(),
        Some(RELAY_STATE),
        "RelayState must be echoed to the SP"
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

/// A `RelayState` is echoed straight back from whatever the SP sent, so it is the sharpest
/// injection surface in this protocol. Unescaped, a `"` broke out of the surrounding
/// attribute and injected markup into a page the browser renders *and auto-submits*.
#[tokio::test]
async fn test_saml_idp_escapes_relay_state() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML IDP escapes RelayState ===");

    const HOSTILE: &str = r#"" /><script>alert(1)</script><input x=""#;

    let prompt = "Start a SAML Identity Provider on port {AVAILABLE_PORT}. \
        Echo the RelayState the SP sent.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_idp_request")
            .and_event_data_contains("path", "/sso")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_saml_response",
                    "assertion_xml": "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Subject><saml:NameID>testuser</saml:NameID></saml:Subject></saml:Assertion>",
                    "acs_url": "http://127.0.0.1:8081/acs",
                    "relay_state": HOSTILE
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Identity Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-idp",
                    "instruction": "SAML IDP echoing RelayState"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let html = reqwest::get(format!("http://127.0.0.1:{}/sso", server.port))
        .await?
        .text()
        .await?;

    assert!(
        !html.contains("<script>"),
        "a RelayState containing markup must not reach the page unescaped:\n{html}"
    );
    assert!(
        html.contains("&lt;script&gt;"),
        "the hostile RelayState must appear escaped, proving it was echoed *and* escaped \
         rather than dropped:\n{html}"
    );
    assert!(
        html.contains("&quot;"),
        "the double quote that would break out of the value attribute must be escaped"
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

/// `/metadata` and the error path. `status_code` is model-supplied, and an out-of-range one
/// used to panic the connection task inside `Response::builder().status(..).unwrap()`.
#[tokio::test]
async fn test_saml_idp_metadata_and_error_response() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML IDP metadata and errors ===");

    const METADATA: &str = concat!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" "#,
        r#"entityID="http://127.0.0.1/idp"><IDPSSODescriptor "#,
        r#"protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
        r#"<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" "#,
        r#"Location="http://127.0.0.1/sso"/></IDPSSODescriptor></EntityDescriptor>"#
    );

    let prompt = "Start a SAML Identity Provider on port {AVAILABLE_PORT}. \
        Serve metadata on /metadata and reject unknown service providers.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_idp_request")
            .and_event_data_contains("path", "/metadata")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_metadata",
                    "metadata_xml": METADATA
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("saml_idp_request")
            .and_event_data_contains("path", "/sso")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_error_response",
                    "error_message": "Unknown service provider <evil>",
                    "status_code": 403
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Identity Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-idp",
                    "instruction": "SAML IDP serving metadata"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Metadata: served verbatim, with the media type a SAML consumer looks for.
    let response = reqwest::get(format!("http://127.0.0.1:{}/metadata", server.port)).await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/samlmetadata+xml"),
        "metadata must be served as application/samlmetadata+xml"
    );
    let body = response.text().await?;
    assert_eq!(
        body, METADATA,
        "metadata must reach the client byte for byte"
    );

    // Error: the handler's status code is honoured and the message is HTML-escaped.
    let response = reqwest::get(format!("http://127.0.0.1:{}/sso", server.port)).await?;
    assert_eq!(
        response.status(),
        403,
        "the handler's status_code must be honoured"
    );
    let body = response.text().await?;
    assert!(
        body.contains("Unknown service provider &lt;evil&gt;"),
        "the error message must appear escaped, not raw:\n{body}"
    );
    assert!(
        !body.contains("<evil>"),
        "an unescaped error message is reflected HTML injection"
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

/// The fail-closed path: the model answered, but with nothing this handler can put on the
/// wire. The peer must get a 5xx that is plainly *not* a sign-in, and the body must carry a
/// category only — never the backend URL, the model name, a file path or netget's own retry
/// text. An empty `200` here would be the dangerous shape: an SP reads it as a completed
/// response with no assertion rather than as a server fault.
#[tokio::test]
async fn test_saml_idp_fails_closed_when_model_answers_nothing() -> E2EResult<()> {
    println!("\n=== E2E Test: SAML IDP fails closed on an unusable answer ===");

    let prompt = "Start a SAML Identity Provider on port {AVAILABLE_PORT}. \
        Only answer requests you understand.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("saml_idp_request")
            .and_event_data_contains("path", "/sso")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("SAML Identity Provider")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "saml-idp",
                    "instruction": "SAML IDP that only answers what it understands"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = reqwest::get(format!("http://127.0.0.1:{}/sso", server.port)).await?;
    let status = response.status();
    let body = response.text().await?;
    println!("fail-closed response: {status} {body:?}");

    assert!(
        status.is_server_error(),
        "an unusable answer must be a 5xx, not an empty 200 an SP would read as a completed \
         response; got {status}"
    );

    // Only a category reaches the peer. These are the exact things that leaked in the
    // incident tests/wire_failure_test.rs exists for.
    for token in [
        "✗",
        "retries",
        "http://",
        "127.0.0.1",
        "11434",
        "qwen",
        "/Users/",
        "LLM",
        "Ollama",
        "ollama",
        "anyhow",
    ] {
        assert!(
            !body.contains(token),
            "netget internals must never reach the peer, found {token:?} in:\n{body}"
        );
    }
    assert!(
        !body.to_lowercase().contains("saml"),
        "the failure must not look like a SAML Response:\n{body}"
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
