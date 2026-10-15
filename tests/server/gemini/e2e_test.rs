//! Gemini end to end with a mocked model, over a raw TLS socket.
//!
//! `real_client_test.rs` is the evidence that a real client accepts these responses. This file
//! covers what a well-behaved client never sends — another scheme, a relative URL, a BOM,
//! userinfo, a fragment — and pins that NetGet refuses each one itself: the mock's call counts
//! would catch any of them reaching the model.
//!
//! LLM budget: 2 calls (open_server, one request).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini::e2e --test-threads=100

use super::common::{raw_request, split_response};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

#[tokio::test]
async fn a_request_reaches_the_model_and_malformed_ones_never_do() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gemini. One page.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via gemini")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gemini",
                    "instruction": "One page"
                }]))
                .expect_calls(1)
                .and()
                .on_event("gemini_request")
                .and_event_data_contains("path", "/docs/intro")
                .and_event_data_contains("query", "a b+c")
                // A request carrying a query names the prompt's answer in its hint.
                .and_event_data_contains("answer_with", "with \"a b+c\"")
                .and_event_data_contains("host", "example.org")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_gemini_response",
                    "status": 20,
                    "meta": "text/plain",
                    "body": "plain body\n"
                }]))
                .expect_calls(1)
                .and()
        });
    let server = start_netget_server(config).await?;
    let port = server.port;

    // The one request the model sees. The host is not checked against the certificate; the
    // query arrives percent-decoded, with `+` left alone (Gemini queries are not forms).
    let response = raw_request(port, b"gemini://example.org:1965/docs/intro?a%20b+c", 30).await;
    let (header, body) = split_response(&response);
    assert_eq!(header, "20 text/plain");
    assert_eq!(body, b"plain body\n");

    // Refused by NetGet, each with a fixed response and no model call.
    let cases: &[(&[u8], &str)] = &[
        (b"https://example.org/", "53 Proxy request refused"),
        (b"gopher://example.org/", "53 Proxy request refused"),
        (b"/relative/path", "59 Request is not an absolute URL"),
        (b"example.org/", "59 Request is not an absolute URL"),
        (
            "\u{feff}gemini://example.org/".as_bytes(),
            "59 Request must not begin with a BOM",
        ),
        (
            b"gemini://user:pw@example.org/",
            "59 URL must not contain userinfo",
        ),
        (
            b"gemini://example.org/#frag",
            "59 URL must not contain a fragment",
        ),
        (b"gemini:///nohost", "59 URL has no host"),
    ];
    for (request, expected) in cases {
        let response = raw_request(port, request, 10).await;
        let (header, body) = split_response(&response);
        assert_eq!(
            &header,
            expected,
            "request {:?}",
            String::from_utf8_lossy(request)
        );
        assert!(
            body.is_empty(),
            "a non-2x response carries no body: {body:?}"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
