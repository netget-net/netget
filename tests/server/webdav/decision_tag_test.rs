//! WebDAV: a refusal the model chose and a refusal the server fell back to must not read
//! alike in the log.
//!
//! WebDAV is one of the few protocols here whose wire format *can* carry the distinction —
//! it has 403, 409, 423 Locked, 503 and 507 Insufficient Storage — and `mod.rs` uses that:
//! the model picks its own status, while "no answer" is pinned to 503 and a backend outage
//! to 500. But a status alone still cannot say **who decided**, because 503 is a status the
//! model may also choose. Only the `decision=` tag says that, and
//! `grep decision=fail_closed` is the diagnostic the root `CLAUDE.md` teaches.
//!
//! Two tests, deliberately a pair: one drives the backend into failure and one has the model
//! refuse. Either alone would pass against a server that tagged every outcome identically.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

fn propfind_body() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
     <D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>"
}

/// `PROPFIND` answered by nobody: the mock returns something that is not an action, the
/// retry/repair loop exhausts, `call_llm` returns `Err`.
///
/// The dangerous outcome would be a synthesised `207 Multi-Status` — an empty but
/// *affirmative* listing, which a client reads as "the collection exists and is empty". This
/// asserts the opposite on both channels: a 5xx on the wire, and a `fail_closed_` tag in the
/// log that cannot be confused with the model having chosen that status.
#[tokio::test]
async fn test_webdav_llm_failure_is_tagged_fail_closed() -> E2EResult<()> {
    println!("\n=== E2E Test: WebDAV LLM failure carries decision=fail_closed_* ===");

    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} using webdav stack and serve a share",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("webdav")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "WebDAV",
                "instruction": "Serve a share"
            }]))
            .expect_calls(1)
            .and()
            // Not JSON and not an action, so the repair loop exhausts and `call_llm` errors.
            // `expect_at_least` because the retry count is the LLM layer's business, not this
            // test's.
            .on_event("webdav_request")
            .respond_with_raw("the backend is having a bad day and this is not an action")
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("WebDAV server on port {}", server.port);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()?;
    let response = crate::helpers::retry(|| async {
        http.request(
            reqwest::Method::from_bytes(b"PROPFIND").expect("PROPFIND is a valid method token"),
            format!("http://127.0.0.1:{}/", server.port),
        )
        .header("Depth", "1")
        .header("content-type", "application/xml")
        .body(propfind_body())
        .send()
        .await
    })
    .await
    .map_err(|e| {
        format!(
            "no WebDAV response: the server went silent on LLM failure, which leaves the \
             client hanging until its own timeout ({e})"
        )
    })?;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("PROPFIND on LLM failure -> {status} {text}");

    assert!(
        (500..600).contains(&status),
        "a backend outage must not be answered with a 207 Multi-Status: an empty listing is \
         an affirmative statement that the collection exists and is empty. Got {status}"
    );
    assert!(
        !text.contains("multistatus"),
        "a failure must never produce a DAV:multistatus body: {text}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("PROPFIND") && l.contains("decision=fail_closed_")),
        "the LLM-failure path must log a fail_closed decision tag naming the method; a status \
         code alone cannot say whether the model chose it. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_")),
        "the model was never reached, so no line may record its decision. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// The same 4xx/5xx region, reached the other way: the model deliberately refuses a `PUT`
/// with `423 Locked`. That is the model deciding, so it must be `decision=model_reject` and
/// must never carry the `fail_closed_` prefix an operator greps for.
#[tokio::test]
async fn test_webdav_model_refusal_is_tagged_model_reject() -> E2EResult<()> {
    println!("\n=== E2E Test: WebDAV model refusal carries decision=model_reject ===");

    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} using webdav stack, read-only share",
    )
    .with_mock(|mock| {
        mock.on_event("webdav_request")
            .and_event_data_contains("method", "PUT")
            .respond_with_actions(serde_json::json!([{
                "type": "send_webdav_status",
                "status": 423,
                "body": "resource is locked"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("webdav")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "WebDAV",
                "instruction": "Refuse every write with 423 Locked"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()?;
    let response = crate::helpers::retry(|| async {
        http.put(format!("http://127.0.0.1:{}/notes.txt", server.port))
            .body("hello")
            .send()
            .await
    })
    .await
    .map_err(|e| format!("no WebDAV response to PUT ({e})"))?;

    assert_eq!(
        response.status().as_u16(),
        423,
        "the model's chosen status must reach the client verbatim"
    );

    server.wait_for_any(&["decision=model_reject"], 30).await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("PUT") && l.contains("decision=model_reject")),
        "a status the model chose is the model's decision. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed_")),
        "nothing failed closed: the model answered, and tagging this fail_closed would make \
         the documented grep report a backend outage that never happened. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}
