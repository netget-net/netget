//! CoAP server driven by libcoap's real **`coap-client`** binary.
//!
//! The peer is not a Rust crate. `src/server/coap/codec.rs` is a hand-rolled RFC 7252
//! codec; `coap-client` ships with libcoap, a C implementation by a different author
//! in a different language that shares no code with anything NetGet links. A request
//! it round-trips is therefore independent evidence, not one codec agreeing with
//! itself.
//!
//! What is driven is a real request/response exchange in both directions, with the
//! payload libcoap *parsed and printed* as the assertion:
//!
//! ```text
//!   GET  /sensors/moisture -> 2.05 Content, application/json, body asserted
//!   POST /actuators/valve  -> 2.04 Changed, body derived from the request, asserted
//!   GET  /nope             -> 4.04 Not Found, reported by libcoap as an error
//! ```
//!
//! This test is **not** `#[ignore]`d and does **not** skip when libcoap is missing —
//! see `require_coap_client`.

use crate::server::helpers::*;
use std::time::Duration;
use tokio::process::Command;

const MOISTURE_BODY: &str = "{\"resource\":\"/sensors/moisture\",\"pct\":41.2}";

/// Fail — never skip — when `coap-client` is absent.
///
/// A skip that returns `Ok(())` is a silent pass on any machine without libcoap,
/// which is how a maturity rating outlives the evidence behind it. CoAP's rating
/// leans on this exchange, so a runner without the binary has to say so.
async fn require_coap_client() -> E2EResult<()> {
    // `coap-client` with no arguments prints its banner and exits non-zero, so the
    // check is that it ran and identified itself, not that it exited 0.
    match Command::new("coap-client").output().await {
        Ok(out) => {
            let banner = String::from_utf8_lossy(&out.stderr).to_string()
                + &String::from_utf8_lossy(&out.stdout);
            if banner.contains("coap-client") {
                println!(
                    "[real-client] {}",
                    banner.lines().next().unwrap_or("coap-client")
                );
                Ok(())
            } else {
                Err(format!(
                    "`coap-client` ran but did not identify itself, so it is not libcoap's \
                     client. This test's whole point is driving the real libcoap client against \
                     NetGet's CoAP server; skipping would leave CoAP's maturity rating resting \
                     on nothing. Output was: {banner}"
                )
                .into())
            }
        }
        Err(e) => Err(format!(
            "coap-client is not available ({e}). This test's whole point is driving libcoap's \
             real client against NetGet's CoAP server, and skipping it would leave CoAP's \
             maturity rating resting on nothing."
        )
        .into()),
    }
}

/// Run one `coap-client` invocation under a wall-clock bound and return
/// `(stdout, stderr, success)`.
///
/// libcoap retransmits a Confirmable request whose ACK is slow, and this server has
/// no deduplication cache, so an unbounded run against a wedged server would hang
/// rather than fail. `-B` bounds libcoap's own retry window; the timeout bounds the
/// process.
async fn coap_client(args: &[&str], what: &str) -> E2EResult<(String, String, bool)> {
    let out = tokio::time::timeout(
        Duration::from_secs(45),
        Command::new("coap-client").args(args).output(),
    )
    .await
    .map_err(|_| format!("coap-client {what} did not finish within 45s"))?
    .map_err(|e| format!("failed to run coap-client {what}: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!(
        "[coap-client {what}] status={} stdout={stdout:?}",
        out.status
    );
    if !stderr.trim().is_empty() {
        println!("[coap-client {what}] stderr={stderr:?}");
    }
    Ok((stdout, stderr, out.status.success()))
}

#[tokio::test]
async fn test_coap_get_post_and_not_found_against_libcoap_client() -> E2EResult<()> {
    require_coap_client().await?;

    let config = NetGetConfig::new(
        "Start a CoAP server on port {AVAILABLE_PORT} pretending to be a soil moisture sensor",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("CoAP server")
            .and_instruction_containing("on port")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "coap",
                "instruction": "Soil moisture sensor"
            }]))
            .expect_calls(1)
            .and()
            // A resource the device has. Answered from the event so the body is tied
            // to the request that provoked it rather than to a fixed literal.
            .on_event("coap_request")
            .and_event_data_contains("path", "/sensors/moisture")
            .respond_with_actions_from_event(|event| {
                let path = event["path"].as_str().unwrap_or("/");
                serde_json::json!([{
                    "type": "send_coap_response",
                    "code": "2.05",
                    "payload": format!("{{\"resource\":\"{path}\",\"pct\":41.2}}"),
                    "content_format": "application/json"
                }])
            })
            // libcoap retransmits a CON whose ACK is late and this server has no
            // dedup cache, so a second identical request is possible under load.
            .expect_at_least(1)
            .and()
            // A state change: 2.04 Changed, echoing the body libcoap sent, which is
            // what proves the request payload survived the round trip.
            .on_event("coap_request")
            .and_event_data_contains("path", "/actuators/valve")
            .respond_with_actions_from_event(|event| {
                let body = event["payload"].as_str().unwrap_or("");
                serde_json::json!([{
                    "type": "send_coap_response",
                    "code": "2.04",
                    "payload": format!("valve={body}"),
                    "content_format": "text/plain"
                }])
            })
            .expect_at_least(1)
            .and()
            // A resource the device does not have.
            .on_event("coap_request")
            .and_event_data_contains("path", "/nope")
            .respond_with_actions(serde_json::json!([{
                "type": "send_coap_response",
                "code": "4.04"
            }]))
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server.wait_for_log("CoAP receive loop started", 15).await?;
    let base = format!("coap://127.0.0.1:{}", server.port);
    println!("[real-client] NetGet CoAP server at {base}");

    // -- GET a resource that exists ----------------------------------------------------
    //
    // libcoap prints a payload only after decoding a message whose version, type,
    // token length, code, message id, option deltas and payload marker it all
    // accepted, and whose token and message id match the request it sent. That
    // printed body is the assertion a raw socket cannot make.
    let uri = format!("{base}/sensors/moisture");
    let (stdout, stderr, ok) =
        coap_client(&["-B", "20", "-m", "get", &uri], "GET moisture").await?;
    assert!(
        ok,
        "coap-client exited non-zero on a GET NetGet answered 2.05. stderr: {stderr}"
    );
    assert!(
        stdout.contains(MOISTURE_BODY),
        "libcoap did not print the representation NetGet served.\n  expected to contain: \
         {MOISTURE_BODY}\n  stdout: {stdout:?}\n  stderr: {stderr:?}"
    );
    println!("[real-client] libcoap parsed and printed NetGet's 2.05 Content body");

    // -- POST a state change -----------------------------------------------------------
    let uri = format!("{base}/actuators/valve");
    let (stdout, stderr, ok) = coap_client(
        &[
            "-B",
            "20",
            "-m",
            "post",
            "-e",
            "open",
            "-t",
            "text/plain",
            &uri,
        ],
        "POST valve",
    )
    .await?;
    assert!(
        ok,
        "coap-client exited non-zero on a POST NetGet answered 2.04. stderr: {stderr}"
    );
    assert!(
        stdout.contains("valve=open"),
        "libcoap did not print the 2.04 Changed body echoing the payload it sent, so either the \
         request payload or the response payload did not survive.\n  stdout: {stdout:?}\n  \
         stderr: {stderr:?}"
    );
    println!("[real-client] libcoap round-tripped a POST payload through NetGet");

    // -- GET a resource that does not exist --------------------------------------------
    //
    // The negative path has to be structurally distinct from the positive one, or a
    // server that answered 2.05 to everything would pass. libcoap reports a
    // non-2.xx response code rather than printing a body.
    let uri = format!("{base}/nope");
    let (stdout, stderr, _ok) = coap_client(&["-B", "20", "-m", "get", &uri], "GET nope").await?;
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("4.04"),
        "libcoap did not report the 4.04 NetGet sent for a missing resource.\n  stdout: \
         {stdout:?}\n  stderr: {stderr:?}"
    );
    assert!(
        !stdout.contains(MOISTURE_BODY),
        "the 4.04 response carried the moisture representation, so the server is answering every \
         path the same way.\n  stdout: {stdout:?}"
    );
    println!("[real-client] libcoap reported NetGet's 4.04 for the missing resource");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
