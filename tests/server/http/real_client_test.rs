//! Two clients that are not `reqwest`: the real `curl` binary and Python's `http.client`.
//!
//! # Why
//!
//! `http` is the most-used protocol here and its Beta rating rested on **reqwest** alone —
//! hyper, in-process, in the same runtime, written by the same ecosystem as the server. One
//! client can agree with one bug, and this session found three protocols where it was doing
//! exactly that (`etcd`, `grpc` and `mysql`, each unusable by any conformant client while every
//! test passed).
//!
//! Two are added at once because they are cheap and because they fail differently:
//!
//! * **curl** is libcurl, C, and the program an operator reaches for. It parses the status line
//!   and headers itself and will complain about a malformed framing that hyper tolerates.
//! * **Python's `http.client`** is a third, unrelated implementation in the standard library, so
//!   it needs no install anywhere. It exposes the reason phrase and the raw header list, which
//!   is where a hand-built response most often differs from a generated one.
//!
//! # What this deliberately does not claim
//!
//! The project CLAUDE.md is blunt that a generic HTTP client "proves an HTTP server answers, not
//! that the protocol on top is right" — that rule is about protocols *layered over* HTTP, like
//! `couchdb` or `openapi`. Here HTTP **is** the protocol, so an independent HTTP implementation
//! is exactly the right peer, and these two are as independent as it gets.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when a client binary is absent.
async fn require(program: &str, arg: &str, install: &str) -> E2EResult<String> {
    match Command::new(program).arg(arg).output().await {
        Ok(out) if out.status.success() => {
            let text = if out.stdout.is_empty() {
                String::from_utf8_lossy(&out.stderr)
            } else {
                String::from_utf8_lossy(&out.stdout)
            };
            Ok(text.lines().next().unwrap_or_default().trim().to_string())
        }
        Ok(out) => Err(format!("`{program} {arg}` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "{program} is not available ({e}): this test exists to put a client that is NOT \
             reqwest on this server, because one client can agree with one bug. {install}"
        )
        .into()),
    }
}

/// Three responses the model authors, picked so each client has something distinct to get wrong.
fn http_server() -> NetGetConfig {
    NetGetConfig::new("Listen on port {AVAILABLE_PORT} via HTTP. Answer requests").with_mock(
        |mock| {
            mock.on_instruction_containing("via HTTP")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "Answer requests"
                }]))
                .expect_calls(1)
                .and()
                .on_event("http_request")
                .and_event_data_contains("path", "/missing")
                .respond_with_actions(json!([{
                    "type": "send_http_response",
                    "status": 404,
                    "body": "no such thing"
                }]))
                .expect_calls(1)
                .and()
                .on_event("http_request")
                .and_event_data_contains("path", "/json")
                .respond_with_actions(json!([{
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {"content-type": "application/json", "x-netget-probe": "alpha"},
                    "body": "{\"answer\":42}"
                }]))
                .expect_calls(1)
                .and()
                .on_event("http_request")
                .respond_with_actions(json!([{
                    "type": "send_http_response",
                    "status": 200,
                    "body": "<h1>Hello from the model</h1>"
                }]))
                .expect_calls(1)
                .and()
        },
    )
}

#[tokio::test]
async fn curl_and_python_both_read_our_responses() -> E2EResult<()> {
    let curl_version = require(
        "curl",
        "--version",
        "curl ships with macOS and is in the \
                                `curl` package on Debian/Ubuntu.",
    )
    .await?;
    let py_version = require(
        "python3",
        "--version",
        "python3 provides `http.client` in its \
                              standard library; the Debian/Ubuntu package is `python3`.",
    )
    .await?;
    println!("{curl_version}\n{py_version}");

    let server = start_netget_server(http_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    // --- curl: the body, and the status line it parsed for itself ----------
    let out = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "20",
            // Print the status curl decoded, not the one we hoped it would read.
            "--write-out",
            "\nSTATUS=%{http_code}\n",
            &format!("http://127.0.0.1:{port}/"),
        ])
        .output()
        .await
        .expect("failed to spawn curl");
    let curl_body = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "curl failed: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        curl_body.contains("<h1>Hello from the model</h1>"),
        "curl did not read the body the model authored:\n{curl_body}"
    );
    assert!(
        curl_body.contains("STATUS=200"),
        "curl decoded a status other than 200:\n{curl_body}"
    );

    // --- curl: a 404 is a status, not an error page ------------------------
    //
    // `--fail` makes curl exit non-zero on a 4xx, which is the assertion: a server that answered
    // 200 with the words "no such thing" would pass a body check and fail here.
    let out = Command::new("curl")
        .args([
            "--silent",
            "--fail",
            "--max-time",
            "20",
            &format!("http://127.0.0.1:{port}/missing"),
        ])
        .output()
        .await
        .expect("failed to spawn curl");
    assert!(
        !out.status.success(),
        "curl --fail succeeded on /missing, so the 404 did not reach the status line"
    );

    // --- python: headers and the reason phrase -----------------------------
    //
    // `http.client` exposes the raw header list and the reason phrase, neither of which reqwest
    // surfaces in the existing suite. A response whose headers are mis-cased, duplicated or
    // missing their separator shows up here.
    let script = r#"
import http.client, json, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=20)
c.request("GET", "/json")
r = c.getresponse()
body = r.read().decode()
print(json.dumps({
    "status": r.status,
    "reason": r.reason,
    "content_type": r.getheader("Content-Type"),
    "probe": r.getheader("X-Netget-Probe"),
    "body": body,
}))
"#;
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(port.to_string())
        .output()
        .await
        .expect("failed to spawn python3");
    assert!(
        out.status.success(),
        "python3 http.client failed: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "python printed something unparseable ({e}): {:?}",
            out.stdout
        )
    });

    assert_eq!(parsed["status"], 200, "python read the wrong status");
    assert_eq!(
        parsed["content_type"], "application/json",
        "the Content-Type the model set did not survive to an independent parser"
    );
    assert_eq!(
        parsed["probe"], "alpha",
        "a custom header the model set was lost, and header case must not matter to the lookup"
    );
    assert_eq!(
        parsed["body"], "{\"answer\":42}",
        "the JSON body did not survive"
    );
    assert!(
        parsed["reason"]
            .as_str()
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        "the status line carried no reason phrase; some clients render it and an empty one is \
         a malformed status line rather than a stylistic choice: {parsed}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
