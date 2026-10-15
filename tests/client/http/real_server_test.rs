//! The HTTP client against **nginx** — the evidence its maturity rating rests on.
//!
//! NetGet's HTTP client is `reqwest` over hyper; the server here is nginx, a C implementation
//! with its own HTTP parser, spawned per test by `tests/helpers/real_server.rs` with a config
//! written into its temp dir. HTTP *is* the protocol this client speaks, so a real HTTP server is
//! exactly the right peer — the generic-HTTP exclusion in the root `CLAUDE.md` rules out
//! protocols layered on HTTP, not HTTP itself.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire —
//! is asserted from nginx's side, through **nginx's own access log**: every request line, the
//! `X-NetGet` header, the `User-Agent` and the request body length the model's actions produced
//! are recorded there by nginx, and the test reads them back. One of those header values was
//! built by the model from a response body it was shown.
//!
//! **No test here skips.** A missing `nginx` fails with the install command.
//!
//! LLM calls: 5.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http --test client -- http::real_server_test --test-threads=100

use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;

const NGINX: InstallHint = InstallHint {
    brew: "nginx",
    apt: "nginx",
};

/// nginx as an unprivileged, foreground, single-worker server rooted in its temp dir.
///
/// Every path nginx would otherwise take from its compiled-in prefix (pid, logs, the five temp
/// paths) is pointed into `{dir}`, and `error_log stderr` takes over once the config is read.
/// There is deliberately no `-e stderr`: that flag arrived in nginx 1.19.5, and Ubuntu 22.04 (the
/// `registry-audit` runner) ships 1.18, which exits on it with `invalid option: "e"`. Without it,
/// an unprivileged nginx first fails to open its compiled-in error log, which it reports as a
/// non-fatal `[alert]` and carries on. `start worker processes` is logged only after the
/// listening socket is bound.
async fn start_nginx() -> E2EResult<RealServer> {
    RealServer::builder("nginx", NGINX)
        .config_file("www/hello.txt", "hello from nginx\n")
        .config_file(
            "nginx.conf",
            r#"worker_processes 1;
daemon off;
pid {dir}/nginx.pid;
error_log stderr notice;
events { worker_connections 64; }
http {
    log_format netget '$request|$http_x_netget|$http_user_agent|$content_length|$status';
    access_log {dir}/access.log netget;
    client_body_temp_path {dir}/tmp_body;
    proxy_temp_path {dir}/tmp_proxy;
    fastcgi_temp_path {dir}/tmp_fastcgi;
    uwsgi_temp_path {dir}/tmp_uwsgi;
    scgi_temp_path {dir}/tmp_scgi;
    default_type text/plain;
    server {
        listen 127.0.0.1:{port};
        root {dir}/www;
        location /echo {
            return 200 "nginx received: $request with X-NetGet $http_x_netget\n";
        }
    }
}
"#,
        )
        .args(["-p", "{dir}", "-c", "{dir}/nginx.conf"])
        .ready_when_log_matches("start worker processes")
        .start()
        .await
}

/// A static file, a POST whose header the model built from that file, and a 404.
///
/// 1. On `http_connected` the model sends `GET /hello.txt`. NetGet was started with a
///    `default_headers` `User-Agent`, which must reach nginx on every request.
/// 2. The 200 reaches the model (matched on `status_code` 200 and the file's text in `body`); it
///    answers `POST /echo` with `X-NetGet: model saw <body>` and a 13-byte body.
/// 3. nginx's `return` echoes the request line and header back; the model's rule matches only
///    if that echo contains the header value it chose, and answers `GET /missing`.
/// 4. The 404 reaches the model (matched on `status_code` 404); it does nothing.
///
/// Then nginx's own access log must hold the three requests exactly as the model shaped them.
///
/// LLM calls: 5 (startup, http_connected, three http_response_received).
#[tokio::test]
async fn http_client_follows_the_model_through_nginx() -> E2EResult<()> {
    let server = start_nginx().await?;
    let result = follows_the_model(&server).await;
    server.with_log(result)
}

async fn follows_the_model(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Browse the web server at {addr}. HTTP-NGINX-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("HTTP-NGINX-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "HTTP",
                "remote_addr": addr,
                "instruction": "Read hello.txt, report what it said to /echo, then try /missing.",
                "startup_params": {"default_headers": {"User-Agent": "netget-e2e/1"}}
            }]))
            .expect_calls(1)
            .and()
            .on_event("http_connected")
            .respond_with_actions(json!([{
                "type": "send_http_request",
                "method": "GET",
                "path": "/hello.txt"
            }]))
            .expect_calls(1)
            .and()
            // First-match-wins, and nginx's echo quotes "hello from nginx" back: this rule must
            // precede the hello.txt rule below or that rule would answer the echo too.
            .on_event("http_response_received")
            .and_event_data_contains("status_code", "200")
            .and_event_data_contains(
                "body",
                "nginx received: POST /echo HTTP/1.1 with X-NetGet model saw hello from nginx",
            )
            .respond_with_actions(json!([{
                "type": "send_http_request",
                "method": "GET",
                "path": "/missing"
            }]))
            .expect_calls(1)
            .and()
            .on_event("http_response_received")
            .and_event_data_contains("status_code", "200")
            .and_event_data_contains("body", "hello from nginx")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "send_http_request",
                    "method": "POST",
                    "path": "/echo",
                    "headers": {
                        "X-NetGet": format!(
                            "model saw {}",
                            event["body"].as_str().unwrap_or("").trim()
                        ),
                        "Content-Type": "text/plain"
                    },
                    "body": "payload bytes"
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("http_response_received")
            .and_event_data_contains("status_code", "404")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    // The last rule is the 404's response, and nginx writes an access-log line when it sends a
    // response, so every line asserted below is already on disk once every rule is met.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    let access_log = std::fs::read_to_string(server.dir().join("access.log"))?;
    let lines: Vec<&str> = access_log.lines().collect();
    assert_eq!(
        lines,
        vec![
            "GET /hello.txt HTTP/1.1|-|netget-e2e/1|-|200",
            "POST /echo HTTP/1.1|model saw hello from nginx|netget-e2e/1|13|200",
            "GET /missing HTTP/1.1|-|netget-e2e/1|-|404",
        ],
        "nginx must have received exactly the requests the model asked for"
    );

    client.stop().await?;
    Ok(())
}
