//! End-to-end HTTP Proxy tests for NetGet
//!
//! These tests spawn actual HTTP/HTTPS target servers and the NetGet proxy,
//! then validate proxy behavior using real HTTP clients configured to route through the proxy.

#![cfg(unix)]

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Simple HTTP test server that echoes requests
async fn start_test_http_server() -> E2EResult<(u16, tokio::task::JoinHandle<()>)> {
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Router,
    };

    // Shared state to track received requests
    #[derive(Clone, Default)]
    struct AppState {
        last_headers: Arc<Mutex<HeaderMap>>,
        last_body: Arc<Mutex<String>>,
    }

    let state = AppState::default();
    let state_clone = state.clone();

    let app = Router::new()
        .route("/", get(|| async { "Test Server Root" }))
        .route(
            "/echo",
            get({
                let state = state.clone();
                move |headers: HeaderMap| async move {
                    *state.last_headers.lock().await = headers.clone();
                    // Echo the headers *back* so the caller can assert on what the proxy
                    // actually forwarded. Storing them in `last_headers` alone made the
                    // header-modification test unable to check its own subject.
                    let mut echoed = String::from("Echo:\n");
                    for (name, value) in headers.iter() {
                        echoed.push_str(name.as_str());
                        echoed.push_str(": ");
                        echoed.push_str(value.to_str().unwrap_or("<binary>"));
                        echoed.push('\n');
                    }
                    echoed
                }
            }),
        )
        .route(
            "/json",
            get(|| async {
                axum::Json(serde_json::json!({
                    "message": "test",
                    "value": 42
                }))
            }),
        )
        .route(
            "/post",
            post({
                let state = state.clone();
                move |headers: HeaderMap, body: String| async move {
                    *state.last_headers.lock().await = headers;
                    *state.last_body.lock().await = body;
                    (StatusCode::CREATED, "Created")
                }
            }),
        )
        .with_state(state_clone);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server time to start

    Ok((port, handle))
}

/// Simple HTTPS test server that echoes requests (with self-signed certificate)
async fn start_test_https_server() -> E2EResult<(u16, tokio::task::JoinHandle<()>)> {
    use axum::{routing::get, Router};
    use axum_server::tls_rustls::RustlsConfig;
    use rcgen::{CertificateParams, KeyPair};

    // Generate self-signed certificate
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName(rcgen::string::Ia5String::try_from("localhost").unwrap()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Keep the PEM in memory. The previous version wrote
    // `${TMPDIR}/test_https_cert_${PID}.pem` and claimed the PID "avoids conflicts when running
    // tests concurrently" — but concurrent Rust tests share one process, so every HTTPS test in
    // this file wrote the *same* two paths with a *different* freshly generated key pair. Whoever
    // read last could get one test's certificate paired with another's key, which surfaces as a
    // flaky `underlying cryptographic error` in the client handshake. The files were also never
    // deleted.
    let config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?;

    // Create simple app
    let app = Router::new()
        .route("/", get(|| async { "HTTPS Test Server" }))
        .route(
            "/get",
            get(|| async {
                axum::Json(serde_json::json!({
                    "origin": "127.0.0.1",
                    "url": "https://localhost/get"
                }))
            }),
        );

    // Bind to random port - we need to get the port before spawning
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // Give server time to start

    Ok((port, handle))
}

#[tokio::test]
async fn test_proxy_http_passthrough() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy HTTP Pass-Through ===");

    // Start target HTTP server
    let (target_port, _target_handle) = start_test_http_server().await?;
    println!("Target HTTP server started on port {}", target_port);

    // Start proxy server with pass-through configuration
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack. Pass all HTTP requests through unchanged to their destination";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Pass all HTTP requests through unchanged"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTP request received
            .on_event("proxy_http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_pass"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Proxy server started on port {}", server.port);

    assert_eq!(server.stack, "Proxy", "Expected Proxy server");

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    println!("Configuring client to use proxy: {}", proxy_url);

    let proxy = reqwest::Proxy::all(&proxy_url)?;
    println!("Proxy configured");

    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    println!("Client built with proxy");

    // Make request through proxy
    let target_url = format!("http://127.0.0.1:{}/", target_port);
    println!(
        "Sending request to target: {} (through proxy {})",
        target_url, proxy_url
    );

    let response = client.get(&target_url).send().await?;
    println!("Response received: {}", response.status());

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("Test Server Root"));

    println!("✓ Request successfully proxied");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_proxy_http_block() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy HTTP Block ===");

    // Start target HTTP server
    let (target_port, _target_handle) = start_test_http_server().await?;
    println!("Target HTTP server started on port {}", target_port);

    // Start proxy server with blocking configuration
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack. Block all HTTP requests with status 403 and body 'Access Denied by Proxy'";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Block all HTTP requests with status 403"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTP request received - block it
            .on_event("proxy_http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_block",
                    "status": 403,
                    "body": "Access Denied by Proxy"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Proxy server started on port {}", server.port);

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::http(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .build()?;

    // Make request through proxy - should be blocked
    let target_url = format!("http://127.0.0.1:{}/", target_port);
    let response = client.get(&target_url).send().await?;

    assert_eq!(response.status(), 403);
    let body = response.text().await?;
    println!("DEBUG: Response body = {:?}", body);
    println!("DEBUG: Body length = {}", body.len());
    assert!(
        body.contains("Access Denied"),
        "Expected 'Access Denied' in body, got: {:?}",
        body
    );

    println!("✓ Request successfully blocked by proxy");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_proxy_modify_request_headers() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy Modify Request Headers ===");

    // Start target HTTP server
    let (target_port, _target_handle) = start_test_http_server().await?;
    println!("Target HTTP server started on port {}", target_port);

    // Start proxy server with header modification
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack. For all HTTP requests, add header 'X-Proxy-Modified: NetGet' and remove 'User-Agent' header before forwarding";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Add X-Proxy-Modified header and remove User-Agent"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTP request received - modify headers
            .on_event("proxy_http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_modify",
                    "headers": {"X-Proxy-Modified": "NetGet"},
                    "remove_headers": ["User-Agent"]
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Proxy server started on port {}", server.port);

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::http(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .user_agent("TestClient/1.0")
        .build()?;

    // Make request through proxy
    let target_url = format!("http://127.0.0.1:{}/echo", target_port);
    let response = client.get(&target_url).send().await?;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("Echo"), "unexpected /echo body: {body:?}");

    // The target echoes the headers it received, so the modification is directly checkable.
    let lowercased = body.to_lowercase();
    assert!(
        lowercased.contains("x-proxy-modified: netget"),
        "handle_request_modify must add X-Proxy-Modified before forwarding; target saw:\n{body}"
    );
    assert!(
        !lowercased.contains("user-agent: testclient/1.0"),
        "handle_request_modify must strip the User-Agent named in remove_headers; target saw:\n{body}"
    );
    println!("✓ Request processed with header modifications");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_proxy_modify_request_body() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy Modify Request (Pass-through) ===");

    // Start target HTTP server
    let (target_port, _target_handle) = start_test_http_server().await?;
    println!("Target HTTP server started on port {}", target_port);

    // Start proxy server in simple pass-through mode for POST requests
    let prompt = r#"listen on port {AVAILABLE_PORT} using proxy stack. Pass all HTTP requests through unchanged to their destination."#;

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Pass all HTTP requests through unchanged"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTP POST request received
            .on_event("proxy_http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_pass"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Proxy server started on port {}", server.port);

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::http(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .build()?;

    // Make POST request
    let target_url = format!("http://127.0.0.1:{}/post", target_port);
    let response = client
        .post(&target_url)
        .body(r#"{"username": "admin", "data": "test"}"#)
        .send()
        .await?;

    // Should succeed - proxy passes request through
    assert_eq!(response.status(), 201);

    println!("✓ POST request successfully proxied");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_proxy_filter_by_path() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy Filter By Path ===");

    // Start target HTTP server
    let (target_port, _target_handle) = start_test_http_server().await?;
    println!("Target HTTP server started on port {}", target_port);

    // Start proxy server with path-based filtering
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack. Block only requests to /json with status 403. Pass all other requests through unchanged";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Block /json with 403, pass others through"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: /json is blocked. This rule MUST come before the catch-all: rule
            // matching is first-match-wins, so two rules with the same `on_event` matcher
            // would both be served by whichever is declared first.
            .on_event("proxy_http_request")
            .and_event_data_contains("path", "/json")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_block",
                    "status": 403,
                    "body": "Forbidden"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: every other path passes through
            .on_event("proxy_http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_pass"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Proxy server started on port {}", server.port);

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::http(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .build()?;

    // Request to / should pass through
    let root_url = format!("http://127.0.0.1:{}/", target_port);
    let response = client.get(&root_url).send().await?;
    assert_eq!(response.status(), 200);
    println!("✓ Root request passed through");

    // Request to /json should be blocked
    let json_url = format!("http://127.0.0.1:{}/json", target_port);
    let response = client.get(&json_url).send().await?;
    assert_eq!(response.status(), 403);
    println!("✓ /json request blocked");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_proxy_https_passthrough() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy HTTPS Pass-Through (CONNECT) ===");

    // Start local HTTPS test server
    let (target_port, _target_handle) = start_test_https_server().await?;
    println!("Target HTTPS server started on port {}", target_port);

    // Start proxy server in pass-through mode (no certificate)
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack with no certificate (pass-through mode). Allow all HTTPS connections";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Pass-through mode, allow all HTTPS"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTPS CONNECT request received
            .on_event("proxy_https_connect")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_https_connection_allow"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!(
        "Proxy server started on port {} (pass-through mode)",
        server.port
    );

    // Configure HTTP client to use proxy for HTTPS
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::all(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .danger_accept_invalid_certs(true) // Accept self-signed cert from test server
        .build()?;

    // Make HTTPS request through proxy to local HTTPS server
    let target_url = format!("https://127.0.0.1:{}/", target_port);
    let response = client.get(&target_url).send().await?;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("HTTPS Test Server"));

    println!("✓ HTTPS request proxied successfully through pass-through mode");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_proxy_https_block_by_sni() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy HTTPS Block by SNI ===");

    // Start local HTTPS test server
    let (target_port, _target_handle) = start_test_https_server().await?;
    println!("Target HTTPS server started on port {}", target_port);

    // Start proxy server with SNI-based blocking
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack with no certificate. Block HTTPS connections to 127.0.0.1 with reason 'Blocked by policy'";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Block HTTPS to 127.0.0.1"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTPS CONNECT request received - block it
            .on_event("proxy_https_connect")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_https_connection_block",
                    "reason": "Blocked by policy"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!(
        "Proxy server started on port {} (SNI blocking mode)",
        server.port
    );

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::all(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    // Attempt HTTPS request that should be blocked
    let target_url = format!("https://127.0.0.1:{}/get", target_port);
    let response = client.get(&target_url).send().await;

    // The proxy must refuse the tunnel. Two shapes are legitimate — a non-2xx status on the
    // CONNECT, or a transport error because the tunnel was never established — but a
    // successful response is not: it would mean the block was ignored and the payload
    // reached the target. The previous version printed "✗ Expected 403" and carried on,
    // so it passed in exactly the case it was written to catch.
    match response {
        Ok(resp) => {
            assert!(
                !resp.status().is_success(),
                "handle_https_connection_block was returned by the LLM, yet the request \
                 completed with {} - the tunnel was not blocked",
                resp.status()
            );
            println!("✓ HTTPS connection blocked with {}", resp.status());
        }
        Err(e) => {
            // Connection being rejected is also acceptable
            println!("✓ HTTPS connection blocked: {}", e);
        }
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

#[tokio::test]
async fn test_proxy_url_rewrite() -> E2EResult<()> {
    println!("\n=== E2E Test: Proxy URL Rewrite ===");

    // Start target HTTP server
    let (target_port, _target_handle) = start_test_http_server().await?;
    println!("Target HTTP server started on port {}", target_port);

    // Start proxy server with URL rewriting
    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack. Rewrite all requests to /api/* to just / before forwarding";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Rewrite /api/* to /"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: HTTP request received - rewrite URL
            .on_event("proxy_http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "handle_request_modify",
                    "new_path": "/"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Proxy server started on port {}", server.port);

    // Configure HTTP client to use proxy
    let proxy_url = format!("http://127.0.0.1:{}", server.port);
    let proxy = reqwest::Proxy::http(&proxy_url)?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .build()?;

    // Request to /api/something should be rewritten to /
    let target_url = format!("http://127.0.0.1:{}/api/something", target_port);
    let response = client.get(&target_url).send().await?;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    // If rewriting works, we should get the root response
    assert!(body.contains("Test Server Root"));

    println!("✓ URL successfully rewritten");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}
