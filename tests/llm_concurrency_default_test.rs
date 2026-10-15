//! Concurrent requests against a server running the **shipped** LLM concurrency
//! default.
//!
//! This is the regression test that should have existed. Every other E2E test
//! goes through `NetGetConfig::new`, which sets
//! `llm_max_concurrent: Some(1000) // High concurrency for E2E tests`, so the
//! value the product actually ships with — `1` — was exercised by exactly zero
//! tests. Under that default the limiter used `try_acquire` for network events
//! and refused any request overlapping an in-flight LLM call: two simultaneous
//! `curl`s against a NetGet HTTP server meant one of them got nothing on the
//! wire and hung until its own timeout.
//!
//! These tests deliberately clear `llm_max_concurrent` so the binary is spawned
//! with no `--llm-max-concurrent` flag at all, and assert that every concurrent
//! peer gets an answer. `tests/helpers/` is left untouched: the field is public,
//! so opting out is a one-line override here.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp,http \
//!       --test llm_concurrency_default_test -- --test-threads=100

// `mod helpers` compiles the whole shared E2E harness into this test binary,
// which uses a small slice of it. Same situation as `tests/server.rs`; silence
// the noise rather than adding ~60 warnings to the lint job's output.
#![allow(dead_code, unused_imports)]

mod helpers;

use helpers::{E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Number of peers that hit the server at once. More than two, because the
/// failure was probabilistic in the old code: one straggler that happened not to
/// overlap would have made the test flaky. With six, at `max_concurrent: 1`,
/// overlap is a certainty.
const CONCURRENT_PEERS: usize = 6;

/// Strip `--llm-max-concurrent` from the spawned command line so the binary runs
/// the default the product ships with.
fn with_shipped_concurrency_default(mut config: NetGetConfig) -> NetGetConfig {
    config.llm_max_concurrent = None;
    config
}

#[tokio::test]
async fn concurrent_http_requests_are_all_answered_at_the_default_concurrency() -> E2EResult<()> {
    println!("\n=== E2E Test: concurrent HTTP at shipped --llm-max-concurrent default ===");

    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For any GET request, return status 200 with body: OK";

    let config = with_shipped_concurrency_default(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server that answers every GET with 200 OK"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "OK"
                }
            ]))
            // One LLM call per request: none may be dropped, and none may be
            // retried into a second call either.
            .expect_calls(CONCURRENT_PEERS)
            .and()
    }));

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    let url = format!("http://127.0.0.1:{}/", server.port);
    let mut requests = Vec::new();
    for idx in 0..CONCURRENT_PEERS {
        let url = url.clone();
        requests.push(tokio::spawn(async move {
            // A fresh client per peer: connection reuse would serialise them at
            // the socket and defeat the point of the test.
            let client = reqwest::Client::builder()
                .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                .timeout(Duration::from_secs(60))
                .build()
                .expect("client");
            let response = client.get(&url).send().await?;
            let status = response.status();
            let body = response.text().await?;
            println!("peer {idx}: {status} {body}");
            Ok::<_, reqwest::Error>((status, body))
        }));
    }

    let mut answered = 0;
    for (idx, request) in requests.into_iter().enumerate() {
        let outcome = tokio::time::timeout(Duration::from_secs(90), request)
            .await
            .unwrap_or_else(|_| panic!("peer {idx} never got a reply"))
            .expect("request task panicked");

        let (status, body) = outcome.unwrap_or_else(|e| {
            panic!("peer {idx} got no HTTP response at all (the pre-fix failure mode): {e}")
        });
        assert_eq!(
            status, 200,
            "peer {idx} must get its answer, not an overload/error status; body was {body:?}"
        );
        assert!(body.contains("OK"), "peer {idx} body was {body:?}");
        answered += 1;
    }
    assert_eq!(answered, CONCURRENT_PEERS);

    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn concurrent_tcp_connections_are_all_answered_at_the_default_concurrency() -> E2EResult<()> {
    println!("\n=== E2E Test: concurrent TCP at shipped --llm-max-concurrent default ===");

    let prompt =
        "listen on port {AVAILABLE_PORT} via tcp. When a client sends 'PING', reply with 'PONG'";

    let config = with_shipped_concurrency_default(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("tcp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "TCP server that replies PONG to PING"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("tcp_data_received")
            .and_event_data_contains("data", "PING")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_tcp_data",
                    "data": "PONG\n"
                }
            ]))
            .expect_calls(CONCURRENT_PEERS)
            .and()
    }));

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Connect every peer first, then write from all of them at once, so the
    // requests really do arrive together rather than being spread out by
    // connection setup.
    let mut streams = Vec::new();
    for _ in 0..CONCURRENT_PEERS {
        streams.push(tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?);
    }

    let mut peers = Vec::new();
    for (idx, mut stream) in streams.into_iter().enumerate() {
        peers.push(tokio::spawn(async move {
            stream.write_all(b"PING").await?;
            stream.flush().await?;

            let mut buffer = vec![0u8; 1024];
            let n = stream.read(&mut buffer).await?;
            let reply = String::from_utf8_lossy(&buffer[..n]).to_string();
            println!("peer {idx}: {reply:?} ({n} bytes)");
            Ok::<_, std::io::Error>(reply)
        }));
    }

    for (idx, peer) in peers.into_iter().enumerate() {
        let reply = tokio::time::timeout(Duration::from_secs(90), peer)
            .await
            .unwrap_or_else(|_| panic!("peer {idx} never got a reply"))
            .expect("peer task panicked")
            .unwrap_or_else(|e| panic!("peer {idx} read failed: {e}"));

        // An empty read is EOF: the pre-fix code wrote nothing and left the
        // connection open, so this used to be a 90s hang instead.
        assert!(
            reply.contains("PONG"),
            "peer {idx} must get its answer, got {reply:?}"
        );
    }

    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}
