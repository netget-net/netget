//! BitTorrent Tracker E2E tests with mocks

use crate::helpers::*;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Test tracker announce and scrape requests with mocks
///
/// LLM calls: 3 total
/// - 1 server startup
/// - 1 announce request
/// - 1 scrape request
#[tokio::test]
async fn test_tracker_announce_and_scrape() -> E2EResult<()> {
    // Start tracker server with mocks
    let server_config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via torrent-tracker. Return peer lists for announce requests with 30-minute interval."
    )
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("torrent-tracker")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-Tracker",
                    "instruction": "BitTorrent tracker with peer coordination"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Announce request
            .on_event("tracker_announce_request")
            .respond_with_actions(json!([
                {
                    "type": "send_announce_response",
                    "interval": 1800,
                    "complete": 10,
                    "incomplete": 5,
                    "peers": [
                        {
                            "peer_id": "-TR2940-xxxxxxxxxxxx",
                            "ip": "192.168.1.100",
                            "port": 51413
                        },
                        {
                            "peer_id": "-UT2210-yyyyyyyyyyyy",
                            "ip": "192.168.1.101",
                            "port": 6881
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Scrape request
            .on_event("tracker_scrape_request")
            .respond_with_actions(json!([
                {
                    "type": "send_scrape_response",
                    "files": [
                        {
                            "info_hash": "0123456789abcdef0123456789abcdef01234567",
                            "complete": 10,
                            "incomplete": 5,
                            "downloaded": 100
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test announce request
    let client = reqwest::Client::new();
    let announce_url = format!(
        "http://127.0.0.1:{}/announce?info_hash=%01%23%45%67%89%AB%CD%EF%01%23%45%67%89%AB%CD%EF%01%23%45%67&peer_id=TESTPEER12345678901&port=6881&uploaded=0&downloaded=0&left=1000000&event=started&compact=0",
        server.port
    );

    println!("Sending announce request to {}", announce_url);

    let response = client
        .get(&announce_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Announce request failed: {}",
        response.status()
    );

    let body = response.bytes().await?;
    println!("Announce response: {} bytes", body.len());

    // Parse bencode response
    let value: serde_bencode::value::Value = serde_bencode::from_bytes(&body)?;
    let dict = match value {
        serde_bencode::value::Value::Dict(d) => d,
        _ => panic!("Expected Dict"),
    };

    // Verify interval
    let interval = dict
        .get(b"interval" as &[u8])
        .and_then(|v| match v {
            serde_bencode::value::Value::Int(i) => Some(i),
            _ => None,
        })
        .expect("Missing interval");
    assert_eq!(*interval, 1800, "Interval should be 1800");

    // Verify peers exist
    assert!(
        dict.contains_key::<[u8]>(b"peers".as_ref()),
        "Response should contain peers"
    );

    println!("✅ Announce request successful");

    // Test scrape request
    let scrape_url = format!(
        "http://127.0.0.1:{}/scrape?info_hash=%01%23%45%67%89%AB%CD%EF%01%23%45%67%89%AB%CD%EF%01%23%45%67",
        server.port
    );

    println!("Sending scrape request to {}", scrape_url);

    let response = client
        .get(&scrape_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Scrape request failed: {}",
        response.status()
    );

    let body = response.bytes().await?;
    println!("Scrape response: {} bytes", body.len());

    // Parse bencode response
    let value: serde_bencode::value::Value = serde_bencode::from_bytes(&body)?;
    let dict = match value {
        serde_bencode::value::Value::Dict(d) => d,
        _ => panic!("Expected Dict"),
    };

    // Verify files dictionary exists
    assert!(
        dict.contains_key::<[u8]>(b"files".as_ref()),
        "Response should contain files"
    );

    println!("✅ Scrape request successful");

    // Verify all mocks were called
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// Test tracker error response with mocks
///
/// LLM calls: 2 total
/// - 1 server startup
/// - 1 error response
#[tokio::test]
async fn test_tracker_error_response() -> E2EResult<()> {
    // Start tracker server with mocks
    let server_config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via torrent-tracker. Return errors for invalid requests.",
    )
    .with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("torrent-tracker")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-Tracker",
                    "instruction": "Tracker with error handling"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Error response for missing parameters
            .on_event("tracker_announce_request")
            .respond_with_actions(json!([
                {
                    "type": "send_error_response",
                    "failure_reason": "Missing required parameter: info_hash"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send malformed request (missing info_hash)
    let client = reqwest::Client::new();
    let announce_url = format!(
        "http://127.0.0.1:{}/announce?peer_id=TESTPEER12345678901&port=6881",
        server.port
    );

    let response = client
        .get(&announce_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    assert!(response.status().is_success(), "Should return HTTP 200");

    let body = response.bytes().await?;
    let value: serde_bencode::value::Value = serde_bencode::from_bytes(&body)?;
    let dict = match value {
        serde_bencode::value::Value::Dict(d) => d,
        _ => panic!("Expected Dict"),
    };

    // Verify error response
    assert!(
        dict.contains_key(b"failure reason" as &[u8]),
        "Response should contain failure reason"
    );

    println!("✅ Error response test successful");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    Ok(())
}

/// Connection stats are recorded on a one-shot tracker request, with **zero LLM
/// calls** (a `*` static handler answers). The tracker is HTTP-style
/// request/response — one read, one write, then close — so it registers no peer
/// handle (the dashboard's "message this peer" would have no live window). What
/// it must still do is refresh `update_connection_stats`, so the dashboard rail
/// shows real `↓ ↑` byte counts and a fresh `last_activity` rather than `↓0 ↑0`.
///
/// In-process (uses `netget::` APIs directly), so it can inspect the server's
/// live connection state after the request completes.
#[tokio::test]
async fn tracker_connection_stats_are_recorded() {
    use ::netget::cli::management::ServerForm;
    use ::netget::state::app_state::AppState;
    use tokio::sync::mpsc;

    // AppState whose LLM points nowhere; nothing here needs a model.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(::netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel::<String>();

    // Tracker that statically answers every announce, so no LLM call fires.
    let server_form = ServerForm {
        protocol: "torrent-tracker".to_string(),
        port: Some(0),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_announce_response",
                    "interval": 1800,
                    "complete": 1,
                    "incomplete": 0,
                    "compact": "{{event.compact}}",
                    "peers": [{"ip": "127.0.0.1", "port": 51413}]
                }]
            }
        })]),
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create torrent-tracker server");

    // Wait for the listener to bind.
    let mut port = 0u16;
    for _ in 0..100 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                port = addr.port();
                break;
            }
            if s.port != 0 {
                port = s.port;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "server never bound a port");

    // Raw HTTP announce over a plain tokio socket.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let request = format!(
        "GET /announce?info_hash=%01%23%45%67%89%AB%CD%EF%01%23%45%67%89%AB%CD%EF%01%23%45%67&peer_id=TESTPEER12345678901&port=6881&uploaded=0&downloaded=0&left=1000000&event=started&compact=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    // Read the whole response (server half-closes / returns after writing).
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    assert!(!response.is_empty(), "server sent no response");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "expected HTTP 200, got: {}",
        String::from_utf8_lossy(&response[..response.len().min(40)])
    );

    // The connection's stats must reflect the one read and one write.
    let mut got_stats = false;
    for _ in 0..100 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(conn) = s.connections.values().next() {
                if conn.bytes_received > 0 && conn.bytes_sent > 0 {
                    assert!(
                        conn.bytes_received as usize >= request.len(),
                        "bytes_received ({}) < request len ({})",
                        conn.bytes_received,
                        request.len()
                    );
                    assert!(conn.packets_received >= 1 && conn.packets_sent >= 1);
                    got_stats = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        got_stats,
        "connection stats never showed both bytes_received and bytes_sent > 0"
    );

    // No peer handle: this protocol deliberately does not adopt it (one-shot HTTP).
    if let Some(s) = state.get_server(server_id).await {
        if let Some((conn_id, _)) = s.connections.iter().next() {
            assert!(
                !state.has_peer_handle(server_id, conn_id.as_u32()).await,
                "torrent-tracker should register no peer handle for one-shot HTTP"
            );
        }
    }
}
