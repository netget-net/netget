//! E2E tests for the HLS protocol.
//!
//! Fetches the .m3u8 playlist and then a segment over HTTP with a mocked LLM, asserting the
//! playlist structure (#EXTM3U, #EXTINF, segment URIs) and the segment Content-Type at the
//! protocol level. This mirrors what a real client (curl, ffplay) does when pulling an HLS stream.
//! Localhost only.


use crate::server::helpers::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Issue one HTTP/1.1 GET and read the whole response (server sends `Connection: close`).
async fn http_get(server: SocketAddr, path: &str) -> E2EResult<String> {
    http_get_within(server, path, Duration::from_secs(10)).await
}

/// Same, with an explicit read deadline: the fail-closed paths answer only after the LLM client
/// has exhausted its own retries, which takes longer than a mocked success.
async fn http_get_within(server: SocketAddr, path: &str, wait: Duration) -> E2EResult<String> {
    let mut stream = TcpStream::connect(server).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(wait, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| "timed out reading HLS response")??;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

#[tokio::test]
async fn test_hls_playlist_and_segment() -> E2EResult<()> {
    let prompt = "listen on port 0 via hls\n\nServe a 2-segment VOD playlist and a placeholder \
                  segment body.";

    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("hls")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "hls", "instruction": "hls serving"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("hls_playlist_request")
                .respond_with_actions(serde_json::json!([{
                    "type": "hls_playlist_response",
                    "target_duration": 6,
                    "version": 3,
                    "segments": [
                        {"uri": "seg0.ts", "duration": 6.0},
                        {"uri": "seg1.ts", "duration": 4.5}
                    ]
                }]))
                .expect_calls(1)
                .and()
                .on_event("hls_segment_request")
                .respond_with_actions(serde_json::json!([{
                    "type": "hls_segment_response",
                    "content_type": "video/mp2t",
                    "encoding": "hex",
                    "data": "47400010"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&test_state, Duration::from_secs(30)).await?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse().unwrap();

    // Playlist
    let resp = http_get(server_addr, "/stream.m3u8").await?;
    assert!(resp.starts_with("HTTP/1.1 200"), "playlist status: {resp}");
    assert!(
        resp.contains("application/vnd.apple.mpegurl"),
        "playlist must have HLS content type: {resp}"
    );
    assert!(resp.contains("#EXTM3U"), "playlist must be an m3u8: {resp}");
    assert!(
        resp.contains("#EXT-X-TARGETDURATION:6"),
        "target duration: {resp}"
    );
    assert!(
        resp.contains("#EXTINF:6.000,"),
        "first segment EXTINF: {resp}"
    );
    assert!(resp.contains("seg0.ts"), "first segment uri: {resp}");
    assert!(resp.contains("seg1.ts"), "second segment uri: {resp}");
    assert!(
        resp.contains("#EXT-X-ENDLIST"),
        "VOD playlist must end: {resp}"
    );

    // Segment — binary body decoded from the declared hex encoding.
    let resp = http_get(server_addr, "/seg0.ts").await?;
    assert!(resp.starts_with("HTTP/1.1 200"), "segment status: {resp}");
    assert!(
        resp.contains("Content-Type: video/mp2t"),
        "segment content type: {resp}"
    );
    assert!(
        resp.contains("Content-Length: 4"),
        "segment body is the 4 decoded bytes: {resp}"
    );
    // The MPEG-TS sync byte 0x47 is the first decoded byte.
    let body_start = resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
    assert_eq!(
        resp.as_bytes().get(body_start),
        Some(&0x47u8),
        "TS sync byte"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Connection stats are recorded on a one-shot HLS request, with **zero LLM calls** (a `*` static
/// handler answers). HLS is HTTP-style request/response — one read, one write, then the connection
/// returns and closes (`Connection: close`) — so it deliberately registers no peer handle: the
/// dashboard's "message this peer" / "disconnect this peer" would have no live window to fire, and
/// `execute_action` needs no `close_connection` arm. What it must still do is refresh
/// `update_connection_stats`, so the rail shows real `↓ ↑` byte counts and a fresh `last_activity`
/// rather than `↓0 ↑0`.
///
/// In-process (uses `netget::` APIs directly), so it can inspect the server's live connection state
/// after the request completes.
#[tokio::test]
async fn hls_connection_stats_are_recorded() {
    use ::netget::cli::management::ServerForm;
    use ::netget::state::app_state::AppState;
    use tokio::sync::mpsc;

    // AppState whose LLM points nowhere; the static handler means nothing here needs a model.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(::netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel::<String>();

    // HLS server that statically answers every playlist request, so no LLM call fires.
    let server_form = ServerForm {
        protocol: "hls".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "hls_playlist_response",
                    "target_duration": 6,
                    "segments": [
                        {"uri": "seg0.ts", "duration": 6.0},
                        {"uri": "seg1.ts", "duration": 6.0}
                    ]
                }]
            }
        })]),
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create hls server");

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

    // Raw HTTP playlist request over a plain tokio socket.
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let request =
        "GET /stream.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".to_string();
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

    // No peer handle: HLS deliberately does not adopt it (one-shot HTTP request/response).
    if let Some(s) = state.get_server(server_id).await {
        if let Some((conn_id, _)) = s.connections.iter().next() {
            assert!(
                !state.has_peer_handle(server_id, conn_id.as_u32()).await,
                "hls should register no peer handle for one-shot HTTP"
            );
        }
    }
}

/// Start an in-process HLS server whose LLM points at a closed port, with the given
/// `event_handlers`, and return its bound port plus the live `AppState`.
async fn start_hls_in_process(
    event_handlers: Option<Vec<serde_json::Value>>,
) -> (::netget::state::app_state::AppState, u16) {
    use ::netget::cli::management::ServerForm;
    use ::netget::state::app_state::AppState;
    use tokio::sync::mpsc;

    // Port 1 on loopback is closed, so any real LLM call fails fast — which is exactly the
    // branch under test.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(::netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel::<String>();

    let server_form = ServerForm {
        protocol: "hls".to_string(),
        port: Some(0),
        event_handlers,
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create hls server");

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
    (state, port)
}

/// Every token below appeared in a real leak of netget's internals onto a peer's terminal.
/// None of them may appear in an HLS failure response, headers or body.
fn assert_no_internal_leak(response: &str, context: &str) {
    for token in [
        "LLM",
        "llm",
        "Ollama",
        "ollama",
        "http://",
        "127.0.0.1:1",
        "11434",
        "anyhow",
        "/Users/",
        "retries",
        "✗",
        "hex",
        "encoding",
    ] {
        assert!(
            !response.contains(token),
            "{context}: response leaked {token:?}:\n{response}"
        );
    }
}

/// When the LLM call itself fails, the peer must get an answer — not silence — and that answer
/// must carry a category only. A player left hanging until its own timeout is the failure mode
/// this guards; a player told netget's backend URL is the one the fix must not introduce.
#[tokio::test]
async fn hls_llm_failure_answers_with_a_category_and_leaks_nothing() {
    let (_state, port) = start_hls_in_process(None).await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    for path in ["/stream.m3u8", "/seg0.ts"] {
        let resp = http_get_within(addr, path, Duration::from_secs(85))
            .await
            .expect("server went silent on LLM failure");

        // 503 (overloaded, retryable) and 500 (unavailable) are the only two shapes.
        assert!(
            resp.starts_with("HTTP/1.1 503") || resp.starts_with("HTTP/1.1 500"),
            "{path} must fail closed with 503 or 500, got: {resp}"
        );
        if resp.starts_with("HTTP/1.1 503") {
            assert!(
                resp.contains("Retry-After:"),
                "a 503 must tell the player to back off: {resp}"
            );
        }
        assert!(
            resp.contains("netget: "),
            "{path} must carry the WireFailure category: {resp}"
        );
        assert_no_internal_leak(&resp, path);
    }
}

/// A segment action carrying neither `data` nor `content` is the model answering nothing usable.
/// It must not become `200 video/mp2t` with an empty body — a player accepts a zero-length
/// segment as a valid one and the stream silently plays nothing.
#[tokio::test]
async fn hls_empty_segment_action_fails_closed_rather_than_serving_an_empty_200() {
    let handlers = vec![serde_json::json!({
        "event_pattern": "hls_segment_request",
        "handler": {
            "type": "static",
            "actions": [{"type": "hls_segment_response", "content_type": "video/mp2t"}]
        }
    })];
    let (_state, port) = start_hls_in_process(Some(handlers)).await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let resp = http_get_within(addr, "/seg0.ts", Duration::from_secs(85))
        .await
        .expect("server went silent on an empty segment action");

    assert!(
        resp.starts_with("HTTP/1.1 500") || resp.starts_with("HTTP/1.1 503"),
        "an empty segment action must fail closed, got: {resp}"
    );
    assert!(
        !resp.contains("Content-Length: 0"),
        "must not serve an empty body as a segment: {resp}"
    );
    assert_no_internal_leak(&resp, "empty segment action");
}
