//! `client::http::transport` — the HTTP client's browser transport — driven natively against
//! NetGet's own servers, in-process and with zero LLM calls (every server answers through a
//! `*` static handler).
//!
//! The transport exists for the browser build, where reqwest cannot run; it compiles on both
//! targets precisely so this file can pin it down without a browser. `web/test/smoke.mjs` then
//! proves the same code runs over the page's virtual loopback.
//!
//! - NetGet's HTTP server: a 200 with its body and headers, and a 404 read as a status rather
//!   than an error.
//! - NetGet's TCP server, answering with hand-written bytes: a **chunked** response (NetGet's
//!   HTTP server never chunks), the body bound (refused, not truncated), and the request
//!   deadline against a server that never answers.
//! - `https://` refused with the reason.
//! - The native reqwest path honours the same body bound, end to end through the client's own
//!   command channel, against an owned streaming TCP peer so the oversized body does not
//!   pass through the shared static-action interpolation budget.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http,tcp --test client -- http::transport --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::client::http::transport::{
    self, fetch, parse_http_url, HTTPS_UNSUPPORTED, MAX_RESPONSE_BODY_BYTES,
};
use netget::state::app_state::AppState;
use netget::state::{ClientId, ServerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Start a server of `protocol` whose every event is answered with `actions`.
async fn static_server(state: &AppState, protocol: &str, actions: serde_json::Value) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: protocol.to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "static", "actions": actions}
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .unwrap_or_else(|e| panic!("create {protocol} server: {e}"));
    wait_for_port(state, id).await
}

/// A TCP server that answers the first read with `raw` and closes.
async fn raw_http_server(state: &AppState, raw: &str) -> u16 {
    static_server(
        state,
        "tcp",
        serde_json::json!([
            {"type": "send_tcp_data", "data": raw},
            {"type": "close_this_connection"}
        ]),
    )
    .await
}

async fn get(
    port: u16,
    path: &str,
    max_body: usize,
) -> anyhow::Result<netget::client::http::HttpExchange> {
    fetch(
        "GET",
        &format!("http://127.0.0.1:{port}{path}"),
        &[("accept".to_string(), "text/plain".to_string())],
        None,
        Duration::from_secs(20),
        max_body,
    )
    .await
}

#[tokio::test]
async fn the_transport_reads_netget_http_responses_with_body_status_and_headers() {
    let state = new_state().await;
    let ok = static_server(
        &state,
        "http",
        serde_json::json!([{
            "type": "send_http_response",
            "status": 200,
            "headers": {"Content-Type": "text/plain", "X-Marker": "from-netget"},
            "body": "hello from netget"
        }]),
    )
    .await;
    let missing = static_server(
        &state,
        "http",
        serde_json::json!([{
            "type": "send_http_response",
            "status": 404,
            "headers": {"Content-Type": "text/plain"},
            "body": "nothing here"
        }]),
    )
    .await;

    let exchange = get(ok, "/hello?x=1", MAX_RESPONSE_BODY_BYTES)
        .await
        .expect("GET against NetGet's HTTP server");
    assert_eq!(exchange.status_code, 200);
    assert_eq!(exchange.status_text, "200 OK");
    assert_eq!(exchange.body, "hello from netget");
    assert_eq!(exchange.headers["x-marker"], "from-netget");
    assert_eq!(exchange.headers["content-type"], "text/plain");

    // A POST carries its body; the server's answer is the same static one.
    let posted = fetch(
        "post",
        &format!("http://127.0.0.1:{ok}/submit"),
        &[("content-type".to_string(), "application/json".to_string())],
        Some("{\"k\":1}".to_string()),
        Duration::from_secs(20),
        MAX_RESPONSE_BODY_BYTES,
    )
    .await
    .expect("POST");
    assert_eq!(posted.status_code, 200);

    // A non-2xx status is an answer to report, not a transport failure.
    let exchange = get(missing, "/missing", MAX_RESPONSE_BODY_BYTES)
        .await
        .expect("a 404 is a response");
    assert_eq!(exchange.status_code, 404);
    assert_eq!(exchange.status_text, "404 Not Found");
    assert_eq!(exchange.body, "nothing here");

    // The server saw the path and query the transport put in the request line.
    let seen = serde_json::to_string(&state.list_access_logs(None).await).unwrap();
    assert!(seen.contains("/hello"), "{seen}");
    assert!(seen.contains("/submit"), "{seen}");
}

#[tokio::test]
async fn the_transport_reads_a_chunked_response_and_bounds_the_body() {
    let state = new_state().await;
    let chunked = raw_http_server(
        &state,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n\
         6\r\nhello \r\n7\r\nchunked\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;

    let exchange = get(chunked, "/", MAX_RESPONSE_BODY_BYTES)
        .await
        .expect("a chunked response");
    assert_eq!(exchange.status_code, 200);
    assert_eq!(exchange.body, "hello chunked world");
    assert_eq!(exchange.headers["transfer-encoding"], "chunked");

    // 19 body bytes against a 10-byte bound: refused whole, never handed on truncated.
    let refused = get(chunked, "/", 10).await.expect_err("over the bound");
    assert!(refused.to_string().contains("10-byte limit"), "{refused:#}");
    // Exactly at the bound is still an answer.
    assert_eq!(
        get(chunked, "/", 19)
            .await
            .expect("at the bound")
            .body
            .len(),
        19
    );
}

#[tokio::test]
async fn the_transport_gives_up_on_a_server_that_never_answers() {
    let state = new_state().await;
    // Answered with nothing: the connection stays open and no byte ever comes back.
    let silent = static_server(&state, "tcp", serde_json::json!([])).await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        fetch(
            "GET",
            &format!("http://127.0.0.1:{silent}/"),
            &[],
            None,
            Duration::from_millis(500),
            MAX_RESPONSE_BODY_BYTES,
        ),
    )
    .await
    .expect("the transport's own deadline fires well inside 15s");
    let err = result.expect_err("no response is an error");
    assert!(err.to_string().contains("within"), "{err:#}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn https_is_refused_with_the_reason_and_urls_parse() {
    let err = parse_http_url("https://127.0.0.1:8443/x").expect_err("https");
    assert!(err.to_string().contains(HTTPS_UNSUPPORTED), "{err:#}");
    assert!(parse_http_url("ftp://host/").is_err());

    let t = parse_http_url("http://127.0.0.1:8080/a/b?q=1").unwrap();
    assert_eq!(
        (
            t.host.as_str(),
            t.port,
            t.authority.as_str(),
            t.path_and_query.as_str()
        ),
        ("127.0.0.1", 8080, "127.0.0.1:8080", "/a/b?q=1")
    );
    let t = parse_http_url("http://localhost").unwrap();
    assert_eq!((t.port, t.path_and_query.as_str()), (80, "/"));
    let t = parse_http_url("http://[::1]:9000/").unwrap();
    assert_eq!((t.host.as_str(), t.port), ("::1", 9000));
    assert_eq!(transport::REQUEST_TIMEOUT, Duration::from_secs(30));
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "HTTP client #{} never registered a command handle",
        id.as_u32()
    );
}

/// The native client reads through reqwest, not the transport, and holds the same bound: a
/// body one byte over [`MAX_RESPONSE_BODY_BYTES`] fails the request instead of being buffered.
#[tokio::test]
async fn the_native_client_refuses_a_body_over_the_bound() {
    let state = new_state().await;
    let size = MAX_RESPONSE_BODY_BYTES + 1;
    // A body larger than the transport bound also exceeds the shared static-action
    // interpolation budget. Stream it from a test-owned peer instead of changing either
    // runtime limit. Dropping the JoinSet cancels the peer if an assertion fails.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized-response peer");
    let huge = listener.local_addr().unwrap().port();
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        tokio::time::timeout(Duration::from_secs(40), async move {
            let (mut socket, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut read_buf = [0u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let read = socket.read(&mut read_buf).await?;
                anyhow::ensure!(read > 0, "client closed before sending request headers");
                anyhow::ensure!(request.len() + read <= 4096, "request headers too large");
                request.extend_from_slice(&read_buf[..read]);
            }
            socket
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            let chunk = [b'a'; 64 * 1024];
            let mut remaining = size;
            while remaining > 0 {
                let count = remaining.min(chunk.len());
                socket.write_all(&chunk[..count]).await?;
                remaining -= count;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .expect("oversized-response peer deadline")
    });
    let small = raw_http_server(
        &state,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nsmall",
    )
    .await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let mut outcomes = Vec::new();
    for port in [small, huge] {
        let client_id = ClientForm {
            protocol: "http".to_string(),
            remote_addr: Some(format!("127.0.0.1:{port}")),
            instruction: Some("test client".to_string()),
            ..Default::default()
        }
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx.clone(),
        )
        .await
        .expect("create http client");
        wait_for_client_handle(&state, client_id).await;
        outcomes.push(
            state
                .send_to_client(
                    client_id,
                    serde_json::json!({"type": "send_http_request", "method": "GET", "path": "/"}),
                    Duration::from_secs(30),
                )
                .await,
        );
    }
    let small = outcomes[0].as_ref().expect("a small body is read");
    assert!(
        format!("{small:?}").contains("-> 200 (5 byte body)"),
        "{small:?}"
    );
    let huge = outcomes[1]
        .as_ref()
        .expect_err("a body over the bound fails the request");
    assert!(huge.to_string().contains("-byte limit"), "{huge:#}");
    peers
        .join_next()
        .await
        .expect("owned response peer")
        .expect("response peer did not panic")
        .expect("response peer streamed the oversized body");
}
