//! A complete RTSP request must be answered even when the bytes behind it are not text.
//!
//! `parse_rtsp_request` used to run `std::str::from_utf8` over the *whole* read buffer before
//! looking for the header terminator. Anything the buffer merely happened to contain past the
//! end of a valid request therefore invalidated the request as well: a multi-byte character
//! split across two TCP segments, or a binary body, or a second pipelined request still
//! arriving. The connection then sat with a fully-formed request unanswered until the 1 MiB
//! overflow closed it — a head-of-line stall that looks exactly like a hung server.
//!
//! In-process with a static handler, so no model is involved.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start_rtsp_in_process() -> (::netget::state::app_state::AppState, u16) {
    use ::netget::cli::management::ServerForm;
    use ::netget::state::app_state::AppState;
    use tokio::sync::mpsc;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(::netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel::<String>();

    let server_id = ServerForm {
        protocol: "rtsp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // Empty rather than None: `ServerForm::create` substitutes a default instruction for
        // `None`, which would send every request to a model that is not there.
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "rtsp_options",
            "handler": {
                "type": "static",
                "actions": [{"type": "rtsp_options_response", "status_code": 200}]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create rtsp server");

    let mut port = 0u16;
    for _ in 0..200 {
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
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_ne!(port, 0, "RTSP server never bound a port");
    (state, port)
}

const OPTIONS: &[u8] = b"OPTIONS rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 7\r\n\r\n";

async fn read_status_line(stream: &mut TcpStream, wait: Duration) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// The control: a lone OPTIONS is answered. Without it, the next test's success proves nothing.
#[tokio::test]
async fn rtsp_answers_a_plain_request() {
    let (_state, port) = start_rtsp_in_process().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(OPTIONS).await.expect("write");

    let response = read_status_line(&mut stream, Duration::from_secs(20))
        .await
        .expect("no response to a plain OPTIONS");
    assert!(
        response.starts_with("RTSP/1.0 200"),
        "control: expected 200, got:\n{response}"
    );
    assert!(
        response.contains("CSeq: 7"),
        "CSeq must be echoed:\n{response}"
    );
}

/// A complete OPTIONS followed in the same segment by a lone 0xFF — never valid UTF-8, and
/// exactly what the leading byte of a split multi-byte character looks like — must still be
/// answered. Under the old whole-buffer decode, this response never came.
#[tokio::test]
async fn rtsp_answers_a_complete_request_followed_by_non_utf8_bytes() {
    let (_state, port) = start_rtsp_in_process().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut stream = TcpStream::connect(addr).await.expect("connect");

    let mut wire = OPTIONS.to_vec();
    wire.push(0xFF);
    stream.write_all(&wire).await.expect("write");

    let response = read_status_line(&mut stream, Duration::from_secs(20))
        .await
        .expect(
            "RTSP stalled on a complete request because bytes AFTER it were not UTF-8 - the \
             head-of-line stall this test exists to catch",
        );
    assert!(
        response.starts_with("RTSP/1.0 200"),
        "expected 200, got:\n{response}"
    );
    assert!(
        response.contains("CSeq: 7"),
        "CSeq must be echoed:\n{response}"
    );
}
