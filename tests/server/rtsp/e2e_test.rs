//! E2E tests for the RTSP protocol.
//!
//! Drives a full OPTIONS → DESCRIBE → SETUP → PLAY exchange over TCP with a mocked LLM, asserting
//! RTSP status lines and the DESCRIBE SDP at the protocol level, and — the important part — that
//! PLAY causes real RTP to arrive on the UDP port negotiated in SETUP. This proves the RTSP front
//! door actually hands out an RTP stream. Localhost only.

use crate::server::helpers::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Read one complete RTSP response (headers + any Content-Length body) from the stream.
async fn read_response(stream: &mut TcpStream) -> E2EResult<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .map_err(|_| "timed out reading RTSP response")??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf);
        if let Some(hdr_end) = text.find("\r\n\r\n") {
            let content_length: usize = text
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= hdr_end + 4 + content_length {
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

#[tokio::test]
async fn test_rtsp_setup_play_streams_rtp() -> E2EResult<()> {
    let prompt =
        "listen on port 0 via rtsp\n\nOffer one PCMU audio stream. On PLAY, stream a 440 Hz \
                  tone.";

    let sdp =
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=NetGet Stream\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
               m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:streamid=0\r\n";

    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(move |mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("rtsp")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "rtsp", "instruction": "rtsp media"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("rtsp_options")
                .respond_with_actions(serde_json::json!([{"type": "rtsp_options_response"}]))
                .expect_calls(1)
                .and()
                .on_event("rtsp_describe")
                .respond_with_actions(serde_json::json!([{"type": "rtsp_describe_response", "sdp": sdp}]))
                .expect_calls(1)
                .and()
                .on_event("rtsp_setup")
                .respond_with_actions(serde_json::json!([{"type": "rtsp_setup_response", "status_code": 200}]))
                .expect_calls(1)
                .and()
                .on_event("rtsp_play")
                .respond_with_actions(serde_json::json!([{
                    "type": "rtsp_play_response", "status_code": 200,
                    "payload_type": "pcmu", "content": "tone", "tone_hz": 440, "duration_ms": 100
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&test_state, Duration::from_secs(30)).await?;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse().unwrap();

    // The client's RTP receive socket. Its port is what we advertise in SETUP's Transport.
    let rtp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let client_rtp_port = rtp_socket.local_addr()?.port();

    let mut stream = TcpStream::connect(server_addr).await?;
    let base_uri = format!("rtsp://127.0.0.1:{}/stream", test_state.port);

    // OPTIONS
    let req = format!("OPTIONS {base_uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let resp = read_response(&mut stream).await?;
    assert!(resp.starts_with("RTSP/1.0 200"), "OPTIONS: {resp}");
    assert!(
        resp.contains("Public:"),
        "OPTIONS must advertise Public methods: {resp}"
    );

    // DESCRIBE
    let req = format!("DESCRIBE {base_uri} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let resp = read_response(&mut stream).await?;
    assert!(resp.starts_with("RTSP/1.0 200"), "DESCRIBE: {resp}");
    assert!(
        resp.contains("application/sdp"),
        "DESCRIBE content type: {resp}"
    );
    assert!(
        resp.contains("m=audio"),
        "DESCRIBE SDP must have an audio m-line: {resp}"
    );
    assert!(
        resp.contains("PCMU/8000"),
        "DESCRIBE SDP must advertise PCMU: {resp}"
    );

    // SETUP with our client RTP port
    let req = format!(
        "SETUP {base_uri}/streamid=0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port={}-{}\r\n\r\n",
        client_rtp_port,
        client_rtp_port + 1
    );
    stream.write_all(req.as_bytes()).await?;
    let resp = read_response(&mut stream).await?;
    assert!(resp.starts_with("RTSP/1.0 200"), "SETUP: {resp}");
    assert!(
        resp.contains("Transport:"),
        "SETUP must echo Transport: {resp}"
    );
    assert!(
        resp.contains(&format!("client_port={}", client_rtp_port)),
        "SETUP Transport must reflect our client_port: {resp}"
    );
    assert!(
        resp.contains("server_port="),
        "SETUP must include server_port: {resp}"
    );
    let session = resp
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("session:")
                .map(|v| v.trim().to_string())
        })
        .expect("SETUP must return a Session id");

    // PLAY
    let req = format!("PLAY {base_uri} RTSP/1.0\r\nCSeq: 4\r\nSession: {session}\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let resp = read_response(&mut stream).await?;
    assert!(resp.starts_with("RTSP/1.0 200"), "PLAY: {resp}");
    assert!(
        resp.contains("RTP-Info"),
        "PLAY must include RTP-Info: {resp}"
    );

    // The negotiated RTP stream must actually arrive.
    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(10), rtp_socket.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out waiting for RTP from PLAY — RTSP did not stream media")??;
    assert!(len >= 12, "RTP packet too short: {len}");
    assert_eq!(buf[0] >> 6, 2, "RTP version must be 2");
    assert_eq!(buf[1] & 0x7F, 0, "payload type must be PCMU");
    assert_eq!(len - 12, 160, "expected a 20 ms PCMU frame");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}
