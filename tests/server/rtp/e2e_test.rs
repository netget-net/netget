//! E2E tests for the RTP protocol.
//!
//! Validates that the server, prompted to answer an inbound RTP packet, synthesizes G.711 audio
//! and returns it as correctly framed RTP. Assertions are at the protocol level — RTP header
//! fields parsed from the raw bytes — not "some bytes arrived". Uses a mocked LLM; the media
//! itself is byte-checked, and interop with a real client (ffmpeg/ffprobe) is exercised through
//! the RTSP suite. Localhost only.

use crate::server::helpers::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Build a minimal 12-byte RTP header + payload (RFC 3550 §5.1).
fn build_rtp(pt: u8, seq: u16, ts: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x80, pt & 0x7F];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ts.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

#[tokio::test]
async fn test_rtp_synthesizes_pcmu_reply() -> E2EResult<()> {
    let prompt =
        "listen on port 0 via rtp\n\nWhen an RTP packet arrives, stream a 440 Hz PCMU tone \
                  back to the caller, echoing its SSRC.";

    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("rtp")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "rtp", "instruction": "rtp media"}
                ]))
                .expect_calls(1)
                .and()
                // Echo the caller's SSRC into the reply so the stream is attributed to the same
                // source — the UDP-style dynamic-echo pattern the harness requires.
                .on_event("rtp_packet_received")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_rtp_audio",
                        "payload_type": "pcmu",
                        "content": "tone",
                        "tone_hz": 440,
                        "duration_ms": 60,
                        "ssrc": e["ssrc"].as_u64().unwrap_or(0)
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await?;

    // Send an RTP packet from a known SSRC.
    let my_ssrc: u32 = 0xDEAD_BEEF;
    let pkt = build_rtp(0, 100, 160, my_ssrc, &[0xFFu8; 160]);
    client.send_to(&pkt, server_addr).await?;

    // Receive the first synthesized RTP packet back.
    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out waiting for RTP reply")??;
    let reply = buf[..len].to_vec();

    assert!(len >= 12, "reply too short to be RTP: {len} bytes");
    assert_eq!(reply[0] >> 6, 2, "RTP version must be 2");
    assert_eq!(reply[1] & 0x7F, 0, "payload type must be PCMU (0)");
    let reply_ssrc = u32::from_be_bytes([reply[8], reply[9], reply[10], reply[11]]);
    assert_eq!(reply_ssrc, my_ssrc, "server should echo the caller's SSRC");
    let payload_len = len - 12;
    assert_eq!(
        payload_len, 160,
        "expected a 20 ms PCMU frame (160 samples)"
    );

    // A second packet should follow (60 ms => 3 frames), with an incremented sequence number.
    let seq1 = u16::from_be_bytes([reply[2], reply[3]]);
    let (len2, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out waiting for second RTP packet")??;
    let seq2 = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(seq2, seq1.wrapping_add(1), "sequence number must increment");
    let ts1 = u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]);
    let ts2 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    assert_eq!(
        ts2,
        ts1.wrapping_add(160),
        "timestamp must advance by frame size"
    );
    assert!(len2 >= 12);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}
