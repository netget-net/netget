//! SIP ↔ RTP interop: a negotiated SDP session must result in RTP actually arriving.
//!
//! SIP alone is signaling only. Built with the `rtp` feature, an accepted INVITE whose action
//! carries an `rtp_audio` description streams real RTP to the m=audio target the caller advertised
//! in its INVITE SDP. This test proves that end-to-end: it sends an INVITE offering a UDP port,
//! and asserts G.711 RTP shows up on that port after the 200 OK.


use crate::server::helpers::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_sip_invite_flows_rtp_to_sdp_target() -> E2EResult<()> {
    let prompt = "listen on port 0 via sip\n\nAccept INVITEs with 200 OK and stream a 440 Hz PCMU \
                  tone to the caller's media address.";

    let answer_sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Call\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                      m=audio 8000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(move |mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("sip")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "sip", "instruction": "sip media"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("sip_invite")
                .respond_with_actions(serde_json::json!([{
                    "type": "sip_invite",
                    "status_code": 200,
                    "reason_phrase": "OK",
                    "sdp": answer_sdp,
                    "rtp_audio": {"content": "tone", "tone_hz": 440, "payload_type": "pcmu", "duration_ms": 100}
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse().unwrap();

    // The caller's RTP receive port, advertised in the INVITE's SDP m=audio line.
    let rtp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let rtp_port = rtp_socket.local_addr()?.port();

    // Signaling socket.
    let sip = UdpSocket::bind("127.0.0.1:0").await?;

    let offer_sdp = format!(
        "v=0\r\no=caller 1 1 IN IP4 127.0.0.1\r\ns=Call\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    );
    let invite = format!(
        "INVITE sip:callee@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKinterop\r\n\
         From: <sip:caller@localhost>;tag=caller\r\n\
         To: <sip:callee@localhost>\r\n\
         Call-ID: interop-1@127.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:caller@127.0.0.1>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        offer_sdp.len(),
        offer_sdp
    );

    sip.send_to(invite.as_bytes(), server_addr).await?;

    // Expect the 200 OK on the signaling socket.
    let mut sbuf = vec![0u8; 65535];
    let (slen, _) = tokio::time::timeout(Duration::from_secs(10), sip.recv_from(&mut sbuf))
        .await
        .map_err(|_| "timed out waiting for SIP 200 OK")??;
    let sresp = String::from_utf8_lossy(&sbuf[..slen]);
    assert!(sresp.contains("SIP/2.0 200"), "expected 200 OK: {sresp}");
    assert!(
        sresp.contains("application/sdp"),
        "200 OK must carry SDP: {sresp}"
    );

    // The negotiated media must actually arrive as RTP on the advertised port.
    let mut rbuf = vec![0u8; 2048];
    let (rlen, _) = tokio::time::timeout(Duration::from_secs(10), rtp_socket.recv_from(&mut rbuf))
        .await
        .map_err(|_| "no RTP arrived at the SDP media target — SIP did not flow media")??;
    assert!(rlen >= 12, "RTP too short: {rlen}");
    assert_eq!(rbuf[0] >> 6, 2, "RTP version 2");
    assert_eq!(rbuf[1] & 0x7F, 0, "PCMU payload type");
    assert_eq!(rlen - 12, 160, "20 ms PCMU frame");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}
