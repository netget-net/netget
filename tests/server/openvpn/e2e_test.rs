//! E2E tests for the OpenVPN control-channel server.
//!
//! Two kinds of test live here.
//!
//! 1. **A real client.** Two tests drive the system's `openvpn` binary against
//!    the server. The first asserts it completes the control-channel TLS
//!    handshake and the key-method-2 exchange — `Control Channel: TLSv1.x` and
//!    `Peer Connection Initiated`, lines it emits only after a TLS session has
//!    been carried over the reliability layer and its key material answered
//!    acceptably. The second asserts that refusing the key exchange stops it
//!    dead at exactly that point. Both assert the client never reports a
//!    completed tunnel, because this server answers no `PUSH_REQUEST`.
//!
//! 2. **Raw UDP with an independent codec.** The remaining tests build request
//!    frames and decode replies with `super::wire`, which is written from the
//!    protocol layout and never calls NetGet's codec.
//!
//! No test requires root. The server has no TUN device, so there is nothing to
//! elevate for.
//!
//! **`openvpn` must be installed.** If it is missing the real-client tests fail
//! rather than skipping: a capability check that returns success when the
//! capability is absent is worse than no test at all.

#![cfg(unix)]

use super::wire::*;
use crate::helpers::*;
use std::process::Stdio;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::time::timeout;

/// The credentials the real client offers. Distinctive so the assertion that
/// the server captured them cannot pass on some other string.
const TEST_USERNAME: &str = "netget-probe-user";
const TEST_PASSWORD: &str = "netget-probe-secret";

/// Static handlers that answer both decisions, so no model call happens per
/// peer.
fn accept_handler() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "openvpn",
        "event_handlers": [
            {
                "event_pattern": "openvpn_peer_reset",
                "handler": {
                    "type": "static",
                    "actions": [{"type": "accept_peer", "reason": "e2e test"}]
                }
            },
            {
                "event_pattern": "openvpn_client_key_exchange",
                "handler": {
                    "type": "static",
                    "actions": [{"type": "accept_key_exchange", "reason": "e2e test"}]
                }
            }
        ]
    }])
}

/// Answers the reset but refuses the key exchange.
fn accept_reset_reject_key_exchange_handler() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "openvpn",
        "event_handlers": [
            {
                "event_pattern": "openvpn_peer_reset",
                "handler": {
                    "type": "static",
                    "actions": [{"type": "accept_peer", "reason": "e2e test"}]
                }
            },
            {
                "event_pattern": "openvpn_client_key_exchange",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "reject_key_exchange",
                        "reason": "username is not on the allow list"
                    }]
                }
            }
        ]
    }])
}

/// Static handler that refuses every peer at the reset.
fn reject_handler() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "openvpn",
        "event_handlers": [{
            "event_pattern": "openvpn_peer_reset",
            "handler": {
                "type": "static",
                "actions": [{"type": "reject_peer", "reason": "not on the allow list"}]
            }
        }]
    }])
}

/// Static handler that produces no decision at all, only a log line.
fn no_decision_handler() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "openvpn",
        "event_handlers": [{
            "event_pattern": "openvpn_peer_reset",
            "handler": {
                "type": "static",
                "actions": [{"type": "show_message", "message": "seen, but undecided"}]
            }
        }]
    }])
}

fn config_with(prompt: &str, startup: serde_json::Value) -> NetGetConfig {
    NetGetConfig::new(prompt).with_mock(move |mock| {
        mock.on_instruction_containing("OpenVPN")
            .respond_with_actions(startup)
            .expect_calls(1)
            .and()
    })
}

/// Bind a client socket and return it together with the server address.
async fn client_socket(port: u16) -> (UdpSocket, String) {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test client socket");
    (sock, format!("127.0.0.1:{}", port))
}

/// Receive one datagram, or `None` if nothing arrives within `secs`.
async fn recv_within(sock: &UdpSocket, secs: u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(secs), sock.recv(&mut buf)).await {
        Ok(Ok(len)) => Some(buf[..len].to_vec()),
        Ok(Err(e)) => panic!("recv failed: {}", e),
        Err(_) => None,
    }
}

/// Receive datagrams until one decodes to `opcode`, ignoring anything else.
///
/// The reliability layer retransmits an unacknowledged control packet, so a
/// specific reply is not necessarily the *next* datagram on the socket. A test
/// that assumed it was would fail for a reason that has nothing to do with what
/// it is checking.
async fn recv_opcode(sock: &UdpSocket, opcode: u8, secs: u64) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut buf = vec![0u8; 65535];
        match timeout(left, sock.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                let datagram = buf[..len].to_vec();
                if !datagram.is_empty() && (datagram[0] >> 3) == opcode {
                    return Some(datagram);
                }
            }
            Ok(Err(e)) => panic!("recv failed: {}", e),
            Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// A real openvpn client
// ---------------------------------------------------------------------------

/// Fail loudly when `openvpn` is missing, rather than reporting success.
async fn require_openvpn() {
    let available = Command::new("openvpn")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        available,
        "the `openvpn` client is required for this test. Install it with \
         `brew install openvpn` (macOS) or `apt-get install openvpn` (Debian/Ubuntu). \
         This test is not skipped when the client is missing, because a skip that \
         reports success would hide a broken handshake."
    );
}

/// Pull the control-channel certificate fingerprint out of the server's log.
///
/// The certificate is generated per run, so this is the only value a client can
/// pin it by, and the server logs it precisely so an operator (or this test) can
/// paste it into `--peer-fingerprint`.
async fn peer_fingerprint(server: &crate::helpers::server::NetGetServer) -> String {
    server.wait_for_any(&["peer fingerprint SHA256="], 30).await;
    let log = server.get_output().await.join("\n");
    log.lines()
        .find_map(|line| line.split("peer fingerprint SHA256=").nth(1))
        .map(|fp| fp.trim().to_string())
        .unwrap_or_else(|| {
            panic!(
                "the server must log its control-channel certificate fingerprint; without it \
                 no client can trust the certificate. Server log:\n{}",
                log
            )
        })
}

/// Run the real `openvpn` client against `port` for `secs` and return its log.
async fn run_openvpn_client(port: u16, fingerprint: &str, secs: u64, tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "netget_openvpn_e2e_{}_{}_{}",
        std::process::id(),
        tag,
        port
    ));
    tokio::fs::create_dir_all(&dir).await.expect("temp dir");
    let creds = dir.join("creds.txt");
    tokio::fs::write(&creds, format!("{}\n{}\n", TEST_USERNAME, TEST_PASSWORD))
        .await
        .expect("write creds");

    let mut client = Command::new("openvpn")
        .args([
            "--client",
            "--dev",
            "null",
            "--proto",
            "udp",
            "--remote",
            "127.0.0.1",
            &port.to_string(),
            "--nobind",
            "--verb",
            "4",
            "--auth-user-pass",
        ])
        .arg(&creds)
        // The server's certificate is self-signed and fresh per run, so this is
        // OpenVPN 2.6+'s documented way to trust it: pin the SHA-256 the server
        // just printed. No CA and no PKI are involved.
        .args(["--peer-fingerprint", fingerprint])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start the openvpn client");

    tokio::time::sleep(Duration::from_secs(secs)).await;
    let _ = client.kill().await;
    let output = client.wait_with_output().await.expect("client output");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !log.contains("Options error"),
        "the openvpn client rejected its own command line, so nothing was tested:\n{}",
        log
    );
    log
}

#[tokio::test]
async fn test_real_openvpn_client_completes_tls_and_key_exchange() -> E2EResult<()> {
    require_openvpn().await;

    let server = start_netget_server(config_with(
        "Start an OpenVPN honeypot on port {AVAILABLE_PORT}",
        accept_handler(),
    ))
    .await?;
    let port = server.port;
    let fingerprint = peer_fingerprint(&server).await;

    let log = run_openvpn_client(port, &fingerprint, 12, "accept").await;

    // Emitted only after a P_CONTROL_HARD_RESET_SERVER_V2 was parsed and the
    // server's session id adopted. A reply with its fields in the wrong order
    // never produces it.
    let marker = format!("TLS: Initial packet from [AF_INET]127.0.0.1:{}", port);
    assert!(
        log.contains(&marker),
        "the real openvpn client did not accept our reset reply (looked for {:?}).\n\
         Client log:\n{}\nServer log:\n{}",
        marker,
        log,
        server.get_output().await.join("\n")
    );

    // The whole point of the reliability layer and the TLS control channel: the
    // client's ClientHello is fragmented across several P_CONTROL_V1 packets,
    // ours are too, and both sides must reassemble in order. `VERIFY OK` is
    // printed from OpenSSL's verification callback, so it means our certificate
    // flight arrived intact and matched the fingerprint the server logged.
    assert!(
        log.contains("VERIFY OK: depth=0"),
        "the openvpn client did not verify our control-channel certificate, so the TLS \
         handshake did not get that far.\nClient log:\n{}\nServer log:\n{}",
        log,
        server.get_output().await.join("\n")
    );
    // OpenVPN prints this only once the session is *established*, which on the
    // client happens inside key_method_2_read - so it is evidence about the key
    // exchange, not about the handshake.
    assert!(
        log.contains("Control Channel: TLSv1"),
        "the openvpn client did not report an established control channel.\n\
         Client log:\n{}\nServer log:\n{}",
        log,
        server.get_output().await.join("\n")
    );

    // Printed after key_method_2_read accepted the server's key material,
    // options string and (empty) username/password/peer-info trailers. A
    // malformed answer produces a TLS Error instead.
    assert!(
        log.contains("Peer Connection Initiated"),
        "the openvpn client did not accept our key method 2 answer, so the key exchange is \
         not actually implemented correctly.\nClient log:\n{}\nServer log:\n{}",
        log,
        server.get_output().await.join("\n")
    );

    // The client only asks for its configuration once it considers the session
    // trusted and active, so this is the furthest-forward evidence available
    // that everything before it worked.
    assert!(
        log.contains("SENT CONTROL") && log.contains("'PUSH_REQUEST'"),
        "the openvpn client never got as far as asking for its configuration.\n\
         Client log:\n{}\nServer log:\n{}",
        log,
        server.get_output().await.join("\n")
    );

    // And be explicit about the limit: a completed key exchange is not a tunnel.
    assert!(
        !log.contains("Initialization Sequence Completed"),
        "the client reported a completed tunnel, which this server cannot build - it answers \
         no PUSH_REQUEST and derives no data channel keys. If that is now genuinely possible, \
         the protocol's metadata and docs are wrong.\n{}",
        log
    );

    server
        .wait_for_any(&["sent PUSH_REQUEST", "PUSH_REQUEST"], 20)
        .await;
    let server_log = server.get_output().await.join("\n");
    assert!(
        server_log.contains("HARD_RESET_SERVER_V2"),
        "server should log the reply it sent. Server log:\n{}",
        server_log
    );
    assert!(
        server_log.contains("TLS handshake completed"),
        "server should log that the control-channel TLS handshake finished. Server log:\n{}",
        server_log
    );
    // The credential capture is the reason this protocol is worth running as a
    // honeypot, and it is only possible because the TLS session is real.
    assert!(
        server_log.contains(TEST_USERNAME),
        "server should have read the username out of the client's key method 2 message. \
         Server log:\n{}",
        server_log
    );
    assert!(
        server_log.contains("PUSH_REQUEST"),
        "the client asks for its configuration next; the server should log that it cannot \
         answer. Server log:\n{}",
        server_log
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_real_openvpn_client_is_refused_at_the_key_exchange() -> E2EResult<()> {
    require_openvpn().await;

    let server = start_netget_server(config_with(
        "Start an OpenVPN honeypot on port {AVAILABLE_PORT}",
        accept_reset_reject_key_exchange_handler(),
    ))
    .await?;
    let port = server.port;
    let fingerprint = peer_fingerprint(&server).await;

    let log = run_openvpn_client(port, &fingerprint, 12, "reject").await;

    // The refusal is applied *after* TLS, so the handshake must still complete:
    // otherwise this test would pass for a server that is simply broken.
    //
    // `VERIFY OK` is the marker rather than `Control Channel: TLSv1.x`, because
    // OpenVPN prints the latter only once key_method_2_read has succeeded — it
    // is a summary of the *established* session, not of the handshake. `VERIFY
    // OK` is printed from OpenSSL's verification callback, so it means our
    // certificate flight arrived intact over the reliability layer and matched
    // the fingerprint.
    assert!(
        log.contains("VERIFY OK: depth=0"),
        "the TLS handshake must still complete - the refusal is a decision about the key \
         exchange, not a broken control channel.\nClient log:\n{}\nServer log:\n{}",
        log,
        server.get_output().await.join("\n")
    );
    assert!(
        !log.contains("Peer Connection Initiated"),
        "reject_key_exchange must be enforced: a refused client must never see a key method 2 \
         answer.\nClient log:\n{}\nServer log:\n{}",
        log,
        server.get_output().await.join("\n")
    );
    assert!(
        !log.contains("Initialization Sequence Completed"),
        "a refused client must certainly not report a tunnel.\n{}",
        log
    );

    let server_log = server.get_output().await.join("\n");
    assert!(
        server_log.contains("decision=model_reject")
            && server_log.contains("username is not on the allow list"),
        "the refusal and its reason should be logged, and an explicit refusal must carry \
         decision=model_reject rather than any fail_closed_ tag. Server log:\n{}",
        server_log
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw UDP against an independent codec
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reset_reply_is_spec_correct_and_control_packets_are_acked() -> E2EResult<()> {
    let server = start_netget_server(config_with(
        "Start an OpenVPN honeypot on port {AVAILABLE_PORT}",
        accept_handler(),
    ))
    .await?;
    let (sock, addr) = client_socket(server.port).await;

    let client_session: u64 = 0x1122_3344_5566_7788;
    let client_reset_pid: u32 = 0;

    sock.send_to(&client_reset_v2(client_session, client_reset_pid), &addr)
        .await
        .expect("send reset");

    let reply = recv_opcode(&sock, OP_HARD_RESET_SERVER_V2, 10)
        .await
        .expect("server must answer an accepted reset");

    assert_eq!(
        reply.len(),
        26,
        "a reset reply is 26 bytes; got {}: {}",
        reply.len(),
        to_hex(&reply)
    );

    let decoded = decode_control(&reply);
    assert_eq!(
        decoded.opcode, OP_HARD_RESET_SERVER_V2,
        "reply must be P_CONTROL_HARD_RESET_SERVER_V2, got opcode {}",
        decoded.opcode
    );
    assert_eq!(
        decoded.acks,
        vec![client_reset_pid],
        "the reply must acknowledge the packet id we actually sent"
    );
    assert_eq!(
        decoded.remote_session_id,
        Some(client_session),
        "the reply must echo our session id, not a fixed value"
    );
    assert_eq!(
        decoded.packet_id,
        Some(0),
        "the server's first control packet is numbered 0"
    );
    assert!(
        decoded.payload.is_empty(),
        "trailing bytes after the packet id would be parsed by a client as control payload: {}",
        to_hex(&decoded.payload)
    );

    let server_session = decoded.session_id;
    assert_ne!(
        server_session, 0,
        "the server must use a real session id of its own"
    );

    // Unacknowledged, the reply must come back on its own: the control channel
    // is a reliable layer, and a peer that missed the first copy has no other
    // way to make progress. This is the reliability layer's whole job and it
    // must not depend on the client asking again.
    let retransmit = recv_opcode(&sock, OP_HARD_RESET_SERVER_V2, 6)
        .await
        .expect("an unacknowledged reset reply must be retransmitted");
    assert_eq!(
        retransmit, reply,
        "a retransmission must be byte-identical: a peer that sees two different frames with \
         one packet id has to guess which it already processed"
    );

    // A retransmitted reset must also be answered again, and must not be
    // treated as a new peer.
    sock.send_to(&client_reset_v2(client_session, client_reset_pid), &addr)
        .await
        .expect("send reset retransmission");
    let again = recv_opcode(&sock, OP_HARD_RESET_SERVER_V2, 10)
        .await
        .expect("a retransmitted reset must be answered again");
    assert_eq!(
        again, reply,
        "the answer to a retransmitted reset must be identical"
    );

    // Now the control packet a real client sends next, acknowledging packet 0
    // so the reset reply leaves the retransmission queue.
    let hello = tls_handshake_record(64);
    sock.send_to(
        &client_control_v1(client_session, server_session, 0, 1, &hello),
        &addr,
    )
    .await
    .expect("send control packet");

    let ack = recv_opcode(&sock, OP_ACK_V1, 10)
        .await
        .expect("the server must acknowledge a control packet");
    assert_eq!(
        ack.len(),
        22,
        "an ACK is 22 bytes; got {}: {}",
        ack.len(),
        to_hex(&ack)
    );

    let decoded_ack = decode_control(&ack);
    assert_eq!(decoded_ack.opcode, OP_ACK_V1);
    assert_eq!(
        decoded_ack.acks,
        vec![1],
        "the ACK must name the control packet id we sent"
    );
    assert_eq!(decoded_ack.remote_session_id, Some(client_session));
    assert_eq!(decoded_ack.session_id, server_session);
    assert_eq!(
        decoded_ack.packet_id, None,
        "P_ACK_V1 has no message packet id; the extra four bytes would be read as payload"
    );
    assert!(decoded_ack.payload.is_empty());

    // A data packet cannot be decrypted - no data channel keys are derived -
    // and must not take the server down or produce a bogus reply.
    sock.send_to(&data_v2(1, &[0xEE; 64]), &addr)
        .await
        .expect("send data packet");

    // Hostile and unsupported input must not stop the server serving.
    let junk: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xFF; 3],
        hex("38090a7265e64d55eeff"), // ACK length 255, nothing behind it
        hex("50aabbccddeeff00112233445566778899"), // tls-crypt-v2 reset
        vec![0x20],                  // control opcode, nothing else
    ];
    for bytes in &junk {
        let _ = sock.send_to(bytes, &addr).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Still alive and still correct: a brand new peer gets a proper answer.
    let (sock2, _) = client_socket(server.port).await;
    let second_session: u64 = 0x0f0e_0d0c_0b0a_0908;
    sock2
        .send_to(&client_reset_v2(second_session, 3), &addr)
        .await
        .expect("send second reset");
    let reply2 = recv_opcode(&sock2, OP_HARD_RESET_SERVER_V2, 10)
        .await
        .expect("the server must still answer after being fed junk");
    let decoded2 = decode_control(&reply2);
    assert_eq!(decoded2.opcode, OP_HARD_RESET_SERVER_V2);
    assert_eq!(decoded2.acks, vec![3]);
    assert_eq!(decoded2.remote_session_id, Some(second_session));

    server.wait_for_any(&["tls-crypt-v2"], 20).await;
    let server_log = server.get_output().await.join("\n");
    assert!(
        server_log.contains("tls-crypt-v2"),
        "the server should say why it ignored the tls-crypt-v2 frame. Server log:\n{}",
        server_log
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_garbage_tls_record_kills_only_that_session() -> E2EResult<()> {
    // A control payload that is not a TLS record must fail the TLS session and
    // nothing else: the server must not answer with anything resembling a
    // handshake, and must keep serving other peers.
    let server = start_netget_server(config_with(
        "Start an OpenVPN honeypot on port {AVAILABLE_PORT}",
        accept_handler(),
    ))
    .await?;
    let (sock, addr) = client_socket(server.port).await;

    let client_session: u64 = 0x4142_4344_4546_4748;
    sock.send_to(&client_reset_v2(client_session, 0), &addr)
        .await
        .expect("send reset");
    let reply = recv_opcode(&sock, OP_HARD_RESET_SERVER_V2, 10)
        .await
        .expect("server must answer an accepted reset");
    let server_session = decode_control(&reply).session_id;

    // A well-formed TLS record header wrapping nonsense.
    sock.send_to(
        &client_control_v1(
            client_session,
            server_session,
            0,
            1,
            &tls_handshake_record(64),
        ),
        &addr,
    )
    .await
    .expect("send bogus handshake");

    let ack = recv_opcode(&sock, OP_ACK_V1, 10)
        .await
        .expect("the packet must still be acknowledged before TLS rejects its contents");
    assert_eq!(decode_control(&ack).acks, vec![1]);

    server.wait_for_any(&["TLS session failed"], 20).await;
    let server_log = server.get_output().await.join("\n");
    assert!(
        server_log.contains("TLS session failed"),
        "the server should say the control-channel TLS session failed. Server log:\n{}",
        server_log
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_rejected_peer_receives_nothing() -> E2EResult<()> {
    let server = start_netget_server(config_with(
        "Start an OpenVPN honeypot on port {AVAILABLE_PORT}",
        reject_handler(),
    ))
    .await?;
    let (sock, addr) = client_socket(server.port).await;

    sock.send_to(&client_reset_v2(0xAAAA_BBBB_CCCC_DDDD, 0), &addr)
        .await
        .expect("send reset");

    assert!(
        recv_within(&sock, 4).await.is_none(),
        "reject_peer must be enforced: a refused peer receives no bytes at all"
    );

    // A retransmission must not slip past the refusal either.
    sock.send_to(&client_reset_v2(0xAAAA_BBBB_CCCC_DDDD, 1), &addr)
        .await
        .expect("send reset retransmission");
    assert!(
        recv_within(&sock, 4).await.is_none(),
        "a retransmitted reset from a refused peer must also go unanswered"
    );

    let server_log = server.get_output().await.join("\n");
    assert!(
        server_log.contains("decision=model_reject")
            && server_log.contains("not on the allow list"),
        "the refusal and its reason should be logged, and an explicit model refusal must \
         carry decision=model_reject rather than any fail_closed_ tag. Server log:\n{}",
        server_log
    );
    assert!(
        !server_log.contains("decision=fail_closed"),
        "a model refusal must never be recorded as fail-closed: the two are different \
         events and an operator greps for the difference. Server log:\n{}",
        server_log
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_absent_decision_fails_closed() -> E2EResult<()> {
    // The handler runs and produces output, but no accept_peer and no
    // reject_peer. Silence from the decision layer must not fall through to
    // answering the peer, and must be distinguishable in the log from an
    // explicit refusal.
    let server = start_netget_server(config_with(
        "Start an OpenVPN honeypot on port {AVAILABLE_PORT}",
        no_decision_handler(),
    ))
    .await?;
    let (sock, addr) = client_socket(server.port).await;

    sock.send_to(&client_reset_v2(0x0102_0304_0506_0708, 0), &addr)
        .await
        .expect("send reset");

    assert!(
        recv_within(&sock, 4).await.is_none(),
        "an undecided peer must not be answered - defaulting to a reply would make an LLM \
         outage indistinguishable from approval"
    );

    let server_log = server.get_output().await.join("\n");
    assert!(
        server_log.contains("decision=fail_closed_no_action"),
        "the no-decision path must be logged distinctly from a refusal, under its own \
         greppable decision= tag. Server log:\n{}",
        server_log
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
