//! The model is not on RTP's per-packet path, and the ceiling that keeps it off is real.
//!
//! A single G.711 stream is 50 packets per second. One LLM call per inbound datagram would
//! exhaust the model budget in seconds, and — because each consultation can authorize up to 30
//! seconds of outbound media — a spoofed source address would turn the server into an
//! amplifier. `llm_max_per_minute` is the ceiling; a script or static handler is never charged
//! against it, which is what makes a low ceiling usable rather than crippling.
//!
//! Three things are measured here, and the third is what makes the other two mean anything:
//! over-budget datagrams get nothing, a handler-answered datagram gets media *at the same
//! ceiling of zero*, and the window itself admits exactly N and then stops.


use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use ::netget::server::rtp::RtpLlmBudget;

/// Minimal RFC 3550 §5.1 header, no payload.
fn rtp_packet(seq: u16) -> Vec<u8> {
    let mut pkt = vec![0x80, 0x00];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&1000u32.to_be_bytes());
    pkt.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    pkt.extend_from_slice(&[0xFFu8; 160]);
    pkt
}

/// Start an in-process RTP server with the given startup params and routing rules.
///
/// The LLM endpoint is a closed port, so any consultation that does happen fails fast. That is
/// deliberate: it means "nothing came back" cannot be confused with "the model was slow".
async fn start_rtp_in_process(
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> (::netget::state::app_state::AppState, u16) {
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
        protocol: "rtp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // Empty rather than None: `ServerForm::create` substitutes a default instruction for
        // `None`, which would make the server consult the model on every packet.
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create rtp server");

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
    assert_ne!(port, 0, "RTP server never bound a port");
    (state, port)
}

/// Send one RTP packet and wait for a reply, returning `None` if nothing arrives.
async fn probe(port: u16, seq: u16, wait: Duration) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    socket
        .send_to(&rtp_packet(seq), server)
        .await
        .expect("send rtp");
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// `llm_max_per_minute: 0` forbids model consultation outright, and RTP's answer to that is
/// the same silence every other RTP failure produces — no error frame, nothing on the wire.
///
/// This is the fail-closed direction: a rate-limited packet must not fall through to some
/// default stream, because that would be media the model never authorized.
#[tokio::test]
async fn rtp_over_budget_sends_nothing() {
    let (_state, port) =
        start_rtp_in_process(Some(serde_json::json!({"llm_max_per_minute": 0})), None).await;

    for seq in 0..3u16 {
        assert!(
            probe(port, seq, Duration::from_secs(3)).await.is_none(),
            "packet {seq}: the budget forbids model consultation, so nothing may be streamed"
        );
    }
}

/// The other half, and the one that makes a zero ceiling a usable configuration rather than an
/// off switch: a static handler answers without a model call and is **never charged**, so it
/// streams at the same `llm_max_per_minute: 0` that silenced the test above.
///
/// Without this control, `rtp_over_budget_sends_nothing` is indistinguishable from a server
/// that never streams anything at all.
#[tokio::test]
async fn rtp_static_handler_is_never_charged_against_the_budget() {
    let (_state, port) = start_rtp_in_process(
        Some(serde_json::json!({"llm_max_per_minute": 0})),
        Some(vec![serde_json::json!({
            "event_pattern": "rtp_packet_received",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_rtp_audio",
                    "payload_type": "pcmu",
                    "content": "tone",
                    "tone_hz": 440,
                    "duration_ms": 60
                }]
            }
        })]),
    )
    .await;

    let reply = probe(port, 0, Duration::from_secs(20))
        .await
        .expect("a static handler must stream even at llm_max_per_minute: 0");

    assert!(reply.len() >= 12, "reply is not an RTP packet: {reply:?}");
    assert_eq!(reply[0] >> 6, 2, "RTP version must be 2");
    assert_eq!(reply[1] & 0x7F, 0, "PCMU is payload type 0");
}

/// The window itself: exactly `max_per_minute` consultations are admitted, then none, and the
/// admissions come back as the window slides — a sliding window, not a bucket that refills
/// continuously and permits bursts above the ceiling.
#[test]
fn rtp_budget_admits_exactly_the_ceiling_then_refuses() {
    let start = Instant::now();
    let mut budget = RtpLlmBudget::new(3);

    for i in 0..3 {
        assert!(
            budget.try_take_at(start + Duration::from_millis(i * 10)),
            "consultation {i} is within the ceiling of 3"
        );
    }
    assert!(
        !budget.try_take_at(start + Duration::from_millis(40)),
        "a fourth consultation in the same minute must be refused"
    );

    // Still refused at 59 seconds: the window is a minute, not an average.
    assert!(
        !budget.try_take_at(start + Duration::from_secs(59)),
        "the window has not yet expired"
    );
    // The first hit ages out at 60 seconds, so exactly one slot reopens.
    assert!(
        budget.try_take_at(start + Duration::from_secs(60)),
        "the first consultation has aged out, so one slot is free"
    );
    assert!(
        !budget.try_take_at(start + Duration::from_secs(60)),
        "and only one"
    );
}

/// Zero forbids everything, including the first call. An operator who sets it means it.
#[test]
fn rtp_budget_of_zero_admits_nothing() {
    let mut budget = RtpLlmBudget::new(0);
    assert!(!budget.try_take());
    assert!(!budget.try_take());
    assert_eq!(budget.max_per_minute(), 0);
}
