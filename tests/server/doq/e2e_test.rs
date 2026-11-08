use super::support::*;
use hickory_proto::op::{MessageType, ResponseCode};
use netget::client::doq::exchange;
use netget::server::doq::wire::{decode, encode, PROTOCOL_ERROR};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn independent_kdig_reads_authenticated_a_aaaa_and_negative_answers() {
    let fixture = Fixture::standard().await;
    for (kind, expected) in [
        ("A", "192.0.2.19"),
        ("AAAA", "2001:db8::19"),
        ("MX", "NXDOMAIN"),
    ] {
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("kdig")
                .arg("+quic")
                .arg(format!(
                    "+tls-ca={}",
                    fixture.dir.path().join("cert.pem").display()
                ))
                .arg("+tls-hostname=localhost")
                .arg("+timeout=3")
                .arg("+retry=0")
                .arg("@127.0.0.1")
                .arg("-p")
                .arg(fixture.addr.port().to_string())
                .arg("independent.example")
                .arg(kind)
                .output(),
        )
        .await
        .unwrap()
        .expect("kdig is required: brew install knot (with QUIC support)");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "kdig failed: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains(expected), "{kind}: {stdout}");
    }
    fixture.close().await;
}

#[tokio::test]
async fn multiplexing_fin_id_question_and_cleanup() {
    let fixture = Fixture::standard().await;
    let (_endpoint, connection) = fixture.peer().await;
    let a = query("one.example", "A");
    let aaaa = query("two.example", "AAAA");
    let (first, second) = tokio::join!(
        exchange(&connection, &a, Duration::from_secs(5)),
        exchange(&connection, &aaaa, Duration::from_secs(5))
    );
    let (first, s1) = first.unwrap();
    let (second, s2) = second.unwrap();
    assert_ne!(s1, s2);
    assert_eq!(first.id, 0);
    assert_eq!(second.id, 0);
    assert_eq!(first.queries, a.queries);
    assert_eq!(second.queries, aaaa.queries);
    assert_eq!(first.answers[0].ttl, 17);
    assert_eq!(second.answers[0].ttl, 23);
    fixture.decision("decision=model_answer").await;
    fixture.close().await;
    tokio::time::timeout(Duration::from_secs(3), connection.closed())
        .await
        .unwrap();
    // Aborting the owner also releases the UDP port, including established streams.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if std::net::UdpSocket::bind(fixture.addr).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_frames_close_the_connection_with_doq_protocol_error() {
    let fixture = Fixture::standard().await;
    let valid = encode(&query("example.com", "A")).unwrap();
    let mut extra = valid.clone();
    extra.extend_from_slice(&valid);
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&valid[2..]);
    let declared = (trailing.len() - 2) as u16;
    trailing[..2].copy_from_slice(&declared.to_be_bytes());
    let mut nonzero_id = valid.clone();
    nonzero_id[3] = 1;
    let mut short = valid.clone();
    short.pop();
    let oversized = vec![0; 65538];
    for frame in [vec![0, 0], extra, trailing, nonzero_id, short, oversized] {
        let (_endpoint, c) = fixture.peer().await;
        let (mut send, _recv) = c.open_bi().await.unwrap();
        // A strict receive window may reject the oversized body while writing.
        let _ = tokio::time::timeout(Duration::from_secs(3), send.write_all(&frame)).await;
        let _ = send.finish();
        let error = tokio::time::timeout(Duration::from_secs(4), c.closed())
            .await
            .unwrap();
        assert!(
            matches!(error,quinn::ConnectionError::ApplicationClosed(ref e) if e.error_code==PROTOCOL_ERROR),
            "{error:?}"
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn missing_fin_times_out_and_cancellation_leaves_other_streams_usable() {
    let fixture = Fixture::new(json!({"exchange_timeout_secs":1,"max_streams":2}),Some(json!({"type":"static","actions":[{"type":"send_dns_a_response","domain":"live.example","ip":"192.0.2.1"}]}))).await;
    let (_endpoint, c) = fixture.peer().await;
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(&encode(&query("dangling.example", "A")).unwrap())
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(65537))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error,quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) if code.into_inner()==5)
    );
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(&[0, 25, 0]).await.unwrap();
    recv.stop(3u32.into()).unwrap();
    send.reset(3u32.into()).unwrap();
    let (response, _) = exchange(&c, &query("live.example", "A"), Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(response.answers.len(), 1);
    fixture.close().await;
}

#[tokio::test]
async fn connection_cap_releases_slots_idle_timeout_and_alpn() {
    let fixture = Fixture::new(
        json!({"max_connections":1,"idle_timeout_secs":1}),
        Some(json!({"type":"static","actions":[]})),
    )
    .await;
    let (endpoint, c) = fixture.peer().await;
    let original_peer_addr = endpoint.local_addr().unwrap();
    let other = fixture.endpoint(b"doq");
    assert!(other
        .connect(fixture.addr, "localhost")
        .unwrap()
        .await
        .is_err());
    tokio::time::timeout(Duration::from_secs(3), c.closed())
        .await
        .unwrap();
    // The peer observes its idle close before the server finishes retiring its
    // session. Wait for this peer's server row, rather than retrying a refused
    // replacement connection and hiding a capacity-release failure.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let server = fixture.state.get_server(fixture.server).await.unwrap();
            if server.connections.values().any(|connection| {
                connection.remote_addr == original_peer_addr
                    && connection.status == netget::state::server::ConnectionStatus::Closed
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("original DoQ server session did not close after its idle deadline");
    let (_endpoint, c2) = fixture.peer().await;
    c2.close(0u32.into(), b"done");
    let wrong = fixture.endpoint(b"h3");
    assert!(wrong
        .connect(fixture.addr, "localhost")
        .unwrap()
        .await
        .is_err());
    fixture.close().await;
}

#[tokio::test]
async fn handler_failure_returns_servfail_and_xfr_is_explicitly_unsupported() {
    let fixture = Fixture::new(json!({}), None).await;
    let (_endpoint, c) = fixture.peer().await;
    let (response, _) = exchange(&c, &query("failure.example", "A"), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::ServFail);
    fixture
        .decision("decision=fail_closed_llm_error category=unavailable")
        .await;
    let mut xfr = query("zone.example", "A");
    xfr.queries[0].set_query_type(hickory_proto::rr::RecordType::AXFR);
    let (response, _) = exchange(&c, &xfr, Duration::from_secs(3)).await.unwrap();
    assert_eq!(response.response_code, ResponseCode::NotImp);
    fixture.close().await;
}

#[tokio::test]
async fn decision_logs_distinguish_silence_negative_answers_and_action_failure() {
    for (actions, decision, expected) in [
        (json!([]), "decision=model_silent", None),
        (
            json!([{"type":"send_dns_nxdomain","domain":"decision.example","query_type":"A"}]),
            "decision=model_reject",
            Some(ResponseCode::NXDomain),
        ),
        (
            json!([{"type":"send_dns_a_response","domain":"decision.example","ip":"invalid"}]),
            "decision=fail_closed_action_error",
            Some(ResponseCode::ServFail),
        ),
    ] {
        let fixture =
            Fixture::new(json!({}), Some(json!({"type":"static","actions":actions}))).await;
        let (_endpoint, c) = fixture.peer().await;
        let result = exchange(&c, &query("decision.example", "A"), Duration::from_secs(3)).await;
        if let Some(code) = expected {
            assert_eq!(result.unwrap().0.response_code, code);
        } else {
            assert!(result.is_err(), "silence resets the stream");
        }
        fixture.decision(decision).await;
        fixture.close().await;
    }
}

#[test]
fn decoder_rejects_truncation_extra_messages_ids_and_tcp_keepalive() {
    let mut q = query("example.com", "A");
    let frame = encode(&q).unwrap();
    assert!(decode(&frame[..frame.len() - 1], MessageType::Query).is_err());
    assert!(decode(&frame, MessageType::Response).is_err());
    let mut trailing = frame.clone();
    trailing.push(0);
    let declared = (trailing.len() - 2) as u16;
    trailing[..2].copy_from_slice(&declared.to_be_bytes());
    assert!(decode(&trailing, MessageType::Query).is_err());
    q.metadata.id = 2;
    assert!(encode(&q).is_err());
    q.metadata.id = 0;
    let mut edns = hickory_proto::op::Edns::new();
    edns.options_mut()
        .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
            11,
            vec![],
        ));
    q.set_edns(edns);
    assert!(decode(&encode(&q).unwrap(), MessageType::Query).is_err());
}

#[tokio::test]
async fn stream_credit_bounds_dangling_queries_and_recovers_after_cancellation() {
    let fixture = Fixture::new(
        json!({"max_streams":2,"exchange_timeout_secs":3}),
        Some(json!({"type":"static","actions":[]})),
    )
    .await;
    let (_endpoint, c) = fixture.peer().await;
    let (mut first_send, mut first_recv) = c.open_bi().await.unwrap();
    first_send.write_all(&[0, 30, 0]).await.unwrap();
    let (mut second_send, _second_recv) = c.open_bi().await.unwrap();
    second_send.write_all(&[0, 30, 0]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), c.open_bi())
            .await
            .is_err(),
        "third stream must wait for credit"
    );
    first_send.reset(3u32.into()).unwrap();
    first_recv.stop(3u32.into()).unwrap();
    let (mut third_send, _third_recv) = tokio::time::timeout(Duration::from_secs(2), c.open_bi())
        .await
        .unwrap()
        .unwrap();
    third_send.write_all(&[0, 30, 0]).await.unwrap();
    fixture.close().await;
    tokio::time::timeout(Duration::from_secs(2), c.closed())
        .await
        .unwrap();
}

#[tokio::test]
async fn handshake_deadline_releases_a_slot_without_a_completed_tls_session() {
    let fixture = Fixture::new(
        json!({"max_connections":1,"handshake_timeout_secs":1,"idle_timeout_secs":10}),
        Some(json!({"type":"static","actions":[]})),
    )
    .await;
    // Forward an authentic QUIC Initial, then blackhole the server flight. This
    // creates an Incoming that can never finish TLS, without a hand-written QUIC codec.
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stalled_endpoint = fixture.endpoint(b"doq");
    let _stalled = stalled_endpoint
        .connect(relay.local_addr().unwrap(), "localhost")
        .unwrap();
    let mut packet = vec![0; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    relay.send_to(&packet[..n], fixture.addr).await.unwrap();
    // Receiving its flight proves the server created the pending handshake.
    tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    let probe = fixture.endpoint(b"doq");
    assert!(
        probe
            .connect(fixture.addr, "localhost")
            .unwrap()
            .await
            .is_err(),
        "pending handshake consumes the only slot"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let (_endpoint, c) = fixture.peer().await;
    c.close(0u32.into(), b"done");
    fixture.close().await;
}
