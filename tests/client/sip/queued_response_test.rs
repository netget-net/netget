//! What the SIP client does with responses that arrive while the model is answering an earlier
//! one, and where its automatic ACK goes relative to the model's answer.
//!
//! The client carried a copy of the server's Idle/Processing/Accumulating machine with a
//! `queued_data` buffer that was cleared after one parse: had it ever filled, every queued
//! datagram but the first would have been lost. It never filled — the read loop calls the model
//! inline, so nothing is read during a call — and the machine is gone. What arrives during a
//! call waits in the socket, one datagram per response, and is read in turn afterwards. The
//! first test pins that every such response reaches the model, in order, one call each.
//!
//! The second pins the automatic ACK for an INVITE's 200: it goes out before the model is asked,
//! with the INVITE's sequence number from the response. It used to go out after the model's
//! actions, numbered from the dialog's counter, so a model answering the 200 with BYE put the
//! BYE on the wire first and gave the ACK the BYE's CSeq.
//!
//! The peer is a plain UDP socket.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const EVENT: &str = "sip_client_response_received";

async fn client(mock: &MockOllamaServer, peer: &UdpSocket) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "sip".to_string(),
        remote_addr: Some(peer.local_addr().unwrap().to_string()),
        instruction: Some("Note every response.".to_string()),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create sip client");
    (state, id)
}

/// Make the client send an OPTIONS, so the peer learns its address. Returns that address.
async fn learn_address(state: &AppState, id: ClientId, peer: &UdpSocket) -> std::net::SocketAddr {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let outcome = state
        .send_to_client(
            id,
            serde_json::json!({
                "type": "sip_options",
                "from": "sip:probe@127.0.0.1",
                "to": "sip:peer@127.0.0.1",
                "request_uri": "sip:peer@127.0.0.1",
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "{outcome:?}"
    );
    let mut buf = vec![0u8; 65535];
    let (_, addr) = recv(peer, &mut buf).await;
    addr
}

async fn recv(peer: &UdpSocket, buf: &mut [u8]) -> (String, std::net::SocketAddr) {
    let (n, addr) = tokio::time::timeout(Duration::from_secs(10), peer.recv_from(buf))
        .await
        .expect("nothing arrived within 10s")
        .expect("recv_from");
    (String::from_utf8_lossy(&buf[..n]).to_string(), addr)
}

fn response(reason: &str, cseq: &str) -> String {
    format!(
        "SIP/2.0 200 {reason}\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
         From: <sip:probe@127.0.0.1>;tag=a\r\n\
         To: <sip:peer@127.0.0.1>;tag=b\r\n\
         Call-ID: test@127.0.0.1\r\n\
         CSeq: {cseq}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responses_that_arrive_during_a_model_call_are_each_delivered() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("reason_phrase", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (state, id) = client(&mock, &peer).await;
    let addr = learn_address(&state, id, &peer).await;

    let reasons = |records: Vec<crate::helpers::mock_config::MockCallRecord>| {
        records
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
            .map(|c| {
                c.context.event_data["reason_phrase"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect::<Vec<_>>()
    };

    peer.send_to(response("first", "2 OPTIONS").as_bytes(), addr)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while reasons(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    peer.send_to(response("second", "3 OPTIONS").as_bytes(), addr)
        .await
        .unwrap();
    peer.send_to(response("third", "4 OPTIONS").as_bytes(), addr)
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let seen = reasons(mock.recorded_calls().await);
        if seen.len() >= 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "responses that arrived during the call were lost; the model saw only {seen:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        reasons(mock.recorded_calls().await),
        vec!["first", "second", "third"],
        "each response must reach the model once, in the order it arrived"
    );
    let _ = state.remove_client(id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ack_precedes_the_models_answer_and_repeats_the_invites_cseq() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("method", "INVITE")
            .respond_with_actions(serde_json::json!([{
                "type": "sip_bye",
                "from": "sip:probe@127.0.0.1",
                "to": "sip:peer@127.0.0.1",
                "request_uri": "sip:peer@127.0.0.1",
            }]))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (state, id) = client(&mock, &peer).await;
    let addr = learn_address(&state, id, &peer).await;

    peer.send_to(response("OK", "7 INVITE").as_bytes(), addr)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let (first, _) = recv(&peer, &mut buf).await;
    let (second, _) = recv(&peer, &mut buf).await;
    assert!(
        first.starts_with("ACK "),
        "the ACK must go out before the model's answer; first came:\n{first}"
    );
    assert!(
        first.contains("CSeq: 7 ACK"),
        "the ACK must repeat the INVITE's sequence number:\n{first}"
    );
    assert!(
        second.starts_with("BYE "),
        "the model's BYE must follow:\n{second}"
    );
    mock.verify_calls().await.unwrap();
    let _ = state.remove_client(id).await;
}
