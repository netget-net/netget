//! The CoAP client's transport against servers that misbehave on purpose.
//!
//! libcoap does not drop requests, stream Block2 forever, send oversize datagrams or repeat a
//! notification on request, so each bound here is shown against a few lines of test code that
//! does exactly one of those things, built with the shared codec. Every bound was verified by
//! removing it from `src/client/coap/mod.rs` and watching its test fail.
//!
//! LLM calls: 3 + 3 + 3 + 4 across the four model-driven tests; none in the exchange-cap test.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features coap --test client -- coap::transport_test --test-threads=100

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::*;
use ::netget::server::coap::codec::{code, CoapMessage, MessageType, CODE_EMPTY};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

const OPT_OBSERVE: u16 = 6;
const OPT_BLOCK2: u16 = 23;

async fn fake_server() -> (Arc<UdpSocket>, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    (Arc::new(socket), addr)
}

fn open_client<F>(
    addr: SocketAddr,
    marker: &str,
    startup: serde_json::Value,
    rules: F,
) -> NetGetConfig
where
    F: FnOnce(MockLlmBuilder) -> MockLlmBuilder,
{
    let addr = addr.to_string();
    let marker = marker.to_string();
    NetGetConfig::new(format!("Talk CoAP to {addr}. {marker}.")).with_mock(move |mock| {
        rules(
            mock.on_instruction_containing(&marker)
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "protocol": "CoAP",
                    "remote_addr": addr,
                    "instruction": "Read the resource.",
                    "startup_params": startup
                }]))
                .expect_calls(1)
                .and(),
        )
    })
}

/// A Confirmable request nobody answers is sent 1 + `max_retransmit` times, with the same
/// message id, and then reported to the model as a timeout — never retried forever.
#[tokio::test]
async fn an_unanswered_confirmable_request_is_retransmitted_a_bounded_number_of_times(
) -> E2EResult<()> {
    let (socket, addr) = fake_server().await;
    let seen: Arc<Mutex<Vec<u16>>> = Arc::default();
    let listener = {
        let (socket, seen) = (socket.clone(), seen.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = socket.recv_from(&mut buf).await {
                if let Ok(msg) = CoapMessage::decode(&buf[..n]) {
                    seen.lock().unwrap().push(msg.message_id);
                }
            }
        })
    };

    let config = open_client(
        addr,
        "COAP-SILENT-STARTUP",
        json!({"ack_timeout_ms": 100, "max_retransmit": 2}),
        |mock| {
            mock.on_event("coap_connected")
                .respond_with_actions(json!([{"type": "coap_get", "path": "/silent"}]))
                .expect_calls(1)
                .and()
                .on_event("coap_error")
                .and_event_data_contains("kind", "timeout")
                .and_event_data_contains("path", "/silent")
                .respond_with_actions(json!([]))
                .expect_calls(1)
                .and()
        },
    );
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        3,
        "one transmission and two retransmissions: {seen:?}"
    );
    assert!(
        seen.iter().all(|m| *m == seen[0]),
        "a retransmission carries the original message id: {seen:?}"
    );
    listener.abort();
    client.stop().await?;
    Ok(())
}

/// A server that answers every block with "more" is cut off at the reassembly limit and the
/// model is told `body_too_large`; the number of block requests is bounded by it.
#[tokio::test]
async fn a_block2_transfer_that_never_ends_is_cut_off() -> E2EResult<()> {
    let (socket, addr) = fake_server().await;
    let requests = Arc::new(Mutex::new(0usize));
    let responder = {
        let (socket, requests) = (socket.clone(), requests.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(req) = CoapMessage::decode(&buf[..n]) else {
                    continue;
                };
                *requests.lock().unwrap() += 1;
                let num = req
                    .option_values(OPT_BLOCK2)
                    .first()
                    .map(|v| v.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) >> 4)
                    .unwrap_or(0);
                let block = (num << 4) | 0x08 | 6; // more, SZX 6 = 1024 bytes
                let reply = CoapMessage {
                    mtype: MessageType::Acknowledgement,
                    code: code(2, 5),
                    message_id: req.message_id,
                    token: req.token.clone(),
                    options: vec![(OPT_BLOCK2, block.to_be_bytes()[1..].to_vec())],
                    payload: vec![b'x'; 1024],
                };
                let _ = socket.send_to(&reply.encode().unwrap(), peer).await;
            }
        })
    };

    let config = open_client(addr, "COAP-ENDLESS-STARTUP", json!({}), |mock| {
        mock.on_event("coap_connected")
            .respond_with_actions(json!([{"type": "coap_get", "path": "/endless"}]))
            .expect_calls(1)
            .and()
            .on_event("coap_error")
            .and_event_data_contains("kind", "body_too_large")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    let count = *requests.lock().unwrap();
    assert_eq!(
        count, 65,
        "64 KiB of 1024-byte blocks is 64 accepted blocks and the 65th refused"
    );
    responder.abort();
    client.stop().await?;
    Ok(())
}

/// A server that answers the request for block 1 with block 5 has lost the transfer's place;
/// the client refuses to splice it in and tells the model `bad_block`.
#[tokio::test]
async fn an_out_of_order_block_is_refused() -> E2EResult<()> {
    let (socket, addr) = fake_server().await;
    let responder = {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(req) = CoapMessage::decode(&buf[..n]) else {
                    continue;
                };
                let asked = req
                    .option_values(OPT_BLOCK2)
                    .first()
                    .map(|v| v.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) >> 4)
                    .unwrap_or(0);
                let sent = if asked == 0 { 0u32 } else { 5 };
                let block = (sent << 4) | 0x08 | 2; // more, SZX 2 = 64 bytes
                let reply = CoapMessage {
                    mtype: MessageType::Acknowledgement,
                    code: code(2, 5),
                    message_id: req.message_id,
                    token: req.token.clone(),
                    options: vec![(OPT_BLOCK2, vec![u8::try_from(block).unwrap()])],
                    payload: vec![b'z'; 64],
                };
                let _ = socket.send_to(&reply.encode().unwrap(), peer).await;
            }
        })
    };

    let config = open_client(addr, "COAP-SKIP-STARTUP", json!({}), |mock| {
        mock.on_event("coap_connected")
            .respond_with_actions(json!([{"type": "coap_get", "path": "/skips"}]))
            .expect_calls(1)
            .and()
            .on_event("coap_error")
            .and_event_data_contains("kind", "bad_block")
            .and_event_data_contains("message", "block 5")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    responder.abort();
    client.stop().await?;
    Ok(())
}

/// A datagram over the 1152-byte message bound is dropped unread, so a server that only ever
/// answers with one is a server that never answered.
#[tokio::test]
async fn an_oversize_datagram_is_dropped() -> E2EResult<()> {
    let (socket, addr) = fake_server().await;
    let responder = {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(req) = CoapMessage::decode(&buf[..n]) else {
                    continue;
                };
                let reply = CoapMessage {
                    mtype: MessageType::Acknowledgement,
                    code: code(2, 5),
                    message_id: req.message_id,
                    token: req.token.clone(),
                    options: vec![],
                    payload: vec![b'y'; 1200],
                };
                let _ = socket.send_to(&reply.encode().unwrap(), peer).await;
            }
        })
    };

    let config = open_client(
        addr,
        "COAP-OVERSIZE-STARTUP",
        json!({"ack_timeout_ms": 100, "max_retransmit": 1}),
        |mock| {
            mock.on_event("coap_connected")
                .respond_with_actions(json!([{"type": "coap_get", "path": "/huge"}]))
                .expect_calls(1)
                .and()
                .on_event("coap_error")
                .and_event_data_contains("kind", "timeout")
                .respond_with_actions(json!([]))
                .expect_calls(1)
                .and()
        },
    );
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    responder.abort();
    client.stop().await?;
    Ok(())
}

/// A Confirmable notification the server repeats (its ACK was lost) is acknowledged again but
/// shown to the model once; a notification for a token the client does not know is answered
/// with RST.
#[tokio::test]
async fn a_repeated_notification_reaches_the_model_once() -> E2EResult<()> {
    let (socket, addr) = fake_server().await;
    let acks: Arc<Mutex<Vec<(MessageType, u16)>>> = Arc::default();
    let responder = {
        let (socket, acks) = (socket.clone(), acks.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(msg) = CoapMessage::decode(&buf[..n]) else {
                    continue;
                };
                if msg.code == CODE_EMPTY {
                    acks.lock().unwrap().push((msg.mtype, msg.message_id));
                    continue;
                }
                // The registration: piggybacked 2.05 with Observe 1.
                let reg = CoapMessage {
                    mtype: MessageType::Acknowledgement,
                    code: code(2, 5),
                    message_id: msg.message_id,
                    token: msg.token.clone(),
                    options: vec![(OPT_OBSERVE, vec![1])],
                    payload: b"first".to_vec(),
                };
                let _ = socket.send_to(&reg.encode().unwrap(), peer).await;
                // One notification, sent twice with the same message id.
                let note = CoapMessage {
                    mtype: MessageType::Confirmable,
                    code: code(2, 5),
                    message_id: 0x7001,
                    token: msg.token.clone(),
                    options: vec![(OPT_OBSERVE, vec![2])],
                    payload: b"second".to_vec(),
                };
                let bytes = note.encode().unwrap();
                let _ = socket.send_to(&bytes, peer).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = socket.send_to(&bytes, peer).await;
                // And a notification for a token nobody registered.
                let stray = CoapMessage {
                    mtype: MessageType::NonConfirmable,
                    code: code(2, 5),
                    message_id: 0x7002,
                    token: vec![0xde, 0xad],
                    options: vec![(OPT_OBSERVE, vec![3])],
                    payload: b"stray".to_vec(),
                };
                let _ = socket.send_to(&stray.encode().unwrap(), peer).await;
            }
        })
    };

    let config = open_client(addr, "COAP-REPEAT-STARTUP", json!({}), |mock| {
        mock.on_event("coap_connected")
            .respond_with_actions(json!([{"type": "coap_observe", "path": "/obs"}]))
            .expect_calls(1)
            .and()
            .on_event("coap_response")
            .and_event_data_contains("observing", "true")
            .and_event_data_contains("payload", "first")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("coap_notification")
            .and_event_data_contains("payload", "second")
            .and_event_data_contains("sequence", "2")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    for _ in 0..100 {
        if acks.lock().unwrap().len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    client.verify_mocks().await?;
    let acks = acks.lock().unwrap().clone();
    assert_eq!(
        acks.iter()
            .filter(|a| **a == (MessageType::Acknowledgement, 0x7001))
            .count(),
        2,
        "each copy of a Confirmable notification is acknowledged: {acks:?}"
    );
    assert!(
        acks.contains(&(MessageType::Reset, 0x7002)),
        "a notification for an unknown token is answered with RST: {acks:?}"
    );
    responder.abort();
    client.stop().await?;
    Ok(())
}

/// The exchange cap: requests to a server that never answers stay open, and the one past
/// `MAX_EXCHANGES` is refused.
#[tokio::test]
async fn requests_past_the_exchange_cap_are_refused() -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;

    let (_socket, addr) = fake_server().await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "coap".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create coap client: {e}"))?;
    for _ in 0..1_000 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut sent = 0;
    let mut refused = None;
    for i in 0..100 {
        match state
            .send_to_client(
                client_id,
                json!({"type": "coap_get", "path": format!("/r{i}")}),
                Duration::from_secs(10),
            )
            .await?
        {
            ClientSendOutcome::Sent { .. } => sent += 1,
            ClientSendOutcome::Rejected { error } => {
                refused = Some(error);
                break;
            }
            other => return Err(format!("unexpected outcome {other:?}").into()),
        }
    }
    assert_eq!(sent, 32, "MAX_EXCHANGES requests stay open unanswered");
    let refused = refused.ok_or("the request past the cap must be refused")?;
    assert!(refused.contains("already open"), "{refused}");
    Ok(())
}
