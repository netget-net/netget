//! The RADIUS client's reply checks and bounds, against servers that misbehave on purpose.
//!
//! FreeRADIUS signs every reply correctly, so a client that never checked would pass every
//! real-server test. Each check here is shown against a few lines of test code that gets
//! exactly one thing wrong — a forged Response Authenticator, a missing or wrong
//! Message-Authenticator, a reply from the wrong address, an oversize datagram, silence — built
//! with the shared codec. Every check was verified by removing it and watching its test fail.
//!
//! LLM calls: 3-4 per model-driven test; none in the in-flight cap test.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features radius --test client -- radius::transport_test --test-threads=100


use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::*;
use ::netget::client::radius::wire::hmac_md5;
use ::netget::server::radius::packet::{
    response_authenticator, CODE_ACCESS_ACCEPT, CODE_STATUS_SERVER,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

const SECRET: &[u8] = b"s3cret";

/// How the fake server answers.
#[derive(Clone, Copy)]
enum Reply {
    /// A correct Access-Accept with a correct Message-Authenticator.
    Good,
    /// Response Authenticator computed with the wrong secret.
    WrongAuthenticator,
    /// Correct Response Authenticator, no Message-Authenticator.
    NoMessageAuthenticator,
    /// Correct Response Authenticator, Message-Authenticator of zeros.
    WrongMessageAuthenticator,
    /// A correct reply, sent from a different socket.
    WrongSource,
    /// A correct reply padded past 4096 bytes.
    Oversize,
    /// Nothing at all.
    Silent,
}

/// Build an Access-Accept for `request` (its identifier and Request Authenticator).
fn accept(request: &[u8], reply: Reply) -> Vec<u8> {
    let id = request[1];
    let mut ra = [0u8; 16];
    ra.copy_from_slice(&request[4..20]);
    let mut attrs = vec![18u8, 7];
    attrs.extend_from_slice(b"hello");
    let with_ma = !matches!(reply, Reply::NoMessageAuthenticator);
    if with_ma {
        attrs.extend_from_slice(&[80, 18]);
        attrs.extend_from_slice(&[0u8; 16]);
    }
    let len = u16::try_from(20 + attrs.len()).unwrap();
    let mut pkt = vec![CODE_ACCESS_ACCEPT, id];
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(&ra);
    pkt.extend_from_slice(&attrs);
    if with_ma && !matches!(reply, Reply::WrongMessageAuthenticator) {
        // RFC 3579 §3.2: over the reply with the Request Authenticator in place.
        let mac = hmac_md5(SECRET, &pkt);
        let at = pkt.len() - 16;
        pkt[at..].copy_from_slice(&mac);
    }
    let secret: &[u8] = if matches!(reply, Reply::WrongAuthenticator) {
        b"not-the-secret"
    } else {
        SECRET
    };
    let auth = response_authenticator(CODE_ACCESS_ACCEPT, id, &pkt[20..], &ra, secret);
    pkt[4..20].copy_from_slice(&auth);
    if matches!(reply, Reply::Oversize) {
        pkt.resize(5000, 0); // padding past the Length field, and past the 4096 maximum
    }
    pkt
}

struct Fake {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

async fn fake(reply: Reply) -> Fake {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let task = {
        let received = received.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let request = buf[..n].to_vec();
                received.lock().unwrap().push(request.clone());
                match reply {
                    Reply::Silent => {}
                    Reply::WrongSource => {
                        let _ = other.send_to(&accept(&request, Reply::Good), peer).await;
                    }
                    r => {
                        let _ = socket.send_to(&accept(&request, r), peer).await;
                    }
                }
            }
        })
    };
    Fake {
        addr,
        received,
        task,
    }
}

fn nas<F>(addr: SocketAddr, marker: &str, rules: F) -> NetGetConfig
where
    F: FnOnce(MockLlmBuilder) -> MockLlmBuilder,
{
    let addr = addr.to_string();
    let marker = marker.to_string();
    NetGetConfig::new(format!("Be a NAS for {addr}. {marker}.")).with_mock(move |mock| {
        rules(
            mock.on_instruction_containing(&marker)
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "protocol": "RADIUS",
                    "remote_addr": addr,
                    "instruction": "Log alice in.",
                    "startup_params": {
                        "secret": "s3cret", "timeout_ms": 300, "retries": 1
                    }
                }]))
                .expect_calls(1)
                .and()
                .on_event("radius_connected")
                .respond_with_actions(json!([{
                    "type": "radius_access_request", "user_name": "alice", "password": "pw"
                }]))
                .expect_calls(1)
                .and(),
        )
    })
}

/// A reply that fails `kind`'s check is discarded and reported; the request goes on waiting
/// and, with no genuine reply coming, times out. The model is never shown an accept.
async fn refused_then_timeout(reply: Reply, kind: &str, marker: &str) -> E2EResult<()> {
    let server = fake(reply).await;
    let kind = kind.to_string();
    let config = nas(server.addr, marker, move |mock| {
        mock.on_event("radius_error")
            .and_event_data_contains("kind", &kind)
            .respond_with_actions(json!([]))
            .expect_at_least(1)
            .and()
            .on_event("radius_error")
            .and_event_data_contains("kind", "timeout")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("radius_access_accept")
            .respond_with_actions(json!([]))
            .expect_calls(0)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    server.task.abort();
    client.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_good_reply_is_accepted() -> E2EResult<()> {
    let server = fake(Reply::Good).await;
    let config = nas(server.addr, "RADIUS-GOOD-STARTUP", |mock| {
        mock.on_event("radius_access_accept")
            .and_event_data_contains("reply_message", "hello")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    server.task.abort();
    client.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_forged_response_authenticator_is_refused() -> E2EResult<()> {
    refused_then_timeout(
        Reply::WrongAuthenticator,
        "bad_authenticator",
        "RADIUS-FORGED-STARTUP",
    )
    .await
}

#[tokio::test]
async fn a_reply_without_a_message_authenticator_is_refused() -> E2EResult<()> {
    refused_then_timeout(
        Reply::NoMessageAuthenticator,
        "missing_message_authenticator",
        "RADIUS-NO-MA-STARTUP",
    )
    .await
}

#[tokio::test]
async fn a_wrong_message_authenticator_is_refused() -> E2EResult<()> {
    refused_then_timeout(
        Reply::WrongMessageAuthenticator,
        "bad_message_authenticator",
        "RADIUS-BAD-MA-STARTUP",
    )
    .await
}

/// A correct reply from an address the request did not go to, and a correct reply padded past
/// 4096 bytes, are dropped before they are read: the request only times out.
#[tokio::test]
async fn replies_from_elsewhere_or_oversize_are_dropped() -> E2EResult<()> {
    for (reply, marker) in [
        (Reply::WrongSource, "RADIUS-SOURCE-STARTUP"),
        (Reply::Oversize, "RADIUS-OVERSIZE-STARTUP"),
    ] {
        let server = fake(reply).await;
        let config = nas(server.addr, marker, |mock| {
            mock.on_event("radius_error")
                .and_event_data_contains("kind", "timeout")
                .respond_with_actions(json!([]))
                .expect_calls(1)
                .and()
                .on_event("radius_access_accept")
                .respond_with_actions(json!([]))
                .expect_calls(0)
                .and()
        });
        let client = start_netget_client(config).await?;
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        server.task.abort();
        client.stop().await?;
    }
    Ok(())
}

/// An unanswered request is sent 1 + `retries` times, byte for byte the same (RFC 2865 §2.5),
/// then reported as a timeout.
#[tokio::test]
async fn an_unanswered_request_is_retransmitted_identically_a_bounded_number_of_times(
) -> E2EResult<()> {
    let server = fake(Reply::Silent).await;
    let config = nas(server.addr, "RADIUS-SILENT-STARTUP", |mock| {
        mock.on_event("radius_error")
            .and_event_data_contains("kind", "timeout")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    let received = server.received.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "one send and one retransmission");
    assert_eq!(
        received[0], received[1],
        "a retransmission is the identical packet"
    );
    server.task.abort();
    client.stop().await?;
    Ok(())
}

/// Requests to a server that never answers stay pending; the one past `MAX_IN_FLIGHT` is
/// refused. Status-Server carries no password, so nothing sensitive is spent on this.
#[tokio::test]
async fn requests_past_the_in_flight_cap_are_refused() -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;

    let server = fake(Reply::Silent).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "radius".to_string(),
        remote_addr: Some(server.addr.to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(json!({"secret": "s3cret"})),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create radius client: {e}"))?;
    for _ in 0..1_000 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut sent = 0;
    let mut refused = None;
    for _ in 0..100 {
        match state
            .send_to_client(
                client_id,
                json!({"type": "radius_status_server"}),
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
    assert_eq!(sent, 32, "MAX_IN_FLIGHT requests stay pending");
    assert!(refused
        .ok_or("the request past the cap must be refused")?
        .contains("already waiting"));
    let first = server.received.lock().unwrap()[0].clone();
    assert_eq!(first[0], CODE_STATUS_SERVER);
    server.task.abort();
    Ok(())
}
