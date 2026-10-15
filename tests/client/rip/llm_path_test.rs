//! The RIP client's LLM path, end to end, against a mocked model and a stub router.
//!
//! This is the only coverage of `connect_with_llm_actions`'s LLM path that runs. The suite's
//! other end-to-end test needed a live Ollama and was `#[ignore]`d, so nothing exercised
//! `rip_connected` -> `send_rip_request` -> `rip_response_received` -> follow-up at all — which
//! is how two `MutexGuard`-in-a-`match`-scrutinee holds survived in that exact stretch of code.
//!
//! The chain asserted here is the point: the request the model asks for on connect really
//! leaves the socket, the router's reply really becomes a `rip_response_received` event, and
//! the model's answer to *that* is really carried out. A client that asked and discarded would
//! stall after the first step with every mock rule still green except the last.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rip --test client -- rip::llm_path --test-threads=100


use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{ClientId, ClientStatus};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

/// A stand-in RIP router. Answers any Request with a two-route RIPv2 Response and records how
/// many Requests it saw.
async fn spawn_stub_router() -> (u16, Arc<AsyncMutex<usize>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind router");
    let port = socket.local_addr().unwrap().port();
    let requests = Arc::new(AsyncMutex::new(0usize));
    let seen = requests.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            // Command 1 = Request. Anything else is not ours to answer.
            if n < 4 || buf[0] != 1 {
                continue;
            }
            *seen.lock().await += 1;

            let mut response = vec![2, 2, 0, 0]; // Response, RIPv2, must-be-zero
            for (net, mask, hop, metric) in [
                (
                    Ipv4Addr::new(10, 0, 0, 0),
                    Ipv4Addr::new(255, 0, 0, 0),
                    Ipv4Addr::new(192, 168, 1, 254),
                    2u32,
                ),
                (
                    Ipv4Addr::new(172, 16, 0, 0),
                    Ipv4Addr::new(255, 255, 0, 0),
                    Ipv4Addr::new(192, 168, 1, 253),
                    5u32,
                ),
            ] {
                response.extend_from_slice(&[0, 2]); // AFI = IPv4
                response.extend_from_slice(&[0, 0]); // route tag
                response.extend_from_slice(&net.octets());
                response.extend_from_slice(&mask.octets());
                response.extend_from_slice(&hop.octets());
                response.extend_from_slice(&metric.to_be_bytes());
            }

            let _ = socket.send_to(&response, peer).await;
        }
    });

    (port, requests)
}

async fn wait_for_requests(seen: &Arc<AsyncMutex<usize>>, want: usize, secs: u64) -> usize {
    for _ in 0..(secs * 40) {
        let n = *seen.lock().await;
        if n >= want {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    *seen.lock().await
}

#[tokio::test]
async fn the_model_drives_request_response_and_the_follow_up_is_carried_out() {
    let (router_port, seen) = spawn_stub_router().await;

    // One rule per event. `rip_connected` fires once, on connect; `rip_response_received`
    // fires for the router's reply, and its answer — `disconnect` — is only reachable if the
    // client executed what the model said rather than counting it and moving on.
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("rip_connected")
            .respond_with_actions(serde_json::json!([
                { "type": "send_rip_request", "version": 2 }
            ]))
            .expect_calls(1)
            .and()
            .on_event("rip_response_received")
            .respond_with_actions(serde_json::json!([{ "type": "disconnect" }]))
            .expect_at_least(1)
            .and()
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id: ClientId = ClientForm {
        protocol: "RIP".to_string(),
        remote_addr: Some(format!("127.0.0.1:{router_port}")),
        instruction: Some("Query the router's routing table with RIPv2.".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await
    .expect("create rip client");

    // Step one: the connect-event answer reached the wire.
    assert!(
        wait_for_requests(&seen, 1, 20).await >= 1,
        "the model's send_rip_request was never sent to the router"
    );

    // Step two: the router's Response became an event and the model's answer to it ran. The
    // client disconnects only if `rip_response_received` was raised AND its actions executed.
    let mut ended = false;
    for _ in 0..800 {
        if matches!(
            state.get_client(client_id).await.map(|c| c.status),
            Some(ClientStatus::Disconnected)
        ) {
            ended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        ended,
        "client never disconnected: the rip_response_received answer was not carried out \
         (status={:?})",
        state.get_client(client_id).await.map(|c| c.status)
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.expect("mock expectations");
}

/// A version the wire cannot carry is refused, not silently downgraded to RIPv2 and reported
/// as sent. `RipMessage::encode` has no representation for a third version, so accepting one
/// would put a v2 datagram on the wire under a v7 label in the log.
#[tokio::test]
async fn an_unsupported_rip_version_is_refused() {
    use netget::client::rip::actions::RipClientProtocol;
    use netget::llm::actions::client_trait::Client;

    let protocol = RipClientProtocol::new();

    for good in [1u64, 2] {
        assert!(
            protocol
                .execute_action(serde_json::json!({"type": "send_rip_request", "version": good}))
                .is_ok(),
            "version {good} is a real RIP version and must be accepted"
        );
    }

    for bad in [0u64, 3, 7, 256, u32::MAX as u64 + 1] {
        let err = protocol
            .execute_action(serde_json::json!({"type": "send_rip_request", "version": bad}))
            .expect_err(&format!("version {bad} should be refused"));
        assert!(
            err.to_string().contains("version"),
            "the refusal should name the field: {err}"
        );
    }
}
