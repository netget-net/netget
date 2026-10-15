//! The dashboard's `[ send ]` path on a STUN client: `AppState::send_to_client` injects
//! `send_binding_request` and a real binding exchange runs against a local responder.
//!
//! The outcome is deliberately `Executed`, not `Sent`. The exchange runs inside `stunclient`,
//! which binds and owns its own UDP socket and reports no byte count, so there is no truthful
//! number to hand back; the detail string carries the discovered external address instead —
//! the thing the caller actually wants to see, and proof the exchange completed.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its `stun_connected`
//! call fails and the loop has to tolerate that.
//!
//! The responder is written by hand rather than started as a NetGet STUN server: a binding
//! response must echo the request's random 96-bit transaction id, and NetGet's STUN server
//! takes `transaction_id` as an action parameter, which a static handler cannot supply.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features stun --test client -- stun::command_channel --test-threads=100

#![cfg(unix)]

use std::net::IpAddr;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MAGIC_COOKIE: u32 = 0x2112_A442;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// Regression guard for the "register the channel before the connect LLM call" rule.
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "STUN client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// Build an RFC 5389 Binding Success Response reporting `peer` as the mapped address.
fn binding_success(request: &[u8], peer: std::net::SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20 {
        return None;
    }
    let IpAddr::V4(ip) = peer.ip() else {
        return None;
    };
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let octets = ip.octets();

    // XOR-MAPPED-ADDRESS (0x0020): reserved, family, x-port, x-address.
    let mut attr = vec![0x00, 0x01];
    attr.extend_from_slice(&(peer.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    for i in 0..4 {
        attr.push(octets[i] ^ cookie[i]);
    }

    let mut msg = Vec::with_capacity(20 + 4 + attr.len());
    msg.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success Response
    msg.extend_from_slice(&0u16.to_be_bytes()); // length, patched below
    msg.extend_from_slice(&cookie);
    msg.extend_from_slice(&request[8..20]); // transaction id, echoed
    msg.extend_from_slice(&0x0020u16.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&attr);

    let body_len = (msg.len() - 20) as u16;
    msg[2..4].copy_from_slice(&body_len.to_be_bytes());
    Some(msg)
}

#[tokio::test]
async fn injected_binding_request_runs_a_real_exchange() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind stun server");
    let server_addr = server.local_addr().expect("stun server addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((n, peer)) = server.recv_from(&mut buf).await {
            if let Some(reply) = binding_success(&buf[..n], peer) {
                let _ = server.send_to(&reply, peer).await;
            }
        }
    });

    let client_id = ClientForm {
        protocol: "stun".to_string(),
        remote_addr: Some(server_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create stun client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_binding_request"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client send_binding_request");
    match outcome {
        ClientSendOutcome::Executed { ref detail } => {
            assert!(
                detail.contains("external address 127.0.0.1:"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // A verb this client does not have is Rejected, never silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_stun_verb"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and drops the handle.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle should be gone after an injected disconnect");
}
