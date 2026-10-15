//! The dashboard's `[ send ]` path on a DNS client: `AppState::send_to_client` injects
//! `send_dns_query` from outside the client's conversation task, and the query goes out over
//! the *same* hickory resolver the LLM path uses.
//!
//! The outcome is deliberately `Executed`, not `Sent`: hickory owns the wire encoding and the
//! socket and reports no byte count, so there is no truthful number to hand back. The detail
//! string carries the response code and answer count instead.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its `dns_connected`
//! call fails and the loop has to tolerate that.
//!
//! The responder is written by hand rather than started as a NetGet DNS server: a DNS reply
//! must echo the client's random transaction id, which a static handler cannot do (see
//! `tests/server/dns/CLAUDE.md`) and which a script handler would need `python3` for.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dns --test client -- dns::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

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
        "DNS client #{} never registered a command handle",
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

/// Build a NOERROR reply carrying one A record, echoing the query's id and question.
///
/// Built from scratch rather than by patching the query in place: hickory may put an OPT
/// record in the additional section, and appending an answer after it would leave the
/// sections out of order.
fn dns_a_reply(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // Walk the QNAME to find where the question ends. A question never uses compression.
    let mut i = 12usize;
    loop {
        let len = *query.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        i += len;
    }
    let question_end = i + 4; // QTYPE + QCLASS
    if query.len() < question_end {
        return None;
    }

    let mut reply = Vec::with_capacity(question_end + 16);
    reply.extend_from_slice(&query[0..2]); // transaction id, echoed
    reply.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, RCODE=NOERROR
    reply.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    reply.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
    reply.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    reply.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    reply.extend_from_slice(&query[12..question_end]); // the question, verbatim
    reply.extend_from_slice(&[0xC0, 0x0C]); // NAME -> offset 12
    reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
    reply.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL 300
    reply.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    reply.extend_from_slice(&[93, 184, 216, 34]); // RDATA
    Some(reply)
}

#[tokio::test]
async fn injected_dns_query_uses_the_live_resolver() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let resolver = UdpSocket::bind("127.0.0.1:0").await.expect("bind resolver");
    let resolver_addr = resolver.local_addr().expect("resolver addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = resolver.recv_from(&mut buf).await {
            if let Some(reply) = dns_a_reply(&buf[..n]) {
                let _ = resolver.send_to(&reply, peer).await;
            }
        }
    });

    let client_id = ClientForm {
        protocol: "dns".to_string(),
        remote_addr: Some(resolver_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dns client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_dns_query",
                "domain": "example.com",
                "query_type": "A"
            }),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client send_dns_query");
    match outcome {
        // Executed, not Sent: see the module comment. The detail proves the query really ran
        // against the resolver, which is what a byte count would otherwise have shown.
        ClientSendOutcome::Executed { ref detail } => {
            assert!(
                detail.contains("NOERROR") && detail.contains("1 answer(s)"),
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
            serde_json::json!({"type": "not_a_dns_verb"}),
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
