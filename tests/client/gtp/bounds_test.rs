//! The GTP client's bounds, driven over real UDP by a peer written in this file from
//! TS 29.274 — so it is not evidence of interoperability (`real_server_test.rs` and
//! `osmo_ggsn_test.rs` are), only of what the client refuses and when it stops:
//!
//! - an answer is matched by sequence **and** message type; a wrong type, a wrong sequence, a
//!   wrong version and a malformed datagram are each refused, and the request stays pending;
//! - an unanswered request is sent 1 + N3 times, byte-identical, then reported as gtp_timeout;
//! - a request the peer starts reaches the model, and gtp_respond answers it;
//! - a model that answers every response with another request is stopped at
//!   MAX_FOLLOWUP_DEPTH.
//!
//! No LLM calls: script handlers play the model.
use super::real_server_test::wait_event;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

async fn client(state: &AppState, peer: SocketAddr, script: &str, params: Value) -> ClientId {
    let (tx, _) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "gtp".into(),
        remote_addr: Some(peer.to_string()),
        instruction: Some("bounds".into()),
        startup_params: Some(params),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":script}})]),
        ..Default::default()
    }
    .create(state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .expect("connect")
}

async fn recv(sock: &UdpSocket, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 65_536];
    match tokio::time::timeout(within, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => Some((buf[..n].to_vec(), from)),
        _ => None,
    }
}

/// GTPv2 header without TEID: flags, type, length, 24-bit sequence, spare.
fn v2_no_teid(t: u8, seq: u32, ies: &[u8]) -> Vec<u8> {
    let mut b = vec![0x40, t];
    b.extend(((4 + ies.len()) as u16).to_be_bytes());
    b.extend(&seq.to_be_bytes()[1..]);
    b.push(0);
    b.extend(ies);
    b
}

fn v2_teid(t: u8, teid: u32, seq: u32, ies: &[u8]) -> Vec<u8> {
    let mut b = vec![0x48, t];
    b.extend(((8 + ies.len()) as u16).to_be_bytes());
    b.extend(teid.to_be_bytes());
    b.extend(&seq.to_be_bytes()[1..]);
    b.push(0);
    b.extend(ies);
    b
}

const RECOVERY_5: [u8; 5] = [3, 0, 1, 0, 5];
const CAUSE_ACCEPTED: [u8; 6] = [2, 0, 2, 0, 16, 0];

fn seq_of(b: &[u8]) -> u32 {
    u32::from_be_bytes([0, b[4], b[5], b[6]])
}

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .map(|e| e["request"].clone())
        .collect()
}

const ECHO_ONCE: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='gtp_client_ready':
  a=[{'type':'gtp_echo'}]
elif t=='gtp_peer_request':
  a=[{'type':'gtp_respond','sequence':e['sequence'],'cause':'request_accepted'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn answers_are_matched_and_unanswered_requests_stop_after_n3() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = client(
        &state,
        peer.local_addr().unwrap(),
        ECHO_ONCE,
        json!({"interface": "s5", "user_plane_port": 0, "t3_response_ms": 300, "n3_requests": 2}),
    )
    .await;

    let (first, from) = recv(&peer, Duration::from_secs(30))
        .await
        .expect("an echo request");
    assert_eq!(first[0] >> 5, 2, "GTPv2");
    assert_eq!(first[1], 1, "Echo Request");
    let seq = seq_of(&first);
    // None of these answers the echo: a Create Session Response with its sequence, an Echo
    // Response with the next one, a GTPv1 Echo Response with its sequence, and an Echo Response
    // whose header declares more than the datagram holds.
    let wrong_type = v2_teid(33, 0, seq, &CAUSE_ACCEPTED);
    let wrong_seq = v2_no_teid(2, (seq + 1) & 0xFF_FFFF, &RECOVERY_5);
    let mut wrong_version = vec![0x32, 2, 0, 6, 0, 0, 0, 0];
    wrong_version.extend(((seq & 0xFFFF) as u16).to_be_bytes());
    wrong_version.extend([0, 0, 14, 5]);
    let mut truncated = v2_no_teid(2, seq, &RECOVERY_5);
    truncated[3] = 40;
    for b in [&wrong_type, &wrong_seq, &wrong_version, &truncated] {
        peer.send_to(b, from).await.unwrap();
    }

    // 1 + N3 = 3 sends in all, each the same datagram, then nothing more.
    let mut copies = vec![first.clone()];
    while let Some((b, _)) = recv(&peer, Duration::from_secs(5)).await {
        copies.push(b);
        if copies.len() == 3 {
            break;
        }
    }
    assert_eq!(
        copies.len(),
        3,
        "expected the first send and two retransmissions"
    );
    assert!(
        copies.iter().all(|c| *c == first),
        "retransmissions must repeat the datagram"
    );
    let timeout = wait_event(&state, id, |e| e["event_type"] == "gtp_timeout").await;
    assert_eq!(timeout["request"], "echo_request", "{timeout}");
    assert_eq!(timeout["attempts"], 3, "{timeout}");
    assert!(
        recv(&peer, Duration::from_millis(900)).await.is_none(),
        "a fourth send after the timeout"
    );
    assert!(
        events(&state, id, "gtp_response").await.is_empty(),
        "an answer that did not match was taken for one"
    );

    // A request the peer starts reaches the model, and its gtp_respond goes back with the
    // request's sequence and a Cause.
    let delete_bearer = v2_teid(99, 0, 0x1234, &[73, 0, 1, 0, 5]);
    peer.send_to(&delete_bearer, from).await.unwrap();
    let (answer, _) = recv(&peer, Duration::from_secs(30))
        .await
        .expect("a Delete Bearer Response");
    assert_eq!(answer[1], 100, "Delete Bearer Response");
    assert_eq!(seq_of(&answer[4..]), 0x1234, "its sequence");
    assert_eq!(
        &answer[12..],
        &CAUSE_ACCEPTED,
        "a Cause IE, request accepted"
    );
    let asked = wait_event(&state, id, |e| e["event_type"] == "gtp_peer_request").await;
    assert_eq!(asked["message"], "Delete Bearer Request", "{asked}");
}

const ECHO_FOREVER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
print(json.dumps({'actions':[{'type':'gtp_echo'}] if t in ('gtp_client_ready','gtp_response') else []}))"#;

#[tokio::test]
async fn a_chain_of_model_turns_stops_at_the_followup_depth() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let _id = client(
        &state,
        peer.local_addr().unwrap(),
        ECHO_FOREVER,
        json!({"interface": "s5", "user_plane_port": 0}),
    )
    .await;
    let mut seen = 0u32;
    while let Some((b, from)) =
        recv(&peer, Duration::from_secs(if seen == 0 { 30 } else { 10 })).await
    {
        assert_eq!(b[1], 1, "only echoes are asked for");
        seen += 1;
        peer.send_to(&v2_no_teid(2, seq_of(&b), &RECOVERY_5), from)
            .await
            .unwrap();
        if seen == netget::client::gtp::MAX_FOLLOWUP_DEPTH {
            break;
        }
    }
    assert_eq!(
        seen,
        netget::client::gtp::MAX_FOLLOWUP_DEPTH,
        "the chain stopped early"
    );
    assert!(
        recv(&peer, Duration::from_millis(1500)).await.is_none(),
        "the chain went past MAX_FOLLOWUP_DEPTH"
    );
}
