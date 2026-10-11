//! RFC 9221 DATAGRAM frames on NetGet's raw QUIC server, against two independent
//! implementations: **aioquic** (Python) and **quic-go** (Go). Neither shares code with
//! Quinn. Each peer sends a text datagram and a binary one; a script handler answers the
//! first with `pong:` + text and the second with 0xff + the same bytes (the hex path), and
//! the peer reports what came back. No LLM calls; both peers fail rather than skip.
use crate::helpers::quic_peer::*;
use netget::state::AccessLogOwner;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const HANDLER: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
if e['encoding']=='utf8':
  a=[{'type':'send_quic_datagram','data':'pong:'+e['data']}]
else:
  a=[{'type':'send_quic_datagram','data':'ff'+e['data'],'encoding':'hex'}]
print(json.dumps({'actions':a}))"#;

async fn answers_datagrams(peer: DatagramPeer) {
    let state = state();
    let cert = Certificate::new();
    let (id, addr) = server(
        &state,
        "quic",
        &cert,
        json!({}),
        vec![
            json!({"event_pattern":"quic_datagram_received","handler":{"type":"script","language":"python","code":HANDLER}}),
            empty_handler(),
        ],
    )
    .await;
    let report = peer
        .client(addr.port(), &cert, &[b"ping", &[0x00, 0xff, 0x10]], 2)
        .await;
    let got: BTreeSet<String> = report["received"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let want: BTreeSet<String> = [hex::encode("pong:ping"), "ff00ff10".to_string()].into();
    assert_eq!(got, want, "{peer:?}: {report}");

    let events: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "quic_datagram_received")
        .map(|e| e["request"].clone())
        .collect();
    assert_eq!(events.len(), 2, "{events:?}");
    let binary = events
        .iter()
        .find(|e| e["encoding"] == "hex")
        .expect("the binary datagram reached the handler as hex");
    assert_eq!(binary["data"], "00ff10");
    assert_eq!(binary["bytes"], 3);
    assert!(
        binary["max_datagram_size"].as_u64().unwrap_or(0) >= 1000,
        "the peer negotiated datagrams, so the limit is known: {binary}"
    );
    state.remove_server(id).await;
}

#[tokio::test]
async fn aioquic_datagrams_are_answered_with_datagrams() {
    answers_datagrams(DatagramPeer::Aioquic).await;
}

#[tokio::test]
async fn quic_go_datagrams_are_answered_with_datagrams() {
    answers_datagrams(DatagramPeer::QuicGo).await;
}

#[test]
fn a_datagram_action_larger_than_a_packet_is_refused() {
    use netget::llm::actions::protocol_trait::Server;
    let protocol = netget::server::quic::actions::QuicProtocol::new();
    let too_big = "x".repeat(netget::server::quic::actions::MAX_DATAGRAM_BYTES + 1);
    let err = protocol
        .execute_action(json!({"type":"send_quic_datagram","data":too_big}))
        .unwrap_err();
    assert!(err.to_string().contains("send_quic_data"), "{err}");
    assert!(protocol
        .execute_action(json!({"type":"send_quic_datagram","data":"00ff","encoding":"hex"}))
        .is_ok());
}
