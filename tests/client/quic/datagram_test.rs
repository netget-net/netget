//! NetGet's raw QUIC client sending and receiving RFC 9221 DATAGRAM frames, against two
//! independent echo servers: **aioquic** (Python) and **quic-go** (Go). The handler sends
//! `hello` when connected; the peer echoes `echo:hello`; the handler answers that with the
//! two bytes 00 ff (the hex path), which the peer reports receiving. No LLM calls; both
//! peers fail rather than skip.
use crate::helpers::quic_peer::*;
use netget::state::AccessLogOwner;
use serde_json::{json, Value};
use std::time::Duration;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='quic_connected':
  a=[{'type':'send_quic_datagram','data':'hello'}]
elif t=='quic_datagram_received' and e['data']=='echo:hello':
  a=[{'type':'send_quic_datagram','data':'00ff','encoding':'hex'}]
print(json.dumps({'actions':a}))"#;

async fn exchanges_datagrams(peer: DatagramPeer) {
    let mut server = peer.server().await;
    let state = state();
    let id = client(
        &state,
        "quic",
        format!("127.0.0.1:{}", server.port),
        server.cert.trust(),
        vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}})],
    )
    .await;

    // What the independent server decoded, in order: NetGet's first datagram, then its
    // answer to the echo.
    assert_eq!(server.next_datagram().await, b"hello", "{peer:?}");
    assert_eq!(server.next_datagram().await, vec![0x00, 0xff], "{peer:?}");

    let events = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut rows: Vec<Value> = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .collect();
            rows.sort_by_key(|e| e["id"].as_u64());
            let rows: Vec<(String, Value)> = rows
                .into_iter()
                .map(|e| {
                    (
                        e["event_type"].as_str().unwrap_or("").to_string(),
                        e["request"].clone(),
                    )
                })
                .collect();
            if rows
                .iter()
                .filter(|(k, _)| k == "quic_datagram_received")
                .count()
                >= 2
            {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both echoes reach the handler");
    let connected = events
        .iter()
        .find(|(k, _)| k == "quic_connected")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(
        connected["max_datagram_size"].as_u64().unwrap_or(0) >= 1000,
        "{peer:?} negotiated datagrams: {connected}"
    );
    let echoes: Vec<&Value> = events
        .iter()
        .filter(|(k, _)| k == "quic_datagram_received")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(echoes[0]["data"], "echo:hello", "{peer:?}");
    assert_eq!(echoes[1]["data"], hex::encode(b"echo:\x00\xff"), "{peer:?}");
    assert_eq!(echoes[1]["encoding"], "hex", "{peer:?}");
    state.remove_client(id).await;
}

#[tokio::test]
async fn aioquic_echoes_netget_datagrams() {
    exchanges_datagrams(DatagramPeer::Aioquic).await;
}

#[tokio::test]
async fn quic_go_echoes_netget_datagrams() {
    exchanges_datagrams(DatagramPeer::QuicGo).await;
}
