//! The devp2p server's own paths: NetGet's client and server in one session, the refusals,
//! the bounds, the operator's injected actions, and the model's path through a mocked LLM.
//!
//! The hand-driven peer (`support::RawPeer`) is NetGet's wire code; it is here for what no
//! third-party node will send — a model that is down, a header that answers the wrong
//! question, an oversized frame, an RLP bomb — not as evidence of interoperability, which is
//! `real_client_test.rs`'s job.
use super::support::{self, RawPeer, SERVER_KEY};
use super::wire_test::chain;
use crate::helpers::{self, E2EResult, NetGetConfig};
use netget::cli::management::ClientForm;
use netget::server::devp2p::eth::{self, code, HeaderRequest, Hello, Origin, Status};
use netget::server::devp2p::rlp::Rlp;
use netget::server::devp2p::{rlp, session};
use netget::state::app_state::AppState;
use netget::state::AccessLogOwner;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// `chain(n)` keyed by decimal number, as the policy wants it.
fn chain_map(n: u64) -> Value {
    let mut m = serde_json::Map::new();
    for (i, h) in chain(n).into_iter().enumerate() {
        m.insert(i.to_string(), h);
    }
    Value::Object(m)
}

fn genesis_of(c: &Value) -> [u8; 32] {
    eth::parse_fixed(&c["0"]["hash"], "hash").unwrap()
}

/// Hello and our Status; returns the server's Status.
async fn admitted(node: &support::Node, genesis: [u8; 32]) -> (RawPeer, Status) {
    admitted_at(node.addr(), node.key.public(), genesis).await
}

async fn admitted_at(
    addr: std::net::SocketAddr,
    key: &secp256k1::PublicKey,
    genesis: [u8; 32],
) -> (RawPeer, Status) {
    let (mut p, hello) = RawPeer::hello_to(addr, key).await;
    assert!(
        hello.client_id.starts_with("NetGet/"),
        "{}",
        hello.client_id
    );
    p.send(
        eth::ETH_OFFSET + code::STATUS,
        &support::status69(genesis).encode(),
    )
    .await;
    let (c, payload) = p.recv().await.expect("the server's Status");
    assert_eq!(c, eth::ETH_OFFSET + code::STATUS, "{payload:?}");
    (p, Status::decode(&payload, 69).unwrap())
}

fn headers_of(payload: &[u8]) -> (u64, Vec<Rlp>) {
    eth::decode_response(payload, 1024, "BlockHeaders").unwrap()
}

#[tokio::test]
async fn netget_client_and_server_exchange_a_chain() -> E2EResult<()> {
    let c = chain_map(5);
    let node = support::start(SERVER_KEY, support::policy(&c), json!({})).await;
    // NetGet's server waits for the dialler's Status and NetGet's client waits briefly for the
    // listener's, so between two NetGet nodes the client speaks first: from configuration.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let policy = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='eth_status':
  a=[{'type':'eth_send_status','mirror_peer':e['peer_status'] is not None},{'type':'eth_request_block_headers','origin':0,'amount':5}]
print(json.dumps({'actions':a}))"#;
    let id = ClientForm {
        protocol: "devp2p".into(),
        remote_addr: Some(node.enode()),
        instruction: Some("Fetch the chain".into()),
        event_handlers: Some(vec![
            json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": policy}}),
        ]),
        startup_params: Some(json!({
            "network_id": 1337,
            "genesis_hash": c["0"]["hash"],
            "latest_block": 4,
            "latest_block_hash": c["4"]["hash"],
        })),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await?;
    let received = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let v: Vec<Value> = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .filter(|e| e["event_type"] == "eth_block_headers_received")
                .map(|e| e["request"].clone())
                .collect();
            if let Some(e) = v.into_iter().next() {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("no headers reached the client:\n{}", node.log_text()))?;
    assert_eq!(received["count"], 5, "{received}");
    assert_eq!(received["matches_request"], true);
    assert_eq!(received["linked"], true);
    for (i, h) in received["headers"].as_array().unwrap().iter().enumerate() {
        assert_eq!(h["hash"], c[i.to_string()]["hash"], "block {i}");
    }
    // The server's model saw the client's Status, built from the client's configuration.
    let status = node.wait_for_events("eth_status", 1).await;
    assert_eq!(status[0]["peer_status"]["genesis_hash"], c["0"]["hash"]);
    assert_eq!(status[0]["peer_status"]["latest_block"], 4);
    Ok(())
}

#[tokio::test]
async fn a_model_that_is_down_refuses_the_peer() {
    let node = support::start(SERVER_KEY, None, json!({})).await;
    let (mut p, _) = RawPeer::hello(&node).await;
    p.send(
        eth::ETH_OFFSET + code::STATUS,
        &support::status69([5; 32]).encode(),
    )
    .await;
    assert_eq!(
        p.disconnect_reason().await,
        Some(0x10),
        "{}",
        node.log_text()
    );
    assert!(
        node.wait_for_log("decision=fail_closed_llm_error").await,
        "{}",
        node.log_text()
    );
}

#[tokio::test]
async fn an_answer_without_a_status_is_a_refusal() {
    let silent = Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}}),
    ]);
    let node = support::start(SERVER_KEY, silent, json!({})).await;
    let (mut p, _) = RawPeer::hello(&node).await;
    p.send(
        eth::ETH_OFFSET + code::STATUS,
        &support::status69([5; 32]).encode(),
    )
    .await;
    assert_eq!(
        p.disconnect_reason().await,
        Some(0x10),
        "{}",
        node.log_text()
    );
    assert!(
        node.wait_for_log("decision=model_silent").await,
        "{}",
        node.log_text()
    );

    let refuse = Some(vec![
        json!({"event_pattern": "eth_status", "handler": {"type": "static",
        "actions": [{"type": "devp2p_disconnect", "reason": "too_many_peers"}]}}),
    ]);
    let node = support::start(SERVER_KEY, refuse, json!({})).await;
    let (mut p, _) = RawPeer::hello(&node).await;
    p.send(
        eth::ETH_OFFSET + code::STATUS,
        &support::status69([5; 32]).encode(),
    )
    .await;
    assert_eq!(
        p.disconnect_reason().await,
        Some(0x04),
        "{}",
        node.log_text()
    );
    assert!(
        node.wait_for_log("decision=model_reject").await,
        "{}",
        node.log_text()
    );
}

#[tokio::test]
async fn headers_that_do_not_answer_the_request_are_never_sent() {
    // The policy answers every header request with block 2, whatever was asked.
    let c = chain_map(3);
    let wrong = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
B2=json.loads({b2})
a=[]
if t=='eth_status': a=[{{'type':'eth_send_status','mirror_peer':True}}]
elif t=='eth_block_headers_requested': a=[{{'type':'eth_send_block_headers','headers':[B2]}}]
print(json.dumps({{'actions':a}}))"#,
        b2 = serde_json::to_string(&c["2"].to_string()).unwrap()
    );
    let handlers = Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": wrong}}),
    ]);
    let node = support::start(SERVER_KEY, handlers, json!({})).await;
    let (mut p, _) = admitted(&node, genesis_of(&c)).await;

    // Block 2 for a request starting at block 2 is sent, with the hash Rust computed…
    let ask = |origin| HeaderRequest {
        origin,
        amount: 1,
        skip: 0,
        reverse: false,
    };
    p.send(
        eth::ETH_OFFSET + code::GET_BLOCK_HEADERS,
        &ask(Origin::Number(2)).encode(7),
    )
    .await;
    let (cd, payload) = p.recv().await.unwrap();
    assert_eq!(cd, eth::ETH_OFFSET + code::BLOCK_HEADERS);
    let (rid, headers) = headers_of(&payload);
    assert_eq!(rid, 7);
    assert_eq!(eth::hex0x(&eth::header_hash(&headers[0])), c["2"]["hash"]);

    // …but block 2 for a request starting at block 0 is not: the request goes unanswered and
    // the session is closed instead of answered with something untrue.
    p.send(
        eth::ETH_OFFSET + code::GET_BLOCK_HEADERS,
        &ask(Origin::Number(0)).encode(8),
    )
    .await;
    loop {
        let (cd, payload) = p.recv().await.expect("a Disconnect");
        assert_ne!(
            cd,
            eth::ETH_OFFSET + code::BLOCK_HEADERS,
            "a wrong header was sent"
        );
        if cd == code::DISCONNECT {
            assert_eq!(eth::decode_disconnect(&payload), 0x10);
            break;
        }
    }
    let log = node.log_text();
    assert!(log.contains("decision=fail_closed_bad_action"), "{log}");
    assert!(log.contains("decision=fail_closed_unanswered"), "{log}");
}

#[tokio::test]
async fn the_peer_must_be_who_it_authenticated_as_and_speak_eth() {
    let node = support::start(SERVER_KEY, support::policy(&json!({})), json!({})).await;
    // A Hello naming another node than the one the handshake proved.
    let mut p = RawPeer::handshake(&node).await;
    let other = netget::server::devp2p::crypto::NodeKey::random();
    p.send(code::HELLO, &Hello::ours("liar", 0, other.id()).encode())
        .await;
    p.reader.set_snappy(false);
    let _hello = p.recv().await.expect("the server's Hello");
    p.reader.set_snappy(true);
    assert_eq!(p.disconnect_reason().await, Some(0x09));

    // A Hello without eth.
    let mut p = RawPeer::handshake(&node).await;
    let mut h = Hello::ours("snap-only", 0, p.key.id());
    h.caps = vec![("snap".into(), 1)];
    p.send(code::HELLO, &h.encode()).await;
    let _hello = p.recv().await.expect("the server's Hello");
    p.reader.set_snappy(true);
    assert_eq!(p.disconnect_reason().await, Some(0x03));
    assert!(node.events("eth_status").await.is_empty());
}

#[tokio::test]
async fn an_oversized_handshake_is_refused_unread() {
    let node = support::start(SERVER_KEY, support::policy(&json!({})), json!({})).await;
    let mut s = tokio::net::TcpStream::connect(node.addr()).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // A size prefix of 65535 and a few bytes: the server refuses on the prefix alone.
    s.write_all(&[0xff, 0xff, 1, 2, 3]).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf))
        .await
        .expect("the server kept a connection with an oversized handshake open")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert!(
        node.wait_for_log("decision=protocol_error").await,
        "{}",
        node.log_text()
    );
    assert!(
        node.wait_for_log("above the 2048-byte bound").await,
        "{}",
        node.log_text()
    );
}

#[tokio::test]
async fn oversized_and_malformed_messages_close_the_session_before_the_model() {
    let node = support::start(SERVER_KEY, support::policy(&json!({})), json!({})).await;

    // A frame whose declared size is past the bound: only its header is sent, and the refusal
    // comes without the body.
    let (mut p, _) = RawPeer::hello(&node).await;
    p.writer.set_snappy(false);
    let frame = p
        .writer
        .encode(eth::ETH_OFFSET, &vec![7u8; 6 << 20])
        .unwrap();
    p.send_raw(&frame[..32]).await;
    assert_eq!(
        p.disconnect_reason().await,
        Some(0x02),
        "{}",
        node.log_text()
    );
    assert!(
        node.wait_for_log("decision=fail_closed_message_too_large")
            .await
    );

    // A Snappy block that would decompress past the bound.
    let (mut p, _) = RawPeer::hello(&node).await;
    p.send(eth::ETH_OFFSET, &vec![0u8; session::MAX_MESSAGE_BYTES + 1])
        .await;
    assert_eq!(p.disconnect_reason().await, Some(0x02));

    // A Status that is an RLP nesting bomb.
    let (mut p, _) = RawPeer::hello(&node).await;
    let mut bomb = vec![0xc0];
    for _ in 0..50_000 {
        let mut outer = Vec::new();
        let len = bomb.len();
        if len <= 55 {
            outer.push(0xc0 + len as u8);
        } else {
            let be = (len as u64).to_be_bytes();
            let start = be.iter().position(|b| *b != 0).unwrap();
            outer.push(0xf7 + (8 - start) as u8);
            outer.extend_from_slice(&be[start..]);
        }
        outer.extend_from_slice(&bomb);
        bomb = outer;
    }
    assert!(rlp::decode(&bomb).is_err());
    p.send(eth::ETH_OFFSET + code::STATUS, &bomb).await;
    assert_eq!(p.disconnect_reason().await, Some(0x02));

    // A request before any Status.
    let (mut p, _) = RawPeer::hello(&node).await;
    let ask = HeaderRequest {
        origin: Origin::Number(0),
        amount: 1,
        skip: 0,
        reverse: false,
    };
    p.send(eth::ETH_OFFSET + code::GET_BLOCK_HEADERS, &ask.encode(1))
        .await;
    assert_eq!(p.disconnect_reason().await, Some(0x02));

    // None of them reached the model.
    assert!(
        node.events("eth_status").await.is_empty(),
        "{}",
        node.log_text()
    );
}

#[tokio::test]
async fn the_operator_can_ask_a_peer_and_hang_up() {
    let c = chain_map(1);
    let node = support::start(SERVER_KEY, support::policy(&c), json!({})).await;
    let (mut p, _) = admitted(&node, genesis_of(&c)).await;
    // Find the connection and inject a request through its peer handle.
    let conn = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = node.state.get_server(node.id).await {
                if let Some(c) = s.connections.keys().next() {
                    break c.as_u32();
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let outcome = node
        .state
        .send_to_peer(
            node.id,
            conn,
            json!({"type": "eth_request_block_headers", "origin": 0, "amount": 2}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        format!("{outcome:?}").contains("asked for 2 headers"),
        "{outcome:?}"
    );
    let (cd, payload) = p.recv().await.unwrap();
    assert_eq!(cd, eth::ETH_OFFSET + code::GET_BLOCK_HEADERS);
    let (_, req) = HeaderRequest::decode(&payload).unwrap();
    assert_eq!((req.origin, req.amount), (Origin::Number(0), 2));
    // A malformed injected action is refused without touching the session.
    let refused = node
        .state
        .send_to_peer(
            node.id,
            conn,
            json!({"type": "eth_request_block_headers"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(format!("{refused:?}").contains("Rejected"), "{refused:?}");
    // [ disconnect ] sends Disconnect `requested`.
    node.state
        .send_to_peer(
            node.id,
            conn,
            json!({"type": "close_connection"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(p.disconnect_reason().await, Some(0x00));
}

/// The model's own path: a mocked LLM opens the node, admits a peer and answers its header
/// request with fields it read from the event, for the NetGet binary.
#[tokio::test]
async fn a_mocked_model_admits_and_answers() -> E2EResult<()> {
    let c = chain_map(2);
    let block1 = c["1"].clone();
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via devp2p").with_mock(|mock| {
        mock.on_instruction_containing("via devp2p")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "devp2p",
                "startup_params": {"node_private_key": SERVER_KEY},
                "instruction": "Admit every peer by mirroring its Status; serve block 1"
            }]))
            .expect_calls(1)
            .and()
            .on_event("eth_status")
            .respond_with_actions(json!([{"type": "eth_send_status", "mirror_peer": true}]))
            .expect_calls(1)
            .and()
            .on_event("eth_block_headers_requested")
            .respond_with_actions_from_event(move |e| {
                json!([{"type": "eth_send_block_headers", "request_id": e["request_id"], "headers": [block1.clone()]}])
            })
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let key = netget::server::devp2p::crypto::NodeKey::from_hex(SERVER_KEY).unwrap();
    let (mut p, status) = admitted_at(
        ([127, 0, 0, 1], server.port).into(),
        key.public(),
        genesis_of(&c),
    )
    .await;
    assert_eq!(status.genesis, genesis_of(&c));
    let ask = HeaderRequest {
        origin: Origin::Number(1),
        amount: 1,
        skip: 0,
        reverse: false,
    };
    p.send(eth::ETH_OFFSET + code::GET_BLOCK_HEADERS, &ask.encode(42))
        .await;
    let (cd, payload) = p.recv().await.expect("BlockHeaders");
    assert_eq!(cd, eth::ETH_OFFSET + code::BLOCK_HEADERS);
    let (rid, headers) = headers_of(&payload);
    assert_eq!(rid, 42);
    assert_eq!(eth::hex0x(&eth::header_hash(&headers[0])), c["1"]["hash"]);
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
