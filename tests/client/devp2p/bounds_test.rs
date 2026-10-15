//! The devp2p client against a hostile or broken peer: a listener built from NetGet's own wire
//! code that sends exactly what each test means — an RLP bomb for a Status, more headers than
//! were asked for, the wrong headers, a request nobody answers — and a model that is down or
//! will not stop asking. What these show is that the client refuses before the model sees the
//! bytes, fails closed with a Disconnect, and stops a follow-up chain at its bound.
use netget::cli::management::ClientForm;
use netget::server::devp2p::crypto::NodeKey;
use netget::server::devp2p::eth::{self, code, HeaderRequest, Hello, Status};
use netget::server::devp2p::rlp::Rlp;
use netget::server::devp2p::rlpx::{self, FrameReader, FrameWriter};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

/// One accepted connection on the hostile listener, past Hello.
struct Peer {
    reader: FrameReader,
    writer: FrameWriter,
    r: OwnedReadHalf,
    w: OwnedWriteHalf,
}

impl Peer {
    async fn send(&mut self, c: u64, payload: &[u8]) {
        let frame = self.writer.encode(c, payload).unwrap();
        self.w.write_all(&frame).await.unwrap();
    }

    /// The next message other than Ping/Pong; None when the connection ends or 20s pass.
    async fn recv(&mut self) -> Option<(u64, Vec<u8>)> {
        self.recv_within(Duration::from_secs(20)).await
    }

    /// `wait` covers the whole wait, Pings included.
    async fn recv_within(&mut self, wait: Duration) -> Option<(u64, Vec<u8>)> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let m = tokio::time::timeout_at(deadline, self.reader.read(&mut self.r))
                .await
                .ok()?
                .ok()?;
            match m.0 {
                code::PING => self.send(code::PONG, &eth::empty_payload()).await,
                code::PONG => {}
                _ => return Some(m),
            }
        }
    }

    async fn disconnect_reason(&mut self) -> Option<u64> {
        loop {
            let (c, payload) = self.recv().await?;
            if c == code::DISCONNECT {
                return Some(eth::decode_disconnect(&payload));
            }
        }
    }
}

/// Listen once, start a NetGet client against it, and return the accepted peer.
async fn connect(handlers: Option<Vec<Value>>, params: Value) -> (Peer, AppState, ClientId) {
    let key = NodeKey::random();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let enode = eth::format_enode(&key.id(), listener.local_addr().unwrap());
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = stream.into_split();
        let secrets = rlpx::respond(&mut r, &mut w, &key).await.unwrap();
        let (mut reader, mut writer) = rlpx::codec(secrets, 16 << 20);
        let hello = Hello::ours("hostile/1", 0, key.id()).encode();
        w.write_all(&writer.encode(code::HELLO, &hello).unwrap())
            .await
            .unwrap();
        let (c, _) = reader.read(&mut r).await.unwrap();
        assert_eq!(c, code::HELLO);
        reader.set_snappy(true);
        writer.set_snappy(true);
        Peer {
            reader,
            writer,
            r,
            w,
        }
    });
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "devp2p".into(),
        remote_addr: Some(enode),
        instruction: Some("Talk to the peer".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .unwrap();
    (accept.await.unwrap(), state, id)
}

fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": code}}),
    ])
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

async fn wait_events(state: &AppState, id: ClientId, kind: &str, n: usize) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let v = events(state, id, kind).await;
        if v.len() >= n || tokio::time::Instant::now() > deadline {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn status() -> Status {
    Status {
        version: 69,
        network_id: 1337,
        genesis: [3; 32],
        fork_hash: eth::fork_hash(&[3; 32], &[]),
        fork_next: 0,
        total_difficulty: Vec::new(),
        head: [0; 32],
        earliest_block: 0,
        latest_block: 0,
        latest_block_hash: [3; 32],
    }
}

const MIRROR: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[]
if t=='eth_status': a=[{'type':'eth_send_status','mirror_peer':True}]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn a_status_bomb_is_refused_before_the_model_sees_it() {
    let (mut peer, state, id) = connect(script(MIRROR), json!({})).await;
    let mut bomb = vec![0xc0];
    for _ in 0..50_000 {
        let len = bomb.len();
        let mut outer = if len <= 55 {
            vec![0xc0 + len as u8]
        } else {
            let be = (len as u64).to_be_bytes();
            let start = be.iter().position(|b| *b != 0).unwrap();
            let mut v = vec![0xf7 + (8 - start) as u8];
            v.extend_from_slice(&be[start..]);
            v
        };
        outer.extend_from_slice(&bomb);
        bomb = outer;
    }
    peer.send(eth::ETH_OFFSET + code::STATUS, &bomb).await;
    assert_eq!(peer.disconnect_reason().await, Some(0x02));
    assert!(events(&state, id, "eth_status").await.is_empty());
}

#[tokio::test]
async fn a_model_that_is_down_closes_the_session() {
    let (mut peer, state, id) = connect(None, json!({})).await;
    peer.send(eth::ETH_OFFSET + code::STATUS, &status().encode())
        .await;
    assert_eq!(peer.disconnect_reason().await, Some(0x10));
    // The client reports itself disconnected; the model was never answered, so nothing it
    // could have said reached the peer.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = state.get_client(id).await.map(|c| c.status);
        if matches!(status, Some(netget::state::ClientStatus::Disconnected)) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "still {status:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(events(&state, id, "eth_block_headers_received")
        .await
        .is_empty());
}

#[tokio::test]
async fn a_peer_request_left_unanswered_closes_the_session() {
    let (mut peer, _state, _id) = connect(script(MIRROR), json!({})).await;
    peer.send(eth::ETH_OFFSET + code::STATUS, &status().encode())
        .await;
    let (c, _) = peer.recv().await.expect("the client's Status");
    assert_eq!(c, eth::ETH_OFFSET + code::STATUS);
    let ask = HeaderRequest {
        origin: eth::Origin::Number(0),
        amount: 1,
        skip: 0,
        reverse: false,
    };
    peer.send(eth::ETH_OFFSET + code::GET_BLOCK_HEADERS, &ask.encode(5))
        .await;
    assert_eq!(peer.disconnect_reason().await, Some(0x10));
}

/// Read the client's GetBlockHeaders and answer with these headers.
async fn answer(peer: &mut Peer, headers: Vec<Rlp>) -> Option<HeaderRequest> {
    let (c, payload) = peer.recv_within(Duration::from_secs(3)).await?;
    if c != eth::ETH_OFFSET + code::GET_BLOCK_HEADERS {
        return None;
    }
    let (rid, req) = HeaderRequest::decode(&payload).unwrap();
    peer.send(
        eth::ETH_OFFSET + code::BLOCK_HEADERS,
        &eth::encode_response(rid, headers),
    )
    .await;
    Some(req)
}

#[tokio::test]
async fn a_model_that_never_stops_asking_is_stopped_at_the_follow_up_bound() {
    // Every answer prompts another request, forever.
    let greedy = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[]
if t=='eth_status': a=[{'type':'eth_send_status','mirror_peer':True},{'type':'eth_request_block_headers','origin':0}]
elif t=='eth_block_headers_received': a=[{'type':'eth_request_block_headers','origin':0}]
print(json.dumps({'actions':a}))"#;
    let (mut peer, _state, _id) = connect(script(greedy), json!({})).await;
    peer.send(eth::ETH_OFFSET + code::STATUS, &status().encode())
        .await;
    let (c, _) = peer.recv().await.unwrap();
    assert_eq!(c, eth::ETH_OFFSET + code::STATUS);
    let mut requests = 0;
    while answer(&mut peer, Vec::new()).await.is_some() {
        requests += 1;
        assert!(requests <= 20, "the chain is not bounded");
    }
    // The Status turn asks once; each answer is one turn deeper; the eighth is not asked about.
    assert_eq!(
        requests,
        netget::client::devp2p::MAX_FOLLOWUP_DEPTH,
        "requests in the chain"
    );
}

#[tokio::test]
async fn answers_are_checked_against_the_question() {
    let one_request = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[]
if t=='eth_status': a=[{'type':'eth_send_status','mirror_peer':True},{'type':'eth_request_block_headers','origin':5,'amount':2}]
print(json.dumps({'actions':a}))"#;
    let h = |n: u64| {
        let mut j = netget::server::devp2p::actions::example_header();
        j["number"] = json!(n);
        eth::header_from_json(&j).unwrap()
    };
    // The wrong blocks: reported, with matches_request false.
    let (mut peer, state, id) = connect(script(one_request), json!({})).await;
    peer.send(eth::ETH_OFFSET + code::STATUS, &status().encode())
        .await;
    peer.recv().await.unwrap();
    answer(&mut peer, vec![h(9)]).await.expect("the request");
    let got = wait_events(&state, id, "eth_block_headers_received", 1).await;
    assert_eq!(got[0]["matches_request"], false, "{got:?}");
    assert_eq!(got[0]["headers"][0]["number"], 9);

    // More headers than were asked for: a protocol breach, never shown to the model.
    let (mut peer, state, id) = connect(script(one_request), json!({})).await;
    peer.send(eth::ETH_OFFSET + code::STATUS, &status().encode())
        .await;
    peer.recv().await.unwrap();
    answer(&mut peer, vec![h(5), h(6), h(7)])
        .await
        .expect("the request");
    assert_eq!(peer.disconnect_reason().await, Some(0x02));
    assert!(events(&state, id, "eth_block_headers_received")
        .await
        .is_empty());
}
