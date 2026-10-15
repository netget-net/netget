//! Shared harness for the devp2p server suites: an in-process NetGet devp2p node with a python
//! policy standing in for the model, and a minimal hand-driven peer built from NetGet's own
//! wire code for the paths no third-party implementation will take (malformed frames, refusals,
//! a model that is down).
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::server::devp2p::crypto::NodeKey;
use netget::server::devp2p::eth::{self, code, Hello, Status};
use netget::server::devp2p::rlpx::{self, FrameReader, FrameWriter};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

/// The node key every in-process NetGet server here uses, so its enode is known up front.
pub const SERVER_KEY: &str = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
pub const CLIENT_ID: &str = "NetGet/devp2p-test";

/// The model, as a python script: admit every peer by mirroring its Status, and answer header
/// requests from `HEADERS` (block number → header JSON, as eth_getBlockByNumber returns it).
/// Bodies and pooled transactions are answered with nothing held.
pub fn policy(headers: &Value) -> Option<Vec<Value>> {
    let code = format!(
        r#"import json,sys
HEADERS=json.loads({headers})
BY_HASH=dict((h['hash'],h) for h in HEADERS.values() if 'hash' in h)
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='eth_status':
  a=[{{'type':'eth_send_status','mirror_peer':True}}]
elif t=='eth_block_headers_requested':
  o=e['origin']; out=[]
  first=BY_HASH.get(o) if isinstance(o,str) else HEADERS.get(str(o))
  if first is not None:
    n=int(first['number'],16) if isinstance(first['number'],str) else first['number']
    for k in range(e['amount']):
      h=HEADERS.get(str(n))
      if h is None: break
      out.append(h)
      n=n-(e['skip']+1) if e['reverse'] else n+(e['skip']+1)
      if n<0: break
  a=[{{'type':'eth_send_block_headers','headers':out}}]
elif t=='eth_block_bodies_requested':
  a=[{{'type':'eth_send_block_bodies','bodies':[]}}]
elif t=='eth_pooled_transactions_requested':
  a=[{{'type':'eth_send_pooled_transactions','transactions':[]}}]
print(json.dumps({{'actions':a}}))"#,
        headers = serde_json::to_string(&headers.to_string()).unwrap()
    );
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

/// A running in-process devp2p server and everything it printed.
pub struct Node {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub key: NodeKey,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Node {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    pub fn enode(&self) -> String {
        eth::format_enode(&self.key.id(), ([127, 0, 0, 1], self.port).into())
    }

    pub fn node_id(&self) -> String {
        hex::encode(self.key.id())
    }

    /// Wait until the server's status stream contains `needle`.
    pub async fn wait_for_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !self.log_text().contains(needle) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Every event of `kind` the server raised, oldest first: what the model was shown.
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        let mut v: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == kind)
            .collect();
        v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
        v.into_iter().map(|e| e["request"].clone()).collect()
    }

    pub async fn wait_for_events(&self, kind: &str, n: usize) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let v = self.events(kind).await;
            if v.len() >= n || tokio::time::Instant::now() > deadline {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }
}

/// Start a server with this key. `handlers` is the routing table (the python policy, a static
/// rule, or `None` to send every event to a model that is not there).
pub async fn start(key_hex: &str, handlers: Option<Vec<Value>>, extra: Value) -> Node {
    start_with_llm(key_hex, handlers, extra, "http://127.0.0.1:1").await
}

pub async fn start_with_llm(
    key_hex: &str,
    handlers: Option<Vec<Value>>,
    extra: Value,
    llm: &str,
) -> Node {
    let state = AppState::new_with_options(false, llm.into());
    state
        .set_llm_client(netget::llm::OllamaClient::new(llm))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    let mut params = json!({"node_private_key": key_hex, "client_id": CLIENT_ID});
    if let Some(o) = extra.as_object() {
        for (k, v) in o {
            params[k] = v.clone();
        }
    }
    let id = ServerForm {
        protocol: "devp2p".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an Ethereum node".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the devp2p server never reported its address");
    Node {
        state,
        id,
        port,
        key: NodeKey::from_hex(key_hex).unwrap(),
        log,
    }
}

/// A hand-driven peer: NetGet's own RLPx code dialling a server, so a test can send exactly
/// the bytes it means to — including the ones no real client would.
pub struct RawPeer {
    pub key: NodeKey,
    pub reader: FrameReader,
    pub writer: FrameWriter,
    pub r: OwnedReadHalf,
    pub w: OwnedWriteHalf,
}

impl RawPeer {
    /// TCP and the RLPx handshake only.
    pub async fn handshake(node: &Node) -> RawPeer {
        RawPeer::handshake_to(node.addr(), node.key.public()).await
    }

    pub async fn handshake_to(
        addr: std::net::SocketAddr,
        remote: &secp256k1::PublicKey,
    ) -> RawPeer {
        let key = NodeKey::random();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut r, mut w) = stream.into_split();
        let secrets = rlpx::initiate(&mut r, &mut w, &key, remote).await.unwrap();
        let (reader, writer) = rlpx::codec(secrets, 16 << 20);
        RawPeer {
            key,
            reader,
            writer,
            r,
            w,
        }
    }

    /// Handshake and Hello both ways; returns the server's Hello.
    pub async fn hello(node: &Node) -> (RawPeer, Hello) {
        RawPeer::hello_to(node.addr(), node.key.public()).await
    }

    pub async fn hello_to(
        addr: std::net::SocketAddr,
        remote: &secp256k1::PublicKey,
    ) -> (RawPeer, Hello) {
        let mut p = RawPeer::handshake_to(addr, remote).await;
        p.send(
            code::HELLO,
            &Hello::ours("raw-peer", 0, p.key.id()).encode(),
        )
        .await;
        let (c, payload) = p.recv().await.expect("the server's Hello");
        assert_eq!(c, code::HELLO);
        let hello = Hello::decode(&payload).unwrap();
        p.reader.set_snappy(true);
        p.writer.set_snappy(true);
        (p, hello)
    }

    pub async fn send(&mut self, c: u64, payload: &[u8]) {
        let frame = self.writer.encode(c, payload).unwrap();
        self.w.write_all(&frame).await.unwrap();
    }

    /// Write raw bytes, frame or not.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        let _ = self.w.write_all(bytes).await;
    }

    /// The next message, skipping Ping/Pong; None when the connection ends or 20s pass. The
    /// deadline covers the whole wait: a server that keeps pinging must not keep it open.
    pub async fn recv(&mut self) -> Option<(u64, Vec<u8>)> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let m = tokio::time::timeout_at(deadline, self.reader.read(&mut self.r))
                .await
                .ok()?
                .ok()?;
            if m.0 == code::PING {
                self.send(code::PONG, &eth::empty_payload()).await;
                continue;
            }
            if m.0 == code::PONG {
                continue;
            }
            return Some(m);
        }
    }

    /// Wait for a Disconnect; its reason, or None if the connection ended without one.
    pub async fn disconnect_reason(&mut self) -> Option<u64> {
        loop {
            let (c, payload) = self.recv().await?;
            if c == code::DISCONNECT {
                return Some(eth::decode_disconnect(&payload));
            }
        }
    }
}

/// An eth/69 Status for the test chain.
pub fn status69(genesis: [u8; 32]) -> Status {
    Status {
        version: 69,
        network_id: 1337,
        genesis,
        fork_hash: eth::fork_hash(&genesis, &[]),
        fork_next: 0,
        total_difficulty: Vec::new(),
        head: [0; 32],
        earliest_block: 0,
        latest_block: 0,
        latest_block_hash: genesis,
    }
}
