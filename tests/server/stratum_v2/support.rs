//! Shared by the Stratum V2 pool tests: starting a pool with a policy, reading what the model
//! was asked, and a raw device that speaks Noise frames by hand.
use netget::cli::management::ServerForm;
use netget::server::stratum_v2::{noise, wire};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// SRI's example authority pair, so SRI's tools can pin the key without NetGet printing it.
pub const SECRET: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
pub const PUBLIC: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

/// The model, as a python policy: devices with vendor "blocked" and users not starting with
/// netget are refused; channels open at `DIFF` on a job whose coinbase and prev hash the
/// model chose; odd-numbered shares are credited and even ones refused.
pub fn policy(difficulty: f64) -> Option<Vec<Value>> {
    let code = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='stratum_v2_setup_connection':
  a=[{{'type':'stratum_v2_accept'}}] if e['vendor']!='blocked' else [{{'type':'stratum_v2_reject','error_code':'device-blocked'}}]
elif t=='stratum_v2_open_channel':
  a=[{{'type':'stratum_v2_accept'}},{{'type':'stratum_v2_set_target','difficulty':{difficulty}}},{{'type':'stratum_v2_new_job','message':'model job','prev_hash':'00000000000000000000000000000000000000000000000000000000deadbeef'}}] if e['user_identity'].startswith('netget') else [{{'type':'stratum_v2_reject','error_code':'unknown-user'}}]
else:
  a=[{{'type':'stratum_v2_accept'}}] if e['sequence_number']%2==1 else [{{'type':'stratum_v2_reject','error_code':'policy-rejected'}}]
print(json.dumps({{'actions':a}}))"#
    );
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "stratum_v2".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Run a small mining pool".into()),
        startup_params: Some(params),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port)
}

/// Start a server with `params` (a `role` among them) and keep everything it prints to the
/// operator, which is where a template provider's solved blocks and connection summaries go.
pub async fn start_role(
    handlers: Option<Vec<Value>>,
    params: Value,
) -> (AppState, ServerId, u16, super::peers::Status) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let status = super::peers::Status::default();
    let sink = status.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.0.lock().unwrap().push(line);
        }
    });
    let id = ServerForm {
        protocol: "stratum_v2".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Serve Stratum V2".into()),
        startup_params: Some(params),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port, status)
}

/// A python script as the model: `body` sets `a` from `t` (the event id) and `e` (its data).
pub fn script(body: &str) -> Option<Vec<Value>> {
    let code = format!(
        "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\n{body}\nprint(json.dumps({{'actions':a}}))"
    );
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

/// What the model was asked, of one kind, in order.
pub async fn events(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .map(|e| e["request"].clone())
        .collect()
}

/// Every model call so far, of any kind.
pub async fn model_calls(state: &AppState, id: ServerId) -> usize {
    let mut n = 0;
    for kind in [
        "stratum_v2_setup_connection",
        "stratum_v2_open_channel",
        "stratum_v2_share",
    ] {
        n += events(state, id, kind).await.len();
    }
    n
}

/// A device written by hand from NetGet's own codec, for the refusals no real device sends.
pub struct Raw {
    pub reader: wire::FrameReader<ReadHalf<TcpStream>>,
    pub writer: WriteHalf<TcpStream>,
    pub send: noise::CipherState,
}

impl Raw {
    pub async fn connect(port: u16) -> Raw {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let authority = noise::decode_authority_key(PUBLIC).unwrap();
        let (session, _) =
            wire::connect_handshake(&mut stream, &authority, Duration::from_secs(10))
                .await
                .expect("handshake");
        let (r, w) = tokio::io::split(stream);
        Raw {
            reader: wire::FrameReader::new(r, session.recv, 1 << 20),
            writer: w,
            send: session.send,
        }
    }

    pub async fn frame(&mut self, frame: &wire::Frame) {
        let bytes = wire::seal(&mut self.send, frame).unwrap();
        self.raw(&bytes).await;
    }

    pub async fn send(&mut self, m: &wire::Message) {
        self.frame(&m.encode()).await;
    }

    pub async fn raw(&mut self, bytes: &[u8]) {
        // The pool may already have hung up; what it did is what the caller checks.
        let _ = self.writer.write_all(bytes).await;
    }

    /// The next message, or None once the pool has closed the connection.
    pub async fn recv(&mut self) -> Option<wire::Message> {
        match tokio::time::timeout(
            Duration::from_secs(20),
            self.reader.next(Duration::from_secs(120)),
        )
        .await
        .expect("the pool neither answered nor hung up")
        {
            Ok(Some(f)) => Some(wire::Message::decode(&f).expect("a frame the pool sent")),
            Ok(None) | Err(_) => None,
        }
    }

    pub async fn setup(&mut self, vendor: &str, flags: u32) -> wire::Message {
        self.send(&setup_message(vendor, flags)).await;
        self.recv().await.expect("an answer to SetupConnection")
    }

    /// Open a standard channel: the success, the future job and the prev hash.
    pub async fn open_standard(
        &mut self,
        user: &str,
    ) -> (wire::Message, wire::Message, wire::Message) {
        self.send(&wire::Message::OpenStandardMiningChannel {
            request_id: 7,
            user_identity: user.as_bytes().to_vec(),
            nominal_hash_rate: 1000.0,
            max_target: [0xff; 32],
        })
        .await;
        let a = self.recv().await.expect("an answer to the channel");
        let b = self.recv().await.expect("a job");
        let c = self.recv().await.expect("a prev hash");
        (a, b, c)
    }
}

pub fn setup_message(vendor: &str, flags: u32) -> wire::Message {
    wire::Message::SetupConnection {
        protocol: 0,
        min_version: 2,
        max_version: 2,
        flags,
        endpoint_host: b"127.0.0.1".to_vec(),
        endpoint_port: 3333,
        vendor: vendor.as_bytes().to_vec(),
        hardware_version: b"raw".to_vec(),
        firmware: b"test".to_vec(),
        device_id: b"raw-1".to_vec(),
    }
}

/// Mine a header for (version, prev, root, ntime, nbits) until it meets `target`.
pub fn find_nonce(
    version: u32,
    prev: &[u8; 32],
    root: &[u8; 32],
    ntime: u32,
    nbits: u32,
    target: &[u8; 32],
    meet: bool,
) -> (u32, [u8; 32]) {
    for nonce in 0..u32::MAX {
        let hash = wire::sha256d(&wire::header(version, prev, root, ntime, nbits, nonce));
        if wire::meets(&hash, target) == meet {
            return (nonce, hash);
        }
    }
    unreachable!("no nonce found")
}
