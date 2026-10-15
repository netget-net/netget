//! Shared harness for the OpenFlow controller suites: an in-process controller with a python
//! policy standing in for the model, and a raw OpenFlow 1.3 switch written against the wire
//! format in `src/server/openflow/wire.rs`, which records every byte both ways so the pcap
//! oracle can read them.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::server::openflow::wire::{self, msg, Message, VERSION_1_3};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

pub const DPID: u64 = 0x0000_0000_0000_0abc;
pub const HOST_A: &str = "02:00:00:00:00:01";
pub const HOST_B: &str = "02:00:00:00:00:02";
/// A destination the policy drops.
pub const BLOCKED: &str = "02:00:00:00:00:66";

/// The model, as a python script: a table-miss flow on connect; a packet for HOST_B gets a
/// flow to port 2 and is sent there; a packet for BLOCKED is dropped; anything else is
/// flooded. Errors and statistics are acknowledged with nothing.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='openflow_switch_connected':
  a=[{'type':'openflow_flow_mod','priority':0,'match':{},'actions':[{'type':'output','port':'controller'}]}]
elif t=='openflow_packet_in':
  p=e['packet']
  if p.get('eth_dst')=='02:00:00:00:00:02':
    a=[{'type':'openflow_flow_mod','priority':10,'idle_timeout':30,'match':{'in_port':e['in_port'],'eth_dst':p['eth_dst']},'actions':[{'type':'output','port':2}]},
       {'type':'openflow_packet_out','actions':[{'type':'output','port':2}]}]
  elif p.get('eth_dst')=='02:00:00:00:00:66':
    a=[{'type':'openflow_drop_packet','reason':'blocked'}]
  else:
    a=[{'type':'openflow_packet_out','actions':[{'type':'output','port':'flood'}]}]
print(json.dumps({'actions':a}))"#;

/// The same policy, asking for flow statistics as soon as the table-miss flow is sent.
pub const STATS_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[]
if t=='openflow_switch_connected':
  a=[{'type':'openflow_flow_mod','priority':0,'match':{},'actions':[{'type':'output','port':'controller'}]},
     {'type':'openflow_request_stats','kind':'flow'}]
print(json.dumps({'actions':a}))"#;

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

pub fn policy() -> Option<Vec<Value>> {
    script(POLICY)
}

pub fn static_rule(actions: Value) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": actions}}),
    ])
}

/// A running in-process controller and everything it printed.
pub struct Controller {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Controller {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
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

    /// Every event of `kind` the server raised, oldest first, as the model saw it.
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

    /// Wait until at least `n` events of `kind` were raised; returns them.
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

    /// The live connection ids, for `send_to_peer`.
    pub async fn connections(&self) -> Vec<u32> {
        self.state
            .get_server(self.id)
            .await
            .map(|s| {
                s.connections
                    .values()
                    .map(|c| c.id.as_u32())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }
}

/// Start a controller. `handlers` is the routing table (a python policy, a static rule, or
/// `None` to send every event to a model that is not there).
pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> Controller {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    let id = ServerForm {
        protocol: "openflow".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an SDN controller".into()),
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
    .expect("the OpenFlow controller never reported its address");
    Controller {
        state,
        id,
        port,
        log,
    }
}

/// A raw OpenFlow 1.3 switch: every byte it sent and received is kept, in order, as
/// `(to_controller, bytes)`.
pub struct RawSwitch {
    r: OwnedReadHalf,
    w: OwnedWriteHalf,
    pub chunks: Vec<(bool, Vec<u8>)>,
}

pub fn port(no: u32, name: &str) -> wire::Port {
    wire::Port {
        port_no: no,
        hw_addr: [0x02, 0xaa, 0, 0, 0, no as u8],
        name: name.into(),
        config: 0,
        state: wire::PORT_STATE_LIVE,
        curr: wire::PORT_FEATURES_DEFAULT,
        advertised: 0,
        supported: 0,
        peer: 0,
        curr_speed: 10_000_000,
        max_speed: 10_000_000,
    }
}

impl RawSwitch {
    pub async fn connect(addr: std::net::SocketAddr) -> RawSwitch {
        let s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (r, w) = s.into_split();
        RawSwitch {
            r,
            w,
            chunks: Vec::new(),
        }
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.chunks.push((true, bytes.to_vec()));
        self.w.write_all(bytes).await.unwrap();
    }

    pub async fn send(&mut self, msg_type: u8, xid: u32, body: &[u8]) {
        let b = wire::encode(VERSION_1_3, msg_type, xid, body).unwrap();
        self.send_raw(&b).await;
    }

    /// The next message, or None on EOF / after `within`.
    pub async fn recv_within(&mut self, within: Duration) -> Option<Message> {
        let mut h = [0u8; wire::HEADER_LEN];
        let read = tokio::time::timeout(within, self.r.read_exact(&mut h)).await;
        match read {
            Ok(Ok(_)) => {}
            _ => return None,
        }
        let header = wire::Header::parse(&h);
        let mut body = vec![0u8; (header.length as usize).saturating_sub(wire::HEADER_LEN)];
        self.r.read_exact(&mut body).await.ok()?;
        let mut raw = h.to_vec();
        raw.extend_from_slice(&body);
        self.chunks.push((false, raw));
        Some(Message { header, body })
    }

    pub async fn recv(&mut self) -> Message {
        self.recv_within(Duration::from_secs(30))
            .await
            .expect("the controller sent nothing within 30 s")
    }

    /// The next message of `msg_type`, answering ECHO_REQUESTs on the way.
    pub async fn expect(&mut self, msg_type: u8) -> Message {
        loop {
            let m = self.recv().await;
            if m.header.msg_type == msg_type {
                return m;
            }
            if m.header.msg_type == msg::ECHO_REQUEST {
                self.send(msg::ECHO_REPLY, m.header.xid, &m.body.clone())
                    .await;
                continue;
            }
            panic!(
                "expected {}, got {} ({:?})",
                wire::msg_name(msg_type),
                wire::msg_name(m.header.msg_type),
                m.body
            );
        }
    }

    /// Whether the controller closed the connection within `within` (reading and discarding).
    pub async fn closed_within(&mut self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        let mut buf = [0u8; 4096];
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, self.r.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    /// HELLO both ways, then answer FEATURES, SET_CONFIG, DESC and PORT_DESC as an OpenFlow
    /// 1.3 switch with ports 1 and 2. Returns the SET_CONFIG the controller sent.
    pub async fn handshake(&mut self) -> (u16, u16) {
        self.send(msg::HELLO, 1, &wire::hello_body(&[VERSION_1_3]))
            .await;
        let hello = self.expect(msg::HELLO).await;
        assert_eq!(hello.header.version, VERSION_1_3);
        let bitmap = wire::parse_hello_bitmap(&hello.body).unwrap().unwrap();
        assert_eq!(wire::bitmap_versions(&bitmap), vec![VERSION_1_3]);
        let mut config = None;
        let mut desc = false;
        let mut ports = false;
        let mut features = false;
        while !(features && desc && ports && config.is_some()) {
            let m = self.recv().await;
            assert_eq!(m.header.version, VERSION_1_3);
            match m.header.msg_type {
                msg::FEATURES_REQUEST => {
                    let f = wire::Features {
                        datapath_id: DPID,
                        n_buffers: 0,
                        n_tables: 254,
                        auxiliary_id: 0,
                        capabilities: 1 | 2 | 4,
                    };
                    self.send(msg::FEATURES_REPLY, m.header.xid, &f.encode())
                        .await;
                    features = true;
                }
                msg::SET_CONFIG => config = Some(wire::parse_config(&m.body).unwrap()),
                msg::MULTIPART_REQUEST => {
                    let (t, _, _) = wire::parse_multipart(&m.body).unwrap();
                    let body = match t {
                        wire::mp::DESC => {
                            desc = true;
                            wire::desc_body(["Raw", "raw switch", "1", "s1", "test"])
                        }
                        wire::mp::PORT_DESC => {
                            ports = true;
                            let mut b = Vec::new();
                            port(1, "p1").encode(&mut b);
                            port(2, "p2").encode(&mut b);
                            b
                        }
                        other => panic!("unexpected multipart {other} in the handshake"),
                    };
                    self.send(
                        msg::MULTIPART_REPLY,
                        m.header.xid,
                        &wire::multipart_body(t, 0, &body),
                    )
                    .await;
                }
                other => panic!("unexpected {} during the handshake", wire::msg_name(other)),
            }
        }
        config.unwrap()
    }

    /// Send a PACKET_IN carrying `frame` from `in_port`, unbuffered.
    pub async fn packet_in(&mut self, xid: u32, in_port: u32, frame: &[u8]) {
        let pi = wire::PacketIn {
            buffer_id: wire::NO_BUFFER,
            total_len: frame.len() as u16,
            reason: wire::packet_in_reason::NO_MATCH,
            table_id: 0,
            cookie: 0,
            matched: wire::Match {
                oxms: vec![wire::Oxm::basic(0, in_port.to_be_bytes().to_vec())],
            },
            data: frame.to_vec(),
        };
        self.send(msg::PACKET_IN, xid, &pi.encode()).await;
    }

    /// Ask for an ECHO and wait for its reply, failing on anything else in between. Proves
    /// the controller sent nothing before it.
    pub async fn nothing_before_echo(&mut self, xid: u32) {
        self.send(msg::ECHO_REQUEST, xid, b"probe").await;
        let m = self.recv().await;
        assert_eq!(
            m.header.msg_type,
            msg::ECHO_REPLY,
            "the controller sent {} before the echo reply",
            wire::msg_name(m.header.msg_type)
        );
        assert_eq!(m.header.xid, xid);
        assert_eq!(m.body, b"probe");
    }
}

/// The pcap oracle over a recorded OpenFlow stream: `(to_controller, bytes)` in wire order.
pub fn oracle(chunks: &[(bool, Vec<u8>)]) -> crate::helpers::pcap_oracle::PcapOracle {
    let mut o = crate::helpers::pcap_oracle::PcapOracle::tcp("openflow").also_named("openflow_v4");
    for (to_controller, bytes) in chunks {
        o = if *to_controller {
            o.to_server(bytes)
        } else {
            o.from_server(bytes)
        };
    }
    o
}

/// A 98-byte ICMP echo request from HOST_A to `dst`.
pub fn ping(dst: &str) -> Vec<u8> {
    netget::server::openflow::packet::build(&json!({
        "eth_src": HOST_A,
        "eth_dst": dst,
        "ipv4": {"src": "10.0.0.1", "dst": "10.0.0.2"},
        "icmp": {"type": 8, "id": 7, "seq": 1},
        "payload_text": "netget openflow test payload 0123456789abcdefghijklmnopq",
    }))
    .unwrap()
}
