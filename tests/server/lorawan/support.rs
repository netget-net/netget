//! Shared harness for the LoRaWAN network-server suites: an in-process server whose model is a
//! python policy (the LLM endpoint is unreachable, so a device the policy does not answer
//! exercises the fail-closed path), and a raw packet forwarder that writes datagrams itself.
#![allow(dead_code)]

use base64::Engine;
use netget::cli::management::ServerForm;
use netget::server::lorawan::mac;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const APP_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
pub const DEV_EUI: &str = "0102030405060708";
pub const APP_EUI: &str = "70b3d57ed0000001";
pub const GATEWAY: [u8; 8] = [0xaa, 0x55, 0x5a, 0, 0, 0, 0, 1];
pub const ABP_ADDR: &str = "26011bda";
pub const ABP_NWK: &str = "000102030405060708090a0b0c0d0e0f";
pub const ABP_APP: &str = "0f0e0d0c0b0a09080706050403020100";

/// The network's model: meter-1 and abp-node are admitted, `rejected` is refused, `silent`
/// gets no answer, `invalid` an answer NetGet must refuse. Uplinks: "hello" is answered on
/// port 10 with "world", "status?" asks DevStatusReq, "twice" queues two downlinks, "nothing"
/// is ignored, "silent" gets no answer at all and "badport" an invalid one.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='lorawan_join_request':
  d=e.get('device')
  if d=='rejected': a=[{'type':'lorawan_reject_join'}]
  elif d=='silent': a=[]
  elif d=='invalid': a=[{'type':'lorawan_accept_join_now'}]
  else: a=[{'type':'lorawan_accept_join'}]
else:
  p=e['payload']
  if p=='hello': a=[{'type':'lorawan_send_downlink','f_port':10,'payload':'world'}]
  elif p=='status?': a=[{'type':'lorawan_request_device_status'}]
  elif p=='twice': a=[{'type':'lorawan_send_downlink','f_port':11,'payload':'one'},{'type':'lorawan_send_downlink','f_port':12,'payload':'0203','encoding':'hex','confirmed':True}]
  elif p=='silent': a=[]
  elif p=='badport': a=[{'type':'lorawan_send_downlink','f_port':0,'payload':'x'}]
  else: a=[{'type':'lorawan_ignore'}]
print(json.dumps({'actions':a}))"#;

pub fn devices() -> Value {
    json!([
        {"name": "meter-1", "dev_eui": DEV_EUI, "app_eui": APP_EUI, "app_key": APP_KEY},
        {"name": "rejected", "dev_eui": "1111111111111111", "app_key": APP_KEY},
        {"name": "silent", "dev_eui": "2222222222222222", "app_key": APP_KEY},
        {"name": "invalid", "dev_eui": "3333333333333333", "app_key": APP_KEY},
        {"name": "abp-node", "dev_addr": ABP_ADDR, "nwk_s_key": ABP_NWK, "app_s_key": ABP_APP},
    ])
}

pub struct Started {
    pub state: AppState,
    pub id: ServerId,
    pub addr: SocketAddr,
}

pub async fn start(policy: &str, params: Value) -> Started {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "lorawan".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Run the network".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":policy}}),
        ]),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("starting lorawan: {e}"));
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return a.port();
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    panic!("lorawan failed to start: {e}");
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server started");
    Started {
        state,
        id,
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
    }
}

/// What the model was shown, per event type, oldest first.
pub async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all.sort_by_key(|e| e["f_cnt"].as_u64().unwrap_or(0));
    all
}

pub async fn wait_events(state: &AppState, id: ServerId, event_type: &str, n: usize) -> Vec<Value> {
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        while events(state, id, event_type).await.len() < n {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    events(state, id, event_type).await
}

/// A packet forwarder written from PROTOCOL.TXT: one socket up, one down, as lora_pkt_fwd.
pub struct Forwarder {
    pub up: UdpSocket,
    pub down: UdpSocket,
    pub server: SocketAddr,
    pub eui: [u8; 8],
}

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn rxpk(phy: &[u8], tmst: u32, datr: &str) -> Value {
    json!({"tmst": tmst, "chan": 0, "rfch": 0, "freq": 868.1, "stat": 1, "modu": "LORA",
           "datr": datr, "codr": "4/5", "rssi": -57, "lsnr": 9.5, "size": phy.len(), "data": b64(phy)})
}

impl Forwarder {
    pub async fn new(server: SocketAddr) -> Self {
        Self::with_eui(server, GATEWAY).await
    }

    pub async fn with_eui(server: SocketAddr, eui: [u8; 8]) -> Self {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let down = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self {
            up,
            down,
            server,
            eui,
        }
    }

    /// PULL_DATA from the downstream socket; returns the PULL_ACK's identifier byte.
    pub async fn pull(&self) -> Option<Vec<u8>> {
        let mut d = vec![2, 0x12, 0x34, 0x02];
        d.extend(self.eui);
        self.down.send_to(&d, self.server).await.unwrap();
        recv(&self.down, Duration::from_secs(2)).await
    }

    pub fn push_datagram(&self, body: &Value, token: u16) -> Vec<u8> {
        let t = token.to_be_bytes();
        let mut d = vec![2, t[0], t[1], 0x00];
        d.extend(self.eui);
        d.extend(serde_json::to_vec(body).unwrap());
        d
    }

    /// PUSH_DATA; returns the PUSH_ACK when one came.
    pub async fn push_raw(&self, d: &[u8]) -> Option<Vec<u8>> {
        self.up.send_to(d, self.server).await.unwrap();
        recv(&self.up, Duration::from_secs(2)).await
    }

    pub async fn push(&self, phy: &[u8], tmst: u32) -> Option<Vec<u8>> {
        let d = self.push_datagram(&json!({"rxpk": [rxpk(phy, tmst, "SF7BW125")]}), 0xbeef);
        self.push_raw(&d).await
    }

    /// The next PULL_RESP on the downstream socket: (token, txpk). Answers its TX_ACK.
    pub async fn pull_resp(&self, within: Duration) -> Option<(u16, Value)> {
        let d = recv(&self.down, within).await?;
        assert_eq!(d[3], 0x03, "expected PULL_RESP, got {d:02x?}");
        assert_eq!(d[0], 2, "version");
        let token = u16::from_be_bytes([d[1], d[2]]);
        let body: Value = serde_json::from_slice(&d[4..]).unwrap();
        let mut ack = vec![2, d[1], d[2], 0x05];
        ack.extend(self.eui);
        ack.extend(br#"{"txpk_ack":{"error":"NONE"}}"#);
        self.down.send_to(&ack, self.server).await.unwrap();
        Some((token, body["txpk"].clone()))
    }

    pub fn phy_of(txpk: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(txpk["data"].as_str().unwrap())
            .unwrap()
    }
}

pub async fn recv(s: &UdpSocket, within: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65536];
    match tokio::time::timeout(within, s.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

pub fn key(s: &str) -> mac::Key {
    mac::parse_key("key", s).unwrap()
}
pub fn eui(s: &str) -> mac::Eui {
    mac::parse_eui("eui", s).unwrap()
}

/// A joined device from the test's side: the keys it derived from the Join Accept.
pub struct Device {
    pub dev_addr: u32,
    pub nwk: mac::Key,
    pub app: mac::Key,
    pub fcnt_up: u32,
}

impl Device {
    pub fn abp() -> Self {
        Self {
            dev_addr: mac::parse_dev_addr(ABP_ADDR).unwrap(),
            nwk: key(ABP_NWK),
            app: key(ABP_APP),
            fcnt_up: 0,
        }
    }

    pub fn uplink(&mut self, port: u8, payload: &[u8], confirmed: bool, f_opts: &[u8]) -> Vec<u8> {
        let phy = mac::encode_data(
            &mac::OutFrame {
                mtype: if confirmed {
                    mac::MTYPE_CONFIRMED_UP
                } else {
                    mac::MTYPE_UNCONFIRMED_UP
                },
                dev_addr: self.dev_addr,
                adr: false,
                adr_ack_req: false,
                ack: false,
                f_pending: false,
                f_cnt: self.fcnt_up,
                f_opts,
                f_port: Some(port),
                payload,
            },
            &self.nwk,
            &self.app,
        )
        .unwrap();
        self.fcnt_up += 1;
        phy
    }

    /// Decode a downlink: (frame, decrypted payload, decoded MAC commands).
    pub fn decode(&self, phy: &[u8], expected_fcnt: u32) -> (mac::DataFrame, Vec<u8>, Vec<Value>) {
        let f = mac::parse_data(phy).unwrap();
        assert_eq!(f.dev_addr, self.dev_addr);
        assert_eq!(f.f_cnt as u32, expected_fcnt, "downlink FCnt");
        assert!(
            mac::data_mic_ok(phy, &self.nwk, mac::DIR_DOWN, f.dev_addr, expected_fcnt),
            "downlink MIC"
        );
        let key = if f.f_port == Some(0) { self.nwk } else { self.app };
        let plain = mac::crypt_frm(&key, mac::DIR_DOWN, f.dev_addr, expected_fcnt, &f.frm_payload);
        let cmds = mac::decode_mac_commands(&f.f_opts, false);
        (f, plain, cmds)
    }
}
