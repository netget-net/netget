//! Shared harness for the Zigbee co-processor suites: an in-process server whose model is a
//! python policy (the LLM endpoint is unreachable, so nothing reaches a real model), and a
//! raw ASH/EZSP host that writes frames itself for the wire, bound and fail-closed tests.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::server::zigbee::{ash, ezsp};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub const LAMP_IEEE: &str = "00:12:4b:00:1c:a1:b2:01";
pub const SWITCH_IEEE: &str = "00:12:4b:00:1c:a1:b2:02";
pub const SILENT_IEEE: &str = "00:12:4b:00:1c:a1:b2:03";
pub const INVALID_IEEE: &str = "00:12:4b:00:1c:a1:b2:04";
pub const LAMP_NWK: u16 = 0x4a21;
pub const SILENT_NWK: u16 = 0x4a23;
pub const INVALID_NWK: u16 = 0x4a24;
pub const NETWORK_KEY: &str = "c0ffee00112233445566778899aabbcc";

/// The network's model. On permit joining, the devices a host-side test asks for join (the
/// lamps by default); a device's ZCL request is answered as the device would: On/Off switches
/// and reports, writes are accepted, anything else is unsupported. `silent-lamp` gets no
/// answer at all and `invalid-lamp` an answer NetGet must refuse — the fail-closed paths.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='zigbee_permit_joining':
  want=('kitchen-lamp','silent-lamp','invalid-lamp')
  a=[{'type':'zigbee_join_device','device':d['name']} for d in e['waiting_devices'] if d['name'] in want] or [{'type':'zigbee_ignore'}]
else:
  d=e['device']; c=e['cluster']; cmd=e['command']
  if d=='silent-lamp': a=[]
  elif d=='invalid-lamp': a=[{'type':'zigbee_set_attributes','attributes':[{'attribute':0,'value':'not a bool'}]}]
  elif c=='on_off' and cmd in ('on','off','toggle'):
    cur=e['current_attributes'].get('0x0000',{}).get('value',False)
    v=(cmd=='on') if cmd!='toggle' else (not cur)
    a=[{'type':'zigbee_set_attributes','attributes':[{'attribute':0,'value':v}],'report':True},{'type':'zigbee_default_response','status':'success'}]
  elif e['kind']=='write_attributes': a=[{'type':'zigbee_default_response','status':'success'}]
  else: a=[{'type':'zigbee_default_response','status':'unsup_cluster_command'}]
print(json.dumps({'actions':a}))"#;

fn lamp(name: &str, ieee: &str, nwk: u16) -> Value {
    json!({
        "name": name, "ieee": ieee, "nwk": format!("0x{nwk:04x}"), "type": "router",
        "manufacturer": "NetGet", "model": "Lamp-1",
        "endpoints": [{
            "id": 1, "profile": 260, "device_type": 256,
            "in_clusters": ["basic", "identify", "on_off", "level_control"],
            "out_clusters": ["ota"],
            "attributes": [
                {"cluster": "on_off", "attribute": 0, "type": "bool", "value": false},
                {"cluster": "level_control", "attribute": 0, "type": "uint8", "value": 254}
            ]
        }]
    })
}

pub fn devices() -> Value {
    json!([
        lamp("kitchen-lamp", LAMP_IEEE, LAMP_NWK),
        {
            "name": "wall-switch", "ieee": SWITCH_IEEE, "type": "end_device",
            "power_source": "battery", "manufacturer": "NetGet", "model": "Switch-1",
            "endpoints": [{"id": 1, "device_type": 0, "in_clusters": ["basic", "power_configuration"],
                           "out_clusters": ["on_off"],
                           "attributes": [{"cluster": "power_configuration", "attribute": 32, "type": "uint8", "value": 30}]}]
        },
        lamp("silent-lamp", SILENT_IEEE, SILENT_NWK),
        lamp("invalid-lamp", INVALID_IEEE, INVALID_NWK),
    ])
}

/// A network already formed in the co-processor's flash.
pub fn formed(channel: u8) -> Value {
    json!({"channel": channel, "pan_id": "0x1a62", "extended_pan_id": "dd:dd:dd:dd:dd:dd:dd:dd"})
}

pub struct Started {
    pub state: AppState,
    pub id: ServerId,
    pub addr: SocketAddr,
    /// The server's status lines, `decision=` among them.
    pub logs: mpsc::UnboundedReceiver<String>,
}

pub async fn start(policy: &str, params: Value) -> Started {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, logs) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "zigbee".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Run the Zigbee network".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":policy}}),
        ]),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("starting zigbee: {e}"));
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return a.port();
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    panic!("zigbee failed to start: {e}");
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
        logs,
    }
}

/// Access-log entries of one kind, oldest first: what the model was asked (`zigbee_*` event
/// ids) and what was answered from a description.
pub async fn log_entries(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    all.reverse();
    all
}

/// The events the model (the policy) was asked, of one kind.
pub async fn model_calls(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    log_entries(state, id, kind)
        .await
        .into_iter()
        .filter(|e| e["response"].to_string().contains("\"type\""))
        .map(|e| e["request"].clone())
        .collect()
}

/// Every log line the server sent to its status channel, for `decision=` assertions.
pub async fn wait_for_log(
    lines: &mut mpsc::UnboundedReceiver<String>,
    needle: &str,
    secs: u64,
) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, lines.recv()).await {
            Ok(Some(l)) if l.contains(needle) => return l,
            Ok(Some(_)) => {}
            _ => panic!("no log line containing {needle:?} within {secs}s"),
        }
    }
}

/// A frame the raw host received.
#[derive(Debug, Clone)]
pub enum Got {
    Frame(ash::Frame),
    Rstack(u8),
    Error(u8),
}

/// A raw ASH/EZSP host: NetGet's own framing helpers build the frames, the assertions read
/// the bytes the server wrote.
pub struct Host {
    pub stream: TcpStream,
    deframer: ash::Deframer,
    /// Our next DATA frame number.
    pub frm: u8,
    /// The next NCP frame number we expect (our ackNum).
    pub ack: u8,
    pub seq: u8,
    /// Received and not yet consumed.
    pub inbox: VecDeque<Got>,
    /// EZSP callbacks received, in order.
    pub callbacks: VecDeque<(u16, Vec<u8>)>,
    /// Acknowledge NCP DATA frames automatically.
    pub auto_ack: bool,
}

pub fn parse_raw(raw: &[u8]) -> Got {
    match raw.first() {
        Some(0xC1) if raw.len() == 5 => Got::Rstack(raw[2]),
        Some(0xC2) if raw.len() == 5 => Got::Error(raw[2]),
        _ => Got::Frame(ash::Frame::parse(raw).expect("the server's frame parses")),
    }
}

impl Host {
    pub async fn connect(addr: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(addr).await.expect("connect"),
            deframer: ash::Deframer::new(),
            frm: 0,
            ack: 0,
            seq: 0,
            inbox: VecDeque::new(),
            callbacks: VecDeque::new(),
            auto_ack: true,
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
    }

    /// Read until at least one unit arrives or the deadline passes; `false` on EOF.
    async fn fill(&mut self, deadline: tokio::time::Instant) -> bool {
        let mut buf = [0u8; 1024];
        let n = match tokio::time::timeout_at(deadline, self.stream.read(&mut buf)).await {
            Err(_) => return true,
            Ok(Ok(0)) | Ok(Err(_)) => return false,
            Ok(Ok(n)) => n,
        };
        let mut out = Vec::new();
        self.deframer.push(&buf[..n], &mut out);
        for d in out {
            if let ash::Deframed::Frame(raw) = d {
                let got = parse_raw(&raw);
                if let Got::Frame(ash::Frame::Data { frm_num, ezsp, .. }) = &got {
                    if self.auto_ack {
                        if *frm_num == self.ack {
                            self.ack = (self.ack + 1) & 7;
                        }
                        let a = ash::ack_frame(self.ack, false);
                        self.stream.write_all(&a).await.expect("ack");
                        if ezsp.len() >= 2 && ezsp[1] & ezsp::FC_ASYNC_CALLBACK != 0 {
                            let id = u16::from_le_bytes([ezsp[3], ezsp[4]]);
                            self.callbacks.push_back((id, ezsp[5..].to_vec()));
                            continue;
                        }
                    }
                }
                self.inbox.push_back(got);
            }
        }
        true
    }

    /// The next unit received within `secs`, if any.
    pub async fn next(&mut self, secs: f64) -> Option<Got> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(secs);
        loop {
            if let Some(g) = self.inbox.pop_front() {
                return Some(g);
            }
            if tokio::time::Instant::now() >= deadline || !self.fill(deadline).await {
                return self.inbox.pop_front();
            }
        }
    }

    /// Whether the server closed the connection within `secs`.
    pub async fn closed_within(&mut self, secs: u64) -> bool {
        let mut buf = [0u8; 256];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            match tokio::time::timeout_at(deadline, self.stream.read(&mut buf)).await {
                Err(_) => return false,
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => {}
            }
        }
    }

    pub async fn reset(&mut self) -> u8 {
        self.frm = 0;
        self.ack = 0;
        self.write(&ash::rst_frame()).await;
        loop {
            match self.next(5.0).await {
                Some(Got::Rstack(code)) => return code,
                Some(_) => {}
                None => panic!("no RSTACK"),
            }
        }
    }

    /// Send an EZSP frame in a DATA frame.
    pub async fn send_ezsp(&mut self, frame: &[u8]) {
        let f = ash::data_frame(self.frm, false, self.ack, frame);
        self.frm = (self.frm + 1) & 7;
        self.write(&f).await;
    }

    /// The next EZSP response (not a callback) within `secs`.
    pub async fn response(&mut self, secs: f64) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(secs);
        while tokio::time::Instant::now() < deadline {
            let left = (deadline - tokio::time::Instant::now()).as_secs_f64();
            match self.next(left).await {
                Some(Got::Frame(ash::Frame::Data { ezsp, .. })) => return Some(ezsp),
                Some(_) => {}
                None => return None,
            }
        }
        None
    }

    pub fn ext(&mut self, frame_id: u16, params: &[u8]) -> Vec<u8> {
        self.seq = self.seq.wrapping_add(1);
        let mut f = vec![self.seq, 0x00, 0x01];
        f.extend_from_slice(&frame_id.to_le_bytes());
        f.extend_from_slice(params);
        f
    }

    /// One extended-format command; returns the response's frame id and parameters.
    pub async fn command(&mut self, frame_id: u16, params: &[u8]) -> (u16, Vec<u8>) {
        let f = self.ext(frame_id, params);
        self.send_ezsp(&f).await;
        let r = self
            .response(5.0)
            .await
            .unwrap_or_else(|| panic!("no response to 0x{frame_id:04x}"));
        assert_eq!(r[0], self.seq, "response sequence");
        assert_eq!(r[1] & 0x80, 0x80, "response direction");
        assert_eq!(r[2] & 0x03, 0x01, "extended format");
        (u16::from_le_bytes([r[3], r[4]]), r[5..].to_vec())
    }

    /// Reset and negotiate a version the way bellows does: legacy version(4), then the
    /// NCP's own in the extended format.
    pub async fn startup(&mut self) -> u8 {
        assert_eq!(self.reset().await, ash::reset::SOFTWARE);
        self.seq = self.seq.wrapping_add(1);
        self.send_ezsp(&[self.seq, 0x00, 0x00, 4]).await;
        let r = self.response(5.0).await.expect("legacy version response");
        assert_eq!(&r[..3], &[self.seq, 0x80, 0x00], "legacy response header");
        let v = r[3];
        let (id, p) = self.command(ezsp::id::VERSION, &[v]).await;
        assert_eq!(id, ezsp::id::VERSION);
        assert_eq!(p[0], v);
        v
    }

    /// The next callback with this frame id within `secs`.
    pub async fn callback(&mut self, frame_id: u16, secs: f64) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(secs);
        loop {
            if let Some(i) = self.callbacks.iter().position(|(id, _)| *id == frame_id) {
                return self.callbacks.remove(i).map(|(_, p)| p);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            let left = (deadline - tokio::time::Instant::now()).as_secs_f64();
            if let Some(g) = self.next(left.min(0.2)).await {
                self.inbox.push_back(g);
                // Responses that arrive here are kept for the next response() call.
                if self.inbox.len() > 64 {
                    self.inbox.pop_front();
                }
            }
        }
    }

    /// Form a network on `channel` with NetGet's test key, as a host does.
    pub async fn form(&mut self, channel: u8) {
        let mut sec = Vec::new();
        sec.extend_from_slice(&0x0B04u16.to_le_bytes());
        sec.extend_from_slice(b"ZigBeeAlliance09");
        sec.extend_from_slice(&hex::decode(NETWORK_KEY).unwrap());
        sec.push(0);
        sec.extend_from_slice(&[0xFF; 8]);
        let (_, p) = self
            .command(ezsp::id::SET_INITIAL_SECURITY_STATE, &sec)
            .await;
        assert_eq!(status(&p), 0, "setInitialSecurityState");
        let mut params = Vec::new();
        params.extend_from_slice(&[0xdd; 8]);
        params.extend_from_slice(&0x1a62u16.to_le_bytes());
        params.extend_from_slice(&[8, channel, 0]);
        params.extend_from_slice(&0u16.to_le_bytes());
        params.push(0);
        params.extend_from_slice(&(1u32 << channel).to_le_bytes());
        let (_, p) = self.command(ezsp::id::FORM_NETWORK, &params).await;
        assert_eq!(status(&p), 0, "formNetwork");
        let up = self
            .callback(ezsp::id::STACK_STATUS_HANDLER, 5.0)
            .await
            .expect("stackStatusHandler after formNetwork");
        assert_eq!(status(&up), 0x15, "NETWORK_UP");
    }

    /// Register endpoint 1 (HA) as zigpy does.
    pub async fn add_endpoint(&mut self) {
        let mut p = vec![1];
        p.extend_from_slice(&0x0104u16.to_le_bytes());
        p.extend_from_slice(&0x0400u16.to_le_bytes());
        p.extend_from_slice(&[0, 1, 0]);
        p.extend_from_slice(&0x0006u16.to_le_bytes());
        let (_, r) = self.command(ezsp::id::ADD_ENDPOINT, &p).await;
        assert_eq!(status(&r), 0, "addEndpoint");
    }

    /// Open the network and wait for the trust-center joins the policy produces.
    pub async fn permit_and_join(&mut self, expect: usize) -> Vec<(u16, u64)> {
        let (_, p) = self.command(ezsp::id::PERMIT_JOINING, &[30]).await;
        assert_eq!(status(&p), 0, "permitJoining");
        let mut joined = Vec::new();
        for _ in 0..expect {
            let tc = self
                .callback(ezsp::id::TRUST_CENTER_JOIN_HANDLER, 15.0)
                .await
                .expect("trustCenterJoinHandler");
            let nwk = u16::from_le_bytes([tc[0], tc[1]]);
            let mut e = [0u8; 8];
            e.copy_from_slice(&tc[2..10]);
            joined.push((nwk, u64::from_le_bytes(e)));
        }
        joined
    }

    /// sendUnicast; returns its status.
    pub async fn unicast(
        &mut self,
        nwk: u16,
        profile: u16,
        cluster: u16,
        dst_ep: u8,
        tag: u16,
        message: &[u8],
    ) -> u32 {
        let mut p = vec![0x00];
        p.extend_from_slice(&nwk.to_le_bytes());
        p.extend_from_slice(&profile.to_le_bytes());
        p.extend_from_slice(&cluster.to_le_bytes());
        p.push(if profile == 0 { 0 } else { 1 });
        p.push(dst_ep);
        p.extend_from_slice(&0x0140u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.push(0);
        p.extend_from_slice(&tag.to_le_bytes());
        p.push(message.len() as u8);
        p.extend_from_slice(message);
        let (_, r) = self.command(ezsp::id::SEND_UNICAST, &p).await;
        status(&r)
    }

    /// The next incomingMessageHandler: (cluster, source endpoint, sender, payload).
    pub async fn incoming(&mut self, secs: f64) -> Option<(u16, u8, u16, Vec<u8>)> {
        let p = self
            .callback(ezsp::id::INCOMING_MESSAGE_HANDLER, secs)
            .await?;
        let cluster = u16::from_le_bytes([p[3], p[4]]);
        let src_ep = p[5];
        let sender = u16::from_le_bytes([p[12], p[13]]);
        let len = p[30] as usize;
        Some((cluster, src_ep, sender, p[31..31 + len].to_vec()))
    }
}

pub fn status(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

/// The ZCL frames a host sends.
pub fn zcl_on(tsn: u8) -> Vec<u8> {
    vec![0x01, tsn, 0x01]
}

pub fn zcl_read(tsn: u8, attrs: &[u16]) -> Vec<u8> {
    let mut v = vec![0x00, tsn, 0x00];
    for a in attrs {
        v.extend_from_slice(&a.to_le_bytes());
    }
    v
}
