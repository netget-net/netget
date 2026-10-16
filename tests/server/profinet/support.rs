//! Shared harness for the PROFINET suites: an in-process device and controller with python
//! policies standing in for the model, and a hand-built peer that speaks the lab transport
//! (whole Ethernet frames in UDP datagrams) and PNIO RPC, recording every frame both ways for
//! the pcap oracle.
#![allow(dead_code)]

use netget::cli::management::{ClientForm, ServerForm};
use netget::server::profinet::{blocks, dcp, rpc, rt};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// The device's model: accept connects from controllers named plc-*, set slot 1's input to
/// 42; accept renames to line-*; answer I&M0; accept writes of user record 123; refuse the
/// rest.
pub const DEVICE_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='profinet_connect_request':
  if e['controller']['station_name'].startswith('plc-'):
    a=[{'type':'profinet_accept_connect'},{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'inputs':42}}]
  else:
    a=[{'type':'profinet_refuse_connect','reason':'unknown controller'}]
elif t=='profinet_dcp_set_request':
  n=e.get('name_of_station')
  if (n is not None and not n.startswith('line-')) or e.get('factory_reset'):
    a=[{'type':'profinet_refuse_dcp_set','reason':'locked'}]
  else:
    a=[{'type':'profinet_accept_dcp_set'}]
elif t=='profinet_read_record':
  if e['index']==0xAFF0:
    a=[{'type':'profinet_read_response','im0':{'order_id':'NG-PN-1','serial_number':'SN-0042','hardware_revision':3,'software_revision':'V2.1.0','im_supported':[1]}}]
  elif e['index']==123:
    a=[{'type':'profinet_read_response','fields':[{'type':'u32','value':7}]}]
  else:
    a=[{'type':'profinet_refuse_record','error':'invalid_index'}]
elif t=='profinet_write_record':
  a=[{'type':'profinet_accept_write'}] if e['index']==123 else [{'type':'profinet_refuse_record','error':'access_denied'}]
elif t=='profinet_outputs_changed':
  for o in e['outputs']:
    if o['slot']==1 and o['iops']=='good':
      a=[{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'inputs':(o['values']['outputs']+1)%256}}]
print(json.dumps({'actions':a}))"#;

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

pub fn static_rule(actions: Value) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": actions}}),
    ])
}

pub struct Logged {
    pub state: AppState,
    pub log: Arc<Mutex<Vec<String>>>,
}

pub fn new_state() -> (
    AppState,
    mpsc::UnboundedSender<String>,
    Arc<Mutex<Vec<String>>>,
) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    (state, tx, log)
}

/// A running in-process device.
pub struct Device {
    pub state: AppState,
    pub id: ServerId,
    pub rpc: SocketAddr,
    pub lab: Option<SocketAddr>,
    pub log: Arc<Mutex<Vec<String>>>,
}

pub fn log_text(log: &Arc<Mutex<Vec<String>>>) -> String {
    log.lock().unwrap().join("\n")
}

pub async fn wait_for(log: &Arc<Mutex<Vec<String>>>, needle: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !log_text(log).contains(needle) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

async fn events_of(state: &AppState, owner: AccessLogOwner, kind: &str) -> Vec<Value> {
    let mut v: Vec<Value> = state
        .list_access_logs_for(Some(owner), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
    v.into_iter().map(|e| e["request"].clone()).collect()
}

async fn wait_events(state: &AppState, owner: AccessLogOwner, kind: &str, n: usize) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let v = events_of(state, owner, kind).await;
        if v.len() >= n || tokio::time::Instant::now() > deadline {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl Device {
    pub fn log_text(&self) -> String {
        log_text(&self.log)
    }

    pub async fn wait_for_log(&self, needle: &str) -> bool {
        wait_for(&self.log, needle).await
    }

    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Server(self.id.as_u32()), kind).await
    }

    pub async fn wait_for_events(&self, kind: &str, n: usize) -> Vec<Value> {
        wait_events(
            &self.state,
            AccessLogOwner::Server(self.id.as_u32()),
            kind,
            n,
        )
        .await
    }

    pub async fn connections(&self) -> Vec<u32> {
        self.state
            .get_server(self.id)
            .await
            .map(|s| s.connections.values().map(|c| c.id.as_u32()).collect())
            .unwrap_or_default()
    }
}

/// Parse "… on HOST:PORT" out of the lab link's start-up line.
fn lab_addr(log: &str) -> Option<SocketAddr> {
    log.lines()
        .find(|l| l.contains("PROFINET lab link"))
        .and_then(|l| l.rsplit("on ").next())
        .and_then(|a| a.trim().parse().ok())
}

/// Start a device on the lab transport. `state` lets a test put a controller beside it.
pub async fn start_device_in(
    state: AppState,
    tx: mpsc::UnboundedSender<String>,
    log: Arc<Mutex<Vec<String>>>,
    handlers: Option<Vec<Value>>,
    mut params: Value,
) -> Device {
    params["transport"] = json!("udp");
    let id = ServerForm {
        protocol: "profinet".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a PROFINET IO device".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let rpc = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the PROFINET device never reported its address");
    assert!(
        wait_for(&log, "PROFINET lab link").await,
        "{}",
        log_text(&log)
    );
    let lab = lab_addr(&log_text(&log));
    Device {
        state,
        id,
        rpc,
        lab,
        log,
    }
}

pub async fn start_device(handlers: Option<Vec<Value>>, params: Value) -> Device {
    let (state, tx, log) = new_state();
    start_device_in(state, tx, log, handlers, params).await
}

/// A running in-process controller.
pub struct Controller {
    pub state: AppState,
    pub id: ClientId,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Controller {
    pub fn log_text(&self) -> String {
        log_text(&self.log)
    }

    pub async fn wait_for_log(&self, needle: &str) -> bool {
        wait_for(&self.log, needle).await
    }

    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Client(self.id.as_u32()), kind).await
    }

    pub async fn wait_for_events(&self, kind: &str, n: usize) -> Vec<Value> {
        wait_events(
            &self.state,
            AccessLogOwner::Client(self.id.as_u32()),
            kind,
            n,
        )
        .await
    }

    pub async fn send(&self, action: Value) -> netget::state::client_handles::ClientSendOutcome {
        self.state
            .send_to_client(self.id, action, Duration::from_secs(30))
            .await
            .unwrap()
    }
}

pub async fn start_controller_in(
    state: AppState,
    tx: mpsc::UnboundedSender<String>,
    log: Arc<Mutex<Vec<String>>>,
    remote: &str,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> anyhow::Result<Controller> {
    let id = ClientForm {
        protocol: "PROFINET".into(),
        remote_addr: Some(remote.into()),
        instruction: Some("Be a PROFINET IO controller".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok(Controller { state, id, log })
}

/// A hand-built peer on the lab transport: it sends and receives whole Ethernet frames, and
/// keeps every one (`true` = sent by the peer) for the oracle.
pub struct LabPeer {
    pub sock: UdpSocket,
    pub device: SocketAddr,
    pub mac: [u8; 6],
    pub frames: Vec<(bool, Vec<u8>)>,
}

impl LabPeer {
    pub async fn new(device: SocketAddr) -> LabPeer {
        LabPeer {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            device,
            mac: [0x02, 0x99, 0, 0, 0, 0x01],
            frames: Vec::new(),
        }
    }

    pub async fn send_payload(&mut self, dst: [u8; 6], payload: &[u8]) {
        let frame = rt::build_eth(dst, self.mac, None, payload);
        self.send_frame(frame).await;
    }

    pub async fn send_frame(&mut self, frame: Vec<u8>) {
        self.frames.push((true, frame.clone()));
        self.sock.send_to(&frame, self.device).await.unwrap();
    }

    /// The next frame from the device within `secs`, or None.
    pub async fn recv(&mut self, secs: u64) -> Option<rt::EthFrame> {
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(secs), self.sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        self.frames.push((false, buf[..n].to_vec()));
        rt::parse_eth(&buf[..n])
    }

    /// The next DCP PDU from the device, skipping cyclic frames.
    pub async fn recv_dcp(&mut self, secs: u64) -> Option<dcp::Pdu> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let f = self.recv(left.as_secs().max(1)).await?;
            if let Ok(p) = dcp::Pdu::parse(&f.payload) {
                return Some(p);
            }
        }
    }

    /// The next cyclic frame with this FrameID.
    pub async fn recv_rt(
        &mut self,
        frame_id: u16,
        data_length: usize,
        secs: u64,
    ) -> Option<rt::RtFrame> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let f = self.recv(left.as_secs().max(1)).await?;
            if rt::frame_id_of(&f.payload) == Some(frame_id) {
                return rt::parse_rt(&f.payload, data_length).ok();
            }
        }
    }

    pub async fn identify(&mut self, xid: u32, name: Option<&str>) -> Option<dcp::Pdu> {
        let pdu = dcp::identify_request(xid, name, 0).encode().unwrap();
        self.send_payload(dcp::MULTICAST_IDENTIFY, &pdu).await;
        self.recv_dcp(3).await
    }
}

/// A hand-built PNIO RPC client: datagrams both ways are kept for the oracle.
pub struct RpcPeer {
    pub sock: UdpSocket,
    pub device: SocketAddr,
    pub activity: rpc::Uuid,
    pub seq: u32,
    pub datagrams: Vec<(bool, Vec<u8>)>,
}

impl RpcPeer {
    pub async fn new(device: SocketAddr) -> RpcPeer {
        RpcPeer {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            device,
            activity: rpc::random_uuid(),
            seq: 0,
            datagrams: Vec::new(),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.sock.local_addr().unwrap()
    }

    pub async fn send_raw(&mut self, d: Vec<u8>) {
        self.datagrams.push((true, d.clone()));
        self.sock.send_to(&d, self.device).await.unwrap();
    }

    pub async fn recv_raw(&mut self, secs: u64) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(secs), self.sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        self.datagrams.push((false, buf[..n].to_vec()));
        Some(buf[..n].to_vec())
    }

    /// One PNIO call: blocks in, (header, PNIO status, response blocks) out.
    pub async fn call(
        &mut self,
        op: u16,
        blocks: &[u8],
        little_endian: bool,
    ) -> (rpc::Header, rpc::PnioStatus, Vec<u8>) {
        self.seq += 1;
        let mut h = rpc::Header::request(
            rpc::object_uuid(1, 1, 0),
            rpc::IF_DEVICE,
            self.activity,
            self.seq,
            op,
        );
        h.little_endian = little_endian;
        let body = if little_endian {
            // An NDR header in little-endian order, as Siemens controllers send it.
            let mut b = Vec::new();
            let len = blocks.len() as u32;
            for v in [1024u32.max(len), len, 1024u32.max(len), 0, len] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(blocks);
            b
        } else {
            rpc::ndr_request(1024, blocks)
        };
        self.send_raw(rpc::encode(&h, &body).unwrap()).await;
        loop {
            let d = self
                .recv_raw(15)
                .await
                .expect("the device did not answer the RPC call");
            let (rh, rb) = rpc::parse(&d).unwrap();
            if rh.seqnum != self.seq || rh.activity != self.activity {
                continue;
            }
            if rh.ptype != rpc::ptype::RESPONSE {
                return (rh, rpc::PnioStatus::new(0xff, 0xff, 0xff, 0xff), Vec::new());
            }
            let (status, b) = rpc::parse_ndr_response(rb, rh.little_endian).unwrap();
            return (rh, status, b.to_vec());
        }
    }
}

/// A Connect for the default device layout, as a controller at `mac` named `station` would
/// send it: DAP and slot 1 (one u8 in, one u8 out), 4 ms cycle.
pub fn default_connect(
    mac: [u8; 6],
    station: &str,
    ar_uuid: rpc::Uuid,
) -> (Vec<u8>, rt::CrLayout, rt::CrLayout) {
    let specs = netget::server::profinet::values::default_layout();
    let input = rt::CrLayout::for_controller(&specs, true).unwrap();
    let output = rt::CrLayout::for_controller(&specs, false).unwrap();
    let mut out = blocks::ArBlockReq {
        ar_type: blocks::ar_type::IOC_AR_SINGLE,
        ar_uuid,
        session_key: 7,
        initiator_mac: mac,
        initiator_object_uuid: rpc::object_uuid(1, 1, 0),
        ar_properties: 0x11,
        activity_timeout_factor: 100,
        initiator_udp_rt_port: 0x8892,
        station_name: station.into(),
    }
    .encode();
    for (kind, layout, fid, r) in [
        (blocks::iocr_type::INPUT, &input, 0xc010u16, 1u16),
        (blocks::iocr_type::OUTPUT, &output, 0xffffu16, 2u16),
    ] {
        let (io_data, iocs) = layout.descriptors();
        out.extend(
            blocks::IocrBlockReq {
                iocr_type: kind,
                iocr_reference: r,
                lt: 0x8892,
                properties: blocks::RT_CLASS_1,
                data_length: layout.data_length as u16,
                frame_id: fid,
                send_clock_factor: 32,
                reduction_ratio: 4,
                phase: 1,
                sequence: 0,
                frame_send_offset: 0xffff_ffff,
                watchdog_factor: 250,
                data_hold_factor: 250,
                tag_header: 0xc000,
                multicast_mac: [0; 6],
                apis: vec![blocks::IocrApi {
                    api: 0,
                    io_data,
                    iocs,
                }],
            }
            .encode(),
        );
    }
    out.extend(
        blocks::AlarmCrBlockReq {
            alarm_cr_type: 1,
            lt: 0x8892,
            properties: 0,
            rta_timeout_factor: 100,
            rta_retries: 3,
            local_alarm_reference: 1,
            max_alarm_data_length: 200,
            tag_header_high: 0xc000,
            tag_header_low: 0xa000,
        }
        .encode(),
    );
    let expected: Vec<blocks::ExpectedSubmodule> = specs.iter().map(|s| s.to_expected()).collect();
    for slot in [0u16, 1] {
        let subs: Vec<&blocks::ExpectedSubmodule> =
            expected.iter().filter(|e| e.slot == slot).collect();
        out.extend(blocks::encode_expected_slot(&subs).unwrap());
    }
    (out, input, output)
}
