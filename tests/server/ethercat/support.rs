//! Shared harness for the EtherCAT suites: an in-process slave segment and master with python
//! policies standing in for the model, a hand-built EtherCAT-in-UDP master for the fail-closed
//! and bound paths, and a bridge that lets ethercrab — which speaks Ethernet frames — drive the
//! slave over EtherCAT-in-UDP. Every payload both ways is kept for the pcap oracle.
#![allow(dead_code)]

use netget::cli::management::{ClientForm, ServerForm};
use netget::server::ethercat::frame::{self, cmd, Datagram};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// The slave's model: accept every state change, setting count 42 and ready on the way to
/// SAFE-OP; Speed limit reads 1500 and takes writes up to 3000; Serial text reads a string;
/// each output change in OP sets count to setpoint + 1.
pub const SLAVE_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='ethercat_state_change_request':
  if e['to']=='safeop':
    a=[{'type':'ethercat_set_inputs','values':{'count':42,'ready':True}}]
  a.append({'type':'ethercat_accept_state_change'})
elif t=='ethercat_sdo_read':
  if e['index']==0x8000:
    a=[{'type':'ethercat_sdo_value','value':1500}]
  elif e['index']==0x2001:
    a=[{'type':'ethercat_sdo_value','value':'NetGet EtherCAT slave, serial text that needs SDO segments'}]
  else:
    a=[{'type':'ethercat_sdo_abort','abort':'device_state'}]
elif t=='ethercat_sdo_write':
  a=[{'type':'ethercat_sdo_accept_write'}] if e['value']<=3000 else [{'type':'ethercat_sdo_abort','abort':'value_too_high','reason':'over the limit'}]
elif t=='ethercat_outputs_changed':
  o=e['outputs']
  if o.get('motor_on'):
    a=[{'type':'ethercat_set_inputs','values':{'count':(o['setpoint']+1)%65536}}]
print(json.dumps({'actions':a}))"#;

/// The slave every suite starts: bit-packed process data (a bool before an i16 puts the i16 at
/// bit 1), a read-write u16 object and a read-only string.
pub fn slave_params() -> Value {
    json!({
        "slaves": [{
            "name": "NetGet Test Slave",
            "vendor_id": "0x00000ABC",
            "product_code": "0x00012345",
            "revision": 7,
            "serial": 99,
            "inputs": [{"name": "count", "type": "u16"}, {"name": "ready", "type": "bool"}],
            "outputs": [{"name": "motor_on", "type": "bool"}, {"name": "setpoint", "type": "i16"}],
            "objects": [
                {"index": "0x8000", "subindex": 1, "name": "Speed limit", "type": "u16", "access": "rw"},
                {"index": "0x2001", "subindex": 0, "name": "Serial text", "type": "string", "access": "ro"}
            ]
        }]
    })
}

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
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

pub fn log_text(log: &Arc<Mutex<Vec<String>>>) -> String {
    log.lock().unwrap().join("\n")
}

pub async fn wait_for(log: &Arc<Mutex<Vec<String>>>, needle: &str, secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while !log_text(log).contains(needle) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

pub async fn events_of(state: &AppState, owner: AccessLogOwner, kind: &str) -> Vec<Value> {
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

/// Wait until an event of `kind` satisfies `pred`; returns it.
pub async fn wait_event(
    state: &AppState,
    owner: AccessLogOwner,
    kind: &str,
    secs: u64,
    pred: impl Fn(&Value) -> bool,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(e) = events_of(state, owner, kind).await.into_iter().find(&pred) {
            return Some(e);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A running in-process slave segment.
pub struct Segment {
    pub state: AppState,
    pub id: ServerId,
    pub addr: SocketAddr,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Segment {
    pub fn log_text(&self) -> String {
        log_text(&self.log)
    }
    pub async fn wait_for_log(&self, needle: &str) -> bool {
        wait_for(&self.log, needle, 30).await
    }
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Server(self.id.as_u32()), kind).await
    }
    pub async fn wait_event(&self, kind: &str, pred: impl Fn(&Value) -> bool) -> Option<Value> {
        wait_event(
            &self.state,
            AccessLogOwner::Server(self.id.as_u32()),
            kind,
            30,
            pred,
        )
        .await
    }
}

/// Start a slave segment on EtherCAT-in-UDP (loopback, OS-assigned port).
pub async fn start_segment_in(
    state: AppState,
    tx: mpsc::UnboundedSender<String>,
    log: Arc<Mutex<Vec<String>>>,
    handlers: Option<Vec<Value>>,
    mut params: Value,
) -> Segment {
    params["transport"] = json!("udp");
    let id = ServerForm {
        protocol: "ethercat".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an EtherCAT slave".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                if a.port() != 0 {
                    break a;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the EtherCAT slave never reported its address");
    Segment {
        state,
        id,
        addr,
        log,
    }
}

pub async fn start_segment(handlers: Option<Vec<Value>>, params: Value) -> Segment {
    let (state, tx, log) = new_state();
    start_segment_in(state, tx, log, handlers, params).await
}

/// A running in-process master.
pub struct Master {
    pub state: AppState,
    pub id: ClientId,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Master {
    pub fn log_text(&self) -> String {
        log_text(&self.log)
    }
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Client(self.id.as_u32()), kind).await
    }
    pub async fn wait_event(
        &self,
        kind: &str,
        secs: u64,
        pred: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        wait_event(
            &self.state,
            AccessLogOwner::Client(self.id.as_u32()),
            kind,
            secs,
            pred,
        )
        .await
    }
    pub async fn send(&self, action: Value) -> netget::state::client_handles::ClientSendOutcome {
        self.state
            .send_to_client(self.id, action, Duration::from_secs(60))
            .await
            .unwrap()
    }
}

pub async fn start_master_in(
    state: AppState,
    tx: mpsc::UnboundedSender<String>,
    log: Arc<Mutex<Vec<String>>>,
    remote: &str,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> anyhow::Result<Master> {
    let id = ClientForm {
        protocol: "EtherCAT".into(),
        remote_addr: Some(remote.into()),
        instruction: Some("Be an EtherCAT master".into()),
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
    Ok(Master { state, id, log })
}

/// A hand-built master on EtherCAT-in-UDP, keeping every payload (`true` = sent by it).
pub struct UdpMaster {
    pub sock: UdpSocket,
    pub slave: SocketAddr,
    pub payloads: Vec<(bool, Vec<u8>)>,
    idx: u8,
}

impl UdpMaster {
    pub async fn new(slave: SocketAddr) -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            slave,
            payloads: Vec::new(),
            idx: 0,
        }
    }

    pub async fn send_raw(&mut self, p: &[u8]) {
        self.payloads.push((true, p.to_vec()));
        self.sock.send_to(p, self.slave).await.unwrap();
    }

    pub async fn recv_raw(&mut self, ms: u64) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_millis(ms), self.sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        self.payloads.push((false, buf[..n].to_vec()));
        Some(buf[..n].to_vec())
    }

    /// One frame of datagrams, its answer decoded.
    pub async fn exchange(&mut self, mut dgs: Vec<Datagram>) -> Vec<Datagram> {
        self.idx = self.idx.wrapping_add(1);
        for d in dgs.iter_mut() {
            d.idx = self.idx;
        }
        let p = frame::encode(&dgs).unwrap();
        self.send_raw(&p).await;
        loop {
            let r = self.recv_raw(2000).await.expect("the slave did not answer");
            let back = frame::decode(&r).unwrap();
            if back[0].idx == self.idx {
                return back;
            }
        }
    }

    pub async fn one(&mut self, d: Datagram) -> Datagram {
        self.exchange(vec![d]).await.remove(0)
    }

    pub async fn fprd(&mut self, station: u16, ado: u16, len: usize) -> Datagram {
        self.one(Datagram::physical(cmd::FPRD, station, ado, vec![0; len]))
            .await
    }

    pub async fn fpwr(&mut self, station: u16, ado: u16, data: Vec<u8>) -> u16 {
        self.one(Datagram::physical(cmd::FPWR, station, ado, data))
            .await
            .wkc
    }

    pub async fn al_status(&mut self, station: u16) -> (u8, u16) {
        let d = self.fprd(station, 0x0130, 6).await;
        (d.data[0], u16::from_le_bytes([d.data[4], d.data[5]]))
    }

    /// Poll the AL status until it is not `from` (or `secs` pass).
    pub async fn wait_al_change(&mut self, station: u16, from: u8, secs: u64) -> (u8, u16) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let s = self.al_status(station).await;
            if s.0 != from || tokio::time::Instant::now() > deadline {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// ethercrab's frames, carried over EtherCAT-in-UDP: what it sends loses its Ethernet header
/// and goes to the slave as one UDP datagram; what comes back gets an Ethernet header with the
/// locally administered source address an ESC writes. Nothing else is touched — every octet of
/// every datagram is ethercrab's.
pub mod crab {
    use super::*;
    use ethercrab::{MainDevice, MainDeviceConfig, PduRx, PduStorage, PduTx, Timeouts};
    use std::future::poll_fn;
    use std::task::Poll;

    pub const MAX_FRAMES: usize = 16;
    pub const MAX_PDU_DATA: usize = PduStorage::element_size(1100);
    pub type Storage = PduStorage<MAX_FRAMES, MAX_PDU_DATA>;

    /// A MainDevice whose frames reach `slave` over UDP. The returned list is every payload
    /// both ways (`true` = from ethercrab).
    pub fn main_device(
        slave: SocketAddr,
    ) -> (
        Arc<MainDevice<'static>>,
        Arc<Mutex<Vec<(bool, Vec<u8>)>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let storage: &'static Storage = Box::leak(Box::new(PduStorage::new()));
        let (tx, rx, pdu_loop) = storage.try_split().expect("split once");
        let md = Arc::new(MainDevice::new(
            pdu_loop,
            Timeouts {
                state_transition: Duration::from_secs(20),
                pdu: Duration::from_millis(200),
                eeprom: Duration::from_millis(200),
                mailbox_response: Duration::from_secs(10),
                ..Default::default()
            },
            MainDeviceConfig {
                dc_static_sync_iterations: 0,
                ..MainDeviceConfig::default()
            },
        ));
        let record = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(bridge(tx, rx, slave, record.clone()));
        (md, record, task)
    }

    async fn bridge(
        mut tx: PduTx<'static>,
        mut rx: PduRx<'static>,
        slave: SocketAddr,
        record: Arc<Mutex<Vec<(bool, Vec<u8>)>>>,
    ) {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_sock.connect(slave).unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let send = std_sock.try_clone().unwrap();
        let recv = UdpSocket::from_std(std_sock).unwrap();
        let rec_tx = record.clone();
        let sender = poll_fn(move |cx| {
            tx.replace_waker(cx.waker());
            while let Some(f) = tx.next_sendable_frame() {
                let _ = f.send_blocking(|eth| {
                    let payload = &eth[14..];
                    rec_tx.lock().unwrap().push((true, payload.to_vec()));
                    send.send(payload)
                        .map_err(|_| ethercrab::error::Error::SendFrame)?;
                    Ok(eth.len())
                });
            }
            Poll::<()>::Pending
        });
        let receiver = async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok(n) = recv.recv(&mut buf).await else {
                    continue;
                };
                record.lock().unwrap().push((false, buf[..n].to_vec()));
                let mut eth = vec![0xFF; 6];
                eth.extend_from_slice(&[0x12, 0x10, 0x10, 0x10, 0x10, 0x10]);
                eth.extend_from_slice(&frame::ETHERTYPE.to_be_bytes());
                eth.extend_from_slice(&buf[..n]);
                let _ = rx.receive_frame(&eth);
            }
        };
        tokio::join!(sender, receiver);
    }
}
