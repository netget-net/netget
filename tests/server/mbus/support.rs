//! Shared harness for the M-Bus slave suites: an in-process gateway with a python script
//! playing the model, and a raw master that writes telegrams and collects every byte that
//! comes back within a window.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::server::mbus::frame::{self, Frame};
use netget::server::mbus::records;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The meters the suites put behind the gateway: a Kamstrup heat meter at 1 and an Elster
/// water meter at 2 whose identification numbers differ only in the last digit, so a mask
/// with that digit wildcarded matches both.
pub fn meters() -> Value {
    json!([
        {"primary_address": 1, "id": "12345678", "manufacturer": "KAM", "version": 1, "medium": "heat"},
        {"primary_address": 2, "id": "12345679", "manufacturer": "ELS", "version": 2, "medium": "water"}
    ])
}

pub const HEAT: &str = "123456782D2C0104";
pub const WATER: &str = "1234567993150207";

/// The model, as a python script. The heat meter reports energy (kWh, an integer coding),
/// volume (m3, BCD), flow temperature (°C) and last period's energy (storage 1, tariff 1)
/// with its date; the water meter a volume in litres as a real and a negative BCD value
/// (a reverse-flow counter). A meter whose id ends in 9 refuses writes; the other accepts
/// them. Application resets are accepted. The readout counter in the event's fcb is not
/// used: every REQ_UD2 that reaches the model is a fresh readout.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
m=e.get('meter',{})
a=[]
if t=='mbus_request_data':
  if m.get('id')=='12345678':
    a=[{'type':'mbus_respond_data','records':[
      {'quantity':'energy','unit':'kWh','value':12345},
      {'quantity':'volume','unit':'m3','value':456.789,'encoding':'bcd'},
      {'quantity':'flow_temperature','unit':'°C','value':65.4},
      {'quantity':'energy','unit':'kWh','value':11000,'storage':1,'tariff':1},
      {'quantity':'date','value':'2026-09-30','storage':1}]}]
  else:
    a=[{'type':'mbus_respond_data','status':['power_low'],'records':[
      {'quantity':'volume','unit':'l','value':1234.5,'encoding':'real'},
      {'quantity':'volume','unit':'l','value':-42,'encoding':'bcd','function':'error'}]}]
elif t=='mbus_write_data':
  a=[{'type':'mbus_no_response','reason':'read-only'}] if m.get('id','').endswith('9') else [{'type':'mbus_acknowledge'}]
elif t=='mbus_application_reset':
  a=[{'type':'mbus_acknowledge'}]
print(json.dumps({'actions':a}))"#;

/// A readout of 120 energy records (storage 0-119), more than one telegram holds, counted in
/// whole Wh (`resolution` 1) as a meter with a fixed step would.
pub const BIG_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[]
if t=='mbus_request_data':
  a=[{'type':'mbus_respond_data','records':[{'quantity':'energy','unit':'Wh','value':1000+n,'storage':n,'encoding':'int32','resolution':1} for n in range(120)]}]
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

/// A running in-process gateway and everything it printed.
pub struct Gateway {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Gateway {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    pub async fn wait_for_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !self.log_text().contains(needle) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Every event of `kind` the gateway raised, oldest first, as the model saw it.
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

    pub fn addr(&self) -> std::net::SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    pub async fn master(&self) -> RawMaster {
        RawMaster::connect(self.addr()).await
    }
}

/// Start a gateway. `handlers` is the routing table (a python policy, a static rule, or `None`
/// to send every event to a model that is not there).
pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> Gateway {
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
        protocol: "mbus".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be the meters".into()),
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
    .expect("the M-Bus gateway never reported its address");
    Gateway {
        state,
        id,
        port,
        log,
    }
}

pub fn params() -> Value {
    json!({"meters": meters()})
}

/// A raw master: it writes telegrams and reads back whatever arrives.
pub struct RawMaster {
    pub stream: TcpStream,
    /// Every byte written and read, in order, as `(to_gateway, bytes)`.
    pub chunks: Vec<(bool, Vec<u8>)>,
}

impl RawMaster {
    pub async fn connect(addr: std::net::SocketAddr) -> RawMaster {
        let stream = TcpStream::connect(addr)
            .await
            .expect("connect to the gateway");
        stream.set_nodelay(true).unwrap();
        RawMaster {
            stream,
            chunks: Vec::new(),
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
        self.chunks.push((true, bytes.to_vec()));
    }

    pub async fn send(&mut self, f: &Frame) {
        let bytes = f.encode().unwrap();
        self.write(&bytes).await;
    }

    /// Everything that arrives until `quiet` passes with nothing new, or `total` runs out.
    /// Waits up to `total` for the first byte.
    pub async fn collect(&mut self, total: Duration, quiet: Duration) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + total;
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let wait = if out.is_empty() {
                deadline.saturating_duration_since(tokio::time::Instant::now())
            } else {
                quiet
            };
            match tokio::time::timeout(wait, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break,
            }
            if tokio::time::Instant::now() > deadline {
                break;
            }
        }
        if !out.is_empty() {
            self.chunks.push((false, out.clone()));
        }
        out
    }

    /// Send a telegram and return every whole telegram that answers it.
    pub async fn ask(&mut self, f: &Frame) -> Vec<Frame> {
        self.send(f).await;
        let bytes = self
            .collect(Duration::from_secs(20), Duration::from_millis(300))
            .await;
        let (frames, errors) = frame::parse_all(&bytes);
        assert!(errors.is_empty(), "broken answer {bytes:02x?}: {errors:?}");
        frames
    }

    /// Send a telegram and expect silence for `wait`.
    pub async fn expect_silence(&mut self, f: &Frame, wait: Duration) {
        self.send(f).await;
        let bytes = self.collect(wait, Duration::from_millis(100)).await;
        assert!(bytes.is_empty(), "expected no answer, got {bytes:02x?}");
    }

    pub async fn req_ud2(&mut self, a: u8, fcb: bool) -> Vec<Frame> {
        self.ask(&Frame::Short {
            c: frame::c::REQ_UD2 | if fcb { frame::c::FCB } else { 0 },
            a,
        })
        .await
    }

    pub async fn snd_nke(&mut self, a: u8) -> Vec<Frame> {
        self.ask(&Frame::Short {
            c: frame::c::SND_NKE,
            a,
        })
        .await
    }

    pub async fn select(&mut self, mask: &str) -> Vec<Frame> {
        self.ask(&select_frame(mask)).await
    }
}

pub fn select_frame(mask: &str) -> Frame {
    Frame::Long {
        c: frame::c::SND_UD | frame::c::FCB,
        a: frame::addr::NETWORK_LAYER,
        ci: frame::ci::SELECT,
        data: frame::mask_from_hex(mask).unwrap().to_vec(),
    }
}

/// The header and records of one RSP_UD.
pub fn decode(f: &Frame) -> (records::Header, records::Decoded) {
    match f {
        Frame::Long { c, ci, data, .. } => {
            assert_eq!(
                frame::c::function(*c),
                frame::c::RSP_UD,
                "not a RSP_UD: {f:?}"
            );
            records::decode_response(*ci, data).unwrap()
        }
        other => panic!("expected a RSP_UD long frame, got {other:?}"),
    }
}

/// Wait until `needle` appears in the gateway's log, failing with the log otherwise.
pub async fn expect_log(g: &Gateway, needle: &str) {
    assert!(
        g.wait_for_log(needle).await,
        "the gateway never logged {needle:?}:\n{}",
        g.log_text()
    );
}
