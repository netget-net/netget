//! Shared harness for the M-Bus master suites: NetGet's master with a python policy playing
//! the model, NetGet's own gateway as a regression peer, and helpers to read what each raised.
#![allow(dead_code)]

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

fn sink() -> (mpsc::UnboundedSender<String>, Arc<Mutex<Vec<String>>>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let s = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            s.lock().unwrap().push(line);
        }
    });
    (tx, log)
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

pub struct Master {
    pub state: AppState,
    pub id: ClientId,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Master {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Client(self.id.as_u32()), kind).await
    }

    /// Wait until at least `n` events of `kind` were raised; returns them.
    pub async fn wait_for_events(&self, kind: &str, n: usize, secs: u64) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let v = self.events(kind).await;
            if v.len() >= n || tokio::time::Instant::now() > deadline {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn send(&self, action: Value) -> netget::state::client_handles::ClientSendOutcome {
        self.state
            .send_to_client(self.id, action, Duration::from_secs(30))
            .await
            .unwrap()
    }
}

/// NetGet's master, connected to `addr`, with `handlers` as its routing table.
pub async fn connect(addr: &str, handlers: Option<Vec<Value>>, timeout_ms: u64) -> Master {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, log) = sink();
    let id = ClientForm {
        protocol: "M-Bus".into(),
        remote_addr: Some(addr.into()),
        instruction: Some("Read the meters".into()),
        event_handlers: handlers,
        startup_params: Some(json!({"response_timeout_ms": timeout_ms})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("the M-Bus master connects");
    Master { state, id, log }
}

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

/// NetGet's own gateway: the regression peer, never the evidence.
pub struct Gateway {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Gateway {
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Server(self.id.as_u32()), kind).await
    }
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
    /// Wait until at least `n` events of `kind` were raised; returns them.
    pub async fn wait_for_events(&self, kind: &str, n: usize, secs: u64) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let v = self.events(kind).await;
            if v.len() >= n || tokio::time::Instant::now() > deadline {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }
}

/// The slave side's model: each meter reports its id's last digit as kWh and a volume; meters
/// whose id ends in 9 refuse writes. `BIG` makes meter 12345678 answer 120 records.
pub const SLAVE_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
m=e.get('meter',{})
a=[]
if t=='mbus_request_data':
  if m.get('id')=='00000777':
    a=[{'type':'mbus_respond_data','records':[{'quantity':'energy','unit':'Wh','value':1000+n,'storage':n,'encoding':'int32'} for n in range(120)]}]
  else:
    a=[{'type':'mbus_respond_data','records':[
      {'quantity':'energy','unit':'kWh','value':int(m['id'][-1])},
      {'quantity':'volume','unit':'m3','value':12.5,'encoding':'bcd'}]}]
elif t=='mbus_write_data':
  a=[{'type':'mbus_no_response'}] if m.get('id','').endswith('9') else [{'type':'mbus_acknowledge'}]
elif t=='mbus_application_reset':
  a=[{'type':'mbus_acknowledge'}]
print(json.dumps({'actions':a}))"#;

pub fn meters() -> Value {
    json!([
        {"primary_address": 1, "id": "12345678", "manufacturer": "KAM", "version": 1, "medium": "heat"},
        {"primary_address": 2, "id": "12345679", "manufacturer": "ELS", "version": 2, "medium": "water"},
        {"primary_address": 4, "id": "00000777", "manufacturer": "NGT", "version": 1, "medium": "electricity"}
    ])
}

pub async fn gateway(meters: Value) -> Gateway {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, log) = sink();
    let id = ServerForm {
        protocol: "mbus".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be the meters".into()),
        event_handlers: script(SLAVE_POLICY),
        startup_params: Some(json!({"meters": meters})),
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
    .expect("the gateway started");
    Gateway {
        state,
        id,
        port,
        log,
    }
}
