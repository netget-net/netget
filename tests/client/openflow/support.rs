//! Shared harness for the OpenFlow switch suites: NetGet's switch with a python policy playing
//! the model, and helpers to read what it raised.
#![allow(dead_code)]

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub const HOST_A: &str = "02:00:00:00:00:01";
pub const HOST_B: &str = "02:00:00:00:00:02";

/// The model, as a python script: once the controller's table-miss flow arrives, HOST_A
/// pings HOST_B through port 1; the first PACKET_OUT (the controller flooding the unknown
/// destination) is answered by HOST_B's reply through port 2. Nothing else is answered.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
def ping(port, src, dst, sip, dip, typ):
  return {'type':'openflow_packet_in','in_port':port,'packet':{'eth_src':src,'eth_dst':dst,
    'ipv4':{'src':sip,'dst':dip},'icmp':{'type':typ,'id':1,'seq':1},'payload_text':'netget switch'}}
a=[]
if t=='openflow_flow_mod_received' and e['priority']==0 and e['command']=='add':
  a=[ping(1,'02:00:00:00:00:01','02:00:00:00:00:02','10.0.0.1','10.0.0.2',8)]
elif t=='openflow_packet_out_received' and e['packet'].get('eth_dst')=='02:00:00:00:00:02':
  a=[ping(2,'02:00:00:00:00:02','02:00:00:00:00:01','10.0.0.2','10.0.0.1',0)]
print(json.dumps({'actions':a}))"#;

pub fn policy() -> Vec<Value> {
    vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": POLICY}
    })]
}

pub fn quiet() -> Vec<Value> {
    vec![json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}})]
}

pub struct Switch {
    pub state: AppState,
    pub id: ClientId,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Switch {
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

    /// Every event of `kind` the switch raised, oldest first, as the model saw it.
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        let mut v: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Client(self.id.as_u32())), None)
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

    pub async fn send(&self, action: Value) -> netget::state::client_handles::ClientSendOutcome {
        self.state
            .send_to_client(self.id, action, Duration::from_secs(30))
            .await
            .unwrap()
    }
}

/// NetGet's switch, connected to `addr`. `llm` is the model endpoint (an unreachable one for
/// the fail-closed tests).
pub async fn connect(
    addr: &str,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> anyhow::Result<Switch> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    let id = ClientForm {
        protocol: "OpenFlow".into(),
        remote_addr: Some(addr.into()),
        instruction: Some("Be a switch".into()),
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
    Ok(Switch { state, id, log })
}

pub fn params() -> Value {
    json!({
        "datapath_id": "0000000000000abc",
        "ports": [
            {"port_no": 1, "name": "eth1", "hw_addr": "02:aa:00:00:00:01"},
            {"port_no": 2, "name": "eth2", "hw_addr": "02:aa:00:00:00:02"}
        ]
    })
}
