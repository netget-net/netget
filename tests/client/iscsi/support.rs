//! Shared harness for the iSCSI initiator suites: a client whose model is a python policy (the
//! LLM endpoint is unreachable, so an event the policy does not answer fails closed), and the
//! events it raised.
#![allow(dead_code)]

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

pub fn chain(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub async fn client(
    remote: String,
    params: Value,
    handlers: Option<Vec<Value>>,
) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "iscsi".into(),
        remote_addr: Some(remote),
        instruction: Some("Use the storage as you are asked".into()),
        startup_params: Some(params),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok((state, id))
}

/// Every event of a type the client raised, oldest first.
pub async fn client_events(state: &AppState, id: ClientId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all
}

/// Wait for the `nth` (from 0) event of a type.
pub async fn wait_event(state: &AppState, id: ClientId, event_type: &str, nth: usize) -> Value {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(e) = client_events(state, id, event_type).await.get(nth) {
                return e.clone();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {event_type} #{nth}: was the model's action dropped?"))
}

/// The command results, waiting until there are `n`.
pub async fn results(state: &AppState, id: ClientId, n: usize) -> Vec<Value> {
    wait_event(state, id, "iscsi_command_result", n - 1).await;
    client_events(state, id, "iscsi_command_result").await
}

/// The model for a whole session: log in (to `target`, or the first discovered target), list
/// the LUNs, ask LUN 0 what it is and how big, read block 0, write `WRITE_TEXT` to block 100,
/// read it back, log out.
pub const SESSION_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='iscsi_connected':
  a=[{'type':'iscsi_discover'}]
elif t=='iscsi_targets':
  if e['targets']:
    a=[{'type':'iscsi_login','target_name':e['targets'][0]['name']}]
elif t=='iscsi_login_result' and e['logged_in']:
  a=[{'type':'iscsi_report_luns'}]
elif t=='iscsi_command_result':
  op=e['operation']
  if op=='report_luns':
    a=[{'type':'iscsi_inquiry','lun':0}]
  elif op=='inquiry':
    a=[{'type':'iscsi_read_capacity','lun':0}]
  elif op=='read_capacity':
    a=[{'type':'iscsi_read','lun':0,'lba':0,'blocks':1}]
  elif op=='read' and e.get('lba')==0:
    a=[{'type':'iscsi_write','lun':0,'lba':100,'data':'written by the netget initiator','encoding':'utf8'}]
  elif op=='write':
    a=[{'type':'iscsi_read','lun':0,'lba':100,'blocks':1}]
  elif op=='read' and e.get('lba')==100:
    a=[{'type':'iscsi_logout'}]
print(json.dumps({'actions':a}))"#;

pub const WRITE_TEXT: &str = "written by the netget initiator";

/// [`SESSION_POLICY`] logging straight in to the configured `target_name`, without discovery.
pub fn login_first_policy() -> String {
    SESSION_POLICY.replace(
        "a=[{'type':'iscsi_discover'}]",
        "a=[{'type':'iscsi_login'}]",
    )
}

/// [`SESSION_POLICY`] against another LUN (tgt's LUN 0 is its controller).
pub fn session_policy(lun: u16) -> String {
    SESSION_POLICY.replace("'lun':0", &format!("'lun':{lun}"))
}
