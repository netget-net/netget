//! Shared harness for the NVMe/TCP host suites: a client whose model is a python policy (the
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
        protocol: "nvme_tcp".into(),
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
    wait_event(state, id, "nvme_tcp_command_result", n - 1).await;
    client_events(state, id, "nvme_tcp_command_result").await
}

/// The model for a whole session: read the discovery log, connect to its first NVM subsystem
/// (a log may list itself as the current discovery subsystem first) (or
/// straight to the configured one when the log is skipped), identify namespace NSID, read block
/// 0, write `WRITE_TEXT` to block 100, read it back, read the health log, flush, disconnect.
pub const SESSION_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
NS=1
a=[]
if t=='nvme_tcp_connected':
  a=[{'type':'nvme_tcp_discover'}]
elif t=='nvme_tcp_discovery_log':
  nvm=[x for x in e['entries'] if x['subsystem_type']=='nvme subsystem']
  if nvm:
    a=[{'type':'nvme_tcp_connect','subsystem_nqn':nvm[0]['subsystem_nqn']}]
elif t=='nvme_tcp_connect_result' and e['connected']:
  a=[{'type':'nvme_tcp_identify_namespace','nsid':NS}]
elif t=='nvme_tcp_command_result':
  op=e['operation']
  if op=='identify_namespace':
    a=[{'type':'nvme_tcp_read','nsid':NS,'lba':0,'blocks':1}]
  elif op=='read' and e.get('lba')==0:
    a=[{'type':'nvme_tcp_write','nsid':NS,'lba':100,'data':'written by the netget host','encoding':'utf8'}]
  elif op=='write':
    a=[{'type':'nvme_tcp_read','nsid':NS,'lba':100,'blocks':1}]
  elif op=='read' and e.get('lba')==100:
    a=[{'type':'nvme_tcp_get_log_page','page':'smart'}]
  elif op=='get_log_page':
    a=[{'type':'nvme_tcp_flush','nsid':NS}]
  elif op=='flush':
    a=[{'type':'nvme_tcp_disconnect'}]
print(json.dumps({'actions':a}))"#;

pub const WRITE_TEXT: &str = "written by the netget host";

/// [`SESSION_POLICY`] connecting straight to the configured `subsystem_nqn`.
pub fn connect_first_policy() -> String {
    SESSION_POLICY.replace(
        "a=[{'type':'nvme_tcp_discover'}]",
        "a=[{'type':'nvme_tcp_connect'}]",
    )
}

/// [`SESSION_POLICY`] against another namespace.
pub fn session_policy(nsid: u32) -> String {
    SESSION_POLICY.replace("NS=1", &format!("NS={nsid}"))
}
