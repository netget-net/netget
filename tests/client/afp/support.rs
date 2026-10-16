//! Shared harness for the AFP client suites: NetGet's client with a python policy playing the
//! model, NetGet's own AFP server as a regression peer, and helpers to read what each raised.
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

pub struct Client {
    pub state: AppState,
    pub id: ClientId,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Client {
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

/// NetGet's AFP client, connected to `addr`. `Err` carries why the connect failed.
pub async fn try_connect(
    addr: &str,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> Result<Client, String> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, log) = sink();
    let id = ClientForm {
        protocol: "AFP".into(),
        remote_addr: Some(addr.into()),
        instruction: Some("Browse the file server".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .map_err(|e| format!("{e:#}"))?;
    Ok(Client { state, id, log })
}

pub async fn connect(addr: &str, handlers: Option<Vec<Value>>, params: Value) -> Client {
    try_connect(addr, handlers, params)
        .await
        .expect("the AFP client connects")
}

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

/// The client's model for a whole tour of volume `share` (netatalk names a volume after its
/// lower-cased section; NetGet's server matches volume names without regard to case): list the volumes, list the root,
/// read hello.txt and bin.dat, describe `sub`, write written.txt, create `made`, delete
/// todelete.txt, then list `sub`.
pub const TOUR: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='afp_connected':
  a=[{'type':'afp_list_volumes'}]
elif t=='afp_volumes':
  a=[{'type':'afp_list_directory','volume':'share','path':''}]
elif t=='afp_directory' and e['path']=='':
  a=[{'type':'afp_read_file','volume':'share','path':'hello.txt'},
     {'type':'afp_read_file','volume':'share','path':'bin.dat'},
     {'type':'afp_get_info','volume':'share','path':'sub'}]
elif t=='afp_file' and e['path']=='hello.txt':
  a=[{'type':'afp_write_file','volume':'share','path':'written.txt','content':'written by NetGet\n'}]
elif t=='afp_done' and e['operation']=='afp_write_file':
  a=[{'type':'afp_create_directory','volume':'share','path':'made'}]
elif t=='afp_done' and e['operation']=='afp_create_directory':
  a=[{'type':'afp_delete','volume':'share','path':'todelete.txt'}]
elif t=='afp_done' and e['operation']=='afp_delete':
  a=[{'type':'afp_list_directory','volume':'share','path':'sub'}]
print(json.dumps({'actions':a}))"#;

/// NetGet's own AFP server: the regression peer, never the evidence.
pub struct Server {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Server {
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Server(self.id.as_u32()), kind).await
    }
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }
}

/// The server side's model: volume Share holding hello.txt, bin.dat, todelete.txt and sub/;
/// every create, write and delete allowed except anything named `deny*`.
pub const SERVER_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='afp_list_directory':
  if e['path']=='':
    a=[{'type':'afp_directory_listing','entries':[
      {'name':'hello.txt','type':'file','size':20},
      {'name':'bin.dat','type':'file','size':4},
      {'name':'todelete.txt','type':'file','size':1},
      {'name':'sub','type':'directory'}]}]
  else:
    a=[{'type':'afp_directory_listing','entries':[{'name':'inner.txt','type':'file','size':3}]}]
elif t=='afp_read_file':
  if e['path']=='bin.dat':
    a=[{'type':'afp_file_content','content':'000102ff','encoding':'hex'}]
  else:
    a=[{'type':'afp_file_content','content':'hello from netatalk\n'}]
elif e.get('path','').split('/')[-1].startswith('deny'):
  a=[{'type':'afp_deny','error':'access_denied'}]
else:
  a=[{'type':'afp_allow'}]
print(json.dumps({'actions':a}))"#;

pub async fn server(params: Value) -> Server {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, log) = sink();
    let id = ServerForm {
        protocol: "afp".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a file server".into()),
        event_handlers: script(SERVER_POLICY),
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
    .expect("the AFP server started");
    Server {
        state,
        id,
        port,
        log,
    }
}
