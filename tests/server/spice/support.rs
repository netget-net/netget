//! Shared harness for the SPICE server suites: an in-process server with a python policy
//! standing in for the model, NetGet's own SPICE client for the in-process checks, and the
//! colours the policy draws so a test can look for them in whatever a client rendered.
#![allow(dead_code)]

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub const PASSWORD: &str = "spice-Pw-31";
pub const WIDTH: u32 = 640;
pub const HEIGHT: u32 = 400;
/// The policy's background, and the panel it draws at (PANEL_X, PANEL_Y) PANEL_W x PANEL_H.
pub const BACKGROUND: [u8; 3] = [0x1e, 0x29, 0x3b];
pub const PANEL: [u8; 3] = [0x38, 0xbd, 0xf8];
/// The panel's colour once the model has seen the key `x`.
pub const PANEL_AFTER_X: [u8; 3] = [0x16, 0xa3, 0x4a];
/// The panel's colour after a left click.
pub const PANEL_AFTER_CLICK: [u8; 3] = [0xf9, 0x73, 0x16];
pub const PANEL_X: u32 = 80;
pub const PANEL_Y: u32 = 120;
pub const PANEL_W: u32 = 300;
pub const PANEL_H: u32 = 160;

/// The model, as a python script: admit everyone and draw the panel; a key `x` turns it green,
/// a left click orange, any other key leaves the screen alone; every key and click is also
/// recorded in the text line, so a run can be read off the screen.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
def screen(panel, line):
  return {'type':'spice_render_display','commands':[
    {'type':'background','color':'#1e293b'},
    {'type':'rectangle','x':80,'y':120,'width':300,'height':160,'color':panel,'filled':True},
    {'type':'text','x':20,'y':40,'text':line,'size':24,'color':'white'}]}
a=[]
if t=='spice_connection_request':
  a=[{'type':'spice_accept_connection'},screen('#38bdf8','Welcome to NetGet SPICE'),{'type':'spice_notify','message':'welcome','severity':'info'}]
elif t=='spice_display_ready':
  a=[screen('#38bdf8','Welcome to NetGet SPICE')]
elif t=='spice_key_event':
  if e['key']=='x':
    a=[screen('#16a34a','You typed x')]
  else:
    a=[{'type':'spice_no_change'}]
elif t=='spice_mouse_event':
  if e['button']=='left':
    a=[screen('#f97316','Clicked at %d,%d' % (e['x'], e['y']))]
  else:
    a=[{'type':'spice_no_change'}]
print(json.dumps({'actions':a}))"#;

pub fn policy() -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": POLICY}
    })])
}

pub fn params() -> Value {
    json!({"password": PASSWORD, "width": WIDTH, "height": HEIGHT, "name": "NetGet test desktop"})
}

/// A running in-process SPICE server and everything it printed.
pub struct Spice {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Spice {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    /// Wait until the server's status stream contains `needle`.
    pub async fn wait_for_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !self.log_text().contains(needle) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Every event of `kind` the server raised, oldest first.
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
        v
    }

    /// Wait until at least `n` events of `kind` were raised; returns them.
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

    pub fn addr(&self) -> std::net::SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }
}

/// Start a server. `handlers` is the routing table (the python policy, a static rule, or
/// `None` to send every event to a model that is not there).
pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> Spice {
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
        protocol: "spice".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a remote desktop".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the SPICE server never reported its address");
    Spice {
        state,
        id,
        port,
        log,
    }
}

/// NetGet's own SPICE client, connected with `password`, every event answered with nothing so
/// the test drives it. Err when the connection was refused.
pub async fn netget_client(
    addr: std::net::SocketAddr,
    password: &str,
) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "SPICE".into(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Look at the display".into()),
        event_handlers: Some(vec![
            json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}}),
        ]),
        startup_params: Some(json!({"password": password})),
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

/// Send an action through a NetGet client and return its outcome detail.
pub async fn send(state: &AppState, id: ClientId, action: Value) -> Value {
    let outcome = state
        .send_to_client(id, action, Duration::from_secs(30))
        .await
        .unwrap();
    match outcome {
        ClientSendOutcome::Executed { detail } => {
            serde_json::from_str(&detail).unwrap_or(json!({"detail": detail}))
        }
        other => panic!("{other:?}"),
    }
}

/// Read the client's screen, sampling the panel's centre and a background corner.
pub async fn read_screen(state: &AppState, id: ClientId) -> Value {
    send(
        state,
        id,
        json!({"type": "spice_read_screen", "grid": 4, "settle_ms": 300,
               "points": [[PANEL_X + PANEL_W / 2, PANEL_Y + PANEL_H / 2], [WIDTH - 5, HEIGHT - 5]]}),
    )
    .await
}

pub fn hex(rgb: [u8; 3]) -> String {
    format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])
}

/// Every event of `kind` a client raised, oldest first.
pub async fn client_events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect()
}

/// Wait for a client event of `kind` whose request satisfies `pred`.
pub async fn wait_client_event(
    state: &AppState,
    id: ClientId,
    kind: &str,
    pred: impl Fn(&Value) -> bool,
) -> Option<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(e) = client_events(state, id, kind)
                .await
                .into_iter()
                .find(|e| pred(&e["request"]))
            {
                return e["request"].clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .ok()
}

/// Wait until a reading of the client's screen shows `rgb` at the panel's centre.
pub async fn wait_for_panel(state: &AppState, id: ClientId, rgb: [u8; 3]) -> Value {
    let want = hex(rgb);
    let mut last = Value::Null;
    for _ in 0..40 {
        last = read_screen(state, id).await;
        if last["points"][0]["color"] == want.as_str() {
            return last;
        }
    }
    panic!("the panel never turned {want}; last reading {last}");
}
