//! Harness for the PROFINET controller suites: an in-process controller (and, for the lab
//! suite, an in-process device beside it) with python policies standing in for the model.
#![allow(dead_code)]

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

pub type Log = Arc<Mutex<Vec<String>>>;

pub fn new_state() -> (AppState, mpsc::UnboundedSender<String>, Log) {
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

pub fn text(log: &Log) -> String {
    log.lock().unwrap().join("\n")
}

pub async fn wait_for(log: &Log, needle: &str, secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while !text(log).contains(needle) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

pub async fn events(state: &AppState, owner: AccessLogOwner, kind: &str) -> Vec<Value> {
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

/// Wait until an event of `kind` satisfies `pred`; return every event of that kind.
pub async fn wait_until(
    state: &AppState,
    owner: AccessLogOwner,
    kind: &str,
    secs: u64,
    pred: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let v = events(state, owner, kind).await;
        if v.iter().any(&pred) || tokio::time::Instant::now() > deadline {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Start a device on the lab transport; returns its id and lab link address.
pub async fn start_lab_device(
    state: &AppState,
    tx: mpsc::UnboundedSender<String>,
    log: &Log,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> (ServerId, SocketAddr) {
    let mut params = params;
    params["transport"] = json!("udp");
    let before = text(log).matches("PROFINET lab link").count();
    let id = ServerForm {
        protocol: "profinet".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a PROFINET IO device".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .unwrap();
    let lab = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let t = text(log);
            if t.matches("PROFINET lab link").count() > before {
                let line = t
                    .lines()
                    .filter(|l| l.contains("PROFINET lab link"))
                    .last()
                    .unwrap()
                    .to_string();
                break line
                    .rsplit("on ")
                    .next()
                    .unwrap()
                    .trim()
                    .parse::<SocketAddr>()
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the device never reported its lab link");
    (id, lab)
}

pub async fn start_controller(
    state: &AppState,
    tx: mpsc::UnboundedSender<String>,
    remote: &str,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> anyhow::Result<ClientId> {
    ClientForm {
        protocol: "PROFINET".into(),
        remote_addr: Some(remote.into()),
        instruction: Some("Be a PROFINET IO controller".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
}
