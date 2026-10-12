//! EPP fixtures: a registry handler, server and client through the shared forms, pyepp
//! (`tests/server/epp/peer.py`), the epp-lib registry (`tests/server/epp/registry/`) and raw
//! framed exchanges.
// Shared by the server and client test binaries; each uses a different subset.
#![allow(dead_code)]
use netget::{
    cli::management::{ClientForm, ServerForm},
    state::{app_state::AppState, AccessLogOwner, ClientId, ClientStatus, ServerId},
};
use serde_json::{json, Value};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

pub(crate) fn state() -> AppState {
    AppState::new_with_options(false, "http://127.0.0.1:1".into())
}

/// taken.example belongs to OtherReg (transfer password move-me-1); everything else is free.
pub(crate) const REGISTRY: &str = r#"import json,sys
i=json.load(sys.stdin); e=i['event']; c=e['command']; o=e['object']; f=e['fields']
def out(*a): print(json.dumps({'actions':list(a)})); sys.exit()
TAKEN={'taken.example'}
NOW='2026-10-04T12:00:00.0Z'
if c=='check': out({'type':'epp_check_result','results':[{'name':n,'available':n not in TAKEN,'reason':'In use' if n in TAKEN else None} for n in f['names']]})
if c=='create' and o=='contact': out({'type':'epp_created','id':f['id'],'cr_date':NOW})
if c=='create' and o=='host': out({'type':'epp_created','name':f['name'],'cr_date':NOW})
if c=='create' and o=='domain':
    if f['name'] in TAKEN: out({'type':'epp_result','code':2302})
    out({'type':'epp_created','name':f['name'],'cr_date':NOW,'ex_date':'2028-10-04T12:00:00.0Z'})
if c=='info' and o=='domain':
    if f['name'] not in TAKEN: out({'type':'epp_result','code':2303,'reason':'No such domain'})
    out({'type':'epp_info','info':{'name':'taken.example','roid':'TAKEN1-REP','status':['clientTransferProhibited'],'registrant':'other-1','contacts':[{'type':'admin','id':'other-1'}],'ns':['ns1.other.example'],'cl_id':'OtherReg','cr_date':'2020-01-02T03:04:05.0Z','ex_date':'2030-01-02T03:04:05.0Z'}})
if c=='renew': out({'type':'epp_renewed','name':f['name'],'ex_date':'2029-10-04T12:00:00.0Z'})
if c=='transfer':
    if f.get('auth_info')!='move-me-1': out({'type':'epp_result','code':2202,'reason':'Wrong authInfo'})
    out({'type':'epp_transfer_status','name':f['name'],'tr_status':'pending','re_id':e['client_id'],'re_date':NOW,'ac_id':'OtherReg','ac_date':'2026-10-09T12:00:00.0Z','code':1001})
if c=='delete': out({'type':'epp_result','code':1500})
out({'type':'epp_result','code':2101})
"#;

pub(crate) fn script(code: &str) -> Vec<Value> {
    vec![
        json!({"event_pattern": "*", "handler": {"type":"script","language":"python","code": code}}),
    ]
}

pub(crate) fn registrar() -> Value {
    json!({"clients": {"registrar1": "secret-pw-1"}})
}

pub(crate) async fn server_with(
    state: &AppState,
    handlers: Option<Vec<Value>>,
    params: Value,
) -> (ServerId, SocketAddr) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let id = ServerForm {
        protocol: "epp".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    (id, addr)
}

pub(crate) async fn server_in(state: &AppState, params: Value) -> (ServerId, SocketAddr) {
    server_with(state, Some(script(REGISTRY)), params).await
}

/// The self-signed certificate the server published, written where a client can trust it.
pub(crate) async fn certificate(state: &AppState, id: ServerId, dir: &Path) -> String {
    let pem = state.get_server(id).await.unwrap().protocol_data["certificate_pem"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = dir.join("epp-ca.pem");
    std::fs::write(&path, pem).unwrap();
    path.to_str().unwrap().to_owned()
}

pub(crate) async fn client_in(
    state: &AppState,
    remote: String,
    handlers: Vec<Value>,
    params: Value,
) -> anyhow::Result<ClientId> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let id = ClientForm {
        protocol: "epp".into(),
        remote_addr: Some(remote),
        instruction: Some(String::new()),
        event_handlers: Some(handlers),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        while !state.has_client_handle(id).await {
            if let Some(ClientStatus::Error(e)) = state.get_client(id).await.map(|c| c.status) {
                anyhow::bail!(e);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("EPP client did not connect"))??;
    Ok(id)
}

pub(crate) async fn wait_for(
    state: &AppState,
    owner: AccessLogOwner,
    kind: &str,
    want: impl Fn(&Value) -> bool,
) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(e) = state
                .list_access_logs_for(Some(owner), None)
                .await
                .into_iter()
                .find(|e| e.event_type == kind && want(&e.request))
            {
                break e.request;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    match found {
        Ok(v) => v,
        Err(_) => {
            let seen: Vec<String> = state
                .list_access_logs_for(Some(owner), None)
                .await
                .into_iter()
                .map(|e| format!("{} {}", e.event_type, e.request))
                .collect();
            panic!(
                "timed out waiting for a matching {kind} access-log entry; saw:\n{}",
                seen.join("\n")
            )
        }
    }
}

pub(crate) async fn pyepp(port: u16, ca: &str) -> Value {
    let python = std::env::var("NETGET_EPP_PYTHON").expect("NETGET_EPP_PYTHON must name the Python from tests/server/epp/install_peers.py (pyepp 0.2.0); this evidence never skips");
    let run = tokio::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/server/epp/peer.py"
        ))
        .args(["localhost", &port.to_string(), ca])
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(120), run)
        .await
        .expect("pyepp did not finish")
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "pyepp failed:\n{stdout}\n{stderr}");
    serde_json::from_str(stdout.lines().last().unwrap_or_default())
        .unwrap_or_else(|e| panic!("pyepp printed no result ({e}):\n{stdout}\n{stderr}"))
}

/// The epp-lib registry; accounts: registrar1 / secret-pw-1.
pub(crate) struct Registry {
    pub port: u16,
    pub ca: String,
    child: tokio::process::Child,
    _dir: tempfile::TempDir,
}

impl Registry {
    pub(crate) async fn start() -> Self {
        let bin = std::env::var("NETGET_EPP_REGISTRY").expect("NETGET_EPP_REGISTRY must name the registry built by tests/server/epp/install_peers.py (epp-lib v0.2.0); this evidence never skips");
        let dir = tempfile::tempdir().unwrap();
        let mut child = tokio::process::Command::new(bin)
            .arg(dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start the epp-lib registry");
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
            .await
            .expect("the registry did not start")
            .unwrap()
            .expect("the registry exited");
        let ready: Value = serde_json::from_str(&line).unwrap();
        Self {
            port: ready["port"].as_u64().unwrap() as u16,
            ca: dir.path().join("cert.pem").to_str().unwrap().to_owned(),
            child,
            _dir: dir,
        }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// A raw plain-TCP session: frames in and out.
pub(crate) struct Raw(pub tokio::net::TcpStream);

impl Raw {
    pub(crate) async fn connect(addr: SocketAddr) -> Self {
        Self(tokio::net::TcpStream::connect(addr).await.unwrap())
    }
    pub(crate) async fn send(&mut self, xml: &str) {
        let mut frame = ((xml.len() + 4) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(xml.as_bytes());
        self.0.write_all(&frame).await.unwrap();
    }
    /// The next frame, or None when the server closed.
    pub(crate) async fn recv(&mut self) -> Option<String> {
        let mut len = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(30), self.0.read_exact(&mut len))
            .await
            .expect("no answer")
        {
            Ok(_) => {}
            Err(_) => return None,
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize - 4];
        self.0.read_exact(&mut body).await.unwrap();
        Some(String::from_utf8(body).unwrap())
    }
    pub(crate) async fn command(&mut self, inner: &str) -> String {
        self.send(&format!(r#"<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command>{inner}<clTRID>raw-1</clTRID></command></epp>"#)).await;
        self.recv()
            .await
            .expect("the server closed instead of answering")
    }
}

pub(crate) fn code(xml: &str) -> u16 {
    let at = xml.find("code=\"").expect("no result code") + 6;
    xml[at..at + 4].parse().unwrap()
}

pub(crate) const LOGIN: &str = r#"<login><clID>registrar1</clID><pw>secret-pw-1</pw><options><version>1.0</version><lang>en</lang></options><svcs><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI></svcs></login>"#;
