//! Independent pinned aioquic peers. Missing dependency is a hard failure.
#![allow(dead_code)]
use netget::{
    cli::management::{ClientForm, ServerForm},
    llm::OllamaClient,
    state::{AppState, ClientId, ServerId},
};
use serde_json::{json, Value};
use std::{net::SocketAddr, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
pub fn python() -> String {
    std::env::var("NETGET_AIOQUIC_PYTHON").unwrap_or_else(|_| "python3".into())
}
pub fn script() -> String {
    format!("{}/tests/helpers/quic_peer.py", env!("CARGO_MANIFEST_DIR"))
}
pub struct Certificate {
    pub dir: tempfile::TempDir,
}
impl Certificate {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), c.cert.pem()).unwrap();
        std::fs::write(dir.path().join("key.pem"), c.signing_key.serialize_pem()).unwrap();
        Self { dir }
    }
    pub fn cert(&self) -> std::path::PathBuf {
        self.dir.path().join("cert.pem")
    }
    pub fn key(&self) -> std::path::PathBuf {
        self.dir.path().join("key.pem")
    }
    pub fn trust(&self) -> Value {
        json!({"server_name":"localhost","ca_cert_path":self.cert()})
    }
}
pub struct Peer {
    pub cert: Certificate,
    pub port: u16,
    pub child: tokio::process::Child,
}
impl Peer {
    pub async fn start(protocol: &str) -> Self {
        let cert = Certificate::new();
        let mut child = tokio::process::Command::new(python())
            .arg(script())
            .args(["server", protocol, "--port", "0"])
            .arg("--cert")
            .arg(cert.cert())
            .arg("--key")
            .arg(cert.key())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("Install aioquic==1.3.0 and set NETGET_AIOQUIC_PYTHON");
        let mut line = String::new();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        tokio::time::timeout(Duration::from_secs(8), out.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let readiness: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("invalid aioquic readiness: {error}: {line}"));
        assert_eq!(readiness["ready"], true, "aioquic did not start: {line}");
        let port = readiness["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .unwrap_or_else(|| panic!("invalid bound aioquic port: {line}"));
        Self { cert, port, child }
    }
    pub async fn close(&mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }
    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}
pub async fn external_client(
    protocol: &str,
    port: u16,
    cert: &Certificate,
    requests: Value,
) -> Value {
    let out = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(python())
            .arg(script())
            .args(["client", protocol, "--port", &port.to_string()])
            .arg("--ca")
            .arg(cert.cert())
            .arg("--requests")
            .arg(requests.to_string())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        out.status.success(),
        "aioquic failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
pub fn state() -> AppState {
    AppState::new_with_options(false, "http://127.0.0.1:1".into())
}
pub fn empty_handler() -> Value {
    json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})
}
pub async fn client(
    state: &AppState,
    protocol: &str,
    remote: String,
    params: Value,
    handlers: Vec<Value>,
) -> ClientId {
    let llm = OllamaClient::new("http://127.0.0.1:1");
    state.set_llm_client(llm.clone()).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: protocol.into(),
        remote_addr: Some(remote),
        startup_params: Some(params),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(state, llm, tx)
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.has_client_handle(id).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    id
}
pub async fn server(
    state: &AppState,
    protocol: &str,
    cert: &Certificate,
    params: Value,
    handlers: Vec<Value>,
) -> (ServerId, SocketAddr) {
    let llm = OllamaClient::new("http://127.0.0.1:1");
    state.set_llm_client(llm).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let mut p = json!({"cert_path":cert.cert(),"key_path":cert.key()});
    p.as_object_mut()
        .unwrap()
        .extend(params.as_object().unwrap().clone());
    let id = ServerForm {
        protocol: protocol.into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        startup_params: Some(p),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let s = state.get_server(id).await.unwrap();
            if let Some(addr) = s.local_addr {
                break addr;
            }
            if let netget::state::ServerStatus::Error(e) = s.status {
                panic!("{e}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (id, addr)
}
pub async fn wait_log(state: &AppState, id: ClientId, text: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let logs = state
                .list_access_logs_for(
                    Some(netget::state::AccessLogOwner::Client(id.as_u32())),
                    None,
                )
                .await;
            if format!("{logs:?}").contains(text) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

/// The two independent RFC 9221 peers: aioquic (Python) and quic-go (Go). They share one
/// command line (`tests/helpers/quic_datagram_peer.py`), so a test runs against both.
#[derive(Clone, Copy, Debug)]
pub enum DatagramPeer {
    Aioquic,
    QuicGo,
}
pub struct DatagramServer {
    pub cert: Certificate,
    pub port: u16,
    pub child: tokio::process::Child,
    pub lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}
impl DatagramPeer {
    fn command(self) -> tokio::process::Command {
        match self {
            DatagramPeer::Aioquic => {
                let mut c = tokio::process::Command::new(python());
                c.arg(format!(
                    "{}/tests/helpers/quic_datagram_peer.py",
                    env!("CARGO_MANIFEST_DIR")
                ));
                c
            }
            DatagramPeer::QuicGo => {
                let bin = std::env::var("NETGET_QUIC_GO_PEER").unwrap_or_default();
                assert!(
                    !bin.is_empty(),
                    "NETGET_QUIC_GO_PEER is required: go build -o <dir>/quic-go-peer \
                     ./tests/helpers/quic_go_peer and export its path"
                );
                tokio::process::Command::new(bin)
            }
        }
    }
    /// Connect, send `send` as datagrams, and return the peer's report once `expect` came back.
    pub async fn client(
        self,
        port: u16,
        cert: &Certificate,
        send: &[&[u8]],
        expect: usize,
    ) -> Value {
        let send: Vec<String> = send.iter().map(hex::encode).collect();
        let out = tokio::time::timeout(
            Duration::from_secs(20),
            self.command()
                .args(["client", "--port", &port.to_string(), "--ca"])
                .arg(cert.cert())
                .args(["--send", &serde_json::to_string(&send).unwrap()])
                .args(["--expect", &expect.to_string()])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap_or_else(|_| panic!("{self:?} client did not finish"))
        .unwrap_or_else(|e| panic!("{self:?} client could not run: {e}"));
        assert!(
            out.status.success(),
            "{self:?} client failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    /// An echoing datagram server; each received datagram is a `{"datagram": hex}` line.
    pub async fn server(self) -> DatagramServer {
        let cert = Certificate::new();
        let mut child = self
            .command()
            .args(["server", "--port", "0", "--cert"])
            .arg(cert.cert())
            .arg("--key")
            .arg(cert.key())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("{self:?} server could not run: {e}"));
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap_or_else(|_| panic!("{self:?} server never became ready"))
            .unwrap()
            .unwrap_or_else(|| panic!("{self:?} server exited"));
        let ready: Value = serde_json::from_str(&ready).unwrap();
        let port = ready["port"].as_u64().unwrap() as u16;
        DatagramServer {
            cert,
            port,
            child,
            lines,
        }
    }
}
impl DatagramServer {
    /// The next datagram the server reported receiving, as bytes.
    pub async fn next_datagram(&mut self) -> Vec<u8> {
        let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
            .await
            .expect("the peer server received no datagram")
            .unwrap()
            .expect("the peer server exited");
        let v: Value = serde_json::from_str(&line).unwrap();
        hex::decode(v["datagram"].as_str().unwrap()).unwrap()
    }
}
