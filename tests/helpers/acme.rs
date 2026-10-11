//! ACME fixtures: a CA policy script, server and client through the shared forms, the pinned
//! lego / certbot / Pebble peers (`tests/server/acme/install_peers.py`) and access-log waits.
// Shared by the server and client test binaries; each uses a different subset.
#![allow(dead_code)]
use netget::{
    cli::management::{ClientForm, ServerForm},
    state::{app_state::AppState, AccessLogOwner, ClientId, ClientStatus, ServerId},
};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use tokio::sync::mpsc;

pub(crate) fn state() -> AppState {
    AppState::new_with_options(false, "http://127.0.0.1:1".into())
}

const POLICY: &str = r#"import json,sys
d=json.load(sys.stdin); kind=d['event_type_id']; e=d['event']
def out(a): print(json.dumps({'actions':[a]})); sys.exit()
def no(err, detail): out({'type':'acme_reject','error':err,'detail':detail})
if kind=='acme_new_account' and 'mailto:blocked@example.test' in e['contact']: no('unauthorized','this contact may not register')
if kind=='acme_new_order' and any(i.endswith('.forbidden.test') for i in e['identifiers']): no('rejectedIdentifier','names under forbidden.test are not issued')
if kind=='acme_revoke' and e.get('reason')==1: no('unauthorized','keyCompromise revocations go through the operator')
out({'type':'acme_accept'})
"#;

/// A CA policy: everything is approved except accounts with contact blocked@example.test,
/// orders naming anything under forbidden.test, and keyCompromise revocations.
pub(crate) fn policy() -> Vec<Value> {
    vec![
        json!({"event_pattern": "*", "handler": {"type":"script","language":"python","code": POLICY}}),
    ]
}

pub(crate) async fn server_in(
    state: &AppState,
    handlers: Vec<Value>,
    params: Value,
) -> (ServerId, SocketAddr) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let id = ServerForm {
        protocol: "acme".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(handlers),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(10), async {
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

/// An ACME client whose events are all answered with nothing, so only injected actions run.
pub(crate) async fn client_in(
    state: &AppState,
    remote: String,
    params: Value,
) -> anyhow::Result<ClientId> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let handlers = ["acme_connected", "acme_response"]
        .iter()
        .map(|e| json!({"event_pattern": e,"handler":{"type":"static","actions":[]}}))
        .collect();
    let id = ClientForm {
        protocol: "acme".into(),
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
    tokio::time::timeout(Duration::from_secs(15), async {
        while !state.has_client_handle(id).await {
            if let Some(ClientStatus::Error(e)) = state.get_client(id).await.map(|c| c.status) {
                anyhow::bail!(e);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("ACME client did not connect"))??;
    Ok(id)
}

pub(crate) async fn logs(
    state: &AppState,
    owner: AccessLogOwner,
    kind: &str,
    count: usize,
) -> Vec<netget::state::app_state::AccessLogEntry> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let mut rows = state
                .list_access_logs_for(Some(owner), None)
                .await
                .into_iter()
                .filter(|e| e.event_type == kind)
                .collect::<Vec<_>>();
            if rows.len() >= count {
                rows.sort_by_key(|e| e.id);
                break rows;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {count} {kind} access-log entries"))
}

/// A path from `tests/server/acme/install_peers.py`'s output.
pub(crate) fn peer(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| panic!("{var} must be set from tests/server/acme/install_peers.py (lego 4.35.2, Pebble 2.10.1, certbot 5.8.0); this evidence never skips"))
}

/// A test CA and a `localhost` server certificate it signed, written into `dir`, for the CA's
/// HTTPS listener: (CA certificate the peers trust, server chain, server key).
pub(crate) fn tls_files(dir: &std::path::Path) -> (String, String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    let now = time::OffsetDateTime::now_utc();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.distinguished_name
        .push(DnType::CommonName, "NetGet test TLS root");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_before = now - time::Duration::hours(1);
    ca.not_after = now + time::Duration::days(30);
    let issuer = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.not_before = now - time::Duration::hours(1);
    leaf.not_after = now + time::Duration::days(30);
    let key = KeyPair::generate().unwrap();
    let cert = leaf.signed_by(&key, &issuer).unwrap();
    let (root, chain, k) = (
        dir.join("root.pem"),
        dir.join("tls.pem"),
        dir.join("tls.key"),
    );
    std::fs::write(&root, issuer.pem()).unwrap();
    std::fs::write(&chain, format!("{}{}", cert.pem(), issuer.pem())).unwrap();
    std::fs::write(&k, key.serialize_pem()).unwrap();
    (
        root.display().to_string(),
        chain.display().to_string(),
        k.display().to_string(),
    )
}

/// Run a peer to completion with extra environment; (success, stdout + stderr).
pub(crate) async fn run(program: &str, args: &[String], env: &[(&str, &str)]) -> (bool, String) {
    let out = tokio::time::timeout(
        Duration::from_secs(180),
        tokio::process::Command::new(program)
            .args(args)
            .envs(env.iter().copied())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{program} timed out"))
    .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

pub(crate) struct Pebble {
    pub dns: super::real_server::RealServer,
    pub ca: super::real_server::RealServer,
    /// The port Pebble's validation authority connects to for http-01.
    pub http01_port: u16,
}

impl Pebble {
    pub fn directory_host(&self) -> String {
        self.ca.addr()
    }
    pub fn dns_management(&self) -> String {
        self.dns.addr()
    }
}

/// pebble-challtestsrv answering every A query with 127.0.0.1, and Pebble resolving through it
/// and validating http-01 on `http01_port`.
pub(crate) async fn start_pebble(http01_port: u16) -> super::E2EResult<Pebble> {
    let hint = super::real_server::InstallHint {
        brew: "go (then tests/server/acme/install_peers.py)",
        apt: "golang-go (then tests/server/acme/install_peers.py)",
    };
    let dns = super::real_server::RealServer::builder(&peer("NETGET_ACME_CHALLTESTSRV"), hint)
        .extra_ports(1)
        .args([
            "-management",
            "127.0.0.1:{port}",
            "-dnsserver",
            "127.0.0.1:{port1}",
            "-http01",
            "",
            "-https01",
            "",
            "-tlsalpn01",
            "",
            "-doh",
            "",
            "-defaultIPv4",
            "127.0.0.1",
            "-defaultIPv6",
            "",
        ])
        .start()
        .await?;
    let certs = peer("NETGET_ACME_PEBBLE_CERTS");
    let config = json!({"pebble": {
        "listenAddress": "127.0.0.1:{port}",
        "managementListenAddress": "127.0.0.1:{port1}",
        "certificate": format!("{certs}/cert.pem"),
        "privateKey": format!("{certs}/key.pem"),
        "httpPort": http01_port,
        "tlsPort": 1,
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false,
        "domainBlocklist": ["blocked-domain.example"],
        "retryAfter": {"authz": 1, "order": 1},
        "keyAlgorithm": "ecdsa",
    }});
    let ca = super::real_server::RealServer::builder(&peer("NETGET_ACME_PEBBLE"), hint)
        .extra_ports(1)
        .env("PEBBLE_VA_NOSLEEP", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        .config_file("pebble.json", &config.to_string())
        .args([
            "-config".to_owned(),
            "{dir}/pebble.json".to_owned(),
            "-dnsserver".to_owned(),
            format!("127.0.0.1:{}", dns.extra_ports[0]),
        ])
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await?;
    Ok(Pebble {
        dns,
        ca,
        http01_port,
    })
}
