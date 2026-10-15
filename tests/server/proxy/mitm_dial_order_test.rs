//! The MITM proxy touches the outside world only once something has decided it should.
//!
//! **The upstream is dialled after the model's decision.** Dialling `dest_host:dest_port`
//! (and sending a TLS ClientHello carrying the peer's SNI) right after the client handshake
//! would let any proxy client make NetGet open a TCP connection to an arbitrary host:port —
//! a reachability oracle for internal addresses, with the answer in handshake timing — and
//! a request the model went on to block would already have cost its destination a
//! handshake. `perform_mitm` reads the request and asks the model first.
//!
//! **`ca_export_path` destroys nothing.** It is a startup parameter, so the model can set it
//! through `open_server`. `write_ca_export` refuses a symlink, creates a new file without
//! truncating anything, and replaces an existing file only when it is an earlier NetGet
//! export (one PEM certificate whose subject is `CA_COMMON_NAME`), which is what a restart
//! pointed at the same path finds; any other file — another PEM certificate or CA
//! bundle included — is refused and left untouched.
//!
//! The model here is a closed port, so every request decision fails closed to a block
//! (`decision=llm_error`), which is exactly the decision after which no dial may happen.
//! Loopback only; the "upstream" is a listener that counts accepts and never speaks.
//!
//! Run with:
//!   cargo test --no-default-features --features proxy --test server -- proxy::mitm_dial_order

#![cfg(unix)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::proxy::write_ca_export;
use netget::state::app_state::AppState;
use netget::state::server::ServerStatus;
use netget::state::ServerId;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if let ServerStatus::Error(e) = &s.status {
                panic!("proxy server failed to start: {e}");
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Proxy server #{} never bound a port", id.as_u32());
}

async fn start_mitm_proxy(
    state: &AppState,
    startup_params: serde_json::Value,
) -> anyhow::Result<(ServerId, u16)> {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "proxy".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        ..Default::default()
    }
    .create(state, tx)
    .await?;
    let port = wait_for_port(state, server_id).await;
    Ok((server_id, port))
}

/// A listener that counts accepted connections and never writes a byte.
async fn counting_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn a_blocked_mitm_request_never_dials_the_upstream() {
    let state = new_state().await;
    let (_id, proxy_port) =
        start_mitm_proxy(&state, serde_json::json!({"certificate_mode": "generate"}))
            .await
            .expect("start MITM proxy");
    let (upstream_port, accepted) = counting_upstream().await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        // The proxy mints a leaf for "127.0.0.1" on the fly; nothing trusts its CA here.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let response = client
        .get(format!("https://127.0.0.1:{upstream_port}/secret"))
        .send()
        .await;
    // The model is unreachable, so the request fails closed: a 5xx the proxy wrote itself.
    match response {
        Ok(r) => assert!(
            r.status().is_server_error(),
            "a fail-closed block must be a 5xx, got {}",
            r.status()
        ),
        Err(e) => panic!("the proxy must answer the blocked request itself, got {e}"),
    }

    // Give a stray dial every chance to land before counting.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "the upstream was dialled before the model blocked the request"
    );
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "netget-proxy-ca-export-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

#[test]
fn ca_export_refuses_to_overwrite_a_file_that_is_not_a_previous_export() {
    let dir = scratch_dir("foreign");
    let path = dir.join("authorized_keys");
    std::fs::write(&path, "ssh-ed25519 AAAA operator@host\n").unwrap();
    let err = write_ca_export(&path, PEM).expect_err("must refuse a foreign file");
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "ssh-ed25519 AAAA operator@host\n",
        "the file must be untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn ca_export_refuses_a_symlink() {
    let dir = scratch_dir("symlink");
    let target = dir.join("target.txt");
    std::fs::write(&target, "keep me").unwrap();
    let link = dir.join("ca.pem");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = write_ca_export(&link, PEM).expect_err("must refuse a symlink");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me");

    // A dangling symlink is refused too, and its target is not created.
    let missing = dir.join("missing.pem");
    let dangling = dir.join("dangling.pem");
    std::os::unix::fs::symlink(&missing, &dangling).unwrap();
    let err = write_ca_export(&dangling, PEM).expect_err("must refuse a dangling symlink");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert!(
        !missing.exists(),
        "the symlink's target must not be created"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A real NetGet CA certificate, as `generate_ca_certificate` builds it.
fn netget_ca_pem() -> String {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        netget::server::proxy::CA_COMMON_NAME,
    );
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().pem()
}

#[test]
fn ca_export_writes_a_new_file_and_replaces_its_own_earlier_export() {
    let dir = scratch_dir("ok");
    let path = dir.join("ca.pem");
    let first = netget_ca_pem();
    write_ca_export(&path, &first).expect("a new file");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
    // The CA is regenerated on every start, so a restart exports a different certificate to
    // the same path and must replace the earlier export.
    let next = netget_ca_pem();
    assert_ne!(first, next);
    write_ca_export(&path, &next).expect("a restart replaces the earlier export");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), next);
    // A file holding NetGet's certificate and anything else is not an export NetGet wrote.
    let bundle = format!("{next}{first}");
    std::fs::write(&path, &bundle).unwrap();
    let err = write_ca_export(&path, &first).expect_err("a bundle is not an export");
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bundle);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ca_export_leaves_an_existing_unrelated_certificate_untouched() {
    let dir = scratch_dir("unrelated-cert");
    // Another certificate, a CA bundle that starts with the certificate being exported, and
    // an empty file: none of them is an earlier NetGet export, so none may be replaced.
    let other_cert = PEM.replace("MIIB", "MIIC");
    let bundle = format!("{PEM}{other_cert}");
    for (name, contents) in [
        ("other.pem", other_cert.as_str()),
        ("bundle.pem", bundle.as_str()),
        ("empty.pem", ""),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        let err = write_ca_export(&path, PEM)
            .expect_err("an existing file that is not this export must be refused");
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "{name}: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            contents,
            "{name} must be untouched"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_proxy_whose_ca_export_path_is_a_foreign_file_does_not_start_and_leaves_it_alone() {
    let dir = scratch_dir("startup");
    let path = dir.join("bashrc");
    std::fs::write(&path, "export PS1='$ '\n").unwrap();
    let state = new_state().await;
    let started = start_mitm_proxy(
        &state,
        serde_json::json!({
            "certificate_mode": "generate",
            "ca_export_path": path.to_string_lossy(),
        }),
    )
    .await;
    // Either `create` reports the error or the server lands in `Error`; what matters is
    // that it is not Running and the file is intact.
    if let Ok((id, _)) = started {
        let status = state.get_server(id).await.map(|s| s.status);
        assert!(
            matches!(status, Some(ServerStatus::Error(_))),
            "the proxy must not start on a foreign ca_export_path, got {status:?}"
        );
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "export PS1='$ '\n");
    let _ = std::fs::remove_dir_all(&dir);
}
