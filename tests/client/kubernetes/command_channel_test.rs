//! The dashboard's `[ send ]` path on a Kubernetes client: `AppState::send_to_client` injects
//! an action from outside the client's own tasks, the client's command loop runs it through
//! the same `apply_action` any other path would use, and the apiserver request really reaches
//! a listener on loopback.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so the response-event call
//! fails - the loop has to tolerate that, which is part of what this verifies. Nothing here
//! contacts a real cluster: `KUBECONFIG` is pointed at a throwaway file whose only cluster is
//! a plain TCP listener on 127.0.0.1, which also keeps the developer's own `~/.kube/config`
//! out of the picture.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features kubernetes --test client -- kubernetes::command_channel --test-threads=100


use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// A canned-response HTTP listener on loopback. Records every request it saw so a test can
/// prove the injected action actually put bytes on the wire.
struct HttpStub {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl HttpStub {
    fn saw(&self, needle: &str) -> bool {
        self.seen
            .lock()
            .map(|v| v.iter().any(|r| r.contains(needle)))
            .unwrap_or(false)
    }
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

async fn spawn_http_stub(
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
) -> HttpStub {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                                if buf.len() - (pos + 4) >= content_length(&head) {
                                    break;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                }
                if let Ok(mut guard) = seen.lock() {
                    guard.push(String::from_utf8_lossy(&buf).to_string());
                }
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });

    HttpStub { port, seen }
}

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "Kubernetes client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// Write a kubeconfig whose single cluster is the loopback stub, and point `KUBECONFIG` at it.
/// `kube::Client::try_default()` would otherwise read the developer's real kubeconfig and talk
/// to a real cluster.
fn pin_kubeconfig_to_loopback(port: u16) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("netget-k8s-cmdchan-{}.yaml", port));
    let kubeconfig = format!(
        r#"apiVersion: v1
kind: Config
current-context: netget-test
clusters:
- name: netget-test
  cluster:
    server: http://127.0.0.1:{port}
contexts:
- name: netget-test
  context:
    cluster: netget-test
    user: netget-test
    namespace: default
users:
- name: netget-test
  user:
    token: netget-test-token
"#
    );
    std::fs::write(&path, kubeconfig).expect("write test kubeconfig");
    std::env::set_var("KUBECONFIG", &path);

    // `kube` refuses to build a client at all when a proxy is configured in the environment
    // unless the optional `kube/http-proxy` feature is on, and NetGet does not enable it.
    // Everything this test talks to is on loopback, which no proxy should ever handle, so
    // clear the variables rather than route around them.
    for var in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        std::env::remove_var(var);
    }

    path
}

/// `kube` builds a rustls `ClientConfig` even for an `http://` apiserver, and rustls 0.23
/// panics at that point unless exactly one of its `ring` / `aws-lc-rs` features is enabled or
/// a process-wide provider has been installed. This binary compiles the AWS SDK (aws-lc-rs)
/// alongside `kube` (ring), so both are on and neither wins - install one explicitly.
///
/// Reached through `quinn`, a dev-dependency that re-exports rustls: NetGet's own `rustls`
/// dependency is optional and is not enabled by the `kubernetes` feature, so `rustls::` is not
/// nameable from here.
///
/// **Belt-and-braces, not a workaround.** `connect_with_llm_actions` installs the provider
/// itself (as `dot`, `tls`, `dc` and `http3` do), and `src/bin/netget.rs` installs one for the
/// shipped binary under a gate `tests/rustls_provider_gate_test.rs` keeps honest. Calling it
/// here as well is harmless — `install_default` returns `Err` when one is already set — and it
/// keeps the test independent of which of those ran first. See
/// `src/client/kubernetes/CLAUDE.md`.
fn install_rustls_provider() {
    let _ = quinn::rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
async fn injected_list_pods_reaches_the_apiserver() {
    install_rustls_provider();
    let stub = spawn_http_stub(
        "200 OK",
        "application/json",
        r#"{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"1"},"items":[{"metadata":{"name":"dashboard-marker","namespace":"default"}}]}"#,
    )
    .await;
    let kubeconfig = pin_kubeconfig_to_loopback(stub.port);

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "kubernetes".to_string(),
        // "default" is the only accepted form; it means "use the kubeconfig", which the
        // helper above has pinned to the loopback stub.
        remote_addr: Some("default".to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create kubernetes client");

    wait_for_client_handle(&state, client_id).await;

    // An unknown verb is refused by the client's own `execute_action`, not silently eaten.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_verb"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // The client's own wire verb, injected from outside its loop. `Executed`, not `Sent`:
    // `kube` owns the socket and reports no byte count, so the detail names the operation
    // and what it returned rather than inventing a number.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "k8s_list_pods", "namespace": "default"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client k8s_list_pods");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("list pods completed"),
                "expected a completed pod listing, got {detail:?}"
            );
            assert!(
                detail.contains("dashboard-marker"),
                "expected the stub's pod name in the detail, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Proof it was a real request, not a bookkeeping entry.
    assert!(
        stub.saw("/api/v1/namespaces/default/pods"),
        "the stub never saw the pod list request: {:?}",
        stub.seen.lock().unwrap()
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !state.has_client_handle(client_id).await,
        "the command handle outlived the disconnected client"
    );

    state.remove_client(client_id).await;
    let _ = std::fs::remove_file(kubeconfig);
}
