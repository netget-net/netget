//! The declared `jid` / `password` startup parameters are where the XMPP client's account
//! comes from, and the only place: `remote_addr` is the server's address and nothing else.
//!
//! The account reaches the wire before any authentication does: the stream header the client
//! opens with carries the JID's domain as its `to`. A loopback listener that reads that header
//! therefore sees the startup `jid` in use without any XMPP server existing. It never answers,
//! so the session never comes up and `create` fails once `session_timeout_secs` runs out; the
//! JID the client recorded on itself is checked while it waits.
//!
//! Nothing here leaves 127.0.0.1, and no model is called.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test client -- xmpp::startup_params --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
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

fn spawn_create(
    state: &AppState,
    remote_addr: String,
    startup_params: serde_json::Value,
) -> tokio::task::JoinHandle<anyhow::Result<netget::state::ClientId>> {
    let state = state.clone();
    tokio::spawn(async move {
        let (tx, _rx) = mpsc::unbounded_channel();
        ClientForm {
            protocol: "xmpp".to_string(),
            remote_addr: Some(remote_addr),
            instruction: Some("startup parameter probe".to_string()),
            startup_params: Some(startup_params),
            ..Default::default()
        }
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx,
        )
        .await
    })
}

/// The JID the client recorded on itself, if it has started.
async fn recorded_jid(state: &AppState) -> Option<String> {
    state.get_all_clients().await.into_iter().find_map(|c| {
        c.get_protocol_field("jid")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    })
}

#[tokio::test]
async fn jid_and_password_come_from_the_startup_parameters() {
    let state = new_state().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("local addr");

    // `remote_addr` is a bare socket address; the account exists only in the parameters.
    let create = spawn_create(
        &state,
        target.to_string(),
        serde_json::json!({
            "jid": "alice@xmpp.netget.invalid",
            "password": "s3cret-from-startup-params",
            "session_timeout_secs": 3,
        }),
    );

    let (mut peer, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("an XMPP client given jid+password as startup parameters must dial remote_addr")
        .expect("accept");

    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !String::from_utf8_lossy(&seen).contains("xmpp.netget.invalid") {
        let n = tokio::time::timeout_at(deadline, peer.read(&mut buf))
            .await
            .expect("the stream header should name the startup JID's domain within 10s")
            .expect("read");
        assert!(n > 0, "the client closed before opening a stream");
        seen.extend_from_slice(&buf[..n]);
    }

    assert_eq!(
        recorded_jid(&state).await.as_deref(),
        Some("alice@xmpp.netget.invalid"),
        "the client must connect as the JID the caller supplied"
    );

    // The listener never answers, so no session: `create` fails once the timeout runs out.
    assert!(create.await.expect("create task").is_err());
    drop(peer);
}

#[tokio::test]
async fn a_wrong_typed_parameter_names_itself() {
    let state = new_state().await;
    let err = spawn_create(
        &state,
        "127.0.0.1:1".to_string(),
        serde_json::json!({ "jid": "alice@xmpp.netget.invalid", "password": 1234 }),
    )
    .await
    .expect("create task")
    .expect_err("a numeric password is refused at startup");
    assert!(
        err.to_string().contains("password"),
        "the error should name the parameter, got: {err}"
    );
}
