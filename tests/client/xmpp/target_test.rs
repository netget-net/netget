//! The XMPP client connects to `remote_addr` and nowhere else, and is `Connected` only once the
//! server has accepted the session.
//!
//! **Target.** `tokio_xmpp::Client::new` finds its server by an SRV lookup on the JID's
//! domain. A client built that way and pointed at a local server would send the account's
//! password to whatever the JID's domain publishes. The JID here is on `example.invalid`, which
//! no resolver answers for (RFC 6761), so a connection arriving at the loopback listener can
//! only have come from `remote_addr`. The stream header the client sends still names
//! `example.invalid` as its `to`, which shows the JID was used for the stream and only for that.
//!
//! **Status.** The generic startup path marks a client `Connected` as soon as `connect()`
//! returns `Ok`, so `connect()` must not return before tokio-xmpp's `Online` event. The
//! listener here accepts and never says a word, so `Online` never comes: the client must stay
//! `Connecting` for the whole session timeout and then fail, never passing through
//! `Connected`.
//!
//! Nothing here leaves 127.0.0.1, and no model is called (the LLM URL is `127.0.0.1:1` and the
//! connected-event call is only made after `Online`).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test client -- xmpp::target --test-threads=100

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::xmpp::resolve_target;
use netget::state::app_state::AppState;
use netget::state::{ClientId, ClientStatus};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Short enough for a test, long enough for a loopback connect and a stream header.
const TEST_SESSION_TIMEOUT_SECS: u64 = 3;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// Start creating an XMPP client in the background; `create` returns only once the session
/// is up or has failed.
fn spawn_create(
    state: &AppState,
    remote_addr: String,
    startup_params: serde_json::Value,
) -> tokio::task::JoinHandle<anyhow::Result<ClientId>> {
    let state = state.clone();
    tokio::spawn(async move {
        let (tx, _rx) = mpsc::unbounded_channel();
        ClientForm {
            protocol: "xmpp".to_string(),
            remote_addr: Some(remote_addr),
            instruction: Some("target probe".to_string()),
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

/// Read from `stream` until `needle` appears, or give up after 10 seconds.
async fn read_until(stream: &mut tokio::net::TcpStream, needle: &str) -> String {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains(needle) {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no {needle:?} from the client within 10s; it sent {:?}",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read from the client");
        assert!(
            n > 0,
            "the client closed before sending {needle:?}; it sent {:?}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test]
async fn connects_to_remote_addr_and_never_to_the_jid_domain() {
    let state = new_state().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("local addr");

    let create = spawn_create(
        &state,
        target.to_string(),
        serde_json::json!({
            "jid": "alice@example.invalid",
            "password": "never-sent-anywhere",
            "session_timeout_secs": TEST_SESSION_TIMEOUT_SECS,
        }),
    );

    let (mut peer, peer_addr) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect(
            "the client never connected to the address it was given; a client that resolves \
             the JID's domain instead cannot reach example.invalid at all",
        )
        .expect("accept");
    assert!(peer_addr.ip().is_loopback(), "connection from {peer_addr}");

    let header = read_until(&mut peer, "example.invalid").await;
    assert!(
        header.contains("stream:stream") || header.contains("<stream"),
        "the first bytes should open an XMPP stream, got {header:?}"
    );

    // Hold `peer` open and silent until the client gives up.
    let result = create.await.expect("create task");
    drop(peer);
    let err = result.expect_err("no session was ever established, so create must fail");
    assert!(
        err.to_string().contains(&target.to_string()),
        "the error should name the address the client used, got: {err}"
    );
}

#[tokio::test]
async fn connected_is_not_reported_before_the_session_is_online() {
    let state = new_state().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("local addr");

    let create = spawn_create(
        &state,
        target.to_string(),
        serde_json::json!({
            "jid": "alice@example.invalid",
            "password": "secret",
            "session_timeout_secs": TEST_SESSION_TIMEOUT_SECS,
        }),
    );

    // Accept and say nothing: TCP is up, the XMPP session never is.
    let (peer, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the client never connected")
        .expect("accept");

    // Watch the client's status for as long as `create` is pending.
    let mut seen: Vec<String> = Vec::new();
    while !create.is_finished() {
        for client in state.get_all_clients().await {
            let status = client.status.as_str().to_string();
            if seen.last() != Some(&status) {
                seen.push(status);
            }
            assert!(
                !matches!(client.status, ClientStatus::Connected),
                "the client reported Connected while the server had not even opened a stream \
                 (statuses so far: {seen:?})"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(peer);

    assert!(
        seen.iter().any(|s| s == "Connecting"),
        "the client should have sat in Connecting while the session was pending, saw {seen:?}"
    );
    let err = create
        .await
        .expect("create task")
        .expect_err("a session that never came online must fail");
    assert!(
        err.to_string()
            .contains(&format!("within {}s", TEST_SESSION_TIMEOUT_SECS)),
        "the error should say the session was not established in time, got: {err}"
    );
    assert!(
        state.get_all_clients().await.is_empty(),
        "a client that failed to start is removed rather than left looking alive"
    );
}

#[tokio::test]
async fn a_missing_password_is_refused_before_any_connection() {
    let state = new_state().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("local addr");

    let err = spawn_create(
        &state,
        target.to_string(),
        serde_json::json!({ "jid": "alice@example.invalid" }),
    )
    .await
    .expect("create task")
    .expect_err("an XMPP client with no password must not start");
    assert!(
        err.to_string().contains("password"),
        "the error should name the missing parameter, got: {err}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "a client refused at startup must not have dialled the server"
    );
}

#[tokio::test]
async fn a_jid_without_a_local_part_is_refused_before_any_connection() {
    let state = new_state().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("local addr");

    let err = spawn_create(
        &state,
        target.to_string(),
        serde_json::json!({ "jid": "example.invalid", "password": "pw" }),
    )
    .await
    .expect("create task")
    .expect_err("a JID with no local part must not start: tokio-xmpp's login would panic on it");
    assert!(
        err.to_string().contains("local part"),
        "the error should say what is missing, got: {err}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "a client refused at startup must not have dialled the server"
    );
}

#[tokio::test]
async fn the_target_comes_from_remote_addr_alone() {
    let explicit: SocketAddr = "127.0.0.1:15222".parse().unwrap();
    assert_eq!(resolve_target("127.0.0.1:15222").await.unwrap(), explicit);
    assert_eq!(
        resolve_target("[::1]:15222").await.unwrap(),
        "[::1]:15222".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        resolve_target("127.0.0.1").await.unwrap(),
        "127.0.0.1:5222".parse::<SocketAddr>().unwrap(),
        "a bare IP gets XMPP's client port"
    );

    // No address at all: refused, never filled in from anywhere else.
    let err = resolve_target("").await.expect_err("empty remote_addr");
    assert!(err.to_string().contains("remote_addr"), "{err}");
    let err = resolve_target("   ").await.expect_err("blank remote_addr");
    assert!(err.to_string().contains("remote_addr"), "{err}");

    // An account where the address belongs is refused, and the password is not echoed.
    let err = resolve_target("alice@example.invalid@hunter2")
        .await
        .expect_err("an account is not an address");
    let msg = err.to_string();
    assert!(msg.contains("startup parameters"), "{msg}");
    assert!(
        !msg.contains("hunter2"),
        "the refusal must not repeat a password: {msg}"
    );

    assert!(resolve_target("127.0.0.1:notaport").await.is_err());
}
