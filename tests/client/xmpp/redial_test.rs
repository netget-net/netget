//! An XMPP client that has ended dials its target no more.
//!
//! tokio-xmpp 5.0 runs its connect-and-login loop in a task it spawns itself and retries every
//! failed attempt (1s backoff, doubling to 30s) until a login succeeds; dropping the `Client`
//! does not reach that task. The client therefore builds its `tokio_xmpp::Client` on a connector
//! that refuses to dial once the client has ended, by whichever path it ended. Each test here
//! ends a client a different way - the session timeout, an injected `disconnect`, a stop - and
//! then counts the connections arriving at the target for a window longer than the library's
//! first backoffs. Before the client ends, the same listener sees the library redial, so a
//! quiet window means the dialling stopped rather than never started.
//!
//! The "server" accepts and drops every connection at once, so each attempt fails within
//! milliseconds and the library's next one comes on its backoff schedule: from the first
//! attempt at 0s, the next are at about 1s, 3s, 7s and 15s.
//!
//! **A model-produced `disconnect` is not driven here**, and cannot be by this suite: every
//! event the model answers (`xmpp_connected`, `xmpp_message_received`, `xmpp_presence_received`)
//! comes after tokio-xmpp's `Online`, which needs STARTTLS with a certificate the library
//! trusts, SASL and resource binding, and no XMPP server this suite can start completes that
//! (see `src/client/xmpp/AGENTS.md`). What the model path shares with the injected one is
//! `end_session` - a model `disconnect` and an injected one both cancel the same token and drop
//! the same handle - so the injected-disconnect test below is the evidence for both.
//!
//! Nothing here leaves 127.0.0.1, and no model is called (the LLM URL is `127.0.0.1:1`, and the
//! client makes no model call before `Online`).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test client -- xmpp::redial --test-threads=100

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Lets a connect the client began just before it ended reach the listener's count before
/// the quiet window starts.
const SETTLE: Duration = Duration::from_millis(500);

/// Long enough to span at least two of the library's redials (at about 1s, 3s and 7s after
/// its first attempt) wherever in that schedule the client ended.
const QUIET_WINDOW: Duration = Duration::from_millis(6_500);

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// A loopback listener that counts every connection and drops it at once.
async fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let dials = Arc::new(AtomicUsize::new(0));
    let counter = dials.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (addr, dials, task)
}

/// Start creating an XMPP client in the background; `create` returns only once the session
/// is up or has failed.
fn spawn_create(
    state: &AppState,
    target: SocketAddr,
    session_timeout_secs: u64,
) -> tokio::task::JoinHandle<anyhow::Result<ClientId>> {
    let state = state.clone();
    tokio::spawn(async move {
        let (tx, _rx) = mpsc::unbounded_channel();
        ClientForm {
            protocol: "xmpp".to_string(),
            remote_addr: Some(target.to_string()),
            instruction: Some("redial probe".to_string()),
            startup_params: Some(serde_json::json!({
                "jid": "netget@example.invalid",
                "password": "secret",
                "session_timeout_secs": session_timeout_secs,
            })),
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

async fn wait_for_client(state: &AppState) -> ClientId {
    for _ in 0..1_000 {
        if let Some(client) = state.get_all_clients().await.first() {
            return client.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the XMPP client was never registered");
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "XMPP client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_first_dial(dials: &AtomicUsize) {
    for _ in 0..1_000 {
        if dials.load(Ordering::SeqCst) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the XMPP client never dialled its target");
}

/// Wait for `create` to fail, as it must for a client that ended before its session came up.
async fn expect_create_to_fail(create: tokio::task::JoinHandle<anyhow::Result<ClientId>>) {
    let result = tokio::time::timeout(Duration::from_secs(20), create)
        .await
        .expect("create should return once the client has ended")
        .expect("create task");
    assert!(
        result.is_err(),
        "a client that ended before its session came up must not start, got {result:?}"
    );
}

/// No connection reaches the target for `QUIET_WINDOW`, once `SETTLE` has passed.
async fn assert_no_further_dials(dials: &AtomicUsize, how_it_ended: &str) {
    tokio::time::sleep(SETTLE).await;
    let before = dials.load(Ordering::SeqCst);
    tokio::time::sleep(QUIET_WINDOW).await;
    let after = dials.load(Ordering::SeqCst);
    assert_eq!(
        after,
        before,
        "after {how_it_ended}, the XMPP client dialled its target {} more time(s) in {:?}: \
         tokio-xmpp's reconnect loop is still running",
        after - before,
        QUIET_WINDOW
    );
}

#[tokio::test]
async fn a_client_whose_session_timed_out_stops_dialling() {
    let state = new_state().await;
    let (target, dials, listener) = counting_listener().await;

    let create = spawn_create(&state, target, 2);
    expect_create_to_fail(create).await;
    assert!(
        dials.load(Ordering::SeqCst) >= 1,
        "the client should have dialled its target before the session timed out"
    );

    assert_no_further_dials(&dials, "the session timeout").await;
    listener.abort();
}

#[tokio::test]
async fn an_injected_disconnect_while_connecting_stops_dialling() {
    let state = new_state().await;
    let (target, dials, listener) = counting_listener().await;

    let create = spawn_create(&state, target, 120);
    let client_id = wait_for_client(&state).await;
    wait_for_client_handle(&state, client_id).await;
    wait_for_first_dial(&dials).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );
    expect_create_to_fail(create).await;

    assert_no_further_dials(&dials, "an injected disconnect").await;
    listener.abort();
}

#[tokio::test]
async fn stopping_a_connecting_client_stops_dialling() {
    let state = new_state().await;
    let (target, dials, listener) = counting_listener().await;

    let create = spawn_create(&state, target, 120);
    let client_id = wait_for_client(&state).await;
    wait_for_first_dial(&dials).await;

    // What the dashboard's stop and MCP's stop_client do: the client's tasks are aborted, so
    // none of the event loop's own exit path runs.
    assert!(
        state.remove_client(client_id).await.is_some(),
        "the client should have been registered"
    );
    expect_create_to_fail(create).await;

    assert_no_further_dials(&dials, "the client was stopped").await;
    listener.abort();
}
