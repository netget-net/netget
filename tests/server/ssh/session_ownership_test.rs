//! The connection task owns the whole russh session, not just its first few packets.
//!
//! `russh::server::run_stream(..).await` returns once the identification strings are exchanged:
//! it spawns the session driver itself and hands back a `RunningSession`, which is the session.
//! The server used to drop that value, so the connection task ended straight after the banner
//! exchange — releasing its connection-cap permit and marking the connection `Closed` while the
//! peer went on to authenticate and work — and `stop_server`, which aborts that task, had
//! nothing left to abort: the driver kept the socket open on a server the operator had stopped.
//!
//! Three properties, each asserted where a defect would show:
//!
//! 1. An authenticated session is still `Active` in `AppState` while it is open.
//! 2. Stopping the server closes an authenticated session's socket, seen from the peer.
//! 3. Stopping the server while an authentication decision is parked for a human ends the
//!    connection and retires the parked request, rather than leaving both to the 300s timeout.
//!
//! `ssh2` (libssh2) is blocking, so every client call runs under `spawn_blocking`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh,tcp --test server -- ssh::session_ownership --test-threads=100

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use serde_json::json;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    // A dead model endpoint: every event below is answered by a rule or parks for a human.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn start_server(state: &AppState, auth_handler: serde_json::Value) -> (ServerId, u16) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let server_id = ServerForm {
        protocol: "ssh".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![json!({
            "event_pattern": "ssh_auth",
            "handler": auth_handler,
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ssh server");
    for _ in 0..200 {
        if let Some(addr) = state.get_server(server_id).await.and_then(|s| s.local_addr) {
            return (server_id, addr.port());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("SSH server #{} never bound a port", server_id.as_u32());
}

fn accept_everyone() -> serde_json::Value {
    json!({"type": "static", "actions": [{"type": "ssh_auth_decision", "allowed": true}]})
}

async fn active_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| matches!(c.status, ConnectionStatus::Active))
                .count()
        })
        .unwrap_or(0)
}

async fn wait_until<F, Fut>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Authenticate with libssh2 and hand back the session with its socket, still open.
async fn authenticated_session(port: u16) -> (ssh2::Session, TcpStream) {
    tokio::task::spawn_blocking(move || {
        let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let mut session = ssh2::Session::new().expect("libssh2 session");
        session.set_tcp_stream(tcp.try_clone().expect("socket handle for the test"));
        session.handshake().expect("SSH handshake");
        session
            .userauth_password("operator", "anything")
            .expect("the static rule accepts every password");
        assert!(session.authenticated());
        (session, tcp)
    })
    .await
    .expect("libssh2 task")
}

/// Read the raw socket until the server closes it, bounded by `timeout`.
///
/// libssh2 puts its socket in non-blocking mode and the test's handle shares that file
/// description, so `WouldBlock` means "nothing yet", not an answer.
async fn peer_sees_close(mut tcp: TcpStream, timeout: Duration) -> bool {
    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + timeout;
        let mut buf = [0u8; 4096];
        while std::time::Instant::now() < deadline {
            match tcp.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return true,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return false,
            }
        }
        false
    })
    .await
    .expect("reader task")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authenticated_session_stays_active_and_ends_when_the_server_stops() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state, accept_everyone()).await;

    let (session, tcp) = authenticated_session(port).await;

    // Give a prematurely finished connection task every chance to mark itself closed: before
    // the fix it did so right after the banner exchange, well before authentication finished.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        active_connections(&state, server_id).await,
        1,
        "an authenticated, open SSH session must be Active in AppState; Closed here means the \
         connection task stopped owning the session after run_stream's setup phase"
    );

    state.remove_server(server_id).await;
    assert!(
        peer_sees_close(tcp, Duration::from_secs(10)).await,
        "the SSH socket was still open 10s after the server stopped: russh's session driver \
         outlived the connection task stop_server aborted"
    );
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_server_ends_a_connection_parked_on_a_manual_auth_decision() {
    let state = new_state().await;
    let (server_id, port) =
        start_server(&state, json!({"type": "manual", "timeout_secs": 300})).await;

    let (tcp_tx, tcp_rx) = std::sync::mpsc::channel::<TcpStream>();
    let client = tokio::task::spawn_blocking(move || {
        let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        tcp_tx
            .send(tcp.try_clone().expect("socket handle for the test"))
            .expect("hand the socket to the test");
        let mut session = ssh2::Session::new().expect("libssh2 session");
        session.set_tcp_stream(tcp);
        session.handshake().expect("SSH handshake");
        // Blocks until the parked decision is answered or the connection goes away.
        session.userauth_password("operator", "anything").is_ok()
    });
    let tcp = tokio::task::spawn_blocking(move || tcp_rx.recv().expect("socket"))
        .await
        .expect("socket task");

    let parked = wait_until(Duration::from_secs(20), || async {
        !state.list_intercepts().await.is_empty()
    })
    .await;
    assert!(parked, "the ssh_auth event never parked for a human");

    state.remove_server(server_id).await;

    assert!(
        peer_sees_close(tcp, Duration::from_secs(10)).await,
        "a connection parked on a manual authentication decision stayed open after its server \
         stopped"
    );
    let authenticated = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("libssh2 returned once the connection closed")
        .expect("libssh2 task");
    assert!(
        !authenticated,
        "nobody answered, so nobody may be logged in"
    );
    let retired = wait_until(Duration::from_secs(5), || async {
        state.list_intercepts().await.is_empty()
    })
    .await;
    assert!(
        retired,
        "the parked authentication request outlived its connection and would wait out its \
         300s timeout for an answer nobody can deliver"
    );
}
