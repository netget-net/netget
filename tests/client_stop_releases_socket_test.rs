//! Regression tests: stopping a client must actually stop it.
//!
//! `ClientInstance.handle` was never populated — there was no
//! `register_client_task()` — so every client protocol spawned its read/LLM loop
//! detached. `remove_client()` dropped the bookkeeping while the socket stayed
//! open and the loop kept invoking the model. Dropping a Tokio `JoinHandle` only
//! DETACHES the task; it has to be aborted (IMPROVEMENTS.md item 10).
//!
//! No Ollama required: the TCP client is pointed at an unreachable Ollama URL and
//! the resulting error is logged and ignored, which is the same path a real client
//! takes when the backend is down.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test client_stop_releases_socket_test -- --test-threads=100

use netget::state::app_state::AppState;
use netget::state::client::ClientInstance;
use netget::state::ClientId;
use std::sync::Arc;
use std::time::Duration;

/// Register a client instance so the test has a client to operate on.
async fn add_placeholder_client(state: &Arc<AppState>, proto: &str, remote: &str) -> ClientId {
    let client = ClientInstance::new(
        ClientId::new(0),
        remote.to_string(),
        proto.to_string(),
        "test".to_string(),
    );
    state.add_client(client).await
}

/// Registered tasks are aborted by `remove_client`, and a task registered against
/// an already-removed client is aborted immediately.
#[tokio::test]
async fn remove_client_aborts_every_registered_task() {
    let state = Arc::new(AppState::new());
    let client_id = add_placeholder_client(&state, "tcp", "127.0.0.1:1").await;

    // Several tasks, to prove handles accumulate rather than overwrite each other
    // (the server-side `register_server_task` keeps only the last one).
    let flags: Vec<Arc<std::sync::atomic::AtomicBool>> = (0..3)
        .map(|_| Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .collect();

    for flag in &flags {
        let flag = flag.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        state.register_client_task(client_id, handle).await;
    }

    // Let them all run at least once.
    tokio::time::sleep(Duration::from_millis(60)).await;
    for (i, flag) in flags.iter().enumerate() {
        assert!(
            flag.load(std::sync::atomic::Ordering::SeqCst),
            "task {} should have run before the stop",
            i
        );
    }

    assert!(state.remove_client(client_id).await.is_some());

    // After the abort, none of them may tick again.
    for flag in &flags {
        flag.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    for (i, flag) in flags.iter().enumerate() {
        assert!(
            !flag.load(std::sync::atomic::Ordering::SeqCst),
            "task {} kept running after remove_client — the handle leaked",
            i
        );
    }

    // Registering against a client that is already gone must not leak either.
    let orphan_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = orphan_flag.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(5)).await;
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    state.register_client_task(client_id, handle).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        !orphan_flag.load(std::sync::atomic::Ordering::SeqCst),
        "a task registered against a removed client must be aborted on the spot"
    );
}

/// End-to-end: a real TCP client's read loop dies with the client, releasing the
/// connection. Before the fix the loop outlived `remove_client` and the peer never
/// saw the connection close.
#[tokio::test]
async fn stopping_tcp_client_closes_its_connection() {
    use netget::client::tcp::TcpClient;
    use netget::llm::ollama_client::OllamaClient;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accepted = tokio::spawn(async move { listener.accept().await });

    let state = Arc::new(AppState::new());
    let client_id = add_placeholder_client(&state, "tcp", &addr.to_string()).await;

    // Unreachable Ollama: the connected-event LLM call fails fast and is logged,
    // which is exactly the path a real client takes when the backend is down.
    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    TcpClient::connect_with_llm_actions(addr.to_string(), llm, state.clone(), status_tx, client_id)
        .await
        .expect("tcp client should connect");

    let (mut peer, _) = accepted
        .await
        .expect("accept task")
        .expect("server should accept the client");

    // The read loop must have been registered.
    assert!(
        state.remove_client(client_id).await.is_some(),
        "client should still be present before stop"
    );

    // Once the read loop is aborted both halves of the stream drop, so the peer
    // observes EOF. Without the abort this read blocks until the test times out.
    let mut buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut buf)).await;

    match eof {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("expected EOF after stop_client, got {} bytes", n),
        Ok(Err(e)) => {
            // A reset is equally good evidence that the socket went away.
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ),
                "unexpected error waiting for close: {}",
                e
            );
        }
        Err(_) => panic!(
            "connection still open 5s after remove_client — the client's read loop \
             outlived the client (register_client_task not wired up?)"
        ),
    }
}
