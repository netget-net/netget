//! The dashboard's `[ send ]` path on an NFS client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, and the ONC-RPC call reaches a NetGet NFS
//! server of our own over a real socket.
//!
//! Zero LLM calls. The server answers through one `*` static rule — each of its VFS callbacks
//! sieves the batch for the response type it wants, so one rule carrying both
//! `nfs_lookup_response` and `nfs_getattr_response` covers a LOOKUP (whose reply also carries
//! post-op attributes). The client's LLM points at an unreachable URL, so its connected-event
//! call fails; the loop tolerates that and the command task is independent of it by design.
//!
//! **Why the export is `/` and why the ports are pinned.** `nfsserve` multiplexes portmapper,
//! MOUNT and NFS on the single port it binds and its portmapper always answers with that same
//! port, so the client has to be told where all three live — otherwise `nfs3_client` asks
//! 111 no matter what address it was given. `privileged_source_port` is turned off because
//! the default binds a local port below 1024, which needs root. Export `/` maps to
//! `root_dir()` without a VFS lookup, so MOUNT itself needs no handler.
//!
//! Outcome semantics under test: `nfs3_client` frames every RPC, so an operation that ran
//! reports `Executed` naming it and summarising the reply. There is no byte count this client
//! can honestly claim.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nfs --test client -- nfs::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use tokio::sync::mpsc;

const MARKER: &str = "dashboard-marker";

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
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("NFS server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "NFS client #{} never registered a command handle",
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
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_nfs_operation_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "nfs".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [
                    {"type": "nfs_lookup_response", "fileid": 2},
                    {
                        "type": "nfs_getattr_response",
                        "fileid": 2,
                        "file_type": "regular",
                        "mode": 420,
                        "size": 11
                    }
                ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create nfs server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "nfs".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}:/")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "portmapper_port": port,
            "mount_port": port,
            "nfs_port": port,
            "privileged_source_port": false
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create nfs client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "nfs_lookup", "path": format!("/{MARKER}")}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client nfs_lookup");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("nfs_lookup") && detail.contains(MARKER),
            "detail should name the operation and its reply, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and seen by the server — which is
    // what proves the LOOKUP actually crossed the connection.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(&state, AccessLogOwner::Server(server_id.as_u32()), MARKER).await;

    // An action the protocol refuses never reaches the server.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_real_action"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client unknown action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client should have dropped its command handle after an injected disconnect");
}
