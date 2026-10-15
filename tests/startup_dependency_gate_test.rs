//! The startup dependency gate (IMPROVEMENTS item 20b): a server or client whose runtime
//! dependency is **definitively** absent is refused with the dependency and its install hint
//! before anything is registered — and a probe that merely cannot tell never refuses.
//!
//! gRPC is the protocol under test because it is the one that overrides `get_dependencies()`
//! with a real runtime tool (`protoc`, which it runs via `Command::new` to compile `.proto`
//! text); the other overrides are `wireguard`'s `wireguard-go`, which sits behind a `Root`
//! requirement that refuses first on an unprivileged host.
//!
//! Controlling `PATH` is how "absent" is produced, so this file is its own test binary with a
//! single test: nothing else in the process reads `PATH` while it is being changed.
//!
//! Five starts, each asserted on what the caller gets back:
//!
//! 1. server, inline `.proto` text, `PATH` without `protoc` → refused, names `protoc` and how to
//!    install it, and no server row is left behind;
//! 2. server, pre-compiled base64 descriptor set, same `PATH` → **not** refused: that form never
//!    runs `protoc`, so refusing it would block a start that works;
//! 3. server, inline text, `PATH` **unset** → not refused by the gate: the probe cannot search a
//!    `PATH` that does not exist, and "could not tell" is not "no";
//! 4. server, inline text, `PATH` holding an executable `protoc` → the gate passes;
//! 5. client, inline text, `PATH` without `protoc` → refused the same way, no client row left.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features grpc,tcp \
//!       --test startup_dependency_gate_test -- --test-threads=100


use base64::Engine as _;
use netget::cli::{client_startup, server_startup};
use netget::llm::OllamaClient;
use netget::state::app_state::AppState;
use prost::Message as _;
use tokio::sync::mpsc;

const INLINE_PROTO: &str = "syntax = \"proto3\"; package gate; service Echo { rpc Say(Msg) returns (Msg); } message Msg { string text = 1; }";

/// The refusal's own wording; anything else is some later, unrelated failure.
const REFUSAL: &str = "Tool 'protoc' must be available in PATH";

fn base64_descriptor_set() -> String {
    let fds = prost_types::FileDescriptorSet {
        file: vec![prost_types::FileDescriptorProto {
            name: Some("gate.proto".into()),
            package: Some("gate".into()),
            syntax: Some("proto3".into()),
            ..Default::default()
        }],
    };
    base64::engine::general_purpose::STANDARD.encode(fds.encode_to_vec())
}

async fn start_grpc_server(state: &AppState, schema: &str) -> anyhow::Result<()> {
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = server_startup::start_server_from_action(
        state,
        None,
        None,
        Some("127.0.0.1".into()),
        Some(0),
        "grpc",
        false,
        None,
        String::new(),
        Some(serde_json::json!({ "proto_schema": schema })),
        None,
        None,
        None,
        tx,
    )
    .await?;
    state.remove_server(id).await;
    Ok(())
}

fn not_the_refusal(result: &anyhow::Result<()>, case: &str) {
    if let Err(e) = result {
        assert!(
            !format!("{e:#}").contains(REFUSAL),
            "{case}: the dependency gate refused a start it must let through: {e:#}"
        );
    }
}

#[tokio::test]
async fn startup_refuses_only_a_definitively_missing_dependency() {
    let original_path = std::env::var_os("PATH");
    let empty = tempfile::tempdir().expect("empty dir");
    let with_protoc = tempfile::tempdir().expect("protoc dir");
    let fake = with_protoc.path().join("protoc");
    std::fs::write(&fake, "#!/bin/sh\nexit 1\n").expect("fake protoc");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let state = AppState::new();
    state
        .set_llm_client(OllamaClient::new("http://127.0.0.1:1".to_string()))
        .await;

    // 1. Definitively absent: refused, named, nothing registered.
    std::env::set_var("PATH", empty.path());
    let refused = start_grpc_server(&state, INLINE_PROTO).await;
    let message = format!(
        "{:#}",
        refused.expect_err("a start without protoc must be refused")
    );
    assert!(message.contains(REFUSAL), "names the dependency: {message}");
    assert!(
        message.contains("Install from"),
        "carries the install hint: {message}"
    );
    assert!(
        state.get_all_servers().await.is_empty(),
        "a refused start leaves no server row behind"
    );

    // 2. A pre-compiled descriptor set never runs protoc: not refused.
    let precompiled = start_grpc_server(&state, &base64_descriptor_set()).await;
    not_the_refusal(&precompiled, "base64 descriptor set without protoc");

    // 3. No PATH at all: the probe cannot answer, so the gate must not refuse.
    std::env::remove_var("PATH");
    let unknown = start_grpc_server(&state, INLINE_PROTO).await;
    not_the_refusal(&unknown, "PATH unset");

    // 4. An executable protoc on PATH: the gate passes (the fake then fails to compile).
    std::env::set_var("PATH", with_protoc.path());
    let present = start_grpc_server(&state, INLINE_PROTO).await;
    not_the_refusal(&present, "protoc present");

    // 5. The client half is gated the same way.
    std::env::set_var("PATH", empty.path());
    let client = client_startup::start_client_from_action(
        &state,
        "grpc",
        "127.0.0.1:1",
        String::new(),
        Some(serde_json::json!({ "proto_schema": INLINE_PROTO })),
        None,
        None,
        None,
        None,
        OllamaClient::new("http://127.0.0.1:1".to_string()),
        None,
    )
    .await;

    match original_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }

    let message = format!(
        "{:#}",
        client.expect_err("a client start without protoc must be refused")
    );
    assert!(message.contains(REFUSAL), "names the dependency: {message}");
    assert!(
        state.get_all_clients().await.is_empty(),
        "a refused client start leaves no client row behind"
    );
}
