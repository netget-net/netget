//! `use_tls: true` must be refused, not silently ignored.
//!
//! Mirrors `tests/client/imap/use_tls_refusal_test.rs`, because POP3 had the identical defect:
//! `use_tls` was declared in `get_startup_parameters()` and read by nothing, and this client
//! has no TLS — it speaks POP3 over a plain `TcpStream`. A POP3 session's next move after the
//! greeting is `USER`/`PASS`, so silently downgrading meant the password went out in cleartext
//! while the parameter said the connection was encrypted.
//!
//! Worth recording: this was thought to be unfixable here. The note on the drift baseline said
//! `connect_with_llm_actions` "does not receive startup parameters at all, so nothing *can*
//! read it" — but that signature is per-protocol, so passing them through was the whole fix.
//! The same reasoning would have wrongly excused any other client.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features pop3 --test client -- pop3::use_tls --test-threads=100

use std::sync::Arc;

use netget::client::pop3::Pop3Client;
use netget::llm::actions::protocol_trait::Protocol;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::sync::mpsc;

fn params(use_tls: bool) -> netget::protocol::StartupParams {
    let mut map = serde_json::Map::new();
    map.insert("use_tls".into(), serde_json::json!(use_tls));
    let schema = netget::client::pop3::actions::Pop3ClientProtocol::new().get_startup_parameters();
    netget::protocol::StartupParams::new(serde_json::Value::Object(map), schema)
        .expect("use_tls is a declared parameter")
}

#[tokio::test]
async fn use_tls_true_is_refused_with_a_reason() {
    let state = Arc::new(AppState::new_with_options(
        false,
        "http://127.0.0.1:1".to_string(),
    ));
    let (tx, _rx) = mpsc::unbounded_channel();

    // 127.0.0.1:1 is not a POP3 server. The point is that this fails on the TLS refusal
    // *before* any socket is opened, so the address never matters.
    let err = Pop3Client::connect_with_llm_actions(
        "127.0.0.1:1".to_string(),
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        state,
        tx,
        ClientId::new(1),
        Some(params(true)),
    )
    .await
    .expect_err("use_tls: true must be refused");

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("tls"),
        "the refusal must say TLS is what could not be honoured: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("cleartext") || msg.to_lowercase().contains("plain"),
        "the refusal must say what would otherwise happen to the credentials: {msg}"
    );
}
