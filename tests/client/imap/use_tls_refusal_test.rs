//! `use_tls: true` must be refused, not silently ignored.
//!
//! `use_tls` was declared in `get_startup_parameters()` and documented twice in
//! `src/client/imap/CLAUDE.md` ("Upgrade to TLS if port 993 or `use_tls=true`"), while nothing
//! in `src/client/imap/` read it — this client drives `async_imap` over a plain `TcpStream` and
//! has no TLS support at all. So asking for TLS produced a cleartext session carrying the
//! password, with both the parameter list and the documentation claiming otherwise.
//!
//! Refusing is the fix rather than silence, following the same rule as `bluetooth_ble_beacon`:
//! declining out loud with a reason beats a capability that quietly does nothing. Nobody should
//! hand credentials to a plaintext socket believing it is encrypted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features imap --test client -- imap::use_tls --test-threads=100


use std::sync::Arc;

use netget::client::imap::ImapClient;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::sync::mpsc;

fn params(use_tls: Option<bool>) -> netget::protocol::StartupParams {
    let mut map = serde_json::Map::new();
    map.insert("username".into(), serde_json::json!("user@example.com"));
    map.insert("password".into(), serde_json::json!("hunter2"));
    if let Some(v) = use_tls {
        map.insert("use_tls".into(), serde_json::json!(v));
    }
    use netget::llm::actions::protocol_trait::Protocol;
    let schema = netget::client::imap::actions::ImapClientProtocol::new().get_startup_parameters();
    netget::protocol::StartupParams::new(serde_json::Value::Object(map), schema)
        .expect("declared parameters")
}

#[tokio::test]
async fn use_tls_true_is_refused_with_a_reason() {
    let state = Arc::new(AppState::new_with_options(
        false,
        "http://127.0.0.1:1".to_string(),
    ));
    let (tx, _rx) = mpsc::unbounded_channel();

    // 127.0.0.1:1 is not an IMAP server. The point is that this must fail on the TLS refusal
    // *before* any socket is opened, so the address never matters.
    let err = ImapClient::connect_with_llm_actions(
        "127.0.0.1:1".to_string(),
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        state,
        tx,
        ClientId::new(1),
        Some(params(Some(true))),
    )
    .await
    .expect_err("use_tls: true must be refused");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not implement TLS"),
        "the refusal must say TLS is unimplemented, not fail as a connection error: {msg}"
    );
    assert!(
        msg.contains("cleartext"),
        "the refusal must say what would otherwise happen to the password: {msg}"
    );
}
