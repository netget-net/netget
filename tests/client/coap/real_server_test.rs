//! The CoAP client against libcoap's **`coap-server`** — the evidence its maturity rating rests
//! on.
//!
//! NetGet encodes and decodes CoAP with the codec its own server uses
//! (`src/server/coap/codec.rs`). The server here is libcoap 4.3, a C implementation, spawned per
//! test on a probed loopback port; it serves `/`, an observable `/time` and a writable, observable
//! `/example_data`. What it holds is written and read back with libcoap's own **`coap-client`**.
//! Nothing on the wire was written by this repository except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire —
//! is asserted from the server's side: `coap-client` reads back a value the mocked model PUT,
//! built from a Block2 transfer the model was shown whole.
//!
//! **No test here skips.** A missing `coap-server` or `coap-client` fails with the install
//! command.
//!
//! LLM calls: 7 or more in the first test (every `/time` notification that arrives before the
//! cancellation lands is one turn). None in the second, whose model endpoint is unreachable on
//! purpose.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features coap --test client -- coap::real_server_test --test-threads=100

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const LIBCOAP: InstallHint = InstallHint {
    brew: "libcoap",
    apt: "libcoap2-bin (Ubuntu 22.04) or libcoap3-bin",
};

/// libcoap's example server on loopback, verbose enough to log its endpoints. It also opens a
/// TCP endpoint on the same port (CoAP over TCP), which nothing here uses.
async fn start_coap_server() -> E2EResult<RealServer> {
    RealServer::builder("coap-server", LIBCOAP)
        .args(["-A", "127.0.0.1", "-p", "{port}", "-v", "7"])
        .ready_when_log_matches(r"created UDP\s+endpoint")
        .without_tcp_readiness()
        .start()
        .await
}

fn uri(server: &RealServer, path: &str) -> String {
    format!("coap://127.0.0.1:{}{path}", server.port)
}

/// `coap-client -m get <uri>`, trailing newline dropped.
async fn coap_get(server: &RealServer, path: &str) -> E2EResult<String> {
    let mut cmd = Command::new("coap-client");
    cmd.args(["-m", "get", &uri(server, path)]);
    Ok(run_tool(cmd, "coap-client", LIBCOAP)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// The body `coap-client` prepares: 3000 bytes, three 1024-byte blocks when read back.
fn big_body() -> String {
    "0123456789".repeat(300)
}

/// Block2, PUT, Observe and its cancellation against libcoap, and the PUT read back.
///
/// 1. `coap-client` PUTs a 3000-byte body to `/example_data` (itself block-wise, `-b 1024`).
/// 2. On `coap_connected` the model GETs `/example_data`. libcoap answers in 1024-byte Block2
///    blocks; the model is shown **one** `coap_response` with all 3000 bytes and `blocks: 3`.
/// 3. It PUTs `the model read 3000 bytes ending in 0123456789` back to `/example_data`.
/// 4. On that 2.04 it observes `/time`: a `coap_response` with `observing: true`, then
///    `coap_notification`s, the first of which it answers with `coap_observe_cancel`.
/// 5. The cancellation's response arrives with `observing: false`.
///
/// Then `coap-client` must read the model's sentence from `/example_data`.
#[tokio::test]
async fn coap_client_reassembles_puts_and_observes_against_libcoap() -> E2EResult<()> {
    let server = start_coap_server().await?;
    let result = reassembles_puts_and_observes(&server).await;
    server.with_log(result)
}

async fn reassembles_puts_and_observes(server: &RealServer) -> E2EResult<()> {
    let body_file = server.dir().join("big.txt");
    std::fs::write(&body_file, big_body())?;
    let mut put = Command::new("coap-client");
    put.args(["-m", "put", "-b", "1024", "-f"])
        .arg(&body_file)
        .arg(uri(server, "/example_data"));
    run_tool(put, "coap-client", LIBCOAP).await?;
    assert_eq!(coap_get(server, "/example_data").await?, big_body());

    let addr = server.addr();
    let config = NetGetConfig::new(format!("Talk CoAP to {addr}. COAP-REAL-SERVER-STARTUP."))
        .with_mock(move |mock| {
            mock.on_instruction_containing("COAP-REAL-SERVER-STARTUP")
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "protocol": "CoAP",
                    "remote_addr": addr,
                    "instruction": "Read /example_data, write back what you read, then watch /time."
                }]))
                .expect_calls(1)
                .and()
                .on_event("coap_connected")
                .respond_with_actions(json!([{"type": "coap_get", "path": "/example_data"}]))
                .expect_calls(1)
                .and()
                .on_event("coap_response")
                .and_event_data_contains("method", "GET")
                .and_event_data_contains("path", "/example_data")
                .and_event_data_contains("code", "2.05")
                .and_event_data_contains("blocks", "3")
                .and_event_data_contains("payload_size", "3000")
                .respond_with_actions_from_event(|event| {
                    // What the model writes back says whether the body it was shown is the body
                    // coap-client stored, byte for byte and in block order; the final read-back
                    // asserts on it.
                    let payload = event["payload"].as_str().unwrap_or("");
                    let sentence = if payload == "0123456789".repeat(300) {
                        let tail = &payload[payload.len() - 10..];
                        format!("the model read {} bytes ending in {tail}", payload.len())
                    } else {
                        format!("REASSEMBLY MISMATCH: {} bytes", payload.len())
                    };
                    json!([{"type": "coap_put", "path": "/example_data", "payload": sentence}])
                })
                .expect_calls(1)
                .and()
                .on_event("coap_response")
                .and_event_data_contains("method", "PUT")
                .and_event_data_contains("path", "/example_data")
                .and_event_data_contains("code", "2.0")
                .respond_with_actions(json!([{"type": "coap_observe", "path": "/time"}]))
                .expect_calls(1)
                .and()
                .on_event("coap_response")
                .and_event_data_contains("path", "/time")
                .and_event_data_contains("observing", "true")
                .respond_with_actions(json!([]))
                .expect_calls(1)
                .and()
                .on_event("coap_notification")
                .and_event_data_contains("path", "/time")
                .respond_with_actions(json!([{"type": "coap_observe_cancel", "path": "/time"}]))
                .expect_at_least(1)
                .and()
                // A second notification that arrives while the first cancellation is in flight
                // asks to cancel an observation that is already being cancelled.
                .on_event("coap_error")
                .and_event_data_contains("kind", "not_observing")
                .respond_with_actions(json!([]))
                .expect_at_most(10)
                .and()
                .on_event("coap_response")
                .and_event_data_contains("path", "/time")
                .and_event_data_contains("observing", "false")
                .respond_with_actions(json!([]))
                .expect_calls(1)
                .and()
        });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        coap_get(server, "/example_data").await?,
        "the model read 3000 bytes ending in 0123456789",
        "libcoap must hold what the model PUT, built from the Block2 body it was shown"
    );
    client.stop().await?;
    Ok(())
}

/// The dashboard's `[ send ]` / MCP `send_to_client` path against the same server: an injected
/// PUT that `coap-client` reads back, a payload over 64 KiB refused before the wire, and a
/// `disconnect`.
#[tokio::test]
async fn injected_coap_put_reaches_libcoap() -> E2EResult<()> {
    let server = start_coap_server().await?;
    let result = injected_put(&server).await;
    server.with_log(result)
}

async fn injected_put(server: &RealServer) -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;
    use ::netget::state::ClientStatus;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "coap".to_string(),
        remote_addr: Some(server.addr()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create coap client: {e}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !state.has_client_handle(client_id).await {
        if std::time::Instant::now() > deadline {
            return Err("coap client never registered a command handle".into());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let outcome = state
        .send_to_client(
            client_id,
            json!({"type": "coap_put", "path": "/example_data", "payload": "from the dashboard"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected Sent, got {outcome:?}"
    );
    let outcome = state
        .send_to_client(
            client_id,
            json!({
                "type": "coap_put",
                "path": "/example_data",
                "payload": "x".repeat(::netget::server::coap::codec::MAX_REPRESENTATION_LEN + 1)
            }),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "a payload over MAX_REPRESENTATION_LEN must be refused before the wire, got {outcome:?}"
    );

    let mut value = String::new();
    for _ in 0..100 {
        value = coap_get(server, "/example_data").await.unwrap_or_default();
        if value == "from the dashboard" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        value, "from the dashboard",
        "libcoap must hold the injected PUT"
    );

    let outcome = state
        .send_to_client(
            client_id,
            json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );
    for _ in 0..300 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Err("client should be Disconnected with no command handle".into())
}
