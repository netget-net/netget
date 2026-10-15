//! Vault with a mocked model, driven by the real `vault` CLI.
//!
//! The model is the storage: one rule per event, and the write rule's generator keeps what it
//! was given so the read rule can return it — the shape an LLM holding secrets in memory has.
//! The token is configured, so the events carry `token_configured: true`, and one request with
//! a wrong token is refused by the model on the event's `token_matches_configured`. The test
//! also asserts that the token string itself never appears in anything the model was sent.
//!
//! LLM calls: 6 — the startup instruction, `kv put`, `kv get`, `kv list`, a wrong-token
//! `kv get`, and `kv metadata get`. `status` and every KV preflight are served without the model.

use super::real_client_test::{require_tool, vault, FIXTURE_TOKEN};
use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn test_vault_cli_against_a_mocked_model() -> E2EResult<()> {
    let bin = require_tool("vault");
    let stored: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let seen_events: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let (store_w, store_r) = (stored.clone(), stored.clone());
    let (seen_w, seen_r, seen_l) = (
        seen_events.clone(),
        seen_events.clone(),
        seen_events.clone(),
    );

    let config =
        NetGetConfig::new("Open a Vault server on port {AVAILABLE_PORT} for the payments team")
            .with_mock(move |mock| {
                mock.on_instruction_containing("Vault server")
                    .respond_with_actions(json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "vault",
                        "instruction": "Payments team secrets. Remember every write.",
                        "startup_params": {"token": FIXTURE_TOKEN}
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("vault_write")
                    .respond_with_actions_from_event(move |event| {
                        seen_w.lock().unwrap().push(event.clone());
                        *store_w.lock().unwrap() = Some(event["data"].clone());
                        json!([{"type": "send_vault_write_ok", "version": 1}])
                    })
                    .expect_calls(1)
                    .and()
                    .on_event("vault_read")
                    .respond_with_actions_from_event(move |event| {
                        seen_r.lock().unwrap().push(event.clone());
                        if event["token_matches_configured"] != true {
                            return json!([{"type": "send_vault_error", "status": 403,
                                       "errors": ["permission denied"]}]);
                        }
                        match store_r.lock().unwrap().clone() {
                            Some(data) => json!([{"type": "send_vault_secret", "data": data,
                                              "version": 1}]),
                            None => {
                                json!([{"type": "send_vault_error", "status": 404, "errors": []}])
                            }
                        }
                    })
                    .expect_calls(3)
                    .and()
                    .on_event("vault_list")
                    .respond_with_actions_from_event(move |event| {
                        seen_l.lock().unwrap().push(event.clone());
                        json!([{"type": "send_vault_list", "keys": ["stripe"]}])
                    })
                    .expect_calls(1)
                    .and()
            });

    let server = helpers::start_netget_server(config).await?;
    let home = tempfile::TempDir::new()?;
    let h = home.path();

    let status = vault(&bin, h, server.port, FIXTURE_TOKEN, &["status"]).await;
    assert_eq!(status.code, 0, "{}", status.stderr);

    let put = vault(
        &bin,
        h,
        server.port,
        FIXTURE_TOKEN,
        &[
            "kv",
            "put",
            "secret/payments/stripe",
            "api_key=sk_test_netget",
        ],
    )
    .await;
    assert_eq!(put.code, 0, "{}", put.stderr);

    let get = vault(
        &bin,
        h,
        server.port,
        FIXTURE_TOKEN,
        &["kv", "get", "-field=api_key", "secret/payments/stripe"],
    )
    .await;
    assert_eq!(
        get.stdout, "sk_test_netget",
        "the model returned what it was given: {}",
        get.stderr
    );

    let list = vault(
        &bin,
        h,
        server.port,
        FIXTURE_TOKEN,
        &["kv", "list", "secret/payments"],
    )
    .await;
    assert!(
        list.stdout.lines().any(|l| l.trim() == "stripe"),
        "{}",
        list.stdout
    );

    let denied = vault(
        &bin,
        h,
        server.port,
        "hvs.not-the-token",
        &["kv", "get", "secret/payments/stripe"],
    )
    .await;
    assert!(denied.stderr.contains("Code: 403"), "{}", denied.stderr);

    let meta = vault(
        &bin,
        h,
        server.port,
        FIXTURE_TOKEN,
        &["kv", "metadata", "get", "secret/payments/stripe"],
    )
    .await;
    assert_eq!(meta.code, 0, "{}", meta.stderr);

    // What the model saw: structured fields, booleans for the token, never the token.
    let events = seen_events.lock().unwrap().clone();
    assert_eq!(events.len(), 5, "{events:?}");
    for e in &events {
        let text = e.to_string();
        assert!(
            !text.contains(FIXTURE_TOKEN) && !text.contains("hvs.not-the-token"),
            "{text}"
        );
        assert_eq!(e["mount"], "secret");
        assert_eq!(e["token_configured"], true);
    }
    assert_eq!(events[0]["path"], "payments/stripe");
    assert_eq!(events[0]["data"], json!({"api_key": "sk_test_netget"}));
    assert!(events
        .iter()
        .any(|e| e["token_matches_configured"] == false));
    assert!(events.iter().any(|e| e["what"] == "metadata"));

    for tag in ["decision=model_answer", "decision=model_reject"] {
        server.wait_for_any(&[tag], 30).await;
        assert!(
            server.output_contains(tag).await,
            "expected {tag} in the log"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
