//! Two things the CouchDB server must refuse rather than wave through.
//!
//! **An oversized request body.** `Incoming` has no default limit, so the handler buffered
//! whatever an unauthenticated peer chose to send — one `POST /db/_bulk_docs` was enough to
//! exhaust the process — and the body is then embedded whole in an LLM prompt, so there is no
//! legitimate large one either. The refusal has to land *before* the LLM call, which is why
//! this test counts model calls as well as checking the status.
//!
//! **A replication response nothing asserted.** `send_replication_response` declared every
//! parameter optional and defaulted every one, so a bare `{"type":
//! "send_replication_response"}` produced `{"ok": true}` — the most affirmative body the
//! replication protocol has — complete with the literal session id `"abc123"` and
//! `source_last_seq: "0"`. That is the OAuth2 fail-open shape: a model that meant to say
//! nothing said yes, and a peer stored a checkpoint for a replication that never ran.

use crate::server::helpers::*;
use ::netget::llm::actions::protocol_trait::Server;
use ::netget::server::CouchDbProtocol;
use serde_json::json;

#[tokio::test]
async fn an_oversized_body_is_refused_with_413_before_any_llm_call() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen for CouchDB")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "CouchDB",
                    "instruction": "Handle CouchDB protocol events"
                }]))
                .expect_calls(1)
                .and()
            // Deliberately no rule for `couchdb_request`. If the oversized body reached the
            // model the request would fall through to a real LLM call, the mock would answer
            // HTTP 500, and the assertions below would see something other than 413.
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;

    // Comfortably past the 8 MiB cap, and cheap to build.
    let oversized = "x".repeat(9 * 1024 * 1024);
    let body = format!(r#"{{"docs":[{{"_id":"big","blob":"{oversized}"}}]}}"#);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/mydb/_bulk_docs"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    assert_eq!(
        resp.status(),
        413,
        "an oversized body must be refused with 413; a 500 would mean it reached the model \
         and a 2xx would mean it was silently truncated to nothing and answered as an empty \
         bulk update"
    );
    let json: serde_json::Value = resp.json().await?;
    assert_eq!(json["error"], "too_large");

    // The refusal costs no LLM call: only the startup rule fires.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

#[test]
fn send_replication_response_cannot_claim_a_replication_nobody_ran() {
    let p = CouchDbProtocol::new();

    for action in [
        json!({"type": "send_replication_response"}),
        json!({"type": "send_replication_response", "session_id": "abc123"}),
        json!({"type": "send_replication_response", "source_last_seq": "10-xyz"}),
        json!({"type": "send_replication_response", "session_id": "", "source_last_seq": "1-a"}),
    ] {
        p.execute_action(action.clone()).expect_err(&format!(
            "{action} must be refused, not defaulted into ok:true"
        ));
    }

    p.execute_action(json!({
        "type": "send_replication_response",
        "session_id": "abc123",
        "source_last_seq": "10-xyz"
    }))
    .expect("a complete replication response is still accepted");
}

/// `total_rows` and `last_seq` are declared `required: true` and are statements about the
/// database, not decoration: a replicator uses `last_seq` as the checkpoint it resumes from,
/// and `total_rows: 0` beside a non-empty `rows` array is a response no client can reconcile.
#[test]
fn result_set_metadata_is_not_defaulted() {
    let p = CouchDbProtocol::new();
    let rows = json!([{"id": "doc1", "key": "doc1", "value": {"rev": "1-abc"}}]);

    for action in [
        json!({"type": "send_all_docs", "rows": rows}),
        json!({"type": "send_view_response", "rows": rows}),
        json!({"type": "send_changes_response", "results": rows}),
    ] {
        p.execute_action(action.clone())
            .expect_err(&format!("{action} must be refused"));
    }

    p.execute_action(json!({"type": "send_all_docs", "total_rows": 1, "rows": rows}))
        .expect("a complete send_all_docs is still accepted");
    p.execute_action(json!({
        "type": "send_changes_response", "results": rows, "last_seq": "2-def"
    }))
    .expect("a complete send_changes_response is still accepted");
}
