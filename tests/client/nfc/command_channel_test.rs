//! The dashboard's `[ send ]` path on an NFC client.
//!
//! **What this environment can and cannot check.** The NFC client is a PC/SC reader client: it
//! refuses to start when `SCardListReaders` reports no reader, so on a machine without one the
//! injection half cannot run and there is no software stand-in for a contactless card. Claiming
//! otherwise would be a fabricated pass.
//!
//! The always-running test checks the rule that needs no hardware and is easiest to get wrong:
//! a client whose connect failed must not be left offering `[ send ]`. If a reader *is* present,
//! the same test runs the injection half for real, asserting that an unknown verb is `Rejected`
//! and that `read_ndef` comes back as an `Executed` naming what happened rather than silently
//! doing nothing.
//!
//! The NDEF codec and the APDU builder are pure functions over bytes, so they need no reader at
//! all and are pinned against literal specification bytes in `e2e_test.rs`.
//!
//! `send_apdu` against a real card is the `#[ignore]`d half. It is the only NFC verb that can
//! report `Sent`, and only when a card actually answered.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nfc-client --test client -- nfc::command_channel --test-threads=100

#![cfg(all(unix, feature = "pcsc"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "NFC client #{} never registered a command handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn command_channel_follows_the_reader() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // remote_addr is required by the form and ignored by the NFC client, which selects its
    // reader from startup params.
    let created = ClientForm {
        protocol: "nfc".to_string(),
        remote_addr: Some("pcsc:0".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "reader_index": 0 })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await;

    let client_id = match created {
        Err(e) => {
            // The expected path with no reader attached (and on any CI runner).
            for client in state.get_all_clients().await {
                assert!(
                    !state.has_client_handle(client.id).await,
                    "client #{} left a stale command handle after a failed reader open",
                    client.id.as_u32()
                );
                let sent = state
                    .send_to_client(
                        client.id,
                        serde_json::json!({"type": "send_apdu_raw", "apdu_hex": "00A4040000"}),
                        Duration::from_secs(2),
                    )
                    .await;
                assert!(
                    sent.is_err(),
                    "send_to_client must fail for a client with no handle, got {sent:?}"
                );
            }
            eprintln!("no PC/SC reader here, injection half skipped: {e:#}");
            return;
        }
        Ok(id) => id,
    };

    // A reader is attached: the rest runs for real.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_nfc_verb"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Rejected { error } => assert!(
            error.contains("no_such_nfc_verb"),
            "the rejection must name the verb, got {error:?}"
        ),
        other => panic!("expected Rejected{{..}}, got {other:?}"),
    }

    // read_ndef runs the real Type 4 APDU sequence. Whether it succeeds depends on what is
    // on the reader, which this test cannot control — so what is asserted is the part that
    // holds either way: the answer names the verb, and it is neither silence nor a claim of
    // success. (This assertion used to require the detail to say "not implemented", which was
    // true when the verb was a stub and became a lie the day it was implemented. It never
    // failed, because it only runs when a reader is attached.)
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "read_ndef"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client read_ndef");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("read_ndef"),
            "detail must name the verb and say what happened, got {detail:?}"
        ),
        other => panic!("expected Executed{{..}}, got {other:?}"),
    }

    for entry in state
        .list_access_logs_for(Some(AccessLogOwner::Client(client_id.as_u32())), None)
        .await
    {
        if serde_json::to_string(&entry)
            .unwrap_or_default()
            .contains("injected_action")
        {
            return;
        }
    }
    panic!("injected actions must be recorded in the client's access log");
}

/// Requires a PC/SC reader with a card presented on it. Run with `--ignored`.
///
/// Ignored because a contactless card cannot be emulated through PC/SC: `SCardConnect` needs a
/// card in the field, so there is no way to reach `Card::transmit` in software.
#[tokio::test]
#[ignore = "requires a PC/SC reader with a card presented"]
async fn injected_apdu_reaches_a_real_card() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "nfc".to_string(),
        remote_addr: Some("pcsc:0".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "reader_index": 0 })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("a PC/SC reader must be attached");

    wait_for_client_handle(&state, client_id).await;

    // SELECT by AID header, 5 bytes. Sent{5} only if the card really answered.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_apdu_raw", "apdu_hex": "00A4040000"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 5 }),
        "expected Sent{{5}} from a card that answered, got {outcome:?}"
    );
}
