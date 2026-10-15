//! What the Modbus client does when a device answers wrongly or not at all.
//!
//! No real device misbehaves on request, so the "device" here is a few lines of test code: it
//! answers the first request with another function's response, and never answers anything
//! after that. The model must be told both — `modbus_error {kind: bad_response}` and then
//! `modbus_error {kind: timeout}` — rather than shown a wrong value or left waiting forever. A
//! second test fills the request queue (`MAX_QUEUED`) against the same silence.
//!
//! LLM calls: 4 in the first test, none in the second.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features modbus --test client -- modbus::unanswered_test --test-threads=100


use crate::helpers::*;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Accept one connection. Answer the first ADU with an FC 4 response whatever it asked, then
/// read and ignore everything.
async fn misbehaving_device() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut header = [0u8; 7];
        if sock.read_exact(&mut header).await.is_err() {
            return;
        }
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let mut pdu = vec![0u8; len.saturating_sub(1)];
        if sock.read_exact(&mut pdu).await.is_err() {
            return;
        }
        // Same transaction id and unit, FC 4 with one register: not an answer to FC 3.
        let reply = [
            header[0], header[1], 0, 0, 0, 5, header[6], 0x04, 0x02, 0x00, 0x2A,
        ];
        let _ = sock.write_all(&reply).await;
        let mut sink = [0u8; 1024];
        while let Ok(n) = sock.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    });
    (addr, task)
}

#[tokio::test]
async fn a_wrong_answer_and_no_answer_both_reach_the_model() -> E2EResult<()> {
    let (addr, device) = misbehaving_device().await;
    let addr = addr.to_string();
    let config = NetGetConfig::new(format!(
        "Connect to the Modbus device at {addr}. MODBUS-UNANSWERED-STARTUP."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("MODBUS-UNANSWERED-STARTUP")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Modbus",
                "remote_addr": addr,
                "instruction": "Read holding register 0."
            }]))
            .expect_calls(1)
            .and()
            .on_event("modbus_connected")
            .respond_with_actions(json!([{
                "type": "modbus_read_holding_registers", "address": 0, "quantity": 1
            }]))
            .expect_calls(1)
            .and()
            .on_event("modbus_error")
            .and_event_data_contains("kind", "bad_response")
            .and_event_data_contains("function", "read_holding_registers")
            .respond_with_actions(json!([{
                "type": "modbus_read_holding_registers", "address": 1, "quantity": 1
            }]))
            .expect_calls(1)
            .and()
            .on_event("modbus_error")
            .and_event_data_contains("kind", "timeout")
            .and_event_data_contains("address", "1")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    device.abort();
    Ok(())
}

#[tokio::test]
async fn requests_past_the_queue_bound_are_refused() -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;

    // A device that never answers anything.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let silent = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut sink = [0u8; 4096];
        while let Ok(n) = sock.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    });

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "modbus".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create modbus client: {e}"))?;
    for _ in 0..1_000 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut sent = 0;
    let mut refused = None;
    for i in 0..100u16 {
        let outcome = state
            .send_to_client(
                client_id,
                json!({"type": "modbus_read_coils", "address": i, "quantity": 1}),
                Duration::from_secs(10),
            )
            .await?;
        match outcome {
            // The first is written; the rest queue behind it, since a device that has not
            // answered is not sent a second transaction.
            ClientSendOutcome::Sent { .. } => sent += 1,
            ClientSendOutcome::Executed { detail } if detail.contains("queued") => sent += 1,
            ClientSendOutcome::Rejected { error } => {
                refused = Some(error);
                break;
            }
            other => return Err(format!("unexpected outcome {other:?}").into()),
        }
    }
    assert_eq!(
        sent, 32,
        "exactly MAX_QUEUED requests are accepted unanswered"
    );
    let refused = refused.ok_or("the request past the bound must be refused")?;
    assert!(refused.contains("already waiting"), "{refused}");
    silent.abort();
    Ok(())
}
