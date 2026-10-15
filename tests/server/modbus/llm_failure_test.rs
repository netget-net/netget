//! `src/server/modbus/CLAUDE.md`'s failure section, read as a list of assertions.
//!
//! The DNS pass found that a failure section is usually where a doc promises something the code
//! does not do — there, "answered SERVFAIL when the model returned nothing usable" described the
//! one case that wrote nothing at all. So each clause of Modbus's "Fail closed" list is driven
//! here, from the wire, and checked twice: the PDU the client receives, and the `decision=` token
//! the log carries — because on this protocol the wire *cannot* tell a model's deliberate 0x04
//! from a fail-closed one, and the log is the only place the difference lives.
//!
//! | clause | driven by | wire | log |
//! |---|---|---|---|
//! | the LLM call itself failed | a write, which no mock rule answers (the mock returns 500) | `0x86 0x04` | `fail_closed_llm_error` |
//! | no usable action came back | the model answers `[]` | `0x83 0x04` | `fail_closed_no_action` |
//! | wrong *kind*, from the model (bits for a register read) | `send_modbus_bits` to FC 3 | `0x83 0x04` | `fail_closed_llm_error` — see below |
//! | wrong *kind*, from the model (a write ack for a read) | `send_modbus_write_ack` to FC 1 | `0x81 0x04` | `fail_closed_llm_error` |
//! | wrong *kind*, from a static rule | `send_modbus_registers` to FC 1 | `0x81 0x04` | `fail_closed_wrong_shape` (second test) |
//! | wrong *number* of values | one register for a two-register read | `0x83 0x04` | `fail_closed_wrong_shape` |
//! | a register value outside 0-65535 | `65536`, refused by `execute_action` | `0x83 0x04` | `fail_closed_no_action` |
//! | the model's own 0x04 | `send_modbus_exception 4` | `0x83 0x04` | `model_reject` |
//!
//! **The wrong-kind rows are the finding.** The server's own doc said a model answering the
//! wrong kind is logged `fail_closed_wrong_shape`. It is not, because such an answer never
//! reaches the server: each event offers the model only its own actions, so `send_modbus_bits`
//! on a register read is an *unknown action* to the LLM layer, which re-asks once
//! (`MAX_UNKNOWN_ACTION_RETRIES` in `src/llm/conversation.rs` — hence the extra mock call on
//! each of those rules) and then fails the call. The wire is right either way; the log reads
//! `fail_closed_llm_error`, preceded by `LLM failed to use valid actions`. The server's
//! wrong-kind check is reached only by a handler that bypasses that vocabulary — a static or
//! script rule — which the second test drives.
//!
//! And a control: the same rule answering a correct request correctly, so a rule that never
//! matched cannot make every row above pass by failing closed for a different reason.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn adu(transaction_id: u16, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&((pdu.len() as u16) + 1).to_be_bytes());
    out.push(1);
    out.extend_from_slice(pdu);
    out
}

/// Send one request and return the response PDU, asserting the transaction id came back.
async fn exchange(stream: &mut TcpStream, transaction_id: u16, pdu: &[u8]) -> Vec<u8> {
    stream
        .write_all(&adu(transaction_id, pdu))
        .await
        .expect("write request");
    let mut header = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut header))
        .await
        .expect(
            "no Modbus response — a fail-closed path that writes nothing leaves the master \
                 blocked until its own timeout",
        )
        .expect("read header");
    assert_eq!(
        u16::from_be_bytes([header[0], header[1]]),
        transaction_id,
        "the response must answer this request"
    );
    let length = u16::from_be_bytes([header[4], header[5]]) as usize;
    let mut body = vec![0u8; length - 1];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("timed out reading the PDU")
        .expect("read PDU");
    body
}

fn read_holding(start: u16, quantity: u16) -> Vec<u8> {
    let mut pdu = vec![0x03];
    pdu.extend_from_slice(&start.to_be_bytes());
    pdu.extend_from_slice(&quantity.to_be_bytes());
    pdu
}

#[tokio::test]
async fn every_fail_closed_clause_answers_0x04_and_logs_which_one_it_was() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a Modbus server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Modbus server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "modbus",
                    "instruction": "A PLC that answers badly on purpose"
                }]))
                .expect_calls(1)
                .and()
                // ONE rule for every register read, branching on the address: two rules on the
                // same event cannot be told apart.
                .on_event("modbus_read_registers")
                .respond_with_actions_from_event(|event| {
                    match event["start_address"].as_u64().unwrap_or(0) {
                        // Wrong number: one value for a two-register read.
                        10 => serde_json::json!([{"type": "send_modbus_registers", "values": [7]}]),
                        // Wrong kind: bits for a register read.
                        20 => serde_json::json!([{
                            "type": "send_modbus_bits", "values": [true, false]
                        }]),
                        // Nothing at all.
                        30 => serde_json::json!([]),
                        // Out of range: 65536 does not fit a register and must not be narrowed.
                        40 => serde_json::json!([{
                            "type": "send_modbus_registers", "values": [65536, 1]
                        }]),
                        // The model's own device-failure exception.
                        50 => serde_json::json!([{
                            "type": "send_modbus_exception", "exception_code": 4
                        }]),
                        // Control: a correct answer derived from the request.
                        _ => {
                            let q = event["quantity"].as_u64().unwrap_or(1);
                            let values: Vec<u64> = (0..q).map(|i| 100 + i).collect();
                            serde_json::json!([{"type": "send_modbus_registers", "values": values}])
                        }
                    }
                })
                // Six requests plus one re-ask for the out-of-vocabulary answer at 20.
                .expect_calls(7)
                .and()
                // Wrong kind the other way: a write acknowledgement for a coil read. Asked
                // twice, because the first answer is outside the event's vocabulary.
                .on_event("modbus_read_bits")
                .respond_with_actions(serde_json::json!([{"type": "send_modbus_write_ack"}]))
                .expect_calls(2)
                .and()
            // Deliberately NO rule for modbus_write_request: the mock answers HTTP 500, which is
            // the shape of a real backend outage and drives the server down its LLM-error path.
        });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("Modbus accept loop started", 15)
        .await?;
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;

    // Control first: if this fails, nothing below means anything.
    assert_eq!(
        exchange(&mut stream, 1, &read_holding(0, 2)).await,
        vec![0x03, 0x04, 0x00, 100, 0x00, 101],
        "control: the rule answers a correct read correctly"
    );

    for (txid, start, what) in [
        (10u16, 10u16, "one value for a two-register read"),
        (20, 20, "bits for a register read"),
        (30, 30, "an empty answer"),
        (40, 40, "a register value of 65536"),
        (50, 50, "the model's own exception 0x04"),
    ] {
        assert_eq!(
            exchange(&mut stream, txid, &read_holding(start, 2)).await,
            vec![0x83, 0x04],
            "{what} must reach the client as exception 0x04 (server device failure), never as \
             data"
        );
    }

    assert_eq!(
        exchange(&mut stream, 60, &[0x01, 0x00, 0x00, 0x00, 0x04]).await,
        vec![0x81, 0x04],
        "a write acknowledgement answering a coil read must fail closed"
    );

    // Write Single Register: no rule, so the LLM call fails.
    assert_eq!(
        exchange(&mut stream, 70, &[0x06, 0x00, 0x07, 0x10, 0x92]).await,
        vec![0x86, 0x04],
        "a failed LLM call must answer exception 0x04, not silence and not an echo"
    );

    // The wire cannot tell these apart; the log must.
    for token in [
        "decision=fail_closed_wrong_shape",
        "decision=fail_closed_no_action",
        "decision=fail_closed_llm_error",
        "decision=model_reject",
        "decision=model_answer",
    ] {
        server.wait_for_log(token, 30).await.map_err(|e| {
            format!("{token} was never logged, so an operator cannot tell this outcome from the others: {e}")
        })?;
    }

    // Per request, not just somewhere in the log: each outcome must be attributed to the
    // request that produced it.
    // Wait for each exact line rather than snapshotting: a decision token an earlier request
    // already logged satisfies the per-token wait above, and a request's reply reaches the socket
    // before its own log line is written, so under load a snapshot taken here can miss the last one.
    for (at, decision) in [
        ("read_holding_registers unit=1 @0 x2", "model_answer"),
        (
            "read_holding_registers unit=1 @10 x2",
            "fail_closed_wrong_shape",
        ),
        (
            "read_holding_registers unit=1 @20 x2",
            "fail_closed_llm_error",
        ),
        (
            "read_holding_registers unit=1 @30 x2",
            "fail_closed_no_action",
        ),
        (
            "read_holding_registers unit=1 @40 x2",
            "fail_closed_no_action",
        ),
        ("read_holding_registers unit=1 @50 x2", "model_reject"),
        ("read_coils unit=1 @0 x4", "fail_closed_llm_error"),
        (
            "write_single_register unit=1 @7 x1",
            "fail_closed_llm_error",
        ),
    ] {
        let line = format!("{at} decision={decision}");
        server.wait_for_log(&line, 30).await.map_err(|e| {
            format!("expected the log line `{line}`: each outcome must be attributed to the request that produced it: {e}")
        })?;
    }
    let out = server.get_output().await.join("\n");
    // The out-of-range value specifically: refused by the executor, never narrowed to 0.
    assert!(
        out.contains("exceeds 65535"),
        "execute_action should have refused 65536 by name; the wire already showed it was not \
         narrowed into a reading"
    );
    // The wrong-kind answers were refused as outside the event's vocabulary.
    assert!(
        out.contains("LLM failed to use valid actions"),
        "the wrong-kind answers should have been refused by the LLM layer as unknown actions"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The wrong-kind check inside the server, reached the only way it can be: a static rule, which
/// is not held to the event's action vocabulary. `send_modbus_registers` answering a coil read
/// must become exception 0x04, never a frame that `codec.rs` would build from register values
/// under a coil function code.
#[tokio::test]
async fn a_static_rule_answering_the_wrong_kind_fails_closed() {
    use netget::cli::management::ServerForm;
    use netget::state::app_state::AppState;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "modbus".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "modbus_read_bits",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_modbus_registers", "values": [1, 2, 3, 4]}]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create modbus server");
    let mut port = 0;
    for _ in 0..200 {
        if let Some(addr) = state.get_server(server_id).await.and_then(|s| s.local_addr) {
            port = addr.port();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "Modbus server never bound a port");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    assert_eq!(
        exchange(&mut stream, 9, &[0x01, 0x00, 0x00, 0x00, 0x04]).await,
        vec![0x81, 0x04],
        "register values answering a coil read must fail closed as exception 0x04"
    );
}
