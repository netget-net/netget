//! Wireshark's `mbtcp` dissector over a whole Modbus/TCP session, both directions.
//!
//! `e2e_test.rs::read_adu` already hands every ADU it reads to the oracle — but the only ADUs
//! that path reads are **exceptions** (the spec-rejected requests in
//! `test_modbus_spec_exceptions_and_mbap_framing`), because the success paths are read by
//! `tokio-modbus`, which never shows the test the bytes. So until this file the oracle had never
//! seen a register block, a packed coil byte or a write echo — which is most of what
//! `codec.rs` writes by hand, and exactly where a byte count that disagreed with its data would
//! live.
//!
//! This test puts all eight implemented function codes and an exception on one connection and
//! hands the whole stream — requests and responses, in order — to the oracle, so `mbtcp`
//! matches each response to its request by transaction id the way a capture of a real session
//! would. It also asserts the decoded values itself, so a clean dissection of the wrong numbers
//! cannot pass.
//!
//! The server is model-free: static handlers answer every event, so the test costs no LLM call.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

fn adu(transaction_id: u16, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&((pdu.len() as u16) + 1).to_be_bytes());
    out.push(1);
    out.extend_from_slice(pdu);
    out
}

async fn read_raw_adu(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut header))
        .await
        .expect("timed out waiting for a Modbus response")
        .expect("read header");
    let length = u16::from_be_bytes([header[4], header[5]]) as usize;
    let mut raw = header.to_vec();
    let mut body = vec![0u8; length - 1];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut body))
        .await
        .expect("timed out reading the PDU")
        .expect("read PDU");
    raw.extend_from_slice(&body);
    raw
}

#[tokio::test]
async fn mbtcp_dissects_every_function_code_this_server_answers_in_both_directions() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;

    let static_rule = |pattern: &str, actions: serde_json::Value| {
        serde_json::json!({
            "event_pattern": pattern,
            "handler": { "type": "static", "actions": actions }
        })
    };
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "modbus".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            // Every read below asks for exactly three registers or ten bits, so a fixed answer
            // of that width is a correct one.
            static_rule(
                "modbus_read_registers",
                serde_json::json!([{"type": "send_modbus_registers", "values": [1800, 1810, 65535]}]),
            ),
            static_rule(
                "modbus_read_bits",
                serde_json::json!([{
                    "type": "send_modbus_bits",
                    "values": [true, false, true, true, false, false, true, true, true, false]
                }]),
            ),
            static_rule(
                "modbus_write_request",
                serde_json::json!([{"type": "send_modbus_write_ack"}]),
            ),
        ]),
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

    // (request PDU, expected response PDU), each from MODBUS Application Protocol V1.1b3.
    let exchanges: Vec<(Vec<u8>, Vec<u8>)> = vec![
        // FC 1, ten coils: 0b1100_1101, 0b0000_0001.
        (
            vec![0x01, 0x00, 0x13, 0x00, 0x0A],
            vec![0x01, 0x02, 0xCD, 0x01],
        ),
        // FC 2, same shape.
        (
            vec![0x02, 0x00, 0xC4, 0x00, 0x0A],
            vec![0x02, 0x02, 0xCD, 0x01],
        ),
        // FC 3, three registers, big-endian.
        (
            vec![0x03, 0x00, 0x6B, 0x00, 0x03],
            vec![0x03, 0x06, 0x07, 0x08, 0x07, 0x12, 0xFF, 0xFF],
        ),
        // FC 4, same shape.
        (
            vec![0x04, 0x00, 0x08, 0x00, 0x03],
            vec![0x04, 0x06, 0x07, 0x08, 0x07, 0x12, 0xFF, 0xFF],
        ),
        // FC 5, ON is 0xFF00, echoed.
        (
            vec![0x05, 0x00, 0xAC, 0xFF, 0x00],
            vec![0x05, 0x00, 0xAC, 0xFF, 0x00],
        ),
        // FC 6, echoed.
        (
            vec![0x06, 0x00, 0x01, 0x00, 0x03],
            vec![0x06, 0x00, 0x01, 0x00, 0x03],
        ),
        // FC 15, ten coils from 0x13; the echo is start + quantity.
        (
            vec![0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01],
            vec![0x0F, 0x00, 0x13, 0x00, 0x0A],
        ),
        // FC 16, two registers from 1; the echo is start + quantity.
        (
            vec![0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02],
            vec![0x10, 0x00, 0x01, 0x00, 0x02],
        ),
        // An exception: FC 3 with quantity 0 is illegal data value.
        (vec![0x03, 0x00, 0x00, 0x00, 0x00], vec![0x83, 0x03]),
    ];

    let mut oracle = crate::helpers::pcap_oracle::PcapOracle::tcp("modbus");
    for (i, (request, expected)) in exchanges.iter().enumerate() {
        let txid = 0x0100 + i as u16;
        let wire_request = adu(txid, request);
        stream.write_all(&wire_request).await.expect("write");
        let response = read_raw_adu(&mut stream).await;
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            txid,
            "exchange {i}: transaction id must be echoed"
        );
        assert_eq!(
            &response[7..],
            expected.as_slice(),
            "exchange {i} (FC {:#04x}): wrong response PDU",
            request[0]
        );
        oracle = oracle.to_server(&wire_request).from_server(&response);
    }
    oracle.assert_clean();
}
