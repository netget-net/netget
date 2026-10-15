//! E2E tests for the Modbus TCP server.
//!
//! The peer is **`tokio-modbus` 0.17**, a separate implementation from
//! `src/server/modbus/codec.rs`, which is hand-rolled. Every assertion below is on a
//! decoded PDU — register values, coil bits, function codes, exception codes, MBAP
//! fields — never on "some bytes arrived".
//!
//! See `tests/server/modbus/CLAUDE.md` for the LLM call budget.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::modbus::codec;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_modbus::prelude::*;

/// Read exactly `n` bytes or fail the test.
async fn read_exact_timeout(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .expect("timed out waiting for a Modbus response")
        .expect("failed to read a Modbus response");
    buf
}

/// Pull one complete ADU off the socket and return `(transaction_id, unit_id, pdu)`.
async fn read_adu(stream: &mut TcpStream) -> (u16, u8, Vec<u8>) {
    let header = read_exact_timeout(stream, 7).await;
    let transaction_id = u16::from_be_bytes([header[0], header[1]]);
    let protocol_id = u16::from_be_bytes([header[2], header[3]]);
    let length = u16::from_be_bytes([header[4], header[5]]);
    let unit_id = header[6];

    assert_eq!(
        protocol_id, 0,
        "MBAP protocol identifier must be 0 for Modbus"
    );
    assert!(
        length >= 2,
        "MBAP length must cover at least the unit id and a function code, got {length}"
    );

    let pdu = read_exact_timeout(stream, length as usize - 1).await;

    // The pcap oracle. tokio-modbus reads the PDU this test asserts on; Wireshark's
    // `mbtcp` dissector reads the MBAP header around it, which is the part
    // `src/server/modbus/codec.rs` writes by hand: protocol id, a length that must
    // cover exactly the unit id plus the PDU, and the exception encoding. A length
    // field that disagreed with the bytes actually written would still satisfy the
    // assertions below, because `read_adu` believes the length field.
    //
    // The capture is deliberately server-side only: each call sees one complete ADU,
    // and `mbtcp` classifies request from response by the port, which the oracle
    // fabricates as 502 for exactly this reason.
    let mut raw = header.clone();
    raw.extend_from_slice(&pdu);
    crate::helpers::pcap_oracle::PcapOracle::tcp("modbus")
        .from_server(&raw)
        .assert_clean();

    (transaction_id, unit_id, pdu)
}

/// Build a Modbus/TCP ADU by hand, from the spec rather than from our own encoder.
fn adu(transaction_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // protocol id
    out.extend_from_slice(&((pdu.len() as u16) + 1).to_be_bytes());
    out.push(unit_id);
    out.extend_from_slice(pdu);
    out
}

// ===========================================================================
// The main test: an independent Modbus client drives the server
// ===========================================================================

#[tokio::test]
async fn test_modbus_reads_writes_and_exceptions_against_tokio_modbus() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a Modbus server on port {AVAILABLE_PORT} pretending to be a water treatment PLC",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // 1. Server startup
            .on_instruction_containing("Modbus server")
            .and_instruction_containing("on port")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "modbus",
                "instruction": "Water treatment PLC"
            }]))
            .expect_calls(1)
            .and()
            // 2. Input-register read of an address this device does not have. Declared
            //    before the holding-register rule so the narrower matcher wins.
            .on_event("modbus_read_registers")
            .and_event_data_contains("register_type", "input")
            // Matches only when the event says what a missing address is answered with.
            .and_event_data_contains("answer_with", "NetGet answers exception 2")
            .respond_with_actions(serde_json::json!([{
                "type": "send_modbus_exception",
                "exception_code": 2
            }]))
            .expect_calls(1)
            .and()
            // 3. Holding-register read: the model invents the telemetry, keyed by address.
            //    Answered from the event so the reply is tied to the request that provoked
            //    it rather than to a hardcoded constant, and with one register beyond the
            //    window, which the server must leave out of the frame.
            .on_event("modbus_read_registers")
            .and_event_data_contains("register_type", "holding")
            .respond_with_actions_from_event(|event| {
                let quantity = event["quantity"].as_u64().unwrap_or(1);
                let start = event["start_address"].as_u64().unwrap_or(0);
                // Tank level then pump speed, derived from the addresses asked for.
                let registers: serde_json::Map<String, serde_json::Value> = (0..=quantity)
                    .map(|i| {
                        (
                            (start + i).to_string(),
                            serde_json::json!(1800 + start + i * 10),
                        )
                    })
                    .collect();
                serde_json::json!([{
                    "type": "send_modbus_registers",
                    "registers": registers
                }])
            })
            .expect_calls(1)
            .and()
            // 4. Coil read (FC 1) and discrete-input read (FC 2).
            .on_event("modbus_read_bits")
            .respond_with_actions_from_event(|event| {
                let quantity = event["quantity"].as_u64().unwrap_or(1);
                let start = event["start_address"].as_u64().unwrap_or(0);
                // Pattern derived from the request width, not a fixed literal, keyed by
                // address from the request's own start.
                let bits: serde_json::Map<String, serde_json::Value> = (0..quantity)
                    .map(|i| ((start + i).to_string(), serde_json::json!(i % 3 == 0)))
                    .collect();
                serde_json::json!([{
                    "type": "send_modbus_bits",
                    "bits": bits
                }])
            })
            .expect_calls(2)
            .and()
            // 4b. Coil writes (FC 5 and FC 15). Accepted only if the coil values the client
            //     sent reached the model intact, so the unpacking of FC 15's bit field is
            //     checked through the event, not assumed.
            .on_event("modbus_write_request")
            .and_event_data_contains("function", "coil")
            .respond_with_actions_from_event(|event| {
                let values = event["coil_values"].clone();
                if values == serde_json::json!([true])
                    || values
                        == serde_json::json!([
                            true, false, true, true, false, false, true, true, true
                        ])
                {
                    serde_json::json!([{"type": "send_modbus_write_ack"}])
                } else {
                    serde_json::json!([{
                        "type": "send_modbus_exception",
                        "exception_code": "illegal_data_value"
                    }])
                }
            })
            .expect_calls(2)
            .and()
            // 5. Refused write - the explicit denial path, structurally distinct from
            //    an acknowledgement. Declared before the accepted-write rule.
            .on_event("modbus_write_request")
            .and_event_data_contains("function", "write_multiple_registers")
            .respond_with_actions(serde_json::json!([{
                "type": "send_modbus_exception",
                "exception_code": "illegal_data_value"
            }]))
            .expect_calls(1)
            .and()
            // 6. Accepted write.
            .on_event("modbus_write_request")
            .and_event_data_contains("function", "write_single_register")
            .respond_with_actions(serde_json::json!([{
                "type": "send_modbus_write_ack"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("Modbus accept loop started", 15)
        .await?;

    let addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let mut ctx = tokio_modbus::client::tcp::connect_slave(addr, Slave(1))
        .await
        .expect("tokio-modbus failed to connect");

    // --- FC 3: read holding registers -------------------------------------
    let registers = ctx
        .read_holding_registers(0, 2)
        .await
        .expect("transport error on read_holding_registers")
        .expect("server returned an exception for read_holding_registers");
    assert_eq!(
        registers,
        vec![1800u16, 1810u16],
        "holding registers decoded by tokio-modbus must be exactly what the model returned"
    );

    // --- FC 4: read input registers, refused ------------------------------
    let err = ctx
        .read_input_registers(300, 1)
        .await
        .expect("transport error on read_input_registers")
        .expect_err("server should have refused this address with an exception");
    assert_eq!(
        err,
        ExceptionCode::IllegalDataAddress,
        "refusal must decode as exception 0x02, not as data"
    );

    // --- FC 1: read coils --------------------------------------------------
    let coils = ctx
        .read_coils(0, 4)
        .await
        .expect("transport error on read_coils")
        .expect("server returned an exception for read_coils");
    assert_eq!(
        coils,
        vec![true, false, false, true],
        "coil bits must survive the LSB-first packing round trip"
    );

    // --- FC 2: read discrete inputs ----------------------------------------
    let inputs = ctx
        .read_discrete_inputs(100, 10)
        .await
        .expect("transport error on read_discrete_inputs")
        .expect("server returned an exception for read_discrete_inputs");
    assert_eq!(
        inputs,
        vec![true, false, false, true, false, false, true, false, false, true],
        "ten discrete inputs span two bytes; both must unpack LSB-first"
    );

    // --- FC 5: write single coil, accepted ---------------------------------
    ctx.write_single_coil(3, true)
        .await
        .expect("transport error on write_single_coil")
        .expect("server should have accepted this coil write (tokio-modbus checks the echo)");

    // --- FC 15: write multiple coils, accepted -----------------------------
    ctx.write_multiple_coils(
        0x13,
        &[true, false, true, true, false, false, true, true, true],
    )
    .await
    .expect("transport error on write_multiple_coils")
    .expect(
        "server should have accepted this write; an exception here means the nine coil values \
         did not reach the model as sent",
    );

    // --- FC 6: write single register, accepted ----------------------------
    ctx.write_single_register(7, 4242)
        .await
        .expect("transport error on write_single_register")
        .expect("server should have accepted this write");

    // --- FC 16: write multiple registers, refused -------------------------
    let err = ctx
        .write_multiple_registers(20, &[1, 2])
        .await
        .expect("transport error on write_multiple_registers")
        .expect_err("server should have refused this write with an exception");
    assert_eq!(
        err,
        ExceptionCode::IllegalDataValue,
        "the model's named exception must reach the client as exception 0x03"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ===========================================================================
// A keyed answer that does not cover the request is exception 2
// ===========================================================================

/// The model answers a read with the addresses the device has; a requested address it did not
/// give is one the device does not have. This is the answer llama3.1:8b gives to "ten holding
/// registers at addresses 0 to 9 ... nothing at any other address" when asked for 500-501 -
/// the whole register map - and the wire must carry exception 2 for it, not data and not a
/// device failure. Partial coverage (8-11 against 0-9) and an empty map are the same answer.
#[tokio::test]
async fn test_modbus_keyed_answer_missing_an_address_is_illegal_data_address() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Start a Modbus server on port {AVAILABLE_PORT} with ten zero registers")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("Modbus server")
                    .and_instruction_containing("on port")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "modbus",
                        "instruction": "Ten holding registers at 0 to 9, all zero"
                    }]))
                    .expect_calls(1)
                    .and()
                    // Every read gets the device's whole map, 0-9, whatever it asked for - except
                    // a discrete-input read, which gets an empty map.
                    .on_event("modbus_read_registers")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_modbus_registers",
                        "registers": {"0": 0, "1": 0, "2": 0, "3": 0, "4": 0,
                                      "5": 0, "6": 0, "7": 0, "8": 0, "9": 0}
                    }]))
                    .expect_calls(3)
                    .and()
                    .on_event("modbus_read_bits")
                    .respond_with_actions(
                        serde_json::json!([{"type": "send_modbus_bits", "bits": {}}]),
                    )
                    .expect_calls(1)
                    .and()
            });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("Modbus accept loop started", 15)
        .await?;
    let addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let mut ctx = tokio_modbus::client::tcp::connect_slave(addr, Slave(1))
        .await
        .expect("tokio-modbus failed to connect");

    for (start, count) in [(500u16, 2u16), (8, 4)] {
        let err = ctx
            .read_holding_registers(start, count)
            .await
            .expect("transport error on read_holding_registers")
            .expect_err("addresses the map does not give must be refused");
        assert_eq!(
            err,
            ExceptionCode::IllegalDataAddress,
            "a read of {start}+{count} against a map of 0-9 must be exception 0x02"
        );
    }
    // The same map serves a read inside it.
    let registers = ctx
        .read_holding_registers(7, 3)
        .await
        .expect("transport error on read_holding_registers")
        .expect("7-9 are in the map");
    assert_eq!(registers, vec![0u16, 0, 0]);

    let err = ctx
        .read_discrete_inputs(0, 1)
        .await
        .expect("transport error on read_discrete_inputs")
        .expect_err("an empty map has no address 0");
    assert_eq!(err, ExceptionCode::IllegalDataAddress);

    server
        .wait_for_log("decision=model_address_absent", 10)
        .await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ===========================================================================
// Spec-determined behaviour, answered without any model round-trip
// ===========================================================================

#[tokio::test]
async fn test_modbus_spec_exceptions_and_mbap_framing() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a Modbus server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Modbus server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "modbus",
                    "instruction": "Bare PLC"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("Modbus accept loop started", 15)
        .await?;

    let addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let mut stream = TcpStream::connect(addr).await?;

    // Two requests in ONE TCP write. Both are rejected by the specification, so neither
    // reaches the model - and getting two separate, correctly framed answers back proves
    // the ADU framing loop, not just that a byte or two arrived.
    let mut batch = Vec::new();
    // FC 0x08 (Diagnostics) - not implemented here, so exception 0x01.
    batch.extend_from_slice(&adu(0xBEEF, 0x11, &[0x08, 0x00, 0x00, 0x00, 0x00]));
    // FC 0x03 with a quantity of 0 - illegal per the spec, so exception 0x03.
    batch.extend_from_slice(&adu(0x0102, 0x22, &[0x03, 0x00, 0x00, 0x00, 0x00]));
    stream.write_all(&batch).await?;
    stream.flush().await?;

    let (txid, unit, pdu) = read_adu(&mut stream).await;
    assert_eq!(txid, 0xBEEF, "MBAP transaction id must be echoed verbatim");
    assert_eq!(unit, 0x11, "MBAP unit id must be echoed verbatim");
    assert_eq!(
        pdu,
        vec![0x88, 0x01],
        "an unimplemented function code must produce fc|0x80 and exception 0x01"
    );

    let (txid, unit, pdu) = read_adu(&mut stream).await;
    assert_eq!(
        txid, 0x0102,
        "second response must carry its own transaction id"
    );
    assert_eq!(unit, 0x22);
    assert_eq!(
        pdu,
        vec![0x83, 0x03],
        "a quantity of 0 must produce exception 0x03 (illegal data value)"
    );

    // A read of 2001 coils exceeds the 2000 the spec allows.
    stream
        .write_all(&adu(0x0003, 0x01, &[0x01, 0x00, 0x00, 0x07, 0xD1]))
        .await?;
    let (txid, _, pdu) = read_adu(&mut stream).await;
    assert_eq!(txid, 0x0003);
    assert_eq!(
        pdu,
        vec![0x81, 0x03],
        "a coil quantity above 2000 must produce exception 0x03"
    );

    // One ADU split across two TCP writes, cut inside the MBAP header. The first write leaves
    // the connection Accumulating; only the second completes a frame. A server that framed each
    // read on its own would see a 4-octet fragment and either wait forever or call it garbage.
    let split = adu(0x0707, 0x01, &[0x08, 0x00, 0x00, 0x00, 0x00]);
    stream.write_all(&split[..4]).await?;
    stream.flush().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    stream.write_all(&split[4..]).await?;
    let (txid, _, pdu) = read_adu(&mut stream).await;
    assert_eq!(
        txid, 0x0707,
        "the reassembled frame is answered with its own id"
    );
    assert_eq!(
        pdu,
        vec![0x88, 0x01],
        "a frame split across segments must be reassembled"
    );

    drop(stream);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ===========================================================================
// Codec assertions against literal, spec-derived bytes
// ===========================================================================

#[test]
fn test_codec_parses_spec_example_frames() {
    // Read Holding Registers, 2 registers from address 0x006B (spec section 6.3 example).
    let frame = adu(0x0001, 0x11, &[0x03, 0x00, 0x6B, 0x00, 0x02]);
    let (parsed, consumed) = codec::try_parse_adu(&frame)
        .expect("well-formed frame")
        .expect("complete frame");
    assert_eq!(consumed, frame.len());
    assert_eq!(parsed.transaction_id, 0x0001);
    assert_eq!(parsed.unit_id, 0x11);

    let request = codec::parse_request(&parsed.pdu).expect("legal request");
    assert_eq!(
        request,
        codec::ModbusRequest::ReadHoldingRegisters {
            start: 0x006B,
            quantity: 2
        }
    );

    // A frame that is one byte short must be reported as incomplete, not as an error:
    // the caller has to accumulate rather than close the connection.
    assert_eq!(
        codec::try_parse_adu(&frame[..frame.len() - 1]).expect("no framing error"),
        None
    );

    // A non-zero protocol identifier is not Modbus at all.
    let mut bogus = frame.clone();
    bogus[2] = 0x00;
    bogus[3] = 0x07;
    assert_eq!(
        codec::try_parse_adu(&bogus),
        Err(codec::FrameError::NotModbus { protocol_id: 7 })
    );
}

#[test]
fn test_codec_encodes_bit_and_register_responses() {
    // Read Coils response for 9 coils: byte count 2, first coil in the LSB of byte 0.
    let values = [
        true, false, true, true, false, false, true, true, // byte 0 = 0b1100_1101
        true, // byte 1 = 0b0000_0001
    ];
    assert_eq!(
        codec::encode_bits_response(codec::FC_READ_COILS, &values).unwrap(),
        vec![0x01, 0x02, 0xCD, 0x01]
    );

    // Read Holding Registers response: byte count then big-endian registers.
    assert_eq!(
        codec::encode_registers_response(codec::FC_READ_HOLDING_REGISTERS, &[0x022B, 0x0000])
            .unwrap(),
        vec![0x03, 0x04, 0x02, 0x2B, 0x00, 0x00]
    );

    // Write Single Coil is confirmed by echoing the request, with ON encoded as 0xFF00.
    assert_eq!(
        codec::encode_write_ack(&codec::ModbusRequest::WriteSingleCoil {
            address: 0x00AC,
            value: true
        }),
        vec![0x05, 0x00, 0xAC, 0xFF, 0x00]
    );

    // Write Multiple Registers is confirmed with the address and the count, not the data.
    assert_eq!(
        codec::encode_write_ack(&codec::ModbusRequest::WriteMultipleRegisters {
            start: 0x0001,
            values: vec![0x000A, 0x0102]
        }),
        vec![0x10, 0x00, 0x01, 0x00, 0x02]
    );

    assert_eq!(
        codec::encode_exception(
            codec::FC_READ_HOLDING_REGISTERS,
            codec::EXC_ILLEGAL_DATA_ADDRESS
        ),
        vec![0x83, 0x02]
    );
}

#[test]
fn test_codec_rejects_malformed_requests() {
    // Byte count that disagrees with the quantity is an illegal data value.
    let pdu = [0x10, 0x00, 0x01, 0x00, 0x02, 0x03, 0x00, 0x0A, 0x01];
    assert_eq!(
        codec::parse_request(&pdu),
        Err(codec::EXC_ILLEGAL_DATA_VALUE)
    );

    // Write Single Coil accepts only 0x0000 and 0xFF00.
    assert_eq!(
        codec::parse_request(&[0x05, 0x00, 0xAC, 0x12, 0x34]),
        Err(codec::EXC_ILLEGAL_DATA_VALUE)
    );

    // A range that runs off the end of the address space is an address error.
    assert_eq!(
        codec::parse_request(&[0x03, 0xFF, 0xFF, 0x00, 0x02]),
        Err(codec::EXC_ILLEGAL_DATA_ADDRESS)
    );

    // An unknown function code is always exception 0x01.
    assert_eq!(
        codec::parse_request(&[0x2B, 0x0E, 0x01, 0x00]),
        Err(codec::EXC_ILLEGAL_FUNCTION)
    );

    // Write Multiple Coils packs bits LSB-first, same as the read response.
    assert_eq!(
        codec::parse_request(&[0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01]),
        Ok(codec::ModbusRequest::WriteMultipleCoils {
            start: 0x0013,
            values: vec![true, false, true, true, false, false, true, true, true, false]
        })
    );
}

// ===========================================================================
// The model's values are refused, never narrowed
// ===========================================================================

/// A register value or an exception code the model puts out of range must be **refused**,
/// not cast into range.
///
/// This is the defect class the quality programme keeps finding, and Modbus is the
/// protocol where it does physical damage: `65736 as u16` is `200`, so a narrowing cast
/// would report a tank level of 200 cm to a client that would believe it, with no error
/// anywhere. Every out-of-range value below is one a bare `as u16` / `as u8` would have
/// silently accepted.
#[test]
fn test_out_of_range_model_values_are_refused_not_narrowed() {
    use netget::llm::actions::protocol_trait::Server;
    use netget::server::modbus::actions::ModbusProtocol;

    let protocol = ModbusProtocol::new();

    // 65536 is the first value that wraps: `65536 as u16` is 0.
    let err = protocol
        .execute_action(serde_json::json!({
            "type": "send_modbus_registers",
            "values": [1834, 65536]
        }))
        .expect_err("65536 does not fit a 16-bit register and must be refused");
    assert!(
        err.to_string().contains("65535"),
        "the refusal should tell the model the real range, got: {err}"
    );

    // 65736 is the case worth naming: it wraps to 200, a plausible-looking reading.
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_modbus_registers",
            "values": [65736]
        }))
        .is_err());

    // A negative value is not a register either, and `as u16` on the way through
    // `as_u64()` would have dropped it silently.
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_modbus_registers",
            "values": [-1]
        }))
        .is_err());

    // The whole legal range is still accepted, so this is a bound and not a blanket
    // refusal.
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_modbus_registers",
            "values": [0, 65535]
        }))
        .is_ok());

    // Exception codes are checked against the codes the specification defines, not
    // against `u8`. 0x104 would have become 0x04 (server device failure) - a fail-closed
    // answer manufactured out of a typo.
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_modbus_exception",
            "exception_code": 260
        }))
        .is_err());

    // 7 and 9 are gaps in the spec's own table, so no client can interpret them.
    for undefined in [0u64, 7, 9, 12, 255] {
        assert!(
            protocol
                .execute_action(serde_json::json!({
                    "type": "send_modbus_exception",
                    "exception_code": undefined
                }))
                .is_err(),
            "exception code {undefined} is not defined by the specification and must be \
             refused"
        );
    }

    // Every code the specification does define is still accepted, by number and by name.
    for defined in [1u64, 2, 3, 4, 5, 6, 8, 10, 11] {
        assert!(
            protocol
                .execute_action(serde_json::json!({
                    "type": "send_modbus_exception",
                    "exception_code": defined
                }))
                .is_ok(),
            "exception code {defined} is defined by the specification and must be accepted"
        );
    }
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_modbus_exception",
            "exception_code": "illegal_data_address"
        }))
        .is_ok());
}
