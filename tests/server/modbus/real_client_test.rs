//! Modbus/TCP server driven by the real **`mbpoll`** binary.
//!
//! The peer is not a Rust crate. `src/server/modbus/codec.rs` is a hand-rolled MBAP +
//! PDU codec; `mbpoll` is a C program built on libmodbus, which shares no code with
//! anything NetGet links against. A register value it decodes and prints is
//! independent evidence, not one codec agreeing with itself.
//!
//! What is driven is a real master/slave session, not a connect:
//!
//! ```text
//!   FC 3   read holding registers   -> values asserted on mbpoll's printed output
//!   FC 1   read coils               -> bit pattern asserted on mbpoll's printed output
//!   FC 2   read discrete inputs     -> ten bits across two bytes, asserted in order
//!   FC 6   write single register    -> acknowledged, mbpoll reports the write
//!   FC 16  write multiple registers -> acknowledged; the values reached the model intact
//!   FC 5   write single coil        -> acknowledged
//!   FC 15  write multiple coils     -> acknowledged; the bits reached the model intact
//!   FC 4   read input registers     -> exception 0x02, mbpoll reports the Modbus error
//! ```
//!
//! That is every function code the server implements, so the second client covers the same
//! surface as the first rather than a sample of it.
//!
//! This test is **not** `#[ignore]`d and does **not** skip when mbpoll is missing —
//! see `require_mbpoll`.

use crate::server::helpers::*;
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when `mbpoll` is absent.
///
/// A skip that returns `Ok(())` is a silent pass on any machine without libmodbus's
/// CLI, which is how a maturity rating outlives its evidence. Modbus's rating leans
/// on this session, so a runner without the binary has to say so.
async fn require_mbpoll() -> E2EResult<()> {
    // `mbpoll -h` prints usage and exits non-zero, so the check is that it ran and
    // identified itself, not that it exited 0.
    match Command::new("mbpoll").arg("-h").output().await {
        Ok(out) => {
            let banner = String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr);
            if banner.contains("mbpoll") {
                println!("[real-client] mbpoll present");
                Ok(())
            } else {
                Err(format!(
                    "`mbpoll -h` ran but did not identify itself. This test's whole point is \
                     driving the real mbpoll against NetGet's Modbus server; skipping would \
                     leave Modbus's maturity rating resting on nothing. Output was: {banner}"
                )
                .into())
            }
        }
        Err(e) => Err(format!(
            "mbpoll is not available ({e}). This test's whole point is driving the real mbpoll \
             client against NetGet's Modbus server, and skipping it would leave Modbus's \
             maturity rating resting on nothing."
        )
        .into()),
    }
}

/// One `mbpoll` invocation, bounded, returning `(stdout, stderr, success)`.
///
/// `-1` is mandatory in every call site: without it mbpoll polls forever, and each
/// poll is another event and another mock call.
async fn mbpoll(args: &[&str], what: &str) -> E2EResult<(String, String, bool)> {
    let out = tokio::time::timeout(
        Duration::from_secs(45),
        Command::new("mbpoll").args(args).output(),
    )
    .await
    .map_err(|_| format!("mbpoll {what} did not finish within 45s"))?
    .map_err(|e| format!("failed to run mbpoll {what}: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("[mbpoll {what}] status={}\n{stdout}", out.status);
    if !stderr.trim().is_empty() {
        println!("[mbpoll {what}] stderr: {stderr}");
    }
    Ok((stdout, stderr, out.status.success()))
}

#[tokio::test]
async fn test_modbus_reads_writes_and_exceptions_against_mbpoll() -> E2EResult<()> {
    require_mbpoll().await?;

    let config = NetGetConfig::new(
        "Start a Modbus server on port {AVAILABLE_PORT} pretending to be a water treatment PLC",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("Modbus server")
            .and_instruction_containing("on port")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "modbus",
                "instruction": "Water treatment PLC"
            }]))
            .expect_calls(1)
            .and()
            // Input-register read of an address this device does not have. Declared
            // before the holding-register rule so the narrower matcher wins.
            .on_event("modbus_read_registers")
            .and_event_data_contains("register_type", "input")
            .respond_with_actions(serde_json::json!([{
                "type": "send_modbus_exception",
                "exception_code": 2
            }]))
            .expect_calls(1)
            .and()
            // Holding-register read. Derived from the event: the count must equal the
            // quantity asked for or the server fails closed with exception 0x04, so
            // this also proves mbpoll's quantity reached the model intact.
            .on_event("modbus_read_registers")
            .and_event_data_contains("register_type", "holding")
            .respond_with_actions_from_event(|event| {
                let quantity = event["quantity"].as_u64().unwrap_or(1);
                let start = event["start_address"].as_u64().unwrap_or(0);
                let values: Vec<u64> = (0..quantity).map(|i| 1800 + start + i * 10).collect();
                serde_json::json!([{
                    "type": "send_modbus_registers",
                    "values": values
                }])
            })
            .expect_calls(1)
            .and()
            // Coil read (FC 1) and discrete-input read (FC 2). Same width contract, on the bit
            // path.
            .on_event("modbus_read_bits")
            .respond_with_actions_from_event(|event| {
                let quantity = event["quantity"].as_u64().unwrap_or(1);
                let values: Vec<bool> = (0..quantity).map(|i| i % 3 == 0).collect();
                serde_json::json!([{
                    "type": "send_modbus_bits",
                    "values": values
                }])
            })
            .expect_calls(2)
            .and()
            // Coil writes (FC 5 and FC 15), accepted only when the bits libmodbus packed are the
            // bits the model is shown — otherwise refused, and the test sees an exception.
            .on_event("modbus_write_request")
            .and_event_data_contains("function", "coil")
            .respond_with_actions_from_event(|event| {
                let values = event["coil_values"].clone();
                if values == serde_json::json!([true])
                    || values
                        == serde_json::json!([
                            true, false, true, true, false, true, false, false, true
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
            // FC 16, same contract on registers. Declared before the single-register rule.
            .on_event("modbus_write_request")
            .and_event_data_contains("function", "write_multiple_registers")
            .respond_with_actions_from_event(|event| {
                if event["register_values"] == serde_json::json!([1000, 2000, 65535]) {
                    serde_json::json!([{"type": "send_modbus_write_ack"}])
                } else {
                    serde_json::json!([{
                        "type": "send_modbus_exception",
                        "exception_code": "illegal_data_value"
                    }])
                }
            })
            .expect_calls(1)
            .and()
            // Accepted write.
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
    let port = server.port.to_string();
    println!("[real-client] NetGet Modbus server on 127.0.0.1:{port}");

    // -- FC 3, read holding registers --------------------------------------------------
    //
    // `-0` puts mbpoll into PDU addressing so `-r 0` is literally address 0 on the
    // wire, matching what the model is shown. libmodbus prints a value only after
    // accepting the MBAP header (transaction id echo, protocol id 0, a length that
    // covers the PDU) and the byte count in the PDU -- none of which a raw socket
    // assertion would check.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "4",
            "-r",
            "0",
            "-c",
            "3",
            "-p",
            &port,
            "127.0.0.1",
        ],
        "read holding",
    )
    .await?;
    assert!(
        ok,
        "mbpoll failed reading holding registers from NetGet. stderr: {stderr}"
    );
    for expected in ["1800", "1810", "1820"] {
        assert!(
            stdout.contains(expected),
            "libmodbus did not decode register value {expected} from NetGet's FC 3 reply.\n\
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    println!("[real-client] libmodbus decoded NetGet's three holding registers");

    // -- FC 1, read coils --------------------------------------------------------------
    //
    // The model answers [true, false, false, true], which libmodbus must unpack from
    // the bit-packed byte the server writes.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "0",
            "-r",
            "0",
            "-c",
            "4",
            "-p",
            &port,
            "127.0.0.1",
        ],
        "read coils",
    )
    .await?;
    assert!(
        ok,
        "mbpoll failed reading coils from NetGet. stderr: {stderr}"
    );
    let coil_values: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(|v| v.trim())
        .filter(|v| *v == "0" || *v == "1")
        .collect();
    assert_eq!(
        coil_values,
        vec!["1", "0", "0", "1"],
        "libmodbus unpacked a different coil pattern than the model supplied \
         ([true,false,false,true]), so the server's bit packing is wrong.\nstdout:\n{stdout}"
    );
    println!("[real-client] libmodbus unpacked NetGet's coil bits in the right order");

    // -- FC 2, read discrete inputs ----------------------------------------------------
    //
    // Ten bits span two response bytes, so this checks the packing across a byte boundary,
    // which four coils cannot.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "1",
            "-r",
            "0",
            "-c",
            "10",
            "-p",
            &port,
            "127.0.0.1",
        ],
        "read discrete inputs",
    )
    .await?;
    assert!(
        ok,
        "mbpoll failed reading discrete inputs from NetGet. stderr: {stderr}"
    );
    let input_values: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(|v| v.trim())
        .filter(|v| *v == "0" || *v == "1")
        .collect();
    assert_eq!(
        input_values,
        vec!["1", "0", "0", "1", "0", "0", "1", "0", "0", "1"],
        "libmodbus unpacked a different discrete-input pattern than the model supplied, so the \
         second response byte is packed wrong.\nstdout:\n{stdout}"
    );
    println!("[real-client] libmodbus unpacked ten discrete inputs across two bytes");

    // -- FC 6, write single register ---------------------------------------------------
    //
    // A write is the other direction: mbpoll checks that the server echoed the
    // address and value back verbatim, which is how Modbus acknowledges FC 6.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "4",
            "-r",
            "7",
            "-p",
            &port,
            "127.0.0.1",
            "4242",
        ],
        "write single register",
    )
    .await?;
    assert!(
        ok,
        "mbpoll failed writing a holding register to NetGet -- the FC 6 echo was not accepted. \
         stderr: {stderr}"
    );
    assert!(
        stdout.to_lowercase().contains("written"),
        "mbpoll did not report a completed write.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    println!("[real-client] libmodbus accepted NetGet's FC 6 write echo");

    // -- FC 16, write multiple registers -----------------------------------------------
    //
    // Three values make mbpoll use FC 16. The mock accepts only if [1000, 2000, 65535] reached
    // the model, and libmodbus checks the start+quantity echo.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "4",
            "-r",
            "20",
            "-p",
            &port,
            "127.0.0.1",
            "1000",
            "2000",
            "65535",
        ],
        "write multiple registers",
    )
    .await?;
    assert!(
        ok && stdout.to_lowercase().contains("written"),
        "mbpoll did not complete an FC 16 write against NetGet.\nstdout:\n{stdout}\nstderr:\n\
         {stderr}"
    );
    println!("[real-client] libmodbus accepted NetGet's FC 16 echo");

    // -- FC 5, write single coil ---------------------------------------------------------
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "0",
            "-r",
            "3",
            "-p",
            &port,
            "127.0.0.1",
            "1",
        ],
        "write single coil",
    )
    .await?;
    assert!(
        ok && stdout.to_lowercase().contains("written"),
        "mbpoll did not complete an FC 5 write against NetGet.\nstdout:\n{stdout}\nstderr:\n\
         {stderr}"
    );
    println!("[real-client] libmodbus accepted NetGet's FC 5 echo");

    // -- FC 15, write multiple coils -----------------------------------------------------
    //
    // Nine coils, so libmodbus packs two bytes. The mock accepts only the exact pattern.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "0",
            "-r",
            "0",
            "-p",
            &port,
            "127.0.0.1",
            "1",
            "0",
            "1",
            "1",
            "0",
            "1",
            "0",
            "0",
            "1",
        ],
        "write multiple coils",
    )
    .await?;
    assert!(
        ok && stdout.to_lowercase().contains("written"),
        "mbpoll did not complete an FC 15 write against NetGet — an exception here means the \
         nine coil bits libmodbus packed did not reach the model as sent.\nstdout:\n{stdout}\n\
         stderr:\n{stderr}"
    );
    println!("[real-client] libmodbus accepted NetGet's FC 15 echo");

    // -- FC 4, the exception path ------------------------------------------------------
    //
    // Structurally distinct from every success above: the server sets the high bit of
    // the function code and sends one exception byte. A client that reported this as
    // success would make the three assertions above meaningless.
    let (stdout, stderr, ok) = mbpoll(
        &[
            "-m",
            "tcp",
            "-1",
            "-0",
            "-a",
            "1",
            "-t",
            "3",
            "-r",
            "0",
            "-c",
            "2",
            "-p",
            &port,
            "127.0.0.1",
        ],
        "read input registers",
    )
    .await?;
    let combined = format!("{stdout}{stderr}").to_lowercase();
    assert!(
        !ok || combined.contains("illegal data address") || combined.contains("exception"),
        "mbpoll treated NetGet's Modbus exception 0x02 as a successful read.\nstdout:\n{stdout}\n\
         stderr:\n{stderr}"
    );
    assert!(
        combined.contains("illegal data address") || combined.contains("exception"),
        "libmodbus did not surface NetGet's exception 0x02 (illegal data address).\nstdout:\n\
         {stdout}\nstderr:\n{stderr}"
    );
    println!("[real-client] libmodbus reported NetGet's illegal-data-address exception");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
