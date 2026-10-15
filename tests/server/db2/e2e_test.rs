//! Integration test: a real TCP connection driving the Db2 DRDA handshake and a
//! basic statement against a running NetGet server, with the LLM mocked.
//!
//! The client side is built from spec-derived DRDA bytes (via the same codec the
//! `drda_test.rs` byte-literal tests validate independently). This exercises the
//! server's real frame parsing and reply path, but it is still **byte-literal
//! evidence**, not interoperability with a genuine Db2 driver — no such driver is
//! available on macOS to point at localhost.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::server::db2::drda;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Read exactly one DSS reply from the stream and parse it.
async fn read_dss(stream: &mut TcpStream) -> drda::ParsedDss {
    let mut header = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .expect("read DSS header timed out")
        .expect("read DSS header");
    let total = u16::from_be_bytes([header[0], header[1]]) as usize;
    assert!(total >= 6, "DSS length must be >= 6, got {total}");
    let mut rest = vec![0u8; total - 6];
    stream.read_exact(&mut rest).await.expect("read DSS body");
    let mut buf = header.to_vec();
    buf.extend_from_slice(&rest);
    let (parsed, consumed) = drda::parse_dss(&buf).expect("parse reply DSS");
    assert_eq!(consumed, buf.len());
    parsed
}

#[tokio::test]
async fn test_db2_handshake_and_statement() -> E2EResult<()> {
    println!("\n=== E2E Test: Db2 DRDA handshake + statement ===");

    let prompt = "Start an IBM Db2 server on port {AVAILABLE_PORT}. Accept the login and \
        answer statements successfully.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Db2 server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "db2",
                    "instruction": "Db2 server accepting logins and answering statements"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("db2_connect")
            .respond_with_actions(serde_json::json!([
                { "type": "db2_accept_connection" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("db2_query")
            .respond_with_actions(serde_json::json!([
                { "type": "db2_query_ok", "sqlcode": 0, "rows_affected": 1 }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Db2 server on port {}", server.port);

    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;

    // 1) EXCSAT → EXCSATRD (no LLM)
    let excsat = drda::encode_dss(
        drda::DSSFMT_RQSDSS,
        false,
        1,
        &drda::encode_object(
            drda::cp::EXCSAT,
            &drda::encode_scalar_str(drda::cp::EXTNAM, "test-client"),
        ),
    );
    stream.write_all(&excsat).await?;
    let rd = read_dss(&mut stream).await;
    assert_eq!(rd.codepoint, drda::cp::EXCSATRD, "expected EXCSATRD");
    assert_eq!(rd.correlator, 1);

    // 2) ACCSEC → ACCSECRD (no LLM), requesting USRIDPWD (SECMEC=3)
    let accsec = drda::encode_dss(
        drda::DSSFMT_RQSDSS,
        false,
        2,
        &drda::encode_object(
            drda::cp::ACCSEC,
            &drda::encode_scalar(drda::cp::SECMEC, &[0x00, 0x03]),
        ),
    );
    stream.write_all(&accsec).await?;
    let rd = read_dss(&mut stream).await;
    assert_eq!(rd.codepoint, drda::cp::ACCSECRD, "expected ACCSECRD");

    // 3) SECCHK → SECCHKRM (LLM accepts)
    let mut secchk_body = Vec::new();
    secchk_body.extend_from_slice(&drda::encode_scalar_str(drda::cp::USRID, "DB2INST1"));
    secchk_body.extend_from_slice(&drda::encode_scalar_str(drda::cp::PASSWORD, "secret"));
    secchk_body.extend_from_slice(&drda::encode_scalar_str(drda::cp::RDBNAM, "SAMPLE"));
    let secchk = drda::encode_dss(
        drda::DSSFMT_RQSDSS,
        false,
        3,
        &drda::encode_object(drda::cp::SECCHK, &secchk_body),
    );
    stream.write_all(&secchk).await?;
    let rd = read_dss(&mut stream).await;
    assert_eq!(rd.codepoint, drda::cp::SECCHKRM, "expected SECCHKRM");
    let svrcod = drda::find_param(&rd.body, drda::cp::SVRCOD).expect("SVRCOD");
    assert_eq!(
        u16::from_be_bytes([svrcod[0], svrcod[1]]),
        drda::svrcod::INFO,
        "accepted login must report severity INFO (0)"
    );
    let secchkcd = drda::find_param(&rd.body, drda::cp::SECCHKCD).expect("SECCHKCD");
    assert_eq!(secchkcd, vec![drda::secchkcd::SUCCESS]);

    // 4) ACCRDB → ACCRDBRM (auto, authenticated → severity INFO)
    let accrdb = drda::encode_dss(
        drda::DSSFMT_RQSDSS,
        false,
        4,
        &drda::encode_object(
            drda::cp::ACCRDB,
            &drda::encode_scalar_str(drda::cp::RDBNAM, "SAMPLE"),
        ),
    );
    stream.write_all(&accrdb).await?;
    let rd = read_dss(&mut stream).await;
    assert_eq!(rd.codepoint, drda::cp::ACCRDBRM, "expected ACCRDBRM");
    let svrcod = drda::find_param(&rd.body, drda::cp::SVRCOD).expect("SVRCOD");
    assert_eq!(
        u16::from_be_bytes([svrcod[0], svrcod[1]]),
        drda::svrcod::INFO
    );

    // 5) EXCSQLIMM with embedded SQLSTT → SQLCARD success (LLM db2_query_ok)
    let mut excsqlimm_body = Vec::new();
    excsqlimm_body.extend_from_slice(&drda::encode_scalar_str(drda::cp::RDBNAM, "SAMPLE"));
    excsqlimm_body.extend_from_slice(&drda::encode_scalar_str(
        drda::cp::SQLSTT,
        "INSERT INTO T VALUES (1)",
    ));
    let excsqlimm = drda::encode_dss(
        drda::DSSFMT_RQSDSS,
        false,
        5,
        &drda::encode_object(drda::cp::EXCSQLIMM, &excsqlimm_body),
    );
    stream.write_all(&excsqlimm).await?;
    let rd = read_dss(&mut stream).await;
    assert_eq!(rd.codepoint, drda::cp::SQLCARD, "expected SQLCARD reply");
    // The model answered with rows_affected 1, which travels in SQLERRD3 of a full SQLCA:
    // SQLCODE 0, SQLSTATE 00000, and the third SQLERRD of the SQLCAXGRP.
    assert_eq!(rd.body, drda::sqlcard(0, "00000", 1)[4..].to_vec());
    assert_eq!(&rd.body[1..5], &0i32.to_be_bytes(), "SQLCODE 0");
    assert_eq!(&rd.body[5..10], b"00000");
    assert_eq!(
        &rd.body[27..31],
        &1i32.to_be_bytes(),
        "SQLERRD3 = rows affected"
    );
    assert_eq!(drda::sqlcard_success(), vec![0x00, 0x05, 0x24, 0x08, 0xFF]);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    println!("✓ Db2 handshake + statement passed\n");
    Ok(())
}
