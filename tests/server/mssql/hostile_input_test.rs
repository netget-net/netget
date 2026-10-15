//! What an MSSQL server does with TDS packets a real driver would never send.
//!
//! Both cases below were live defects, and neither is reachable through `tiberius` — which is
//! why the rest of this suite, driven entirely by `tiberius`, missed them.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TDS packet types.
const TDS_SQL_BATCH: u8 = 0x01;
const TDS_RPC: u8 = 0x03;
const TDS_PRELOGIN: u8 = 0x12;

/// The TDS ERROR token.
const TOKEN_ERROR: u8 = 0xAA;

/// Frame one TDS message as a single EOM packet.
fn tds_packet(packet_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(packet_type);
    out.push(0x01); // status: EOM
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // SPID
    out.push(0x01); // packet id
    out.push(0x00); // window
    out.extend_from_slice(payload);
    out
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// A NetGet MSSQL server whose handler would happily answer any query it is asked about.
///
/// Both tests below assert that it is *not* asked, so the `mssql_query` rule is deliberately
/// permissive: if the server ever reached it, the client would get a result set rather than the
/// error each test demands, and the test would fail on the token it read rather than on a
/// mock expectation.
fn permissive_server_config(prompt: &'static str) -> NetGetConfig {
    NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MSSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MSSQL",
                    "instruction": "Answer every query"
                }
            ]))
            .and()
            .on_event("mssql_query")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_ok_response",
                    "rows_affected": 1
                }
            ]))
            .expect_calls(0)
            .and()
    })
}

/// Read whatever the server sends next, with a deadline. Returns the payload of the first TDS
/// packet, or `None` if the peer closed without sending one.
async fn read_tds_message(stream: &mut TcpStream) -> E2EResult<Option<Vec<u8>>> {
    let mut header = [0u8; 8];
    match tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut header)).await {
        Err(_) => Err("MSSQL sent nothing within 20s".into()),
        Ok(Err(_)) => Ok(None), // clean EOF or reset before any reply
        Ok(Ok(_)) => {
            let total = u16::from_be_bytes([header[2], header[3]]) as usize;
            assert!(
                total >= 8,
                "MSSQL declared a TDS packet length of {total}, which is shorter than its own \
                 header"
            );
            let mut payload = vec![0u8; total - 8];
            tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut payload))
                .await
                .map_err(|_| "MSSQL declared a packet length it never finished sending")??;

            // The pcap oracle. This function already checks the one field it needs —
            // that the declared length covers its own header — and the tests then
            // scan the payload for token bytes. Wireshark's `tds` dissector reads the
            // whole 8-byte TDS header (type, status, length, SPID, packet id, window)
            // and then the token stream inside it, so a token whose own length field
            // disagrees with the bytes that follow is caught here and nowhere else in
            // this suite.
            let mut whole = header.to_vec();
            whole.extend_from_slice(&payload);
            crate::helpers::pcap_oracle::PcapOracle::tcp("mssql")
                .from_server(&whole)
                .assert_clean();

            Ok(Some(payload))
        }
    }
}

/// A SQL Batch sent before any LOGIN7 must be refused, not answered.
///
/// The dispatch loop used to treat packet types as independent of one another, so a peer that
/// never logged in still had its statements executed and `mssql_login` never fired — the
/// admission decision the model is asked to make was skippable by not asking for it.
/// `expect_calls(0)` on `mssql_query` is what actually asserts that here: the mock records
/// every call, so an answered query fails the test even if the client also reads an error.
#[tokio::test]
async fn test_mssql_refuses_a_batch_sent_before_any_login() -> E2EResult<()> {
    let server = start_netget_server(permissive_server_config(
        "Open MSSQL on port {AVAILABLE_PORT}. Answer every query.",
    ))
    .await?;

    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream.set_nodelay(true)?;

    // Straight to a statement: no pre-login, no LOGIN7.
    let mut batch = vec![0u8; 22]; // ALL_HEADERS, contents irrelevant to the parser
    batch.extend_from_slice(&utf16le("SELECT 1"));
    stream.write_all(&tds_packet(TDS_SQL_BATCH, &batch)).await?;

    let payload = read_tds_message(&mut stream)
        .await?
        .ok_or("MSSQL closed the connection without answering an unauthenticated batch")?;
    assert_eq!(
        payload.first(),
        Some(&TOKEN_ERROR),
        "an unauthenticated batch must be answered with a TDS ERROR token, got token 0x{:02x}",
        payload.first().copied().unwrap_or(0)
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// An RPC packet whose UTF-16 payload contains a character whose *Unicode* upper-casing is a
/// different byte length must not kill the connection task.
///
/// `parse_rpc_request` located the SQL keyword in an upper-cased copy of the text and then
/// sliced the original at that offset. U+FB01 `ﬁ` upper-cases to the two ASCII bytes `FI`, so
/// the offset was one byte short and landed inside the character — a panic, from the wire,
/// which also skipped the connection teardown and left the connection `Active` forever.
///
/// The packet is sent unauthenticated on purpose: the parse happens during dispatch, so the
/// panic (if it were still there) fires before the login gate can matter, and the assertion
/// stays about the parser rather than about who is allowed to query.
#[tokio::test]
async fn test_mssql_survives_an_rpc_whose_case_folding_changes_byte_length() -> E2EResult<()> {
    let server = start_netget_server(permissive_server_config(
        "Open MSSQL on port {AVAILABLE_PORT}. Answer every query.",
    ))
    .await?;

    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream.set_nodelay(true)?;

    // A pre-login first, so the assertion below distinguishes "the server is alive and
    // speaking TDS" from "the server never came up".
    stream.write_all(&tds_packet(TDS_PRELOGIN, &[0xFF])).await?;
    let prelogin = read_tds_message(&mut stream)
        .await?
        .ok_or("MSSQL closed the connection during pre-login")?;
    assert!(
        !prelogin.is_empty(),
        "MSSQL answered pre-login with an empty payload"
    );

    stream
        .write_all(&tds_packet(TDS_RPC, &utf16le("\u{FB01}SELECT 1")))
        .await?;

    // The server must answer rather than die. Either reply is correct here - the point is
    // that the process is still running and this connection was handled to completion.
    let payload = read_tds_message(&mut stream).await?.ok_or(
        "MSSQL closed the connection without answering an RPC containing U+FB01 - the \
         connection task panicked inside parse_rpc_request",
    )?;
    assert!(
        !payload.is_empty(),
        "MSSQL answered the hostile RPC with an empty payload"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
