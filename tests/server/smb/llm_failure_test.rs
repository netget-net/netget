//! What an SMB2 client gets when the LLM backend fails.
//!
//! The failure is forced the same way `tests/server/dns/llm_failure_test.rs` does it: the
//! mock is configured for the startup instruction and for the operations the test needs to
//! get *past*, and for nothing else. The operation under test then matches no rule, the
//! mock Ollama server answers HTTP 500, and `consult_llm` returns `Err` - the same shape as
//! a real backend outage, an overload, or a malformed model response.
//!
//! Five of the six `consult_llm` call sites in `src/server/smb/mod.rs` used to propagate
//! that error with `?`, which broke out of the connection loop and closed the socket. A
//! client cannot tell a dropped connection from a hung server; it waits out its own
//! timeout. They now answer with an SMB2 ERROR response (MS-SMB2 2.2.2) carrying
//! STATUS_INTERNAL_ERROR and the request's own MessageId/TreeId/SessionId.
//!
//! The assertions are at the protocol level - the actual response bytes - because a
//! failure response the client cannot correlate to its request is as useless as silence.


use super::wire_util::{nbss, read_frame_sync, tree_connect};
use crate::server::helpers::{start_netget_server, E2EResult};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// MS-ERREF 2.3.1: "An internal error occurred."
const STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;

fn build_smb2_header(command: u16, message_id: u64) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(b"\xFESMB"); // 0  ProtocolId
    packet.extend_from_slice(&[64, 0]); // 4  StructureSize
    packet.extend_from_slice(&[0; 2]); // 6  CreditCharge
    packet.extend_from_slice(&[0; 4]); // 8  Status
    packet.extend_from_slice(&command.to_le_bytes()); // 12 Command
    packet.extend_from_slice(&[1, 0]); // 14 CreditRequest
    packet.extend_from_slice(&[0; 4]); // 16 Flags
    packet.extend_from_slice(&[0; 4]); // 20 NextCommand
    packet.extend_from_slice(&message_id.to_le_bytes()); // 24 MessageId
    packet.extend_from_slice(&[0; 4]); // 32 Reserved
    packet.extend_from_slice(&[1, 0, 0, 0]); // 36 TreeId
    packet.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // 40 SessionId
    packet.extend_from_slice(&[0; 16]); // 48 Signature
    assert_eq!(packet.len(), 64);
    packet
}

/// SMB2 NEGOTIATE request (MS-SMB2 2.2.3), framed for Direct TCP.
fn build_smb2_negotiate() -> Vec<u8> {
    let mut packet = build_smb2_header(0x0000, 0);
    packet.extend_from_slice(&[36, 0]); // StructureSize
    packet.extend_from_slice(&[1, 0]); // DialectCount
    packet.extend_from_slice(&[0; 2]); // SecurityMode
    packet.extend_from_slice(&[0; 2]); // Reserved
    packet.extend_from_slice(&[0; 4]); // Capabilities
    packet.extend_from_slice(&[0; 16]); // ClientGuid
    packet.extend_from_slice(&[0; 8]); // NegotiateContextOffset/Count
    packet.extend_from_slice(&[0x10, 0x02]); // Dialect SMB 2.1
    nbss(packet)
}

/// SMB2 SESSION_SETUP request (MS-SMB2 2.2.5), guest - empty security buffer.
fn build_smb2_session_setup() -> Vec<u8> {
    let mut packet = build_smb2_header(0x0001, 1);
    packet.extend_from_slice(&[25, 0]); // StructureSize
    packet.extend_from_slice(&[0; 1]); // Flags
    packet.extend_from_slice(&[0; 1]); // SecurityMode
    packet.extend_from_slice(&[0; 4]); // Capabilities
    packet.extend_from_slice(&[0; 4]); // Channel
    packet.extend_from_slice(&[88, 0]); // SecurityBufferOffset
    packet.extend_from_slice(&[0, 0]); // SecurityBufferLength
    packet.extend_from_slice(&[0; 8]); // PreviousSessionId
    nbss(packet)
}

/// SMB2 CREATE request (MS-SMB2 2.2.13). The UTF-16LE name sits at absolute offset 120,
/// which is what NameOffset advertises.
fn build_smb2_create(message_id: u64, path: &str) -> Vec<u8> {
    let name_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut packet = build_smb2_header(0x0005, message_id);
    packet.extend_from_slice(&[57, 0]); // StructureSize
    packet.push(0); // SecurityFlags
    packet.push(0); // RequestedOplockLevel
    packet.extend_from_slice(&[0; 4]); // ImpersonationLevel
    packet.extend_from_slice(&[0; 8]); // SmbCreateFlags
    packet.extend_from_slice(&[0; 8]); // Reserved
    packet.extend_from_slice(&[0x89, 0x00, 0x12, 0x00]); // DesiredAccess
    packet.extend_from_slice(&[0x80, 0, 0, 0]); // FileAttributes = NORMAL
    packet.extend_from_slice(&[0x07, 0, 0, 0]); // ShareAccess
    packet.extend_from_slice(&[0x01, 0, 0, 0]); // CreateDisposition = FILE_OPEN
    packet.extend_from_slice(&[0x40, 0, 0, 0]); // CreateOptions
    packet.extend_from_slice(&120u16.to_le_bytes()); // NameOffset
    packet.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes()); // NameLength
    packet.extend_from_slice(&[0; 4]); // CreateContextsOffset
    packet.extend_from_slice(&[0; 4]); // CreateContextsLength
    assert_eq!(packet.len(), 120, "name buffer must start at absolute 120");
    packet.extend_from_slice(&name_utf16);
    nbss(packet)
}

/// SMB2 READ request (MS-SMB2 2.2.19), 49-byte body.
fn build_smb2_read(message_id: u64, file_id: &[u8], length: u32) -> Vec<u8> {
    let mut packet = build_smb2_header(0x0008, message_id);
    packet.extend_from_slice(&[49, 0]); // StructureSize
    packet.push(0); // Padding
    packet.push(0); // Flags
    packet.extend_from_slice(&length.to_le_bytes()); // Length
    packet.extend_from_slice(&0u64.to_le_bytes()); // Offset
    packet.extend_from_slice(file_id); // FileId
    packet.extend_from_slice(&[0; 4]); // MinimumCount
    packet.extend_from_slice(&[0; 4]); // Channel
    packet.extend_from_slice(&[0; 4]); // RemainingBytes
    packet.extend_from_slice(&[0; 2]); // ReadChannelInfoOffset
    packet.extend_from_slice(&[0; 2]); // ReadChannelInfoLength
    packet.push(0); // Buffer
    assert_eq!(packet.len(), 64 + 49);
    nbss(packet)
}

/// SMB2 CLOSE request (MS-SMB2 2.2.15), 24-byte body. Handled without an LLM call, so it
/// is the cheapest way to prove the connection survived an error response.
fn build_smb2_close(message_id: u64, file_id: &[u8]) -> Vec<u8> {
    let mut packet = build_smb2_header(0x0006, message_id);
    packet.extend_from_slice(&[24, 0]); // StructureSize
    packet.extend_from_slice(&[0; 2]); // Flags
    packet.extend_from_slice(&[0; 4]); // Reserved
    packet.extend_from_slice(file_id); // FileId
    assert_eq!(packet.len(), 64 + 24);
    nbss(packet)
}

/// One response: a Direct TCP frame, unwrapped.
fn read_smb2_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    read_frame_sync(stream)
}

fn parse_smb2_status(response: &[u8]) -> Option<u32> {
    if response.len() < 64 || &response[0..4] != b"\xFESMB" {
        return None;
    }
    Some(u32::from_le_bytes([
        response[8],
        response[9],
        response[10],
        response[11],
    ]))
}

/// Extract the 16-byte FileId from a CREATE response (body offset 64).
fn create_response_file_id(response: &[u8]) -> Vec<u8> {
    assert!(
        response.len() >= 64 + 89,
        "CREATE response too short: {} bytes",
        response.len()
    );
    response[64 + 64..64 + 80].to_vec()
}

/// Assert `response` is an SMB2 ERROR response for `command` carrying `status`, correlated
/// to a request with `message_id`.
///
/// Correlation is the point: a client matches replies to outstanding requests by
/// MessageId, so an error carrying the wrong one is discarded and the client is back to
/// waiting out its own timeout - exactly the failure this path exists to prevent.
fn expect_smb2_error(response: &[u8], command: u16, status: u32, message_id: u64) {
    assert!(
        response.len() >= 64 + 9,
        "ERROR response is shorter than a header plus the 9-byte error body: {} bytes",
        response.len()
    );
    assert_eq!(&response[0..4], b"\xFESMB", "invalid SMB2 signature");
    assert_eq!(
        parse_smb2_status(response),
        Some(status),
        "expected NTSTATUS 0x{status:08X}, got 0x{:08X} - a fail-open success here would \
         hand the client invented content",
        parse_smb2_status(response).unwrap_or(0)
    );
    assert_eq!(
        u16::from_le_bytes([response[12], response[13]]),
        command,
        "the error must name the command that failed"
    );
    assert_eq!(
        response[16] & 0x01,
        0x01,
        "SMB2_FLAGS_SERVER_TO_REDIR must be set on a response"
    );
    assert_eq!(
        &response[24..32],
        &message_id.to_le_bytes(),
        "MessageId must be echoed so the client can correlate the failure"
    );
    assert_eq!(
        &response[36..40],
        &1u32.to_le_bytes(),
        "TreeId must be echoed from the request"
    );
    assert_eq!(
        &response[40..48],
        &1u64.to_le_bytes(),
        "SessionId must be echoed from the request"
    );
    assert_eq!(
        u16::from_le_bytes([response[64], response[65]]),
        9,
        "SMB2 ERROR response body has StructureSize 9"
    );
}

/// NEGOTIATE + SESSION_SETUP + TREE_CONNECT, so the connection is ready for file operations
/// on tree 1 of session 1, which is what every request above addresses.
fn smb_handshake(stream: &mut TcpStream) -> E2EResult<()> {
    stream.write_all(&build_smb2_negotiate())?;
    stream.flush()?;
    let _ = read_smb2_response(stream)?;

    stream.write_all(&build_smb2_session_setup())?;
    stream.flush()?;
    let response = read_smb2_response(stream)?;
    assert_eq!(
        parse_smb2_status(&response),
        Some(0),
        "SESSION_SETUP must succeed for the rest of the flow"
    );

    stream.write_all(&nbss(tree_connect(2, 1, "\\\\127.0.0.1\\share")))?;
    stream.flush()?;
    let response = read_smb2_response(stream)?;
    assert_eq!(
        parse_smb2_status(&response),
        Some(0),
        "TREE_CONNECT must succeed"
    );
    Ok(())
}

/// CREATE when the LLM is down: the client gets STATUS_INTERNAL_ERROR, not a dead socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_create_errors_when_llm_fails() -> E2EResult<()> {
    let prompt = "Start an SMB file server via smb serving /documents.";

    let config = crate::helpers::NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(1)
            .and()
            // The startup instruction is the ONLY other rule. `create` therefore matches
            // nothing, the mock answers HTTP 500, and consult_llm returns Err - the same
            // shape as a real backend outage. A catch-all `on_any()` here would answer the
            // create event instead and the test would prove nothing.
            .on_instruction_containing("via smb")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    smb_handshake(&mut stream)?;

    stream.write_all(&build_smb2_create(2, "/documents/report.txt"))?;
    stream.flush()?;

    let response = read_smb2_response(&mut stream).map_err(|e| {
        format!(
            "No CREATE response ({e}) - the server dropped the connection on LLM failure, \
             which is the exact defect this test exists to catch"
        )
    })?;
    assert!(
        !response.is_empty(),
        "read returned 0 bytes: the server closed the connection instead of answering"
    );

    expect_smb2_error(&response, 0x0005, STATUS_INTERNAL_ERROR, 2);
    println!("  [TEST] CREATE -> STATUS_INTERNAL_ERROR, MessageId echoed");

    drop(stream);
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// READ when the LLM is down, on a handle that was created successfully.
///
/// Also asserts the connection is left in a sane state: a CLOSE (which needs no LLM call)
/// is still answered afterwards, so the error response ends the *operation*, not the
/// session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_read_errors_when_llm_fails_and_connection_survives() -> E2EResult<()> {
    let prompt = "Start an SMB file server via smb serving one file.";

    let config = crate::helpers::NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .and_event_data_contains("path", "/documents/notes.txt")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_create_file", "path": "/documents/notes.txt"}
            ]))
            .expect_calls(1)
            .and()
            // Deliberately NO rule for the `read` operation, and no catch-all: it must
            // fall through to the mock's HTTP 500.
            .on_instruction_containing("via smb")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    smb_handshake(&mut stream)?;

    stream.write_all(&build_smb2_create(2, "/documents/notes.txt"))?;
    stream.flush()?;
    let create_response = read_smb2_response(&mut stream)?;
    assert_eq!(
        parse_smb2_status(&create_response),
        Some(0),
        "CREATE is mocked and must succeed"
    );
    let file_id = create_response_file_id(&create_response);

    stream.write_all(&build_smb2_read(3, &file_id, 4096))?;
    stream.flush()?;
    let read_response = read_smb2_response(&mut stream).map_err(|e| {
        format!(
            "No READ response ({e}) - the server dropped the connection on LLM failure, \
             which is the exact defect this test exists to catch"
        )
    })?;
    assert!(
        !read_response.is_empty(),
        "read returned 0 bytes: the server closed the connection instead of answering"
    );

    expect_smb2_error(&read_response, 0x0008, STATUS_INTERNAL_ERROR, 3);

    // A READ that failed must not have delivered a body: a client reading DataLength bytes
    // off a "successful" response is how invented content reaches an application.
    assert_eq!(
        read_response.len(),
        64 + 9,
        "an ERROR response carries only the 9-byte error body, got {} bytes",
        read_response.len()
    );
    println!("  [TEST] READ -> STATUS_INTERNAL_ERROR with no payload");

    // The session must still be usable: CLOSE takes no LLM call and must be answered.
    stream.write_all(&build_smb2_close(4, &file_id))?;
    stream.flush()?;
    let close_response = read_smb2_response(&mut stream)?;
    assert_eq!(
        parse_smb2_status(&close_response),
        Some(0),
        "the connection must survive an LLM-failure response, not be torn down"
    );
    println!("  [TEST] CLOSE still answered - connection left in a sane state");

    drop(stream);
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
