//! The 64-byte SMB2 response header, laid out by every builder the server has, and on the wire.
//!
//! A client matches a reply to its outstanding request by MessageId (MS-SMB2 3.2.5.1.2), which
//! sits at offset 24 of the header (MS-SMB2 2.2.1.2). Eight of this server's response builders
//! once wrote it at offset 20 — NextCommand's slot — while the NEGOTIATE and ERROR builders had
//! it right, so a real client got past NEGOTIATE and then matched nothing. These tests hold the
//! layout in two places:
//!
//! 1. `every_builder_puts_the_message_id_at_offset_24_and_it_round_trips` calls each builder in
//!    `netget::server::smb::wire` with a header echoing a request whose MessageId, TreeId and
//!    SessionId are all distinct byte patterns, checks every field at its specified offset, and
//!    parses the result back with the request-side parser.
//! 2. `a_full_session_answers_every_request_with_its_own_message_id` drives a whole session
//!    over TCP — every command the server implements, including refusals — with a different
//!    MessageId on every request, checks each reply against its request, and hands the capture
//!    to the pcap oracle (Wireshark's `nbss`/`smb2` dissectors), which must report no
//!    malformed frame.
//!
//! A third test, `a_write_before_any_session_is_refused_and_the_stream_stays_in_step`, is the
//! WRITE that used to be refused without its body being read, leaving the payload to be parsed
//! as the next header.
//!
//! **Verified by removal:** writing the MessageId at offset 20 in `ResponseHeader::encode` fails
//! both of the first two tests — the builder test on the offset assertion, the wire test on the
//! first reply after NEGOTIATE's correlation check — and the oracle.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb --test server -- smb::header_layout --test-threads=100


use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use netget::server::smb::wire::{self, FileMeta, RequestHeader, ResponseHeader};

use super::wire_util::{self as w, nbss, read_frame_sync};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

const MESSAGE_ID: u64 = 0x1122_3344_5566_7788;
const TREE_ID: u32 = 0xA1B2_C3D4;
const SESSION_ID: u64 = 0x0102_0304_0506_0708;

/// Assert every header field of `resp` is where MS-SMB2 2.2.1.2 puts it.
fn assert_header(resp: &[u8], command: u16, status: u32, message_id: u64, what: &str) {
    assert!(resp.len() >= 64, "{what}: shorter than a header");
    assert_eq!(&resp[0..4], b"\xFESMB", "{what}: ProtocolId at 0");
    assert_eq!(
        u16::from_le_bytes([resp[4], resp[5]]),
        64,
        "{what}: StructureSize at 4"
    );
    assert_eq!(w::status(resp), status, "{what}: Status at 8");
    assert_eq!(w::command(resp), command, "{what}: Command at 12");
    assert!(
        u16::from_le_bytes([resp[14], resp[15]]) >= 1,
        "{what}: CreditResponse at 14 must grant at least one credit"
    );
    assert_eq!(w::flags(resp) & 1, 1, "{what}: SERVER_TO_REDIR at 16");
    assert_eq!(
        w::next_command(resp),
        0,
        "{what}: NextCommand at 20 must be zero for a lone response"
    );
    assert_eq!(
        w::message_id(resp),
        message_id,
        "{what}: MessageId at 24 must echo the request's (bytes 20..32 are {:02x?})",
        &resp[20..32]
    );
    assert_eq!(&resp[48..64], &[0u8; 16], "{what}: Signature at 48");
}

#[test]
fn every_builder_puts_the_message_id_at_offset_24_and_it_round_trips() {
    let meta = FileMeta {
        is_directory: false,
        size: 12,
        time: 0x01DC_0000_0000_0000,
        file_index: 7,
    };
    let file_id = [0x5Au8; 16];

    // Build a request header for every command, parse it with the server's own parser, and
    // answer it with the builder for that command.
    let cases: Vec<(u16, u32, Box<dyn Fn(&ResponseHeader) -> Vec<u8>>)> = vec![
        (
            w::NEGOTIATE,
            0,
            Box::new(|h| {
                wire::negotiate_response(
                    h,
                    &wire::NegotiateParams {
                        dialect: 0x0210,
                        server_guid: [1; 16],
                        capabilities: 0,
                        max_transact_size: 65536,
                        max_read_size: 65536,
                        max_write_size: 65536,
                        system_time: 1,
                        security_blob: netget::server::smb::auth::negotiate_blob(),
                    },
                )
            }),
        ),
        (
            w::SESSION_SETUP,
            0xC000_0016,
            Box::new(|h| wire::session_setup_response(h, 0, b"NTLMSSP\0challenge")),
        ),
        (
            w::SESSION_SETUP,
            0,
            Box::new(|h| wire::session_setup_response(h, 1, &[])),
        ),
        (w::LOGOFF, 0, Box::new(wire::empty_response)),
        (
            w::TREE_CONNECT,
            0,
            Box::new(|h| wire::tree_connect_response(h, wire::SHARE_TYPE_DISK, 0x001F_01FF)),
        ),
        (w::TREE_DISCONNECT, 0, Box::new(wire::empty_response)),
        (
            w::CREATE,
            0,
            Box::new(move |h| wire::create_response(h, &file_id, &meta, wire::FILE_OPENED)),
        ),
        (w::CLOSE, 0, Box::new(|h| wire::close_response(h, None))),
        (
            w::CLOSE,
            0,
            Box::new(move |h| wire::close_response(h, Some(&meta))),
        ),
        (
            w::READ,
            0,
            Box::new(|h| wire::read_response(h, b"hello world\n")),
        ),
        (w::WRITE, 0, Box::new(|h| wire::write_response(h, 12))),
        (w::ECHO, 0, Box::new(wire::empty_response)),
        (
            w::QUERY_DIRECTORY,
            0,
            Box::new(move |h| {
                let entries = [
                    wire::directory_entry(wire::file_class::ID_BOTH_DIRECTORY, ".", &meta),
                    wire::directory_entry(wire::file_class::ID_BOTH_DIRECTORY, "a.txt", &meta),
                ];
                wire::query_directory_response(h, &wire::join_directory_entries(&entries))
            }),
        ),
        (
            w::QUERY_INFO,
            0,
            Box::new(move |h| {
                wire::query_info_response(
                    h,
                    &wire::file_info(wire::file_class::ALL, &meta).unwrap(),
                )
            }),
        ),
        (w::READ, 0xC000_0011, Box::new(wire::error_response)),
        (
            w::QUERY_DIRECTORY,
            0x8000_0006,
            Box::new(wire::error_response),
        ),
    ];

    for (command, status, build) in cases {
        let request = w::header(command, MESSAGE_ID, TREE_ID, SESSION_ID);
        let parsed = RequestHeader::parse(&request).expect("the request header parses");
        assert_eq!(
            parsed.message_id, MESSAGE_ID,
            "the request-side parser reads offset 24"
        );
        let hdr = ResponseHeader::for_request(&parsed, status);
        let resp = build(&hdr);
        let what = format!("builder for command 0x{command:04x} status 0x{status:08x}");

        assert_header(&resp, command, status, MESSAGE_ID, &what);
        assert_eq!(
            w::tree_id(&resp),
            TREE_ID,
            "{what}: TreeId at 36 echoes the request"
        );
        assert_eq!(
            w::session_id(&resp),
            SESSION_ID,
            "{what}: SessionId at 40 echoes the request"
        );

        // Round trip: the response header read back by the same offsets the request parser
        // uses gives back the request's identity.
        let back = RequestHeader::parse(&resp).expect("the response header parses");
        assert_eq!(back.message_id, MESSAGE_ID, "{what}: MessageId round trip");
        assert_eq!(back.tree_id, TREE_ID, "{what}: TreeId round trip");
        assert_eq!(back.session_id, SESSION_ID, "{what}: SessionId round trip");
        assert_eq!(back.command, command, "{what}: Command round trip");
        assert_eq!(back.next_command, 0, "{what}: NextCommand round trip");
    }

    // A header that allocates a session or a tree says so, and still echoes the MessageId.
    let request = w::header(w::SESSION_SETUP, MESSAGE_ID, 0, 0);
    let hdr = ResponseHeader::for_request(&RequestHeader::parse(&request).unwrap(), 0)
        .with_session_id(42)
        .with_tree_id(9);
    let resp = wire::session_setup_response(&hdr, 1, &[]);
    assert_eq!(
        (
            w::message_id(&resp),
            w::session_id(&resp),
            w::tree_id(&resp)
        ),
        (MESSAGE_ID, 42, 9)
    );

    // A compound chain: every response but the last names the next by an 8-byte-aligned
    // NextCommand, and each keeps its own MessageId.
    let a = wire::empty_response(&ResponseHeader::for_request(
        &RequestHeader::parse(&w::header(w::ECHO, 1, 0, 0)).unwrap(),
        0,
    ));
    let b = wire::empty_response(&ResponseHeader::for_request(
        &RequestHeader::parse(&w::header(w::ECHO, 2, 0, 0)).unwrap(),
        0,
    ));
    let chain = wire::chain(vec![a, b]);
    let next = w::next_command(&chain) as usize;
    assert_eq!(next % 8, 0, "NextCommand is 8-byte aligned");
    assert_eq!(w::message_id(&chain), 1);
    assert_eq!(w::message_id(&chain[next..]), 2);
    assert_eq!(w::next_command(&chain[next..]), 0);
}

/// The server's answers for a whole scripted session. Returns (requests, responses) in order.
fn drive_session(port: u16) -> std::io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut exchange = Vec::new();
    // A CANCEL is never answered (MS-SMB2 3.3.5.16), so it is written and not waited for; the
    // request after it proves no answer came, because the next frame read is that request's.
    let mut send = |s: &mut TcpStream, req: Vec<u8>| -> std::io::Result<Vec<u8>> {
        s.write_all(&nbss(req.clone()))?;
        if w::command(&req) == w::CANCEL {
            exchange.push((req, Vec::new()));
            return Ok(Vec::new());
        }
        let resp = read_frame_sync(s)?;
        exchange.push((req, resp.clone()));
        Ok(resp)
    };

    // Every MessageId differs from every other and from the fields that sit beside it, so a
    // reply that echoes the wrong bytes cannot match by accident.
    let base: u64 = 0x5A00_0000_0000_0100;
    let r = send(&mut s, w::negotiate(base))?;
    assert_header(&r, w::NEGOTIATE, 0, base, "NEGOTIATE");
    let r = send(&mut s, w::session_setup(base + 1))?;
    assert_header(&r, w::SESSION_SETUP, 0, base + 1, "SESSION_SETUP");
    let sid = w::session_id(&r);
    assert_ne!(sid, 0, "SESSION_SETUP allocates a session id");
    let r = send(&mut s, w::tree_connect(base + 2, sid, r"\\127.0.0.1\share"))?;
    assert_header(&r, w::TREE_CONNECT, 0, base + 2, "TREE_CONNECT");
    assert_eq!(w::session_id(&r), sid, "TREE_CONNECT echoes the SessionId");
    let tid = w::tree_id(&r);
    assert_ne!(tid, 0, "TREE_CONNECT allocates a tree id");

    let r = send(&mut s, w::create_with(base + 3, tid, sid, "", 1))?;
    assert_header(&r, w::CREATE, 0, base + 3, "CREATE of the share root");
    assert_eq!(
        (w::tree_id(&r), w::session_id(&r)),
        (tid, sid),
        "CREATE ids"
    );
    let dir = w::create_file_id(&r);
    let r = send(
        &mut s,
        w::query_directory(base + 4, tid, sid, &dir, 37, "*"),
    )?;
    assert_header(&r, w::QUERY_DIRECTORY, 0, base + 4, "QUERY_DIRECTORY");
    let r = send(
        &mut s,
        w::query_directory(base + 5, tid, sid, &dir, 37, "*"),
    )?;
    assert_header(
        &r,
        w::QUERY_DIRECTORY,
        w::STATUS_NO_MORE_FILES,
        base + 5,
        "QUERY_DIRECTORY end",
    );
    let r = send(&mut s, w::query_info(base + 6, tid, sid, &dir, 2, 7))?;
    assert_header(
        &r,
        w::QUERY_INFO,
        0,
        base + 6,
        "QUERY_INFO FileFsFullSizeInformation",
    );
    let r = send(&mut s, w::close(base + 7, tid, sid, &dir))?;
    assert_header(&r, w::CLOSE, 0, base + 7, "CLOSE of the root");

    let r = send(
        &mut s,
        w::create_with(base + 8, tid, sid, "hello.txt", 0x40),
    )?;
    assert_header(&r, w::CREATE, 0, base + 8, "CREATE of a file");
    let file = w::create_file_id(&r);
    let r = send(&mut s, w::query_info(base + 9, tid, sid, &file, 1, 18))?;
    assert_header(
        &r,
        w::QUERY_INFO,
        0,
        base + 9,
        "QUERY_INFO FileAllInformation",
    );
    let r = send(&mut s, w::read(base + 10, tid, sid, &file, 0, 4096))?;
    assert_header(&r, w::READ, 0, base + 10, "READ");
    assert_eq!(w::read_payload(&r), b"hello world\n");
    let r = send(&mut s, w::read(base + 11, tid, sid, &file, 12, 4096))?;
    assert_header(
        &r,
        w::READ,
        w::STATUS_END_OF_FILE,
        base + 11,
        "READ at end of file",
    );
    let r = send(&mut s, w::write(base + 12, tid, sid, &file, b"more"))?;
    assert_header(&r, w::WRITE, 0, base + 12, "WRITE");
    let r = send(&mut s, w::flush(base + 20, tid, sid, &file))?;
    assert_header(&r, w::FLUSH, 0, base + 20, "FLUSH");
    // The refusals are answers too, each to its own MessageId: IOCTL has no FSCTL behind it,
    // and SET_INFO and LOCK are not implemented.
    let r = send(&mut s, w::ioctl(base + 21, tid, sid, &file, 0x0014_0204))?;
    assert_header(
        &r,
        w::IOCTL,
        w::STATUS_INVALID_DEVICE_REQUEST,
        base + 21,
        "IOCTL",
    );
    let r = send(&mut s, w::set_info_delete(base + 22, tid, sid, &file))?;
    assert_header(
        &r,
        w::SET_INFO,
        w::STATUS_NOT_SUPPORTED,
        base + 22,
        "SET_INFO",
    );
    let r = send(&mut s, w::lock(base + 23, tid, sid, &file))?;
    assert_header(&r, w::LOCK, w::STATUS_NOT_SUPPORTED, base + 23, "LOCK");
    send(&mut s, w::simple(w::CANCEL, base + 12, 0, sid))?;
    let r = send(&mut s, w::simple(w::ECHO, base + 24, 0, sid))?;
    assert_header(
        &r,
        w::ECHO,
        0,
        base + 24,
        "the ECHO after a CANCEL (the CANCEL itself is never answered)",
    );
    let r = send(&mut s, w::close(base + 13, tid, sid, &file))?;
    assert_header(&r, w::CLOSE, 0, base + 13, "CLOSE of the file");
    let r = send(&mut s, w::close(base + 14, tid, sid, &file))?;
    assert_header(
        &r,
        w::CLOSE,
        w::STATUS_FILE_CLOSED,
        base + 14,
        "CLOSE of a closed handle",
    );

    let r = send(&mut s, w::simple(w::ECHO, base + 15, 0, sid))?;
    assert_header(&r, w::ECHO, 0, base + 15, "ECHO");
    let r = send(&mut s, w::simple(w::TREE_DISCONNECT, base + 16, tid, sid))?;
    assert_header(&r, w::TREE_DISCONNECT, 0, base + 16, "TREE_DISCONNECT");
    let r = send(&mut s, w::simple(w::LOGOFF, base + 17, 0, sid))?;
    assert_header(&r, w::LOGOFF, 0, base + 17, "LOGOFF");
    let r = send(&mut s, w::create(base + 18, tid, sid, "hello.txt"))?;
    assert_header(
        &r,
        w::CREATE,
        w::STATUS_USER_SESSION_DELETED,
        base + 18,
        "CREATE after LOGOFF",
    );
    Ok(exchange)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_session_answers_every_request_with_its_own_message_id() -> E2EResult<()> {
    let prompt = "Serve one file, hello.txt, over smb.";
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions_from_event(|event| {
                let path = event["path"].as_str().unwrap_or_default().to_string();
                if path == "/" {
                    serde_json::json!([{"type": "smb_create_directory", "path": path}])
                } else {
                    serde_json::json!([{"type": "smb_create_file", "path": path}])
                }
            })
            .expect_calls(2)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "query_directory")
            .respond_with_actions(serde_json::json!([{
                "type": "smb_list_directory",
                "path": "/",
                "files": [{"name": "hello.txt", "size": 12, "is_directory": false,
                           "modified_time": "2026-01-02T03:04:05Z"}]
            }]))
            .expect_calls(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "query_info")
            .respond_with_actions(serde_json::json!([{
                "type": "smb_get_file_info", "path": "/hello.txt", "size": 12,
                "is_directory": false, "modified_time": "2026-01-02T03:04:05Z"
            }]))
            .expect_calls(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "read")
            .respond_with_actions(serde_json::json!([{
                "type": "smb_read_file", "path": "/hello.txt", "content": "hello world\n"
            }]))
            // Twice: the read at offset 12 asks too, and is answered END_OF_FILE.
            .expect_calls(2)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "write")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_write_file", "path": "/hello.txt"}
            ]))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });
    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let port = server.port;
    let exchange = tokio::task::spawn_blocking(move || drive_session(port))
        .await
        .expect("session task")?;

    // Everything that crossed the wire, framed exactly as it was sent, read by Wireshark.
    let mut oracle = PcapOracle::tcp("smb");
    for (req, resp) in &exchange {
        oracle = oracle.to_server(&nbss(req.clone()));
        if !resp.is_empty() {
            oracle = oracle.from_server(&nbss(resp.clone()));
        }
    }
    oracle.assert_clean();

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A WRITE that arrives before any session is refused — and its payload is consumed with it,
/// so the NEGOTIATE that follows on the same connection is read as a NEGOTIATE.
///
/// The server once refused this WRITE having read only its 64-byte header and fixed body; the
/// data behind them was then parsed as the next header, the signature check failed and the
/// connection closed. The model must not be consulted about the refused WRITE at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_before_any_session_is_refused_and_the_stream_stays_in_step() -> E2EResult<()> {
    let prompt = "Serve files over smb.";
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .respond_with_actions(serde_json::json!([]))
            // Upstream of the model: neither the WRITE nor the NEGOTIATE reaches it.
            .expect_calls(0)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });
    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let port = server.port;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut s = TcpStream::connect(("127.0.0.1", port))?;
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        // A payload that is itself a plausible SMB2 header, so a server that read it as the
        // next message would not even fail the signature check — it would answer it.
        let mut payload = w::simple(w::ECHO, 999, 0, 0);
        payload.resize(4096, 0xEE);
        s.write_all(&nbss(w::write(7, 1, 1, &[0xAB; 16], &payload)))?;
        let r = read_frame_sync(&mut s)?;
        assert_header(
            &r,
            w::WRITE,
            w::STATUS_USER_SESSION_DELETED,
            7,
            "WRITE before any session",
        );

        s.write_all(&nbss(w::negotiate(8)))?;
        let r = read_frame_sync(&mut s)?;
        assert_header(&r, w::NEGOTIATE, 0, 8, "NEGOTIATE after the refused WRITE");
        Ok(())
    })
    .await
    .expect("client task")?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
