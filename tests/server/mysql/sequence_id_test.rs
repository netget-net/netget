//! Two packet sequence ids that panic `opensrv-mysql` 0.7.0, refused before it reads them.
//!
//! - **Sequence id `0xFF`.** The crate answers every packet with `writer.set_seq(seq + 1)` on
//!   the client's `u8` (`lib.rs:389` for the handshake response, `:502`, `:563` for commands).
//!   `255 + 1` panics wherever overflow checks are on — every debug and test build — so one
//!   four-byte header in the handshake response, before authentication, killed the connection
//!   task. (Release builds wrap it to 0 and carry on.)
//! - **A chained packet whose fragments are misnumbered.** `packet()` reassembles a chain with
//!   `assert_eq!(nseq, seq + 1)` between fragments and `assert_eq!(last.0, full.0 + 1)` before
//!   the last one (`packet_reader.rs:252`, `:266`) — a panic in every build.
//!
//! A panic there is inside the connection task, which `tokio::spawn` swallows: the server stays
//! `Running`, the socket closes, the peer never learns why, and `close_connection_on_server`
//! never runs, so the connection stays Active on the dashboard. The guard is
//! `PacketLimitReader`, which already reads every header beneath the crate for the size bound
//! and now also refuses both shapes, answering MySQL's own **1156 `ER_NET_PACKETS_OUT_OF_ORDER`**
//! (SQLSTATE `08S01`) at the next sequence id. These tests send the bytes over the server's real
//! socket and require that reply; without the guard the connection closes with nothing on it.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::mysql::packet_limit::{
    PacketLimitReader, PacketLimitTrip, Refusal, FULL_PACKET_PAYLOAD,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ER_NET_PACKETS_OUT_OF_ORDER: u16 = 1156;

fn packet_header(payload_len: usize, sequence: u8) -> Vec<u8> {
    vec![
        (payload_len & 0xFF) as u8,
        ((payload_len >> 8) & 0xFF) as u8,
        ((payload_len >> 16) & 0xFF) as u8,
        sequence,
    ]
}

/// A HandshakeResponse41 `opensrv-mysql` parses: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION,
/// user `root`, an empty auth response. Parsing it is what reaches `set_seq(seq + 1)`.
fn handshake_response_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x0000_8200u32.to_le_bytes()); // capabilities
    p.extend_from_slice(&16_777_216u32.to_le_bytes()); // max packet size
    p.push(0x21); // utf8_general_ci
    p.extend_from_slice(&[0u8; 23]);
    p.extend_from_slice(b"root\0");
    p.push(0); // auth response length
    p
}

async fn feed(bytes: Vec<u8>) -> (bool, Arc<PacketLimitTrip>) {
    let trip = Arc::new(PacketLimitTrip::default());
    let mut reader = PacketLimitReader::new(&bytes[..], trip.clone());
    let mut scratch = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut scratch).await {
            Ok(0) => return (false, trip),
            Ok(_) => {}
            Err(_) => return (true, trip),
        }
    }
}

#[tokio::test]
async fn the_reader_refuses_exactly_the_sequence_ids_opensrv_panics_on() {
    let mut last = packet_header(3, 0xFF);
    last.extend_from_slice(b"abc");
    let (refused, trip) = feed(last).await;
    assert!(refused, "sequence id 0xFF must be refused");
    assert_eq!(trip.refusal(), Refusal::OutOfOrder);
    assert_eq!(
        trip.reply_sequence(),
        0,
        "the reply follows 0xFF, wrapping to 0"
    );

    let mut fe = packet_header(3, 0xFE);
    fe.extend_from_slice(b"abc");
    assert!(
        !feed(fe).await.0,
        "0xFE is harmless (opensrv adds one to it) and must pass — a guard refusing every \
         high sequence id would pass the other half of this test"
    );

    // A chain numbered 3, then 9: `packet()` would assert. The refusal answers the 9.
    let mut misnumbered = packet_header(FULL_PACKET_PAYLOAD, 3);
    misnumbered.extend(std::iter::repeat_n(0u8, FULL_PACKET_PAYLOAD));
    misnumbered.extend(packet_header(2, 9));
    misnumbered.extend_from_slice(b"zz");
    let (refused, trip) = feed(misnumbered).await;
    assert!(refused, "a misnumbered chain must be refused");
    assert_eq!(trip.refusal(), Refusal::OutOfOrder);
    assert_eq!(trip.reply_sequence(), 10);

    // The same chain numbered 3, then 4 is ordinary MySQL and must pass.
    let mut chain = packet_header(FULL_PACKET_PAYLOAD, 3);
    chain.extend(std::iter::repeat_n(0u8, FULL_PACKET_PAYLOAD));
    chain.extend(packet_header(2, 4));
    chain.extend_from_slice(b"zz");
    assert!(!feed(chain).await.0, "a correctly numbered chain must pass");

    // The chain's numbering ends with the chain: the next packet starts a new exchange.
    let mut two = packet_header(1, 0);
    two.push(0x0E);
    two.extend(packet_header(1, 0));
    two.push(0x0E);
    assert!(!feed(two).await.0, "two separate packets may both carry 0");
}

async fn mysql_server() -> E2EResult<crate::helpers::server::NetGetServer> {
    let config = NetGetConfig::new_no_scripts(
        "Open MySQL on port {AVAILABLE_PORT}. Answer queries about a users table.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MySQL",
                "instruction": "Answer queries about a users table"
            }]))
            .expect_calls(1)
            .and()
            // Both packets are refused before authentication completes, so nothing reaches
            // the model.
            .on_event("mysql_query")
            .respond_with_actions(serde_json::json!([{
                "type": "mysql_ok_response",
                "affected_rows": 0
            }]))
            .expect_calls(0)
            .and()
    });
    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    Ok(server)
}

/// Connect, read the greeting, send `bytes`, and return everything the server writes before it
/// closes.
async fn exchange(port: u16, bytes: Vec<u8>, case: &str) -> E2EResult<Vec<u8>> {
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let mut greeting = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), sock.read(&mut greeting))
        .await
        .map_err(|_| format!("{case}: no initial handshake packet"))??;
    assert!(n > 4, "{case}: the greeting should be more than a header");

    let (mut rx, mut tx) = sock.into_split();
    let writer = tokio::spawn(async move {
        let _ = tx.write_all(&bytes).await;
        let _ = tx.flush().await;
    });
    let mut reply = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(60), rx.read_to_end(&mut reply)).await;
    let _ = writer.await;
    read.map_err(|_| format!("{case}: the server neither answered nor closed within 60s"))??;
    Ok(reply)
}

fn assert_out_of_order(reply: &[u8], sequence: u8, case: &str) {
    assert!(
        reply.len() >= 13,
        "{case}: expected an ERR packet, got {} bytes {:02x?} — an empty reply is the \
         connection task dying inside opensrv-mysql, which is the defect",
        reply.len(),
        reply
    );
    assert_eq!(
        reply[3], sequence,
        "{case}: the ERR must follow the refused header"
    );
    assert_eq!(reply[4], 0xFF, "{case}: not an ERR packet");
    assert_eq!(
        u16::from_le_bytes([reply[5], reply[6]]),
        ER_NET_PACKETS_OUT_OF_ORDER,
        "{case}: expected 1156 ER_NET_PACKETS_OUT_OF_ORDER"
    );
    assert_eq!(&reply[7..13], b"#08S01", "{case}: expected SQLSTATE 08S01");
}

#[tokio::test]
async fn panicking_sequence_ids_are_answered_with_1156_and_the_server_keeps_serving(
) -> E2EResult<()> {
    let server = mysql_server().await?;

    // 1. A well-formed handshake response carrying sequence id 0xFF.
    let payload = handshake_response_payload();
    let mut bytes = packet_header(payload.len(), 0xFF);
    bytes.extend_from_slice(&payload);
    let reply = exchange(
        server.port,
        bytes,
        "handshake response with sequence id 0xFF",
    )
    .await?;
    assert_out_of_order(&reply, 0x00, "handshake response with sequence id 0xFF");

    // 2. The handshake response as a two-fragment chain numbered 1, then 7.
    let mut bytes = packet_header(FULL_PACKET_PAYLOAD, 1);
    bytes.extend(std::iter::repeat_n(0u8, FULL_PACKET_PAYLOAD));
    bytes.extend(packet_header(5, 7));
    bytes.extend_from_slice(&[0u8; 5]);
    let reply = exchange(server.port, bytes, "chain numbered 1, then 7").await?;
    assert_out_of_order(&reply, 8, "chain numbered 1, then 7");

    // Still serving: a fresh connection gets its greeting.
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await?;
    let mut greeting = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), sock.read(&mut greeting))
        .await
        .map_err(|_| "no greeting after the refused packets: the server stopped serving")??;
    assert!(n > 4);

    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    Ok(())
}
