//! A MySQL packet larger than `max_allowed_packet` is refused, in MySQL's own vocabulary.
//!
//! # What was wrong
//!
//! `opensrv-mysql` 0.7.0 has no maximum-packet check anywhere. Its `packet()` parser assembles
//! a logical packet with `nom::multi::fold_many0(fullpacket, …)` — an unbounded fold over
//! 16 MiB continuation fragments — and `PacketReader::next_async` doubles its buffer until a
//! whole logical packet fits. The peer therefore decided how much this process allocated, and
//! it decided **before authentication and before any model call**: the first thing a MySQL
//! client ever sends is its handshake response, read through exactly this path.
//!
//! The server also *published* a ceiling it never applied — `opensrv-mysql` answers
//! `SELECT @@max_allowed_packet` with 67108864 itself, without consulting NetGet's shim.
//!
//! # What these tests assert
//!
//! Three things, and the third is what stops the first two from being satisfiable by a guard
//! that refuses everything:
//!
//! 1. A logical packet one byte past `MAX_PACKET_BYTES` is refused with **1153
//!    `ER_NET_PACKET_TOO_LARGE`, SQLSTATE `08S01`**, at the correct sequence id, **during the
//!    handshake** — so the bound is demonstrably pre-authentication — and with **zero** model
//!    calls.
//! 2. A logical packet of exactly `MAX_PACKET_BYTES` is accepted by the framing, and so is a
//!    legitimate multi-fragment chain. Both are asserted against the reader directly, because
//!    asserting them on the wire would mean moving 64 MiB per case for no extra evidence.
//! 3. An ordinary query still works and still reaches the model exactly once.
//!
//! # Why the wire test uses a raw socket
//!
//! `mysql_async` would be the natural client and is the wrong tool here. The refusal has to
//! survive the peer still writing, and a client that polls its read side while writing can
//! parse the answer before the close lands — which hides exactly the `RST`-discards-the-reply
//! failure the lingering drain in `src/server/mysql/mod.rs` exists to prevent. A raw socket
//! that writes and then reads is the honest peer to test against. (The same difference was
//! measured on `ipp`: 5 failures in 8 runs with a raw socket, 5 in 5 with a hyper client.)


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::mysql::packet_limit::{
    PacketLimitReader, PacketLimitTrip, FULL_PACKET_PAYLOAD, MAX_PACKET_BYTES,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `ER_NET_PACKET_TOO_LARGE`, and the SQLSTATE a real MySQL server pairs with it.
const ER_NET_PACKET_TOO_LARGE: u16 = 1153;
const SQLSTATE_COMMUNICATION_LINK_FAILURE: &[u8] = b"08S01";

/// Only one 64 MiB test runs at a time.
///
/// Reaching a 64 MiB bound costs 64 MiB on the wire by construction — the refusal is taken at
/// the header that crosses it, so every earlier fragment's payload really has to be delivered
/// to get there. The `ipp` suite measured what three concurrent oversized-body tests do to a
/// 100-thread run (five unrelated `tuntap` tests failing in half of all runs); this file has
/// one such test and keeps it that way.
static ONE_OVERSIZED_PACKET_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A 4-byte MySQL packet header: 3-byte little-endian payload length, then the sequence id.
fn packet_header(payload_len: usize, sequence: u8) -> Vec<u8> {
    vec![
        (payload_len & 0xFF) as u8,
        ((payload_len >> 8) & 0xFF) as u8,
        ((payload_len >> 16) & 0xFF) as u8,
        sequence,
    ]
}

/// Drive `bytes` through a `PacketLimitReader` with `limit`, reporting whether it refused.
async fn feed(bytes: Vec<u8>, limit: usize) -> (bool, Arc<PacketLimitTrip>) {
    let trip = Arc::new(PacketLimitTrip::default());
    let mut reader = PacketLimitReader::with_limit(&bytes[..], limit, trip.clone());
    let mut scratch = [0u8; 4096];
    let mut refused = false;
    loop {
        match reader.read(&mut scratch).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => {
                refused = true;
                break;
            }
        }
    }
    (refused, trip)
}

#[tokio::test]
async fn a_packet_at_the_limit_passes_and_one_byte_more_is_refused() {
    // Deliberately a small limit. The framing decision is the same at 1 KiB as at 64 MiB —
    // it is taken from the declared length in the header — and a test that had to move 64 MiB
    // to make it could not assert the *exact* boundary without costing a second of wall clock
    // and 128 MiB of buffer for each case.
    const LIMIT: usize = 1024;

    let mut at_limit = packet_header(LIMIT, 1);
    at_limit.extend(std::iter::repeat_n(0x41u8, LIMIT));
    let (refused, _) = feed(at_limit, LIMIT).await;
    assert!(
        !refused,
        "a packet declaring exactly the limit must be accepted; a guard that refuses \
         everything would pass the other half of this test"
    );

    let mut over_limit = packet_header(LIMIT + 1, 7);
    over_limit.extend(std::iter::repeat_n(0x41u8, LIMIT + 1));
    let (refused, trip) = feed(over_limit, LIMIT).await;
    assert!(refused, "a packet one byte past the limit must be refused");
    assert!(trip.tripped(), "the refusal must be recorded as the bound");
    assert_eq!(
        trip.reply_sequence(),
        8,
        "the ERR packet must carry the refused header's sequence id plus one, or a conforming \
         client discards it as out of order"
    );
    assert_eq!(
        trip.declared_bytes(),
        LIMIT + 1,
        "the size logged must be the size the peer declared"
    );
}

#[tokio::test]
async fn a_legitimate_chain_is_accepted_and_the_sum_is_what_is_bounded() {
    // A fragment declaring exactly 2^24-1 means "more follows" (that is the protocol's own
    // framing rule, and the construct that makes `fold_many0` unbounded). So the size to bound
    // is the running sum across the chain, not each fragment: a per-fragment check would pass
    // every fragment forever.
    let mut chain = packet_header(FULL_PACKET_PAYLOAD, 0);
    chain.extend(std::iter::repeat_n(0u8, FULL_PACKET_PAYLOAD));
    chain.extend(packet_header(9, 1));
    chain.extend(std::iter::repeat_n(0u8, 9));

    let (refused, _) = feed(chain.clone(), FULL_PACKET_PAYLOAD + 9).await;
    assert!(
        !refused,
        "a chain summing to exactly the limit must be accepted — chaining is legal MySQL, and \
         refusing it outright would break every large statement rather than only oversized ones"
    );

    let (refused, trip) = feed(chain, FULL_PACKET_PAYLOAD + 8).await;
    assert!(
        refused,
        "a chain summing to one byte past the limit must be refused"
    );
    assert_eq!(
        trip.declared_bytes(),
        FULL_PACKET_PAYLOAD + 9,
        "the bound is on the accumulated declared size of the logical packet"
    );
    assert_eq!(
        trip.reply_sequence(),
        2,
        "the refusal answers the fragment that crossed the bound"
    );
}

#[tokio::test]
async fn an_oversized_handshake_packet_is_refused_with_1153_and_no_model_call() -> E2EResult<()> {
    let _serialised = ONE_OVERSIZED_PACKET_AT_A_TIME.lock().await;

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
            // The load-bearing expectation. The oversized packet is sent *as the handshake
            // response*, so nothing the model could be asked about has happened yet — if this
            // ever goes above zero, the bound has stopped being pre-auth and pre-LLM.
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

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await?;

    // MySQL is server-speaks-first: read the initial handshake so the exchange is a real one.
    let mut greeting = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), sock.read(&mut greeting))
        .await
        .map_err(|_| "MySQL server never sent its initial handshake packet")??;
    assert!(n > 4, "the handshake packet should be more than a header");

    // Four maximum-size fragments (4 * 16777215 = 67108860) and then a fifth declaring five
    // bytes, which takes the logical packet to 67108865 — one past MAX_PACKET_BYTES.
    let fragments = MAX_PACKET_BYTES / FULL_PACKET_PAYLOAD;
    let so_far = fragments * FULL_PACKET_PAYLOAD;
    let tail = MAX_PACKET_BYTES - so_far + 1;
    assert!(
        tail <= FULL_PACKET_PAYLOAD,
        "the tail fragment must be a legal short packet"
    );

    let (mut rx, mut tx) = sock.into_split();
    let writer = tokio::spawn(async move {
        let payload = vec![0u8; FULL_PACKET_PAYLOAD];
        for i in 0..fragments {
            if tx
                .write_all(&packet_header(FULL_PACKET_PAYLOAD, (i + 1) as u8))
                .await
                .is_err()
            {
                return;
            }
            if tx.write_all(&payload).await.is_err() {
                return;
            }
        }
        // The header that crosses the bound. Its payload is deliberately never written: the
        // decision is taken from the *declared* length, before a byte of it is read, which is
        // the whole point of bounding the declared size rather than the remainder.
        let _ = tx
            .write_all(&packet_header(tail, (fragments + 1) as u8))
            .await;
        let _ = tx.flush().await;
    });

    let mut reply = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(60), rx.read_to_end(&mut reply)).await;
    let _ = writer.await;
    read.map_err(|_| "MySQL neither refused the oversized packet nor closed within 60s")??;

    assert!(
        reply.len() >= 4 + 9,
        "expected an ERR packet, got {} bytes: {:?}",
        reply.len(),
        reply
    );
    assert_eq!(
        reply[4], 0xFF,
        "the reply must be an ERR packet (0xFF marker), got 0x{:02x}",
        reply[4]
    );
    assert_eq!(
        u16::from_le_bytes([reply[5], reply[6]]),
        ER_NET_PACKET_TOO_LARGE,
        "expected error 1153 ER_NET_PACKET_TOO_LARGE — the number a real MySQL server sends \
         when max_allowed_packet is exceeded"
    );
    assert_eq!(reply[7], b'#', "the SQLSTATE marker must be present");
    assert_eq!(
        &reply[8..13],
        SQLSTATE_COMMUNICATION_LINK_FAILURE,
        "expected SQLSTATE 08S01, so a driver can classify this without reading the message"
    );
    assert_eq!(
        reply[3],
        (fragments + 2) as u8,
        "the ERR packet must follow the refused header's sequence id; a reply out of sequence \
         is discarded by a conforming client, turning a clear refusal back into silence"
    );

    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn an_ordinary_query_still_reaches_the_model() -> E2EResult<()> {
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
            // mysql_async opens every connection with `SELECT @@max_allowed_packet,…`, and
            // opensrv only answers `SELECT @@max_allowed_packet` on its own when that is the
            // *whole* statement — so this one reaches the model. It must be answered with a
            // large number: the client sizes its own writes by it, and answering `7` makes
            // mysql_async refuse its next packet as too large, which reads exactly like the
            // server-side bound firing. First-match-wins, so this rule precedes the general one.
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT @@")
            .respond_with_actions(serde_json::json!([{
                "type": "mysql_query_response",
                "columns": [{"name": "value", "type": "VARCHAR"}],
                "rows": [["16777216"]]
            }]))
            .expect_at_least(1)
            .and()
            .on_event("mysql_query")
            .respond_with_actions(serde_json::json!([{
                "type": "mysql_query_response",
                "columns": [{"name": "id", "type": "INT"}],
                "rows": [[7]]
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let url = format!("mysql://root@127.0.0.1:{}/test", server.port);
    let pool = mysql_async::Pool::new(url.as_str());
    let rows: Vec<(i64,)> = tokio::time::timeout(Duration::from_secs(30), async {
        use mysql_async::prelude::Queryable;
        let mut conn = pool.get_conn().await?;
        conn.query("SELECT id FROM users").await
    })
    .await
    .map_err(|_| {
        "MySQL never answered an ordinary query — the packet bound refuses everything"
    })??;

    assert_eq!(
        rows,
        vec![(7,)],
        "an ordinary query must still be answered; the bound applies to oversized packets, not \
         to traffic"
    );

    let _ = pool.disconnect().await;
    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    Ok(())
}
