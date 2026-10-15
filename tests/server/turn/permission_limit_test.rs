//! An allocation's permission map is bounded, and the bound is checked before the model is.
//!
//! # What was wrong
//!
//! `AllocationState::permissions` is keyed by an IP address **the client names**, and expiry
//! was filter-on-read: `is_permitted` and `permitted_ips` skipped a stale entry and nothing
//! ever removed one. So the map only grew. Over IPv6 a single client has 2^128 distinct keys to
//! grow it with, and one CreatePermission may name many peers at once (RFC 8656 section 9.1
//! allows repeated XOR-PEER-ADDRESS attributes) — so the five-minute permission lifetime was
//! not a bound on how many could accumulate inside it.
//!
//! This is the shape of the OSPF neighbour-map defect: there the key was a Router ID the sender
//! chose, and a peer spraying Hellos grew the table until the server stopped. OSPF's repair is
//! the one copied here, and its important half is that **expiry is enforced on write** — ageing
//! on read is bookkeeping, ageing on write is a bound.
//!
//! # What these tests assert
//!
//! * A CreatePermission that would take the allocation past `MAX_PERMISSIONS` is answered
//!   **508 Insufficient Capacity** — TURN's own vocabulary, and the same code this server
//!   already uses for the allocation cap — and the model is **not** asked. Resource exhaustion
//!   is not a policy question, and a request naming ten thousand peers must not cost a model
//!   round-trip.
//! * The request that fills the map to *exactly* `MAX_PERMISSIONS` succeeds. Without that, a
//!   guard that refused every CreatePermission would pass the first assertion.
//!
//! There is no lingering-close question here: TURN is UDP. There is no connection to reset, so
//! the refusal is a datagram that either arrives or does not, and nothing the peer does
//! afterwards can discard it.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112_A442;

const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CREATE_PERMISSION_ERROR: u16 = 0x0118;

const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

/// `MAX_PERMISSIONS` in `src/server/turn/mod.rs`. Spelled out rather than imported because the
/// constant is private to the module and making it public for a test would advertise a bound
/// as a knob.
const MAX_PERMISSIONS: usize = 256;

/// Peers named per request.
///
/// Not a round number for its own sake: `RELAY_MTU` is 2048, and an IPv6 XOR-PEER-ADDRESS
/// attribute costs 24 bytes, so 64 of them plus the 20-byte STUN header is 1556 — inside one
/// datagram with room to spare, while 85 would not be. Four of these requests fill the map to
/// exactly the cap.
const PEERS_PER_REQUEST: usize = 64;

fn transaction_id(seed: u8) -> [u8; 12] {
    let mut tid = [0u8; 12];
    for (i, byte) in tid.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1);
    }
    tid
}

fn attribute(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len() + 3);
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// An IPv6 XOR-PEER-ADDRESS value (RFC 8489 section 14.2): family 0x02, the port XOR-ed with
/// the top half of the magic cookie, and the address XOR-ed with the cookie followed by the
/// transaction id.
///
/// IPv6 on purpose. The point of this bound is that the key space is the peer's to choose from,
/// and over IPv6 that space is 2^128 — which is what makes "it expires in five minutes"
/// insufficient on its own.
fn xor_peer_v6(addr: Ipv6Addr, port: u16, tid: &[u8; 12]) -> Vec<u8> {
    let mut value = vec![0x00, 0x02];
    value.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    let magic = MAGIC_COOKIE.to_be_bytes();
    let octets = addr.octets();
    for i in 0..4 {
        value.push(octets[i] ^ magic[i]);
    }
    for i in 0..12 {
        value.push(octets[4 + i] ^ tid[i]);
    }
    value
}

fn build_message(message_type: u16, tid: &[u8; 12], attributes: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = attributes.concat();
    let mut msg = Vec::with_capacity(20 + body.len());
    msg.extend_from_slice(&message_type.to_be_bytes());
    msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tid);
    msg.extend_from_slice(&body);
    msg
}

type ParsedMessage = (u16, [u8; 12], Vec<(u16, Vec<u8>)>);

fn parse_message(msg: &[u8]) -> ParsedMessage {
    assert!(msg.len() >= 20, "STUN message shorter than a header");
    let message_type = u16::from_be_bytes([msg[0], msg[1]]);
    let mut tid = [0u8; 12];
    tid.copy_from_slice(&msg[8..20]);

    let mut attributes = Vec::new();
    let mut pos = 20;
    while pos + 4 <= msg.len() {
        let attr_type = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let attr_len = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
        let value_end = pos + 4 + attr_len;
        assert!(value_end <= msg.len(), "attribute runs past end of message");
        attributes.push((attr_type, msg[pos + 4..value_end].to_vec()));
        pos = value_end + ((4 - attr_len % 4) % 4);
    }
    (message_type, tid, attributes)
}

fn find_attribute(attributes: &[(u16, Vec<u8>)], attr_type: u16) -> Option<&[u8]> {
    attributes
        .iter()
        .find(|(t, _)| *t == attr_type)
        .map(|(_, v)| v.as_slice())
}

/// STUN error codes are a class byte and a number byte, not a u16 (RFC 8489 section 14.8).
fn error_code(attributes: &[(u16, Vec<u8>)]) -> u16 {
    let value = find_attribute(attributes, ATTR_ERROR_CODE)
        .expect("an error response must carry an ERROR-CODE attribute");
    assert!(value.len() >= 4, "ERROR-CODE attribute too short");
    value[2] as u16 * 100 + value[3] as u16
}

async fn recv_within(socket: &UdpSocket, seconds: u64, what: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(seconds), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => buf[..len].to_vec(),
        Ok(Err(e)) => panic!("socket error while waiting for {what}: {e}"),
        Err(_) => panic!("timed out after {seconds}s waiting for {what}"),
    }
}

/// One CreatePermission naming `count` distinct IPv6 peers, starting at index `first`.
fn create_permission_request(tid: &[u8; 12], first: usize, count: usize) -> Vec<u8> {
    let attributes: Vec<Vec<u8>> = (first..first + count)
        .map(|i| {
            let addr = Ipv6Addr::new(
                0x2001,
                0x0db8,
                0,
                0,
                0,
                0,
                (i >> 16) as u16,
                (i & 0xFFFF) as u16,
            );
            attribute(ATTR_XOR_PEER_ADDRESS, &xor_peer_v6(addr, 9000, tid))
        })
        .collect();
    build_message(CREATE_PERMISSION_REQUEST, tid, &attributes)
}

#[tokio::test]
async fn permissions_past_the_cap_are_refused_with_508_and_no_model_call() -> E2EResult<()> {
    let requests_to_fill = MAX_PERMISSIONS / PEERS_PER_REQUEST;
    assert_eq!(
        requests_to_fill * PEERS_PER_REQUEST,
        MAX_PERMISSIONS,
        "the fixture must land exactly on the cap, or 'at the bound' is not what is tested"
    );

    let config = NetGetConfig::new("Start a TURN relay server on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("server")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TURN",
                    "instruction": "TURN relay server"
                }]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_allocate_response",
                        "relay_address": event["relay_address"],
                        "client_address": event["peer_addr"],
                        "transaction_id": event["transaction_id"],
                        "lifetime_seconds": 600
                    }])
                })
                .expect_calls(1)
                .and()
                // The load-bearing count. Four requests fill the map; the fifth must be
                // refused **without** reaching here. If this ever reads five, the capacity
                // check has moved behind the model and an oversized request buys a prompt.
                .on_event("turn_create_permission_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_create_permission_response",
                        "transaction_id": event["transaction_id"]
                    }])
                })
                .expect_calls(4)
                .and()
        });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;

    // Allocate, so there is a permission map to fill.
    let tid = transaction_id(1);
    let allocate = build_message(
        ALLOCATE_REQUEST,
        &tid,
        &[
            attribute(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]),
            attribute(ATTR_LIFETIME, &600u32.to_be_bytes()),
        ],
    );
    client.send_to(&allocate, server_addr).await?;
    let (message_type, _, _) = parse_message(&recv_within(&client, 15, "allocate response").await);
    assert_eq!(
        message_type, ALLOCATE_SUCCESS,
        "expected Allocate success (0x0103), got 0x{message_type:04x}"
    );

    // Fill the map to exactly MAX_PERMISSIONS, 64 distinct IPv6 peers at a time.
    for request in 0..requests_to_fill {
        let tid = transaction_id(10 + request as u8);
        let msg = create_permission_request(&tid, request * PEERS_PER_REQUEST, PEERS_PER_REQUEST);
        assert!(
            msg.len() <= 2048,
            "the fixture request is {} bytes, past TURN's RELAY_MTU — it would be dropped by \
             the read buffer rather than answered",
            msg.len()
        );
        client.send_to(&msg, server_addr).await?;
        let (message_type, echoed, _) = parse_message(
            &recv_within(&client, 15, "create permission response while filling").await,
        );
        assert_eq!(
            message_type, CREATE_PERMISSION_SUCCESS,
            "request {request} of {requests_to_fill} was refused at 0x{message_type:04x}; \
             filling the map up to and including the cap must succeed, or the refusal below \
             proves nothing"
        );
        assert_eq!(echoed, tid, "transaction id must be echoed");
    }

    // One peer more than the map will hold.
    let over_tid = transaction_id(200);
    client
        .send_to(
            &create_permission_request(&over_tid, MAX_PERMISSIONS, 1),
            server_addr,
        )
        .await?;
    let (message_type, echoed, attributes) =
        parse_message(&recv_within(&client, 15, "the refusal past the cap").await);
    assert_eq!(
        message_type, CREATE_PERMISSION_ERROR,
        "expected a CreatePermission error response (0x0118), got 0x{message_type:04x} — the \
         permission map accepted an entry past its cap"
    );
    assert_eq!(
        echoed, over_tid,
        "transaction id must be echoed on an error"
    );
    assert_eq!(
        error_code(&attributes),
        508,
        "expected 508 Insufficient Capacity, which is what this server already answers when \
         the allocation cap is reached"
    );

    server.wait_for_mocks(10).await;
    server.verify_mocks().await?;
    Ok(())
}
