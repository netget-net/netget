//! E2E tests for the TURN relay server.
//!
//! The point of this suite is the relay, not the bookkeeping. A test that only
//! checks NetGet answered an Allocate with a well-formed packet proves nothing:
//! that is exactly what the protocol did while relaying nothing at all. So the
//! headline test puts a **second, ordinary UDP socket** on the other side of
//! the relay address and asserts the payload actually crosses:
//!
//! * peer -> client: the peer sends to the relayed transport address and the
//!   client receives a Data indication carrying those bytes;
//! * client -> peer: the client sends a Send indication and the peer receives
//!   the raw bytes *from the relay address*.
//!
//! Neither direction can pass unless a real socket was bound and real datagrams
//! were forwarded. Requests are encoded and responses decoded here from the RFC
//! 8656 / RFC 8489 wire format (message types are the literal constants from RFC
//! 8656 section 17) rather than by calling NetGet's own encoder.

#![cfg(unix)]

use crate::server::helpers::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Wire format helpers (RFC 8489 / RFC 8656)
// ---------------------------------------------------------------------------

const MAGIC_COOKIE: u32 = 0x2112_A442;

// Message types, RFC 8656 section 17.
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const REFRESH_REQUEST: u16 = 0x0004;
const REFRESH_SUCCESS: u16 = 0x0104;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CHANNEL_BIND_REQUEST: u16 = 0x0009;
const CHANNEL_BIND_SUCCESS: u16 = 0x0109;
const SEND_INDICATION: u16 = 0x0016;
const DATA_INDICATION: u16 = 0x0017;

// Attribute types.
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

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

fn xor_address_value(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = addr else {
        panic!("these tests only use IPv4 peers");
    };
    let mut value = vec![0x00, 0x01];
    value.extend_from_slice(&(v4.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    let magic = MAGIC_COOKIE.to_be_bytes();
    for (i, octet) in v4.ip().octets().iter().enumerate() {
        value.push(octet ^ magic[i]);
    }
    value
}

fn decode_xor_address(value: &[u8]) -> SocketAddr {
    assert!(value.len() >= 8, "XOR address attribute too short");
    assert_eq!(value[1], 0x01, "expected an IPv4 XOR address");
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    let magic = MAGIC_COOKIE.to_be_bytes();
    let mut octets = [0u8; 4];
    for i in 0..4 {
        octets[i] = value[4 + i] ^ magic[i];
    }
    SocketAddr::from((octets, port))
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

/// (message_type, transaction_id, attributes) of a received STUN message.
type ParsedMessage = (u16, [u8; 12], Vec<(u16, Vec<u8>)>);

fn parse_message(msg: &[u8]) -> ParsedMessage {
    assert!(msg.len() >= 20, "STUN message shorter than a header");
    let message_type = u16::from_be_bytes([msg[0], msg[1]]);
    let length = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    assert_eq!(
        u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
        MAGIC_COOKIE,
        "bad magic cookie"
    );
    assert_eq!(
        20 + length,
        msg.len(),
        "declared attribute length {} does not match the {} bytes received",
        length,
        msg.len() - 20
    );

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

fn allocate_request(tid: &[u8; 12], lifetime: u32) -> Vec<u8> {
    build_message(
        ALLOCATE_REQUEST,
        tid,
        &[
            // REQUESTED-TRANSPORT: 17 = UDP
            attribute(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]),
            attribute(ATTR_LIFETIME, &lifetime.to_be_bytes()),
        ],
    )
}

fn create_permission_request(tid: &[u8; 12], peer: SocketAddr) -> Vec<u8> {
    build_message(
        CREATE_PERMISSION_REQUEST,
        tid,
        &[attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(peer))],
    )
}

fn send_indication(tid: &[u8; 12], peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    build_message(
        SEND_INDICATION,
        tid,
        &[
            attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(peer)),
            attribute(ATTR_DATA, payload),
        ],
    )
}

fn channel_bind_request(tid: &[u8; 12], channel: u16, peer: SocketAddr) -> Vec<u8> {
    let mut channel_value = channel.to_be_bytes().to_vec();
    channel_value.extend_from_slice(&[0, 0]); // RFFU
    build_message(
        CHANNEL_BIND_REQUEST,
        tid,
        &[
            attribute(ATTR_CHANNEL_NUMBER, &channel_value),
            attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(peer)),
        ],
    )
}

fn channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&channel.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn recv_within(socket: &UdpSocket, seconds: u64, what: &str) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(seconds), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => (buf[..len].to_vec(), from),
        Ok(Err(e)) => panic!("socket error while waiting for {}: {}", what, e),
        Err(_) => panic!("timed out after {}s waiting for {}", seconds, what),
    }
}

async fn expect_silence(socket: &UdpSocket, millis: u64, what: &str) {
    let mut buf = vec![0u8; 2048];
    if let Ok(Ok((len, from))) =
        tokio::time::timeout(Duration::from_millis(millis), socket.recv_from(&mut buf)).await
    {
        panic!(
            "expected no {} but received {} bytes from {}: {:02x?}",
            what,
            len,
            from,
            &buf[..len.min(64)]
        );
    }
}

/// Allocate a relay through the server and return the relayed transport address.
async fn allocate(
    client: &UdpSocket,
    server_addr: SocketAddr,
    seed: u8,
    lifetime: u32,
) -> SocketAddr {
    let tid = transaction_id(seed);
    client
        .send_to(&allocate_request(&tid, lifetime), server_addr)
        .await
        .expect("send allocate request");

    let (response, _) = recv_within(client, 10, "allocate response").await;
    let (message_type, response_tid, attributes) = parse_message(&response);
    assert_eq!(
        message_type, ALLOCATE_SUCCESS,
        "expected Allocate success (0x0103), got 0x{:04x}",
        message_type
    );
    assert_eq!(response_tid, tid, "transaction ID must be echoed");

    let relayed = find_attribute(&attributes, ATTR_XOR_RELAYED_ADDRESS)
        .expect("Allocate success must carry XOR-RELAYED-ADDRESS");

    // The address must really be XOR-ed with the magic cookie: an
    // implementation that forgot would still round-trip through this test's own
    // decoder. 127.0.0.1 XOR 0x2112A442 = 5E 12 A4 43 (RFC 8489 section 14.2).
    assert_eq!(
        &relayed[4..8],
        &[0x5E, 0x12, 0xA4, 0x43],
        "XOR-RELAYED-ADDRESS is not XOR-ed with the magic cookie"
    );

    let relay_addr = decode_xor_address(relayed);
    assert_eq!(
        relay_addr.ip().to_string(),
        "127.0.0.1",
        "relay should be advertised on the server's own address"
    );
    assert_ne!(relay_addr.port(), 0, "relay port must be a bound port");
    assert_ne!(
        relay_addr.port(),
        server_addr.port(),
        "the relay must be its own socket, not the TURN listener"
    );

    let lifetime_attr =
        find_attribute(&attributes, ATTR_LIFETIME).expect("Allocate success must carry LIFETIME");
    assert_eq!(lifetime_attr.len(), 4, "LIFETIME must be 4 bytes");

    relay_addr
}

async fn create_permission(
    client: &UdpSocket,
    server_addr: SocketAddr,
    seed: u8,
    peer: SocketAddr,
) {
    let tid = transaction_id(seed);
    client
        .send_to(&create_permission_request(&tid, peer), server_addr)
        .await
        .expect("send create permission request");

    let (response, _) = recv_within(client, 10, "create permission response").await;
    let (message_type, response_tid, _) = parse_message(&response);
    assert_eq!(
        message_type, CREATE_PERMISSION_SUCCESS,
        "expected CreatePermission success (0x0108), got 0x{:04x}",
        message_type
    );
    assert_eq!(response_tid, tid, "transaction ID must be echoed");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The test that separates a relay from a pretend relay: bytes cross between two
/// independent UDP sockets, in both directions, through the allocation.
#[tokio::test]
async fn test_turn_relays_payload_between_two_peers() -> E2EResult<()> {
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
                        // The relay address is NetGet's, not the model's.
                        "relay_address": event["relay_address"],
                        "client_address": event["peer_addr"],
                        "transaction_id": event["transaction_id"],
                        "lifetime_seconds": 600
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("turn_create_permission_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_create_permission_response",
                        "transaction_id": event["transaction_id"]
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;

    let relay_addr = allocate(&client, server_addr, 1, 600).await;

    // Before any permission exists, peer traffic is dropped rather than
    // relayed. (This has to be checked *before* CreatePermission: RFC 8656
    // permissions match on IP address only, so on loopback a second socket is
    // indistinguishable from the permitted one.)
    peer.send_to(b"too early", relay_addr).await?;
    expect_silence(&client, 1000, "relayed traffic from an unpermitted peer").await;

    create_permission(&client, server_addr, 2, peer_addr).await;

    // --- peer -> client -------------------------------------------------
    let from_peer = b"payload from the peer";
    peer.send_to(from_peer, relay_addr).await?;

    let (indication, from) = recv_within(&client, 10, "data indication").await;
    assert_eq!(
        from, server_addr,
        "data indications arrive on the TURN 5-tuple"
    );
    let (message_type, _, attributes) = parse_message(&indication);
    assert_eq!(
        message_type, DATA_INDICATION,
        "expected a Data indication (0x0017), got 0x{:04x}",
        message_type
    );
    let echoed_peer = decode_xor_address(
        find_attribute(&attributes, ATTR_XOR_PEER_ADDRESS)
            .expect("Data indication must carry XOR-PEER-ADDRESS"),
    );
    assert_eq!(
        echoed_peer, peer_addr,
        "Data indication must name the peer that sent the datagram"
    );
    assert_eq!(
        find_attribute(&attributes, ATTR_DATA).expect("Data indication must carry DATA"),
        from_peer,
        "relayed payload was altered"
    );

    // --- client -> peer -------------------------------------------------
    let from_client = b"payload from the client";
    client
        .send_to(
            &send_indication(&transaction_id(3), peer_addr, from_client),
            server_addr,
        )
        .await?;

    let (relayed, relayed_from) = recv_within(&peer, 10, "relayed payload at the peer").await;
    assert_eq!(
        relayed, from_client,
        "peer received something other than the client's payload"
    );
    assert_eq!(
        relayed_from, relay_addr,
        "peer must see the traffic coming from the relay address, not the client"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}

/// Channel bindings: the same relay, framed as ChannelData in both directions.
#[tokio::test]
async fn test_turn_relays_over_a_bound_channel() -> E2EResult<()> {
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
                        "transaction_id": event["transaction_id"],
                        "lifetime_seconds": 600
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("turn_channel_bind_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_channel_bind_response",
                        "transaction_id": event["transaction_id"]
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;

    let relay_addr = allocate(&client, server_addr, 11, 600).await;

    // Bind channel 0x4001 to the peer. A channel bind also permits the peer,
    // so no CreatePermission is needed.
    let channel = 0x4001u16;
    let tid = transaction_id(12);
    client
        .send_to(&channel_bind_request(&tid, channel, peer_addr), server_addr)
        .await?;
    let (response, _) = recv_within(&client, 10, "channel bind response").await;
    let (message_type, response_tid, _) = parse_message(&response);
    assert_eq!(
        message_type, CHANNEL_BIND_SUCCESS,
        "expected ChannelBind success (0x0109), got 0x{:04x}",
        message_type
    );
    assert_eq!(response_tid, tid, "transaction ID must be echoed");

    // --- peer -> client, framed as ChannelData ---------------------------
    let from_peer = b"channelled from the peer";
    peer.send_to(from_peer, relay_addr).await?;

    let (frame, _) = recv_within(&client, 10, "channel data").await;
    assert!(frame.len() >= 4, "ChannelData frame is too short");
    assert_eq!(
        u16::from_be_bytes([frame[0], frame[1]]),
        channel,
        "ChannelData carries the bound channel number"
    );
    let length = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    assert_eq!(&frame[4..4 + length], from_peer, "relayed payload altered");

    // --- client -> peer, framed as ChannelData ---------------------------
    let from_client = b"channelled from the client";
    client
        .send_to(&channel_data(channel, from_client), server_addr)
        .await?;

    let (relayed, relayed_from) = recv_within(&peer, 10, "relayed channel payload").await;
    assert_eq!(relayed, from_client, "peer received the wrong payload");
    assert_eq!(
        relayed_from, relay_addr,
        "channelled traffic must leave from the relay address"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}

/// An allocation stops relaying when its lifetime runs out, not when the
/// 30-second cleanup tick happens to notice.
#[tokio::test]
async fn test_turn_stops_relaying_after_the_lifetime_expires() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a TURN relay server on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("server")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TURN",
                    "instruction": "TURN relay server with short allocations"
                }]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_allocate_response",
                        "relay_address": event["relay_address"],
                        "transaction_id": event["transaction_id"],
                        "lifetime_seconds": 5
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("turn_create_permission_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_create_permission_response",
                        "transaction_id": event["transaction_id"]
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;

    let relay_addr = allocate(&client, server_addr, 21, 5).await;
    create_permission(&client, server_addr, 22, peer_addr).await;

    // While the allocation is live the relay works.
    peer.send_to(b"before expiry", relay_addr).await?;
    let (indication, _) = recv_within(&client, 4, "data indication before expiry").await;
    let (message_type, _, attributes) = parse_message(&indication);
    assert_eq!(message_type, DATA_INDICATION);
    assert_eq!(
        find_attribute(&attributes, ATTR_DATA).expect("DATA attribute"),
        b"before expiry"
    );

    // After it expires nothing is relayed, well before the cleanup tick.
    tokio::time::sleep(Duration::from_secs(6)).await;
    peer.send_to(b"after expiry", relay_addr).await?;
    expect_silence(
        &client,
        1500,
        "relayed traffic after the allocation expired",
    )
    .await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}

/// A relay address the model invented is refused rather than confirmed: handing
/// a client an address nobody listens on is the failure this protocol shipped
/// with for its whole existence. Also checks that a datagram with a bad magic
/// cookie is dropped silently.
#[tokio::test]
async fn test_turn_refuses_an_invented_relay_address() -> E2EResult<()> {
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
                        // Not the reserved socket: nothing listens here.
                        "relay_address": "203.0.113.100:55000",
                        "transaction_id": event["transaction_id"],
                        "lifetime_seconds": 600
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;

    let tid = transaction_id(31);
    client
        .send_to(&allocate_request(&tid, 600), server_addr)
        .await?;

    let (response, _) = recv_within(&client, 10, "allocate error response").await;
    let (message_type, response_tid, attributes) = parse_message(&response);
    assert_eq!(
        message_type, ALLOCATE_ERROR,
        "an unusable relay address must produce an Allocate error (0x0113), got 0x{:04x}",
        message_type
    );
    assert_eq!(response_tid, tid, "transaction ID must be echoed");

    let error = find_attribute(&attributes, ATTR_ERROR_CODE).expect("ERROR-CODE attribute");
    assert!(error.len() >= 4, "ERROR-CODE too short");
    assert_eq!(
        (error[2] as u16) * 100 + error[3] as u16,
        508,
        "expected 508 Insufficient Capacity"
    );
    assert!(
        find_attribute(&attributes, ATTR_XOR_RELAYED_ADDRESS).is_none(),
        "a refused allocation must not hand out a relay address"
    );

    // A datagram that is not STUN at all is dropped without a reply.
    let mut bogus = allocate_request(&transaction_id(32), 600);
    bogus[4] = 0xDE;
    bogus[5] = 0xAD;
    bogus[6] = 0xBE;
    bogus[7] = 0xEF;
    client.send_to(&bogus, server_addr).await?;
    expect_silence(&client, 1000, "a reply to a bad magic cookie").await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}

/// The model's refusal reaches the client as a TURN error, and a Refresh it
/// grants comes back with the lifetime it chose.
#[tokio::test]
async fn test_turn_denied_allocation_and_refresh() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a TURN relay server on port 0 that rejects allocations")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("server")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TURN",
                    "instruction": "TURN relay server that refuses allocations"
                }]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_error_response",
                        "error_code": 486,
                        "reason": "Allocation Quota Reached",
                        "method": "allocate",
                        "transaction_id": event["transaction_id"]
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("turn_refresh_request")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_turn_refresh_response",
                        "transaction_id": event["transaction_id"],
                        "lifetime_seconds": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;

    // --- refusal ---------------------------------------------------------
    let tid = transaction_id(41);
    client
        .send_to(&allocate_request(&tid, 600), server_addr)
        .await?;
    let (response, _) = recv_within(&client, 10, "allocate error response").await;
    let (message_type, response_tid, attributes) = parse_message(&response);
    assert_eq!(
        message_type, ALLOCATE_ERROR,
        "expected an Allocate error (0x0113), got 0x{:04x}",
        message_type
    );
    assert_eq!(response_tid, tid);
    let error = find_attribute(&attributes, ATTR_ERROR_CODE).expect("ERROR-CODE attribute");
    assert_eq!((error[2] as u16) * 100 + error[3] as u16, 486);

    // Nothing was allocated, so a Send indication cannot be relayed anywhere.
    let stranger = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(
            &send_indication(&transaction_id(42), stranger.local_addr()?, b"nope"),
            server_addr,
        )
        .await?;
    expect_silence(&stranger, 1000, "traffic relayed without an allocation").await;

    // --- refresh ---------------------------------------------------------
    let tid = transaction_id(43);
    client
        .send_to(
            &build_message(
                REFRESH_REQUEST,
                &tid,
                &[attribute(ATTR_LIFETIME, &300u32.to_be_bytes())],
            ),
            server_addr,
        )
        .await?;
    let (response, _) = recv_within(&client, 10, "refresh response").await;
    let (message_type, response_tid, attributes) = parse_message(&response);
    assert_eq!(
        message_type, REFRESH_SUCCESS,
        "expected a Refresh success (0x0104), got 0x{:04x}",
        message_type
    );
    assert_eq!(response_tid, tid);
    let lifetime = find_attribute(&attributes, ATTR_LIFETIME).expect("LIFETIME attribute");
    assert_eq!(
        u32::from_be_bytes([lifetime[0], lifetime[1], lifetime[2], lifetime[3]]),
        300,
        "refresh must report the lifetime the model granted"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}
