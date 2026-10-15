//! `peer_scope=public` stops the relay being pointed at the operator's own network.
//!
//! TURN's whole purpose is forwarding traffic on behalf of a stranger, so its destination set
//! is its blast radius — and there was no destination set. Whatever peer a client named and a
//! policy permitted, the relay socket sent to: `127.0.0.1:8080`, `10.0.0.5:161`,
//! `169.254.169.254`. Combined with no authentication (REALM/NONCE/MESSAGE-INTEGRITY are not
//! implemented), a server whose instruction says "grant allocations" is a UDP path from anyone
//! who can reach the port into whatever the host can reach, with the answers relayed back.
//!
//! The default stays unrestricted on purpose — this protocol exists to be pointed at by things
//! under test, and the suite next door relays between two loopback sockets — so what is asserted
//! here is that the **lever exists and bites**, and that it bites *over* the model rather than
//! through it: the model is told to permit loopback and is overruled.
//!
//! Both gates are covered, because CreatePermission is not the only way to point a relay:
//! ChannelBind grants a permission as a side effect.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const MAGIC_COOKIE: u32 = 0x2112_A442;

const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CHANNEL_BIND_REQUEST: u16 = 0x0009;
const CHANNEL_BIND_ERROR: u16 = 0x0119;
const SEND_INDICATION: u16 = 0x0016;

const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

fn transaction_id(seed: u8) -> [u8; 12] {
    let mut tid = [0u8; 12];
    for (i, byte) in tid.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8).wrapping_mul(11).wrapping_add(3);
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
        panic!("this test only uses IPv4 peers");
    };
    let mut value = vec![0x00, 0x01];
    value.extend_from_slice(&(v4.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    let magic = MAGIC_COOKIE.to_be_bytes();
    for (i, octet) in v4.ip().octets().iter().enumerate() {
        value.push(octet ^ magic[i]);
    }
    value
}

fn message(kind: u16, tid: &[u8; 12], attrs: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = attrs.concat();
    let mut msg = Vec::with_capacity(20 + body.len());
    msg.extend_from_slice(&kind.to_be_bytes());
    msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tid);
    msg.extend_from_slice(&body);
    msg
}

async fn recv_within(socket: &UdpSocket, secs: u64, what: &str) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (n, from) = timeout(Duration::from_secs(secs), socket.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("no {what} within {secs}s"))
        .unwrap_or_else(|e| panic!("recv {what}: {e}"));
    buf.truncate(n);
    (buf, from)
}

fn message_type(msg: &[u8]) -> u16 {
    u16::from_be_bytes([msg[0], msg[1]])
}

/// A TURN server that grants everything the client asks for, including loopback peers.
/// `peer_scope` is the only thing under test, so the policy must be maximally permissive.
fn permissive_turn_server(peer_scope: Option<&str>) -> NetGetConfig {
    let startup_params = match peer_scope {
        Some(scope) => serde_json::json!({ "peer_scope": scope }),
        None => serde_json::json!({}),
    };

    NetGetConfig::new_no_scripts("Start a TURN relay server on port {AVAILABLE_PORT}").with_mock(
        move |mock| {
            mock.on_instruction_containing("TURN relay server")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TURN",
                    "instruction": "Grant every allocation, permission and channel bind.",
                    "startup_params": startup_params
                }]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_turn_allocate_response",
                        "transaction_id": e["transaction_id"],
                        "relay_address": e["relay_address"],
                        "lifetime_seconds": 600
                    }])
                })
                .and()
                // Deliberately permits every peer the request names — loopback
                // included. peer_scope must overrule this, not ask it.
                .on_event("turn_create_permission_request")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_turn_create_permission_response",
                        "transaction_id": e["transaction_id"]
                    }])
                })
                .and()
                .on_event("turn_channel_bind_request")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_turn_channel_bind_response",
                        "transaction_id": e["transaction_id"]
                    }])
                })
                .and()
        },
    )
}

/// Allocate a relay and return nothing but the assurance that it succeeded.
async fn allocate(client: &UdpSocket, server_addr: SocketAddr, seed: u8) {
    let tid = transaction_id(seed);
    client
        .send_to(
            &message(
                ALLOCATE_REQUEST,
                &tid,
                &[attribute(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0])],
            ),
            server_addr,
        )
        .await
        .expect("send allocate");
    let (response, _) = recv_within(client, 10, "allocate response").await;
    assert_eq!(
        message_type(&response),
        ALLOCATE_SUCCESS,
        "the allocation must be granted, or peer_scope is not what this test measures"
    );
}

/// With `peer_scope=public`, a loopback peer is never permitted — however the model answers —
/// so nothing the client sends can reach it.
#[tokio::test]
async fn public_peer_scope_refuses_a_loopback_destination() -> E2EResult<()> {
    let mut server = start_netget_server(permissive_turn_server(Some("public"))).await?;
    server
        .wait_for_log("TURN peer_scope=public", 10)
        .await
        .map_err(|e| format!("the server should announce its peer_scope at startup: {e}"))?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;

    // The victim: a plain UDP socket on loopback, standing in for anything the
    // operator's host can reach but a stranger should not.
    let victim = UdpSocket::bind("127.0.0.1:0").await?;
    let victim_addr = victim.local_addr()?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    allocate(&client, server_addr, 1).await;

    // CreatePermission for the loopback victim. The request is *acknowledged* —
    // RFC 8656 has no per-peer result in the response — but the permission is not
    // installed, which is what the silence below proves.
    let tid = transaction_id(2);
    client
        .send_to(
            &message(
                CREATE_PERMISSION_REQUEST,
                &tid,
                &[attribute(
                    ATTR_XOR_PEER_ADDRESS,
                    &xor_address_value(victim_addr),
                )],
            ),
            server_addr,
        )
        .await?;
    let (response, _) = recv_within(&client, 10, "create permission response").await;
    assert_eq!(message_type(&response), CREATE_PERMISSION_SUCCESS);

    // Now try to relay to it.
    client
        .send_to(
            &message(
                SEND_INDICATION,
                &transaction_id(3),
                &[
                    attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(victim_addr)),
                    attribute(ATTR_DATA, b"reach-the-operators-network"),
                ],
            ),
            server_addr,
        )
        .await?;

    let mut buf = vec![0u8; 2048];
    let arrived = timeout(Duration::from_secs(3), victim.recv_from(&mut buf)).await;
    assert!(
        arrived.is_err(),
        "peer_scope=public must not relay to a loopback address. The victim socket received \
         {:?} — that is a UDP path from a stranger into the operator's own host.",
        arrived.map(|r| r.map(|(n, _)| String::from_utf8_lossy(&buf[..n]).to_string()))
    );

    // ChannelBind is the second way in, and it grants a permission as a side
    // effect. It must be refused outright rather than acknowledged.
    let tid = transaction_id(4);
    client
        .send_to(
            &message(
                CHANNEL_BIND_REQUEST,
                &tid,
                &[
                    attribute(ATTR_CHANNEL_NUMBER, &0x4000u16.to_be_bytes()),
                    attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(victim_addr)),
                ],
            ),
            server_addr,
        )
        .await?;
    let (response, _) = recv_within(&client, 10, "channel bind response").await;
    assert_eq!(
        message_type(&response),
        CHANNEL_BIND_ERROR,
        "a ChannelBind to a loopback peer must be refused under peer_scope=public, got \
         0x{:04x}",
        message_type(&response)
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The default is unrestricted, and that is deliberate. Asserting it means a later change
/// cannot quietly tighten it and leave `metadata().notes` — which says this in as many words —
/// describing a server that no longer exists.
#[tokio::test]
async fn the_default_peer_scope_relays_to_loopback_and_says_so() -> E2EResult<()> {
    let mut server = start_netget_server(permissive_turn_server(None)).await?;
    server
        .wait_for_log("TURN peer_scope=any", 10)
        .await
        .map_err(|e| {
            format!("the unrestricted default must warn at startup, not pass in silence: {e}")
        })?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;

    let victim = UdpSocket::bind("127.0.0.1:0").await?;
    let victim_addr = victim.local_addr()?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    allocate(&client, server_addr, 11).await;

    client
        .send_to(
            &message(
                CREATE_PERMISSION_REQUEST,
                &transaction_id(12),
                &[attribute(
                    ATTR_XOR_PEER_ADDRESS,
                    &xor_address_value(victim_addr),
                )],
            ),
            server_addr,
        )
        .await?;
    let (response, _) = recv_within(&client, 10, "create permission response").await;
    assert_eq!(message_type(&response), CREATE_PERMISSION_SUCCESS);

    client
        .send_to(
            &message(
                SEND_INDICATION,
                &transaction_id(13),
                &[
                    attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(victim_addr)),
                    attribute(ATTR_DATA, b"relayed-by-default"),
                ],
            ),
            server_addr,
        )
        .await?;

    let (payload, _) = recv_within(&victim, 10, "relayed payload").await;
    assert_eq!(
        payload, b"relayed-by-default",
        "the default scope relays to loopback — this is what makes the local e2e suite and \
         honeypot use work, and what metadata().notes warns about"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
