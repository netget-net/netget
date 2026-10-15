//! The TURN client's **receive** path: it must parse a real Allocate Success Response, and it
//! must survive a hostile one.
//!
//! Nothing covered this before. `command_channel_test.rs` proves the client's datagrams reach
//! the wire, but its peer socket never replies, so `parse_turn_header` and the four attribute
//! extractors had no test at all. Two defects lived there because of it:
//!
//! * **The class bits were decoded wrongly** (`((raw & 0x0110) >> 4) | ((raw & 0x0100) >> 7)`
//!   instead of RFC 8489 §5's `C1<<1 | C0`), so every response and indication decoded to 18 or
//!   19 and fell through to "Unknown". A client receives nothing else, so it could not parse a
//!   single reply: `relay_address` was never stored and `turn_allocated`, `turn_refreshed`,
//!   `turn_permission_created` and `turn_data_received` could not fire however correct the
//!   server was.
//! * **Four attribute walks bounded the cursor on the sender's declared length**, not on what
//!   arrived, while indexing a 2048-byte buffer. Twenty bytes —
//!   `00 07 FF FF 21 12 A4 42 <txid>` — panicked. `tokio::spawn` swallows the panic, so the
//!   read loop died silently while `AppState` still reported the client `Connected`.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so every event's call fails
//! and the loop has to tolerate that.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features turn --test client -- turn::response_parsing --test-threads=100

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MAGIC_COOKIE: u32 = 0x2112_A442;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "TURN client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn recv_one(peer: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("no TURN datagram arrived within 5s")
        .expect("recv_from");
    buf.truncate(n);
    (buf, from)
}

/// Build an Allocate Success Response (0x0103) echoing `request`'s transaction ID and
/// carrying XOR-RELAYED-ADDRESS and LIFETIME.
fn allocate_success(request: &[u8], relay: SocketAddr, lifetime: u32) -> Vec<u8> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let std::net::IpAddr::V4(ip) = relay.ip() else {
        panic!("this helper builds IPv4 relays only");
    };
    let octets = ip.octets();

    // XOR-RELAYED-ADDRESS (0x0016): reserved, family, x-port, x-address.
    let mut relayed = vec![0x00, 0x01];
    relayed.extend_from_slice(&(relay.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    for i in 0..4 {
        relayed.push(octets[i] ^ cookie[i]);
    }

    let mut msg = Vec::new();
    msg.extend_from_slice(&0x0103u16.to_be_bytes()); // class 2 (success), method 3 (Allocate)
    msg.extend_from_slice(&0u16.to_be_bytes()); // length, patched below
    msg.extend_from_slice(&cookie);
    msg.extend_from_slice(&request[8..20]); // transaction id, echoed

    msg.extend_from_slice(&0x0016u16.to_be_bytes());
    msg.extend_from_slice(&(relayed.len() as u16).to_be_bytes());
    msg.extend_from_slice(&relayed);

    msg.extend_from_slice(&0x000Du16.to_be_bytes()); // LIFETIME
    msg.extend_from_slice(&4u16.to_be_bytes());
    msg.extend_from_slice(&lifetime.to_be_bytes());

    let body_len = (msg.len() - 20) as u16;
    msg[2..4].copy_from_slice(&body_len.to_be_bytes());
    msg
}

#[tokio::test]
async fn allocate_response_is_parsed_and_hostile_ones_do_not_kill_the_read_loop() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Stand-in for the TURN server.
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client_id = ClientForm {
        protocol: "turn".to_string(),
        remote_addr: Some(peer_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create turn client");

    wait_for_client_handle(&state, client_id).await;

    // --- The hostile datagram first, so everything after it is also proof of survival.
    //
    // Twenty bytes: type 0x0007 (which the *old* class formula decoded as a
    // DataIndication, routing it straight into the attribute walk), a declared
    // attribute length of 0xFFFF, the magic cookie and a transaction id. The walk
    // then indexed data[20] on a 20-byte slice.
    let mut hostile = Vec::with_capacity(20);
    hostile.extend_from_slice(&0x0007u16.to_be_bytes());
    hostile.extend_from_slice(&0xFFFFu16.to_be_bytes());
    hostile.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    hostile.extend_from_slice(&[0xAB; 12]);

    // Find the client's socket by making it speak first, then answer that address.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "allocate_turn_relay", "lifetime_seconds": 600}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client allocate_turn_relay");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected Sent, got {outcome:?}"
    );
    let (allocate_request, client_addr) = recv_one(&peer).await;

    peer.send_to(&hostile, client_addr)
        .await
        .expect("send hostile datagram");

    // A few more shapes that used to reach the same unbounded walk.
    for declared in [0xFFFFu16, 0xFFFCu16, 0x0100u16] {
        let mut probe = Vec::with_capacity(20);
        probe.extend_from_slice(&0x0103u16.to_be_bytes()); // AllocateResponse
        probe.extend_from_slice(&declared.to_be_bytes());
        probe.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        probe.extend_from_slice(&allocate_request[8..20]);
        peer.send_to(&probe, client_addr)
            .await
            .expect("send truncated probe");
    }

    // An attribute whose own length lies about how much follows.
    let mut lying_attr = Vec::new();
    lying_attr.extend_from_slice(&0x0103u16.to_be_bytes());
    lying_attr.extend_from_slice(&8u16.to_be_bytes());
    lying_attr.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    lying_attr.extend_from_slice(&allocate_request[8..20]);
    lying_attr.extend_from_slice(&0x0016u16.to_be_bytes());
    lying_attr.extend_from_slice(&0xFFFFu16.to_be_bytes()); // declares 65535 bytes of value
    peer.send_to(&lying_attr, client_addr)
        .await
        .expect("send lying attribute");

    // --- Now the real thing. If the read loop had died above, `relay_address` would
    // never be set and the wait below would time out — which is exactly how a
    // swallowed panic presents.
    let relay: SocketAddr = "127.0.0.1:50000".parse().unwrap();
    peer.send_to(
        &allocate_success(&allocate_request, relay, 600),
        client_addr,
    )
    .await
    .expect("send allocate success");

    let mut stored = None;
    for _ in 0..500 {
        stored = state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("relay_address")
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
            })
            .await
            .flatten();
        if stored.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        stored.as_deref(),
        Some("127.0.0.1:50000"),
        "the client must decode XOR-RELAYED-ADDRESS out of an Allocate Success Response and \
         record it. If this is None the read loop either could not decode class 2 or died on \
         one of the hostile datagrams above."
    );

    // And it is still able to send, i.e. the client as a whole is alive.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "refresh_allocation", "lifetime_seconds": 600}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client refresh_allocation");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected Sent after the hostile datagrams, got {outcome:?}"
    );
}
