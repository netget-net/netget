//! End-to-end tests for the HSRP speaker.
//!
//! **The transport really executes here.** Port 1985 is above 1023 and joining a multicast
//! group needs no elevation, so unlike the rest of NetGet's routing/L2 tier there is nothing
//! privileged to mock away: these tests bind a real UDP socket, send real datagrams to it, and
//! assert on the real bytes that come back.
//!
//! What they cannot do is prove interoperability. There is no HSRP crate and no runnable HSRP
//! speaker on this machine, so the peer below is **hand-written from RFC 2281 and Cisco's
//! HSRPv2 documentation**. The root `CLAUDE.md` classes that as an independent *reading* of the
//! spec, not an independent implementation — the same standing as `dhcp`'s in-test RFC 2131
//! decoder. Hence `DevelopmentState::Experimental`; see `tests/server/hsrp/CLAUDE.md`.
//!
//! Every packet is therefore pinned **byte for byte against literal arrays** rather than
//! round-tripped through the server's own codec, which would prove only that the codec agrees
//! with itself. If a field moves, these literals fail.

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// The wire formats, written out by hand from the specifications
// ---------------------------------------------------------------------------

/// HSRPv1 opcodes (RFC 2281 §5).
const OP_HELLO: u8 = 0;
const OP_COUP: u8 = 1;
const OP_RESIGN: u8 = 2;

/// HSRPv1 state codes — a bit-per-state encoding (RFC 2281 §5).
const V1_STATE_INITIAL: u8 = 0;
const V1_STATE_SPEAK: u8 = 4;
const V1_STATE_ACTIVE: u8 = 16;

/// The virtual gateway address used throughout, as it appears on the wire.
const VIP: [u8; 4] = [192, 168, 1, 1];

/// `"cisco"` in the fixed 8-byte authentication field: five ASCII bytes then three NULs.
///
/// This is the notorious Cisco default, and it is **plaintext in every packet** — a
/// misconfiguration guard, not authentication. The padding is asserted explicitly because a
/// space-padded or length-prefixed field is a plausible mistake that no decoder would catch.
const AUTH_CISCO: [u8; 8] = [0x63, 0x69, 0x73, 0x63, 0x6f, 0x00, 0x00, 0x00];

/// Build an HSRPv1 datagram: exactly 20 bytes, laid out field by field per RFC 2281 §5.
///
/// ```text
/// Version | Op Code | State | Hellotime | Holdtime | Priority | Group | Reserved
/// Authentication Data (8 bytes)
/// Virtual IP Address (4 bytes)
/// ```
///
/// Note the Version byte is **0**, not 1 (RFC 2281: "Currently, this is version 0"). Getting
/// that wrong produces a packet no real speaker accepts.
fn v1_packet(
    opcode: u8,
    state: u8,
    hellotime: u8,
    holdtime: u8,
    priority: u8,
    group: u8,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20);
    packet.push(0); // Version
    packet.push(opcode);
    packet.push(state);
    packet.push(hellotime);
    packet.push(holdtime);
    packet.push(priority);
    packet.push(group);
    packet.push(0); // Reserved
    packet.extend_from_slice(&AUTH_CISCO);
    packet.extend_from_slice(&VIP);
    assert_eq!(packet.len(), 20, "an HSRPv1 datagram is exactly 20 bytes");
    packet
}

/// Build an HSRPv2 datagram: a Group State TLV, then a Text Authentication TLV.
///
/// ```text
/// Type=1 Len=40 | Version=2 | Opcode | State | IP Ver | Group(2)
/// Identifier(6) | Priority(4) | Hellotime(4, ms) | Holdtime(4, ms) | Virtual IP(16)
/// Type=3 Len=8  | Authentication text (8)
/// ```
///
/// HSRPv2 is a **completely different encoding** from v1 — nothing about one parses as the
/// other — and its state numbering is dense (`0..=5`) where v1's is a bitmask. Code `4` is
/// therefore **Standby** here and **Speak** in v1, which is the trap both tests below pin from
/// opposite sides.
///
/// The one-field-per-line construction is deliberate and the lints against it are waived: this
/// function's whole job is to be a readable transcription of the specification, so each `push`
/// carries the name of the field it writes. Collapsing the head into a `vec![]` literal, or
/// bundling the arguments into a struct, would hide exactly what a reader comes here to check.
#[allow(clippy::too_many_arguments, clippy::vec_init_then_push)]
fn v2_packet(
    opcode: u8,
    state: u8,
    group: u16,
    identifier: [u8; 6],
    priority: u32,
    hellotime_ms: u32,
    holdtime_ms: u32,
    auth: Option<[u8; 8]>,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(1); // TLV type: Group State
    packet.push(40); // TLV length
    packet.push(2); // Version
    packet.push(opcode);
    packet.push(state);
    packet.push(4); // IP version
    packet.extend_from_slice(&group.to_be_bytes());
    packet.extend_from_slice(&identifier);
    packet.extend_from_slice(&priority.to_be_bytes());
    packet.extend_from_slice(&hellotime_ms.to_be_bytes());
    packet.extend_from_slice(&holdtime_ms.to_be_bytes());
    // The virtual IP field is 16 bytes whatever the family; IPv4 sits in the first four.
    packet.extend_from_slice(&VIP);
    packet.extend_from_slice(&[0u8; 12]);
    assert_eq!(
        packet.len(),
        42,
        "a Group State TLV is 2 header bytes plus 40 of payload"
    );

    if let Some(auth) = auth {
        packet.push(3); // TLV type: Text Authentication
        packet.push(8); // TLV length
        packet.extend_from_slice(&auth);
    }
    packet
}

/// Assert that nothing at all comes back.
///
/// Callers wait for the server's own `decision=` line **first**, so by the time this runs the
/// server has finished deciding: a timeout here means it decided to say nothing, not that it
/// was still thinking.
async fn expect_silence(socket: &UdpSocket, what: &str) -> E2EResult<()> {
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(1500), socket.recv(&mut buf)).await {
        Err(_) => Ok(()),
        Ok(Ok(n)) => Err(format!(
            "{what}: expected NO datagram, got {n} bytes ({}). An HSRP advertisement asserts \
             ownership of the segment's gateway address; one this server was not authorised to \
             send can win an election it cannot serve.",
            hex::encode(&buf[..n])
        )
        .into()),
        Ok(Err(e)) => Err(format!("{what}: socket error while expecting silence: {e}").into()),
    }
}

async fn recv_reply(socket: &UdpSocket, what: &str) -> E2EResult<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| format!("No HSRP reply within 20s for {what}"))??;
    Ok(buf[..n].to_vec())
}

// ---------------------------------------------------------------------------
// Test 1 — HSRPv1: all three events, all four actions
// ---------------------------------------------------------------------------

/// One server, three inbound datagrams, one per event type, exercising every action.
///
/// | in | event | model answers | out |
/// |---|---|---|---|
/// | Hello, `active`, priority 120 | `hsrp_hello_received` | `send_hsrp_hello` `listen`/90 | 20 byte-exact bytes |
/// | Coup, `speak`, priority 200 | `hsrp_coup_received` | `send_hsrp_coup` `active`/250 | 20 byte-exact bytes |
/// | Resign, `initial` | `hsrp_resign_received` | `no_advertisement` | **nothing** |
///
/// The three rules key on distinct event ids, so first-match-wins cannot misroute them.
#[tokio::test]
async fn test_hsrp_v1_handles_hello_coup_and_resign() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via hsrp as an HSRPv1 speaker in group 1";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via hsrp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HSRP",
                    "startup_params": {"version": 1},
                    "instruction": "Speak HSRPv1 in group 1"
                }]))
                .expect_calls(1)
                .and()
                // A neighbour's Hello. The matchers are the assertions that the v1 decoder is
                // right: state code 16 must read as "active" (NOT as v2's numbering, where 16
                // is not a state at all), and the 8-byte NUL-padded auth field must come back
                // as the bare string "cisco".
                .on_event("hsrp_hello_received")
                .and_event_data_contains("state", "active")
                .and_event_data_contains("auth_data", "cisco")
                .and_event_data_contains("virtual_ip", "192.168.1.1")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_hsrp_hello",
                    "version": 1,
                    "state": "listen",
                    "priority": 90,
                    "group": 1,
                    "virtual_ip": "192.168.1.1",
                    "hellotime": 3,
                    "holdtime": 10,
                    "auth_data": "cisco"
                }]))
                .expect_calls(1)
                .and()
                // A Coup raises its OWN event, not hsrp_hello_received. State code 4 must read
                // as "speak" in v1 — the same code means "standby" in v2, which test 2 pins.
                .on_event("hsrp_coup_received")
                .and_event_data_contains("state", "speak")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_hsrp_coup",
                    "version": 1,
                    "state": "active",
                    "priority": 250,
                    "group": 1,
                    "virtual_ip": "192.168.1.1",
                    "hellotime": 3,
                    "holdtime": 10,
                    "auth_data": "cisco"
                }]))
                .expect_calls(1)
                .and()
                // And a Resign raises a third. Answered with deliberate silence.
                .on_event("hsrp_resign_received")
                .respond_with_actions(serde_json::json!([{"type": "no_advertisement"}]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;

    // -----------------------------------------------------------------
    // 1. Hello in -> Hello out, byte for byte.
    // -----------------------------------------------------------------
    socket
        .send(&v1_packet(OP_HELLO, V1_STATE_ACTIVE, 3, 10, 120, 1))
        .await?;

    let reply = recv_reply(&socket, "the neighbour's Hello").await?;
    let expected_hello: [u8; 20] = [
        0x00, // Version: HSRPv1 puts 0 here, not 1
        0x00, // Op Code: Hello
        0x02, // State: Listen (v1 encoding)
        0x03, // Hellotime: 3 seconds
        0x0a, // Holdtime: 10 seconds
        0x5a, // Priority: 90
        0x01, // Group: 1
        0x00, // Reserved
        0x63, 0x69, 0x73, 0x63, 0x6f, 0x00, 0x00, 0x00, // "cisco" NUL-padded to 8
        0xc0, 0xa8, 0x01, 0x01, // Virtual IP 192.168.1.1
    ];
    assert_eq!(
        reply,
        expected_hello.to_vec(),
        "HSRPv1 Hello is not byte-exact. Got {}, expected {}",
        hex::encode(&reply),
        hex::encode(expected_hello)
    );

    // -----------------------------------------------------------------
    // 2. Coup in -> Coup out. The dangerous one: it claims the gateway.
    // -----------------------------------------------------------------
    socket
        .send(&v1_packet(OP_COUP, V1_STATE_SPEAK, 3, 10, 200, 1))
        .await?;

    let reply = recv_reply(&socket, "the neighbour's Coup").await?;
    let expected_coup: [u8; 20] = [
        0x00, // Version
        0x01, // Op Code: Coup
        0x10, // State: Active (16) - this is the byte that claims the gateway
        0x03, 0x0a, //
        0xfa, // Priority: 250
        0x01, 0x00, //
        0x63, 0x69, 0x73, 0x63, 0x6f, 0x00, 0x00, 0x00, //
        0xc0, 0xa8, 0x01, 0x01,
    ];
    assert_eq!(
        reply,
        expected_coup.to_vec(),
        "HSRPv1 Coup is not byte-exact. Got {}, expected {}",
        hex::encode(&reply),
        hex::encode(expected_coup)
    );

    // Claiming the gateway must be loud. An operator should never have to reconstruct this
    // from a packet capture after the segment has already been black-holed.
    server.wait_for_log("claiming the gateway role", 30).await?;

    // -----------------------------------------------------------------
    // 3. Resign in -> nothing out, and the log says the model chose it.
    // -----------------------------------------------------------------
    socket
        .send(&v1_packet(OP_RESIGN, V1_STATE_INITIAL, 3, 10, 200, 1))
        .await?;
    server.wait_for_log("decision=model_silent", 30).await?;
    expect_silence(&socket, "no_advertisement").await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2 — HSRPv2: the other, incompatible wire format
// ---------------------------------------------------------------------------

/// HSRPv2's TLV format, pinned byte for byte, including the state-code collision with v1.
///
/// The inbound packet carries state code **4**. In v1 that is Speak; in v2 it is **Standby**,
/// and the mock rule only matches if the server decoded it as the latter. Together with test
/// 1 — which sends code 4 to a v1 server and requires "speak" — this pins the collision from
/// both directions, which is the failure most likely to pass a round-trip test and still be
/// wrong on a real segment.
#[tokio::test]
async fn test_hsrp_v2_tlv_format_is_byte_exact() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via hsrp as an HSRPv2 speaker in group 1";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via hsrp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HSRP",
                    "startup_params": {"version": 2},
                    "instruction": "Speak HSRPv2 in group 1"
                }]))
                .expect_calls(1)
                .and()
                .on_event("hsrp_hello_received")
                // State code 4 in HSRPv2 is Standby. If the server had used the v1 table it
                // would say "speak" and this rule would never match.
                .and_event_data_contains("state", "standby")
                // The 6-byte identifier is a v2-only field, reported MAC-style.
                .and_event_data_contains("identifier", "00:11:22:33:44:55")
                // v2 carries milliseconds on the wire; 3000ms must be reported as 3 seconds.
                .and_event_data_contains("hellotime", "3")
                // The Text Authentication TLV is a separate TLV in v2, not an inline field.
                .and_event_data_contains("auth_data", "cisco")
                .and_event_data_contains("configured_version", "2")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_hsrp_hello",
                    "version": 2,
                    "state": "listen",
                    "priority": 90,
                    "group": 1,
                    "virtual_ip": "192.168.1.1",
                    "hellotime": 3,
                    "holdtime": 10,
                    "auth_data": "cisco"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;

    socket
        .send(&v2_packet(
            OP_HELLO,
            4, // Standby, in v2's dense numbering
            1,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            100,
            3_000,  // hellotime, milliseconds
            10_000, // holdtime, milliseconds
            Some(AUTH_CISCO),
        ))
        .await?;

    let reply = recv_reply(&socket, "the HSRPv2 Hello").await?;

    let mut expected = Vec::new();
    expected.extend_from_slice(&[
        0x01, // TLV type: Group State
        0x28, // TLV length: 40
        0x02, // Version: 2
        0x00, // Op Code: Hello
        0x02, // State: Listen (v2 encoding)
        0x04, // IP version: 4
        0x00, 0x01, // Group: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Identifier: unset, all zeros
        0x00, 0x00, 0x00, 0x5a, // Priority: 90, four bytes in v2 (one in v1)
        0x00, 0x00, 0x0b, 0xb8, // Hellotime: 3000 ms - v2 is MILLISECONDS
        0x00, 0x00, 0x27, 0x10, // Holdtime: 10000 ms
        0xc0, 0xa8, 0x01, 0x01, // Virtual IP 192.168.1.1 ...
    ]);
    expected.extend_from_slice(&[0u8; 12]); // ... in a 16-byte field
    expected.extend_from_slice(&[
        0x03, // TLV type: Text Authentication
        0x08, // TLV length: 8
        0x63, 0x69, 0x73, 0x63, 0x6f, 0x00, 0x00, 0x00, // "cisco" NUL-padded
    ]);
    assert_eq!(
        expected.len(),
        52,
        "42-byte Group State TLV plus a 10-byte Text Authentication TLV"
    );
    assert_eq!(
        reply,
        expected,
        "HSRPv2 packet is not byte-exact. Got {}, expected {}",
        hex::encode(&reply),
        hex::encode(&expected)
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3 — the assertion that matters most
// ---------------------------------------------------------------------------

/// When the model cannot be reached, the speaker writes **nothing**.
///
/// Most UDP protocols in NetGet answer a backend failure with an error frame, because silence
/// costs the peer its own timeout. HSRP inverts that completely: it has **no negative message
/// at all**, so the only thing that could be sent is a Hello — and a Hello asserts ownership
/// of the segment's gateway address. A fabricated one during an outage can win an election
/// NetGet cannot serve, and every host on the link then sends its off-subnet traffic into a
/// black hole. Silence is strictly safer, and it is also what the protocol expects: a peer
/// that hears nothing simply keeps its own view of the election.
///
/// The failure is forced the same way `tests/server/dns/llm_failure_test.rs` forces it: no
/// mock rule matches the event, so the mock answers HTTP 500 and `call_llm` returns `Err`.
#[tokio::test]
async fn test_hsrp_is_silent_when_the_model_cannot_be_reached() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via hsrp in group 1";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via hsrp")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "HSRP",
                "instruction": "Speak HSRP in group 1"
            }]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for hsrp_hello_received.
    });

    let server = helpers::start_netget_server(server_config).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket
        .send(&v1_packet(OP_HELLO, V1_STATE_ACTIVE, 3, 10, 120, 1))
        .await?;

    // The log is where the distinction lives: `model_silent` (the model looked at the election
    // and stayed out of it) and `fail_closed_llm_error` (the model was never reached) are
    // byte-identical on the wire — both are zero bytes — and conflating them is the OAuth2
    // defect the root CLAUDE.md records. Here it would hide a total backend outage as
    // protocol-correct quiet, indefinitely, because a silent HSRP speaker is entirely normal.
    server
        .wait_for_log("decision=fail_closed_llm_error", 30)
        .await?;
    expect_silence(&socket, "LLM failure").await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
