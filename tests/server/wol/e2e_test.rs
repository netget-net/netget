//! End-to-end Wake-on-LAN tests: what the *server* does with a magic packet.
//!
//! The decoder itself is covered exhaustively and for free next door in `decode_test.rs`.
//! What is left, and what needs a real process and a real socket, is the three things only
//! the server can get wrong:
//!
//! 1. the decoded packet reaches the model as an event with the right fields (and a near-miss
//!    reaches it not at all — no event, no LLM call);
//! 2. **nothing is ever sent back**, and the four outcomes that are all silence on the wire —
//!    the model recognised the host, the model dropped it, the model said nothing, the LLM
//!    call failed — are told apart in the log by a `decision=` tag;
//! 3. `announce_host_awake`, the one non-standard escape hatch, is refused unless the operator
//!    turned it on.
//!
//! Every test binds 127.0.0.1 on a high port. Port 9 is the real Wake-on-LAN port and is
//! privileged, so `PrivilegedPort(9)` genuinely fires there — that declaration is protection,
//! not decoration, which is exactly why these tests must not use it.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

const LAB_NAS: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const NEAR_MISS_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];

/// 6 bytes of 0xFF then `mac` sixteen times — the Magic Packet payload, 102 bytes.
fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut out = vec![0xFFu8; 6];
    for _ in 0..16 {
        out.extend_from_slice(&mac);
    }
    out
}

async fn send_datagram(port: u16, payload: &[u8]) -> E2EResult<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(payload, format!("127.0.0.1:{port}")).await?;
    Ok(())
}

/// Five accepted packets covering every decoding shape, and two near-misses that must raise
/// nothing at all.
///
/// The near-misses are sent **first**: the receive loop decodes datagrams sequentially, so by
/// the time the fifth LLM call has landed both of them have already been through the decoder.
/// That is what makes `expect_calls(5)` a real assertion about them rather than a race.
#[tokio::test]
async fn test_wol_decodes_every_magic_packet_shape_and_rejects_near_misses() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via wol. Record every magic packet you see";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // Most specific first. The generator echoes the event's own target_mac back, so
            // an event carrying the wrong MAC would produce a record for the wrong MAC.
            .on_event("wol_magic_packet_received")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "record_wake_request",
                    "target_mac": event["target_mac"].as_str().unwrap_or("missing"),
                    "host": "lab-nas",
                    "note": format!(
                        "transport={} offset={} password_length={}",
                        event["transport"].as_str().unwrap_or("missing"),
                        event["sync_offset"],
                        event["password_length"],
                    ),
                }])
            })
            .expect_calls(5)
            .and()
            .on_instruction_containing("via wol")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "wol",
                    "instruction": "Record every magic packet you see"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let port = server.port;

    // --- near-misses, which must not raise an event -------------------------------------
    // 15 repetitions instead of 16, padded to the full 102 bytes so only the repetition
    // count is wrong.
    let mut fifteen = vec![0xFFu8; 6];
    for _ in 0..15 {
        fifteen.extend_from_slice(&NEAR_MISS_MAC);
    }
    fifteen.extend_from_slice(&[0x00; 6]);
    assert_eq!(fifteen.len(), 102);
    send_datagram(port, &fifteen).await?;

    // A wrong sync stream: 0xFE six times, then a perfectly good 16 repetitions.
    let mut wrong_sync = vec![0xFEu8; 6];
    for _ in 0..16 {
        wrong_sync.extend_from_slice(&NEAR_MISS_MAC);
    }
    send_datagram(port, &wrong_sync).await?;

    // --- five packets that must be accepted ---------------------------------------------
    // 1. bare payload at offset 0
    send_datagram(port, &magic_packet(LAB_NAS)).await?;

    // 2. the same payload 20 bytes into a larger datagram
    let mut offset_20 = vec![0x5Au8; 20];
    offset_20.extend_from_slice(&magic_packet(LAB_NAS));
    send_datagram(port, &offset_20).await?;

    // 3. a 4-byte SecureON password
    let mut password_4 = magic_packet(LAB_NAS);
    password_4.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    send_datagram(port, &password_4).await?;

    // 4. a 6-byte SecureON password
    let mut password_6 = magic_packet(LAB_NAS);
    password_6.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    send_datagram(port, &password_6).await?;

    // 5. the payload inside an encapsulated Ethernet frame (EtherType 0x0842)
    let mut encapsulated = vec![0xFFu8; 6];
    encapsulated.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    encapsulated.extend_from_slice(&[0x08, 0x42]);
    encapsulated.extend_from_slice(&magic_packet(LAB_NAS));
    send_datagram(port, &encapsulated).await?;

    // Waiting on the mocks waits on the exchange: the fifth call is the last thing these
    // datagrams provoke.
    server.wait_for_mocks(30).await;

    for expected in [
        "(offset 0, udp, password_length=0)",
        "(offset 20, udp, password_length=0)",
        "(offset 0, udp, password_length=4)",
        "(offset 0, udp, password_length=6)",
        "(offset 14, ethernet, password_length=0)",
    ] {
        server
            .wait_for_log(expected, 20)
            .await
            .map_err(|e| format!("no magic packet was reported with {expected}: {e}"))?;
    }

    // Every accepted packet named the right MAC, and the model's echo came back with it.
    server
        .wait_for_log_count("00:11:22:33:44:55", 5, 20)
        .await?;

    // The near-misses reached the decoder and were dropped there: no event, so no LLM call
    // (which `expect_calls(5)` asserts) and no mention of their MAC anywhere.
    assert!(
        !server.output_contains("AA:BB:CC:DD:EE:01").await,
        "a near-miss was decoded as a magic packet - 15 repetitions and a 0xFE sync stream \
         are not Wake-on-LAN payloads"
    );
    assert!(
        server.output_contains("not a magic packet").await,
        "the near-misses were dropped without saying so; a silent drop is indistinguishable \
         from the decoder never having seen them"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The four silences, and the log that tells them apart.
///
/// Wake-on-LAN defines no response, so an LLM outage is *correctly* silent here — there is no
/// error frame to send and no peer waiting for one. That makes the log the only place the
/// distinction can live, which is why it is asserted rather than assumed.
///
/// The fourth packet doubles as the gate test: this server was started without
/// `allow_non_standard_ack`, so `announce_host_awake` must be refused and nothing may be sent.
#[tokio::test]
async fn test_wol_is_silent_on_the_wire_but_distinguishes_its_silences_in_the_log() -> E2EResult<()>
{
    let prompt = "listen on port {AVAILABLE_PORT} via wol. Decide about each magic packet";

    // One MAC per outcome, so first-match-wins rules can tell them apart.
    let silent_mac = [0x00, 0x11, 0x22, 0x00, 0x00, 0x01];
    let reject_mac = [0x00, 0x11, 0x22, 0x00, 0x00, 0x02];
    let announce_mac = [0x00, 0x11, 0x22, 0x00, 0x00, 0x03];
    let outage_mac = [0x00, 0x11, 0x22, 0x00, 0x00, 0x04];

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // The model answered, with nothing that decides the packet.
            .on_event("wol_magic_packet_received")
            .and_event_data_contains("target_mac", "00:11:22:00:00:01")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            // The model explicitly dropped it.
            .on_event("wol_magic_packet_received")
            .and_event_data_contains("target_mac", "00:11:22:00:00:02")
            .respond_with_actions(serde_json::json!([
                {"type": "ignore_magic_packet", "reason": "not a host this server manages"}
            ]))
            .expect_calls(1)
            .and()
            // The model asked for the non-standard announcement, which this server forbids.
            .on_event("wol_magic_packet_received")
            .and_event_data_contains("target_mac", "00:11:22:00:00:03")
            .respond_with_actions(serde_json::json!([
                {"type": "announce_host_awake", "target_mac": "00:11:22:00:00:03"}
            ]))
            .expect_calls(1)
            .and()
            // No rule for 00:11:22:00:00:04 - the mock answers 500 and the call fails.
            .on_instruction_containing("via wol")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "wol",
                    "instruction": "Decide about each magic packet"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let port = server.port;

    // One socket for all four, so a reply to any of them would be visible on it.
    //
    // Unconnected, and `recv_from` rather than `recv`, on purpose: a connected socket
    // discards datagrams from any other source address, and `announce_host_awake` sends from
    // an ephemeral port rather than from the server's. Connecting here would make this
    // assertion pass by filtering out exactly the packet it is meant to catch.
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = format!("127.0.0.1:{port}");
    for mac in [silent_mac, reject_mac, announce_mac, outage_mac] {
        socket.send_to(&magic_packet(mac), &server_addr).await?;
    }

    for (mac, decision) in [
        ("00:11:22:00:00:01", "model_silent"),
        ("00:11:22:00:00:02", "model_reject"),
        ("00:11:22:00:00:03", "model_accept"),
        ("00:11:22:00:00:04", "fail_closed_llm_error"),
    ] {
        // Anchored on both ends: the tag alone would not prove it was *this* packet's
        // outcome, and the MAC alone appears on every line about the packet.
        let pattern = regex::Regex::new(&format!("{mac} from \\S+ decision={decision}"))
            .map_err(|e| format!("bad pattern: {e}"))?;
        server
            .wait_for_regex(&pattern, Duration::from_secs(30))
            .await
            .map_err(|e| {
                format!(
                    "the magic packet for {mac} was not logged with decision={decision}. All \
                     four outcomes are silence on the wire, so a log that does not separate \
                     them makes an outage indistinguishable from a deliberate drop: {e}"
                )
            })?;
    }

    // The outage must additionally say which kind of failure it was, so a client-side
    // overload is not recorded as a permanent fault.
    server
        .wait_for_log("decision=fail_closed_llm_error category=", 30)
        .await?;

    // The gate: this server never had allow_non_standard_ack, so the announcement is refused.
    server
        .wait_for_log("refused announce_host_awake", 30)
        .await
        .map_err(|e| {
            format!(
                "announce_host_awake was not refused. It is not part of Wake-on-LAN and must \
                 be off unless the operator asked for it: {e}"
            )
        })?;

    // Nothing at all may come back, for any of the four.
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
        Err(_) => { /* timed out: the only correct outcome */ }
        Ok(Ok((n, _from))) => panic!(
            "the Wake-on-LAN server sent {n} bytes back: {:?}. Wake-on-LAN defines no \
             response - a real NIC wakes its machine and says nothing - so anything on this \
             socket is invented",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => return Err(format!("recv failed: {e}").into()),
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// With `allow_non_standard_ack: true` the announcement is actually sent — back to whoever
/// sent the magic packet, since no `announce_to` was given.
///
/// This is the only path in the protocol that transmits, and it is deliberately not
/// Wake-on-LAN. The test exists so the escape hatch is known to work when asked for, and so
/// the refusal in the test above is known to be the gate rather than a broken send.
#[tokio::test]
async fn test_wol_sends_the_non_standard_announcement_only_when_enabled() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via wol with non-standard announcements on";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_event("wol_magic_packet_received")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "announce_host_awake",
                    "target_mac": "00:11:22:33:44:55",
                    "message": "netget-wol: lab-nas is awake"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via wol")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "wol",
                    "instruction": "Announce hosts awake",
                    "startup_params": {"allow_non_standard_ack": true}
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    // The operator is warned at startup that the server will transmit.
    server
        .wait_for_log("allow_non_standard_ack=true", 20)
        .await
        .map_err(|e| format!("enabling the non-standard path was not announced: {e}"))?;

    // Unconnected: the announcement is sent from an ephemeral socket, not from the server's
    // own port, so a connected socket would filter it out.
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(&magic_packet(LAB_NAS), format!("127.0.0.1:{}", server.port))
        .await?;

    let mut buf = vec![0u8; 2048];
    let n = match tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _from))) => n,
        Ok(Err(e)) => return Err(format!("recv failed: {e}").into()),
        Err(_) => {
            let output = server.get_output().await;
            panic!(
                "no announcement arrived although allow_non_standard_ack was true.\n{}",
                output.join("\n")
            )
        }
    };
    assert_eq!(
        String::from_utf8_lossy(&buf[..n]),
        "netget-wol: lab-nas is awake",
        "the announcement must be the model's own message, verbatim"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
