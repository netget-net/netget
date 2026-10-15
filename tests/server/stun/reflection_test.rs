//! Regression test: the STUN server answers a Binding **Request** and nothing else.
//!
//! Every reply this server sends goes to the source address written in a UDP datagram, which
//! anyone can forge. So the set of messages it is willing to answer is its whole reflection
//! surface, and that set must be exactly "Binding Request".
//!
//! Before this, `parse_stun_header` returned `is_valid` for any datagram carrying the magic
//! cookie — a Binding *Response* included. Two consequences, both reachable by a stranger with
//! one packet:
//!
//! * **A loop.** One spoofed datagram whose source is a second NetGet STUN server sets the two
//!   answering each other's answers, forever; nothing in either side breaks the cycle.
//! * **Amplification.** A 20-byte request draws a 48-byte reply (XOR-MAPPED-ADDRESS plus
//!   SOFTWARE), so a spoofed source makes this a ~2.4x amplifier aimed at whoever the attacker
//!   names.
//!
//! The control case is what gives the silences meaning: a real Binding Request on the same
//! socket must still be answered. Without it "nothing came back" is indistinguishable from a
//! server that was never reachable.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const TRANSACTION_ID: [u8; 12] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
];

/// A 20-byte STUN header with the given message type and declared attribute length.
fn stun_header(message_type: u16, declared_length: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&message_type.to_be_bytes());
    msg.extend_from_slice(&declared_length.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&TRANSACTION_ID);
    msg
}

/// Send `msg` and return the reply, or `None` if the server stayed silent for `secs`.
async fn probe(socket: &UdpSocket, msg: &[u8], secs: u64) -> Option<Vec<u8>> {
    socket.send(msg).await.expect("send probe");
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(secs), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test]
async fn stun_answers_only_binding_requests() -> E2EResult<()> {
    let server_config = NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via stun")
        .with_mock(|mock| {
            mock.on_instruction_containing("via stun")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "STUN",
                        // Empty, so the binding path is purely static and the
                        // silences below cannot be an LLM timeout in disguise.
                        "instruction": ""
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;
    server.wait_for_log("STUN receive loop started", 5).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;

    // Control first: a genuine Binding Request must be answered, so that every
    // "no reply" below is evidence about the message and not about the server.
    let reply = probe(&socket, &stun_header(0x0001, 0), 10)
        .await
        .expect("a Binding Request must still be answered");
    assert_eq!(
        u16::from_be_bytes([reply[0], reply[1]]),
        0x0101,
        "control probe should get a Binding Success Response"
    );

    // A Binding Success Response. Answering this is what makes two of these
    // servers talk to each other until one is restarted.
    assert!(
        probe(&socket, &stun_header(0x0101, 0), 2).await.is_none(),
        "a Binding Success Response must never be answered — that is the reflection loop"
    );

    // A Binding Error Response: same class of mistake.
    assert!(
        probe(&socket, &stun_header(0x0111, 0), 2).await.is_none(),
        "a Binding Error Response must never be answered"
    );

    // A Binding Indication. RFC 8489 section 6.3.2: received and discarded, never replied to.
    assert!(
        probe(&socket, &stun_header(0x0011, 0), 2).await.is_none(),
        "a Binding Indication must never be answered"
    );

    // A request for a method this server does not implement (method 3 = TURN
    // Allocate). Not ours to answer, and answering widens the surface for nothing.
    assert!(
        probe(&socket, &stun_header(0x0003, 0), 2).await.is_none(),
        "a non-Binding method must not be answered by the STUN server"
    );

    // A header declaring more attribute bytes than arrived. The length is the one
    // field an attacker controls for free, and a message we already know is lying
    // is not one to reply to.
    assert!(
        probe(&socket, &stun_header(0x0001, 0xFFFC), 2)
            .await
            .is_none(),
        "a Binding Request whose declared length overruns the datagram must not be answered"
    );

    // RFC 8489 section 5: the length counts attribute bytes and is a multiple of 4.
    let mut unaligned = stun_header(0x0001, 3);
    unaligned.extend_from_slice(&[0u8; 4]);
    assert!(
        probe(&socket, &unaligned, 2).await.is_none(),
        "a Binding Request with a non-multiple-of-4 length must not be answered"
    );

    // The top two bits of a STUN message type are always zero; 0b01 there is a
    // TURN ChannelData frame, which this server must not mistake for STUN.
    let mut channel_data = stun_header(0x4000, 0);
    channel_data[0] = 0x40;
    assert!(
        probe(&socket, &channel_data, 2).await.is_none(),
        "a ChannelData frame must not be answered as STUN"
    );

    // And the server is still alive after all of that — a silence caused by a
    // crashed receive loop would pass every assertion above.
    let reply = probe(&socket, &stun_header(0x0001, 0), 10)
        .await
        .expect("the receive loop must survive every malformed probe");
    assert_eq!(
        u16::from_be_bytes([reply[0], reply[1]]),
        0x0101,
        "the server must still answer a Binding Request at the end"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
