//! A DNS message whose name-compression pointers chain backwards ~2 000 times, sent to the
//! running server in one UDP datagram.
//!
//! `hickory-proto` 0.24.4 follows a compression pointer by recursing (`rr/domain/name.rs:1203`)
//! and counts nothing, so each two-byte pointer aiming two bytes further back is one more stack
//! frame. Measured: a debug build overflows a 2 MiB tokio worker at 1 702 links — a 3 448-byte
//! message, inside the server's 4 096-byte receive buffer. A stack overflow is not a panic; it
//! aborts the whole process, every other server it runs included.
//!
//! The guard is `netget::utils::dns_screen`, which every DNS decode site in NetGet calls before
//! hickory: it computes the deepest pointer chain any offset could start and refuses the message
//! past `MAX_POINTER_HOPS` (127, the most a 255-octet name can legitimately need). The
//! datagram is dropped and logged, which is how this server treats every unparseable query —
//! and the server goes on answering. Without the guard the legal query after the bomb is never
//! answered, because the process that would answer it is gone.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use netget::utils::dns_screen::{screen_dns_message, MAX_POINTER_HOPS};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Header + a root question + one NULL answer whose RDATA is `links` pointers, each aiming at
/// the one before it, + an additional record whose owner name points at the last link.
///
/// The chain lives in RDATA because hickory never reads a NULL record's RDATA as names; only
/// the additional record's owner name starts the descent.
fn pointer_chain(links: usize) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 1, 0, 0, 0, 1];
    m.push(0); // the question's name: root, at offset 12
    m.extend_from_slice(&[0, 1, 0, 1]);
    m.push(0); // the answer's owner: root
    m.extend_from_slice(&[0, 10, 0, 1, 0, 0, 0, 0]); // NULL, IN, TTL 0
    let rdlength_at = m.len();
    m.extend_from_slice(&[0, 0]);
    let rdata_start = m.len();
    let mut previous = 12u16;
    for _ in 0..links {
        let here = m.len() as u16;
        m.extend_from_slice(&(0xC000 | previous).to_be_bytes());
        previous = here;
    }
    let rdlength = (m.len() - rdata_start) as u16;
    m[rdlength_at..rdlength_at + 2].copy_from_slice(&rdlength.to_be_bytes());
    m.extend_from_slice(&(0xC000 | previous).to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
    m
}

fn a_query(domain: &str, id: u16) -> Vec<u8> {
    let mut message = DnsMessage::new();
    message.set_id(id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);
    message.add_query(Query::query(
        Name::from_str(domain).expect("valid name"),
        RecordType::A,
    ));
    message.to_vec().expect("a query encodes")
}

#[test]
fn the_screen_refuses_exactly_past_the_hop_limit() {
    let at_limit = pointer_chain(usize::from(MAX_POINTER_HOPS) - 1);
    // The owner name's own pointer is one more hop than the chain has links.
    assert!(
        screen_dns_message(&at_limit).is_ok(),
        "a chain of exactly MAX_POINTER_HOPS must pass — a screen refusing every pointer would \
         pass the other half of this test"
    );
    assert!(
        DnsMessage::from_vec(&at_limit).is_ok(),
        "and hickory decodes it, so the screen refuses nothing the decoder handles"
    );
    let reason = screen_dns_message(&pointer_chain(usize::from(MAX_POINTER_HOPS)))
        .expect_err("one hop more must be refused");
    assert!(reason.contains("pointers deep"), "{reason}");

    // Ordinary compression — a response naming the question's name by pointer — passes.
    let mut response = DnsMessage::from_vec(&a_query("www.example.com.", 7)).unwrap();
    response.set_message_type(MessageType::Response);
    response.add_answer(hickory_proto::rr::Record::from_rdata(
        Name::from_str("www.example.com.").unwrap(),
        60,
        hickory_proto::rr::RData::A("192.0.2.1".parse().unwrap()),
    ));
    let bytes = response.to_vec().unwrap();
    assert!(
        bytes.windows(2).any(|w| w == [0xC0, 0x0C]),
        "expected a pointer"
    );
    assert!(screen_dns_message(&bytes).is_ok());

    // Twelve bytes claiming 65 535 answers: hickory would reserve for every one of them.
    let lying = [0, 1, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0];
    assert!(screen_dns_message(&lying).is_err());
}

#[tokio::test]
async fn a_pointer_chain_bomb_is_dropped_and_the_server_keeps_answering() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via dns for a pointer probe")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Pointer probe"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "after.example.com")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "ip": "192.0.2.9",
                        "ttl": 60,
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    server.wait_for_log("DNS server listening on", 20).await?;
    let target: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    let bomb = pointer_chain(2_000);
    assert!(
        bomb.len() <= 4096,
        "the bomb must fit the server's receive buffer"
    );
    socket.send_to(&bomb, target).await?;
    server.wait_for_log("compression chains", 15).await?;

    socket
        .send_to(&a_query("after.example.com.", 0x5151), target)
        .await?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), socket.recv_from(&mut buf))
        .await
        .map_err(|_| {
            "no answer to a legal query after the pointer-chain bomb — the server process died \
             inside hickory's name decoder"
        })??;
    let reply = DnsMessage::from_vec(&buf[..n])?;
    assert_eq!(reply.id(), 0x5151);
    assert_eq!(reply.answers().len(), 1);

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
