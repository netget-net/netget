//! Every bound TCP, EDNS, zone transfers and DNSSEC added to the DNS server, from a socket.
//!
//! | bound | value | test |
//! |---|---|---|
//! | `MAX_TCP_CONNECTIONS` | 64; the next is closed unread | `the_tcp_connection_cap_…` |
//! | `tcp_idle_timeout_secs` | default `DEFAULT_TCP_IDLE_TIMEOUT` (10 s) | `an_idle_tcp_connection_…` |
//! | `PLAIN_UDP_LIMIT` | 512 without EDNS, then TC | `the_udp_limits_…` |
//! | the client's EDNS size, capped at `MAX_UDP_RESPONSE` | 4096 | `the_udp_limits_…` |
//! | AXFR over UDP | NOTIMP, never asked | `axfr_over_udp_…` |
//! | IXFR over UDP that does not fit | the SOA alone | `an_ixfr_too_large_for_udp_…` |
//! | signed IXFR with changes | SERVFAIL, `fail_closed` | `a_signed_zone_refuses_…` |
//! | `MAX_ANSWER_RECORDS` | 100 | `the_record_count_bounds_…` |
//! | `MAX_ZONE_RECORDS` | 10 000 | `the_record_count_bounds_…` |
//! | `TRANSFER_MESSAGE_BYTES` | ~16 KiB a message | `transfer_messages_stay_near_…` |
//!
//! Queries are built with hickory-proto; what NetGet sends back is read by the pcap oracle
//! (tshark's DNS dissector) as well, over UDP and TCP.

use super::zone_support::{DnsDevice, SERIAL};
use crate::helpers::pcap_oracle::PcapOracle;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use netget::llm::actions::protocol_trait::Server;
use netget::server::dns::actions::MAX_ANSWER_RECORDS;
use netget::server::dns::transfer::{
    split_into_messages, MAX_ZONE_RECORDS, TRANSFER_MESSAGE_BYTES,
};
use netget::server::dns::{MAX_TCP_CONNECTIONS, MAX_UDP_RESPONSE, PLAIN_UDP_LIMIT};
use netget::server::DnsProtocol;
use serde_json::json;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn query(id: u16, name: &str, rtype: RecordType, edns_size: Option<u16>) -> Message {
    let mut m = Message::new();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .add_query(Query::query(Name::from_str(name).unwrap(), rtype));
    if let Some(size) = edns_size {
        let mut e = Edns::new();
        e.set_max_payload(size);
        m.set_edns(e);
    }
    m
}

fn ixfr(id: u16, serial: u32) -> Message {
    let mut m = query(id, "example.com.", RecordType::IXFR, None);
    let mut soa = Record::with(Name::from_str("example.com.").unwrap(), RecordType::SOA, 0);
    soa.set_data(Some(RData::SOA(SOA::new(
        Name::root(),
        Name::root(),
        serial,
        0,
        0,
        0,
        0,
    ))));
    soa.set_dns_class(DNSClass::IN);
    m.add_name_server(soa);
    m
}

/// One UDP exchange, recorded for the oracle.
async fn udp(port: u16, q: &Message, wire: &mut Vec<(bool, Vec<u8>)>) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = q.to_vec().unwrap();
    socket.send_to(&bytes, ("127.0.0.1", port)).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    wire.push((true, bytes));
    wire.push((false, buf[..n].to_vec()));
    Message::from_vec(&buf[..n]).expect("the reply decodes")
}

/// Send one framed query on a TCP stream and read every framed reply until `done`.
async fn tcp_exchange(
    stream: &mut TcpStream,
    q: &Message,
    wire: &mut Vec<(bool, Vec<u8>)>,
    replies: usize,
) -> Vec<Message> {
    let bytes = q.to_vec().unwrap();
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    stream.write_all(&framed).await.unwrap();
    wire.push((true, framed));
    let mut out = Vec::new();
    for _ in 0..replies {
        let len = tokio::time::timeout(Duration::from_secs(15), stream.read_u16())
            .await
            .expect("no TCP reply")
            .unwrap() as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        let mut framed = (len as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&buf);
        wire.push((false, framed));
        out.push(Message::from_vec(&buf).unwrap());
    }
    out
}

fn assert_udp_wire_clean(wire: &[(bool, Vec<u8>)]) {
    let mut oracle = PcapOracle::udp("dns");
    for (to_server, bytes) in wire {
        oracle = if *to_server {
            oracle.to_server(bytes)
        } else {
            oracle.from_server(bytes)
        };
    }
    oracle.assert_clean();
}

fn assert_tcp_wire_clean(wire: &[(bool, Vec<u8>)]) {
    let mut oracle = PcapOracle::tcp("dns");
    for (to_server, bytes) in wire {
        oracle = if *to_server {
            oracle.to_server(bytes)
        } else {
            oracle.from_server(bytes)
        };
    }
    oracle.assert_clean();
}

#[tokio::test]
async fn the_udp_limits_truncate_at_512_and_at_the_clients_size_capped_at_4096() {
    let device = DnsDevice::start(None).await;
    let mut wire = Vec::new();

    // No EDNS: 512. A short answer fits; the eight-string TXT does not and comes back TC with
    // the question alone.
    let r = udp(
        device.port,
        &query(1, "www.example.com.", RecordType::A, None),
        &mut wire,
    )
    .await;
    assert!(!r.truncated());
    assert!(
        r.extensions().is_none(),
        "no OPT for a query without one (RFC 6891 §6.1.1)"
    );
    let r = udp(
        device.port,
        &query(2, "big.example.com.", RecordType::TXT, None),
        &mut wire,
    )
    .await;
    assert!(r.truncated(), "{PLAIN_UDP_LIMIT} bytes without EDNS");
    assert!(r.answers().is_empty());
    assert_eq!(r.queries().len(), 1);

    // EDNS 4096: the same answer (~1.7 KB) fits, with this server's OPT.
    let r = udp(
        device.port,
        &query(3, "big.example.com.", RecordType::TXT, Some(4096)),
        &mut wire,
    )
    .await;
    assert!(!r.truncated());
    assert_eq!(r.answers().len(), 1);
    assert_eq!(r.extensions().as_ref().map(|e| e.max_payload()), Some(1232));
    // EDNS 1000: it does not.
    let r = udp(
        device.port,
        &query(4, "big.example.com.", RecordType::TXT, Some(1000)),
        &mut wire,
    )
    .await;
    assert!(r.truncated());

    // A client asking for 65000 gets MAX_UDP_RESPONSE: the ~6 KB TXT is truncated...
    let r = udp(
        device.port,
        &query(5, "huge.example.com.", RecordType::TXT, Some(65000)),
        &mut wire,
    )
    .await;
    assert!(
        r.truncated(),
        "{MAX_UDP_RESPONSE} is the most a client is believed"
    );
    // ...and arrives whole over TCP.
    let mut stream = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let mut tcp_wire = Vec::new();
    let r = tcp_exchange(
        &mut stream,
        &query(6, "huge.example.com.", RecordType::TXT, None),
        &mut tcp_wire,
        1,
    )
    .await;
    assert!(!r[0].truncated());
    assert_eq!(r[0].answers().len(), 1);
    assert_udp_wire_clean(&wire);
    assert_tcp_wire_clean(&tcp_wire);
}

#[tokio::test]
async fn axfr_over_udp_is_notimp_and_never_reaches_the_handler() {
    let device = DnsDevice::start(None).await;
    let mut wire = Vec::new();
    let r = udp(
        device.port,
        &query(7, "example.com.", RecordType::AXFR, None),
        &mut wire,
    )
    .await;
    assert_eq!(r.response_code(), ResponseCode::NotImp);
    assert!(
        device
            .events()
            .await
            .iter()
            .all(|(t, _)| t != "dns_zone_transfer"),
        "AXFR over UDP is the specification's answer, not the model's"
    );
    assert_udp_wire_clean(&wire);
}

#[tokio::test]
async fn an_ixfr_too_large_for_udp_becomes_the_soa_alone() {
    let device = DnsDevice::start(None).await;
    let mut wire = Vec::new();
    // From the previous serial the difference is six records and fits.
    let r = udp(device.port, &ixfr(8, SERIAL - 1), &mut wire).await;
    assert_eq!(r.answers().len(), 6);
    // From an unknown serial the handler sends the whole zone, which does not fit: the SOA
    // alone tells the client to come back over TCP (RFC 1995 §2).
    let r = udp(device.port, &ixfr(9, 1), &mut wire).await;
    assert_eq!(r.answers().len(), 1);
    assert_eq!(r.answers()[0].record_type(), RecordType::SOA);
    assert_udp_wire_clean(&wire);
}

#[tokio::test]
async fn a_signed_zone_refuses_an_ixfr_difference_and_serves_current() {
    let device = DnsDevice::start(Some(json!({"dnssec_zone": "example.com."}))).await;
    let mut stream = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let mut wire = Vec::new();
    // The handler answers SERIAL-1 with a difference; for a signed zone that would be an
    // unsigned change, so the server fails closed.
    let r = tcp_exchange(&mut stream, &ixfr(10, SERIAL - 1), &mut wire, 1).await;
    assert_eq!(r[0].response_code(), ResponseCode::ServFail);
    // "You are current" carries nothing unsigned and is served.
    let r = tcp_exchange(&mut stream, &ixfr(11, SERIAL), &mut wire, 1).await;
    assert_eq!(r[0].response_code(), ResponseCode::NoError);
    assert_eq!(r[0].answers().len(), 1);
    assert_tcp_wire_clean(&wire);
}

#[tokio::test]
async fn the_tcp_connection_cap_closes_the_next_connection_unread() {
    let device = DnsDevice::start(Some(json!({"tcp_idle_timeout_secs": 60}))).await;
    let mut held = Vec::new();
    for _ in 0..MAX_TCP_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", device.port))
                .await
                .unwrap(),
        );
    }
    // Let the server accept all of them before the one past the cap.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut over = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let mut buf = [0u8; 2];
    let read = tokio::time::timeout(Duration::from_secs(5), over.read(&mut buf))
        .await
        .expect("the server neither served nor closed the connection past the cap");
    assert!(matches!(read, Ok(0) | Err(_)), "closed unread");

    // A held connection is still served, and once one is released a new one is too.
    let mut wire = Vec::new();
    let r = tcp_exchange(
        &mut held[0],
        &query(12, "www.example.com.", RecordType::A, None),
        &mut wire,
        1,
    )
    .await;
    assert_eq!(r[0].answers().len(), 1);
    drop(held.pop());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut fresh = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let r = tcp_exchange(
        &mut fresh,
        &query(13, "www.example.com.", RecordType::A, None),
        &mut wire,
        1,
    )
    .await;
    assert_eq!(r[0].answers().len(), 1);
}

#[tokio::test]
async fn an_idle_tcp_connection_is_closed_after_the_idle_timeout() {
    let device = DnsDevice::start(Some(json!({"tcp_idle_timeout_secs": 1}))).await;
    // Silent from the start: closed after about a second.
    let started = Instant::now();
    let mut silent = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let mut buf = [0u8; 2];
    let read = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf))
        .await
        .expect("an idle connection was never closed");
    assert!(matches!(read, Ok(0) | Err(_)));
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(900),
        "not before the timeout: {waited:?}"
    );

    // A connection that keeps asking outlives the timeout several times over.
    let mut busy = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let mut wire = Vec::new();
    for i in 0..5 {
        let r = tcp_exchange(
            &mut busy,
            &query(20 + i, "www.example.com.", RecordType::A, None),
            &mut wire,
            1,
        )
        .await;
        assert_eq!(
            r[0].answers().len(),
            1,
            "query {i} at {:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
}

#[test]
fn the_record_count_bounds_refuse_one_past_the_limit() {
    let protocol = DnsProtocol::new();
    let records = |n: usize| -> Vec<serde_json::Value> {
        (0..n)
            .map(|i| json!({"type": "A", "ip": format!("10.0.{}.{}", i / 256, i % 256)}))
            .collect()
    };
    let answer = |n: usize| {
        protocol.execute_action(json!({
            "type": "send_dns_records", "query_id": 1, "domain": "x.example.com.",
            "query_type": "A", "answers": records(n)
        }))
    };
    assert!(answer(MAX_ANSWER_RECORDS).is_ok());
    let err = answer(MAX_ANSWER_RECORDS + 1).unwrap_err().to_string();
    assert!(err.contains(&MAX_ANSWER_RECORDS.to_string()), "{err}");

    let zone = |n: usize| {
        protocol.execute_action(json!({
            "type": "send_dns_zone", "query_id": 1, "zone": "example.com.",
            "soa": {"mname": "ns1.example.com.", "rname": "h.example.com.", "serial": 1},
            "records": (0..n).map(|i| json!({"name": format!("h{i}"), "type": "A", "ip": "10.0.0.1"})).collect::<Vec<_>>()
        }))
    };
    // The two SOAs count: MAX_ZONE_RECORDS - 2 other records is the most.
    assert!(zone(MAX_ZONE_RECORDS - 2).is_ok());
    let err = zone(MAX_ZONE_RECORDS - 1)
        .err()
        .expect("one past the limit")
        .to_string();
    assert!(err.contains("at most"), "{err}");
}

#[test]
fn transfer_messages_stay_near_the_target_size() {
    let query = query(1, "example.com.", RecordType::AXFR, None);
    let records: Vec<Record> = (0..3000)
        .map(|i| {
            let mut r = Record::with(
                Name::from_str(&format!("host{i}.example.com.")).unwrap(),
                RecordType::A,
                300,
            );
            r.set_data(Some(RData::A(hickory_proto::rr::rdata::A::new(
                10, 0, 0, 1,
            ))));
            r
        })
        .collect();
    let messages =
        split_into_messages(&query, None, records, TRANSFER_MESSAGE_BYTES, |_| {}).unwrap();
    assert!(messages.len() > 3);
    let total: usize = messages
        .iter()
        .map(|m| Message::from_vec(m).unwrap().answers().len())
        .sum();
    assert_eq!(total, 3000, "every record once");
    for m in &messages {
        // Records are counted uncompressed, so a message lands under the target.
        assert!(m.len() <= TRANSFER_MESSAGE_BYTES, "{} bytes", m.len());
    }
}
