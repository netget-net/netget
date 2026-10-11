//! Who may have a zone, how many connections one host may hold, and what the model may put
//! on the wire — each from a socket.
//!
//! | property | test |
//! |---|---|
//! | `dns_zone_transfer` and `dns_query` carry `client_ip` and `client_port` | `the_events_name_the_client_address` |
//! | `send_dns_zone` over UDP is the SOA alone, however small the zone | `a_full_zone_never_goes_over_udp` |
//! | `MAX_TCP_CONNECTIONS_PER_IP` (8); the next from that address is closed unread | `one_address_cannot_hold_more_than_its_share_of_tcp_connections` |
//! | model bytes that are not a DNS message are SERVFAIL, never sent | `model_bytes_that_are_not_dns_are_answered_servfail` |
//!
//! No model: a script handler answers every event.

use super::zone_support::{DnsDevice, SERIAL};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use netget::server::dns::MAX_TCP_CONNECTIONS_PER_IP;
use serde_json::json;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn query(id: u16, name: &str, rtype: RecordType) -> Message {
    let mut m = Message::new();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .add_query(Query::query(Name::from_str(name).unwrap(), rtype));
    m
}

fn ixfr(id: u16, zone: &str, serial: u32) -> Message {
    let mut m = query(id, zone, RecordType::IXFR);
    let mut soa = Record::with(Name::from_str(zone).unwrap(), RecordType::SOA, 0);
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

/// One UDP exchange from `socket`.
async fn udp(socket: &UdpSocket, port: u16, q: &Message) -> Message {
    socket
        .send_to(&q.to_vec().unwrap(), ("127.0.0.1", port))
        .await
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    Message::from_vec(&buf[..n]).expect("the reply decodes")
}

/// Send one framed query and read `replies` framed messages back.
async fn tcp(stream: &mut TcpStream, q: &Message, replies: usize) -> Vec<Message> {
    let bytes = q.to_vec().unwrap();
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    stream.write_all(&framed).await.unwrap();
    let mut out = Vec::new();
    for _ in 0..replies {
        let len = tokio::time::timeout(Duration::from_secs(15), stream.read_u16())
            .await
            .expect("no TCP reply")
            .unwrap() as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        out.push(Message::from_vec(&buf).expect("a framed reply decodes"));
    }
    out
}

/// The model is told who is asking, so "only to a client they allow" is a decision it can
/// make: the address is in the event data the prompt is built from, which is what the access
/// log records — not only in the log template's enrichment.
#[tokio::test]
async fn the_events_name_the_client_address() {
    let device = DnsDevice::start(None).await;

    let mut stream = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let tcp_port = stream.local_addr().unwrap().port();
    // "Current": the SOA alone, one message.
    let r = tcp(&mut stream, &ixfr(1, "example.com.", SERIAL), 1).await;
    assert_eq!(r[0].answers().len(), 1);
    let r = tcp(&mut stream, &query(2, "www.example.com.", RecordType::A), 1).await;
    assert_eq!(r[0].answers().len(), 1);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = socket.local_addr().unwrap().port();
    let r = udp(
        &socket,
        device.port,
        &query(3, "mail.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r.answers().len(), 1);

    let events = device.events().await;
    let find = |kind: &str, field: &str, value: &str| {
        events
            .iter()
            .find(|(t, e)| t == kind && e[field] == value)
            .map(|(_, e)| e.clone())
            .unwrap_or_else(|| panic!("no {kind} with {field}={value}: {events:?}"))
    };
    let transfer = find("dns_zone_transfer", "zone", "example.com.");
    assert_eq!(transfer["client_ip"], "127.0.0.1", "{transfer}");
    assert_eq!(transfer["client_port"], tcp_port, "{transfer}");
    let tcp_query = find("dns_query", "domain", "www.example.com.");
    assert_eq!(tcp_query["client_ip"], "127.0.0.1", "{tcp_query}");
    assert_eq!(tcp_query["client_port"], tcp_port, "{tcp_query}");
    let udp_query = find("dns_query", "domain", "mail.example.com.");
    assert_eq!(udp_query["client_ip"], "127.0.0.1", "{udp_query}");
    assert_eq!(udp_query["client_port"], udp_port, "{udp_query}");
}

/// Answers every transfer of `small.test.` with the whole three-record zone.
const SMALL_ZONE_HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
SOA={'mname':'ns1.small.test.','rname':'hostmaster.small.test.','serial':7}
if t=='dns_zone_transfer':
    a=[{'type':'send_dns_zone','query_id':e['query_id'],'zone':'small.test.','soa':SOA,
        'records':[{'name':'www','type':'A','ip':'192.0.2.80'}]}]
else: a=[]
print(json.dumps({'actions':a}))"#;

/// A UDP source address can be forged, so a zone sent there goes to whoever was named. The
/// zone here fits 512 bytes many times over; over UDP the answer is still the SOA alone
/// (RFC 1995 §2's "ask again over TCP"), and over TCP the same handler answer is the zone.
///
/// Without the UDP branch in `build_axfr` the UDP answer carries all three records, since
/// the zone fits.
#[tokio::test]
async fn a_full_zone_never_goes_over_udp() {
    let device = DnsDevice::start_with_handler(None, SMALL_ZONE_HANDLER).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let r = udp(&socket, device.port, &ixfr(4, "small.test.", 1)).await;
    assert_eq!(r.response_code(), ResponseCode::NoError);
    let types: Vec<RecordType> = r.answers().iter().map(|a| a.record_type()).collect();
    assert_eq!(types, [RecordType::SOA], "the SOA alone: {r:?}");
    match r.answers()[0].data() {
        Some(RData::SOA(soa)) => assert_eq!(soa.serial(), 7),
        other => panic!("not an SOA: {other:?}"),
    }

    let mut stream = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let r = tcp(&mut stream, &ixfr(5, "small.test.", 1), 1).await;
    let types: Vec<RecordType> = r[0].answers().iter().map(|a| a.record_type()).collect();
    assert_eq!(
        types,
        [RecordType::SOA, RecordType::A, RecordType::SOA],
        "over TCP the zone is sent"
    );
    assert!(device
        .events()
        .await
        .iter()
        .any(|(t, e)| t == "dns_zone_transfer" && e["transport"] == "udp"));
}

/// One host may not hold every TCP slot. Eight connections from 127.0.0.1 are held and
/// served; the ninth is closed unread; releasing one lets a new one in.
///
/// Without the per-source check in `tcp_loop` the ninth connection is admitted and held
/// open, and the read times out.
#[tokio::test]
async fn one_address_cannot_hold_more_than_its_share_of_tcp_connections() {
    let device = DnsDevice::start(Some(json!({"tcp_idle_timeout_secs": 60}))).await;
    let mut held = Vec::new();
    for _ in 0..MAX_TCP_CONNECTIONS_PER_IP {
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
        .expect("the server neither served nor closed the connection past the per-address cap");
    assert!(matches!(read, Ok(0) | Err(_)), "closed unread");

    // Every held connection is still served.
    for (i, stream) in held.iter_mut().enumerate() {
        let r = tcp(
            stream,
            &query(10 + i as u16, "www.example.com.", RecordType::A),
            1,
        )
        .await;
        assert_eq!(r[0].answers().len(), 1, "held connection {i}");
    }

    // Once one is released, the address may open another.
    drop(held.pop());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut fresh = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    let r = tcp(&mut fresh, &query(30, "www.example.com.", RecordType::A), 1).await;
    assert_eq!(r[0].answers().len(), 1);
}

/// `send_dns_response` with bytes that are not a DNS message: a 12-byte header claiming a
/// question it does not carry, and 70 000 bytes claiming 65 535 questions — longer than a
/// UDP datagram and than a TCP length prefix can say.
const RAW_HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='dns_query' and e['domain']=='short.test.': d='004281800001000000000000'
elif t=='dns_query' and e['domain']=='long.test.': d='00428180ffff000000000000'+'00'*70000
else: d=None
print(json.dumps({'actions':[{'type':'send_dns_response','data':d}] if d else []}))"#;

/// The model's hand-assembled bytes are answered SERVFAIL, with the client's own id, when
/// they do not parse. Sent as given, the short answer would reach the client with id 0x0042
/// and no question; the long one would fail `send_to` over UDP (no answer at all) and, over
/// TCP, be framed with `len as u16` — 70 012 announced as 4 476 — and desynchronise the
/// stream.
#[tokio::test]
async fn model_bytes_that_are_not_dns_are_answered_servfail() {
    let device = DnsDevice::start_with_handler(None, RAW_HANDLER).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (id, name) in [(0x1111u16, "short.test."), (0x2222, "long.test.")] {
        let r = udp(&socket, device.port, &query(id, name, RecordType::A)).await;
        assert_eq!(r.id(), id, "{name} over UDP");
        assert_eq!(r.response_code(), ResponseCode::ServFail, "{name} over UDP");
    }

    let mut stream = TcpStream::connect(("127.0.0.1", device.port))
        .await
        .unwrap();
    for (id, name) in [(0x3333u16, "short.test."), (0x4444, "long.test.")] {
        let r = tcp(&mut stream, &query(id, name, RecordType::A), 1).await;
        assert_eq!(r[0].id(), id, "{name} over TCP");
        assert_eq!(
            r[0].response_code(),
            ResponseCode::ServFail,
            "{name} over TCP"
        );
    }
}
