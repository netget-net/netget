//! EDNS(0) Padding (RFC 7830) with RFC 8467's block-length policy, over plain DNS — and the
//! helpers `dot`, `doh` and `doq`'s padding tests share, since all four answer through the same
//! `Reply::finish`.
//!
//! | promise | how it is driven |
//! |---|---|
//! | a query with a Padding option gets a reply padded to a multiple of 468 octets | UDP and TCP, an answer and a SERVFAIL; the pad is zero octets and its length is exactly what reaches the block |
//! | a query without one is not padded | EDNS without Padding (an OPT, no Padding), and no EDNS at all (no OPT) |
//! | the pad never passes the transport | UDP: a 480-octet answer is padded to 936 for a client advertising 1232, sent unpadded to one advertising 512; TCP: a 65 526-octet answer cannot reach 65 988 and is sent unpadded, not refused |
//! | real clients | `kdig +padding` over UDP and TCP reads `PADDING` and a 468-multiple size, and without `+padding` neither; `dig +padding` over TCP the same |
//!
//! Every query is answered by a Python script handler, so no model is reached. Loopback only.

use super::zone_support::{dig, kdig, DnsDevice};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, RecordType};
use netget::server::dns::PADDING_BLOCK;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// The answers every padding test asks for, by name; `query_id` is echoed where the event has
/// one (DoQ's is always zero).
///
/// - `nothing.test`: no sendable action, so SERVFAIL — a reply the server builds itself.
/// - `mid.test`: two TXT records sized so the reply, OPT included, is 480 octets: over one
///   468-octet block, so padding takes it to 936.
/// - `near.test`: one TXT record of 256 strings sized so the reply, OPT included, is 65 526
///   octets: it fits a stream, and the next block (65 988) does not. One record rather than
///   hundreds, because hickory-proto compresses only the first 120 names it writes.
/// - anything else: one A record, 192.0.2.53.
///
/// Both TXT answers are `send_dns_records`, the one multi-record action every transport offers
/// (DoQ refuses `send_dns_response`).
pub const HANDLER: &str = r#"import json,sys
e=json.load(sys.stdin)['event']; d=e['domain'].rstrip('.').lower(); qid=e.get('query_id',0)
def txt(records): return {'type':'send_dns_records','query_id':qid,'domain':e['domain'],'query_type':'A','answers':[{'type':'TXT','ttl':60,'text':r} for r in records]}
if d=='nothing.test': acts=[{'type':'notify_operator','message':'nothing to send'}]
elif d=='mid.test': acts=[txt([['x'*255],['y'*162]])]
elif d=='near.test': acts=[txt([['x'*255]*255+['y'*195]])]
else: acts=[{'type':'send_dns_a_response','query_id':qid,'domain':e['domain'],'ip':'192.0.2.53','ttl':60}]
print(json.dumps({'actions':acts}))"#;

/// The length `near.test`'s reply has, OPT included: no pad can reach a block within 65535.
pub const NEAR_LIMIT_REPLY: usize = 65_526;

/// How a test query asks.
#[derive(Clone, Copy, Debug)]
pub enum Ask {
    /// An OPT carrying a Padding option, the query itself padded to 128 octets (RFC 8467's
    /// client policy), advertising this UDP size.
    Padding(u16),
    /// An OPT without a Padding option.
    EdnsOnly,
    /// No OPT at all.
    NoEdns,
}

/// An A query for `domain`, asking as `ask` says.
pub fn query(domain: &str, id: u16, ask: Ask) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_str(domain).expect("valid name"),
        RecordType::A,
    ));
    match ask {
        Ask::NoEdns => {}
        Ask::EdnsOnly => {
            message.set_edns(edns(1232));
        }
        Ask::Padding(size) => {
            message.set_edns(edns(size));
            let unpadded = message.to_vec().expect("a query encodes").len() + 4;
            let pad = unpadded.div_ceil(128) * 128 - unpadded;
            message
                .edns
                .as_mut()
                .expect("set above")
                .options_mut()
                .insert(EdnsOption::Unknown(
                    u16::from(EdnsCode::Padding),
                    vec![0; pad],
                ));
        }
    }
    message.to_vec().expect("a query encodes")
}

fn edns(size: u16) -> Edns {
    let mut e = Edns::new();
    e.set_max_payload(size);
    e.set_version(0);
    e
}

/// The reply's Padding option, if it has one.
pub fn padding(wire: &[u8]) -> Option<Vec<u8>> {
    let message = Message::from_vec(wire).expect("the reply is a DNS message");
    let option = message.edns.as_ref()?.option(EdnsCode::Padding)?.clone();
    Some(Vec::<u8>::try_from(&option).expect("the option encodes"))
}

/// `wire` is padded to a block: a multiple of 468 octets, its Padding option all zeros and
/// exactly as long as reaching the block took (so no more than one block of padding).
pub fn assert_padded(wire: &[u8], what: &str) {
    let pad = padding(wire).unwrap_or_else(|| panic!("{what}: no Padding option in the reply"));
    assert_eq!(
        wire.len() % PADDING_BLOCK,
        0,
        "{what}: a padded reply of {} octets is not a multiple of {PADDING_BLOCK}",
        wire.len()
    );
    assert!(
        pad.iter().all(|b| *b == 0),
        "{what}: padding octets must be zero (RFC 7830 §3)"
    );
    assert!(
        pad.len() + 4 <= PADDING_BLOCK,
        "{what}: {} octets of padding is more than one block",
        pad.len()
    );
}

/// `wire` carries no Padding option.
pub fn assert_unpadded(wire: &[u8], what: &str) {
    assert_eq!(
        padding(wire),
        None,
        "{what}: a reply was padded that should not have been"
    );
}

/// The A record of a reply.
pub fn a_record(wire: &[u8]) -> Option<String> {
    let message = Message::from_vec(wire).expect("the reply is a DNS message");
    message.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(a.0.to_string()),
        _ => None,
    })
}

pub fn rcode(wire: &[u8]) -> ResponseCode {
    Message::from_vec(wire)
        .expect("the reply is a DNS message")
        .response_code
}

/// The size kdig reports receiving (`;; Received N B`).
pub fn kdig_received(output: &str) -> usize {
    output
        .lines()
        .find_map(|l| l.trim().strip_prefix(";; Received "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no ';; Received N B' line in kdig's output:\n{output}"))
}

/// kdig read a padded reply: it printed the Padding option, and the size it received is a block
/// multiple.
pub fn assert_kdig_padded(output: &str, what: &str) {
    assert!(
        output.contains("192.0.2.53"),
        "{what}: kdig did not read the answer:\n{output}"
    );
    assert!(
        output.contains("PADDING"),
        "{what}: kdig shows no Padding option in the reply:\n{output}"
    );
    let size = kdig_received(output);
    assert_eq!(
        size % PADDING_BLOCK,
        0,
        "{what}: kdig received {size} octets, not a multiple of {PADDING_BLOCK}:\n{output}"
    );
}

/// kdig read an unpadded reply.
pub fn assert_kdig_unpadded(output: &str, what: &str) {
    assert!(
        output.contains("192.0.2.53"),
        "{what}: kdig did not read the answer:\n{output}"
    );
    assert!(
        !output.contains("PADDING"),
        "{what}: kdig shows a Padding option nobody asked for:\n{output}"
    );
}

/// The size dig reports receiving (`;; MSG SIZE  rcvd: N`).
pub fn dig_received(output: &str) -> usize {
    output
        .lines()
        .find_map(|l| l.split("rcvd:").nth(1))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("no 'MSG SIZE rcvd: N' line in dig's output:\n{output}"))
}

/// dig read a padded reply: the answer, and a block-multiple size.
pub fn assert_dig_padded(output: &str, what: &str) {
    assert!(
        output.contains("192.0.2.53"),
        "{what}: dig did not read the answer:\n{output}"
    );
    let size = dig_received(output);
    assert_eq!(
        size % PADDING_BLOCK,
        0,
        "{what}: dig received {size} octets, not a multiple of {PADDING_BLOCK}:\n{output}"
    );
}

async fn udp(port: u16, message: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    socket
        .send_to(message, ("127.0.0.1", port))
        .await
        .expect("send");
    let mut buf = vec![0u8; 65_535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply within 20s")
        .expect("recv");
    buf.truncate(n);
    buf
}

async fn tcp(stream: &mut TcpStream, message: &[u8]) -> Vec<u8> {
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).await.expect("write");
    let len = tokio::time::timeout(Duration::from_secs(20), stream.read_u16())
        .await
        .expect("no TCP reply within 20s")
        .expect("read length");
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await.expect("read reply");
    body
}

#[tokio::test]
async fn udp_replies_are_padded_to_a_block_when_asked_and_never_past_the_clients_size() {
    let dns = DnsDevice::start_with_handler(None, HANDLER).await;

    let reply = udp(dns.port, &query("pad.test", 1, Ask::Padding(1232))).await;
    assert_padded(&reply, "UDP answer");
    assert_eq!(
        reply.len(),
        PADDING_BLOCK,
        "a one-record answer fits one block"
    );
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));

    let reply = udp(dns.port, &query("nothing.test", 2, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_padded(&reply, "UDP SERVFAIL");

    let reply = udp(dns.port, &query("pad.test", 3, Ask::EdnsOnly)).await;
    assert!(
        Message::from_vec(&reply).unwrap().edns.is_some(),
        "an EDNS query gets an OPT"
    );
    assert_unpadded(&reply, "UDP, EDNS without Padding");
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));

    let reply = udp(dns.port, &query("pad.test", 4, Ask::NoEdns)).await;
    assert!(
        Message::from_vec(&reply).unwrap().edns.is_none(),
        "a query without EDNS gets no OPT"
    );

    // The same 480-octet answer: padded to two blocks for a client that takes 1232 octets, and
    // sent as it is to one that takes 512, since 936 would not fit.
    let reply = udp(dns.port, &query("mid.test", 5, Ask::Padding(1232))).await;
    assert_padded(&reply, "UDP, 480-octet answer, 1232-octet client");
    assert_eq!(reply.len(), 2 * PADDING_BLOCK);
    let reply = udp(dns.port, &query("mid.test", 6, Ask::Padding(512))).await;
    assert_unpadded(&reply, "UDP, 480-octet answer, 512-octet client");
    assert_eq!(reply.len(), 480, "the answer is sent whole, unpadded");
    assert_eq!(rcode(&reply), ResponseCode::NoError);
}

#[tokio::test]
async fn tcp_replies_are_padded_when_asked_and_sent_unpadded_when_no_block_fits() {
    let dns = DnsDevice::start_with_handler(None, HANDLER).await;
    let mut stream = TcpStream::connect(("127.0.0.1", dns.port))
        .await
        .expect("connect");

    let reply = tcp(&mut stream, &query("pad.test", 1, Ask::Padding(1232))).await;
    assert_padded(&reply, "TCP answer");
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));

    let reply = tcp(&mut stream, &query("nothing.test", 2, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_padded(&reply, "TCP SERVFAIL");

    let reply = tcp(&mut stream, &query("near.test", 3, Ask::Padding(1232))).await;
    assert_eq!(
        rcode(&reply),
        ResponseCode::NoError,
        "an answer that cannot be padded is still sent"
    );
    assert_unpadded(&reply, "TCP, 65 526-octet answer");
    assert_eq!(reply.len(), NEAR_LIMIT_REPLY);

    let reply = tcp(&mut stream, &query("pad.test", 4, Ask::EdnsOnly)).await;
    assert_unpadded(&reply, "TCP, EDNS without Padding");
    let reply = tcp(&mut stream, &query("pad.test", 5, Ask::NoEdns)).await;
    assert!(Message::from_vec(&reply).unwrap().edns.is_none());
}

#[tokio::test]
async fn kdig_and_dig_read_padded_replies_over_udp_and_tcp() {
    let dns = DnsDevice::start_with_handler(None, HANDLER).await;
    let port = dns.port;

    let out = kdig(port, &["+notcp", "+padding", "pad.test", "A"]).await;
    assert_kdig_padded(&out, "kdig +padding over UDP");
    let out = kdig(port, &["+tcp", "+padding", "pad.test", "A"]).await;
    assert_kdig_padded(&out, "kdig +padding over TCP");
    // Over plain DNS kdig does not pad by default, and then neither does the server.
    let out = kdig(port, &["+notcp", "pad.test", "A"]).await;
    assert_kdig_unpadded(&out, "kdig without +padding over UDP");
    let out = kdig(port, &["+tcp", "pad.test", "A"]).await;
    assert_kdig_unpadded(&out, "kdig without +padding over TCP");

    let out = dig(port, &["+tcp", "+padding=128", "pad.test", "A"]).await;
    assert_dig_padded(&out, "dig +padding=128 over TCP");
    let out = dig(port, &["+tcp", "pad.test", "A"]).await;
    assert!(out.contains("192.0.2.53"), "{out}");
    assert_ne!(
        dig_received(&out) % PADDING_BLOCK,
        0,
        "dig without +padding: an unpadded reply is not a block multiple:\n{out}"
    );
}
