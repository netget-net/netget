//! MQTT 5.0 on the wire, byte by byte, with Wireshark as the judge.
//!
//! The packets the client side sends here are written out by hand from the OASIS MQTT 5.0
//! specification, so nothing in `src/server/mqtt/` builds both halves of an exchange. Every
//! exchange the broker answers is then handed to the pcap oracle, whose `mqtt` dissector reads
//! the protocol level from the CONNECT and decodes every later property block against it — a
//! property length that disagrees with its properties, or a reason code where 3.1.1 framing was
//! expected, is a Malformed Packet there.
//!
//! What is pinned:
//!
//! - a v5 session: CONNACK with Maximum Packet Size and Topic Alias Maximum, SUBACK with a
//!   property block, a PUBACK carrying reason 0x10, a broker PUBLISH with properties, a PUBLISH
//!   that names only a Topic Alias, and the default UNSUBACK's per-filter reason code;
//! - the refusals a v5 client is told about with DISCONNECT: an undefined alias (0x82), an
//!   alias past the maximum (0x94) and a packet past `max_packet_size` (0x95);
//! - the fail-closed CONNACK: an unreachable backend refuses with 0x88 and a Reason String
//!   naming only the category, and the connection closes;
//! - one PUBLISH fanned out to a 3.1.1 and a v5 subscriber, framed for each.
//!
//! No LLM calls: a Python handler answers, or — for the failure case — nothing can.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; p=e.get('properties') or {}
a=[]
if t=='mqtt_connect':
  a=[{'type':'mqtt_connack','return_code':0}]
elif t=='mqtt_subscribe':
  a=[{'type':'mqtt_suback','packet_id':e['packet_id'],'granted_qos':[x['qos'] for x in e['topics']]}]
elif t=='mqtt_publish':
  if e['topic'].startswith('fan/'):
    for who in ('fan-old','fan-new'):
      a.append({'type':'mqtt_publish','to_client_id':who,'topic':e['topic'],'payload':e['payload'],'content_type':p.get('content_type')})
  else:
    a=[{'type':'mqtt_publish','topic':'echo/'+e['topic'],'payload':e['payload'],'content_type':'text/plain','user_properties':{'n':'1'}}]
    if e['qos']==1: a.append({'type':'mqtt_puback','packet_id':e['packet_id'],'reason_code':16})
print(json.dumps({'actions':a}))"#;

async fn broker(handler: Option<&str>, max_packet_size: Option<u64>) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("MQTT 5 broker".into()),
        event_handlers: handler.map(|code| {
            vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}})]
        }),
        startup_params: max_packet_size.map(|n| json!({ "max_packet_size": n })),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the MQTT broker never bound");
    (state, port)
}

// ---- packets, by hand from the specification ----------------------------------------------

fn varint(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            return out;
        }
    }
}

fn s(text: &str) -> Vec<u8> {
    let mut out = (text.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(text.as_bytes());
    out
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    out.extend(varint(body.len()));
    out.extend_from_slice(body);
    out
}

fn props(p: &[u8]) -> Vec<u8> {
    let mut out = varint(p.len());
    out.extend_from_slice(p);
    out
}

/// CONNECT at `level` (4 or 5), clean start, keep alive 30.
fn connect(level: u8, client_id: &str, v5_props: &[u8]) -> Vec<u8> {
    let mut body = s("MQTT");
    body.extend([level, 0x02, 0x00, 30]);
    if level == 5 {
        body.extend(props(v5_props));
    }
    body.extend(s(client_id));
    packet(0x10, &body)
}

fn publish_v5(qos: u8, packet_id: u16, topic: &str, p: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = s(topic);
    if qos > 0 {
        body.extend(packet_id.to_be_bytes());
    }
    body.extend(props(p));
    body.extend_from_slice(payload);
    packet(0x30 | (qos << 1), &body)
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await.expect("broker closed");
        let mut out = vec![first[0]];
        let mut len = 0usize;
        for i in 0..4 {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await.unwrap();
            out.push(b[0]);
            len |= ((b[0] & 0x7F) as usize) << (7 * i);
            if b[0] & 0x80 == 0 {
                break;
            }
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        out.extend(body);
        out
    })
    .await
    .expect("no packet from the broker")
}

async fn expect_eof(stream: &mut TcpStream) {
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut b))
        .await
        .expect("the broker left the connection open")
        .unwrap_or(0);
    assert_eq!(n, 0, "expected the broker to close, got {:02x?}", &b[..n]);
}

/// The property block of a v5 CONNACK, SUBACK etc. starting at `at`.
fn property_block(packet: &[u8], at: usize) -> &[u8] {
    let len = packet[at] as usize;
    &packet[at + 1..at + 1 + len]
}

#[tokio::test]
async fn a_v5_session_is_framed_as_wireshark_reads_it() {
    let (_state, port) = broker(Some(HANDLER), None).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut oracle = netget_oracle();

    // CONNECT: Session Expiry 60, Receive Maximum 10, User Property ("app", "wire").
    let mut cp = vec![0x11, 0, 0, 0, 60, 0x21, 0, 10, 0x26];
    cp.extend(s("app"));
    cp.extend(s("wire"));
    let hello = connect(5, "wire-v5", &cp);
    c.write_all(&hello).await.unwrap();
    let connack = read_packet(&mut c).await;
    oracle = oracle.to_server(&hello).from_server(&connack);
    assert_eq!(&connack[..1], &[0x20], "{connack:02x?}");
    assert_eq!(
        &connack[2..4],
        &[0x00, 0x00],
        "flags 0, reason Success: {connack:02x?}"
    );
    let cprops = property_block(&connack, 4);
    // Maximum Packet Size = 262144 and Topic Alias Maximum = 16, in that order.
    assert_eq!(cprops, &[0x27, 0, 4, 0, 0, 0x22, 0, 16], "{connack:02x?}");

    // SUBSCRIBE id 1, Subscription Identifier 5, "w/#" at QoS 1 with No Local.
    let mut body = vec![0, 1];
    body.extend(props(&[0x0B, 5]));
    body.extend(s("w/#"));
    body.push(0x05);
    let subscribe = packet(0x82, &body);
    c.write_all(&subscribe).await.unwrap();
    let suback = read_packet(&mut c).await;
    oracle = oracle.to_server(&subscribe).from_server(&suback);
    assert_eq!(
        suback,
        vec![0x90, 4, 0, 1, 0, 1],
        "SUBACK id 1, no properties, QoS 1"
    );

    // PUBLISH QoS 1 id 2 with Content Type and Topic Alias 1: the broker answers with its own
    // PUBLISH (Content Type + User Property) and a PUBACK carrying 0x10.
    let mut pp = vec![0x03];
    pp.extend(s("text/x"));
    pp.extend([0x23, 0, 1]);
    let first = publish_v5(1, 2, "w/a", &pp, b"x");
    c.write_all(&first).await.unwrap();
    let echo = read_packet(&mut c).await;
    let puback = read_packet(&mut c).await;
    oracle = oracle
        .to_server(&first)
        .from_server(&echo)
        .from_server(&puback);
    let mut expect_props = vec![0x03];
    expect_props.extend(s("text/plain"));
    expect_props.push(0x26);
    expect_props.extend(s("n"));
    expect_props.extend(s("1"));
    let mut expect_echo = s("echo/w/a");
    expect_echo.extend(props(&expect_props));
    expect_echo.push(b'x');
    assert_eq!(echo, packet(0x30, &expect_echo), "{echo:02x?}");
    assert_eq!(
        puback,
        vec![0x40, 4, 0, 2, 0x10, 0],
        "PUBACK id 2, 0x10, no properties"
    );

    // PUBLISH QoS 0 naming only the alias: the broker resolves it to w/a.
    let second = publish_v5(0, 0, "", &[0x23, 0, 1], b"y");
    c.write_all(&second).await.unwrap();
    let echo2 = read_packet(&mut c).await;
    oracle = oracle.to_server(&second).from_server(&echo2);
    assert_eq!(&echo2[2..12], &s("echo/w/a")[..], "{echo2:02x?}");
    assert_eq!(echo2.last(), Some(&b'y'));

    // UNSUBSCRIBE with no handler answer: the default UNSUBACK has one 0x00 per filter.
    let mut body = vec![0, 3, 0];
    body.extend(s("w/#"));
    body.extend(s("z/#"));
    let unsubscribe = packet(0xA2, &body);
    c.write_all(&unsubscribe).await.unwrap();
    let unsuback = read_packet(&mut c).await;
    oracle = oracle.to_server(&unsubscribe).from_server(&unsuback);
    assert_eq!(
        unsuback,
        vec![0xB0, 5, 0, 3, 0, 0, 0],
        "UNSUBACK id 3, two 0x00 codes"
    );

    let bye = vec![0xE0, 2, 0x00, 0];
    c.write_all(&bye).await.unwrap();
    expect_eof(&mut c).await;
    oracle.to_server(&bye).assert_clean();
}

fn netget_oracle() -> crate::helpers::pcap_oracle::PcapOracle {
    crate::helpers::pcap_oracle::PcapOracle::tcp("mqtt")
}

#[tokio::test]
async fn v5_protocol_errors_end_with_a_disconnect_that_says_why() {
    let (_state, port) = broker(Some(HANDLER), Some(128)).await;
    let hello = connect(5, "errors-v5", &[]);

    // An alias the connection never defined: 0x82 Protocol Error.
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&hello).await.unwrap();
    let connack = read_packet(&mut c).await;
    let undefined = publish_v5(0, 0, "", &[0x23, 0, 3], b"?");
    c.write_all(&undefined).await.unwrap();
    let disconnect = read_packet(&mut c).await;
    assert_eq!(disconnect, vec![0xE0, 2, 0x82, 0], "{disconnect:02x?}");
    expect_eof(&mut c).await;
    netget_oracle()
        .to_server(&hello)
        .from_server(&connack)
        .to_server(&undefined)
        .from_server(&disconnect)
        .assert_clean();

    // An alias above the advertised maximum of 16: 0x94 Topic Alias Invalid.
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&connect(5, "errors-v5b", &[])).await.unwrap();
    read_packet(&mut c).await;
    c.write_all(&publish_v5(0, 0, "t", &[0x23, 0, 99], b"?"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut c).await, vec![0xE0, 2, 0x94, 0]);
    expect_eof(&mut c).await;

    // A packet past max_packet_size (128 here): 0x95 Packet Too Large, decided from the
    // declared length before the body is read.
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&connect(5, "errors-v5c", &[])).await.unwrap();
    let connack = read_packet(&mut c).await;
    assert_eq!(
        &property_block(&connack, 4)[..5],
        &[0x27, 0, 0, 0, 128],
        "the CONNACK advertises the configured limit: {connack:02x?}"
    );
    c.write_all(&[0x30, 0xC8, 0x01]).await.unwrap();
    assert_eq!(read_packet(&mut c).await, vec![0xE0, 2, 0x95, 0]);
    expect_eof(&mut c).await;
}

#[tokio::test]
async fn an_unreachable_backend_refuses_a_v5_connect_with_server_unavailable() {
    // No handler, and the model endpoint is a closed port: the CONNECT cannot be decided.
    let (_state, port) = broker(None, None).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let hello = connect(5, "outage-v5", &[]);
    c.write_all(&hello).await.unwrap();
    let connack = read_packet(&mut c).await;
    let mut reason = vec![0x1F];
    reason.extend(s("request could not be processed"));
    let mut body = vec![0x00, 0x88];
    body.extend(props(&reason));
    assert_eq!(
        connack,
        packet(0x20, &body),
        "CONNACK 0x88 Server Unavailable with a category-only Reason String, never 0x00: \
         {connack:02x?}"
    );
    expect_eof(&mut c).await;
    netget_oracle()
        .to_server(&hello)
        .from_server(&connack)
        .assert_clean();
}

#[tokio::test]
async fn one_publish_is_framed_for_each_recipient_s_version() {
    let (_state, port) = broker(Some(HANDLER), None).await;

    let mut old = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    old.write_all(&connect(4, "fan-old", &[])).await.unwrap();
    assert_eq!(
        read_packet(&mut old).await,
        vec![0x20, 2, 0, 0],
        "3.1.1 CONNACK"
    );

    let mut new = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    new.write_all(&connect(5, "fan-new", &[])).await.unwrap();
    assert_eq!(read_packet(&mut new).await[3], 0x00, "v5 CONNACK, Success");

    let mut ct = vec![0x03];
    ct.extend(s("application/json"));
    new.write_all(&publish_v5(0, 0, "fan/x", &ct, b"{}"))
        .await
        .unwrap();

    // The 3.1.1 subscriber gets the 3.1.1 layout: no property block at all.
    let mut expect_old = s("fan/x");
    expect_old.extend(b"{}");
    assert_eq!(read_packet(&mut old).await, packet(0x30, &expect_old));

    // The v5 subscriber gets the Content Type the publisher set.
    let mut expect_new = s("fan/x");
    expect_new.extend(props(&ct));
    expect_new.extend(b"{}");
    assert_eq!(read_packet(&mut new).await, packet(0x30, &expect_new));
}
