//! The MUSTs of MQTT 3.1.1 and 5.0 a broker enforces on what a client sends, and the packet
//! size bound on both sides of its number — each refusal beside a control that differs only in
//! the rule under test, so the refusal cannot come from something else in the packet.
//!
//! | Rule | Control | Refused |
//! |---|---|---|
//! | first packet is CONNECT [MQTT-3.1.0-1] | CONNECT then PINGREQ | PINGREQ first: closed |
//! | protocol name and level [MQTT-3.1.2-1/2] | `MQTT` 4, `MQTT` 5, `MQIsdp` 3 | level 6: CONNACK 1, closed |
//! | reserved CONNECT flag [MQTT-3.1.2-3] | flag clear | flag set: closed |
//! | empty client id needs clean session (3.1.1) [MQTT-3.1.3-8] | clean session 1 | clean session 0: CONNACK 2 |
//! | non-zero packet identifier [MQTT-2.3.1-1] | id 1 | id 0 on PUBLISH QoS 1, SUBSCRIBE, UNSUBSCRIBE: closed |
//! | well-formed UTF-8, no U+0000 [MQTT-1.5.3-1/2] | `a/b` | `a/\xff`, `a\0b`: closed |
//! | no wildcard in a topic name [MQTT-3.3.2-2] | `a/b` | `a/+`, `a/#`: closed (v5: DISCONNECT 0x90) |
//! | topic filter syntax [MQTT-4.7.1-2/3] | `a/+/b`, `a/#`, `#` | `a/b#`, `a+/b`, `a/#/b`, empty: closed (v5: 0x8F) |
//! | requested QoS byte (3.1.1) [MQTT-3.8.3-4] | QoS 2 | QoS 3, reserved bits: closed |
//! | fixed-header flags [MQTT-2.2.2-2] | SUBSCRIBE `0x82` | SUBSCRIBE `0x80`: closed |
//! | `max_packet_size`, whole packet | exactly the limit | one byte more: closed (v5: 0x95) |
//! | its 64-byte floor | a 64-byte packet under `max_packet_size: 1` | 65 bytes: closed |
//! | its 16 MiB ceiling | — | a declared 16 MiB + 1 under `max_packet_size: 1 GiB`: closed from the header |
//! | the remaining-length varint's 4 bytes | 4 bytes | a 5th continuation byte: closed |
//! | the client's Maximum Packet Size (v5) | a broker PUBLISH of exactly it reaches the client | one byte more is not sent |
//! | one connection per client id [MQTT-3.1.4-2] | — | a second accepted CONNECT closes the first (v5: DISCONNECT 0x8E); a refused one does not |
//!
//! No LLM calls: a Python handler answers, and the model endpoint is a closed port.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Accepts every CONNECT except one with the user name `bad`, grants every subscription, and
/// answers a PUBLISH to `send/<n>` by publishing `n` payload bytes back to the publisher, or to
/// `to/<client>` by publishing it to that client.
const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='mqtt_connect':
  a=[{'type':'mqtt_connack','return_code':5 if e.get('username')=='bad' else 0}]
elif t=='mqtt_subscribe':
  a=[{'type':'mqtt_suback','packet_id':e['packet_id'],'granted_qos':[x['qos'] for x in e['topics']]}]
elif t=='mqtt_unsubscribe':
  a=[{'type':'mqtt_unsuback','packet_id':e['packet_id']}]
elif t=='mqtt_publish':
  top=e['topic']
  if top.startswith('send/'): a=[{'type':'mqtt_publish','topic':'r','payload':'x'*int(top[5:])}]
  elif top.startswith('to/'): a=[{'type':'mqtt_publish','to_client_id':top[3:],'topic':'r','payload':e['payload']}]
  if e['qos']==1: a.append({'type':'mqtt_puback','packet_id':e['packet_id']})
print(json.dumps({'actions':a}))"#;

async fn broker(params: serde_json::Value) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        startup_params: Some(params),
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
    (state, id, port)
}

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

fn s(text: &[u8]) -> Vec<u8> {
    let mut out = (text.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(text);
    out
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    out.extend(varint(body.len()));
    out.extend_from_slice(body);
    out
}

fn connect_with(name: &str, level: u8, flags: u8, client_id: &str, v5_props: &[u8]) -> Vec<u8> {
    let mut body = s(name.as_bytes());
    body.extend([level, flags, 0x00, 30]);
    if level == 5 {
        body.extend(varint(v5_props.len()));
        body.extend_from_slice(v5_props);
    }
    body.extend(s(client_id.as_bytes()));
    packet(0x10, &body)
}

fn connect(level: u8, client_id: &str) -> Vec<u8> {
    connect_with("MQTT", level, 0x02, client_id, &[])
}

fn publish(v5: bool, qos: u8, packet_id: u16, topic: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = s(topic);
    if qos > 0 {
        body.extend(packet_id.to_be_bytes());
    }
    if v5 {
        body.push(0);
    }
    body.extend_from_slice(payload);
    packet(0x30 | (qos << 1), &body)
}

fn subscribe(first: u8, packet_id: u16, filter: &[u8], options: u8) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend(s(filter));
    body.push(options);
    packet(first, &body)
}

fn unsubscribe(packet_id: u16, filter: &[u8]) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend(s(filter));
    packet(0xA2, &body)
}

async fn read_packet(stream: &mut TcpStream) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await.ok()?;
        let mut out = vec![first[0]];
        let mut len = 0usize;
        for i in 0..4 {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await.ok()?;
            out.push(b[0]);
            len |= ((b[0] & 0x7F) as usize) << (7 * i);
            if b[0] & 0x80 == 0 {
                break;
            }
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.ok()?;
        out.extend(body);
        Some(out)
    })
    .await
    .expect("the broker neither answered nor closed")
}

/// The broker closes, after at most a v5 DISCONNECT carrying `v5_reason`.
async fn expect_closed(stream: &mut TcpStream, v5_reason: Option<u8>) {
    if let Some(reason) = v5_reason {
        assert_eq!(
            read_packet(stream).await,
            Some(vec![0xE0, 2, reason, 0]),
            "a v5 client is told why"
        );
    }
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut b))
        .await
        .expect("the broker left the connection open")
        .unwrap_or(0);
    assert_eq!(n, 0, "expected the broker to close, got {:02x?}", &b[..n]);
}

/// A connection that sent `connect` and read an accepting CONNACK.
async fn session(port: u16, connect: &[u8]) -> TcpStream {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(connect).await.unwrap();
    let connack = read_packet(&mut c).await.expect("no CONNACK");
    assert_eq!(connack[0], 0x20, "{connack:02x?}");
    assert_eq!(connack[3], 0, "the CONNECT was refused: {connack:02x?}");
    c
}

async fn active_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| c.status == netget::state::server::ConnectionStatus::Active)
                .count()
        })
        .unwrap_or(0)
}

async fn ping_answered(c: &mut TcpStream) {
    c.write_all(&[0xC0, 0x00]).await.unwrap();
    assert_eq!(read_packet(c).await, Some(vec![0xD0, 0x00]));
}

#[tokio::test]
async fn the_first_packet_must_be_connect() {
    let (_s, _id, port) = broker(json!({})).await;
    let mut c = session(port, &connect(4, "first")).await;
    ping_answered(&mut c).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&[0xC0, 0x00]).await.unwrap();
    expect_closed(&mut c, None).await;
}

#[tokio::test]
async fn an_unknown_protocol_level_gets_connack_1_and_a_reserved_flag_closes() {
    let (_s, _id, port) = broker(json!({})).await;
    session(port, &connect(4, "lvl4")).await;
    session(port, &connect(5, "lvl5")).await;
    session(port, &connect_with("MQIsdp", 3, 0x02, "lvl3", &[])).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&connect_with("MQTT", 6, 0x02, "lvl6", &[]))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut c).await, Some(vec![0x20, 2, 0, 1]));
    expect_closed(&mut c, None).await;

    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&connect_with("MQTT", 4, 0x03, "reserved", &[]))
        .await
        .unwrap();
    expect_closed(&mut c, None).await;
}

#[tokio::test]
async fn an_empty_client_id_needs_a_clean_session_on_3_1_1() {
    let (_s, _id, port) = broker(json!({})).await;
    session(port, &connect_with("MQTT", 4, 0x02, "", &[])).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&connect_with("MQTT", 4, 0x00, "", &[]))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut c).await, Some(vec![0x20, 2, 0, 2]));
    expect_closed(&mut c, None).await;
}

#[tokio::test]
async fn packet_identifier_zero_is_refused() {
    let (_s, _id, port) = broker(json!({})).await;
    for (v5, level) in [(false, 4u8), (true, 5u8)] {
        let reason = v5.then_some(0x82);
        let mut c = session(port, &connect(level, &format!("pid-{level}"))).await;
        c.write_all(&publish(v5, 1, 1, b"a/b", b"x")).await.unwrap();
        assert_eq!(read_packet(&mut c).await.unwrap()[0], 0x40, "PUBACK");
        c.write_all(&publish(v5, 1, 0, b"a/b", b"x")).await.unwrap();
        expect_closed(&mut c, reason).await;

        let mut c = session(port, &connect(level, &format!("pid-sub-{level}"))).await;
        let mut sub = subscribe(0x82, 0, b"a/b", 0);
        if v5 {
            sub = {
                let mut body = 0u16.to_be_bytes().to_vec();
                body.push(0);
                body.extend(s(b"a/b"));
                body.push(0);
                packet(0x82, &body)
            };
        }
        c.write_all(&sub).await.unwrap();
        expect_closed(&mut c, reason).await;

        if !v5 {
            let mut c = session(port, &connect(level, "pid-unsub")).await;
            c.write_all(&unsubscribe(1, b"a/b")).await.unwrap();
            assert_eq!(read_packet(&mut c).await.unwrap()[0], 0xB0, "UNSUBACK");
            c.write_all(&unsubscribe(0, b"a/b")).await.unwrap();
            expect_closed(&mut c, None).await;
        }
    }
}

#[tokio::test]
async fn strings_must_be_well_formed_utf8_without_nul() {
    let (_s, _id, port) = broker(json!({})).await;
    let mut c = session(port, &connect(4, "utf8")).await;
    c.write_all(&publish(false, 0, 0, "a/ü".as_bytes(), b"x"))
        .await
        .unwrap();
    ping_answered(&mut c).await;
    c.write_all(&publish(false, 0, 0, b"a/\xff", b"x"))
        .await
        .unwrap();
    expect_closed(&mut c, None).await;

    let mut c = session(port, &connect(4, "nul")).await;
    c.write_all(&publish(false, 0, 0, b"a\0b", b"x"))
        .await
        .unwrap();
    expect_closed(&mut c, None).await;

    // A client id that is not UTF-8 is a malformed CONNECT.
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut body = s(b"MQTT");
    body.extend([4, 0x02, 0x00, 30]);
    body.extend(s(b"id\xc3"));
    c.write_all(&packet(0x10, &body)).await.unwrap();
    expect_closed(&mut c, None).await;
}

#[tokio::test]
async fn a_topic_name_may_not_carry_a_wildcard() {
    let (_s, _id, port) = broker(json!({})).await;
    for (v5, level) in [(false, 4u8), (true, 5u8)] {
        for topic in [&b"a/+"[..], b"a/#"] {
            let mut c = session(port, &connect(level, &format!("wild-{level}"))).await;
            c.write_all(&publish(v5, 0, 0, b"a/b", b"x")).await.unwrap();
            ping_answered(&mut c).await;
            c.write_all(&publish(v5, 0, 0, topic, b"x")).await.unwrap();
            expect_closed(&mut c, v5.then_some(0x90)).await;
        }
    }
}

#[tokio::test]
async fn a_topic_filter_must_follow_the_wildcard_rules() {
    let (_s, _id, port) = broker(json!({})).await;
    let mut c = session(port, &connect(4, "filters")).await;
    for (i, good) in [&b"a/+/b"[..], b"a/#", b"#", b"+", b"/"].iter().enumerate() {
        c.write_all(&subscribe(0x82, i as u16 + 1, good, 1))
            .await
            .unwrap();
        let suback = read_packet(&mut c).await.unwrap();
        assert_eq!(suback[0], 0x90, "{good:?}: {suback:02x?}");
    }
    for bad in [&b"a/b#"[..], b"a+/b", b"a/#/b", b""] {
        let mut c = session(port, &connect(4, "filters-bad")).await;
        c.write_all(&subscribe(0x82, 1, bad, 1)).await.unwrap();
        expect_closed(&mut c, None).await;
    }
    // UNSUBSCRIBE takes filters too.
    let mut c = session(port, &connect(4, "unsub-bad")).await;
    c.write_all(&unsubscribe(1, b"a/b#")).await.unwrap();
    expect_closed(&mut c, None).await;
    // v5 says which rule: 0x8F Topic Filter invalid.
    let mut c = session(port, &connect(5, "filters-v5")).await;
    let mut body = 1u16.to_be_bytes().to_vec();
    body.push(0);
    body.extend(s(b"a+/b"));
    body.push(0);
    c.write_all(&packet(0x82, &body)).await.unwrap();
    expect_closed(&mut c, Some(0x8F)).await;
}

#[tokio::test]
async fn the_requested_qos_byte_and_the_fixed_header_flags_are_checked() {
    let (_s, _id, port) = broker(json!({})).await;
    let mut c = session(port, &connect(4, "qosbyte")).await;
    c.write_all(&subscribe(0x82, 1, b"a", 2)).await.unwrap();
    assert_eq!(read_packet(&mut c).await, Some(vec![0x90, 3, 0, 1, 2]));
    for bad in [3u8, 0x04, 0x80] {
        let mut c = session(port, &connect(4, "qosbyte-bad")).await;
        c.write_all(&subscribe(0x82, 1, b"a", bad)).await.unwrap();
        expect_closed(&mut c, None).await;
    }
    // SUBSCRIBE's fixed header is 1000 0010; 1000 0000 is malformed.
    let mut c = session(port, &connect(4, "flags")).await;
    c.write_all(&subscribe(0x80, 1, b"a", 1)).await.unwrap();
    expect_closed(&mut c, None).await;
    // So is a PINGREQ with a flag set.
    let mut c = session(port, &connect(4, "flags-ping")).await;
    c.write_all(&[0xC1, 0x00]).await.unwrap();
    expect_closed(&mut c, None).await;
}

/// A 3.1.1 QoS 0 PUBLISH of exactly `total` bytes on the wire.
fn publish_of_total(total: usize) -> Vec<u8> {
    // 1 type byte + varint + 2-byte topic length + 1-byte topic + payload.
    for varint_len in 1..=4 {
        let remaining = total - 1 - varint_len;
        if varint(remaining).len() == varint_len {
            let p = publish(false, 0, 0, b"t", &vec![b'x'; remaining - 3]);
            assert_eq!(p.len(), total);
            return p;
        }
    }
    unreachable!()
}

#[tokio::test]
async fn max_packet_size_bounds_the_whole_packet() {
    let (_s, _id, port) = broker(json!({"max_packet_size": 300})).await;
    let mut c = session(port, &connect(4, "size")).await;
    c.write_all(&publish_of_total(300)).await.unwrap();
    ping_answered(&mut c).await;
    c.write_all(&publish_of_total(301)).await.unwrap();
    expect_closed(&mut c, None).await;
    // v5: told with 0x95, and the CONNACK advertised the same number.
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&connect(5, "size-v5")).await.unwrap();
    let connack = read_packet(&mut c).await.unwrap();
    assert!(
        connack.windows(5).any(|w| w == [0x27, 0, 0, 1, 44]),
        "Maximum Packet Size 300 advertised: {connack:02x?}"
    );
    let mut p = publish_of_total(301);
    // As v5: the same bytes with a zero property length in place of one payload byte.
    p.truncate(p.len() - 1);
    p.insert(6, 0);
    c.write_all(&p).await.unwrap();
    expect_closed(&mut c, Some(0x95)).await;
}

#[tokio::test]
async fn max_packet_size_has_a_64_byte_floor_and_a_16_mib_ceiling() {
    let (_s, _id, port) = broker(json!({"max_packet_size": 1})).await;
    let mut c = session(port, &connect(4, "floor")).await;
    c.write_all(&publish_of_total(64)).await.unwrap();
    ping_answered(&mut c).await;
    c.write_all(&publish_of_total(65)).await.unwrap();
    expect_closed(&mut c, None).await;

    let (_s, _id, port) = broker(json!({"max_packet_size": 1u64 << 30})).await;
    let mut c = session(port, &connect(4, "ceiling")).await;
    // Only the header: a declared remaining length past 16 MiB is refused from it.
    let mut header = vec![0x30];
    header.extend(varint(16 * 1024 * 1024));
    c.write_all(&header).await.unwrap();
    expect_closed(&mut c, None).await;
}

#[tokio::test]
async fn a_remaining_length_of_five_bytes_is_malformed() {
    let (_s, _id, port) = broker(json!({})).await;
    let mut c = session(port, &connect(4, "varint")).await;
    c.write_all(&[0x30, 0x80, 0x80, 0x80, 0x80, 0x01])
        .await
        .unwrap();
    expect_closed(&mut c, None).await;
}

#[tokio::test]
async fn the_clients_maximum_packet_size_bounds_what_the_broker_sends_it() {
    let (_s, _id, port) = broker(json!({})).await;
    // CONNECT with Maximum Packet Size (0x27) 64.
    let mut c = session(
        port,
        &connect_with("MQTT", 5, 0x02, "small", &[0x27, 0, 0, 0, 64]),
    )
    .await;
    // The broker's PUBLISH is 2 (header) + 3 (topic "r") + 1 (properties) + n: 58 is 64.
    c.write_all(&publish(true, 0, 0, b"send/58", b""))
        .await
        .unwrap();
    let p = read_packet(&mut c).await.unwrap();
    assert_eq!((p[0], p.len()), (0x30, 64), "{p:02x?}");
    c.write_all(&publish(true, 0, 0, b"send/59", b""))
        .await
        .unwrap();
    // Not sent: the next thing on the wire is the PINGRESP.
    ping_answered(&mut c).await;
}

#[tokio::test]
async fn a_second_connection_with_the_same_client_id_takes_the_session_over() {
    let (state, id, port) = broker(json!({})).await;
    // v5: the first is told 0x8E Session taken over, then closed.
    let mut first = session(port, &connect(5, "same")).await;
    let mut second = session(port, &connect(5, "same")).await;
    expect_closed(&mut first, Some(0x8E)).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while active_connections(&state, id).await != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first connection's teardown never ran");
    // The directory names the second: a PUBLISH routed to "same" reaches it, after the first
    // connection's teardown has run (which must not remove the second's entry).
    let mut other = session(port, &connect(4, "router")).await;
    other
        .write_all(&publish(false, 0, 0, b"to/same", b"routed"))
        .await
        .unwrap();
    let p = read_packet(&mut second).await.unwrap();
    assert_eq!(p[0], 0x30, "{p:02x?}");
    assert!(p.ends_with(b"routed"), "{p:02x?}");

    // 3.1.1: closed with no packet.
    let mut first = session(port, &connect(4, "same311")).await;
    let _second = session(port, &connect(4, "same311")).await;
    expect_closed(&mut first, None).await;

    // A refused CONNECT naming a connected client's id takes nothing over.
    let mut kept = session(port, &connect(4, "kept")).await;
    let mut refused = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut body = s(b"MQTT");
    body.extend([4, 0x82, 0x00, 30]);
    body.extend(s(b"kept"));
    body.extend(s(b"bad"));
    refused.write_all(&packet(0x10, &body)).await.unwrap();
    assert_eq!(read_packet(&mut refused).await, Some(vec![0x20, 2, 0, 5]));
    ping_answered(&mut kept).await;
}
