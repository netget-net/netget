//! MQTT 5.0 refusals that hinge on a property: enhanced authentication nobody performed, a
//! property block with more User Properties than the broker takes, Subscription Identifiers
//! where the specification forbids them, and a Maximum Packet Size of 0.
//!
//! Every packet the client side sends is written out by hand from the OASIS MQTT 5.0
//! specification over a raw `TcpStream`, so nothing in `src/server/mqtt/` builds both halves.
//! Each refusal sits beside a control that differs only in the property under test and is
//! accepted, so a refusal cannot come from something else in the packet.
//!
//! No LLM calls: static handlers answer, and the model endpoint is a closed port.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// A handler that runs and answers nothing: every event falls to the protocol default.
fn silent() -> serde_json::Value {
    json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}})
}

/// A handler that explicitly accepts every CONNECT, then says nothing about anything else.
fn accept_connect() -> Vec<serde_json::Value> {
    vec![
        json!({
            "event_pattern": "mqtt_connect",
            "handler": {"type": "static", "actions": [{"type": "mqtt_connack", "return_code": 0}]}
        }),
        silent(),
    ]
}

async fn broker(handlers: Vec<serde_json::Value>) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("MQTT 5 broker".into()),
        event_handlers: Some(handlers),
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

/// `n` User Properties (0x26), each ("k", "v").
fn user_properties(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(0x26);
        out.extend(s("k"));
        out.extend(s("v"));
    }
    out
}

/// v5 CONNECT, clean start, keep alive 30.
fn connect(client_id: &str, v5_props: &[u8]) -> Vec<u8> {
    let mut body = s("MQTT");
    body.extend([5, 0x02, 0x00, 30]);
    body.extend(props(v5_props));
    body.extend(s(client_id));
    packet(0x10, &body)
}

/// QoS 0 PUBLISH.
fn publish(topic: &str, p: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = s(topic);
    body.extend(props(p));
    body.extend_from_slice(payload);
    packet(0x30, &body)
}

/// SUBSCRIBE with one filter at QoS 0.
fn subscribe(packet_id: u16, p: &[u8], filter: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend(props(p));
    body.extend(s(filter));
    body.push(0x00);
    packet(0x82, &body)
}

/// A refusing v5 CONNACK with no properties: flags 0, the reason, property length 0.
fn connack_refusal(reason: u8) -> Vec<u8> {
    vec![0x20, 0x03, 0x00, reason, 0x00]
}

/// A v5 DISCONNECT with a reason and no properties.
fn disconnect(reason: u8) -> Vec<u8> {
    vec![0xE0, 0x02, reason, 0x00]
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

/// Send `hello` on a fresh connection and return the connection and the broker's reply.
async fn open(port: u16, hello: &[u8]) -> (TcpStream, Vec<u8>) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(hello).await.unwrap();
    let reply = read_packet(&mut c).await;
    (c, reply)
}

/// A v5 CONNACK accepting the session: flags 0, reason 0x00.
fn assert_accepted(connack: &[u8]) {
    assert_eq!(connack[0], 0x20, "{connack:02x?}");
    assert_eq!(&connack[2..4], &[0x00, 0x00], "{connack:02x?}");
}

/// Authentication Method "SCRAM-SHA-1" (0x15).
fn auth_method() -> Vec<u8> {
    let mut p = vec![0x15];
    p.extend(s("SCRAM-SHA-1"));
    p
}

#[tokio::test]
async fn a_silent_handler_refuses_a_connect_naming_an_authentication_method() {
    let (_state, port) = broker(vec![silent()]).await;

    // Control: the same silent handler admits a CONNECT with no Authentication Method - the
    // documented default, so the refusal below is the method's doing.
    let (_plain, connack) = open(port, &connect("no-auth", &[])).await;
    assert_accepted(&connack);

    // Enhanced authentication was asked for and never ran: 0x8C Bad Authentication Method,
    // then the broker closes (§3.2.2.2).
    let (mut c, connack) = open(port, &connect("wants-scram", &auth_method())).await;
    assert_eq!(
        connack,
        connack_refusal(0x8C),
        "silence must not admit a client whose authentication never ran: {connack:02x?}"
    );
    expect_eof(&mut c).await;

    // An explicit mqtt_connack accepting is what admits such a client.
    let (_state, port) = broker(accept_connect()).await;
    let (_c, connack) = open(port, &connect("scram-accepted", &auth_method())).await;
    assert_accepted(&connack);
}

#[tokio::test]
async fn more_than_128_user_properties_are_refused() {
    let (_state, port) = broker(vec![silent()]).await;

    // Control: 128 on a CONNECT is accepted.
    let (mut c, connack) = open(port, &connect("props-128", &user_properties(128))).await;
    assert_accepted(&connack);

    // ... and 128 on a PUBLISH passes too: the PINGREQ after it is answered.
    c.write_all(&publish("t", &user_properties(128), b"x"))
        .await
        .unwrap();
    c.write_all(&[0xC0, 0x00]).await.unwrap();
    assert_eq!(read_packet(&mut c).await, vec![0xD0, 0x00]);

    // 129 on a PUBLISH: DISCONNECT 0x82 Protocol Error, then close.
    c.write_all(&publish("t", &user_properties(129), b"x"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut c).await, disconnect(0x82));
    expect_eof(&mut c).await;

    // 129 on a CONNECT: CONNACK 0x82, then close.
    let (mut c, connack) = open(port, &connect("props-129", &user_properties(129))).await;
    assert_eq!(connack, connack_refusal(0x82), "{connack:02x?}");
    expect_eof(&mut c).await;
}

#[tokio::test]
async fn subscription_identifiers_are_refused_where_the_specification_forbids_them() {
    let (_state, port) = broker(vec![silent()]).await;

    // Control: one non-zero Subscription Identifier on a SUBSCRIBE is answered with a SUBACK.
    let (mut c, connack) = open(port, &connect("subid-ok", &[])).await;
    assert_accepted(&connack);
    c.write_all(&subscribe(1, &[0x0B, 5], "a/#")).await.unwrap();
    let suback = read_packet(&mut c).await;
    assert_eq!(suback[0], 0x90, "{suback:02x?}");

    // A second Subscription Identifier on one SUBSCRIBE: Protocol Error.
    let (mut c, _) = open(port, &connect("subid-two", &[])).await;
    c.write_all(&subscribe(1, &[0x0B, 5, 0x0B, 6], "a/#"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut c).await, disconnect(0x82));
    expect_eof(&mut c).await;

    // A Subscription Identifier of 0: Protocol Error (§3.8.2.1.2).
    let (mut c, _) = open(port, &connect("subid-zero", &[])).await;
    c.write_all(&subscribe(1, &[0x0B, 0], "a/#")).await.unwrap();
    assert_eq!(read_packet(&mut c).await, disconnect(0x82));
    expect_eof(&mut c).await;

    // Any Subscription Identifier on a PUBLISH a client sends: Protocol Error
    // ([MQTT-3.3.4-6]).
    let (mut c, _) = open(port, &connect("subid-publish", &[])).await;
    c.write_all(&publish("t", &[0x0B, 5], b"x")).await.unwrap();
    assert_eq!(read_packet(&mut c).await, disconnect(0x82));
    expect_eof(&mut c).await;

    // And on a CONNECT, where it is not a valid property at all.
    let (mut c, connack) = open(port, &connect("subid-connect", &[0x0B, 5])).await;
    assert_eq!(connack, connack_refusal(0x82), "{connack:02x?}");
    expect_eof(&mut c).await;
}

#[tokio::test]
async fn a_maximum_packet_size_of_zero_is_refused() {
    let (_state, port) = broker(vec![silent()]).await;

    // Control: Maximum Packet Size 1024 is accepted.
    let (_c, connack) = open(port, &connect("max-1024", &[0x27, 0, 0, 4, 0])).await;
    assert_accepted(&connack);

    // 0: Protocol Error (§3.1.2.11.4), CONNACK 0x82 and close.
    let (mut c, connack) = open(port, &connect("max-zero", &[0x27, 0, 0, 0, 0])).await;
    assert_eq!(connack, connack_refusal(0x82), "{connack:02x?}");
    expect_eof(&mut c).await;
}
