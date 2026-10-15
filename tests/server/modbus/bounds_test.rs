//! Every bound the Modbus server declares, driven from the wire.
//!
//! The Stable bar's fourth condition is "every declared bound has a test", and the coap pass
//! showed why it has to be read literally: a declared number can govern the other direction
//! from the one it reads as. So each test below names the bound, the direction it governs, and
//! what the peer sees on each side of it.
//!
//! | bound | direction | test |
//! |---|---|---|
//! | `codec::MAX_ADU_LEN` (260), declared as `max_inbound_bytes` | **inbound**: the MBAP length field a peer may announce | `the_largest_legal_adu_is_answered_and_one_octet_more_closes` |
//! | `MAX_BUFFERED` (2080) | inbound: bytes queued behind a request that is with the model | `bytes_queued_behind_a_parked_request_are_capped` |
//! | `MAX_CONNECTIONS` (256) | concurrent peers | `the_connection_cap_refuses_silently_and_every_close_returns_its_slot` |
//! | `first_byte_timeout_secs` / `idle_timeout_secs` | read deadlines, tunable | `both_read_deadlines_follow_their_startup_parameters` |
//! | quantity limits 2000 / 125 / 1968 / 123 | inbound PDU fields | `every_quantity_limit_is_exact` |
//! | `unit_id` | inbound routing | `a_request_for_another_unit_is_refused_with_exception_0x0b` |
//!
//! The *outbound* side of `MAX_ADU_LEN` — that no response this server frames can exceed it —
//! is `tests/codec_property_test.rs::modbus_props` (`adu_output_is_bounded`,
//! `read_responses_fit_a_legal_pdu`), and the defaults of the two read deadlines are
//! `connection_bounds_test.rs`.
//!
//! Each wire test was verified by removing its bound and watching it fail; the commit that
//! added this file records how.
//!
//! Every server here is model-free: an empty instruction really is model-free (`None` would
//! be replaced by a default instruction), and the requests used are either answered by the
//! specification with no model call or parked on a `manual` rule. Loopback only.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::modbus::codec;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/modbus/mod.rs::MAX_BUFFERED`. Duplicated rather than imported on purpose: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_BUFFERED: usize = 2080;

/// `src/server/modbus/mod.rs::MAX_CONNECTIONS`, which is `accept_bounded::DEFAULT_MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

async fn new_state() -> AppState {
    // A dead LLM endpoint: nothing here should reach the model, and if something did, Modbus's
    // fail-closed path would answer exception 0x04 — which every assertion below would notice.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Modbus server #{} never bound a port", id.as_u32());
}

async fn start(
    state: &AppState,
    startup_params: serde_json::Value,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "modbus".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create modbus server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// A Modbus/TCP ADU built from the specification, not from `codec::encode_adu`, with the MBAP
/// length field written as given so a test can lie in it.
fn raw_adu(transaction_id: u16, length_field: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&length_field.to_be_bytes());
    out.push(unit_id);
    out.extend_from_slice(pdu);
    out
}

fn adu(transaction_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
    raw_adu(transaction_id, pdu.len() as u16 + 1, unit_id, pdu)
}

/// Read one response ADU: `(transaction_id, unit_id, pdu)`.
async fn read_adu(stream: &mut TcpStream) -> (u16, u8, Vec<u8>) {
    let mut header = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut header))
        .await
        .expect("timed out waiting for a Modbus response")
        .expect("reading a Modbus response header");
    let length = u16::from_be_bytes([header[4], header[5]]) as usize;
    assert!(length >= 2, "MBAP length {length} cannot carry a PDU");
    let mut pdu = vec![0u8; length - 1];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut pdu))
        .await
        .expect("timed out reading a Modbus PDU")
        .expect("reading a Modbus PDU");
    (u16::from_be_bytes([header[0], header[1]]), header[6], pdu)
}

/// Wait for the server to close `stream`, and return whatever it wrote first.
async fn read_until_closed(stream: &mut TcpStream, within: Duration, what: &str) -> Vec<u8> {
    let mut sink = Vec::new();
    tokio::time::timeout(within, stream.read_to_end(&mut sink))
        .await
        .unwrap_or_else(|_| panic!("{what}: the server did not close the connection"))
        .unwrap_or_else(|e| panic!("{what}: read failed: {e}"));
    sink
}

// ---------------------------------------------------------------------------------------------
// MAX_ADU_LEN — inbound
// ---------------------------------------------------------------------------------------------

/// `max_inbound_bytes(MAX_ADU_LEN)` is a claim about what a peer may **send**, and it is
/// enforced by the MBAP length field: 254 is the largest legal value (unit id + a 253-octet PDU,
/// a 260-octet ADU), 255 is the first illegal one.
///
/// The PDU used is function code 0x41 — not implemented, so the specification answers it with
/// exception 0x01 and no model is asked — padded to the full 253 octets. Getting that exception
/// back proves the 260-octet ADU was framed and parsed. The same frame one octet longer must be
/// refused, and refused by closing: once a length field is illegal nobody knows where the next
/// frame starts, and Modbus has no message for "your framing is wrong".
#[tokio::test]
async fn the_largest_legal_adu_is_answered_and_one_octet_more_closes() {
    let state = new_state().await;
    let (_id, port) = start(&state, serde_json::json!({}), None).await;

    let mut at_limit_pdu = vec![0x41u8];
    at_limit_pdu.resize(codec::MAX_PDU_LEN, 0xAA);
    let at_limit = adu(0x1234, 1, &at_limit_pdu);
    assert_eq!(
        at_limit.len(),
        codec::MAX_ADU_LEN,
        "test frame must sit exactly at the bound"
    );

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&at_limit).await.expect("write");
    let (txid, unit, pdu) = read_adu(&mut peer).await;
    assert_eq!(txid, 0x1234);
    assert_eq!(unit, 1);
    assert_eq!(
        pdu,
        vec![0xC1, codec::EXC_ILLEGAL_FUNCTION],
        "a {}-octet ADU is legal and must be framed; the unimplemented function code inside it \
         must come back as exception 0x01",
        codec::MAX_ADU_LEN
    );

    let mut over_pdu = at_limit_pdu.clone();
    over_pdu.push(0xAA);
    let over = adu(0x1235, 1, &over_pdu);
    assert_eq!(over.len(), codec::MAX_ADU_LEN + 1);
    assert_eq!(u16::from_be_bytes([over[4], over[5]]), 255);

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&over).await.expect("write");
    let reply = read_until_closed(
        &mut peer,
        Duration::from_secs(15),
        "an MBAP length of 255 (a 261-octet ADU)",
    )
    .await;
    assert!(
        reply.is_empty(),
        "an ADU one octet past MAX_ADU_LEN must be refused by closing, not answered — the length \
         field is what bounds inbound frames. Got {reply:02x?}"
    );
}

// ---------------------------------------------------------------------------------------------
// MAX_BUFFERED — inbound, while a request is with the model
// ---------------------------------------------------------------------------------------------

/// The only time bytes pile up on a Modbus connection is behind a request that is being
/// answered: the framing loop is parked on the model and does not run, so whatever arrives is
/// queued. A `*` → manual rule parks the first request for a human, which holds that state for
/// as long as the test needs without any model at all.
///
/// Exactly `MAX_BUFFERED` octets queued must be tolerated — a master may legitimately pipeline
/// — and one octet more must close the connection without a reply. Without the append-side
/// check the queue grows until the parked request is answered, which is five minutes here and
/// two at the shipped `--llm-queue-timeout`, and the second half of this test hangs.
#[tokio::test]
async fn bytes_queued_behind_a_parked_request_are_capped() {
    let state = new_state().await;
    let (_id, port) = start(
        &state,
        serde_json::json!({}),
        Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "manual", "timeout_secs": 300 }
        })]),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    // Read Holding Registers, one register at 0. Legal, so it goes to the (manual) handler and
    // parks there.
    peer.write_all(&adu(1, 1, &[0x03, 0x00, 0x00, 0x00, 0x01]))
        .await
        .expect("write request");

    // Give the request time to reach the park before queueing behind it. If it had not parked,
    // the filler below would be framed (zeros: protocol id 0, length 0) and closed as a framing
    // error, and the "tolerated" assertion would catch that.
    tokio::time::sleep(Duration::from_millis(500)).await;

    peer.write_all(&vec![0u8; MAX_BUFFERED])
        .await
        .expect("write queue up to the bound");
    let mut probe = [0u8; 16];
    match tokio::time::timeout(Duration::from_millis(1500), peer.read(&mut probe)).await {
        Err(_) => {} // still open, still silent: the request is parked and the queue is legal
        Ok(Ok(0)) => panic!(
            "the connection was closed with exactly MAX_BUFFERED ({MAX_BUFFERED}) octets queued \
             — the bound is enforced one octet early"
        ),
        Ok(Ok(n)) => panic!(
            "the server wrote {:02x?} while the request was parked for a human",
            &probe[..n]
        ),
        Ok(Err(e)) => panic!("read failed: {e}"),
    }

    peer.write_all(&[0u8])
        .await
        .expect("write the octet past the bound");
    let reply = read_until_closed(
        &mut peer,
        Duration::from_secs(15),
        "one octet past MAX_BUFFERED queued behind a parked request",
    )
    .await;
    assert!(
        reply.is_empty(),
        "a queue overrun is not a request and has no answer; the refusal is a close. Got \
         {reply:02x?}"
    );
}

// ---------------------------------------------------------------------------------------------
// MAX_CONNECTIONS
// ---------------------------------------------------------------------------------------------

async fn wait_for_admitted(state: &AppState, id: ServerId, n: usize) {
    for _ in 0..600 {
        if let Some(s) = state.get_server(id).await {
            if s.connections.len() >= n {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let seen = state
        .get_server(id)
        .await
        .map(|s| s.connections.len())
        .unwrap_or(0);
    panic!("the server admitted only {seen} of {n} connections");
}

/// Connect until one is admitted, and return it held open.
///
/// Modbus is client-speaks-first, so an admitted connection is one that is still open and
/// silent after a short window; a refused one reads EOF at once.
async fn connect_until_admitted(port: u16, what: &str) -> TcpStream {
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            Err(_) => return candidate,
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("{what}: no connection was admitted — the slot never came back")
}

/// 256 peers are admitted, the 257th is closed without a byte, and a slot comes back both when a
/// peer hangs up **and** when the server closes a peer that stays connected.
///
/// The second half is the one that failed. A framing error closed the connection from
/// `handle_data`'s task by shutting the write half — the peer read EOF — but the reader task
/// went on reading the still-open socket and held the connection's permit until the peer hung
/// up or went quiet for the idle bound. A peer could therefore take a slot for as long as it
/// liked by sending one malformed header and keeping its end open, and the cap counted a
/// connection that no longer existed anywhere else.
#[tokio::test]
async fn the_connection_cap_refuses_silently_and_every_close_returns_its_slot() {
    let state = new_state().await;
    // Held connections say nothing; keep them inside the first-byte bound for the whole test.
    let (server_id, port) = start(
        &state,
        serde_json::json!({ "first_byte_timeout_secs": 300 }),
        None,
    )
    .await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    wait_for_admitted(&state, server_id, MAX_CONNECTIONS).await;

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener must still accept — a cap is not a closed socket");
    let refusal = read_until_closed(&mut over, Duration::from_secs(20), "the 257th peer").await;
    assert!(
        refusal.is_empty(),
        "every Modbus server message is a reply carrying a transaction id this peer never sent, \
         so the refusal must be a plain close. Got {refusal:02x?}"
    );

    // A held peer breaks framing (protocol id 7 is not Modbus) and then keeps its socket open.
    let mut bad = held.remove(0);
    let mut not_modbus = adu(9, 1, &[0x03, 0x00, 0x00, 0x00, 0x01]);
    not_modbus[3] = 7;
    bad.write_all(&not_modbus).await.expect("write");
    let reply = read_until_closed(&mut bad, Duration::from_secs(15), "a framing error").await;
    assert!(
        reply.is_empty(),
        "a framing error has no answer; got {reply:02x?}"
    );
    // `bad` is deliberately still in scope: its end of the socket stays open.
    held.push(connect_until_admitted(port, "after a framing-error close").await);

    // And the ordinary case: a peer hangs up.
    drop(held.pop());
    held.push(connect_until_admitted(port, "after a peer hung up").await);

    drop(bad);
}

// ---------------------------------------------------------------------------------------------
// Read deadlines
// ---------------------------------------------------------------------------------------------

/// Both deadlines follow their startup parameters, which is also the only way to test the idle
/// one in a test suite: its default is ten minutes.
///
/// The first-byte half connects and says nothing; the idle half sends one request, reads its
/// answer, and then says nothing. Each must be closed near its own configured bound, without a
/// byte, and the idle one must not be closed at the (shorter) first-byte bound — the two bounds
/// are distinct claims.
#[tokio::test]
async fn both_read_deadlines_follow_their_startup_parameters() {
    let state = new_state().await;
    let (_id, port) = start(
        &state,
        serde_json::json!({ "first_byte_timeout_secs": 1, "idle_timeout_secs": 4 }),
        None,
    )
    .await;

    // First byte.
    let mut silent = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    let sink = read_until_closed(&mut silent, Duration::from_secs(20), "a silent peer").await;
    assert!(
        sink.is_empty(),
        "an idle close writes nothing; got {sink:02x?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "closed after {:?}, before the configured 1s first-byte bound",
        started.elapsed()
    );

    // Idle, after one request. FC 0x08 is answered by the specification (exception 0x01).
    let mut talker = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    talker
        .write_all(&adu(7, 1, &[0x08, 0x00, 0x00, 0x00, 0x00]))
        .await
        .expect("write");
    let (txid, _, pdu) = read_adu(&mut talker).await;
    assert_eq!((txid, pdu), (7, vec![0x88, 0x01]));
    let answered = std::time::Instant::now();
    let sink = read_until_closed(&mut talker, Duration::from_secs(30), "a peer gone quiet").await;
    let quiet_for = answered.elapsed();
    assert!(
        sink.is_empty(),
        "an idle close writes nothing; got {sink:02x?}"
    );
    assert!(
        quiet_for >= Duration::from_millis(3000),
        "a peer that had spoken was closed after {quiet_for:?} of silence — that is the \
         first-byte bound (1s), not the idle bound (4s)"
    );
}

// ---------------------------------------------------------------------------------------------
// Quantity limits — inbound PDU fields
// ---------------------------------------------------------------------------------------------

fn read_pdu(fc: u8, quantity: u16) -> Vec<u8> {
    let mut pdu = vec![fc, 0x00, 0x00];
    pdu.extend_from_slice(&quantity.to_be_bytes());
    pdu
}

fn write_coils_pdu(quantity: u16) -> Vec<u8> {
    let byte_count = quantity.div_ceil(8) as usize;
    let mut pdu = vec![codec::FC_WRITE_MULTIPLE_COILS, 0x00, 0x00];
    pdu.extend_from_slice(&quantity.to_be_bytes());
    pdu.push(byte_count as u8);
    pdu.resize(pdu.len() + byte_count, 0x55);
    pdu
}

fn write_registers_pdu(quantity: u16) -> Vec<u8> {
    // At most 124 registers are built here, so the byte count (248) still fits its octet and
    // the frame is well-formed apart from the quantity itself.
    let byte_count = quantity as usize * 2;
    let mut pdu = vec![codec::FC_WRITE_MULTIPLE_REGISTERS, 0x00, 0x00];
    pdu.extend_from_slice(&quantity.to_be_bytes());
    pdu.push(byte_count as u8);
    pdu.resize(pdu.len() + byte_count, 0x00);
    pdu
}

/// The four quantity limits in MODBUS Application Protocol V1.1b3 — 2000 bits and 125 registers
/// per read, 1968 coils and 123 registers per write — each accepted at the limit and refused
/// with exception 0x03 one past it, and zero refused everywhere.
///
/// These are what keep every response inside `MAX_PDU_LEN`: 2000 bits is 250 data octets and
/// 125 registers is 250, so the read limits are the reason a model's answer can always be
/// framed. The property tests generate only legal quantities; this is the refusal side.
#[test]
fn every_quantity_limit_is_exact() {
    type PduBuilder = fn(u16) -> Vec<u8>;
    let cases: [(&str, PduBuilder, u16); 6] = [
        ("read coils", |q| read_pdu(codec::FC_READ_COILS, q), 2000),
        (
            "read discrete inputs",
            |q| read_pdu(codec::FC_READ_DISCRETE_INPUTS, q),
            2000,
        ),
        (
            "read holding registers",
            |q| read_pdu(codec::FC_READ_HOLDING_REGISTERS, q),
            125,
        ),
        (
            "read input registers",
            |q| read_pdu(codec::FC_READ_INPUT_REGISTERS, q),
            125,
        ),
        ("write multiple coils", write_coils_pdu, 1968),
        ("write multiple registers", write_registers_pdu, 123),
    ];
    for (name, build, limit) in cases {
        let at = codec::parse_request(&build(limit));
        assert!(
            at.is_ok(),
            "{name}: a quantity of {limit} is the specification's limit and must be accepted, \
             got {at:?}"
        );
        assert_eq!(
            at.unwrap().quantity(),
            limit,
            "{name}: the quantity must survive parsing"
        );
        assert_eq!(
            codec::parse_request(&build(limit + 1)),
            Err(codec::EXC_ILLEGAL_DATA_VALUE),
            "{name}: a quantity of {} is past the limit and must be exception 0x03",
            limit + 1
        );
        assert_eq!(
            codec::parse_request(&build(0)),
            Err(codec::EXC_ILLEGAL_DATA_VALUE),
            "{name}: a quantity of 0 must be exception 0x03"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// unit_id
// ---------------------------------------------------------------------------------------------

/// With `unit_id` set, the server is a gateway for that one unit: any other unit id is answered
/// with exception 0x0B (gateway target device failed to respond), from the request's own
/// function code, with no model call. A request for the configured unit passes the filter and
/// reaches the next stage — here the specification, which answers FC 0x08 with 0x01.
#[tokio::test]
async fn a_request_for_another_unit_is_refused_with_exception_0x0b() {
    let state = new_state().await;
    let (_id, port) = start(&state, serde_json::json!({ "unit_id": 5 }), None).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&adu(0x0A0A, 7, &[0x03, 0x00, 0x00, 0x00, 0x01]))
        .await
        .expect("write");
    let (txid, unit, pdu) = read_adu(&mut peer).await;
    assert_eq!(txid, 0x0A0A);
    assert_eq!(
        unit, 7,
        "the reply is addressed back to the unit id the request named"
    );
    assert_eq!(
        pdu,
        vec![0x83, codec::EXC_GATEWAY_TARGET_FAILED],
        "a request for unit 7 on a unit-5 gateway must be exception 0x0B"
    );

    peer.write_all(&adu(0x0B0B, 5, &[0x08, 0x00, 0x00, 0x00, 0x00]))
        .await
        .expect("write");
    let (txid, unit, pdu) = read_adu(&mut peer).await;
    assert_eq!((txid, unit), (0x0B0B, 5));
    assert_eq!(
        pdu,
        vec![0x88, codec::EXC_ILLEGAL_FUNCTION],
        "a request for the configured unit must pass the filter"
    );
}
