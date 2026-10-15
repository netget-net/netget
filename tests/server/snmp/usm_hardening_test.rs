//! The agent's SNMPv3 path against hostile and replayed input, from the wire.
//!
//! - **Nested UsmSecurityParameters.** msgSecurityParameters is an OCTET STRING whose contents
//!   are BER of their own. The whole-datagram depth screen reads it as one primitive and never
//!   descends into it, so a userName or engineID written as `24 80` repeated (a constructed
//!   OCTET STRING, two bytes a level) reaches `rasn`'s unbounded recursion unless the contents
//!   are screened too. Thirty thousand levels overflow the stack: the process aborts, which no
//!   task boundary contains. The agent must drop the datagram and go on answering.
//! - **Engine boots across restarts.** With a fixed `engine_id` the localized keys are the same
//!   in every run, so an authenticated request captured from one agent is refused by the next
//!   one only if the second reports more boots. Two agents started in sequence must, and the
//!   captured request must come back as `usmStatsNotInTimeWindows`.
//! - **Out-of-range clocks.** snmpEngineBoots and snmpEngineTime are `0..2147483647`. A correctly
//!   authenticated request carrying `i64::MIN` or any other value outside that range is answered
//!   with the authenticated time report, never with arithmetic on the number: a subtraction on
//!   it overflows, which in a debug build panics the receive loop and takes the agent down.
//!
//! No LLM calls and no external tools: a static handler answers every request.

use netget::cli::management::ServerForm;
use netget::server::snmp::usm::{self, ReportKind, User};
use netget::state::app_state::AppState;
use netget::state::server::ServerStatus;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const ENGINE_ID: &str = "8000000005a1b2c3d4e5f60719";
const DEPTH: usize = 30_000;
/// The depth sent over UDP. macOS caps a datagram at 9216 bytes (net.inet.udp.maxdgram), and
/// at two bytes a level this stays under it while remaining far past `MAX_BER_DEPTH`; the
/// direct decode checks above use `DEPTH`.
const UDP_DEPTH: usize = 4_000;

fn users() -> Value {
    json!([
        {"name": "noauth"},
        {"name": "sha256", "auth_protocol": "sha256", "auth_password": "sha256-auth-pass"},
    ])
}

fn user(name: &str) -> User {
    let all = users();
    User::from_json(
        all.as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == name)
            .unwrap(),
    )
    .unwrap()
}

/// An agent whose every request is answered `sysDescr = "alive"` by a static handler.
async fn agent(params: Value) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "snmp".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            json!({"event_pattern": "*", "handler": {"type": "static",
            "actions": [{"type": "send_snmp_response", "variables": [
                {"oid": "1.3.6.1.2.1.1.1.0", "type": "string", "value": "alive"}]}]}}),
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
    .expect("the SNMP agent never bound");
    (state, id, port)
}

async fn assert_running(state: &AppState, id: ServerId) {
    let status = state.get_server(id).await.map(|s| s.status);
    assert!(
        matches!(status, Some(ServerStatus::Running)),
        "the agent is no longer running: {status:?}"
    );
}

async fn socket_to(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(("127.0.0.1", port)).await.unwrap();
    socket
}

/// Send one datagram and wait for the reply.
async fn exchange(socket: &UdpSocket, bytes: &[u8]) -> Vec<u8> {
    socket.send(bytes).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf))
        .await
        .expect("the agent did not answer")
        .unwrap();
    buf.truncate(n);
    buf
}

/// Discover the agent's engine for `manager`; returns the boots the report carried.
async fn discover(socket: &UdpSocket, manager: &usm::Manager) -> i64 {
    let (msg_id, probe) = manager.discovery().unwrap();
    let report = exchange(socket, &probe).await;
    manager.learn(&report, msg_id).unwrap();
    usm::decode(&report)
        .unwrap()
        .usm
        .authoritative_engine_boots
        .try_into()
        .unwrap()
}

fn get_pdu(request_id: i32) -> rasn_snmp::v2::Pdus {
    rasn_snmp::v2::Pdus::GetRequest(rasn_snmp::v2::GetRequest(rasn_snmp::v2::Pdu {
        request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![rasn_snmp::v2::VarBind {
            name: rasn::types::ObjectIdentifier::new_unchecked(
                vec![1, 3, 6, 1, 2, 1, 1, 1, 0].into(),
            ),
            value: rasn_snmp::v2::VarBindValue::Unspecified,
        }],
    }))
}

/// A GET through `manager`, answered by the handler.
async fn assert_answers(socket: &UdpSocket, manager: &usm::Manager) {
    let request = manager.wrap_request(get_pdu(4242), b"").unwrap();
    let reply = exchange(socket, &request).await;
    match manager.unwrap_reply(&reply).unwrap() {
        usm::Reply::Pdu(rasn_snmp::v2::Pdus::Response(r)) => {
            assert_eq!(r.0.request_id, 4242);
            assert_eq!(r.0.error_status, 0);
        }
        usm::Reply::Pdu(other) => panic!("not a Response: {other:?}"),
        usm::Reply::Report(kind, _) => panic!("a {} report", kind.name()),
    }
}

/// A definite-length TLV.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend([0x81, n as u8]);
    } else {
        assert!(n <= 0xffff);
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// A non-negative INTEGER's minimal content octets.
fn int(v: i64) -> Vec<u8> {
    assert!(v >= 0);
    let bytes = v.to_be_bytes();
    let mut at = 0;
    while at < 7 && bytes[at] == 0 && bytes[at + 1] & 0x80 == 0 {
        at += 1;
    }
    tlv(0x02, &bytes[at..])
}

/// Which UsmSecurityParameters field carries the nesting.
#[derive(Clone, Copy)]
enum Nested {
    EngineId,
    UserName,
}

/// A well-formed v3 message — every outer TLV definite and shallow, a cleartext GetRequest —
/// whose msgSecurityParameters contents nest `depth` constructed OCTET STRINGs in one field,
/// end-of-contents markers left off.
fn nested_usm_message(msg_id: i64, field: Nested, depth: usize) -> Vec<u8> {
    let mut usm = vec![0x30, 0x80];
    if let Nested::UserName = field {
        usm.extend([0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    }
    for _ in 0..depth {
        usm.extend([0x24, 0x80]);
    }
    let header = tlv(
        0x30,
        &[
            int(msg_id),
            int(usm::MAX_MESSAGE_SIZE),
            tlv(0x04, &[usm::FLAG_REPORTABLE]),
            int(usm::USM_SECURITY_MODEL),
        ]
        .concat(),
    );
    let pdu = tlv(0xa0, &[int(1), int(0), int(0), tlv(0x30, &[])].concat());
    let scoped = tlv(0x30, &[tlv(0x04, &[]), tlv(0x04, &[]), pdu].concat());
    let message = tlv(0x30, &[int(3), header, tlv(0x04, &usm), scoped].concat());
    assert!(
        message.len() <= 65_507,
        "one UDP datagram, was {} bytes",
        message.len()
    );
    message
}

/// The datagram is refused by the inner screen, not by the outer one: the outer message is
/// well-formed, so without the inner screen `rasn` would recurse into the nesting.
#[test]
fn the_nested_message_passes_the_outer_screen_and_is_refused_inside() {
    for field in [Nested::EngineId, Nested::UserName] {
        let message = nested_usm_message(7, field, DEPTH);
        assert!(
            netget::server::snmp::check_ber_structure(
                &message,
                netget::server::snmp::MAX_BER_DEPTH
            )
            .is_ok(),
            "the outer message must be shallow, or the test proves nothing"
        );
        assert!(usm::is_v3(&message));
        let error = match usm::decode(&message) {
            Ok(_) => panic!("a {DEPTH}-deep UsmSecurityParameters decoded"),
            Err(e) => e.to_string(),
        };
        assert!(
            error.contains("UsmSecurityParameters") && error.contains("nesting"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn nested_security_parameters_are_dropped_and_the_agent_keeps_answering() {
    let (state, id, port) = agent(json!({"v3_users": users(), "engine_id": ENGINE_ID})).await;
    let socket = socket_to(port).await;
    for field in [Nested::EngineId, Nested::UserName] {
        socket
            .send(&nested_usm_message(7, field, UDP_DEPTH))
            .await
            .unwrap();
    }
    // Neither is answered: the first datagram back is the discovery report.
    let manager = usm::Manager::new(user("noauth"));
    discover(&socket, &manager).await;
    assert_answers(&socket, &manager).await;
    assert_running(&state, id).await;
    state.remove_server(id).await;
}

#[test]
fn default_engine_boots_increase_and_stay_in_range() {
    let floor = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - usm::ENGINE_BOOTS_EPOCH_UNIX_SECS;
    let mut previous = 0;
    for _ in 0..1000 {
        let boots = usm::default_engine_boots();
        assert!(boots > previous, "{boots} after {previous}");
        assert!(
            boots >= floor as i64,
            "{boots} is below the wall clock's {floor}"
        );
        assert!(boots < usm::MAX_ENGINE_BOOTS);
        previous = boots;
    }
}

/// Two agents with one fixed engine_id, started in sequence with no `engine_boots`: the second
/// reports more boots, and an authenticated GET captured from the first is not answered by it.
#[tokio::test]
async fn a_restarted_agent_reports_more_boots_and_refuses_a_replay() {
    let params = json!({"v3_users": users(), "engine_id": ENGINE_ID});

    let (state, id, port) = agent(params.clone()).await;
    let socket = socket_to(port).await;
    let first_run = usm::Manager::new(user("sha256"));
    let first_boots = discover(&socket, &first_run).await;
    let captured = first_run.wrap_request(get_pdu(99), b"").unwrap();
    let captured_id = usm::decode(&captured).unwrap().msg_id;
    let reply = exchange(&socket, &captured).await;
    assert!(matches!(
        first_run.unwrap_reply(&reply).unwrap(),
        usm::Reply::Pdu(_)
    ));
    state.remove_server(id).await;

    let (state, id, port) = agent(params).await;
    let socket = socket_to(port).await;
    let second_run = usm::Manager::new(user("sha256"));
    let second_boots = discover(&socket, &second_run).await;
    assert!(
        second_boots > first_boots,
        "boots went {first_boots} → {second_boots} across a restart"
    );

    // The captured bytes, replayed unchanged: authenticated, and refused as stale.
    let reply = exchange(&socket, &captured).await;
    match second_run.unwrap(&reply, captured_id).unwrap() {
        usm::Reply::Report(kind, _) => assert_eq!(kind, ReportKind::NotInTimeWindows),
        usm::Reply::Pdu(pdu) => panic!("the replay was answered: {pdu:?}"),
    }
    // The second run itself is served.
    assert_answers(&socket, &second_run).await;
    state.remove_server(id).await;
}

/// Authenticated requests whose boots or time lie outside `0..=2147483647` get the
/// authenticated time report, and the agent keeps serving.
#[tokio::test]
async fn out_of_range_boots_and_time_are_reported_not_computed_on() {
    let (state, id, port) =
        agent(json!({"v3_users": users(), "engine_id": ENGINE_ID, "engine_boots": 5})).await;
    let socket = socket_to(port).await;
    let user = user("sha256");
    let engine = hex::decode(ENGINE_ID).unwrap();
    let keys = user.localize(&engine);
    let manager = usm::Manager::new(user.clone());
    assert_eq!(discover(&socket, &manager).await, 5);

    let out_of_range = [
        (5, i64::MIN),
        (5, i64::MAX),
        (5, -1),
        (5, usm::MAX_ENGINE_TIME + 1),
        (i64::MIN, 0),
        (-1, 0),
        (usm::MAX_ENGINE_BOOTS + 1, 0),
        (i64::MAX, 0),
    ];
    for (n, (boots, time)) in out_of_range.into_iter().enumerate() {
        let msg_id = 500 + n as i64;
        let bytes = usm::encode(usm::Outgoing {
            msg_id,
            max_size: usm::MAX_MESSAGE_SIZE,
            flags: usm::FLAG_AUTH | usm::FLAG_REPORTABLE,
            engine_id: &engine,
            boots,
            time,
            user: user.name.as_bytes(),
            keys: Some(&keys),
            salt: 0,
            context_engine_id: &engine,
            context_name: b"",
            pdu: get_pdu(1),
        })
        .unwrap();
        let reply = exchange(&socket, &bytes).await;
        let rx = usm::decode(&reply).unwrap();
        assert_eq!(rx.msg_id, msg_id, "boots {boots}, time {time}");
        assert!(
            usm::verify(&reply, &keys),
            "the time report for boots {boots}, time {time} is authenticated"
        );
        match manager.unwrap(&reply, msg_id).unwrap() {
            usm::Reply::Report(kind, _) => {
                assert_eq!(
                    kind,
                    ReportKind::NotInTimeWindows,
                    "boots {boots}, time {time}"
                )
            }
            usm::Reply::Pdu(pdu) => panic!("boots {boots}, time {time} was answered: {pdu:?}"),
        }
    }
    assert_answers(&socket, &manager).await;
    assert_running(&state, id).await;
    state.remove_server(id).await;
}
