//! NetGet's SNMPv3 manager against hostile replies.
//!
//! - **Nested UsmSecurityParameters.** A reply's msgSecurityParameters contents are BER of their
//!   own, which the whole-datagram depth screen reads as one primitive OCTET STRING and never
//!   descends into. A userName or engineID written as `24 80` repeated reaches `rasn`'s unbounded
//!   recursion unless those contents are screened as well, and thirty thousand levels overflow
//!   the stack and abort the process. Both of the manager's decode paths — the discovery report
//!   (`Manager::learn`) and every reply after it (`Manager::unwrap_reply`) — must refuse it, and a
//!   fake agent on 127.0.0.1 that answers discovery with one before the real report must not stop
//!   the client from connecting.
//! - **Out-of-range clocks.** The discovery report is unauthenticated, and snmpEngineBoots and
//!   snmpEngineTime are `0..2147483647`. A report carrying `i64::MAX` is refused rather than
//!   stored, because every later request adds the elapsed seconds to it; an authenticated report
//!   carrying one is refused rather than believed.
//!
//! No LLM calls and no external tools.

use netget::cli::management::ClientForm;
use netget::server::snmp::usm::{self, User};
use netget::state::app_state::AppState;
use netget::state::ClientStatus;
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc;

const DEPTH: usize = 30_000;
/// The depth sent over UDP. macOS caps a datagram at 9216 bytes (net.inet.udp.maxdgram), and
/// at two bytes a level this stays under it while remaining far past `MAX_BER_DEPTH`; the
/// direct decode checks above use `DEPTH`.
const UDP_DEPTH: usize = 4_000;

fn engine() -> Vec<u8> {
    hex::decode("8000000005a1b2c3d4e5f6071a").unwrap()
}

fn noauth() -> User {
    User::from_json(&json!({"name": "x"})).unwrap()
}

fn sha256() -> User {
    User::from_json(
        &json!({"name": "a", "auth_protocol": "sha256", "auth_password": "sha256-auth-pass"}),
    )
    .unwrap()
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

/// A non-negative INTEGER.
fn int(v: i64) -> Vec<u8> {
    assert!(v >= 0);
    let bytes = v.to_be_bytes();
    let mut at = 0;
    while at < 7 && bytes[at] == 0 && bytes[at + 1] & 0x80 == 0 {
        at += 1;
    }
    tlv(0x02, &bytes[at..])
}

/// A well-formed v3 message, shallow everywhere the outer screen looks, whose
/// UsmSecurityParameters' engineID nests `depth` constructed OCTET STRINGs with no
/// end-of-contents markers.
fn nested_usm_message(msg_id: i64, depth: usize) -> Vec<u8> {
    let mut usm = vec![0x30, 0x80];
    for _ in 0..depth {
        usm.extend([0x24, 0x80]);
    }
    let header = tlv(
        0x30,
        &[
            int(msg_id),
            int(usm::MAX_MESSAGE_SIZE),
            tlv(0x04, &[0]),
            int(usm::USM_SECURITY_MODEL),
        ]
        .concat(),
    );
    let pdu = tlv(
        0xa8, // Report
        &[int(1), int(0), int(0), tlv(0x30, &[])].concat(),
    );
    let scoped = tlv(0x30, &[tlv(0x04, &[]), tlv(0x04, &[]), pdu].concat());
    let message = tlv(0x30, &[int(3), header, tlv(0x04, &usm), scoped].concat());
    assert!(message.len() <= 65_507);
    assert!(
        netget::server::snmp::check_ber_structure(&message, netget::server::snmp::MAX_BER_DEPTH)
            .is_ok(),
        "the outer message must be shallow, or the test proves nothing"
    );
    message
}

fn report_pdu() -> rasn_snmp::v2::Pdus {
    rasn_snmp::v2::Pdus::Report(rasn_snmp::v2::Report(rasn_snmp::v2::Pdu {
        request_id: 1,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![rasn_snmp::v2::VarBind {
            name: rasn::types::ObjectIdentifier::new_unchecked(
                usm::ReportKind::UnknownEngineIds.oid().into(),
            ),
            value: rasn_snmp::v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                rasn_smi::v2::ApplicationSyntax::Counter(rasn_smi::v1::Counter(1)),
            )),
        }],
    }))
}

/// A report from `engine()` with the given clock, authenticated under `keys` when given.
fn report(msg_id: i64, boots: i64, time: i64, user: &[u8], keys: Option<&usm::Keys>) -> Vec<u8> {
    let engine = engine();
    usm::encode(usm::Outgoing {
        msg_id,
        max_size: usm::MAX_MESSAGE_SIZE,
        flags: if keys.is_some() { usm::FLAG_AUTH } else { 0 },
        engine_id: &engine,
        boots,
        time,
        user,
        keys,
        salt: 0,
        context_engine_id: &engine,
        context_name: b"",
        pdu: report_pdu(),
    })
    .unwrap()
}

fn get_pdu() -> rasn_snmp::v2::Pdus {
    rasn_snmp::v2::Pdus::GetRequest(rasn_snmp::v2::GetRequest(rasn_snmp::v2::Pdu {
        request_id: 3,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![],
    }))
}

#[test]
fn learn_and_unwrap_refuse_nested_security_parameters() {
    let manager = usm::Manager::new(noauth());
    let (msg_id, _) = manager.discovery().unwrap();
    let error = manager
        .learn(&nested_usm_message(msg_id, DEPTH), msg_id)
        .expect_err("a nested discovery report was learnt")
        .to_string();
    assert!(error.contains("UsmSecurityParameters"), "{error}");
    assert!(manager.engine_id().is_none());

    manager
        .learn(&report(msg_id, 1, 0, b"", None), msg_id)
        .unwrap();
    let request = manager.wrap_request(get_pdu(), b"").unwrap();
    let outstanding = usm::decode(&request).unwrap().msg_id;
    let error = match manager.unwrap_reply(&nested_usm_message(outstanding, DEPTH)) {
        Ok(_) => panic!("a nested reply was opened"),
        Err(e) => e.to_string(),
    };
    assert!(error.contains("UsmSecurityParameters"), "{error}");
}

#[test]
fn a_discovery_report_with_an_out_of_range_clock_is_not_learnt() {
    for (boots, time) in [
        (1, i64::MAX),
        (1, -1),
        (1, usm::MAX_ENGINE_TIME + 1),
        (-1, 0),
        (i64::MAX, 0),
        (usm::MAX_ENGINE_BOOTS + 1, 0),
    ] {
        let manager = usm::Manager::new(noauth());
        let (msg_id, _) = manager.discovery().unwrap();
        assert!(
            manager
                .learn(&report(msg_id, boots, time, b"", None), msg_id)
                .is_err(),
            "boots {boots}, time {time} was learnt"
        );
        assert!(manager.engine_id().is_none());
    }
    // The top of the range is learnt, and the next request's clock stays inside it.
    let manager = usm::Manager::new(noauth());
    let (msg_id, _) = manager.discovery().unwrap();
    manager
        .learn(&report(msg_id, 1, usm::MAX_ENGINE_TIME, b"", None), msg_id)
        .unwrap();
    let request = manager.wrap_request(get_pdu(), b"").unwrap();
    let time: i64 = usm::decode(&request)
        .unwrap()
        .usm
        .authoritative_engine_time
        .try_into()
        .unwrap();
    assert_eq!(time, usm::MAX_ENGINE_TIME);
}

#[test]
fn an_authenticated_report_with_an_out_of_range_clock_is_not_believed() {
    let user = sha256();
    let keys = user.localize(&engine());
    let manager = usm::Manager::new(user.clone());
    let (msg_id, _) = manager.discovery().unwrap();
    manager
        .learn(&report(msg_id, 4, 100, b"", None), msg_id)
        .unwrap();
    for (boots, time) in [(4, i64::MAX), (4, -1), (i64::MIN, 100)] {
        let request = manager.wrap_request(get_pdu(), b"").unwrap();
        let outstanding = usm::decode(&request).unwrap().msg_id;
        let reply = report(outstanding, boots, time, user.name.as_bytes(), Some(&keys));
        assert!(usm::verify(&reply, &keys), "the report is correctly signed");
        assert!(
            manager.unwrap_reply(&reply).is_err(),
            "boots {boots}, time {time} was believed"
        );
    }
    // The clock learnt from discovery is the one still in use.
    let request = manager.wrap_request(get_pdu(), b"").unwrap();
    let rx = usm::decode(&request).unwrap();
    let boots: i64 = rx.usm.authoritative_engine_boots.try_into().unwrap();
    let time: i64 = rx.usm.authoritative_engine_time.try_into().unwrap();
    assert_eq!(boots, 4);
    assert!((100..200).contains(&time), "{time}");
}

/// A fake agent answers the client's discovery probe first with a nested message, then with
/// a real report. The client survives the first, learns from the second and connects.
#[tokio::test]
async fn a_client_survives_a_nested_discovery_reply_and_connects() {
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = agent.local_addr().unwrap();
    let fake = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let (n, from) = agent.recv_from(&mut buf).await.unwrap();
        let probe = usm::decode(&buf[..n]).expect("the client's probe decodes");
        agent
            .send_to(&nested_usm_message(probe.msg_id, UDP_DEPTH), from)
            .await
            .unwrap();
        agent
            .send_to(&report(probe.msg_id, 1, 0, b"", None), from)
            .await
            .unwrap();
        agent
    });

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let created = ClientForm {
        protocol: "snmp".into(),
        remote_addr: Some(addr.to_string()),
        instruction: Some(String::new()),
        startup_params: Some(
            json!({"version": "v3", "v3_user": {"name": "x"}, "timeout_ms": 3000, "retries": 0}),
        ),
        event_handlers: Some(vec![
            json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}}),
        ]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await;
    let id = created.unwrap_or_else(|e| panic!("the v3 client did not start: {e:#}"));
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match state.get_client(id).await.map(|c| c.status) {
                Some(ClientStatus::Connected) => break,
                Some(ClientStatus::Error(e)) => panic!("the client failed: {e}"),
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("the client never connected");
    let _agent = tokio::time::timeout(Duration::from_secs(5), fake)
        .await
        .expect("the fake agent never finished")
        .unwrap();
    state.remove_client(id).await;
}
