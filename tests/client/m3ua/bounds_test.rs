//! The M3UA client's wiring, bounds and fail-closed rules, against a canned SGP over the lab TCP
//! transport (so they run on any host). The SGP is written here from RFC 4666 — header, TLVs,
//! padding — and what it sends back are jSS7's captured answers (`ss7_support::jss7`), with the
//! transaction ids rewritten to NetGet's. The real-peer evidence is `real_server_test.rs`.
use super::support::{jss7, unhex};
use netget::cli::management::ClientForm;
use netget::server::m3ua::sccp;
use netget::server::m3ua::tcap::{Component, TcKind, TcMessage};
use netget::state::app_state::AppState;
use netget::state::ClientId;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// An M3UA message from RFC 4666 section 3: version 1, class, type, length, then TLVs padded to
/// four octets with the padding outside the parameter length.
fn m3ua(class: u8, msg_type: u8, params: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, value) in params {
        body.extend_from_slice(&tag.to_be_bytes());
        body.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        body.extend_from_slice(value);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }
    let mut out = vec![1, 0, class, msg_type];
    out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// A DATA carrying `sccp` from point code 2 to 1, SI 3, NI 2, routing context 100.
fn data(sccp_bytes: &[u8]) -> Vec<u8> {
    let mut pd = vec![0, 0, 0, 2, 0, 0, 0, 1, 3, 2, 0, 0];
    pd.extend_from_slice(sccp_bytes);
    m3ua(
        1,
        1,
        &[(0x0006, 100u32.to_be_bytes().to_vec()), (0x0210, pd)],
    )
}

/// Read one M3UA message: (class, type, the Protocol Data's user part if it is DATA).
async fn read(s: &mut TcpStream) -> Option<(u8, u8, Option<Vec<u8>>)> {
    let mut h = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut h))
        .await
        .ok()?
        .ok()?;
    let len = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
    let mut body = vec![0u8; len - 8];
    s.read_exact(&mut body).await.ok()?;
    let mut pos = 0;
    let mut user = None;
    while pos + 4 <= body.len() {
        let tag = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let l = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        if tag == 0x0210 {
            user = Some(body[pos + 4 + 12..pos + l].to_vec());
        }
        pos += l.div_ceil(4) * 4;
    }
    Some((h[2], h[3], user))
}

/// Accept the ASP and acknowledge ASPUP and ASPAC (with NTFY AS-ACTIVE, as an SGP does).
async fn admit(listener: &TcpListener) -> TcpStream {
    let (mut s, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read(&mut s).await.map(|m| (m.0, m.1)),
        Some((3, 1)),
        "ASPUP first"
    );
    s.write_all(&m3ua(3, 4, &[])).await.unwrap();
    assert_eq!(
        read(&mut s).await.map(|m| (m.0, m.1)),
        Some((4, 1)),
        "then ASPAC"
    );
    s.write_all(&m3ua(4, 3, &[(0x0006, 100u32.to_be_bytes().to_vec())]))
        .await
        .unwrap();
    s.write_all(&m3ua(0, 1, &[(0x000d, vec![0, 1, 0, 3])]))
        .await
        .unwrap();
    s
}

/// The next TC message NetGet sends, skipping anything that is not DATA.
async fn next_tcap(s: &mut TcpStream) -> Option<TcMessage> {
    loop {
        let (class, _, user) = read(s).await?;
        if class == 1 {
            let ud = sccp::decode(&user?).unwrap();
            return Some(TcMessage::decode(&ud.data).unwrap());
        }
    }
}

/// Connect NetGet's ASP to a canned SGP on `listener`, which admits it; the connect waits for
/// ASPAC ACK, so the SGP runs alongside it.
async fn start(listener: TcpListener, handlers: Vec<Value>) -> (AppState, ClientId, TcpStream) {
    let port = listener.local_addr().unwrap().port();
    let sgp = tokio::spawn(async move { admit(&listener).await });
    let (state, result) = create(port, handlers).await;
    (state, result.unwrap(), sgp.await.unwrap())
}

async fn create(port: u16, handlers: Vec<Value>) -> (AppState, anyhow::Result<ClientId>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "m3ua".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Be an SMSC".into()),
        startup_params: Some(
            json!({"transport": "tcp", "routing_context": 100, "opc": 1, "dpc": 2,
            "local_gt": "31600000100", "remote_gt": "31600000200"}),
        ),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await;
    (state, id)
}

fn script(code: &str) -> Vec<Value> {
    vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": code}}),
    ]
}

/// The SRI-SM answer jSS7's HLR sent, readdressed to NetGet's transaction and invoke.
fn sri_answer(tid: &[u8], invoke_id: i64) -> Vec<u8> {
    let dtid = u32::from_be_bytes([tid[0], tid[1], tid[2], tid[3]]);
    unhex(
        &super::support::with_dtid(jss7::SRI_SM_END, dtid)
            .replace("a21f020100301a", &format!("a21f0201{invoke_id:02x}301a")),
    )
}

const CHAIN: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]; a = []
if t == "m3ua_connected":
    a = [{"type": "send_map_request", "operation": "sendRoutingInfoForSM",
          "argument": {"msisdn": "31628838002", "service_centre_address": "31611111111"}}]
elif t == "m3ua_map_received":
    r = [c for c in e["components"] if c.get("component") == "return_result_last"]
    if r and r[0]["operation"] == "sendRoutingInfoForSM":
        a = [{"type": "send_map_request", "operation": "mt-forwardSM",
              "argument": {"sm_rp_da": {"imsi": r[0]["result"]["imsi"]}, "sm_rp_oa": {"service_centre_address": "31611111111"},
                           "sms": {"originator": "31655500000", "text": "hi"}}}]
print(json.dumps({"actions": a}))"#;

#[tokio::test]
async fn the_models_request_reaches_the_wire_and_its_answer_drives_the_next() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_state, _id, mut sgp) = start(listener, script(CHAIN)).await;
    let begin = next_tcap(&mut sgp).await.expect("the model's SRI-SM");
    assert_eq!(begin.kind, TcKind::Begin);
    let Component::Invoke {
        invoke_id, opcode, ..
    } = &begin.components[0]
    else {
        panic!("{begin:?}")
    };
    assert_eq!(opcode.local(), Some(45));
    sgp.write_all(&data(&sri_answer(begin.otid.as_ref().unwrap(), *invoke_id)))
        .await
        .unwrap();
    // The next dialogue is the model acting on that answer: mt-forwardSM to the IMSI jSS7 named.
    let next = next_tcap(&mut sgp).await.expect("the model's mt-forwardSM");
    assert_eq!(next.kind, TcKind::Begin);
    let Component::Invoke {
        opcode, parameter, ..
    } = &next.components[0]
    else {
        panic!("{next:?}")
    };
    assert_eq!(opcode.local(), Some(44));
    // sm-RP-DA [0] IMSI 001010123456789 in TBCD.
    let da = &parameter.as_ref().unwrap().children[0];
    assert_eq!(hex::encode(&da.value), "00010121436587f9");
}

#[tokio::test]
async fn a_chain_of_model_turns_stops_at_the_followup_depth() {
    let echo = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]
a = [{"type": "send_map_request", "operation": "sendRoutingInfoForSM",
      "argument": {"msisdn": "31628838002", "service_centre_address": "31611111111"}}]
print(json.dumps({"actions": a}))"#;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_state, _id, mut sgp) = start(listener, script(echo)).await;
    let mut begins = 0;
    loop {
        let wait = tokio::time::timeout(Duration::from_secs(3), next_tcap(&mut sgp)).await;
        let Ok(Some(m)) = wait else { break };
        if m.kind != TcKind::Begin {
            continue;
        }
        begins += 1;
        assert!(begins <= 20, "the chain did not stop");
        let Component::Invoke { invoke_id, .. } = &m.components[0] else {
            panic!()
        };
        sgp.write_all(&data(&sri_answer(m.otid.as_ref().unwrap(), *invoke_id)))
            .await
            .unwrap();
    }
    // One from m3ua_connected (depth 0), then one per answer until depth 8.
    assert_eq!(
        begins,
        netget::client::m3ua::MAX_FOLLOWUP_DEPTH as usize,
        "follow-ups"
    );
}

#[tokio::test]
async fn an_inbound_dialogue_the_model_cannot_answer_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Only m3ua_connected is scripted; the map event goes to the unreachable model.
    let quiet = vec![
        json!({"event_pattern": "m3ua_connected", "handler": {"type": "static", "actions": []}}),
    ];
    let (_state, _id, mut sgp) = start(listener, quiet).await;
    sgp.write_all(&data(&unhex(jss7::SRI_SM_BEGIN)))
        .await
        .unwrap();
    let end = next_tcap(&mut sgp).await.expect("an answer");
    assert_eq!(end.kind, TcKind::End);
    assert_eq!(end.dtid.as_deref(), Some(&[0u8, 0, 0, 1][..]));
    // ReturnError systemFailure for invoke 0 — never a result the model did not give.
    assert_eq!(hex::encode(end.components[0].encode()), "a306020100020122");
}

#[tokio::test]
async fn a_silent_model_aborts_an_inbound_dialogue() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_state, _id, mut sgp) = start(
        listener,
        vec![json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}})],
    )
    .await;
    sgp.write_all(&data(&unhex(jss7::SRI_SM_BEGIN)))
        .await
        .unwrap();
    let abort = next_tcap(&mut sgp).await.expect("an answer");
    assert_eq!(abort.kind, TcKind::Abort);
    assert!(abort.components.is_empty());
}

#[tokio::test]
async fn an_sgp_that_refuses_aspup_fails_the_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let refuse = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = read(&mut s).await;
        // ERR, Refused - Management Blocking.
        s.write_all(&m3ua(0, 0, &[(0x000c, vec![0, 0, 0, 0x0d])]))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
    let (_state, result) = create(port, vec![]).await;
    let e = format!("{:#}", result.expect_err("the connect must fail"));
    assert!(e.contains("Refused - Management Blocking"), "{e}");
    refuse.abort();
}
