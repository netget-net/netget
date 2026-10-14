//! NetGet's AMF end to end, in-process, over the **non-standard lab TCP transport** — the only
//! transport this suite can open on macOS. Everything above the socket is the code the SCTP path
//! runs; nothing here is evidence of interoperability (that is `real_client_test.rs`, Linux only).
//!
//! The gNB side is hand-built: its NG Setup Request is UERANSIM's own captured octets, and its
//! other PDUs come from the codec, which `codec_test.rs` pins to literal vectors.
//!
//! LLM budget: **two calls**, both in `the_model_admits_and_rejects`. Every other test uses a
//! script or static handler, or points at an unreachable endpoint to prove a call could not have
//! succeeded.
use super::support::{assert_ngap_clean, lab_frame, read_lab, unhex};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::server::ngap::codec::{self, Cause, PduKind};
use netget::server::ngap::nas;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";
const UERANSIM_NG_SETUP: &str = "00150041000004001b00090000f1105000000001005240140880554552414e53494d2d676e622d312d312d310066001000000000010000f110000010080102030015400140";
const REGISTRATION_REQUEST: &str =
    "7e 00 41 79 00 0d 01 00 f1 10 00 00 00 00 00 00 00 00 10 2e 02 f0 f0";
const WIRE: Duration = Duration::from_secs(30);

/// The AMF policy the script tests run: admit any gNB with its own PLMN, ask each UE for its
/// identity, then reject it as an illegal UE and release it.
const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
          "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1, "sd": "010203"}]}]}]
elif t == "ngap_initial_ue_message":
    a = [{"type": "send_downlink_nas_transport", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "ran_ue_ngap_id": e["ran_ue_ngap_id"], "nas": {"message": "identity_request", "identity_type": "suci"}}]
elif t == "ngap_uplink_nas_transport" and e["nas"].get("message") == "identity_response":
    ids = {"amf_ue_ngap_id": e["amf_ue_ngap_id"], "ran_ue_ngap_id": e["ran_ue_ngap_id"]}
    a = [dict(type="send_downlink_nas_transport", nas={"message": "registration_reject", "cause": "illegal_ue"}, **ids),
         dict(type="send_ue_context_release_command", cause="nas/normal-release", **ids)]
print(json.dumps({"actions": a}))"#;

fn uli() -> Value {
    json!({"cgi": {"plmn": "001-01", "cell_id": 16}, "tai": {"plmn": "001-01", "tac": 1}})
}

async fn start(
    instruction: &str,
    handlers: Option<Vec<Value>>,
    llm: &str,
) -> (AppState, ServerId, u16, mpsc::UnboundedReceiver<String>) {
    let state = AppState::new_with_options(false, llm.into());
    state.set_ollama_model(Some("mock-model".into())).await;
    state
        .set_llm_client(netget::llm::OllamaClient::new(llm))
        .await;
    let (tx, rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "ngap".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(instruction.into()),
        startup_params: Some(json!({"transport": "tcp"})),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port, rx)
}

/// Everything the server said on its status channel so far, for failure messages.
fn status_lines(rx: &mut mpsc::UnboundedReceiver<String>) -> String {
    let mut out = Vec::new();
    while let Ok(line) = rx.try_recv() {
        out.push(line);
    }
    out.join("\n")
}

/// A gNB over the lab transport that keeps every PDU in both directions for the oracle.
struct Gnb {
    stream: TcpStream,
    log: Vec<(bool, Vec<u8>)>,
}

impl Gnb {
    async fn connect(port: u16) -> Gnb {
        Gnb {
            stream: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            log: Vec::new(),
        }
    }
    async fn send(&mut self, pdu: &[u8]) {
        self.stream.write_all(&lab_frame(pdu)).await.unwrap();
        self.log.push((false, pdu.to_vec()));
    }
    async fn recv(&mut self, what: &str) -> codec::Pdu {
        let bytes = tokio::time::timeout(WIRE, read_lab(&mut self.stream))
            .await
            .unwrap_or_else(|_| panic!("no answer within {WIRE:?}: {what}"))
            .unwrap_or_else(|e| panic!("connection ended waiting for {what}: {e}"));
        self.log.push((true, bytes.clone()));
        codec::decode_pdu(&bytes)
            .unwrap_or_else(|e| panic!("NetGet sent an undecodable PDU ({what}): {e}"))
    }
    async fn setup(&mut self) -> codec::Pdu {
        self.send(&unhex(UERANSIM_NG_SETUP)).await;
        self.recv("NG Setup answer").await
    }
}

fn nas_of(pdu: &codec::Pdu) -> Value {
    nas::decode(&codec::parse_nas_transport(pdu).unwrap().nas)
}

fn cause_of(pdu: &codec::Pdu) -> Value {
    codec::parse_cause_message(pdu).unwrap()
}

async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

#[tokio::test]
async fn a_scripted_amf_admits_the_gnb_and_rejects_the_ue() {
    let handlers = vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}}),
    ];
    let (state, id, port, mut rx) = start("Be an AMF", Some(handlers), UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;

    let resp = gnb.setup().await;
    assert_eq!(
        (resp.kind, resp.procedure_code),
        (PduKind::Successful, codec::PROC_NG_SETUP),
        "{}\n{}",
        resp.label(),
        status_lines(&mut rx)
    );
    let r = codec::parse_ng_setup_response(&resp).unwrap();
    assert_eq!(r["amf_name"], "netget-amf");
    assert_eq!(r["served_guami"][0]["amf_region_id"], 2);
    assert_eq!(
        r["plmn_support"][0]["slices"],
        json!([{"sst": 1, "sd": "010203"}])
    );

    // The model saw UERANSIM's gNB decoded, not as octets.
    let setup_events = events(&state, id, "ngap_ng_setup_request").await;
    assert_eq!(
        setup_events[0]["ran_node_name"], "UERANSIM-gnb-1-1-1",
        "{setup_events:?}"
    );

    gnb.send(
        &codec::initial_ue_message(7, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
            .unwrap(),
    )
    .await;
    let dl = gnb.recv("identity request").await;
    assert_eq!(dl.procedure_code, codec::PROC_DOWNLINK_NAS_TRANSPORT);
    let t = codec::parse_nas_transport(&dl).unwrap();
    assert_eq!(t.ran_ue_ngap_id, 7, "the gNB's own id is echoed");
    let amf_id = t.amf_ue_ngap_id;
    assert_eq!(nas::decode(&t.nas)["identity_type"], "suci");

    let initial = events(&state, id, "ngap_initial_ue_message").await;
    let seen = &initial[0];
    assert_eq!(seen["amf_ue_ngap_id"], amf_id);
    assert_eq!(
        seen["nas"]["mobile_identity"]["msin"], "0000000001",
        "{seen}"
    );
    assert_eq!(seen["user_location"]["tai"]["tac"], 1, "{seen}");
    assert_eq!(seen["rrc_establishment_cause"], "mo-Signalling");

    let identity = nas::encode(
        &json!({"message": "identity_response", "mobile_identity": {"type": "suci", "plmn": "001-01", "msin": "0000000001"}}),
        nas::UPLINK_MESSAGES,
    )
    .unwrap();
    gnb.send(&codec::uplink_nas_transport(amf_id, 7, &identity, &uli()).unwrap())
        .await;
    let reject = gnb.recv("registration reject").await;
    assert_eq!(
        nas_of(&reject)["cause"],
        json!({"value": 3, "name": "illegal_ue"})
    );
    let release = gnb.recv("UE context release").await;
    assert_eq!(
        (release.kind, release.procedure_code),
        (PduKind::Initiating, codec::PROC_UE_CONTEXT_RELEASE)
    );
    gnb.send(&codec::ue_context_release_complete(amf_id, 7).unwrap())
        .await;

    // An NG Reset is acknowledged by Rust with no policy involved.
    gnb.send(&codec::ng_reset(&Cause::misc(codec::MISC_OM_INTERVENTION), None).unwrap())
        .await;
    let ack = gnb.recv("NG Reset Acknowledge").await;
    assert_eq!(
        (ack.kind, ack.procedure_code),
        (PduKind::Successful, codec::PROC_NG_RESET)
    );

    assert_ngap_clean(&gnb.log);
}

#[tokio::test]
async fn the_model_admits_and_rejects() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ngap_ng_setup_request")
            .and_event_data_contains("ran_node_name", "UERANSIM-gnb-1-1-1")
            .respond_with_actions(json!([{
                "type": "send_ng_setup_response",
                "amf_name": "mocked-amf",
                "served_guami": [{"plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 4, "amf_set_id": 3, "amf_pointer": 1}],
                "plmn_support": [{"plmn": {"mcc": "001", "mnc": "01"}, "slices": [{"sst": 1}]}]
            }]))
            .expect_calls(1)
            .and()
            .on_event("ngap_initial_ue_message")
            .respond_with_actions_from_event(|e| json!([{
                "type": "send_downlink_nas_transport",
                "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                "ran_ue_ngap_id": e["ran_ue_ngap_id"],
                "nas": {"message": "registration_reject", "cause": "plmn_not_allowed"}
            }]))
            .expect_calls(1)
            .build(),
    )
    .await
    .unwrap();
    let (_state, _id, port, _rx) = start("Be an AMF for PLMN 001-01", None, &mock.base_url()).await;
    let mut gnb = Gnb::connect(port).await;
    let resp = gnb.setup().await;
    assert_eq!(
        codec::parse_ng_setup_response(&resp).unwrap()["amf_name"],
        "mocked-amf"
    );
    gnb.send(
        &codec::initial_ue_message(1, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
            .unwrap(),
    )
    .await;
    let reject = gnb.recv("registration reject").await;
    assert_eq!(nas_of(&reject)["cause"]["name"], "plmn_not_allowed");
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.unwrap();
    assert_ngap_clean(&gnb.log);
}

// ----------------------------------------------------------------------------------------------
// Fail closed
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_model_refuses_ng_setup() {
    let (_s, _i, port, _rx) = start("Be an AMF", None, UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;
    let resp = gnb.setup().await;
    assert_eq!(
        (resp.kind, resp.procedure_code),
        (PduKind::Unsuccessful, codec::PROC_NG_SETUP),
        "{}",
        resp.label()
    );
    let c = cause_of(&resp);
    assert_eq!(c["cause"]["group"], "misc", "{c}");
    assert!(
        c["cause"]["value"] == "unspecified"
            || c["cause"]["value"] == "control-processing-overload",
        "{c}"
    );
    assert!(
        c["time_to_wait"].is_string(),
        "a backend failure tells the gNB when to retry: {c}"
    );
    assert_ngap_clean(&gnb.log);
}

#[tokio::test]
async fn no_policy_refuses_ng_setup_with_om_intervention() {
    let (_s, _i, port, _rx) = start("", None, UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;
    let resp = gnb.setup().await;
    assert_eq!(resp.kind, PduKind::Unsuccessful);
    assert_eq!(
        cause_of(&resp)["cause"],
        json!({"group": "misc", "value": "om-intervention"})
    );
}

#[tokio::test]
async fn a_silent_policy_refuses_ng_setup() {
    let handlers = vec![
        json!({"event_pattern": "ngap_ng_setup_request", "handler": {"type": "static", "actions": [{"type": "wait_for_more"}]}}),
    ];
    let (_s, _i, port, _rx) = start("Be an AMF", Some(handlers), UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;
    let resp = gnb.setup().await;
    assert_eq!(resp.kind, PduKind::Unsuccessful);
    let c = cause_of(&resp);
    assert_eq!(c["cause"], json!({"group": "misc", "value": "unspecified"}));
    assert!(
        c.get("time_to_wait").is_none(),
        "silence is not an outage: {c}"
    );
}

fn admit_only() -> Value {
    json!({"event_pattern": "ngap_ng_setup_request", "handler": {"type": "static", "actions": [{
        "type": "send_ng_setup_response", "amf_name": "amf",
        "served_guami": [{"plmn": "001-01", "amf_region_id": 1, "amf_set_id": 1, "amf_pointer": 1}],
        "plmn_support": [{"plmn": "001-01", "slices": [{"sst": 1}]}]}]}})
}

#[tokio::test]
async fn a_failed_model_rejects_the_ue_and_releases_it() {
    let (_s, _i, port, _rx) = start("Be an AMF", Some(vec![admit_only()]), UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;
    assert_eq!(gnb.setup().await.kind, PduKind::Successful);
    gnb.send(
        &codec::initial_ue_message(3, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
            .unwrap(),
    )
    .await;
    let reject = gnb.recv("fail-closed registration reject").await;
    let n = nas_of(&reject);
    assert_eq!(n["message"], "registration_reject", "{n}");
    assert!(
        n["cause"]["name"] == "protocol_error_unspecified" || n["cause"]["name"] == "congestion",
        "never an accept: {n}"
    );
    let release = gnb.recv("release").await;
    assert_eq!(release.procedure_code, codec::PROC_UE_CONTEXT_RELEASE);
    assert_ngap_clean(&gnb.log);
}

#[tokio::test]
async fn a_silent_model_rejects_the_ue() {
    let handlers = vec![
        admit_only(),
        json!({"event_pattern": "ngap_initial_ue_message", "handler": {"type": "static", "actions": []}}),
    ];
    let (_s, _i, port, _rx) = start("Be an AMF", Some(handlers), UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;
    assert_eq!(gnb.setup().await.kind, PduKind::Successful);
    gnb.send(
        &codec::initial_ue_message(3, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
            .unwrap(),
    )
    .await;
    let reject = gnb.recv("fail-closed registration reject").await;
    assert_eq!(
        nas_of(&reject)["cause"]["name"],
        "protocol_error_unspecified"
    );
    assert_eq!(
        gnb.recv("release").await.procedure_code,
        codec::PROC_UE_CONTEXT_RELEASE
    );
}

// ----------------------------------------------------------------------------------------------
// Refusals Rust makes with no model
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn protocol_refusals_need_no_model() {
    let (_s, _i, port, _rx) = start("Be an AMF", Some(vec![admit_only()]), UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;

    // Before NG Setup, an Initial UE Message is not compatible with the AMF's state.
    gnb.send(
        &codec::initial_ue_message(1, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
            .unwrap(),
    )
    .await;
    let ei = gnb.recv("error indication before setup").await;
    assert_eq!(ei.procedure_code, codec::PROC_ERROR_INDICATION);
    assert_eq!(
        cause_of(&ei)["cause"]["value"],
        "message-not-compatible-with-receiver-state"
    );

    // A PDU that is not APER: transfer syntax error, and the association survives.
    gnb.send(&[0xff, 0xff, 0xff]).await;
    let ei = gnb.recv("error indication for garbage").await;
    assert_eq!(cause_of(&ei)["cause"]["value"], "transfer-syntax-error");

    assert_eq!(gnb.setup().await.kind, PduKind::Successful);
    // An Uplink NAS Transport for a UE this AMF never allocated.
    gnb.send(&codec::uplink_nas_transport(99, 1, &unhex("7e 00 59 14"), &uli()).unwrap())
        .await;
    let ei = gnb.recv("unknown UE").await;
    let c = cause_of(&ei);
    assert_eq!(
        c["cause"],
        json!({"group": "radioNetwork", "value": "unknown-local-UE-NGAP-ID"})
    );
    assert_eq!(c["amf_ue_ngap_id"], 99);
    // The garbage the test sent (entry 2) is not NGAP and is left out of the oracle.
    let judged: Vec<_> = gnb
        .log
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, x)| x.clone())
        .collect();
    assert_ngap_clean(&judged);
}

#[tokio::test]
async fn an_oversized_lab_frame_is_refused_and_ends_the_connection() {
    let (_s, _i, port, _rx) = start("Be an AMF", Some(vec![admit_only()]), UNREACHABLE_LLM).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // Declares one octet over the bound and sends nothing more: the length alone is refused.
    let declared = (codec::MAX_PDU_LEN as u32 + 1).to_be_bytes();
    stream.write_all(&declared).await.unwrap();
    let ei = codec::decode_pdu(
        &tokio::time::timeout(WIRE, read_lab(&mut stream))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cause_of(&ei)["cause"]["value"], "transfer-syntax-error");
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(WIRE, tokio::io::AsyncReadExt::read(&mut stream, &mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "the framing is lost, so the connection closes");
    // One octet less is a frame NetGet reads (and refuses as APER, keeping the connection).
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut frame = (codec::MAX_PDU_LEN as u32).to_be_bytes().to_vec();
    frame.extend(vec![0xffu8; codec::MAX_PDU_LEN]);
    stream.write_all(&frame).await.unwrap();
    let ei = codec::decode_pdu(
        &tokio::time::timeout(WIRE, read_lab(&mut stream))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cause_of(&ei)["cause"]["value"], "transfer-syntax-error");
}

#[tokio::test]
async fn the_ue_context_table_is_bounded() {
    // A silent policy: every UE is rejected and released, but the gNB never confirms the release,
    // so every context stays held — exactly what a gNB that ignores releases would do.
    let handlers = vec![
        admit_only(),
        json!({"event_pattern": "ngap_initial_ue_message", "handler": {"type": "static", "actions": []}}),
    ];
    let (_s, _i, port, _rx) = start("Be an AMF", Some(handlers), UNREACHABLE_LLM).await;
    let mut gnb = Gnb::connect(port).await;
    assert_eq!(gnb.setup().await.kind, PduKind::Successful);
    let cap = netget::server::ngap::MAX_UE_CONTEXTS as u64;
    for ran in 0..cap {
        gnb.send(
            &codec::initial_ue_message(ran, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
                .unwrap(),
        )
        .await;
        gnb.recv("reject").await;
        gnb.recv("release").await;
    }
    gnb.send(
        &codec::initial_ue_message(cap, &unhex(REGISTRATION_REQUEST), &uli(), "mo-Signalling")
            .unwrap(),
    )
    .await;
    let ei = gnb.recv("refusal past the cap").await;
    assert_eq!(
        ei.procedure_code,
        codec::PROC_ERROR_INDICATION,
        "{}",
        ei.label()
    );
    let c = cause_of(&ei);
    assert_eq!(c["cause"]["value"], "control-processing-overload", "{c}");
    assert_eq!(c["ran_ue_ngap_id"], cap);
    // A released context frees a slot.
    gnb.send(&codec::ue_context_release_complete(1, 0).unwrap())
        .await;
    gnb.send(
        &codec::initial_ue_message(
            cap + 1,
            &unhex(REGISTRATION_REQUEST),
            &uli(),
            "mo-Signalling",
        )
        .unwrap(),
    )
    .await;
    assert_eq!(
        gnb.recv("served again").await.procedure_code,
        codec::PROC_DOWNLINK_NAS_TRANSPORT
    );
}
