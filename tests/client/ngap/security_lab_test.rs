//! NetGet's gNB with a subscriber's credentials against NetGet's own AMF, in-process over the
//! **non-standard lab TCP transport** — the only way to run the UE side of 5G-AKA, the security
//! mode procedure, registration and a PDU session on macOS. Both ends are NetGet's, so this is
//! not interoperability evidence (that is `real_server_test.rs` against Open5GS); it is the
//! session logic and the model's view of it.
//!
//! No LLM calls: python policies stand in for both models.
use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const K: &str = "465B5CE8B199B49FAA5F0A2EE238A6BC";
const OPC: &str = "E8ED289DEBA952E4283B54E88E6183CA";

const AMF_POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
          "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
elif t == "ngap_registration_request":
    a = [{"type": "send_registration_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"], "allowed_nssai": [{"sst": 1}]}]
elif t == "ngap_pdu_session_establishment_request":
    a = [{"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"], "ue_ipv4": "10.45.0.7", "reachable_addresses": ["10.45.0.1"]}]
print(json.dumps({"actions": a}))"#;

const GNB_POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
suci = {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"}, "routing_indicator": "0000", "msin": "0000000001"}
a = []
if t == "ngap_connected":
    a = [{"type": "ngap_initial_ue_message", "nas": {"message": "registration_request", "mobile_identity": suci}}]
elif t == "ngap_ue_registered":
    a = [{"type": "ngap_pdu_session_request", "ran_ue_ngap_id": e["ran_ue_ngap_id"], "dnn": "internet", "s_nssai": {"sst": 1}}]
print(json.dumps({"actions": a}))"#;

async fn wait_event(state: &AppState, id: ClientId, event: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(e) = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == event)
            {
                return e["request"].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {event} within 30s"))
}

async fn amf(subscriber_opc: &str) -> u16 {
    let state = Box::leak(Box::new(AppState::new_with_options(
        false,
        "http://127.0.0.1:1".into(),
    )));
    let (tx, _) = mpsc::unbounded_channel();
    let up = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let id = ServerForm {
        protocol: "ngap".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an AMF".into()),
        startup_params: Some(json!({"transport": "tcp", "user_plane_address": up.to_string(),
            "subscribers": [{"supi": "imsi-001010000000001", "subscriber_key": K, "subscriber_opc": subscriber_opc}]})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": AMF_POLICY}})]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

async fn gnb(port: u16) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "ngap".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Be a gNB".into()),
        startup_params: Some(json!({"transport": "tcp", "supi": "imsi-001010000000001",
            "subscriber_key": K, "subscriber_opc": OPC})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": GNB_POLICY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap();
    (state, id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gnbs_ue_registers_and_gets_a_session_from_netgets_amf() {
    let port = amf(OPC).await;
    let (state, id) = gnb(port).await;
    let reg = wait_event(&state, id, "ngap_ue_registered").await;
    assert_eq!(reg["supi"], "imsi-001010000000001", "{reg}");
    assert_eq!(reg["k_gnb_verified"], true, "{reg}");
    assert_eq!(reg["allowed_nssai"], json!([{"sst": 1}]));
    let s = wait_event(&state, id, "ngap_pdu_session_established").await;
    assert_eq!(s["result"], "accepted", "{s}");
    assert_eq!(s["ue_ipv4"], "10.45.0.7");
    assert_eq!(s["dnn"], "internet");
    assert_eq!(s["upf_tunnel"]["address"], "127.0.0.1");
    // The model never saw an Authentication Request or a Security Mode Command.
    let all = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await;
    let text = serde_json::to_string(&all).unwrap();
    assert!(!text.contains("authentication_request") && !text.contains("security_mode_command"));
    assert!(
        !text.to_ascii_uppercase().contains(K),
        "the key reached an event"
    );
}

/// The AMF holds a different OPc: the UE cannot verify its AUTN, answers MAC failure, and the
/// model sees the Authentication Reject that follows — never a registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_whose_network_has_another_key_reports_mac_failure() {
    let port = amf("00000000000000000000000000000001").await;
    let (state, id) = gnb(port).await;
    let dl = wait_event(&state, id, "ngap_downlink_nas_transport").await;
    assert_eq!(dl["nas"]["message"], "authentication_reject", "{dl}");
    assert!(state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .all(|e| serde_json::to_value(e).unwrap()["event_type"] != "ngap_ue_registered"));
}
