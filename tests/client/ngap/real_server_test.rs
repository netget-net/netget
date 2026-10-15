//! NetGet's gNB against **Open5GS's AMF** (`open5gs-amfd`, an independent C implementation using
//! asn1c's NGAP), over a real SCTP association on Linux, with a live capture read back by
//! tshark's ngap dissector.
//!
//! The AMF runs alone, which is the cheapest honest configuration: NG Setup needs nothing else,
//! and an Initial UE Message carrying a 5G-GUTI the AMF never issued makes it ask the UE for its
//! identity — a Downlink NAS Transport it builds without any other network function. The model's
//! Identity Response (a SUCI) is then processed: the AMF accepts the identity and goes looking
//! for an AUSF, which does not exist here, so authentication cannot complete.
//!
//! Fails rather than skips without `open5gs-amfd` (Ubuntu: the `open5gs-amf` package from
//! ppa:open5gs/latest), dumpcap or tshark. No LLM calls: a python policy is the model.
use super::support::{assert_capture, LiveCapture};
use crate::helpers::real_server::{InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::server::ngap::codec;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const HINT: InstallHint = InstallHint {
    brew: "(none: Open5GS's AMF needs SCTP, which macOS lacks)",
    apt: "open5gs-amf (after: sudo add-apt-repository ppa:open5gs/latest)",
};

const AMF_CONFIG: &str = "logger:
  file:
    path: {dir}/amf.log
  level: info
global:
  max:
    ue: 64
amf:
  sbi:
    server:
      - address: 127.0.0.1
        port: {port1}
    client:
      scp:
        - uri: http://127.0.0.1:{port2}
  ngap:
    server:
      - address: 127.0.0.1
        port: {port}
  guami:
    - plmn_id:
        mcc: 001
        mnc: 01
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: 001
        mnc: 01
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 001
        mnc: 01
      s_nssai:
        - sst: 1
  security:
    integrity_order : [ NIA2, NIA1, NIA0 ]
    ciphering_order : [ NEA0, NEA1, NEA2 ]
  network_name:
    full: NetGetTest
    short: NetGet
  amf_name: open5gs-amf-netget
  time:
    t3512:
      value: 540
";

/// The model as a gNB: bring one UE in with a 5G-GUTI the AMF never assigned, and when the AMF
/// asks who it is, answer with a null-scheme SUCI.
const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
suci = {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"}, "routing_indicator": "0000", "msin": "0000000123"}
a = []
if t == "ngap_connected":
    a = [{"type": "ngap_initial_ue_message", "nas": {"message": "registration_request",
          "registration_type": "initial",
          "mobile_identity": {"type": "5g_guti", "plmn": {"mcc": "001", "mnc": "01"},
                              "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0, "tmsi": 3735928559}}}]
elif t == "ngap_downlink_nas_transport" and e["nas"].get("message") == "identity_request":
    a = [{"type": "ngap_uplink_nas_transport", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "ran_ue_ngap_id": e["ran_ue_ngap_id"], "nas": {"message": "identity_response", "mobile_identity": suci}}]
print(json.dumps({"actions": a}))"#;

async fn wait_event(
    state: &AppState,
    id: ClientId,
    event: &str,
    secs: u64,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == event && pred(&e["request"]))
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {event} event within {secs}s"))
}

#[tokio::test]
async fn netgets_gnb_sets_up_n2_with_open5gs_and_its_ue_is_identified() {
    let amf = RealServer::builder("open5gs-amfd", HINT)
        .config_file("amf.yaml", AMF_CONFIG)
        .extra_ports(2)
        .args(["-c", "{dir}/amf.yaml"])
        .ready_when_log_matches(r"ngap_server\(\)")
        .without_tcp_readiness()
        .start()
        .await
        .unwrap();
    let port: u16 = amf.addr().rsplit(':').next().unwrap().parse().unwrap();
    let capture = LiveCapture::start(port).await;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "ngap".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Be a gNB".into()),
        startup_params: Some(json!({"transport": "sctp", "mcc": "001", "mnc": "01", "tac": 1, "sst": 1})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap();

    // NG Setup: the AMF checked NetGet's PLMN, TAC and slice against its own configuration.
    let connected = wait_event(&state, id, "ngap_connected", 30, |_| true).await;
    assert_eq!(
        connected["amf_name"],
        "open5gs-amf-netget",
        "{connected}\n{}",
        amf.log()
    );
    assert_eq!(
        connected["served_guami"][0]["amf_region_id"], 2,
        "{connected}"
    );
    assert_eq!(
        connected["plmn_support"][0]["slices"][0]["sst"], 1,
        "{connected}"
    );

    // The AMF decoded the model's Initial UE Message, did not know the 5G-GUTI, and asked.
    let dl = wait_event(&state, id, "ngap_downlink_nas_transport", 30, |e| {
        e["nas"]["message"] == "identity_request"
    })
    .await;
    assert_eq!(dl["nas"]["identity_type"], "suci", "{dl}\n{}", amf.log());

    // And it processed the model's Identity Response: the SUCI the model wrote appears in the
    // AMF's own log as the UE it is now handling.
    amf.wait_for_log("suci-0-001-01-0000-0-0-0000000123", Duration::from_secs(30))
        .await
        .unwrap_or_else(|e| panic!("the AMF never took the model's SUCI: {e}\n{}", amf.log()));
    let status = state.get_client(id).await.map(|c| c.status);
    assert!(
        matches!(status, Some(ClientStatus::Connected)),
        "{status:?}"
    );

    let frames = capture.finish().await;
    // NetGet's gNB side, read by tshark.
    let netget_sent: Vec<(u8, u8)> = vec![
        (codec::PROC_NG_SETUP, 0),
        (codec::PROC_INITIAL_UE_MESSAGE, 0),
        (codec::PROC_UPLINK_NAS_TRANSPORT, 0),
    ];
    let local_port = frames
        .iter()
        .find(|f| f.src_port != port)
        .map(|f| f.src_port)
        .expect("NetGet sent nothing");
    assert_capture(&frames, local_port, &netget_sent);
    assert!(
        frames
            .iter()
            .any(|f| f.src_port == port && f.procedures.contains(&codec::PROC_NG_SETUP)),
        "the AMF's NG Setup Response is in the capture: {frames:#?}"
    );
}

#[tokio::test]
async fn open5gs_refuses_a_gnb_from_a_plmn_it_does_not_serve() {
    let amf = RealServer::builder("open5gs-amfd", HINT)
        .config_file("amf.yaml", AMF_CONFIG)
        .extra_ports(2)
        .args(["-c", "{dir}/amf.yaml"])
        .ready_when_log_matches(r"ngap_server\(\)")
        .without_tcp_readiness()
        .start()
        .await
        .unwrap();
    let port: u16 = amf.addr().rsplit(':').next().unwrap().parse().unwrap();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "ngap".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Be a gNB".into()),
        startup_params: Some(
            json!({"transport": "sctp", "mcc": "999", "mnc": "70", "tac": 1, "sst": 1}),
        ),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await;
    // The connect fails with the AMF's own cause; nothing is reported as connected.
    let detail = match id {
        Err(e) => e.to_string(),
        Ok(id) => {
            let status = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if let Some(ClientStatus::Error(e)) =
                        state.get_client(id).await.map(|c| c.status)
                    {
                        return e;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("the client never reported the refusal");
            status
        }
    };
    assert!(
        detail.contains("refused NG Setup"),
        "{detail}\n{}",
        amf.log()
    );
    assert!(
        detail.contains("misc"),
        "the AMF's cause is carried through: {detail}"
    );
}
