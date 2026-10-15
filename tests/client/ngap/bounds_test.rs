//! NetGet's gNB against a canned AMF written here with NetGet's own codec, over the lab TCP
//! transport, for what Open5GS never does on demand: refuse NG Setup, send garbage, answer every
//! NAS message with another one so an always-answering handler would loop forever. Not
//! interoperability evidence — that is `real_server_test.rs` — but every bound here was checked
//! by removing it. Also: the model's answer is asserted on the wire (the SUCI the AMF receives is
//! the one the model wrote), and the PDUs NetGet sent go through tshark's ngap dissector.
use super::support::{assert_ngap_clean, lab_frame, read_lab};
use netget::cli::management::ClientForm;
use netget::client::ngap::MAX_FOLLOWUP_DEPTH;
use netget::server::ngap::codec::{self, Cause, PduKind};
use netget::server::ngap::nas;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    /// Accept, ask for identity once, then release the UE.
    Normal,
    /// Refuse NG Setup.
    RefuseSetup,
    /// Answer every Uplink NAS Transport with another Identity Request.
    AskForever,
    /// After NG Setup, send three octets of garbage.
    Garbage,
    /// After NG Setup, declare a frame over the bound.
    Oversize,
}

/// Every PDU the canned AMF received (`false`) and sent (`true`), in order.
type Log = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

async fn canned_amf(behaviour: Behaviour) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        let (mut s, _): (TcpStream, _) = listener.accept().await.unwrap();
        while let Ok(bytes) = read_lab(&mut s).await {
            seen.lock().unwrap().push((false, bytes.clone()));
            let pdu = codec::decode_pdu(&bytes).unwrap();
            let reply: Vec<Vec<u8>> = match (pdu.kind, pdu.procedure_code) {
                (PduKind::Initiating, codec::PROC_NG_SETUP)
                    if behaviour == Behaviour::RefuseSetup =>
                {
                    vec![codec::ng_setup_failure(
                        &Cause::misc(codec::MISC_UNKNOWN_PLMN),
                        Some("v60s"),
                    )
                    .unwrap()]
                }
                (PduKind::Initiating, codec::PROC_NG_SETUP) => {
                    let mut out = vec![codec::ng_setup_response(
                        "canned-amf",
                        json!([{"plmn": "001-01", "amf_region_id": 7, "amf_set_id": 3, "amf_pointer": 1}]).as_array().unwrap(),
                        200,
                        json!([{"plmn": "001-01", "slices": [{"sst": 1}]}]).as_array().unwrap(),
                    )
                    .unwrap()];
                    match behaviour {
                        Behaviour::Garbage => out.push(vec![0xff, 0xff, 0xff]),
                        Behaviour::Oversize => {
                            let declared = (codec::MAX_PDU_LEN as u32 + 1).to_be_bytes();
                            s.write_all(&lab_frame(&out[0])).await.unwrap();
                            s.write_all(&declared).await.unwrap();
                            seen.lock().unwrap().push((true, out[0].clone()));
                            continue;
                        }
                        _ => {}
                    }
                    out
                }
                (PduKind::Initiating, codec::PROC_INITIAL_UE_MESSAGE) => {
                    let ran =
                        codec::decode_ran_ue_ngap_id(pdu.ie(codec::IE_RAN_UE_NGAP_ID).unwrap())
                            .unwrap();
                    let ask = nas::encode(
                        &json!({"message": "identity_request", "identity_type": "suci"}),
                        nas::DOWNLINK_MESSAGES,
                    )
                    .unwrap();
                    vec![codec::downlink_nas_transport(500, ran, &ask).unwrap()]
                }
                (PduKind::Initiating, codec::PROC_UPLINK_NAS_TRANSPORT) => {
                    let t = codec::parse_nas_transport(&pdu).unwrap();
                    if behaviour == Behaviour::AskForever {
                        let ask = nas::encode(
                            &json!({"message": "identity_request", "identity_type": "suci"}),
                            nas::DOWNLINK_MESSAGES,
                        )
                        .unwrap();
                        vec![codec::downlink_nas_transport(
                            t.amf_ue_ngap_id,
                            t.ran_ue_ngap_id,
                            &ask,
                        )
                        .unwrap()]
                    } else {
                        vec![codec::ue_context_release_command(
                            t.amf_ue_ngap_id,
                            Some(t.ran_ue_ngap_id),
                            &Cause::nas(codec::NAS_NORMAL_RELEASE),
                        )
                        .unwrap()]
                    }
                }
                _ => vec![],
            };
            for r in reply {
                seen.lock().unwrap().push((true, r.clone()));
                if s.write_all(&lab_frame(&r)).await.is_err() {
                    return;
                }
            }
        }
    });
    (port, log)
}

/// The model: bring one UE in with a SUCI whose MSIN is chosen here, and answer every identity
/// request with that SUCI.
const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
suci = {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"}, "routing_indicator": "12", "msin": "9876543210"}
a = []
if t == "ngap_connected":
    a = [{"type": "ngap_initial_ue_message", "nas": {"message": "registration_request", "mobile_identity": suci}}]
elif t == "ngap_downlink_nas_transport" and e["nas"].get("message") == "identity_request":
    a = [{"type": "ngap_uplink_nas_transport", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "ran_ue_ngap_id": e["ran_ue_ngap_id"], "nas": {"message": "identity_response", "mobile_identity": suci}}]
print(json.dumps({"actions": a}))"#;

async fn connect(port: u16) -> (AppState, anyhow::Result<ClientId>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "ngap".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Be a gNB".into()),
        startup_params: Some(json!({"transport": "tcp", "mcc": "001", "mnc": "01", "gnb_id": 77, "gnb_id_bits": 24, "tac": 5})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .map_err(|e| anyhow::anyhow!("{e}"));
    (state, id)
}

async fn wait_for(log: &Log, what: &str, pred: impl Fn(&[(bool, Vec<u8>)]) -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if pred(&log.lock().unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("canned AMF never saw {what}"));
}

fn received(log: &[(bool, Vec<u8>)], code: u8, kind: PduKind) -> Vec<codec::Pdu> {
    log.iter()
        .filter(|(sent, _)| !sent)
        .filter_map(|(_, b)| codec::decode_pdu(b).ok())
        .filter(|p| p.procedure_code == code && p.kind == kind)
        .collect()
}

#[tokio::test]
async fn ng_setup_comes_from_the_parameters_and_the_ue_from_the_model() {
    let (port, log) = canned_amf(Behaviour::Normal).await;
    let (state, id) = connect(port).await;
    let id = id.unwrap();
    wait_for(&log, "UE Context Release Complete", |l| {
        !received(l, codec::PROC_UE_CONTEXT_RELEASE, PduKind::Successful).is_empty()
    })
    .await;
    let l = log.lock().unwrap().clone();
    let setup =
        codec::parse_ng_setup_request(&received(&l, codec::PROC_NG_SETUP, PduKind::Initiating)[0])
            .unwrap();
    assert_eq!(setup["global_ran_node_id"]["gnb_id"], 77);
    assert_eq!(setup["global_ran_node_id"]["gnb_id_bits"], 24);
    assert_eq!(setup["supported_ta_list"][0]["tac"], 5);
    // Condition 4: the AMF received exactly the identity the model wrote.
    let initial = &received(&l, codec::PROC_INITIAL_UE_MESSAGE, PduKind::Initiating)[0];
    let ue = codec::parse_initial_ue_message(initial).unwrap();
    let n = nas::decode(&ue.nas);
    assert_eq!(n["mobile_identity"]["msin"], "9876543210", "{n}");
    assert_eq!(n["mobile_identity"]["routing_indicator"], "12", "{n}");
    assert_eq!(ue.user_location["tai"]["tac"], 5);
    let ul = codec::parse_nas_transport(
        &received(&l, codec::PROC_UPLINK_NAS_TRANSPORT, PduKind::Initiating)[0],
    )
    .unwrap();
    assert_eq!(
        ul.amf_ue_ngap_id, 500,
        "the AMF's id from the Downlink NAS Transport is echoed"
    );
    assert_eq!(nas::decode(&ul.nas)["message"], "identity_response");
    // The release was answered by Rust, and the model was told.
    let events: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    assert!(
        events.iter().any(
            |e| e["event_type"] == "ngap_connected" && e["request"]["amf_name"] == "canned-amf"
        ),
        "{events:?}"
    );
    assert_ngap_clean(
        &l.iter()
            .map(|(sent, b)| (*sent, b.clone()))
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn a_refused_ng_setup_fails_the_connect_with_the_amfs_cause() {
    let (port, _log) = canned_amf(Behaviour::RefuseSetup).await;
    let (state, id) = connect(port).await;
    let detail = match id {
        Err(e) => e.to_string(),
        Ok(id) => match state.get_client(id).await.map(|c| c.status) {
            Some(ClientStatus::Error(e)) => e,
            other => panic!("a refused NG Setup left the client {other:?}"),
        },
    };
    assert!(
        detail.contains("refused NG Setup") && detail.contains("unknown-PLMN-or-SNPN"),
        "{detail}"
    );
    assert!(detail.contains("v60s"), "{detail}");
}

#[tokio::test]
async fn the_follow_up_chain_is_bounded() {
    let (port, log) = canned_amf(Behaviour::AskForever).await;
    let (_state, id) = connect(port).await;
    id.unwrap();
    let expected = MAX_FOLLOWUP_DEPTH as usize - 1;
    wait_for(&log, "the chain's last answer", |l| {
        received(l, codec::PROC_UPLINK_NAS_TRANSPORT, PduKind::Initiating).len() >= expected
    })
    .await;
    // Give an unbounded chain the time to show itself: it answers within milliseconds per turn.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let n = received(
        &log.lock().unwrap(),
        codec::PROC_UPLINK_NAS_TRANSPORT,
        PduKind::Initiating,
    )
    .len();
    assert_eq!(
        n, expected,
        "the model and the AMF must stop answering each other at the bound"
    );
}

#[tokio::test]
async fn a_malformed_pdu_from_the_amf_never_reaches_the_model() {
    let (port, log) = canned_amf(Behaviour::Garbage).await;
    let (state, id) = connect(port).await;
    let id = id.unwrap();
    wait_for(&log, "an Error Indication", |l| {
        !received(l, codec::PROC_ERROR_INDICATION, PduKind::Initiating).is_empty()
    })
    .await;
    let ei = &received(
        &log.lock().unwrap(),
        codec::PROC_ERROR_INDICATION,
        PduKind::Initiating,
    )[0];
    assert_eq!(
        codec::parse_cause_message(ei).unwrap()["cause"],
        json!({"group": "protocol", "value": "transfer-syntax-error"})
    );
    let events: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    assert!(
        !events.iter().any(|e| e["event_type"] == "ngap_amf_error"),
        "{events:?}"
    );
}

#[tokio::test]
async fn an_oversized_frame_ends_the_association() {
    let (port, _log) = canned_amf(Behaviour::Oversize).await;
    let (state, id) = connect(port).await;
    let id = id.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.get_client(id).await.map(|c| c.status) {
                Some(ClientStatus::Connected) | None => {}
                Some(_) => return,
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a frame over the bound must end the lab association: its framing is lost");
}
