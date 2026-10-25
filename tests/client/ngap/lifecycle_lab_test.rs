//! The rest of a UE's life with NetGet's gNB: PDU session release and modification, CM-IDLE,
//! Service Request and paging — against **NetGet's own AMF**, in-process over the
//! **non-standard lab TCP transport**, with a relay in between that keeps every PDU.
//!
//! Both ends are NetGet's, so this is circular: it proves the gNB's session logic, the model's
//! view of it and that the model's decisions are acted on, not interoperability. That evidence is
//! `real_server_test.rs` against Open5GS. It runs on macOS and Linux alike.
//!
//! The whole life runs three times: with the AMF's default NAS algorithms, with 128-NIA1/NEA1
//! (SNOW 3G) and with 128-NIA3/NEA3 (ZUC), so the UE's side of every algorithm — including the
//! Service Request's NAS message container, ciphered at the outer message's COUNT — is checked
//! by an AMF that verifies it.
//!
//! No LLM calls: python policies stand in for both models. Model-call budget per run, from the
//! events each side raised: the gNB **10** (connected, registered, two sessions, a release, a
//! modification, two context releases, two service accepts — the second context release is the
//! operator's injected request and the second service accept answers the AMF's paging, which no
//! model asked for); the AMF **6** (NG Setup, registration, two sessions, the release request
//! and the modification request; none for either Service Request or the paging).
use super::support::{assert_ngap_clean, lab_frame};
use netget::cli::management::{ClientForm, ServerForm};
use netget::server::ngap::codec::{self, PduKind};
use netget::server::ngap::{nas, security};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const K: &str = "465B5CE8B199B49FAA5F0A2EE238A6BC";
const OPC: &str = "E8ED289DEBA952E4283B54E88E6183CA";
const SUPI: &str = "imsi-001010000000001";

/// The AMF's model: admit the gNB and the subscriber, give each session an address (IPv4, and an
/// IPv6 prefix and interface identifier when the UE asks for one), release what the UE asks to
/// release, and grant a modification with the 5QI the UE asked for and a new session AMBR.
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
    psi = e["pdu_session_id"]
    acc = {"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
           "pdu_session_id": psi, "ue_ipv4": "10.45.0.%d" % psi}
    if e.get("pdu_session_type") in ("ipv6", "ipv4v6"):
        acc["ue_ipv6_prefix"] = "2001:db8:1:2::/64"
        acc["ue_ipv6_interface_identifier"] = "::%d" % (psi + 1)
    a = [acc]
elif t == "ngap_pdu_session_release_request":
    a = [{"type": "send_pdu_session_release", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"]}]
elif t == "ngap_pdu_session_modification_request":
    a = [{"type": "send_pdu_session_modification", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"], "five_qi": e.get("requested_five_qi") or 9,
          "session_ambr": {"uplink_kbps": 50000, "downlink_kbps": 100000}}]
print(json.dumps({"actions": a}))"#;

/// The gNB's model: register, take session 1, release it, take an IPv4v6 session 2, ask for 5QI 8
/// on it, ask the AMF to idle the UE for inactivity, and bring it back with a Service Request.
/// A release for any other cause (the operator's, later) is left alone.
const GNB_POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
suci = {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"}, "routing_indicator": "0000", "msin": "0000000001"}
a = []
if t == "ngap_connected":
    a = [{"type": "ngap_initial_ue_message", "nas": {"message": "registration_request", "mobile_identity": suci}}]
elif t == "ngap_ue_registered":
    a = [{"type": "ngap_pdu_session_request", "ran_ue_ngap_id": e["ran_ue_ngap_id"], "pdu_session_id": 1,
          "dnn": "internet", "s_nssai": {"sst": 1}}]
elif t == "ngap_pdu_session_established" and e["result"] == "accepted":
    if e["pdu_session_id"] == 1:
        a = [{"type": "ngap_pdu_session_release", "ran_ue_ngap_id": e["ran_ue_ngap_id"], "pdu_session_id": 1}]
    else:
        a = [{"type": "ngap_pdu_session_modification", "ran_ue_ngap_id": e["ran_ue_ngap_id"],
              "pdu_session_id": e["pdu_session_id"], "five_qi": 8}]
elif t == "ngap_pdu_session_released" and e["result"] == "released":
    a = [{"type": "ngap_pdu_session_request", "ran_ue_ngap_id": e["ran_ue_ngap_id"], "pdu_session_id": 2,
          "dnn": "internet", "pdu_session_type": "ipv4v6"}]
elif t == "ngap_pdu_session_modified" and e["result"] == "modified":
    a = [{"type": "ngap_ue_context_release_request", "ran_ue_ngap_id": e["ran_ue_ngap_id"]}]
elif t == "ngap_ue_context_release" and e.get("cm_state") == "idle" and (e.get("cause") or {}).get("value") == "user-inactivity":
    a = [{"type": "ngap_service_request", "supi": e["supi"]}]
print(json.dumps({"actions": a}))"#;

type Wire = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

async fn read_frame(r: &mut tokio::net::tcp::OwnedReadHalf) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.ok()?;
    let mut pdu = vec![0u8; u32::from_be_bytes(len) as usize];
    r.read_exact(&mut pdu).await.ok()?;
    Some(pdu)
}

/// A lab-framing relay between the gNB and the AMF that keeps every PDU, `true` for the gNB's.
async fn relay(amf_port: u16) -> (u16, Wire) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let wire: Wire = Arc::default();
    let w = wire.clone();
    tokio::spawn(async move {
        let (gnb, _) = listener.accept().await.unwrap();
        let amf = TcpStream::connect(("127.0.0.1", amf_port)).await.unwrap();
        let (mut gr, mut gw) = gnb.into_split();
        let (mut ar, mut aw) = amf.into_split();
        let w2 = w.clone();
        tokio::spawn(async move {
            while let Some(pdu) = read_frame(&mut ar).await {
                w2.lock().unwrap().push((false, pdu.clone()));
                if gw.write_all(&lab_frame(&pdu)).await.is_err() {
                    return;
                }
            }
        });
        while let Some(pdu) = read_frame(&mut gr).await {
            w.lock().unwrap().push((true, pdu.clone()));
            if aw.write_all(&lab_frame(&pdu)).await.is_err() {
                return;
            }
        }
    });
    (port, wire)
}

fn logs(entries: Vec<impl serde::Serialize>) -> Vec<Value> {
    entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect()
}

async fn client_events(state: &AppState, id: ClientId) -> Vec<Value> {
    logs(
        state
            .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
            .await,
    )
}

async fn server_events(state: &AppState, id: ServerId) -> Vec<Value> {
    logs(
        state
            .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
            .await,
    )
}

fn count(events: &[Value], t: &str) -> usize {
    events.iter().filter(|e| e["event_type"] == t).count()
}

/// The `n`th (from 1) `event` the gNB raised that satisfies `pred`.
async fn wait_event(
    state: &AppState,
    id: ClientId,
    event: &str,
    n: usize,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hits: Vec<Value> = client_events(state, id)
                .await
                .into_iter()
                .filter(|e| e["event_type"] == event && pred(&e["request"]))
                .map(|e| e["request"].clone())
                .collect();
            if hits.len() >= n {
                return hits[n - 1].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    match found {
        Ok(v) => v,
        Err(_) => panic!(
            "no {event} #{n} within 30s; the gNB raised: {:#?}",
            client_events(state, id)
                .await
                .iter()
                .map(|e| (e["event_type"].clone(), e["request"].clone()))
                .collect::<Vec<_>>()
        ),
    }
}

/// Print a status channel's lines (shown with a failing test's output), labelled.
fn echo_status(label: &'static str) -> mpsc::UnboundedSender<String> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if line != "__UPDATE_UI__" {
                eprintln!("[{label}] {line}");
            }
        }
    });
    tx
}

async fn start_amf(state: &'static AppState, algorithms: Option<(&str, &str)>) -> (ServerId, u16) {
    let tx = echo_status("amf");
    let up = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut params = json!({"transport": "tcp", "user_plane_address": up.to_string(),
        "subscribers": [{"supi": SUPI, "subscriber_key": K, "subscriber_opc": OPC}]});
    if let Some((ia, ea)) = algorithms {
        params["nas_integrity"] = json!(ia);
        params["nas_ciphering"] = json!(ea);
    }
    let id = ServerForm {
        protocol: "ngap".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an AMF".into()),
        startup_params: Some(params),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": AMF_POLICY}})]),
        ..Default::default()
    }
    .create(state, tx)
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
    (id, port)
}

/// The association's connection id at the AMF, for an injected action.
async fn amf_connection(state: &AppState, id: ServerId) -> u32 {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(c) = state
                .get_server(id)
                .await
                .and_then(|s| s.connections.keys().next().map(|c| c.as_u32()))
            {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the gNB's association is registered at the AMF")
}

fn pdus(wire: &Wire, from_gnb: bool, code: u8, kind: PduKind) -> Vec<codec::Pdu> {
    wire.lock()
        .unwrap()
        .iter()
        .filter(|(g, _)| *g == from_gnb)
        .filter_map(|(_, b)| codec::decode_pdu(b).ok())
        .filter(|p| p.procedure_code == code && p.kind == kind)
        .collect()
}

async fn whole_life(algorithms: Option<(&str, &str)>, expect: (&str, &str)) {
    let amf_state: &'static AppState = Box::leak(Box::new(AppState::new_with_options(
        false,
        "http://127.0.0.1:1".into(),
    )));
    let (amf_id, amf_port) = start_amf(amf_state, algorithms).await;
    let (relay_port, wire) = relay(amf_port).await;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let tx = echo_status("gnb");
    let id = ClientForm {
        protocol: "ngap".into(),
        remote_addr: Some(format!("127.0.0.1:{relay_port}")),
        instruction: Some("Be a gNB".into()),
        startup_params: Some(json!({"transport": "tcp", "supi": SUPI,
            "subscriber_key": K, "subscriber_opc": OPC})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": GNB_POLICY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap();

    let reg = wait_event(&state, id, "ngap_ue_registered", 1, |_| true).await;
    assert_eq!(
        reg["nas_security"],
        json!({"integrity": expect.0, "ciphering": expect.1}),
        "{reg}"
    );
    assert_eq!(reg["k_gnb_verified"], true, "{reg}");

    // Session 1, then the UE's own release of it.
    let s1 = wait_event(&state, id, "ngap_pdu_session_established", 1, |e| {
        e["pdu_session_id"] == 1
    })
    .await;
    assert_eq!(s1["ue_ipv4"], "10.45.0.1", "{s1}");
    let released = wait_event(&state, id, "ngap_pdu_session_released", 1, |_| true).await;
    assert_eq!(
        (
            &released["pdu_session_id"],
            &released["result"],
            &released["requested_by"]
        ),
        (&json!(1), &json!("released"), &json!("ue")),
        "{released}"
    );
    assert_eq!(
        released["cause"]["value"], 36,
        "regular deactivation: {released}"
    );

    // Session 2, IPv4v6.
    let s2 = wait_event(&state, id, "ngap_pdu_session_established", 1, |e| {
        e["pdu_session_id"] == 2
    })
    .await;
    assert_eq!(s2["pdu_session_type"], "ipv4v6", "{s2}");
    assert_eq!(s2["ue_ipv4"], "10.45.0.2", "{s2}");
    assert_eq!(s2["ue_ipv6_interface_identifier"], "::3", "{s2}");

    // The UE asked for 5QI 8; the AMF's model granted it with a new session AMBR.
    let m = wait_event(&state, id, "ngap_pdu_session_modified", 1, |_| true).await;
    assert_eq!(m["result"], "modified", "{m}");
    assert_eq!(m["requested_by"], "ue", "{m}");
    assert_eq!(m["requested_five_qi"], 8, "{m}");
    assert_eq!(m["five_qi"], 8, "{m}");
    assert_eq!(
        m["session_ambr_kbps"],
        json!({"uplink": 50000, "downlink": 100000}),
        "{m}"
    );

    // The model's context release request idles the UE; its Service Request brings it back.
    let idle = wait_event(&state, id, "ngap_ue_context_release", 1, |_| true).await;
    assert_eq!(idle["cm_state"], "idle", "{idle}");
    assert_eq!(idle["supi"], SUPI, "{idle}");
    assert_eq!(idle["pdu_sessions"], json!([2]), "{idle}");
    let back = wait_event(&state, id, "ngap_service_accepted", 1, |_| true).await;
    assert_eq!(back["trigger"], "ue", "{back}");
    assert_eq!(back["service_type"], "data", "{back}");
    assert_eq!(back["k_gnb_verified"], true, "{back}");
    assert_eq!(back["pdu_session_status"], json!([2]), "{back}");
    assert_eq!(back["user_plane_sessions"], json!([2]), "{back}");
    assert_ne!(
        back["ran_ue_ngap_id"], reg["ran_ue_ngap_id"],
        "a new RAN UE NGAP ID"
    );

    // The operator idles it again, and the AMF pages it: the UE answers by itself.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "ngap_ue_context_release_request", "ran_ue_ngap_id": back["ran_ue_ngap_id"],
                   "cause": "radioNetwork/unspecified"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    let outcome = serde_json::to_value(&outcome).unwrap().to_string();
    assert!(outcome.to_lowercase().contains("sent"), "{outcome}");
    let idle2 = wait_event(&state, id, "ngap_ue_context_release", 2, |_| true).await;
    assert_eq!(idle2["cm_state"], "idle", "{idle2}");
    let conn = amf_connection(amf_state, amf_id).await;
    amf_state
        .send_to_peer(
            amf_id,
            conn,
            json!({"type": "send_paging", "supi": SUPI}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    let paged = wait_event(&state, id, "ngap_service_accepted", 1, |e| {
        e["trigger"] == "paging"
    })
    .await;
    assert_eq!(paged["service_type"], "mobile_terminated", "{paged}");
    assert_eq!(paged["k_gnb_verified"], true, "{paged}");
    assert_eq!(paged["user_plane_sessions"], json!([2]), "{paged}");

    // The model-call budget: one event per outcome, never one per NAS message.
    let gnb = client_events(&state, id).await;
    for (t, n) in [
        ("ngap_connected", 1),
        ("ngap_ue_registered", 1),
        ("ngap_pdu_session_established", 2),
        ("ngap_pdu_session_released", 1),
        ("ngap_pdu_session_modified", 1),
        ("ngap_ue_context_release", 2),
        ("ngap_service_accepted", 2),
        ("ngap_downlink_nas_transport", 0),
        ("ngap_amf_error", 0),
    ] {
        assert_eq!(count(&gnb, t), n, "gNB {t}: {gnb:#?}");
    }
    let amf = server_events(amf_state, amf_id).await;
    for (t, n) in [
        ("ngap_ng_setup_request", 1),
        ("ngap_registration_request", 1),
        ("ngap_pdu_session_establishment_request", 2),
        ("ngap_pdu_session_release_request", 1),
        ("ngap_pdu_session_modification_request", 1),
        ("ngap_initial_ue_message", 0),
    ] {
        assert_eq!(count(&amf, t), n, "AMF {t}: {amf:#?}");
    }

    // What crossed the wire.
    assert_eq!(
        pdus(
            &wire,
            true,
            codec::PROC_PDU_SESSION_RESOURCE_RELEASE,
            PduKind::Successful
        )
        .len(),
        1
    );
    assert_eq!(
        pdus(
            &wire,
            true,
            codec::PROC_PDU_SESSION_RESOURCE_MODIFY,
            PduKind::Successful
        )
        .len(),
        1
    );
    assert_eq!(
        pdus(
            &wire,
            true,
            codec::PROC_UE_CONTEXT_RELEASE_REQUEST,
            PduKind::Initiating
        )
        .len(),
        2
    );
    assert_eq!(
        pdus(&wire, false, codec::PROC_PAGING, PduKind::Initiating).len(),
        1
    );
    let initial = pdus(
        &wire,
        true,
        codec::PROC_INITIAL_UE_MESSAGE,
        PduKind::Initiating,
    );
    assert_eq!(initial.len(), 3, "registration and two Service Requests");
    for (pdu, service_type) in initial[1..]
        .iter()
        .zip([nas::SERVICE_TYPE_DATA, nas::SERVICE_TYPE_MOBILE_TERMINATED])
    {
        let ue = codec::parse_initial_ue_message(pdu).unwrap();
        assert!(
            ue.five_g_s_tmsi.is_some(),
            "the Initial UE Message names the FiveG-S-TMSI"
        );
        // Integrity protected, not ciphered: the AMF must read the 5G-S-TMSI to find the UE.
        assert_eq!(ue.nas[1] & 0x0F, security::SHT_INTEGRITY);
        let outer = nas::parse_service_request(&ue.nas[7..]).unwrap();
        assert_eq!(outer.service_type, service_type);
        assert_eq!(outer.tmsi != 0, true);
        // Only cleartext IEs outside; the rest rides in the NAS message container.
        assert!(outer.uplink_data_status.is_none() && outer.pdu_session_status.is_none());
        assert!(outer.nas_container.is_some());
    }
    // Every PDU through tshark — except, under NEA1/NEA3, the two Service Requests: tshark 4.2.2
    // dissects a NAS message container inside an integrity-only message as plaintext
    // ("Not a NAS 5GS PD"), and under a real cipher it is not. Under NEA0 they are checked too.
    let ciphered = algorithms.map(|(_, ea)| ea != "nea0").unwrap_or(false);
    let checked: Vec<(bool, Vec<u8>)> = wire
        .lock()
        .unwrap()
        .iter()
        .filter(|(from_gnb, b)| {
            !(ciphered
                && *from_gnb
                && codec::decode_pdu(b)
                    .ok()
                    .and_then(|p| codec::parse_initial_ue_message(&p).ok())
                    .is_some_and(|u| u.five_g_s_tmsi.is_some()))
        })
        .cloned()
        .collect();
    assert_ngap_clean(&checked);
    let _ = state.remove_client_handle(id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_releases_modifies_idles_and_is_paged_back_with_the_default_algorithms() {
    whole_life(None, ("NIA2", "NEA0")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_whole_life_under_snow3g_nia1_and_nea1() {
    whole_life(Some(("nia1", "nea1")), ("NIA1", "NEA1")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_whole_life_under_zuc_nia3_and_nea3() {
    whole_life(Some(("nia3", "nea3")), ("NIA3", "NEA3")).await;
}
