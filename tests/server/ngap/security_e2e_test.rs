//! The AMF with subscriber credentials, in-process over the **non-standard lab TCP transport**:
//! 5G-AKA, the security mode procedure, registration with an Initial Context Setup, a PDU
//! session with its resource setup, ICMP echo through the GTP-U user plane, and deregistration
//! under NAS security — and the refusals: a wrong RES*, a UE that cannot verify the AUTN, a stale
//! SQN resynchronised from AUTS, a forged MAC, a replayed COUNT, a silent model.
//!
//! The UE here is scripted from NetGet's own `security` module, so this suite proves the session
//! logic and the failure paths, not interoperability: UERANSIM is that evidence
//! (`real_client_test.rs`). Every NGAP PDU in both directions goes through tshark's ngap
//! dissector at the end of each test.
//!
//! LLM budget: **three calls**, all in `a_subscriber_registers_gets_a_session_and_pings`: one per
//! decision the model owns (the gNB, the subscriber, the session) and none per NAS message.
use super::support::{assert_ngap_clean, lab_frame, read_lab, unhex};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::server::gtp::codec::{ExtensionHeader, GtpV1Header, GtpV1Message};
use netget::server::ngap::codec::{self, PduKind};
use netget::server::ngap::security::{self, Milenage, NasContext};
use netget::server::ngap::{nas, sm, upf};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";
const UERANSIM_NG_SETUP: &str = "00150041000004001b00090000f1105000000001005240140880554552414e53494d2d676e622d312d312d310066001000000000010000f110000010080102030015400140";
const K: &str = "465B5CE8B199B49FAA5F0A2EE238A6BC";
const OPC: &str = "E8ED289DEBA952E4283B54E88E6183CA";
const SUPI: &str = "001010000000001";
const WIRE: Duration = Duration::from_secs(30);

fn subscribers() -> Value {
    json!([{"supi": format!("imsi-{SUPI}"), "subscriber_key": K, "subscriber_opc": OPC, "amf_field": "8000"}])
}

fn uli() -> Value {
    json!({"cgi": {"plmn": "001-01", "cell_id": 16}, "tai": {"plmn": "001-01", "tac": 1}})
}

fn snn() -> String {
    security::serving_network_name("001", "01")
}

/// A Registration Request for the subscriber, null-scheme SUCI, 5G-EA0-3 and 5G-IA0-3.
fn registration_request() -> Vec<u8> {
    nas::encode(
        &json!({"message": "registration_request", "registration_type": "initial",
                "mobile_identity": {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"},
                                    "routing_indicator": "0000", "msin": "0000000001"}}),
        nas::UPLINK_MESSAGES,
    )
    .unwrap()
}

/// Admit any gNB, register the subscriber on slice 1, accept its session.
const POLICY: &str = r#"import json, sys
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
          "pdu_session_id": e["pdu_session_id"], "ue_ipv4": "10.45.0.2", "reachable_addresses": ["10.45.0.1"]}]
print(json.dumps({"actions": a}))"#;

/// Admit the gNB; say nothing about anything else.
const ADMIT_ONLY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
          "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
elif t == "ngap_registration_request":
    a = [{"type": "send_registration_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"], "allowed_nssai": [{"sst": 1}]}]
print(json.dumps({"actions": a}))"#;

fn script(code: &str) -> Vec<Value> {
    vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": code}}),
    ]
}

/// A free UDP port on loopback for the user plane. Probed, so it can race; nothing else in this
/// suite binds UDP ports by number except the gNB side's 2152.
fn probe_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(
    handlers: Option<Vec<Value>>,
    llm: &str,
    extra: Value,
) -> (AppState, ServerId, u16, mpsc::UnboundedReceiver<String>) {
    let state = AppState::new_with_options(false, llm.into());
    state.set_ollama_model(Some("mock-model".into())).await;
    state
        .set_llm_client(netget::llm::OllamaClient::new(llm))
        .await;
    let (tx, rx) = mpsc::unbounded_channel();
    let mut params = json!({"transport": "tcp", "subscribers": subscribers()});
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    let id = ServerForm {
        protocol: "ngap".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an AMF".into()),
        startup_params: Some(params),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    break a.port();
                }
                assert!(
                    !matches!(s.status, netget::state::server::ServerStatus::Error(_)),
                    "the AMF did not start: {:?}",
                    s.status
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port, rx)
}

fn drain(rx: &mut mpsc::UnboundedReceiver<String>, into: &mut Vec<String>) {
    while let Ok(l) = rx.try_recv() {
        into.push(l);
    }
}

async fn wait_line(rx: &mut mpsc::UnboundedReceiver<String>, seen: &mut Vec<String>, needle: &str) {
    let ok = tokio::time::timeout(WIRE, async {
        loop {
            drain(rx, seen);
            if seen.iter().any(|l| l.contains(needle)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        ok.is_ok(),
        "the AMF never logged {needle:?}:\n{}",
        seen.join("\n")
    );
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

/// A gNB with one scripted UE, over the lab transport, keeping every PDU for the oracle.
struct Gnb {
    stream: TcpStream,
    log: Vec<(bool, Vec<u8>)>,
    amf_id: u64,
    m: Milenage,
    sqn_ms: u64,
    ctx: Option<NasContext>,
}

impl Gnb {
    async fn connect(port: u16) -> Gnb {
        Gnb {
            stream: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            log: Vec::new(),
            amf_id: 0,
            m: Milenage::with_opc(unhex(K).try_into().unwrap(), unhex(OPC).try_into().unwrap()),
            sqn_ms: 0,
            ctx: None,
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
    /// Nothing arrives within `d`.
    async fn silent(&mut self, d: Duration) -> bool {
        tokio::time::timeout(d, read_lab(&mut self.stream))
            .await
            .is_err()
    }
    async fn setup(&mut self) {
        self.send(&unhex(UERANSIM_NG_SETUP)).await;
        let p = self.recv("NG Setup answer").await;
        assert_eq!(
            (p.kind, p.procedure_code),
            (PduKind::Successful, codec::PROC_NG_SETUP)
        );
    }
    /// The plain NAS of a Downlink NAS Transport.
    async fn dl_nas(&mut self, what: &str) -> Vec<u8> {
        let p = self.recv(what).await;
        assert_eq!(
            p.procedure_code,
            codec::PROC_DOWNLINK_NAS_TRANSPORT,
            "{what}: got {}",
            p.label()
        );
        let t = codec::parse_nas_transport(&p).unwrap();
        self.amf_id = t.amf_ue_ngap_id;
        t.nas
    }
    async fn uplink(&mut self, nas_pdu: &[u8]) {
        let pdu = codec::uplink_nas_transport(self.amf_id, 1, nas_pdu, &uli()).unwrap();
        self.send(&pdu).await;
    }
    async fn uplink_protected(&mut self, plain: &[u8]) -> Vec<u8> {
        let wire = self
            .ctx
            .as_mut()
            .unwrap()
            .protect(plain, security::SHT_INTEGRITY_CIPHERED);
        self.uplink(&wire).await;
        wire
    }
    fn unprotect(&mut self, wire: &[u8]) -> Vec<u8> {
        self.ctx.as_mut().unwrap().unprotect(wire).unwrap().0
    }

    /// The UE side of 5G-AKA and the security mode procedure, from Initial UE Message to a
    /// verified Security Mode Command answered. Returns the selected (ia, ea).
    async fn authenticate(&mut self) -> (u8, u8) {
        self.send(
            &codec::initial_ue_message(1, &registration_request(), &uli(), "mo-Signalling")
                .unwrap(),
        )
        .await;
        let k_amf = loop {
            let auth = self.dl_nas("Authentication Request").await;
            let req = nas::parse_authentication_request(&auth).expect("an Authentication Request");
            match security::ue_check_autn(
                &self.m,
                &req.rand,
                &req.autn,
                &snn(),
                self.sqn_ms,
                1 << 28,
            ) {
                security::AutnOutcome::Ok {
                    res_star,
                    k_ausf,
                    sqn,
                } => {
                    self.sqn_ms = sqn;
                    self.uplink(&nas::authentication_response(&res_star)).await;
                    break security::k_amf(&security::k_seaf(&k_ausf, &snn()), SUPI, &req.abba);
                }
                security::AutnOutcome::SynchFailure { auts } => {
                    self.uplink(&nas::authentication_failure(21, Some(&auts)))
                        .await;
                }
                _ => panic!("the UE refused the AMF's AUTN"),
            }
        };
        let smc_wire = self.dl_nas("Security Mode Command").await;
        assert_eq!(
            smc_wire[1], 3,
            "integrity protected with new security context"
        );
        let smc = nas::parse_security_mode_command(&smc_wire[7..]).unwrap();
        assert_eq!(smc.replayed_ue_security_capability, vec![0xf0, 0xf0]);
        assert!(smc.imeisv_request && smc.rinmr);
        let mut ctx = NasContext::new(smc.ngksi, k_amf, smc.ia, smc.ea, security::UPLINK);
        ctx.unprotect(&smc_wire)
            .expect("the Security Mode Command's MAC verifies with the UE's K_AMF");
        let imeisv =
            nas::encode_mobile_identity(&json!({"type": "imeisv", "digits": "4370816125816151"}))
                .unwrap();
        let complete = nas::security_mode_complete(Some(&imeisv), Some(&registration_request()));
        let wire = ctx.protect(&complete, security::SHT_INTEGRITY_CIPHERED_NEW_CONTEXT);
        self.ctx = Some(ctx);
        self.uplink(&wire).await;
        (smc.ia, smc.ea)
    }

    /// Answer the Initial Context Setup and send Registration Complete. Returns the accept.
    async fn complete_registration(&mut self) -> nas::ParsedRegistrationAccept {
        let p = self.recv("Initial Context Setup Request").await;
        assert_eq!(
            (p.kind, p.procedure_code),
            (PduKind::Initiating, codec::PROC_INITIAL_CONTEXT_SETUP),
            "got {}",
            p.label()
        );
        let ics = codec::parse_initial_context_setup_request(&p).unwrap();
        // K_gNB: Annex A.9 from K_AMF and the uplink COUNT of Security Mode Complete.
        assert_eq!(
            ics.security_key,
            self.ctx.as_ref().unwrap().k_gnb(),
            "the AMF's K_gNB is the UE's"
        );
        assert_eq!(ics.ue_security_capabilities[0], 0xE000, "NEA1-3");
        assert_eq!(ics.ue_security_capabilities[1], 0xE000, "NIA1-3");
        let accept_wire = ics.nas.expect("the Registration Accept rides in the ICS");
        assert_eq!(accept_wire[1], 2, "integrity protected and ciphered");
        let plain = self.unprotect(&accept_wire);
        let accept = nas::parse_registration_accept(&plain).unwrap();
        self.send(&codec::initial_context_setup_response(self.amf_id, 1).unwrap())
            .await;
        self.uplink_protected(&nas::registration_complete()).await;
        accept
    }
}

fn gpdu(teid: u32, packet: Vec<u8>) -> Vec<u8> {
    let mut h = GtpV1Header::new(255, teid);
    // UL PDU SESSION INFORMATION (PDU type 1), QFI 1.
    h.extension_headers.push(ExtensionHeader {
        ext_type: 0x85,
        content: vec![0x10, 0x01],
    });
    GtpV1Message {
        header: h,
        body: packet,
    }
    .encode()
}

fn echo_request(src: [u8; 4], dst: [u8; 4], seq: u16) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 36, 0, 1, 0x40, 0, 64, 1, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[8, 0, 0, 0, 0x4e, 0x47]);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(b"netget-1");
    let ip = upf::checksum(&p[..20]);
    p[10..12].copy_from_slice(&ip.to_be_bytes());
    let icmp = upf::checksum(&p[20..]);
    p[22..24].copy_from_slice(&icmp.to_be_bytes());
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscriber_registers_gets_a_session_and_pings() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ngap_ng_setup_request")
            .respond_with_actions(json!([{
                "type": "send_ng_setup_response",
                "amf_name": "mocked-amf",
                "served_guami": [{"plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
                "plmn_support": [{"plmn": {"mcc": "001", "mnc": "01"}, "slices": [{"sst": 1}]}]
            }]))
            .expect_calls(1)
            .and()
            .on_event("ngap_registration_request")
            .and_event_data_contains("supi", "imsi-001010000000001")
            .respond_with_actions_from_event(|e| json!([{
                "type": "send_registration_accept",
                "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                "allowed_nssai": [{"sst": 1}],
                "tmsi": 3405691582u32
            }]))
            .expect_calls(1)
            .and()
            .on_event("ngap_pdu_session_establishment_request")
            .and_event_data_contains("dnn", "internet")
            .respond_with_actions_from_event(|e| json!([{
                "type": "send_pdu_session_accept",
                "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                "pdu_session_id": e["pdu_session_id"],
                "ue_ipv4": "10.45.0.2",
                "reachable_addresses": ["10.45.0.1"]
            }]))
            .expect_calls(1)
            .build(),
    )
    .await
    .unwrap();
    let upf_port = probe_udp_port();
    let (state, id, port, mut rx) = start(
        None,
        &mock.base_url(),
        json!({"user_plane_address": format!("127.0.0.1:{upf_port}")}),
    )
    .await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    let (ia, ea) = gnb.authenticate().await;
    assert_eq!(
        (ia, ea),
        (security::NIA2, security::NEA0),
        "NIA2 with the default NEA0"
    );
    let accept = gnb.complete_registration().await;
    assert_eq!(accept.guti.as_ref().unwrap()["tmsi"], 3405691582u32);
    assert_eq!(accept.guti.as_ref().unwrap()["amf_region_id"], 2);
    assert_eq!(accept.allowed_nssai, vec![nas::Snssai { sst: 1, sd: None }]);
    assert_eq!(accept.tai_list[0]["tac"], 1);
    wait_line(&mut rx, &mut seen, "decision=ue_registered").await;

    // The PDU session.
    let req = sm::establishment_request(1, 7, 1, 1);
    let ul = nas::ul_nas_transport_sm(
        1,
        1,
        Some(&nas::Snssai { sst: 1, sd: None }),
        Some("internet"),
        &req,
    )
    .unwrap();
    gnb.uplink_protected(&ul).await;
    let p = gnb.recv("PDU Session Resource Setup Request").await;
    assert_eq!(
        (p.kind, p.procedure_code),
        (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_SETUP),
        "got {}",
        p.label()
    );
    let (_, _, items) = codec::parse_pdu_session_resource_setup_request(&p).unwrap();
    assert_eq!(items.len(), 1);
    let transfer = codec::decode_setup_request_transfer(&items[0].transfer).unwrap();
    assert_eq!(transfer.ul_tunnel.address.to_string(), "127.0.0.1");
    assert_eq!(transfer.pdu_session_type, "ipv4");
    assert_eq!(transfer.qos_flows[0].qfi, 1);
    assert_eq!(transfer.qos_flows[0].five_qi, 9);
    let sm_plain = gnb.unprotect(items[0].nas.as_ref().unwrap());
    let t = nas::parse_dl_nas_transport(&sm_plain).unwrap();
    assert_eq!(t.pdu_session_id, Some(1));
    let a = sm::parse_establishment_accept(&t.payload).unwrap();
    assert_eq!((a.psi, a.pti), (1, 7), "the PTI of the request comes back");
    assert_eq!(a.address.unwrap().to_string(), "10.45.0.2");
    assert_eq!(a.qfis, vec![1]);
    assert_eq!(a.dnn.as_deref(), Some("internet"));

    // The gNB's side of the tunnel.
    let gtp = UdpSocket::bind("127.0.0.1:2152")
        .await
        .expect("the lab gNB needs 127.0.0.1:2152 for its downlink tunnel");
    let dl_teid = 0x00ab_cdef;
    gnb.send(
        &codec::pdu_session_resource_setup_response(
            gnb.amf_id,
            1,
            &[(
                1,
                codec::SetupResponseTransfer {
                    dl_tunnel: codec::GtpTunnel {
                        address: "127.0.0.1".parse().unwrap(),
                        teid: dl_teid,
                    },
                    qfis: vec![1],
                },
            )],
            &[],
        )
        .unwrap(),
    )
    .await;
    wait_line(&mut rx, &mut seen, "decision=pdu_session_established").await;

    // Echo through the tunnel: answered for the model's address, dropped for any other or
    // from a source that is not the UE's.
    let upf = format!("127.0.0.1:{upf_port}");
    let ul_teid = transfer.ul_tunnel.teid;
    gtp.send_to(
        &gpdu(ul_teid, echo_request([10, 45, 0, 2], [10, 45, 0, 1], 1)),
        &upf,
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(WIRE, gtp.recv_from(&mut buf))
        .await
        .expect("no echo reply through the tunnel")
        .unwrap();
    let reply = GtpV1Message::decode(&buf[..n]).unwrap();
    assert_eq!(
        reply.header.teid, dl_teid,
        "sent on the gNB's downlink TEID"
    );
    assert_eq!(reply.header.extension_headers[0].ext_type, 0x85);
    assert_eq!(
        reply.header.extension_headers[0].content[1] & 0x3f,
        1,
        "QFI 1"
    );
    assert_eq!(&reply.body[12..16], &[10, 45, 0, 1]);
    assert_eq!(&reply.body[16..20], &[10, 45, 0, 2]);
    assert_eq!(reply.body[20], 0, "ICMP echo reply");
    for (src, dst) in [
        ([10, 45, 0, 2], [10, 45, 0, 9]),
        ([10, 45, 0, 3], [10, 45, 0, 1]),
    ] {
        gtp.send_to(&gpdu(ul_teid, echo_request(src, dst, 2)), &upf)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), gtp.recv_from(&mut buf))
                .await
                .is_err(),
            "{src:?} -> {dst:?} was answered"
        );
    }

    // Deregistration under security: a protected accept, then the release.
    let identity = nas::guti_octets(
        &codec::Plmn::from_json(&json!("001-01")).unwrap(),
        2,
        1,
        0,
        3405691582,
    );
    gnb.uplink_protected(&nas::deregistration_request(0, false, &identity))
        .await;
    let accept_wire = gnb.dl_nas("Deregistration Accept").await;
    let plain = gnb.unprotect(&accept_wire);
    assert_eq!(plain[2], nas::DEREGISTRATION_ACCEPT_UE_ORIGINATING);
    let rel = gnb.recv("UE Context Release Command").await;
    assert_eq!(rel.procedure_code, codec::PROC_UE_CONTEXT_RELEASE);
    assert_eq!(
        codec::parse_cause_message(&rel).unwrap()["cause"],
        json!({"group": "nas", "value": "deregister"})
    );
    gnb.send(&codec::ue_context_release_complete(gnb.amf_id, 1).unwrap())
        .await;

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.unwrap();
    // No model call per NAS message: the UE's messages never became events.
    assert!(events(&state, id, "ngap_initial_ue_message")
        .await
        .is_empty());
    assert!(events(&state, id, "ngap_uplink_nas_transport")
        .await
        .is_empty());
    let reg = &events(&state, id, "ngap_registration_request").await[0];
    assert_eq!(reg["authenticated"], true);
    assert_eq!(reg["nas_security"]["integrity"], "NIA2");
    let pdu = &events(&state, id, "ngap_pdu_session_establishment_request").await[0];
    assert_eq!(pdu["s_nssai"], json!({"sst": 1}));
    assert_eq!(pdu["user_plane_available"], true);
    // The keys are nowhere the model or the operator reads.
    drain(&mut rx, &mut seen);
    let everything = format!(
        "{}\n{}",
        serde_json::to_string(
            &state
                .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
                .await
        )
        .unwrap(),
        seen.join("\n")
    )
    .to_ascii_uppercase();
    assert!(
        !everything.contains(K) && !everything.contains(OPC),
        "a key leaked"
    );
    assert_ngap_clean(&gnb.log);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nea2_ciphers_and_a_forged_or_replayed_uplink_is_discarded() {
    let (state, id, port, mut rx) = start(
        Some(script(POLICY)),
        UNREACHABLE_LLM,
        json!({"nas_ciphering": "nea2",
               "user_plane_address": format!("127.0.0.1:{}", probe_udp_port())}),
    )
    .await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    assert_eq!(gnb.authenticate().await, (security::NIA2, security::NEA2));
    gnb.complete_registration().await;
    wait_line(&mut rx, &mut seen, "decision=ue_registered").await;

    let req = sm::establishment_request(1, 1, 1, 1);
    let ul = nas::ul_nas_transport_sm(1, 1, None, Some("internet"), &req).unwrap();
    // A flipped MAC bit: discarded before anything reads it.
    let mut forged = gnb
        .ctx
        .as_mut()
        .unwrap()
        .protect(&ul, security::SHT_INTEGRITY_CIPHERED);
    forged[3] ^= 0x01;
    gnb.uplink(&forged).await;
    wait_line(&mut rx, &mut seen, "decision=nas_integrity_failure").await;
    // An unprotected message once security is on: discarded too.
    gnb.uplink(&ul).await;
    wait_line(&mut rx, &mut seen, "decision=nas_unprotected_refused").await;
    // The genuine message at the next COUNT is accepted; the same octets again are a replay.
    let genuine = gnb.uplink_protected(&ul).await;
    let p = gnb.recv("PDU Session Resource Setup Request").await;
    assert_eq!(
        p.procedure_code,
        codec::PROC_PDU_SESSION_RESOURCE_SETUP,
        "{}",
        p.label()
    );
    gnb.uplink(&genuine).await;
    wait_line(&mut rx, &mut seen, "decision=nas_count_replay").await;
    assert!(
        gnb.silent(Duration::from_millis(500)).await,
        "a replay was answered"
    );
    assert_eq!(
        events(&state, id, "ngap_pdu_session_establishment_request")
            .await
            .len(),
        1,
        "the forged, plain and replayed copies never reached the model"
    );
    assert_ngap_clean(&gnb.log);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_user_plane_an_accepted_session_is_refused() {
    let (_state, _id, port, mut rx) = start(Some(script(POLICY)), UNREACHABLE_LLM, json!({})).await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    gnb.complete_registration().await;
    let req = sm::establishment_request(1, 3, 1, 1);
    gnb.uplink_protected(&nas::ul_nas_transport_sm(1, 1, None, None, &req).unwrap())
        .await;
    let wire = gnb.dl_nas("PDU Session Establishment Reject").await;
    let plain = gnb.unprotect(&wire);
    let t = nas::parse_dl_nas_transport(&plain).unwrap();
    assert_eq!(&t.payload, &sm::establishment_reject(1, 3, 26));
    wait_line(&mut rx, &mut seen, "decision=no_user_plane").await;
    assert_ngap_clean(&gnb.log);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_model_rejects_the_subscriber_and_its_sessions() {
    // The registration decision: nothing answers it.
    let only_setup = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
          "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
print(json.dumps({"actions": a}))"#;
    let (_state, _id, port, mut rx) =
        start(Some(script(only_setup)), UNREACHABLE_LLM, json!({})).await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    let wire = gnb.dl_nas("Registration Reject").await;
    assert_eq!(wire[1], 2, "the reject is protected");
    let plain = gnb.unprotect(&wire);
    assert_eq!(plain, nas::registration_reject(111));
    let rel = gnb.recv("UE Context Release Command").await;
    assert_eq!(rel.procedure_code, codec::PROC_UE_CONTEXT_RELEASE);
    wait_line(&mut rx, &mut seen, "decision=model_silent").await;

    // The session decision: the model registers the UE and then says nothing.
    let (_s, _i, port, mut rx) = start(
        Some(script(ADMIT_ONLY)),
        UNREACHABLE_LLM,
        json!({"user_plane_address": format!("127.0.0.1:{}", probe_udp_port())}),
    )
    .await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    gnb.complete_registration().await;
    let req = sm::establishment_request(2, 9, 1, 1);
    gnb.uplink_protected(&nas::ul_nas_transport_sm(2, 1, None, None, &req).unwrap())
        .await;
    let wire = gnb.dl_nas("PDU Session Establishment Reject").await;
    let plain = gnb.unprotect(&wire);
    let t = nas::parse_dl_nas_transport(&plain).unwrap();
    assert_eq!(&t.payload, &sm::establishment_reject(2, 9, 31));
    wait_line(&mut rx, &mut seen, "decision=model_silent").await;
    assert_ngap_clean(&gnb.log);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_model_rejects_the_authenticated_subscriber() {
    // NG Setup is admitted by a static rule; the registration decision goes to a model that
    // cannot be reached.
    let handlers = vec![
        json!({"event_pattern": "ngap_ng_setup_request", "handler": {"type": "static", "actions": [{
        "type": "send_ng_setup_response", "amf_name": "netget-amf",
        "served_guami": [{"plmn": "001-01", "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
        "plmn_support": [{"plmn": "001-01", "slices": [{"sst": 1}]}]}]}}),
    ];
    let (_state, _id, port, mut rx) = start(Some(handlers), UNREACHABLE_LLM, json!({})).await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    let wire = gnb.dl_nas("Registration Reject").await;
    let plain = gnb.unprotect(&wire);
    assert_eq!(plain[2], nas::REGISTRATION_REJECT);
    assert!(
        matches!(plain[3], 22 | 111),
        "congestion or protocol error, not an accept"
    );
    wait_line(&mut rx, &mut seen, "decision=fail_closed_llm_error").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_res_star_or_an_unverifiable_autn_ends_in_authentication_reject() {
    let (state, id, port, mut rx) = start(Some(script(POLICY)), UNREACHABLE_LLM, json!({})).await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.send(
        &codec::initial_ue_message(1, &registration_request(), &uli(), "mo-Signalling").unwrap(),
    )
    .await;
    let auth = gnb.dl_nas("Authentication Request").await;
    assert!(nas::parse_authentication_request(&auth).is_ok());
    gnb.uplink(&nas::authentication_response(&[0x5a; 16])).await;
    let reject = gnb.dl_nas("Authentication Reject").await;
    assert_eq!(reject, nas::authentication_reject());
    wait_line(&mut rx, &mut seen, "decision=auth_res_mismatch").await;
    let rel = gnb.recv("UE Context Release Command").await;
    assert_eq!(rel.procedure_code, codec::PROC_UE_CONTEXT_RELEASE);

    // A second UE whose USIM holds another key: it reports MAC failure.
    let pdu =
        codec::initial_ue_message(2, &registration_request(), &uli(), "mo-Signalling").unwrap();
    gnb.send(&pdu).await;
    let _ = gnb.dl_nas("Authentication Request").await;
    let p = codec::uplink_nas_transport(
        gnb.amf_id,
        2,
        &nas::authentication_failure(nas::CAUSE_MAC_FAILURE, None),
        &uli(),
    )
    .unwrap();
    gnb.send(&p).await;
    let reject = gnb.dl_nas("Authentication Reject").await;
    assert_eq!(reject, nas::authentication_reject());
    wait_line(&mut rx, &mut seen, "decision=auth_mac_failure").await;
    assert!(
        events(&state, id, "ngap_registration_request")
            .await
            .is_empty(),
        "an unauthenticated UE was offered to the model"
    );
    assert_ngap_clean(&gnb.log);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_sqn_is_resynchronised_from_auts_once() {
    let (_state, _id, port, mut rx) = start(Some(script(POLICY)), UNREACHABLE_LLM, json!({})).await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    // The USIM has already seen SQN 0x1000; the AMF starts at 0, so its first AUTN is stale.
    gnb.sqn_ms = 0x1000;
    gnb.setup().await;
    gnb.authenticate().await;
    assert_eq!(
        gnb.sqn_ms, 0x1020,
        "the retried vector continues from the UE's SQN"
    );
    wait_line(&mut rx, &mut seen, "decision=auth_resync").await;
    gnb.complete_registration().await;
    wait_line(&mut rx, &mut seen, "decision=ue_registered").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_subscriber_is_left_to_the_model_unauthenticated() {
    let (state, id, port, mut rx) = start(Some(script(POLICY)), UNREACHABLE_LLM, json!({})).await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    let other = nas::encode(
        &json!({"message": "registration_request",
                "mobile_identity": {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"}, "msin": "0000000999"}}),
        nas::UPLINK_MESSAGES,
    )
    .unwrap();
    gnb.send(&codec::initial_ue_message(1, &other, &uli(), "mo-Signalling").unwrap())
        .await;
    // The POLICY has no rule for ngap_initial_ue_message: the model saying nothing is a reject.
    let reject = gnb.dl_nas("Registration Reject").await;
    assert_eq!(nas::decode(&reject)["cause"]["value"], 111);
    wait_line(&mut rx, &mut seen, "decision=no_credentials").await;
    assert_eq!(events(&state, id, "ngap_initial_ue_message").await.len(), 1);
}
