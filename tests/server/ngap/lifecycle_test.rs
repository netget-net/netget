//! The rest of a registered UE's life on NetGet's AMF, in-process over the **non-standard lab TCP
//! transport** with a scripted UE: PDU session modification and release (UE- and
//! network-requested), CM-IDLE, Service Request with its NAS message container, paging, a
//! decision queued for an idle UE, IPv6 sessions with ICMPv6 echo and Router Advertisement, the
//! operator's NAS algorithm preference, and the fail-closed answer to each new model decision.
//!
//! The UE is scripted from NetGet's own `security`, `nas` and `sm` modules, so this suite proves
//! the session logic, the bounds and the refusals — not interoperability: UERANSIM is that
//! evidence (`real_client_test.rs`), and Open5GS on the gNB side (`tests/client/ngap/`). Every
//! NGAP PDU in both directions goes through tshark's ngap dissector; the user-plane answers go
//! through its gtp/icmp/icmpv6 dissectors, which verify the checksums NetGet computed.
//!
//! LLM budget: **seven calls**, all in `a_session_is_modified_released_idled_and_paged_back`: the
//! gNB, the subscriber, three PDU sessions, one modification request and one release request —
//! and none for the Service Requests, the paging, the idle transitions or the network-requested
//! release and modification, which are Rust's or the operator's injected actions.
use super::security_e2e_test::{
    events, gpdu, probe_udp_port, script, start, wait_line, Gnb, ADMIT_ONLY, UNREACHABLE_LLM, WIRE,
};
use super::support::{assert_ngap_clean, GTPU_2152};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::gtp::codec::GtpV1Message;
use netget::server::ngap::codec::{self, PduKind};
use netget::server::ngap::{nas, security, sm};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::UdpSocket;

const SUPI_LABEL: &str = "imsi-001010000000001";
/// The 5G-TMSI the model assigns: the AMF's GUAMI has set 1, pointer 0.
const TMSI: u32 = 0x0A0B_0C0D;

fn uli() -> Value {
    super::security_e2e_test::uli()
}

/// The mocked model's answer to NG Setup.
fn admit_gnb() -> Value {
    json!([{
        "type": "send_ng_setup_response",
        "amf_name": "mocked-amf",
        "served_guami": [{"plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
        "plmn_support": [{"plmn": {"mcc": "001", "mnc": "01"}, "slices": [{"sst": 1}]}]
    }])
}

/// The one live connection's id, for injected actions.
async fn connection(state: &AppState, id: ServerId) -> u32 {
    let server = state.get_server(id).await.expect("the server exists");
    server
        .connections
        .keys()
        .next()
        .expect("the gNB's association is registered")
        .as_u32()
}

/// Inject an action into the association, as the dashboard or MCP `send_to_peer` would.
async fn inject(state: &AppState, id: ServerId, action: Value) -> Value {
    let conn = connection(state, id).await;
    let outcome = state
        .send_to_peer(id, conn, action.clone(), Duration::from_secs(10))
        .await
        .unwrap_or_else(|e| panic!("injecting {action}: {e}"));
    serde_json::to_value(outcome).unwrap()
}

impl Gnb {
    /// Ask for a PDU session and answer its resource setup with a downlink tunnel on
    /// 127.0.0.1. Returns the uplink TEID and the 5GSM accept.
    async fn session(
        &mut self,
        psi: u8,
        pti: u8,
        pdu_session_type: u8,
        dl_teid: u32,
    ) -> (u32, sm::ParsedAccept, codec::SetupRequestTransfer) {
        let req = sm::establishment_request(psi, pti, pdu_session_type, 1);
        let ul = nas::ul_nas_transport_sm(
            psi,
            1,
            Some(&nas::Snssai { sst: 1, sd: None }),
            Some("internet"),
            &req,
        )
        .unwrap();
        self.uplink_protected(&ul).await;
        let p = self.recv("PDU Session Resource Setup Request").await;
        assert_eq!(
            (p.kind, p.procedure_code),
            (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_SETUP),
            "got {}",
            p.label()
        );
        let (_, _, items) = codec::parse_pdu_session_resource_setup_request(&p).unwrap();
        let transfer = codec::decode_setup_request_transfer(&items[0].transfer).unwrap();
        let plain = self.unprotect(items[0].nas.as_ref().unwrap());
        let t = nas::parse_dl_nas_transport(&plain).unwrap();
        let accept = sm::parse_establishment_accept(&t.payload).unwrap();
        self.send(
            &codec::pdu_session_resource_setup_response(
                self.amf_id,
                1,
                &[(psi, dl_tunnel(dl_teid))],
                &[],
            )
            .unwrap(),
        )
        .await;
        (transfer.ul_tunnel.teid, accept, transfer)
    }

    /// A 5GSM message of the UE's, protected, in an UL NAS Transport.
    async fn sm_uplink(&mut self, psi: u8, sm: &[u8]) {
        let ul = nas::ul_nas_transport_sm(psi, 1, None, None, sm).unwrap();
        self.uplink_protected(&ul).await;
    }

    /// The 5GSM message inside a protected NAS-PDU.
    fn sm_of(&mut self, nas_pdu: &[u8]) -> Vec<u8> {
        let plain = self.unprotect(nas_pdu);
        nas::parse_dl_nas_transport(&plain)
            .expect("a DL NAS Transport")
            .payload
    }

    /// Release the UE's N2 context the way a gNB does when the AMF commands it: the UE goes idle.
    async fn complete_release(&mut self) -> Value {
        let rel = self.recv("UE Context Release Command").await;
        assert_eq!(
            (rel.kind, rel.procedure_code),
            (PduKind::Initiating, codec::PROC_UE_CONTEXT_RELEASE),
            "got {}",
            rel.label()
        );
        let cause = codec::parse_cause_message(&rel).unwrap()["cause"].clone();
        self.send(&codec::ue_context_release_complete(self.amf_id, 1).unwrap())
            .await;
        cause
    }

    /// The UE's Service Request as TS 24.501 4.4.6 builds it from CM-IDLE: the whole message,
    /// ciphered at the outer message's COUNT, in the NAS message container; outside it only the
    /// cleartext IEs; integrity protected, not ciphered (security header type 1).
    fn service_request(&mut self, service_type: u8, uplink: Option<u16>, status: u16) -> Vec<u8> {
        let ctx = self.ctx.as_mut().unwrap();
        let full = nas::service_request(&nas::ServiceRequest {
            service_type,
            ngksi: ctx.ngksi,
            amf_set_id: 1,
            amf_pointer: 0,
            tmsi: TMSI,
            uplink_data_status: uplink,
            pdu_session_status: Some(status),
            allowed_pdu_session_status: None,
            nas_container: None,
        });
        let count = ctx.counts.tx;
        let mut container = full;
        ctx.cipher_at(count, security::UPLINK, &mut container);
        let outer = nas::service_request(&nas::ServiceRequest {
            service_type,
            ngksi: ctx.ngksi,
            amf_set_id: 1,
            amf_pointer: 0,
            tmsi: TMSI,
            uplink_data_status: None,
            pdu_session_status: None,
            allowed_pdu_session_status: None,
            nas_container: Some(container),
        });
        ctx.protect(&outer, security::SHT_INTEGRITY)
    }

    async fn send_service_request(&mut self, wire: &[u8]) {
        self.send(
            &codec::initial_ue_message_with_tmsi(1, wire, &uli(), "mo-Data", Some((1, 0, TMSI)))
                .unwrap(),
        )
        .await;
    }

    /// The Initial Context Setup answering a verified Service Request: K_gNB, the Service
    /// Accept and the sessions whose user plane comes back. Answered with `dl_teid` for each.
    async fn service_accepted(&mut self, dl_teid: u32) -> (nas::ServiceAccept, Vec<(u8, u32)>) {
        let p = self.recv("Initial Context Setup Request (Service Accept)").await;
        assert_eq!(
            (p.kind, p.procedure_code),
            (PduKind::Initiating, codec::PROC_INITIAL_CONTEXT_SETUP),
            "got {}",
            p.label()
        );
        let ics = codec::parse_initial_context_setup_request(&p).unwrap();
        self.amf_id = ics.amf_ue_ngap_id;
        assert_eq!(
            ics.security_key,
            self.ctx.as_ref().unwrap().k_gnb(),
            "K_gNB from the Service Request's uplink COUNT (TS 33.501 A.9)"
        );
        let wire = ics.nas.expect("the Service Accept rides in the ICS");
        assert_eq!(wire[1], 2, "integrity protected and ciphered");
        let plain = self.unprotect(&wire);
        let accept = nas::parse_service_accept(&plain).expect("a Service Accept");
        let sessions: Vec<(u8, u32)> = ics
            .pdu_sessions
            .iter()
            .map(|it| {
                assert!(it.nas.is_none());
                let t = codec::decode_setup_request_transfer(&it.transfer).unwrap();
                (it.pdu_session_id, t.ul_tunnel.teid)
            })
            .collect();
        let established: Vec<(u8, codec::SetupResponseTransfer)> = sessions
            .iter()
            .map(|(psi, _)| (*psi, dl_tunnel(dl_teid)))
            .collect();
        self.send(
            &codec::initial_context_setup_response(self.amf_id, 1, &established, &[]).unwrap(),
        )
        .await;
        (accept, sessions)
    }
}

fn dl_tunnel(teid: u32) -> codec::SetupResponseTransfer {
    codec::SetupResponseTransfer {
        dl_tunnel: codec::GtpTunnel {
            address: "127.0.0.1".parse().unwrap(),
            teid,
        },
        qfis: vec![1],
    }
}

fn echo_v4(src: [u8; 4], seq: u16) -> Vec<u8> {
    super::security_e2e_test::echo_request(src, [10, 45, 0, 1], seq)
}

/// Send one G-PDU and return the answer, or `None` within half a second.
async fn ping(gtp: &UdpSocket, upf: &str, teid: u32, packet: Vec<u8>) -> Option<GtpV1Message> {
    gtp.send_to(&gpdu(teid, packet), upf).await.unwrap();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(500), gtp.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(GtpV1Message::decode(&buf[..n]).unwrap()),
        _ => None,
    }
}

/// Wait for the AMF to answer a ping on `teid` (the downlink tunnel is set up when the gNB's
/// response has been processed, which the test does not otherwise observe).
async fn ping_until_answered(gtp: &UdpSocket, upf: &str, teid: u32, src: [u8; 4]) -> GtpV1Message {
    let deadline = tokio::time::Instant::now() + WIRE;
    let mut seq = 100;
    loop {
        if let Some(r) = ping(gtp, upf, teid, echo_v4(src, seq)).await {
            return r;
        }
        seq += 1;
        assert!(
            tokio::time::Instant::now() < deadline,
            "TEID {teid:#x} never answered"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_is_modified_released_idled_and_paged_back() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ngap_ng_setup_request")
            .respond_with_actions(admit_gnb())
            .expect_calls(1)
            .and()
            .on_event("ngap_registration_request")
            .and_event_data_contains("supi", SUPI_LABEL)
            .respond_with_actions_from_event(|e| {
                json!([{"type": "send_registration_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                        "allowed_nssai": [{"sst": 1}], "tmsi": TMSI}])
            })
            .expect_calls(1)
            .and()
            .on_event("ngap_pdu_session_establishment_request")
            .respond_with_actions_from_event(|e| {
                let psi = e["pdu_session_id"].as_u64().unwrap();
                json!([{"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                        "pdu_session_id": psi, "ue_ipv4": format!("10.45.0.{}", psi + 1),
                        "reachable_addresses": ["10.45.0.1"]}])
            })
            .expect_calls(3)
            .and()
            .on_event("ngap_pdu_session_modification_request")
            .respond_with_actions_from_event(|e| {
                json!([{"type": "send_pdu_session_modification", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                        "pdu_session_id": e["pdu_session_id"], "five_qi": e["requested_five_qi"],
                        "session_ambr": {"uplink_kbps": 50000, "downlink_kbps": 100000}}])
            })
            .expect_calls(1)
            .and()
            .on_event("ngap_pdu_session_release_request")
            .respond_with_actions_from_event(|e| {
                json!([{"type": "send_pdu_session_release", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
                        "pdu_session_id": e["pdu_session_id"]}])
            })
            .expect_calls(1)
            .build(),
    )
    .await
    .unwrap();
    let upf_port = probe_udp_port();
    let upf = format!("127.0.0.1:{upf_port}");
    let (state, id, port, mut rx) = start(
        None,
        &mock.base_url(),
        json!({"user_plane_address": upf.clone()}),
    )
    .await;
    let mut seen = Vec::new();
    let _gtpu = GTPU_2152.lock().await;
    let gtp = UdpSocket::bind("127.0.0.1:2152")
        .await
        .expect("the lab gNB needs 127.0.0.1:2152 for its downlink tunnels");
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    gnb.complete_registration().await;
    wait_line(&mut rx, &mut seen, "decision=ue_registered").await;

    // Session 1, and its user plane.
    let (teid1, accept1, _) = gnb.session(1, 1, 1, 0x1111).await;
    assert_eq!(accept1.address.unwrap().to_string(), "10.45.0.2");
    let r = ping_until_answered(&gtp, &upf, teid1, [10, 45, 0, 2]).await;
    assert_eq!(r.header.teid, 0x1111);

    // UE-requested modification: the model gives the 5QI it asked for and a new AMBR.
    gnb.sm_uplink(1, &sm::modification_request(1, 2, 1, Some(7)))
        .await;
    let p = gnb.recv("PDU Session Resource Modify Request").await;
    assert_eq!(
        (p.kind, p.procedure_code),
        (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_MODIFY),
        "got {}",
        p.label()
    );
    let (_, _, items) = codec::parse_pdu_session_resource_modify_request(&p).unwrap();
    assert_eq!(items[0].pdu_session_id, 1);
    let t = codec::decode_modify_request_transfer(&items[0].transfer).unwrap();
    assert_eq!(t.ambr_ul_bps, Some(50_000_000));
    assert_eq!(t.ambr_dl_bps, Some(100_000_000));
    assert_eq!(t.qos_flows.len(), 1);
    assert_eq!((t.qos_flows[0].qfi, t.qos_flows[0].five_qi), (1, 7));
    let cmd = gnb.sm_of(items[0].nas.as_ref().unwrap());
    let c = sm::parse_procedure(&cmd).unwrap();
    assert_eq!(
        (c.message_type, c.psi, c.pti),
        (sm::PDU_SESSION_MODIFICATION_COMMAND, 1, 2),
        "the command answers the request's PTI"
    );
    assert_eq!(c.flow_five_qi, Some((1, 7)));
    assert_eq!(
        (c.ambr_uplink_kbps, c.ambr_downlink_kbps),
        (Some(50_000), Some(100_000))
    );
    gnb.send(
        &codec::pdu_session_resource_modify_response(
            gnb.amf_id,
            1,
            &[(1, codec::ModifyResponseTransfer { qfis: vec![1] })],
            &[],
        )
        .unwrap(),
    )
    .await;
    gnb.sm_uplink(1, &sm::modification_complete(1, 2)).await;
    wait_line(&mut rx, &mut seen, "decision=pdu_session_modified").await;

    // Session 2, released at the UE's request: the model answers, Rust releases.
    let (teid2, _, _) = gnb.session(2, 3, 1, 0x2222).await;
    ping_until_answered(&gtp, &upf, teid2, [10, 45, 0, 3]).await;
    gnb.sm_uplink(2, &sm::release_request(2, 4, Some(sm::CAUSE_REGULAR_DEACTIVATION)))
        .await;
    let p = gnb.recv("PDU Session Resource Release Command").await;
    assert_eq!(
        (p.kind, p.procedure_code),
        (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_RELEASE),
        "got {}",
        p.label()
    );
    let rc = codec::parse_pdu_session_resource_release_command(&p).unwrap();
    assert_eq!(rc.sessions.len(), 1);
    assert_eq!(rc.sessions[0].0, 2);
    let cmd = gnb.sm_of(rc.nas.as_ref().unwrap());
    let c = sm::parse_procedure(&cmd).unwrap();
    assert_eq!(
        (c.message_type, c.psi, c.pti, c.cause),
        (
            sm::PDU_SESSION_RELEASE_COMMAND,
            2,
            4,
            Some(sm::CAUSE_REGULAR_DEACTIVATION)
        )
    );
    // The tunnel stopped answering when the command went out.
    assert!(
        ping(&gtp, &upf, teid2, echo_v4([10, 45, 0, 3], 1))
            .await
            .is_none(),
        "the released session's TEID still answers"
    );
    gnb.send(&codec::pdu_session_resource_release_response(gnb.amf_id, 1, &[2]).unwrap())
        .await;
    gnb.sm_uplink(2, &sm::release_complete(2, 4)).await;
    wait_line(&mut rx, &mut seen, "decision=pdu_session_released").await;

    // CM-IDLE: the operator releases the UE's context; it keeps its registration and session 1.
    let out = inject(
        &state,
        id,
        json!({"type": "send_ue_context_release_command", "amf_ue_ngap_id": gnb.amf_id,
               "ran_ue_ngap_id": 1, "cause": "radioNetwork/user-inactivity"}),
    )
    .await;
    assert!(out.to_string().contains("sent"), "{out}");
    assert_eq!(
        gnb.complete_release().await,
        json!({"group": "radioNetwork", "value": "user-inactivity"})
    );
    wait_line(&mut rx, &mut seen, "decision=ue_idle").await;
    assert!(
        ping(&gtp, &upf, teid1, echo_v4([10, 45, 0, 2], 2))
            .await
            .is_none(),
        "an idle UE's session has no downlink tunnel"
    );

    // A Service Request whose MAC does not verify is refused and the real UE is not evicted.
    let mut forged = gnb.service_request(nas::SERVICE_TYPE_DATA, Some(nas::psi_bits([1])), nas::psi_bits([1]));
    forged[3] ^= 0x01;
    gnb.send_service_request(&forged).await;
    let reject = gnb.dl_nas("Service Reject").await;
    assert_eq!(reject, nas::service_reject(9), "plain Service Reject #9");
    gnb.complete_release().await;
    wait_line(&mut rx, &mut seen, "decision=nas_integrity_failure").await;
    // A Service Request naming a 5G-TMSI nobody holds: Service Reject #9.
    {
        let mut stranger = gnb.service_request(nas::SERVICE_TYPE_SIGNALLING, None, 0);
        // The 5G-TMSI is the last four octets of the cleartext 5G-S-TMSI; corrupting it also
        // breaks the MAC, which is not what is checked here — the lookup comes first.
        let at = 7 + 4 + 2 + 3;
        stranger[at] ^= 0xFF;
        gnb.send_service_request(&stranger).await;
        assert_eq!(
            gnb.dl_nas("Service Reject").await,
            nas::service_reject(9)
        );
        gnb.complete_release().await;
        wait_line(&mut rx, &mut seen, "decision=service_request_unknown_ue").await;
    }

    // The UE's COUNT moved on when it built that message; a real UE's next one is higher.
    let sr = gnb.service_request(
        nas::SERVICE_TYPE_DATA,
        Some(nas::psi_bits([1])),
        nas::psi_bits([1]),
    );
    gnb.send_service_request(&sr).await;
    let (accept, sessions) = gnb.service_accepted(0x3333).await;
    assert_eq!(accept.pdu_session_status, Some(nas::psi_bits([1])));
    assert_eq!(sessions, vec![(1, teid1)], "session 1 comes back on its own TEID");
    wait_line(&mut rx, &mut seen, "decision=service_accept").await;
    let r = ping_until_answered(&gtp, &upf, teid1, [10, 45, 0, 2]).await;
    assert_eq!(r.header.teid, 0x3333, "the new downlink tunnel");

    // A network-requested release while connected: PTI 0, the operator's cause.
    inject(
        &state,
        id,
        json!({"type": "send_pdu_session_release", "supi": SUPI_LABEL, "pdu_session_id": 1,
               "cause": "network_failure"}),
    )
    .await;
    let p = gnb.recv("network-requested release").await;
    let rc = codec::parse_pdu_session_resource_release_command(&p).unwrap();
    let c = sm::parse_procedure(&gnb.sm_of(rc.nas.as_ref().unwrap())).unwrap();
    assert_eq!((c.pti, c.cause), (0, Some(sm::CAUSE_NETWORK_FAILURE)));
    gnb.sm_uplink(1, &sm::release_complete(1, 0)).await;
    seen.retain(|l| !l.contains("decision=pdu_session_released"));
    wait_line(&mut rx, &mut seen, "decision=pdu_session_released").await;

    // A third session, then idle again; a modification addressed to the idle UE pages it, and
    // the modification runs once its Service Request is accepted.
    let (teid3, _, _) = gnb.session(3, 5, 1, 0x4444).await;
    ping_until_answered(&gtp, &upf, teid3, [10, 45, 0, 4]).await;
    inject(
        &state,
        id,
        json!({"type": "send_ue_context_release_command", "amf_ue_ngap_id": gnb.amf_id,
               "ran_ue_ngap_id": 1, "cause": "radioNetwork/user-inactivity"}),
    )
    .await;
    gnb.complete_release().await;
    seen.retain(|l| !l.contains("decision=ue_idle"));
    wait_line(&mut rx, &mut seen, "decision=ue_idle").await;
    let out = inject(
        &state,
        id,
        json!({"type": "send_pdu_session_modification", "supi": SUPI_LABEL,
               "pdu_session_id": 3, "five_qi": 6}),
    )
    .await;
    assert!(!out.to_string().contains("rejected"), "{out}");
    let p = gnb.recv("Paging").await;
    assert_eq!(
        (p.kind, p.procedure_code),
        (PduKind::Initiating, codec::PROC_PAGING),
        "got {}",
        p.label()
    );
    let paging = codec::parse_paging(&p).unwrap();
    assert_eq!(
        (paging.amf_set_id, paging.amf_pointer, paging.tmsi),
        (1, 0, TMSI)
    );
    assert_eq!(paging.tais[0].1, 1, "paged in its last tracking area");
    wait_line(&mut rx, &mut seen, "decision=paging").await;
    let sr = gnb.service_request(
        nas::SERVICE_TYPE_MOBILE_TERMINATED,
        None,
        nas::psi_bits([3]),
    );
    gnb.send_service_request(&sr).await;
    let (_, sessions) = gnb.service_accepted(0x5555).await;
    assert_eq!(
        sessions,
        vec![(3, teid3)],
        "a paged UE gets its sessions' user plane back"
    );
    let p = gnb.recv("the queued modification").await;
    assert_eq!(p.procedure_code, codec::PROC_PDU_SESSION_RESOURCE_MODIFY);
    let (amf, _, items) = codec::parse_pdu_session_resource_modify_request(&p).unwrap();
    assert_eq!(amf, gnb.amf_id, "addressed to the UE's new AMF UE NGAP ID");
    let c = sm::parse_procedure(&gnb.sm_of(items[0].nas.as_ref().unwrap())).unwrap();
    assert_eq!((c.pti, c.flow_five_qi), (0, Some((1, 6))));

    // An explicit page of a connected UE is refused, with the reason.
    let out = inject(
        &state,
        id,
        json!({"type": "send_paging", "supi": SUPI_LABEL}),
    )
    .await;
    assert!(out.to_string().contains("connected"), "{out}");

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.unwrap();
    for (event, n) in [
        ("ngap_ng_setup_request", 1),
        ("ngap_registration_request", 1),
        ("ngap_pdu_session_establishment_request", 3),
        ("ngap_pdu_session_modification_request", 1),
        ("ngap_pdu_session_release_request", 1),
        ("ngap_initial_ue_message", 0),
        ("ngap_uplink_nas_transport", 0),
    ] {
        assert_eq!(
            events(&state, id, event).await.len(),
            n,
            "{event}: the model is asked per decision, never per NAS message"
        );
    }
    let req = &events(&state, id, "ngap_pdu_session_modification_request").await[0];
    assert_eq!(req["session"]["five_qi"], 9, "{req}");
    assert_ngap_clean(&gnb.log);
}

/// IPv6 and IPv4v6 sessions: the PDU address carries the model's interface identifier, the
/// user plane answers a Router Solicitation with the model's prefix and an ICMPv6 echo to the
/// model's address, and tshark verifies every checksum.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_sessions_get_their_prefix_and_answer_icmpv6_echo() {
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
elif t == "ngap_pdu_session_establishment_request" and e["pdu_session_type"] == "ipv6":
    a = [{"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"], "ue_ipv6_prefix": "2001:db8:1:2::/64",
          "ue_ipv6_interface_identifier": "::2", "reachable_addresses": ["2001:db8:1:2::1"]}]
elif t == "ngap_pdu_session_establishment_request" and e["pdu_session_type"] == "ipv4v6":
    a = [{"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"], "ue_ipv4": "10.46.0.2",
          "ue_ipv6_prefix": "2001:db8:1:3::/64", "ue_ipv6_interface_identifier": "::abcd",
          "reachable_addresses": ["10.46.0.1", "2001:db8:1:3::1"]}]
print(json.dumps({"actions": a}))"#;
    let upf_port = probe_udp_port();
    let upf = format!("127.0.0.1:{upf_port}");
    let (_state, _id, port, mut rx) = start(
        Some(script(POLICY)),
        UNREACHABLE_LLM,
        json!({"user_plane_address": upf.clone()}),
    )
    .await;
    let mut seen = Vec::new();
    let _gtpu = GTPU_2152.lock().await;
    let gtp = UdpSocket::bind("127.0.0.1:2152").await.unwrap();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    gnb.complete_registration().await;
    wait_line(&mut rx, &mut seen, "decision=ue_registered").await;

    let (teid, accept, transfer) = gnb.session(1, 1, 2, 0x6666).await;
    assert_eq!(accept.pdu_session_type, 2, "IPv6");
    assert_eq!(accept.address, None);
    assert_eq!(accept.ipv6_iid, Some([0, 0, 0, 0, 0, 0, 0, 2]));
    assert_eq!(transfer.pdu_session_type, "ipv6");
    let (_, accept4, transfer4) = gnb.session(2, 2, 3, 0x7777).await;
    assert_eq!(accept4.pdu_session_type, 3, "IPv4v6");
    assert_eq!(accept4.address.unwrap().to_string(), "10.46.0.2");
    assert_eq!(accept4.ipv6_iid, Some([0, 0, 0, 0, 0, 0, 0xab, 0xcd]));
    assert_eq!(transfer4.pdu_session_type, "ipv4v6");

    let mut oracle = PcapOracle::udp("gtp").port(2152);
    let link_local: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
    let global: std::net::Ipv6Addr = "2001:db8:1:2::2".parse().unwrap();
    let router: std::net::Ipv6Addr = "ff02::2".parse().unwrap();
    // Router Solicitation from the UE's link-local address; wait for the downlink tunnel.
    let rs = icmpv6(&link_local, &router, 255, &[133, 0, 0, 0, 0, 0, 0, 0]);
    let deadline = tokio::time::Instant::now() + WIRE;
    let ra = loop {
        if let Some(r) = ping(&gtp, &upf, teid, rs.clone()).await {
            break r;
        }
        assert!(tokio::time::Instant::now() < deadline, "no Router Advertisement");
    };
    oracle = oracle.to_server(&gpdu(teid, rs.clone())).from_server(&ra.encode());
    assert_eq!(ra.header.teid, 0x6666);
    let body = &ra.body;
    assert_eq!(body[6], 58);
    assert_eq!(body[7], 255, "hop limit 255 (RFC 4861)");
    assert_eq!(body[40], 134, "Router Advertisement");
    assert_eq!(&body[24..40], &link_local.octets(), "to the solicitor");
    // Prefix Information: 2001:db8:1:2::/64.
    assert_eq!(&body[40 + 16..40 + 20], &[3, 4, 64, 0xC0]);
    assert_eq!(&body[40 + 32..40 + 40], &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]);

    // Echo to the model's address from the UE's global address.
    let dst: std::net::Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
    let echo = icmpv6(&global, &dst, 64, &[128, 0, 0, 0, 0x12, 0x34, 0, 1, b'n', b'g']);
    let reply = ping(&gtp, &upf, teid, echo.clone()).await.expect("an ICMPv6 echo reply");
    oracle = oracle.to_server(&gpdu(teid, echo)).from_server(&reply.encode());
    assert_eq!(reply.body[40], 129, "echo reply");
    assert_eq!(&reply.body[8..24], &dst.octets());
    assert_eq!(&reply.body[24..40], &global.octets());
    // Not the model's address, and not the session's prefix: dropped.
    let other: std::net::Ipv6Addr = "2001:db8:1:2::9".parse().unwrap();
    assert!(ping(&gtp, &upf, teid, icmpv6(&global, &other, 64, &[128, 0, 0, 0, 0, 1, 0, 1])).await.is_none());
    let foreign: std::net::Ipv6Addr = "2001:db8:9::2".parse().unwrap();
    assert!(ping(&gtp, &upf, teid, icmpv6(&foreign, &dst, 64, &[128, 0, 0, 0, 0, 1, 0, 2])).await.is_none());

    // tshark reads each G-PDU's inner packet and verifies the checksums NetGet wrote.
    let rows = oracle
        .fields(&["icmpv6.type", "icmpv6.checksum.status", "icmpv6.opt.prefix"])
        .expect("tshark reads the user plane");
    let flat: Vec<String> = rows.iter().map(|r| r.join("|")).collect();
    assert!(
        flat.iter().any(|r| r.starts_with("134|1|2001:db8:1:2::")),
        "the Router Advertisement as tshark read it: {flat:?}"
    );
    assert!(
        flat.iter().any(|r| r.starts_with("129|1")),
        "the echo reply as tshark read it: {flat:?}"
    );
    assert_ngap_clean(&gnb.log);
}

/// An IPv6 packet carrying an ICMPv6 message whose checksum this function computes from the
/// RFC 8200 pseudo-header, written out here rather than taken from the code under test.
fn icmpv6(src: &std::net::Ipv6Addr, dst: &std::net::Ipv6Addr, hop: u8, msg: &[u8]) -> Vec<u8> {
    let mut icmp = msg.to_vec();
    icmp[2] = 0;
    icmp[3] = 0;
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&icmp);
    let mut sum: u32 = 0;
    for c in pseudo.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let c = !(sum as u16);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    p.push(58);
    p.push(hop);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&icmp);
    p
}

/// The operator's preference picks the algorithms: NIA1+NEA1 (SNOW 3G) and NIA3+NEA3 (ZUC)
/// protect the whole registration; a UE that offers none of the preferred integrity algorithms
/// is refused with #23.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operators_nas_algorithm_preference_is_selected() {
    for (ia, ea, want) in [
        ("nia1", "nea1", (security::NIA1, security::NEA1)),
        ("nia3,nia2", "nea3,nea2", (security::NIA3, security::NEA3)),
    ] {
        let (_state, _id, port, mut rx) = start(
            Some(script(ADMIT_ONLY)),
            UNREACHABLE_LLM,
            json!({"nas_integrity": ia, "nas_ciphering": ea}),
        )
        .await;
        let mut seen = Vec::new();
        let mut gnb = Gnb::connect(port).await;
        gnb.setup().await;
        assert_eq!(gnb.authenticate().await, want, "{ia} {ea}");
        // Every message after it is protected with that pair: the Registration Accept
        // deciphers and verifies with the UE's context.
        let accept = gnb.complete_registration().await;
        assert!(accept.guti.is_some());
        wait_line(&mut rx, &mut seen, "decision=ue_registered").await;
        assert_ngap_clean(&gnb.log);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_without_the_preferred_integrity_algorithm_is_refused() {
    let (_state, _id, port, mut rx) = start(
        Some(script(ADMIT_ONLY)),
        UNREACHABLE_LLM,
        json!({"nas_integrity": "nia3"}),
    )
    .await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    // 5G-EA0-2 and 5G-IA0-2 only: no ZUC.
    let mut req = super::security_e2e_test::registration_request();
    let at = req
        .windows(2)
        .position(|w| w == [0x2e, 0x02])
        .expect("the UE security capability IE");
    req[at + 2] = 0xe0;
    req[at + 3] = 0xe0;
    gnb.send(&codec::initial_ue_message(1, &req, &uli(), "mo-Signalling").unwrap())
        .await;
    let nas_pdu = gnb.dl_nas("Registration Reject").await;
    assert_eq!(nas_pdu, nas::registration_reject(23));
    wait_line(&mut rx, &mut seen, "decision=ue_security_capabilities_mismatch").await;
}

/// The fail-closed answers to the two new decisions. Silent: a release request is released (a
/// release keeps nothing open), a modification request is rejected #31. Failed (the model
/// cannot be reached): the same, tagged `fail_closed_llm_error`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unanswered_release_and_modification_requests_fail_closed() {
    // ADMIT_ONLY never answers release or modification requests; the rest of the flow needs a
    // session, so it is admitted by a second policy for the establishment only.
    const SILENT: &str = r#"import json, sys
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
          "pdu_session_id": e["pdu_session_id"], "ue_ipv4": "10.47.0.%d" % (e["pdu_session_id"] + 1)}]
print(json.dumps({"actions": a}))"#;
    for (handlers, tag) in [
        // Silent: the policy answers every event and says nothing about these two.
        (
            vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": SILENT}})],
            "decision=model_silent",
        ),
        // Failed: these two events have no handler, so they go to a model that is unreachable.
        (
            [
                "ngap_ng_setup_request",
                "ngap_registration_request",
                "ngap_pdu_session_establishment_request",
            ]
            .iter()
            .map(|e| json!({"event_pattern": e, "handler": {"type": "script", "language": "python", "code": SILENT}}))
            .collect(),
            "decision=fail_closed_llm_error",
        ),
    ] {
        let (_state, _id, port, mut rx) = start(
            Some(handlers),
            UNREACHABLE_LLM,
            json!({"user_plane_address": format!("127.0.0.1:{}", probe_udp_port())}),
        )
        .await;
        let mut seen = Vec::new();
        let mut gnb = Gnb::connect(port).await;
        gnb.setup().await;
        gnb.authenticate().await;
        gnb.complete_registration().await;
        wait_line(&mut rx, &mut seen, "decision=ue_registered").await;
        gnb.session(1, 1, 1, 0x1).await;
        gnb.session(2, 2, 1, 0x2).await;

        gnb.sm_uplink(1, &sm::modification_request(1, 3, 1, Some(5)))
            .await;
        let reject = gnb.dl_nas("Modification Reject").await;
        let plain = gnb.unprotect(&reject);
        let m = sm::parse_procedure(&nas::parse_dl_nas_transport(&plain).unwrap().payload).unwrap();
        assert_eq!(
            (m.message_type, m.pti, m.cause),
            (
                sm::PDU_SESSION_MODIFICATION_REJECT,
                3,
                Some(sm::CAUSE_REQUEST_REJECTED_UNSPECIFIED)
            ),
            "{tag}"
        );
        wait_line(&mut rx, &mut seen, tag).await;

        gnb.sm_uplink(2, &sm::release_request(2, 4, None)).await;
        let p = gnb.recv("Release Command").await;
        assert_eq!(p.procedure_code, codec::PROC_PDU_SESSION_RESOURCE_RELEASE, "{tag}");
        let rc = codec::parse_pdu_session_resource_release_command(&p).unwrap();
        let c = sm::parse_procedure(&gnb.sm_of(rc.nas.as_ref().unwrap())).unwrap();
        assert_eq!(
            (c.message_type, c.pti),
            (sm::PDU_SESSION_RELEASE_COMMAND, 4),
            "{tag}: released as the UE asked"
        );
        assert_ngap_clean(&gnb.log);
    }
}

/// A UE silent for longer than `ue_inactivity_timeout_secs` is released to CM-IDLE by Rust,
/// with radioNetwork/user-inactivity, and comes back with a Service Request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inactivity_timer_idles_a_silent_ue() {
    let (_state, _id, port, mut rx) = start(
        Some(script(ADMIT_ONLY)),
        UNREACHABLE_LLM,
        json!({"ue_inactivity_timeout_secs": 1}),
    )
    .await;
    let mut seen = Vec::new();
    let mut gnb = Gnb::connect(port).await;
    gnb.setup().await;
    gnb.authenticate().await;
    gnb.complete_registration().await;
    wait_line(&mut rx, &mut seen, "decision=ue_registered").await;
    // Nothing more from the UE: the timer fires.
    assert_eq!(
        gnb.complete_release().await,
        json!({"group": "radioNetwork", "value": "user-inactivity"})
    );
    wait_line(&mut rx, &mut seen, "decision=ue_inactivity_release").await;
    wait_line(&mut rx, &mut seen, "decision=ue_idle").await;
}
