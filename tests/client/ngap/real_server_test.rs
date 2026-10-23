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

// ----------------------------------------------------------------------------------------------
// A whole Open5GS core: registration with 5G-AKA and NAS security, and a PDU session
// ----------------------------------------------------------------------------------------------

const MONGO_HINT: InstallHint = InstallHint {
    brew: "mongodb-community (and Open5GS, which needs Linux for SCTP)",
    apt: "mongodb-org-server and mongodb-mongosh (repo.mongodb.org), plus open5gs-{nrf,ausf,udm,udr,pcf,nssf,bsf,smf,upf,amf} from ppa:open5gs/latest",
};

/// The core's addresses: one loopback /24 of its own, each network function on its usual
/// port. There is one full-core test, so nothing else binds these.
const CORE: &str = "127.0.20";

fn nf_config(dir: &std::path::Path, nf: &str) -> String {
    let log = format!(
        "logger:\n  file:\n    path: {}/{nf}.log\n  level: info\nglobal:\n  max:\n    ue: 64\n",
        dir.display()
    );
    let sbi = |ip: u8| {
        format!(
            "  sbi:\n    server:\n      - address: {CORE}.{ip}\n        port: 7777\n    client:\n      nrf:\n        - uri: http://{CORE}.10:7777\n"
        )
    };
    let db = format!("db_uri: mongodb://{CORE}.30/open5gs\n");
    match nf {
        "nrf" => format!("{log}nrf:\n  serving:\n    - plmn_id:\n        mcc: 001\n        mnc: 01\n  sbi:\n    server:\n      - address: {CORE}.10\n        port: 7777\n"),
        "ausf" => format!("{log}ausf:\n{}", sbi(11)),
        "udm" => format!("{log}udm:\n{}", sbi(12)),
        "udr" => format!("{db}{log}udr:\n{}", sbi(20)),
        "pcf" => format!("{db}{log}pcf:\n{}", sbi(13)),
        "nssf" => format!(
            "{log}nssf:\n{}      nsi:\n        - uri: http://{CORE}.10:7777\n          s_nssai:\n            sst: 1\n",
            sbi(14)
        ),
        "bsf" => format!("{log}bsf:\n{}", sbi(15)),
        "smf" => format!(
            "{log}smf:\n{}  pfcp:\n    server:\n      - address: {CORE}.4\n    client:\n      upf:\n        - address: {CORE}.7\n  gtpu:\n    server:\n      - address: {CORE}.4\n  session:\n    - subnet: 10.45.0.0/16\n      gateway: 10.45.0.1\n  dns:\n    - 8.8.8.8\n  mtu: 1400\n",
            sbi(4)
        ),
        "upf" => format!(
            "{log}upf:\n  pfcp:\n    server:\n      - address: {CORE}.7\n  gtpu:\n    server:\n      - address: {CORE}.7\n  session:\n    - subnet: 10.45.0.0/16\n      gateway: 10.45.0.1\n      dev: ngtun0\n"
        ),
        "amf" => format!(
            "{log}amf:\n{}  ngap:\n    server:\n      - address: {CORE}.5\n  guami:\n    - plmn_id:\n        mcc: 001\n        mnc: 01\n      amf_id:\n        region: 2\n        set: 1\n  tai:\n    - plmn_id:\n        mcc: 001\n        mnc: 01\n      tac: 1\n  plmn_support:\n    - plmn_id:\n        mcc: 001\n        mnc: 01\n      s_nssai:\n        - sst: 1\n  security:\n    integrity_order : [ NIA2, NIA1, NIA0 ]\n    ciphering_order : [ NEA0, NEA1, NEA2 ]\n  network_name:\n    full: NetGetTest\n  amf_name: open5gs-amf-netget\n  time:\n    t3512:\n      value: 540\n",
            sbi(5)
        ),
        other => panic!("no config for {other}"),
    }
}

/// The subscriber, as `open5gs-dbctl add` would write it (Open5GS's UDR schema).
const SUBSCRIBER: &str = r#"db.subscribers.insertOne({schema_version: NumberInt(1), imsi: "001010000000003", msisdn: [], imeisv: [], mme_host: [], mm_realm: [], purge_flag: [], slice: [{sst: NumberInt(1), default_indicator: true, session: [{name: "internet", type: NumberInt(3), qos: {index: NumberInt(9), arp: {priority_level: NumberInt(8), pre_emption_capability: NumberInt(1), pre_emption_vulnerability: NumberInt(1)}}, ambr: {downlink: {value: NumberInt(1), unit: NumberInt(3)}, uplink: {value: NumberInt(1), unit: NumberInt(3)}}, pcc_rule: []}]}], security: {k: "465B5CE8B199B49FAA5F0A2EE238A6BC", op: null, opc: "E8ED289DEBA952E4283B54E88E6183CA", amf: "8000", sqn: NumberLong("64")}, ambr: {downlink: {value: NumberInt(1), unit: NumberInt(3)}, uplink: {value: NumberInt(1), unit: NumberInt(3)}}, access_restriction_data: 32, network_access_mode: 0, subscriber_status: 0, operator_determined_barring: 0, subscribed_rau_tau_timer: 12, __v: 0})"#;

/// MongoDB and ten Open5GS network functions, each killed with the test.
struct Core5g {
    procs: Vec<(String, crate::helpers::real_server::ToolProcess)>,
    _dir: tempfile::TempDir,
}

impl Core5g {
    fn dump(&self) -> String {
        self.procs
            .iter()
            .map(|(n, p)| {
                let lines = p.lines();
                let tail = &lines[lines.len().saturating_sub(40)..];
                format!("--- {n} ---\n{}", tail.join("\n"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn lines_of(&self, nf: &str) -> Vec<String> {
        self.procs
            .iter()
            .find(|(n, _)| n == nf)
            .map(|(_, p)| p.lines())
            .unwrap_or_default()
    }

    async fn wait(&self, nf: &str, needle: &str, secs: u64) {
        let p = &self.procs.iter().find(|(n, _)| n == nf).unwrap().1;
        if let Err(e) = p
            .wait_for_line(needle, Duration::from_secs(secs), |l| l.contains(needle))
            .await
        {
            panic!("{nf} never logged {needle:?}: {e}\n{}", self.dump());
        }
    }

    async fn start() -> Core5g {
        use crate::helpers::real_server::{run_tool, ToolProcess};
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db");
        std::fs::create_dir_all(&db).unwrap();
        let mut procs = Vec::new();
        let mut mongod = Command::new("mongod");
        mongod.arg("--dbpath").arg(&db).args([
            "--bind_ip",
            &format!("{CORE}.30"),
            "--port",
            "27017",
        ]);
        procs.push((
            "mongod".to_string(),
            ToolProcess::spawn(mongod, "mongod", MONGO_HINT).unwrap(),
        ));
        let mut core = Core5g { procs, _dir: dir };
        core.wait("mongod", "Waiting for connections", 60).await;
        let mut sh = Command::new("mongosh");
        sh.args([
            "--quiet",
            &format!("mongodb://{CORE}.30/open5gs"),
            "--eval",
            SUBSCRIBER,
        ]);
        if let Err(e) = run_tool(sh, "mongosh", MONGO_HINT).await {
            panic!("provisioning the subscriber: {e}\n{}", core.dump());
        }
        for nf in [
            "nrf", "ausf", "udm", "udr", "pcf", "nssf", "bsf", "upf", "smf", "amf",
        ] {
            let path = core._dir.path().join(format!("{nf}.yaml"));
            std::fs::write(&path, nf_config(core._dir.path(), nf)).unwrap();
            // Each binary named as a literal, so the evidence scan reads which peers run.
            let mut cmd = match nf {
                "nrf" => Command::new("open5gs-nrfd"),
                "ausf" => Command::new("open5gs-ausfd"),
                "udm" => Command::new("open5gs-udmd"),
                "udr" => Command::new("open5gs-udrd"),
                "pcf" => Command::new("open5gs-pcfd"),
                "nssf" => Command::new("open5gs-nssfd"),
                "bsf" => Command::new("open5gs-bsfd"),
                "upf" => Command::new("open5gs-upfd"),
                "smf" => Command::new("open5gs-smfd"),
                _ => Command::new("open5gs-amfd"),
            };
            cmd.arg("-c").arg(&path);
            let p = ToolProcess::spawn(cmd, &format!("open5gs-{nf}d"), MONGO_HINT).unwrap();
            core.procs.push((nf.to_string(), p));
            let ready = match nf {
                "upf" => "UPF initialize...done",
                "amf" => "ngap_server()",
                _ => "initialize...done",
            };
            core.wait(nf, ready, 30).await;
        }
        // The SMF must hold its PFCP association with the UPF before a session can be made.
        core.wait("smf", "PFCP associated", 30).await;
        core
    }
}

/// The model as a gNB with the subscriber's credentials: bring the UE in, and once it is
/// registered ask for an internet session.
const CORE_POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
suci = {"type": "suci", "plmn": {"mcc": "001", "mnc": "01"}, "routing_indicator": "0000", "msin": "0000000003"}
a = []
if t == "ngap_connected":
    a = [{"type": "ngap_initial_ue_message", "nas": {"message": "registration_request",
          "registration_type": "initial", "mobile_identity": suci}}]
elif t == "ngap_ue_registered":
    a = [{"type": "ngap_pdu_session_request", "ran_ue_ngap_id": e["ran_ue_ngap_id"],
          "pdu_session_id": 1, "dnn": "internet", "s_nssai": {"sst": 1}}]
print(json.dumps({"actions": a}))"#;

/// NetGet's gNB against a whole Open5GS 2.8 core (NRF, AUSF, UDM, UDR on MongoDB, PCF, NSSF,
/// BSF, SMF, UPF, AMF). The subscriber is provisioned in Open5GS's own database; NetGet's UE
/// verifies the AUTN Open5GS's UDM built, Open5GS's AUSF accepts NetGet's RES*, the security
/// mode procedure completes, Open5GS registers the UE and hands the gNB a K_gNB equal to the one
/// NetGet's UE derived, and the SMF allocates the PDU session the model asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open5gs_registers_netgets_ue_and_creates_its_pdu_session() {
    let core = Core5g::start().await;
    let capture = LiveCapture::start(38412).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "ngap".into(),
        remote_addr: Some(format!("{CORE}.5:38412")),
        instruction: Some("Be a gNB".into()),
        startup_params: Some(json!({
            "transport": "sctp", "mcc": "001", "mnc": "01", "tac": 1, "sst": 1,
            "supi": "imsi-001010000000003",
            "subscriber_key": "465B5CE8B199B49FAA5F0A2EE238A6BC",
            "subscriber_opc": "E8ED289DEBA952E4283B54E88E6183CA",
        })),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": CORE_POLICY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap_or_else(|e| panic!("the gNB did not connect: {e}\n{}", core.dump()));

    let registered = tokio::time::timeout(
        Duration::from_secs(60),
        wait_event(&state, id, "ngap_ue_registered", 60, |_| true),
    )
    .await
    .unwrap_or_else(|_| panic!("never registered\n{}", core.dump()));
    assert_eq!(registered["supi"], "imsi-001010000000003", "{registered}");
    // Open5GS sends the Registration Accept in a Downlink NAS Transport and the K_gNB later,
    // in the Initial Context Setup that carries the first PDU session; nothing to compare yet.
    assert_ne!(registered["k_gnb_verified"], false, "{registered}");
    assert_eq!(registered["nas_security"]["integrity"], "NIA2");
    assert_eq!(registered["guti"]["amf_region_id"], 2);
    assert_eq!(
        registered["tai_list"],
        json!([{"plmn": {"mcc": "001", "mnc": "01"}, "tac": 1}]),
        "Open5GS's type-10 TAI list: {registered}"
    );
    core.wait("amf", "[imsi-001010000000003] Registration complete", 30)
        .await;

    let session = wait_event(&state, id, "ngap_pdu_session_established", 60, |_| true).await;
    assert_eq!(session["result"], "accepted", "{session}\n{}", core.dump());
    assert_eq!(
        session["k_gnb_verified"],
        true,
        "Open5GS's K_gNB (in the Initial Context Setup with the session) is the one NetGet's UE \
         derived: {session}\n{}",
        core.dump()
    );
    let ip = session["ue_ipv4"].as_str().unwrap_or_default().to_string();
    assert!(ip.starts_with("10.45."), "{session}");
    assert_eq!(session["upf_tunnel"]["address"], format!("{CORE}.7"));
    // The SMF's own record of the session it created for this UE, with the address it gave.
    core.wait(
        "smf",
        &format!("UE SUPI[imsi-001010000000003] DNN[internet] IPv4[{ip}]"),
        30,
    )
    .await;
    // The AMF saw the gNB set the session up.
    assert!(
        core.lines_of("amf")
            .iter()
            .any(|l| l.contains("UE SUPI[imsi-001010000000003] DNN[internet]")),
        "{}",
        core.dump()
    );

    let (frames, nas) = capture.finish_with_nas().await;
    let netget_port = frames
        .iter()
        .find(|f| f.src_port != 38412)
        .map(|f| f.src_port)
        .expect("NetGet sent nothing");
    assert_capture(
        &frames,
        netget_port,
        &[
            (codec::PROC_INITIAL_UE_MESSAGE, 0),
            (codec::PROC_UPLINK_NAS_TRANSPORT, 0),
            // Open5GS sets the first session up inside the Initial Context Setup, so NetGet's
            // answer carries it (PDUSessionResourceSetupListCxtRes).
            (codec::PROC_INITIAL_CONTEXT_SETUP, 1),
        ],
    );
    for code in [codec::PROC_INITIAL_CONTEXT_SETUP] {
        assert!(
            frames.iter().any(|f| f.src_port == 38412
                && f.procedures
                    .iter()
                    .zip(&f.pdu_kinds)
                    .any(|(c, k)| *c == code && *k == 0)),
            "Open5GS never sent procedure {code}: {frames:#?}"
        );
    }
    let mine = |mm: u8| {
        nas.iter()
            .any(|f| f.src_port == netget_port && f.mm_types.contains(&mm))
    };
    let theirs = |mm: u8| {
        nas.iter()
            .any(|f| f.src_port == 38412 && f.mm_types.contains(&mm))
    };
    for mm in [0x57, 0x5e, 0x43, 0x67] {
        assert!(mine(mm), "NetGet's 5GMM 0x{mm:02x} not dissected: {nas:#?}");
    }
    for mm in [0x56, 0x5d, 0x42] {
        assert!(
            theirs(mm),
            "Open5GS's 5GMM 0x{mm:02x} not dissected: {nas:#?}"
        );
    }
    assert!(nas
        .iter()
        .any(|f| f.src_port == netget_port && f.security_headers.contains(&4)));
    assert!(nas
        .iter()
        .any(|f| f.src_port == netget_port && f.sm_types.contains(&0xc1)));
    assert!(nas
        .iter()
        .any(|f| f.src_port == 38412 && f.sm_types.contains(&0xc2)));
    for f in &nas {
        assert!(
            f.experts.iter().all(|s| *s < 0x0060_0000),
            "tshark flags NAS frame {}: {nas:#?}",
            f.number
        );
    }
    drop(core);
}
