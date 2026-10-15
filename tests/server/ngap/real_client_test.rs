//! NetGet's AMF against **UERANSIM** v3.2.7 — `nr-gnb` and `nr-ue`, an independent C++ gNB and UE
//! whose NGAP is asn1c's APER — over a real SCTP association on Linux, with a live capture read
//! back by tshark's ngap dissector.
//!
//! `install_peers.py` builds UERANSIM and prints `NETGET_UERANSIM_DIR`; the tests **fail** without
//! it, and without dumpcap/tshark. Linux only: UERANSIM is Linux software and macOS has no SCTP.
//! No LLM calls: a python policy is the model.
use super::support::{assert_capture, LiveCapture};
use crate::helpers::real_server::ToolProcess;
use netget::cli::management::ServerForm;
use netget::server::ngap::codec;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;
use tokio::sync::mpsc;

const HINT: crate::helpers::real_server::InstallHint = crate::helpers::real_server::InstallHint {
    brew: "(none: UERANSIM is Linux-only)",
    apt:
        "cmake g++ libsctp-dev lksctp-tools, then python3 tests/server/ngap/install_peers.py <dir> \
          (builds UERANSIM v3.2.7 and prints NETGET_UERANSIM_DIR)",
};

/// The model: admit the gNB, challenge the UE with an AUTN it cannot verify (no subscriber key
/// exists here), and when it reports MAC failure, reject it as an illegal UE and release it.
const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
          "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
elif t == "ngap_initial_ue_message":
    a = [{"type": "send_downlink_nas_transport", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "ran_ue_ngap_id": e["ran_ue_ngap_id"],
          "nas": {"message": "authentication_request", "ngksi": 0,
                  "rand": "000102030405060708090a0b0c0d0e0f", "autn": "f0e0d0c0b0a090807060504030201000"}}]
elif t == "ngap_uplink_nas_transport" and e["nas"].get("message") == "authentication_failure":
    ids = {"amf_ue_ngap_id": e["amf_ue_ngap_id"], "ran_ue_ngap_id": e["ran_ue_ngap_id"]}
    a = [dict(type="send_downlink_nas_transport", nas={"message": "registration_reject", "cause": "illegal_ue"}, **ids),
         dict(type="send_ue_context_release_command", cause="nas/normal-release", **ids)]
print(json.dumps({"actions": a}))"#;

fn ueransim(command: &str) -> Command {
    let mut c = Command::new(command);
    if let Ok(dir) = std::env::var("NETGET_UERANSIM_DIR") {
        let path = std::env::var("PATH").unwrap_or_default();
        c.env("PATH", format!("{dir}:{path}"));
    }
    c
}

/// Start NetGet's AMF over SCTP on an OS-assigned port; returns where it actually listens.
async fn start_amf(handlers: Vec<Value>) -> (AppState, ServerId, std::net::SocketAddr) {
    let host = "127.0.0.1";
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "ngap".into(),
        port: Some(0),
        host: Some(host.into()),
        instruction: Some("Be an AMF".into()),
        startup_params: Some(json!({"transport": "sctp"})),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    break a;
                }
                assert!(
                    !matches!(s.status, netget::state::server::ServerStatus::Error(_)),
                    "the AMF did not start over SCTP: {:?}",
                    s.status
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port)
}

fn gnb_config(dir: &std::path::Path, ip: &str, amf: std::net::SocketAddr) -> std::path::PathBuf {
    let (amf_ip, amf_port) = (amf.ip(), amf.port());
    // ignoreStreamIds is left at its default (false): UERANSIM then rejects UE-associated
    // signalling on stream 0, so NetGet's stream selection is under test too.
    let path = dir.join("gnb.yaml");
    std::fs::write(
        &path,
        format!(
            "mcc: '001'\nmnc: '01'\nnci: '0x000000010'\nidLength: 32\ntac: 1\n\
             linkIp: {ip}\nngapIp: {ip}\ngtpIp: {ip}\n\
             amfConfigs:\n  - address: {amf_ip}\n    port: {amf_port}\n\
             slices:\n  - sst: 1\nignoreStreamIds: false\n"
        ),
    )
    .unwrap();
    path
}

fn ue_config(dir: &std::path::Path, gnb_ip: &str) -> std::path::PathBuf {
    let path = dir.join("ue.yaml");
    std::fs::write(
        &path,
        format!(
            "supi: 'imsi-001010000000001'\nmcc: '001'\nmnc: '01'\nprotectionScheme: 0\n\
             homeNetworkPublicKey: '5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650'\n\
             homeNetworkPublicKeyId: 1\nroutingIndicator: '0000'\n\
             key: '465B5CE8B199B49FAA5F0A2EE238A6BC'\nop: 'E8ED289DEBA952E4283B54E88E6183CA'\n\
             opType: 'OPC'\namf: '8000'\nimei: '356938035643803'\nimeiSv: '4370816125816151'\n\
             tunNetmask: '255.255.255.0'\ngnbSearchList:\n  - {gnb_ip}\n\
             uacAic:\n  mps: false\n  mcs: false\n\
             uacAcc:\n  normalClass: 0\n  class11: false\n  class12: false\n  class13: false\n  class14: false\n  class15: false\n\
             sessions: []\nconfigured-nssai:\n  - sst: 1\ndefault-nssai:\n  - sst: 1\n\
             integrity:\n  IA1: true\n  IA2: true\n  IA3: true\n\
             ciphering:\n  EA1: true\n  EA2: true\n  EA3: true\n\
             integrityMaxRate:\n  uplink: 'full'\n  downlink: 'full'\n"
        ),
    )
    .unwrap();
    path
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
async fn ueransim_sets_up_n2_and_its_ue_is_challenged_and_rejected() {
    let handlers = vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}}),
    ];
    let (state, id, amf) = start_amf(handlers).await;
    let port = amf.port();
    let capture = LiveCapture::start(port).await;
    let dir = tempfile::tempdir().unwrap();

    let mut gnb_cmd = ueransim("nr-gnb");
    gnb_cmd
        .arg("-c")
        .arg(gnb_config(dir.path(), "127.0.0.51", amf));
    let gnb = ToolProcess::spawn(gnb_cmd, "nr-gnb", HINT).unwrap();
    gnb.wait_for_line("NG Setup success", Duration::from_secs(30), |l| {
        l.contains("NG Setup procedure is successful")
    })
    .await
    .unwrap();

    let mut ue_cmd = ueransim("nr-ue");
    ue_cmd.arg("-c").arg(ue_config(dir.path(), "127.0.0.51"));
    let ue = ToolProcess::spawn(ue_cmd, "nr-ue", HINT).unwrap();
    // The UE could not verify the model's AUTN — it holds a key NetGet does not — and said so.
    ue.wait_for_line("authentication failure", Duration::from_secs(60), |l| {
        l.contains("Sending Authentication Failure") && l.contains("MAC_FAILURE")
    })
    .await
    .unwrap();
    // And then it received the model's Registration Reject with its cause.
    ue.wait_for_line("registration reject", Duration::from_secs(60), |l| {
        l.contains("Initial Registration failed") && l.contains("ILLEGAL_UE")
    })
    .await
    .unwrap();
    // The gNB released the UE when the AMF said so, which only happens on a non-zero stream.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if gnb
                .lines()
                .iter()
                .any(|l| l.contains("UE Context Release Command received"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the gNB never released the UE:\n{}", gnb.lines().join("\n")));
    assert!(
        !gnb.lines()
            .iter()
            .any(|l| l.contains("stream number") || l.contains("APER decoding failed")),
        "UERANSIM refused NetGet's NGAP:\n{}",
        gnb.lines().join("\n")
    );

    // What the model was shown: UERANSIM's gNB and UE, decoded.
    let setup = &events(&state, id, "ngap_ng_setup_request").await[0];
    // nci 0x000000010 with a 32-bit gNB ID: the top 32 of 36 bits, so gNB ID 1.
    assert_eq!(setup["global_ran_node_id"]["gnb_id"], 1, "{setup}");
    let initial = &events(&state, id, "ngap_initial_ue_message").await[0];
    assert_eq!(
        initial["nas"]["message"], "registration_request",
        "{initial}"
    );
    // UERANSIM writes key identifier 0 for the null scheme whatever its configuration says.
    assert_eq!(
        initial["nas"]["mobile_identity"],
        json!({"type": "suci", "supi_format": "imsi", "plmn": {"mcc": "001", "mnc": "01"},
               "routing_indicator": "0000", "protection_scheme": "null", "protection_scheme_id": 0,
               "home_network_public_key_id": 0, "msin": "0000000001"}),
        "{initial}"
    );
    assert_eq!(initial["user_location"]["cgi"]["cell_id"], 16, "{initial}");
    let uplink = &events(&state, id, "ngap_uplink_nas_transport").await[0];
    assert_eq!(uplink["nas"]["cause"]["name"], "mac_failure", "{uplink}");

    drop(ue);
    drop(gnb);
    let frames = capture.finish().await;
    assert_capture(
        &frames,
        port,
        &[
            (codec::PROC_NG_SETUP, 1),
            (codec::PROC_DOWNLINK_NAS_TRANSPORT, 0),
            (codec::PROC_UE_CONTEXT_RELEASE, 0),
        ],
    );
    // And UERANSIM's side of the conversation reached NetGet in the same capture.
    for (code, kind) in [
        (codec::PROC_NG_SETUP, 0u8),
        (codec::PROC_INITIAL_UE_MESSAGE, 0),
        (codec::PROC_UPLINK_NAS_TRANSPORT, 0),
        (codec::PROC_UE_CONTEXT_RELEASE, 1),
    ] {
        assert!(
            frames.iter().any(|f| f.src_port != port
                && f.procedures
                    .iter()
                    .zip(&f.pdu_kinds)
                    .any(|(c, k)| *c == code && *k == kind)),
            "UERANSIM never sent procedure {code} kind {kind}: {frames:#?}"
        );
    }
}

#[tokio::test]
async fn ueransim_reports_the_models_ng_setup_failure() {
    let handlers = vec![
        json!({"event_pattern": "ngap_ng_setup_request", "handler": {"type": "static", "actions": [{
        "type": "send_ng_setup_failure", "cause": "misc/unknown-PLMN-or-SNPN", "time_to_wait": "v60s"}]}}),
    ];
    let (_state, _id, amf) = start_amf(handlers).await;
    let port = amf.port();
    let capture = LiveCapture::start(port).await;
    let dir = tempfile::tempdir().unwrap();
    let mut gnb_cmd = ueransim("nr-gnb");
    gnb_cmd
        .arg("-c")
        .arg(gnb_config(dir.path(), "127.0.0.53", amf));
    let gnb = ToolProcess::spawn(gnb_cmd, "nr-gnb", HINT).unwrap();
    // asn1c names Rel-15's value unknown-PLMN; the encoding is the same index.
    let line = gnb
        .wait_for_line("NG Setup failure", Duration::from_secs(30), |l| {
            l.contains("NG Setup procedure is failed")
        })
        .await
        .unwrap();
    assert!(line.contains("misc/unknown-PLMN"), "{line}");
    drop(gnb);
    let frames = capture.finish().await;
    assert_capture(&frames, port, &[(codec::PROC_NG_SETUP, 2)]);
}
