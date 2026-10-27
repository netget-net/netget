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
    // Every UERANSIM process registers itself in /tmp/UERANSIM.proc-table/, created with a
    // check-then-mkdir: two started at once both see it missing and the loser aborts with
    // "File exists". Creating it first, before any of the parallel tests spawns one, closes that.
    let table = std::path::Path::new("/tmp/UERANSIM.proc-table");
    let _ = std::fs::create_dir_all(table);
    let _ = std::fs::set_permissions(table, std::os::unix::fs::PermissionsExt::from_mode(0o777));
    let mut c = Command::new(command);
    if let Ok(dir) = std::env::var("NETGET_UERANSIM_DIR") {
        let path = std::env::var("PATH").unwrap_or_default();
        c.env("PATH", format!("{dir}:{path}"));
    }
    c
}

/// Start NetGet's AMF over SCTP on an OS-assigned port; returns where it actually listens.
async fn start_amf(handlers: Vec<Value>) -> (AppState, ServerId, std::net::SocketAddr) {
    start_amf_with(handlers, json!({"transport": "sctp"})).await
}

async fn start_amf_with(
    handlers: Vec<Value>,
    startup_params: Value,
) -> (AppState, ServerId, std::net::SocketAddr) {
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
        startup_params: Some(startup_params),
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
    ue_config_with(dir, gnb_ip, "imsi-001010000000001", 0, "[]")
}

/// A UE config: its SUPI, SUCI protection scheme (0 null, 1 Profile A with the TS 33.501 C.4.3
/// home network key) and PDU sessions.
fn ue_config_with(
    dir: &std::path::Path,
    gnb_ip: &str,
    supi: &str,
    scheme: u8,
    sessions: &str,
) -> std::path::PathBuf {
    let path = dir.join("ue.yaml");
    std::fs::write(
        &path,
        format!(
            "supi: '{supi}'\nmcc: '001'\nmnc: '01'\nprotectionScheme: {scheme}\n\
             homeNetworkPublicKey: '5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650'\n\
             homeNetworkPublicKeyId: 1\nroutingIndicator: '0000'\n\
             key: '465B5CE8B199B49FAA5F0A2EE238A6BC'\nop: 'E8ED289DEBA952E4283B54E88E6183CA'\n\
             opType: 'OPC'\namf: '8000'\nimei: '356938035643803'\nimeiSv: '4370816125816151'\n\
             tunNetmask: '255.255.255.0'\ngnbSearchList:\n  - {gnb_ip}\n\
             uacAic:\n  mps: false\n  mcs: false\n\
             uacAcc:\n  normalClass: 0\n  class11: false\n  class12: false\n  class13: false\n  class14: false\n  class15: false\n\
             sessions: {sessions}\nconfigured-nssai:\n  - sst: 1\ndefault-nssai:\n  - sst: 1\n\
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

/// The model of the secured test: admit the gNB, register the authenticated subscriber on slice
/// 1, give its session 10.60.0.2 and let 10.60.0.1 answer its ping.
const SECURE_POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
          "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
elif t == "ngap_registration_request" and e["supi"] == "imsi-001010000000002":
    a = [{"type": "send_registration_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"], "allowed_nssai": [{"sst": 1}]}]
elif t == "ngap_pdu_session_establishment_request" and e["dnn"] == "internet":
    a = [{"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"], "ue_ipv4": "10.60.0.2", "reachable_addresses": ["10.60.0.1"]}]
print(json.dumps({"actions": a}))"#;

/// Where a UERANSIM binary is: `NETGET_UERANSIM_DIR` when set, else on `PATH`.
fn ueransim_binary(name: &str) -> std::path::PathBuf {
    match std::env::var("NETGET_UERANSIM_DIR") {
        Ok(dir) => std::path::Path::new(&dir).join(name),
        Err(_) => crate::helpers::real_server::find_binary(name)
            .unwrap_or_else(|| std::path::PathBuf::from(name)),
    }
}

/// Kills a root `nr-ue` started through sudo, matched by its own temp-dir config path.
struct RootReaper(std::path::PathBuf);

impl Drop for RootReaper {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "pkill", "-KILL", "-f"])
            .arg(&self.0)
            .status();
    }
}

/// What decides whether nr-ue may build its tunnel, for a failure message: who runs the test,
/// whether sudo works, the capabilities on nr-ue and ip, /dev/net/tun, and how nr-ue's
/// directory is mounted.
fn privilege_report() -> String {
    let run = |cmd: &str, args: &[&str]| -> String {
        match Command::new(cmd).args(args).output() {
            Ok(o) => format!(
                "$ {cmd} {}\n{}{}",
                args.join(" "),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => format!("$ {cmd} {}: {e}\n", args.join(" ")),
        }
    };
    let ue = ueransim_binary("nr-ue");
    let ue = ue.to_string_lossy().to_string();
    let dir = std::path::Path::new(&ue)
        .parent()
        .map(|d| d.to_string_lossy().to_string())
        .unwrap_or_default();
    let ip = String::from_utf8_lossy(
        &Command::new("sh")
            .args(["-c", "readlink -f \"$(command -v ip)\""])
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string();
    [
        run("id", &[]),
        run("sudo", &["-n", "true"]),
        run("getcap", &[&ue, &ip]),
        run("ls", &["-l", "/dev/net/tun"]),
        run("findmnt", &["-no", "TARGET,OPTIONS", "-T", &dir]),
    ]
    .concat()
}

const PING_HINT: crate::helpers::real_server::InstallHint =
    crate::helpers::real_server::InstallHint {
        brew: "(none: the UE's tunnel is Linux-only)",
        apt: "iputils-ping",
    };

/// UERANSIM's UE registers for real: its SUCI is concealed with ECIES Profile A and deconcealed
/// by NetGet's AMF, it verifies the AUTN NetGet built from its key, accepts the Security Mode
/// Command's MAC and every protected message after it, gets a PDU session, brings up
/// `uesimtun*` with the model's address, and its ping crosses the GTP-U tunnel to NetGet's user
/// plane and back. Then it deregisters under security.
///
/// `nr-ue` refuses to create its TUN device unless its effective uid is 0: UERANSIM checks
/// `geteuid() == 0` itself before opening `/dev/net/tun` (`UeAppTask::setupTunInterface`), so no
/// capability can stand in for root. Root runs it directly; anyone else runs it through
/// `sudo -n`, which a GitHub runner allows. Without either the test fails, saying so, rather
/// than skipping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ueransim_registers_gets_a_pdu_session_and_pings_through_the_tunnel() {
    let handlers = vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": SECURE_POLICY}}),
    ];
    let (state, id, amf) = start_amf_with(
        handlers,
        json!({
            "transport": "sctp",
            "subscribers": [{"supi": "imsi-001010000000002",
                             "subscriber_key": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                             "subscriber_opc": "E8ED289DEBA952E4283B54E88E6183CA",
                             "amf_field": "8000"}],
            "suci_keys": [{"key_id": 1, "scheme": "profile_a",
                           "home_network_private_key": "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d"}],
            "user_plane_address": "127.0.0.62",
        }),
    )
    .await;
    let port = amf.port();
    let capture = LiveCapture::start(port).await;
    let dir = tempfile::tempdir().unwrap();

    let mut gnb_cmd = ueransim("nr-gnb");
    gnb_cmd
        .arg("-c")
        .arg(gnb_config(dir.path(), "127.0.0.61", amf));
    let gnb = ToolProcess::spawn(gnb_cmd, "nr-gnb", HINT).unwrap();
    gnb.wait_for_line("NG Setup success", Duration::from_secs(30), |l| {
        l.contains("NG Setup procedure is successful")
    })
    .await
    .unwrap();

    let ue_cfg = ue_config_with(
        dir.path(),
        "127.0.0.61",
        "imsi-001010000000002",
        1,
        "\n  - type: 'IPv4'\n    apn: 'internet'\n    slice:\n      sst: 1",
    );
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let ue_cmd = if root {
        let mut c = ueransim("nr-ue");
        c.arg("-c").arg(&ue_cfg);
        c
    } else {
        // sudo resets PATH, so it is handed nr-ue's absolute path.
        let mut c = ueransim("sudo");
        c.arg("-n")
            .arg(ueransim_binary("nr-ue"))
            .arg("-c")
            .arg(&ue_cfg);
        c
    };
    let ue = ToolProcess::spawn(ue_cmd, "nr-ue", HINT).unwrap();
    // Killing sudo does not kill the root nr-ue it started; this does, by its own config path.
    let _reaper = (!root).then(|| RootReaper(ue_cfg.clone()));
    fn fail(what: &str, ue: &ToolProcess, gnb: &ToolProcess) -> ! {
        panic!(
            "{what}\n--- privileges ---\n{}\n--- nr-ue ---\n{}\n--- nr-gnb ---\n{}",
            privilege_report(),
            ue.lines().join("\n"),
            gnb.lines().join("\n")
        )
    }
    if ue
        .wait_for_line("registration", Duration::from_secs(60), |l| {
            l.contains("Initial Registration is successful")
        })
        .await
        .is_err()
    {
        fail("UERANSIM's UE did not register", &ue, &gnb);
    }
    if ue
        .wait_for_line("PDU session", Duration::from_secs(60), |l| {
            l.contains("PDU Session establishment is successful")
        })
        .await
        .is_err()
    {
        fail("UERANSIM's UE got no PDU session", &ue, &gnb);
    }
    let tun_line = match ue
        .wait_for_line("TUN", Duration::from_secs(30), |l| {
            l.contains("TUN interface[") && l.contains("is up")
        })
        .await
    {
        Ok(l) => l,
        Err(_) => fail(
            "the UE's TUN interface never came up: nr-ue creates it only as root (it checks \
             geteuid() itself), so run the test as root or where `sudo -n` works",
            &ue,
            &gnb,
        ),
    };
    // "TUN interface[uesimtun0, 10.60.0.2] is up."
    let inside = tun_line
        .split("TUN interface[")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .unwrap_or_default()
        .to_string();
    let (iface, addr) = inside
        .split_once(", ")
        .unwrap_or_else(|| fail(&tun_line, &ue, &gnb));
    assert_eq!(
        addr, "10.60.0.2",
        "the UE has the model's address: {tun_line}"
    );

    // Ping through the tunnel: the UE's kernel -> nr-ue -> nr-gnb (GTP-U) -> NetGet's UPF, and
    // the reply the whole way back.
    let mut ping = Command::new("ping");
    ping.args(["-I", iface, "-c", "3", "-W", "3", "10.60.0.1"]);
    let out = match crate::helpers::real_server::run_tool(ping, "ping", PING_HINT).await {
        Ok(o) => o,
        Err(e) => fail(&format!("ping through {iface} failed: {e}"), &ue, &gnb),
    };
    assert!(out.contains("3 received"), "{out}");
    // An address the model did not choose does not answer.
    let mut ping = Command::new("ping");
    ping.args(["-I", iface, "-c", "1", "-W", "1", "10.60.0.9"]);
    assert!(
        crate::helpers::real_server::run_tool(ping, "ping", PING_HINT)
            .await
            .is_err(),
        "10.60.0.9 answered"
    );

    // Deregistration under security, asked of the UE through UERANSIM's own CLI.
    let mut cli = ueransim("nr-cli");
    cli.args(["imsi-001010000000002", "-e", "deregister normal"]);
    if let Err(e) = crate::helpers::real_server::run_tool(cli, "nr-cli", HINT).await {
        fail(&format!("nr-cli: {e}"), &ue, &gnb);
    }
    if ue
        .wait_for_line("deregistration", Duration::from_secs(30), |l| {
            l.contains("De-registration is successful")
        })
        .await
        .is_err()
    {
        fail("the UE did not deregister", &ue, &gnb);
    }

    // The model was asked three things — the gNB, the subscriber, the session — and nothing per
    // NAS message.
    assert_eq!(events(&state, id, "ngap_ng_setup_request").await.len(), 1);
    let reg = events(&state, id, "ngap_registration_request").await;
    assert_eq!(reg.len(), 1);
    assert_eq!(reg[0]["supi"], "imsi-001010000000002");
    assert_eq!(reg[0]["suci"]["protection_scheme"], "profile_a");
    let pdu = events(&state, id, "ngap_pdu_session_establishment_request").await;
    assert_eq!(pdu.len(), 1, "{pdu:?}");
    assert_eq!(pdu[0]["dnn"], "internet");
    assert!(events(&state, id, "ngap_initial_ue_message")
        .await
        .is_empty());
    assert!(events(&state, id, "ngap_uplink_nas_transport")
        .await
        .is_empty());

    drop(ue);
    drop(gnb);
    let (frames, nas) = capture.finish_with_nas().await;
    assert_capture(
        &frames,
        port,
        &[
            (codec::PROC_NG_SETUP, 1),
            (codec::PROC_DOWNLINK_NAS_TRANSPORT, 0),
            (codec::PROC_INITIAL_CONTEXT_SETUP, 0),
            (codec::PROC_PDU_SESSION_RESOURCE_SETUP, 0),
            (codec::PROC_UE_CONTEXT_RELEASE, 0),
        ],
    );
    for (code, kind) in [
        (codec::PROC_INITIAL_CONTEXT_SETUP, 1u8),
        (codec::PROC_PDU_SESSION_RESOURCE_SETUP, 1),
    ] {
        assert!(
            frames.iter().any(|f| f.src_port != port
                && f.procedures
                    .iter()
                    .zip(&f.pdu_kinds)
                    .any(|(c, k)| *c == code && *k == kind)),
            "UERANSIM never answered procedure {code}: {frames:#?}"
        );
    }
    // tshark's nas-5gs dissector, reading through NEA0: the AMF's Security Mode Command (header
    // type 3), Registration Accept and PDU Session Establishment Accept, the UE's Security Mode
    // Complete (header type 4), Registration Complete and Deregistration Request — every
    // message of the procedure, in both directions, with no Warn-or-worse expert info.
    let from = |netget: bool| {
        nas.iter()
            .filter(move |f| (f.src_port == port) == netget)
            .collect::<Vec<_>>()
    };
    let has = |frames: &[&super::support::NasFrame], mm: u8| {
        frames.iter().any(|f| f.mm_types.contains(&mm))
    };
    let amf_side = from(true);
    let ue_side = from(false);
    assert!(
        amf_side.iter().any(|f| f.security_headers.contains(&3)),
        "{nas:#?}"
    );
    for mm in [0x56, 0x5d, 0x42, 0x68, 0x46] {
        assert!(
            has(&amf_side, mm),
            "NetGet never sent 5GMM 0x{mm:02x}: {nas:#?}"
        );
    }
    assert!(
        amf_side.iter().any(|f| f.sm_types.contains(&0xc2)),
        "no PDU Session Establishment Accept dissected: {nas:#?}"
    );
    assert!(ue_side.iter().any(|f| f.security_headers.contains(&4)));
    for mm in [0x41, 0x57, 0x5e, 0x43, 0x67, 0x45] {
        assert!(
            has(&ue_side, mm),
            "UERANSIM never sent 5GMM 0x{mm:02x}: {nas:#?}"
        );
    }
    for f in &nas {
        assert!(
            f.experts.iter().all(|s| *s < 0x0060_0000),
            "tshark flags NAS frame {}: {nas:#?}",
            f.number
        );
    }
}

// ============================================================================
// The rest of the UE's life: release, CM-IDLE, Service Request, paging, SNOW 3G and ZUC
// ============================================================================

/// The model of the lifecycle tests: admit the gNB, register the subscriber, give each session
/// 10.<net>.0.<psi+1> with 10.<net>.0.1 answering, and release a session when the UE asks.
fn lifecycle_policy(supi: &str, net: u8) -> String {
    format!(
        r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "ngap_ng_setup_request":
    plmn = e["global_ran_node_id"]["plmn"]
    a = [{{"type": "send_ng_setup_response", "amf_name": "netget-amf",
          "served_guami": [{{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}}],
          "plmn_support": [{{"plmn": plmn, "slices": [{{"sst": 1}}]}}]}}]
elif t == "ngap_registration_request" and e["supi"] == "{supi}":
    a = [{{"type": "send_registration_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"], "allowed_nssai": [{{"sst": 1}}]}}]
elif t == "ngap_pdu_session_establishment_request" and e["dnn"] == "internet":
    a = [{{"type": "send_pdu_session_accept", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"], "ue_ipv4": "10.{net}.0.%d" % (e["pdu_session_id"] + 1),
          "reachable_addresses": ["10.{net}.0.1"]}}]
elif t == "ngap_pdu_session_release_request":
    a = [{{"type": "send_pdu_session_release", "amf_ue_ngap_id": e["amf_ue_ngap_id"],
          "pdu_session_id": e["pdu_session_id"]}}]
print(json.dumps({{"actions": a}}))"#
    )
}

/// One UERANSIM gNB and UE registered with a secured session through NetGet's AMF.
struct Rig {
    state: AppState,
    id: ServerId,
    port: u16,
    supi: String,
    capture: LiveCapture,
    gnb: ToolProcess,
    ue: ToolProcess,
    _reaper: Option<RootReaper>,
    _dir: tempfile::TempDir,
}

impl Rig {
    /// `addrs`: the gNB's and the user plane's loopback addresses, distinct per test.
    async fn start(supi: &str, net: u8, gnb_ip: &str, upf_ip: &str, extra: Value) -> Rig {
        let handlers = vec![json!({"event_pattern": "*", "handler": {"type": "script",
            "language": "python", "code": lifecycle_policy(&format!("imsi-{supi}"), net)}})];
        let mut params = json!({
            "transport": "sctp",
            "subscribers": [{"supi": format!("imsi-{supi}"),
                             "subscriber_key": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                             "subscriber_opc": "E8ED289DEBA952E4283B54E88E6183CA",
                             "amf_field": "8000"}],
            "user_plane_address": upf_ip,
        });
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        let (state, id, amf) = start_amf_with(handlers, params).await;
        let port = amf.port();
        let capture = LiveCapture::start(port).await;
        let dir = tempfile::tempdir().unwrap();
        let mut gnb_cmd = ueransim("nr-gnb");
        gnb_cmd.arg("-c").arg(gnb_config(dir.path(), gnb_ip, amf));
        let gnb = ToolProcess::spawn(gnb_cmd, "nr-gnb", HINT).unwrap();
        gnb.wait_for_line("NG Setup success", Duration::from_secs(30), |l| {
            l.contains("NG Setup procedure is successful")
        })
        .await
        .unwrap();
        let ue_cfg = ue_config_with(
            dir.path(),
            gnb_ip,
            &format!("imsi-{supi}"),
            0,
            "\n  - type: 'IPv4'\n    apn: 'internet'\n    slice:\n      sst: 1",
        );
        // nr-ue names its TUN by a prefix and the first free number, and two UEs starting at
        // once race for the same name (TUNSETIFF: Device or resource busy): each rig has its own
        // prefix. `-r` keeps nr-ue out of the host's policy routing, which every nr-ue edits
        // (`ip route add ... table rt_<tun>`) with no lock between processes; the TUN's own
        // /24 route is all a ping through it needs.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&ue_cfg)
                .unwrap();
            writeln!(f, "tunName: 'ngx{}t'", &supi[supi.len() - 3..]).unwrap();
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        let root = unsafe { libc::geteuid() } == 0;
        let ue_cmd = if root {
            let mut c = ueransim("nr-ue");
            c.arg("-r").arg("-c").arg(&ue_cfg);
            c
        } else {
            let mut c = ueransim("sudo");
            c.arg("-n")
                .arg(ueransim_binary("nr-ue"))
                .arg("-r")
                .arg("-c")
                .arg(&ue_cfg);
            c
        };
        let ue = ToolProcess::spawn(ue_cmd, "nr-ue", HINT).unwrap();
        let rig = Rig {
            state,
            id,
            port,
            supi: format!("imsi-{supi}"),
            capture,
            gnb,
            ue,
            _reaper: (!root).then(|| RootReaper(ue_cfg.clone())),
            _dir: dir,
        };
        rig.wait_ue("registration", 1, |l| {
            l.contains("Initial Registration is successful")
        })
        .await;
        rig
    }

    fn fail(&self, what: &str) -> ! {
        panic!(
            "{what}\n--- privileges ---\n{}\n--- nr-ue ---\n{}\n--- nr-gnb ---\n{}",
            privilege_report(),
            self.ue.lines().join("\n"),
            self.gnb.lines().join("\n")
        )
    }

    /// Wait until `n` of nr-ue's lines satisfy `pred`; the newest one.
    async fn wait_ue(&self, what: &str, n: usize, pred: impl Fn(&str) -> bool) -> String {
        self.wait_lines(&self.ue, what, n, pred).await
    }

    async fn wait_gnb(&self, what: &str, n: usize, pred: impl Fn(&str) -> bool) -> String {
        self.wait_lines(&self.gnb, what, n, pred).await
    }

    async fn wait_lines(
        &self,
        p: &ToolProcess,
        what: &str,
        n: usize,
        pred: impl Fn(&str) -> bool,
    ) -> String {
        let found = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let hits: Vec<String> = p.lines().into_iter().filter(|l| pred(l)).collect();
                if hits.len() >= n {
                    return hits[n - 1].clone();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        match found {
            Ok(l) => l,
            Err(_) => self.fail(&format!("nothing logged {what} (wanted {n})")),
        }
    }

    /// The interface of PDU session `psi` once its TUN is up (the `n`th time).
    async fn tun(&self, n: usize) -> (String, String) {
        let line = self
            .wait_ue("TUN up", n, |l| {
                l.contains("TUN interface[") && l.contains("is up")
            })
            .await;
        let inside = line
            .split("TUN interface[")
            .nth(1)
            .and_then(|s| s.split(']').next())
            .unwrap_or_default()
            .to_string();
        match inside.split_once(", ") {
            Some((i, a)) => (i.to_string(), a.to_string()),
            None => self.fail(&line),
        }
    }

    async fn cli(&self, command: &str) -> String {
        let mut cli = ueransim("nr-cli");
        cli.args([self.supi.as_str(), "-e", command]);
        match crate::helpers::real_server::run_tool(cli, "nr-cli", HINT).await {
            Ok(o) => o,
            Err(e) => self.fail(&format!("nr-cli {command}: {e}")),
        }
    }

    async fn inject(&self, action: Value) -> Value {
        let server = self.state.get_server(self.id).await.unwrap();
        let conn = server.connections.keys().next().unwrap().as_u32();
        let out = self
            .state
            .send_to_peer(self.id, conn, action.clone(), Duration::from_secs(10))
            .await
            .unwrap_or_else(|e| self.fail(&format!("injecting {action}: {e}")));
        serde_json::to_value(out).unwrap()
    }
}

/// `cmd args`, as root: directly when the test is root, else through `sudo -n` (passwordless on
/// a GitHub runner, as for nr-ue itself).
fn as_root(cmd: &str, args: &[&str]) -> Command {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        let mut c = Command::new(cmd);
        c.args(args);
        c
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(cmd).args(args);
        c
    }
}

async fn ping_count(iface: &str, dst: &str, count: u32) -> Result<String, String> {
    let mut ping = Command::new("ping");
    ping.args(["-I", iface, "-c", &count.to_string(), "-W", "2", dst]);
    crate::helpers::real_server::run_tool(ping, "ping", PING_HINT)
        .await
        .map_err(|e| e.to_string())
}

/// UERANSIM's UE releases its session (the model agrees) and its `uesimtun` goes away; it
/// establishes another, is released to CM-IDLE by the AMF, and is paged: UERANSIM's gNB takes
/// NetGet's Paging and the UE answers it with a Service Request that UERANSIM's own gNB then
/// cannot route (see below). The model is asked about the gNB, the subscriber, two sessions and
/// one release — nothing about the idle transition or the paging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ueransim_releases_a_session_goes_idle_and_answers_paging() {
    let rig = Rig::start("001010000000004", 61, "127.0.0.71", "127.0.0.72", json!({})).await;
    rig.wait_ue("PDU session", 1, |l| {
        l.contains("PDU Session establishment is successful")
    })
    .await;
    let (iface, addr) = rig.tun(1).await;
    assert_eq!(addr, "10.61.0.2");
    match ping_count(&iface, "10.61.0.1", 2).await {
        Ok(o) if o.contains("2 received") => {}
        other => rig.fail(&format!("ping before release: {other:?}")),
    }

    // UE-requested release, through UERANSIM's own CLI; the model answers it.
    rig.cli("ps-release 1").await;
    rig.wait_ue("release command", 1, |l| {
        l.contains("PDU Session Release Command received")
    })
    .await;
    rig.wait_gnb("resources released", 1, |l| {
        l.contains("PDU session resource(s) released")
    })
    .await;
    // The TUN interface goes when the session does.
    let gone = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let st = Command::new("ip").args(["link", "show", &iface]).output();
            if matches!(st, Ok(o) if !o.status.success()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if gone.is_err() {
        rig.fail(&format!("{iface} is still there after the release"));
    }
    let list = rig.cli("ps-list").await;
    assert!(!list.contains("PDU Session1"), "{list}");

    // A new session, then CM-IDLE: the AMF releases the UE's context.
    rig.cli("ps-establish IPv4 --sst 1 --dnn internet").await;
    rig.wait_ue("PDU session", 2, |l| {
        l.contains("PDU Session establishment is successful")
    })
    .await;
    let (iface, addr) = rig.tun(2).await;
    assert_eq!(addr, "10.61.0.2", "PSI 1 again");
    // A packet leaving the UE's TUN while it is idle makes nr-ue send its own Service Request
    // (`IDLE-UPLINK-DATA-PENDING`), and a UE with a procedure in flight ignores paging. On a
    // GitHub runner something on the host sends on every new interface (the CI run that found
    // this saw uplink data 11 ms after CM-IDLE). So this test makes that traffic itself, on
    // purpose and without stopping — a datagram from the UE's address every 2 ms — and takes the
    // interface down before idling the UE: a down interface carries nothing, whoever sends.
    // Without the `ip link set down` this test fails at the check below every time (measured in
    // the Linux container); with it, nothing reaches nr-ue once it is idle.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stray = {
        let stop = stop.clone();
        // A thread of its own, not a task: the runtime's workers are busy with the rig.
        std::thread::spawn(move || {
            let Ok(sock) = std::net::UdpSocket::bind("10.61.0.2:0") else {
                return;
            };
            let _ = sock.set_nonblocking(true);
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                // Refused once the interface is down; that is the point.
                let _ = sock.send_to(b"stray uplink", "10.61.0.9:9");
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    match as_root("ip", &["link", "set", "dev", &iface, "down"]).output() {
        Ok(o) if o.status.success() => {}
        other => rig.fail(&format!(
            "taking {iface} down (as root or through sudo -n): {other:?}"
        )),
    }
    let out = rig
        .inject(
            json!({"type": "send_ue_context_release_command", "supi": rig.supi,
                        "cause": "radioNetwork/user-inactivity"}),
        )
        .await;
    assert!(out.to_string().contains("sent"), "{out}");
    rig.wait_ue("CM-IDLE", 1, |l| {
        l.contains("UE switches to state [CM-IDLE]")
    })
    .await;
    // Idle with nothing in flight: no uplink data reached nr-ue after it went idle, and it has
    // started no Service Request of its own. Read after the UE's own CM-IDLE line, so anything
    // the stray sender got through would already show here.
    let lines = rig.ue.lines();
    let idle_at = lines
        .iter()
        .rposition(|l| l.contains("UE switches to state [CM-IDLE]"))
        .unwrap_or(0);
    if let Some(l) = lines[idle_at..]
        .iter()
        .find(|l| l.contains("pending[true]") || l.contains("Sending Service Request"))
    {
        rig.fail(&format!(
            "the idle UE started a procedure of its own before it was paged: {l}"
        ));
    }

    // Paged by the operator: UERANSIM's gNB accepts NetGet's Paging and pages over its radio,
    // and the UE recognises its own 5G-S-TMSI in it (it compares AMF Set ID, AMF Pointer and
    // 5G-TMSI with the 5G-GUTI NetGet assigned) and answers with a Service Request.
    let out = rig
        .inject(json!({"type": "send_paging", "supi": rig.supi}))
        .await;
    assert!(out.to_string().contains("sent"), "{out}");
    rig.wait_gnb("paging", 1, |l| l.contains("Paging received"))
        .await;
    rig.wait_ue("paging", 1, |l| l.contains("Responding to received Paging"))
        .await;
    rig.wait_ue("service request", 1, |l| {
        l.contains("Sending Service Request due to [IDLE-PAGING]")
    })
    .await;
    // That Service Request never reaches an AMF: UERANSIM v3.2.7's gNB picks the AMF for an
    // initial NAS message by the slice in a Registration Request's requested NSSAI
    // (`extractSliceInfoAndModifyPdu` then `selectAmf`), and a Service Request has none, so it
    // logs this and drops it — whichever core is behind it. NetGet's verification of a Service
    // Request is therefore shown by `lifecycle_test` (scripted UE) and by NetGet's gNB against
    // Open5GS's AMF (`tests/client/ngap/`), not here. This assertion pins the reason, so a
    // UERANSIM that fixes it fails here and the test can be extended.
    rig.wait_gnb("AMF selection", 1, |l| {
        l.contains("AMF selection for UE") && l.contains("failed")
    })
    .await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = stray.join();

    // The model was asked five things — the gNB, the subscriber, two sessions, one release.
    for (event, n) in [
        ("ngap_ng_setup_request", 1),
        ("ngap_registration_request", 1),
        ("ngap_pdu_session_establishment_request", 2),
        ("ngap_pdu_session_release_request", 1),
        ("ngap_initial_ue_message", 0),
        ("ngap_uplink_nas_transport", 0),
    ] {
        assert_eq!(events(&rig.state, rig.id, event).await.len(), n, "{event}");
    }

    let Rig {
        capture,
        ue,
        gnb,
        port,
        ..
    } = rig;
    drop(ue);
    drop(gnb);
    let (frames, nas) = capture.finish_with_nas().await;
    assert_capture(
        &frames,
        port,
        &[
            (codec::PROC_PDU_SESSION_RESOURCE_RELEASE, 0),
            (codec::PROC_UE_CONTEXT_RELEASE, 0),
            (codec::PROC_PAGING, 0),
        ],
    );
    for (code, kind) in [
        (codec::PROC_PDU_SESSION_RESOURCE_RELEASE, 1u8),
        (codec::PROC_UE_CONTEXT_RELEASE, 1),
    ] {
        assert!(
            frames.iter().any(|f| f.src_port != port
                && f.procedures
                    .iter()
                    .zip(&f.pdu_kinds)
                    .any(|(c, k)| *c == code && *k == kind)),
            "UERANSIM never answered procedure {code}: {frames:#?}"
        );
    }
    // nas-5gs through NEA0: the 5GSM release request, command and complete.
    let from = |netget: bool| {
        nas.iter()
            .filter(move |f| (f.src_port == port) == netget)
            .collect::<Vec<_>>()
    };
    let amf_side = from(true);
    let ue_side = from(false);
    assert!(
        ue_side.iter().any(|f| f.sm_types.contains(&0xd1)),
        "no Release Request: {nas:#?}"
    );
    assert!(
        amf_side.iter().any(|f| f.sm_types.contains(&0xd3)),
        "no Release Command: {nas:#?}"
    );
    assert!(
        ue_side.iter().any(|f| f.sm_types.contains(&0xd4)),
        "no Release Complete: {nas:#?}"
    );
    for f in &nas {
        assert!(
            f.experts.iter().all(|s| *s < 0x0060_0000),
            "tshark flags NAS frame {}: {nas:#?}",
            f.number
        );
    }
}

/// NetGet's AMF selects SNOW 3G (128-NIA1/128-NEA1) and then ZUC (128-NIA3/128-NEA3) by the
/// operator's preference, and UERANSIM's UE — which implements both independently — verifies
/// the Security Mode Command's MAC, deciphers the Registration Accept and the session accept,
/// and pings through the session: every downlink NAS message it acted on was protected with the
/// selected pair, and every uplink one it sent was checked with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ueransim_registers_under_snow3g_and_under_zuc() {
    for (supi, net, gnb_ip, upf_ip, ia, ea, want) in [
        (
            "001010000000005",
            62,
            "127.0.0.73",
            "127.0.0.74",
            "nia1",
            "nea1",
            "Selected integrity[1] ciphering[1]",
        ),
        (
            "001010000000006",
            63,
            "127.0.0.75",
            "127.0.0.76",
            "nia3,nia2",
            "nea3",
            "Selected integrity[3] ciphering[3]",
        ),
    ] {
        let rig = Rig::start(
            supi,
            net,
            gnb_ip,
            upf_ip,
            json!({"nas_integrity": ia, "nas_ciphering": ea}),
        )
        .await;
        let line = rig
            .wait_ue("selected algorithms", 1, |l| {
                l.contains("Selected integrity")
            })
            .await;
        assert!(line.contains(want), "{ia}/{ea}: {line}");
        rig.wait_ue("PDU session", 1, |l| {
            l.contains("PDU Session establishment is successful")
        })
        .await;
        let (iface, _) = rig.tun(1).await;
        match ping_count(&iface, &format!("10.{net}.0.1"), 2).await {
            Ok(o) if o.contains("2 received") => {}
            other => rig.fail(&format!("{ia}/{ea} ping: {other:?}")),
        }
        let reg = events(&rig.state, rig.id, "ngap_registration_request").await;
        assert_eq!(
            reg[0]["nas_security"],
            json!({"integrity": format!("NIA{}", &ia[3..4]), "ciphering": format!("NEA{}", &ea[3..4])})
        );
        let Rig {
            capture,
            ue,
            gnb,
            port,
            ..
        } = rig;
        drop(ue);
        drop(gnb);
        let frames = capture.finish().await;
        assert_capture(&frames, port, &[(codec::PROC_INITIAL_CONTEXT_SETUP, 0)]);
    }
}
