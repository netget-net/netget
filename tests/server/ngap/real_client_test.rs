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
