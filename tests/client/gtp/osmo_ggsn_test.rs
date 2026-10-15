//! NetGet's GTP client as an SGSN on Gn (GTPv1) against **Osmocom osmo-ggsn**, a GGSN that
//! shares no code with NetGet or with go-gtp. Its user plane is a Linux tun device, so an ICMP
//! echo request NetGet tunnels to the tun's own address is answered by the **kernel**, and the
//! reply comes back to NetGet as a G-PDU that osmo-ggsn encapsulated. The kernel drops a
//! packet with a wrong checksum and osmo-ggsn drops one from an address it did not assign, so
//! a reply arriving at all says the inner packet, the TEIDs and the GSN addresses were right.
//!
//! Needs Linux, the `osmo-ggsn` package (Ubuntu/Debian: `apt-get install osmo-ggsn`) and
//! CAP_NET_ADMIN for its tun device (`sudo setcap cap_net_admin+ep "$(command -v osmo-ggsn)"`,
//! or run as root). Fails rather than skips without them. osmo-ggsn binds 127.0.0.2 on 2123
//! and 2152, and NetGet's GTP-U endpoint takes 127.0.0.1:2152, so nothing else in the run may.
//!
//! The chain: echo; on the echo response create a PDP context; the test then tunnels one
//! ICMP echo to the tun address; on the echo reply the model updates the PDP context, and on
//! acceptance deletes it.
use super::real_server_test::wait_event;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='gtp_client_ready':
  a=[{'type':'gtp_echo'}]
elif t=='gtp_response':
  r=e.get('request')
  if r=='echo_request':
    a=[{'type':'gtp_create_session','imsi':'001010000000042','apn':'internet','msisdn':'491701234567',
        'mei':'3534900698733190','pdn_type':'ipv4','ebi':5,'qos':{'arp_priority_level':2}}]
  elif r=='modify_bearer' and e.get('accepted'):
    a=[{'type':'gtp_delete_session','session':e['session']}]
elif t=='gtp_tunnel_packet':
  icmp=e['inner'].get('icmp') or {}
  if e['known_tunnel'] and icmp.get('type_name')=='echo_reply':
    a=[{'type':'gtp_modify_bearer','session':e['session']}]
print(json.dumps({'actions':a}))"#;

const GGSN: &str = "127.0.0.2";

fn config(state_dir: &str, tun: &str) -> String {
    format!(
        "log stderr
 logging filter all 1
 logging color 0
 logging print category 1
 logging level ggsn info
 logging level lgtp info
 logging level tun info
!
line vty
 bind {GGSN}
!
ctrl
 bind {GGSN}
!
ggsn ggsn0
 gtp state-dir {state_dir}
 gtp bind-ip {GGSN}
 apn internet
  gtpu-mode tun
  tun-device {tun}
  type-support v4
  ip prefix dynamic 10.233.0.0/24
  ip dns 0 10.233.0.53
  ip dns 1 10.233.0.54
  ip ifconfig 10.233.0.0/24
  no shutdown
 default-apn internet
 no shutdown ggsn
"
    )
}

/// The IPv4 address osmo-ggsn gave its tun device, read back from the kernel.
async fn tun_address(tun: &str, log: &std::path::Path) -> String {
    for _ in 0..200 {
        let out = tokio::process::Command::new("ip")
            .args(["-4", "-o", "addr", "show", "dev", tun])
            .output()
            .await
            .expect("iproute2's ip");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if let Some(addr) = text
            .split_whitespace()
            .skip_while(|w| *w != "inet")
            .nth(1)
            .and_then(|a| a.split('/').next())
        {
            return addr.to_string();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "osmo-ggsn never gave {tun} an IPv4 address; its log:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

#[tokio::test]
async fn netget_sgsn_against_osmo_ggsn_and_the_kernel_tun() {
    if !cfg!(target_os = "linux") {
        panic!(
            "osmo-ggsn's user plane is a Linux tun device: run this on Linux (the gtp-client job \
             of .github/workflows/protocol-pairs.yml does)"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let tun = format!("ngtp{}", std::process::id() % 100_000);
    let cfg = dir.path().join("osmo-ggsn.cfg");
    std::fs::write(&cfg, config(&dir.path().display().to_string(), &tun)).unwrap();
    let log_path = dir.path().join("osmo-ggsn.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let ggsn = tokio::process::Command::new("osmo-ggsn")
        .arg("-c")
        .arg(&cfg)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .kill_on_drop(true)
        .spawn();
    let mut ggsn = ggsn.unwrap_or_else(|e| {
        panic!(
            "cannot run osmo-ggsn ({e}). Install it (apt-get install osmo-ggsn) and give it \
             CAP_NET_ADMIN for its tun device: sudo setcap cap_net_admin+ep \"$(command -v osmo-ggsn)\""
        )
    });
    let tun_addr = tun_address(&tun, &log_path).await;
    if let Ok(Some(status)) = ggsn.try_wait() {
        panic!(
            "osmo-ggsn exited ({status}); its log:\n{}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
    }

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "gtp".into(),
        remote_addr: Some(format!("{GGSN}:2123")),
        instruction: Some("Run one PDP context through its life".into()),
        startup_params: Some(json!({"interface": "gn", "user_plane_port": 2152,
            "t3_response_ms": 500, "n3_requests": 10})),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap_or_else(|e| panic!("connect: {e:#}"));
    let ggsn_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    let echoed = tokio::time::timeout(
        Duration::from_secs(40),
        wait_event(&state, id, |e| {
            e["event_type"] == "gtp_response" && e["request"]["request"] == "echo_request"
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("osmo-ggsn never answered an echo; its log:\n{}", ggsn_log()));
    assert_eq!(echoed["version"], 1, "{echoed}");
    assert!(
        echoed["recovery"].is_u64(),
        "an Echo Response carries Recovery: {echoed}"
    );

    let created = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response" && e["request"]["request"] == "create_session"
    })
    .await;
    assert_eq!(
        created["message"], "Create PDP Context Response",
        "{created}"
    );
    assert_eq!(
        created["cause"],
        "request_accepted",
        "{created}\n{}",
        ggsn_log()
    );
    assert_eq!(created["accepted"], true, "{created}");
    let ue = created["ue_address"]
        .as_str()
        .expect("an End User Address")
        .to_string();
    assert!(ue.starts_with("10.233.0."), "{created}");
    assert_eq!(created["pdn_type"], "IPv4", "{created}");
    assert_eq!(created["peer_data_address"], GGSN, "{created}");
    assert!(
        created["peer_control_teid"].as_u64().unwrap_or(0) != 0,
        "{created}"
    );
    assert!(
        created["peer_data_teid"].as_u64().unwrap_or(0) != 0,
        "{created}"
    );
    assert_eq!(
        created["dns_servers"],
        json!(["10.233.0.53", "10.233.0.54"]),
        "{created}"
    );
    let session = created["session"].as_u64().unwrap();
    let local_u = created["local_data_teid"].as_u64().unwrap();

    // One ICMP echo through the tunnel to the tun's own address: the kernel answers it.
    let sent = state
        .send_to_client(
            id,
            json!({"type": "gtp_send_gpdu", "session": session, "destination": tun_addr,
                   "protocol": "icmp_echo", "identifier": 0x77, "sequence": 3, "payload": "ping from netget"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");
    let back = tokio::time::timeout(
        Duration::from_secs(30),
        wait_event(&state, id, |e| e["event_type"] == "gtp_tunnel_packet"),
    )
    .await
    .unwrap_or_else(|_| panic!("no G-PDU came back; osmo-ggsn's log:\n{}", ggsn_log()));
    assert_eq!(back["known_tunnel"], true, "{back}");
    assert_eq!(back["teid"], local_u, "{back}");
    let inner: &Value = &back["inner"];
    assert_eq!(inner["source"], tun_addr.as_str(), "{back}");
    assert_eq!(inner["destination"], ue.as_str(), "{back}");
    assert_eq!(inner["ipv4_header_checksum_ok"], true, "{back}");
    assert_eq!(inner["icmp"]["type_name"], "echo_reply", "{back}");
    assert_eq!(inner["icmp"]["identifier"], 0x77, "{back}");
    assert_eq!(inner["icmp"]["sequence"], 3, "{back}");
    assert_eq!(inner["icmp"]["checksum_ok"], true, "{back}");
    assert_eq!(inner["payload"], "ping from netget", "{back}");

    // The model's answer to the reply: Update PDP Context, then Delete PDP Context.
    let updated = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response" && e["request"]["request"] == "modify_bearer"
    })
    .await;
    assert_eq!(
        updated["message"], "Update PDP Context Response",
        "{updated}"
    );
    assert_eq!(updated["accepted"], true, "{updated}\n{}", ggsn_log());
    let deleted = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response" && e["request"]["request"] == "delete_session"
    })
    .await;
    assert_eq!(
        deleted["message"], "Delete PDP Context Response",
        "{deleted}"
    );
    assert_eq!(deleted["accepted"], true, "{deleted}\n{}", ggsn_log());

    // The context is gone on NetGet's side too.
    let after = state
        .send_to_client(
            id,
            json!({"type": "gtp_send_gpdu", "session": session, "destination": tun_addr}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        matches!(&after, ClientSendOutcome::Rejected { error } if error.contains("no session")),
        "{after:?}"
    );
}
