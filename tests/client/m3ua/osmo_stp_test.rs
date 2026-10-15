//! NetGet's ASP through **osmo-stp** (libosmo-sigtran's STP, an independent C SIGTRAN
//! implementation, acting as the SGP) to jSS7 behind it: osmo-stp admits NetGet (ASPUP, ASPAC,
//! NTFY), routes its MAP dialogues by DPC to jSS7 at point code 2, and routes jSS7's answers back.
//! The model's second dialogue is built from the first answer, as in `real_server_test.rs`.
//!
//! Fails rather than skips without osmo-stp (Ubuntu: `osmo-stp`), the jSS7 driver, dumpcap or
//! tshark.
use super::live::{
    assert_capture, field, free_port, jss7_command, osmo_stp, pct_decode, LiveCapture, JSS7_HINT,
};
use crate::helpers::real_server::ToolProcess;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::AccessLogOwner;
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc;

const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]; a = []
if t == "m3ua_connected":
    a = [{"type": "send_map_request", "operation": "sendRoutingInfoForSM",
          "argument": {"msisdn": "31628838002", "service_centre_address": "31611111111"}}]
elif t == "m3ua_map_received":
    r = [c for c in e["components"] if c.get("component") == "return_result_last" and c.get("operation") == "sendRoutingInfoForSM"]
    if r:
        a = [{"type": "send_map_request", "operation": "mt-forwardSM",
              "argument": {"sm_rp_da": {"imsi": r[0]["result"]["imsi"]}, "sm_rp_oa": {"service_centre_address": "31611111111"},
                           "sms": {"originator": "31655500000", "text": "Routed by osmo-stp to " + r[0]["result"]["imsi"]}}}]
print(json.dumps({"actions": a}))"#;

#[tokio::test]
async fn netgets_asp_reaches_jss7_through_osmo_stp() {
    let stp_listen = free_port();
    let netget_local = free_port();
    let jss7_local = free_port();
    let capture = LiveCapture::start(&[stp_listen]).await;
    // osmo-stp is PC 0.0.3 and listens; NetGet is PC 1 (routing context 1), jSS7 PC 2 (RC 2).
    let stp = osmo_stp(&format!(
        "cs7 instance 0
 point-code 0.0.3
 asp asp-netget {netget_local} {stp_listen} m3ua
  local-ip 127.0.0.1
  remote-ip 127.0.0.1
 asp asp-jss7 {jss7_local} {stp_listen} m3ua
  local-ip 127.0.0.1
  remote-ip 127.0.0.1
 as as-netget m3ua
  asp asp-netget
  routing-key 1 0.0.1
 as as-jss7 m3ua
  asp asp-jss7
  routing-key 2 0.0.2
 route-table system
  update route 0.0.1 7.255.7 linkset as-netget
  update route 0.0.2 7.255.7 linkset as-jss7
 listen m3ua {stp_listen}
  local-ip 127.0.0.1
"
    ))
    .await;

    let mut cmd = jss7_command();
    cmd.args([
        "role=answer",
        "transport=sctp",
        "association=client",
        "m3ua=as",
        &format!("local=127.0.0.1:{jss7_local}"),
        &format!("remote=127.0.0.1:{stp_listen}"),
        "opc=2",
        "dpc=1",
        "rc=2",
        "max_dialogues=2",
        "timeout_secs=60",
    ]);
    let peer = ToolProcess::spawn(cmd, "java (jSS7 driver)", JSS7_HINT).unwrap();
    peer.wait_for_line(
        "jSS7 active behind osmo-stp",
        Duration::from_secs(30),
        |l| l == "READY",
    )
    .await
    .unwrap_or_else(|e| panic!("{e}\nosmo-stp:\n{}", stp.lines().join("\n")));

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "m3ua".into(),
        remote_addr: Some(format!("127.0.0.1:{stp_listen}")),
        instruction: Some("Be an SMSC".into()),
        startup_params: Some(json!({"transport": "sctp", "local_port": netget_local, "opc": 1, "dpc": 2,
            "routing_context": 1, "local_ssn": 8, "remote_ssn": 6,
            "local_gt": "31600000100", "remote_gt": "31600000200"})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap_or_else(|e| panic!("{e:#}\nosmo-stp:\n{}", stp.lines().join("\n")));

    // osmo-stp's NTFY while NetGet came up is reported to the model.
    let connected = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .find(|e| e["event_type"] == "m3ua_connected")
        .map(|e| e["request"].clone());
    if let Some(c) = connected {
        assert_eq!(c["routing_context"], 1, "{c}");
    }

    peer.wait_for_line("both dialogues", Duration::from_secs(60), |l| {
        l.starts_with("DONE")
    })
    .await
    .unwrap_or_else(|e| panic!("{e}\nosmo-stp:\n{}", stp.lines().join("\n")));
    let lines = peer.lines();
    let mt = lines
        .iter()
        .find(|l| l.starts_with("RECV op=mt-fsm"))
        .unwrap_or_else(|| panic!("{}", lines.join("\n")));
    assert_eq!(field(mt, "da"), Some("imsi:001010123456789"), "{mt}");
    assert_eq!(
        pct_decode(field(mt, "text").unwrap()),
        "Routed by osmo-stp to 001010123456789"
    );
    drop(peer);
    drop(stp);

    let frames = capture.finish().await;
    // NetGet's frames are the ones from its own local port on the association with osmo-stp.
    assert_capture(
        &frames,
        netget_local,
        &[
            "ASPUP",
            "ASPAC",
            "invoke sendRoutingInfoForSM",
            "invoke mt-forwardSM",
        ],
    );
}
