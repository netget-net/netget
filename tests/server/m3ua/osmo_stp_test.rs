//! NetGet's SGP behind **osmo-stp** (libosmo-sigtran's STP, an independent C SIGTRAN
//! implementation): osmo-stp connects to NetGet as an ASP over SCTP, comes up and goes active,
//! and routes jSS7's MAP traffic for point code 2 to it by DPC; NetGet's answers go back through
//! osmo-stp to jSS7 at point code 1.
//!
//! So two independent implementations hold NetGet's SGP to the M3UA side of the bargain — the
//! ASP state machine and NTFY from osmo-stp, which then forwards only what it accepted — and
//! jSS7 decodes the MAP answers at the far end. Fails rather than skips without osmo-stp
//! (Ubuntu: `osmo-stp`), the jSS7 driver, dumpcap or tshark.
use super::ss7_live::{
    assert_capture, field, free_port, jss7_command, osmo_stp, pct_decode, LiveCapture, JSS7_HINT,
};
use crate::helpers::real_server::run_tool;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc;

const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]; a = []
if t == "m3ua_asp_up_received": a = [{"type": "send_m3ua_asp_up_ack"}]
elif t == "m3ua_asp_active_received":
    rc = e.get("routing_context")
    a = [{"type": "send_m3ua_asp_active_ack", "routing_context": rc, "traffic_mode": "override"},
         {"type": "send_m3ua_notify", "status_type": "as_state_change", "status_info": "as_active", "routing_context": rc}]
elif t == "m3ua_map_received" and e["tcap"] == "begin":
    inv = e["components"][0]; d = e["dialogue_id"]
    if inv["operation"] == "sendRoutingInfoForSM":
        a = [{"type": "send_map_result", "dialogue_id": d, "result": {"imsi": "001019999999999", "network_node_number": "31600009999"}}]
    elif inv["operation"] == "processUnstructuredSS-Request":
        a = [{"type": "send_map_result", "dialogue_id": d, "result": {"ussd_text": "via osmo-stp: " + inv["argument"]["ussd_text"]}}]
print(json.dumps({"actions": a}))"#;

#[tokio::test]
async fn jss7_reaches_netgets_sgp_through_osmo_stp() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "m3ua".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an SGP".into()),
        startup_params: Some(json!({"transport": "sctp", "routing_context": 100})),
        event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}})]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let netget_port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let stp_listen = free_port();
    let stp_to_netget = free_port();
    let jss7_local = free_port();
    let capture = LiveCapture::start(&[netget_port, stp_listen]).await;
    // osmo-stp is PC 0.0.3. NetGet's SGP serves PC 2 (osmo-stp dials it as an ASP, routing
    // context 100); jSS7 is PC 1 and dials osmo-stp (routing context 7).
    let config = format!(
        "cs7 instance 0
 point-code 0.0.3
 asp asp-netget {netget_port} {stp_to_netget} m3ua
  local-ip 127.0.0.1
  remote-ip 127.0.0.1
  role asp
  sctp-role client
 asp asp-jss7 {jss7_local} {stp_listen} m3ua
  local-ip 127.0.0.1
  remote-ip 127.0.0.1
 as as-netget m3ua
  asp asp-netget
  routing-key 100 0.0.2
 as as-jss7 m3ua
  asp asp-jss7
  routing-key 7 0.0.1
 route-table system
  update route 0.0.2 7.255.7 linkset as-netget
  update route 0.0.1 7.255.7 linkset as-jss7
 listen m3ua {stp_listen}
  local-ip 127.0.0.1
"
    );
    let stp = osmo_stp(&config).await;

    // osmo-stp came up as an ASP of NetGet's SGP and went active.
    let ups = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let seen = state
                .list_access_logs_for(
                    Some(netget::state::AccessLogOwner::Server(id.as_u32())),
                    None,
                )
                .await
                .iter()
                .any(|e| {
                    serde_json::to_value(e).unwrap()["event_type"] == "m3ua_asp_active_received"
                });
            if seen {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        ups.is_ok(),
        "osmo-stp never activated on NetGet's SGP:\n{}",
        stp.lines().join("\n")
    );

    let mut cmd = jss7_command();
    cmd.args([
        "role=originate",
        "transport=sctp",
        "association=client",
        "m3ua=as",
        &format!("local=127.0.0.1:{jss7_local}"),
        &format!("remote=127.0.0.1:{stp_listen}"),
        "opc=1",
        "dpc=2",
        "rc=7",
        "scenarios=sri-sm,ussd",
        "ussd=*55#",
        "timeout_secs=20",
    ]);
    let out = run_tool(cmd, "java (jSS7 driver)", JSS7_HINT)
        .await
        .unwrap_or_else(|e| panic!("{e}\nosmo-stp:\n{}", stp.lines().join("\n")));
    let lines: Vec<&str> = out.lines().collect();
    let sri = lines
        .iter()
        .find(|l| l.starts_with("RESULT scenario=sri-sm"))
        .unwrap_or_else(|| panic!("{out}\nosmo-stp:\n{}", stp.lines().join("\n")));
    assert_eq!(field(sri, "imsi"), Some("001019999999999"), "{sri}");
    assert_eq!(field(sri, "nnn"), Some("31600009999"), "{sri}");
    let ussd = lines
        .iter()
        .find(|l| l.starts_with("RESULT scenario=ussd"))
        .unwrap_or_else(|| panic!("{out}"));
    assert_eq!(
        pct_decode(field(ussd, "text").unwrap()),
        "via osmo-stp: *55#"
    );
    drop(stp);

    let frames = capture.finish().await;
    assert_capture(
        &frames,
        netget_port,
        &[
            "ASPUP_ACK",
            "ASPAC_ACK",
            "returnResultLast sendRoutingInfoForSM",
            "returnResultLast processUnstructuredSS-Request",
        ],
    );
}
