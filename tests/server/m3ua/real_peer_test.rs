//! NetGet's SGP against **Restcomm jSS7 8.0.112** — an independent Java SS7 stack (SCTP, M3UA,
//! SCCP, TCAP, MAP, CAP) driven by `jss7_peer/Ss7Peer.java` — over a real SCTP association on
//! Linux, with a live capture read back by tshark.
//!
//! jSS7 is an M3UA AS (it waits for NTFY AS-ACTIVE before it sends anything), opens one MAP or
//! CAP dialogue per scenario and prints what it decoded from NetGet's answers. A python policy is
//! the model, so the answers are known and asserted on jSS7's side of the wire.
//!
//! `install_peers.py` builds the driver and prints `NETGET_JSS7_PEER`; the tests **fail** without
//! it, without Java, and without dumpcap/tshark. Linux only: macOS has no SCTP.
use super::ss7_live::{
    assert_capture, field, free_port, jss7_command, pct_decode, LiveCapture, JSS7_HINT,
};
use crate::helpers::real_server::run_tool;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// The model as an SGP with an HLR, an SMSC, a USSD gateway and a gsmSCF behind it.
const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
if t == "m3ua_asp_up_received":
    a = [{"type": "send_m3ua_asp_up_ack"}]
elif t == "m3ua_asp_active_received":
    rc = e.get("routing_context")
    a = [{"type": "send_m3ua_asp_active_ack", "traffic_mode": "loadshare", "routing_context": rc},
         {"type": "send_m3ua_notify", "status_type": "as_state_change", "status_info": "as_active", "routing_context": rc}]
elif t == "m3ua_map_received" and e["tcap"] == "begin":
    inv = e["components"][0]; op = inv["operation"]; arg = inv["argument"]; d = e["dialogue_id"]
    if op == "sendRoutingInfoForSM" and arg["msisdn"]["digits"].endswith("0000"):
        a = [{"type": "send_map_error", "dialogue_id": d, "error": "absentSubscriberSM"}]
    elif op == "sendRoutingInfoForSM":
        a = [{"type": "send_map_result", "dialogue_id": d, "result": {"imsi": "262019876543210", "network_node_number": "491720000001", "lmsi": "01020304"}}]
    elif op == "anyTimeInterrogation":
        a = [{"type": "send_map_result", "dialogue_id": d, "result": {"subscriber_state": "camelBusy",
              "location_information": {"age_of_location_information": 7, "vlr_number": "491720000002",
                                       "cell_global_id": {"mcc": "262", "mnc": "01", "lac": 4097, "cell_id": 8193}}}}]
    elif op == "processUnstructuredSS-Request":
        a = [{"type": "send_map_result", "dialogue_id": d, "result": {"ussd_text": "Saldo: 12,50 EUR for " + arg["ussd_text"]}}]
    elif op in ("mo-forwardSM", "mt-forwardSM"):
        a = [{"type": "send_map_result", "dialogue_id": d, "result": {}}]
elif t == "m3ua_cap_received":
    inv = [c for c in e["components"] if c.get("component") == "invoke"]
    d = e["dialogue_id"]
    if inv and inv[0]["operation"] == "initialDP":
        a = [{"type": "send_cap_operations", "dialogue_id": d, "operations": [
              {"operation": "requestReportBCSMEvent", "bcsm_events": [
                  {"event_type_bcsm": "oAnswer", "monitor_mode": "notifyAndContinue", "leg": 2},
                  {"event_type_bcsm": "oDisconnect", "monitor_mode": "interrupted", "leg": 2}]},
              {"operation": "connect", "destination_routing_address": "491729999999"}]}]
    elif inv and inv[0]["argument"]["event_type_bcsm"] == "oDisconnect":
        a = [{"type": "send_cap_operations", "dialogue_id": d, "operations": [{"operation": "releaseCall", "cause": "normal_call_clearing"}]}]
print(json.dumps({"actions": a}))"#;

/// Start NetGet's SGP over SCTP on an OS-assigned port. `handlers` replace the default policy.
async fn start_sgp(handlers: Vec<Value>, instruction: &str) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "m3ua".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(instruction.into()),
        startup_params: Some(json!({"transport": "sctp", "routing_context": 100})),
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
                    break a.port();
                }
                assert!(
                    !matches!(s.status, netget::state::server::ServerStatus::Error(_)),
                    "the SGP did not start over SCTP: {:?}",
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

/// Run jSS7 as the originating AS against NetGet's SGP and return its output lines.
async fn originate(sgp_port: u16, scenarios: &str, extra: &[&str]) -> Vec<String> {
    let mut cmd = jss7_command();
    cmd.args([
        "role=originate",
        "transport=sctp",
        "association=client",
        "m3ua=as",
        &format!("local=127.0.0.1:{}", free_port()),
        &format!("remote=127.0.0.1:{sgp_port}"),
        "opc=1",
        "dpc=2",
        "rc=100",
        &format!("scenarios={scenarios}"),
        "timeout_secs=20",
    ]);
    cmd.args(extra);
    let out = run_tool(cmd, "java (jSS7 driver)", JSS7_HINT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    out.lines().map(str::to_string).collect()
}

fn line<'a>(lines: &'a [String], prefix: &str) -> &'a str {
    lines
        .iter()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("jSS7 printed no {prefix:?}:\n{}", lines.join("\n")))
}

#[tokio::test]
async fn jss7_map_and_camel_dialogues_are_answered_by_the_model_over_sctp() {
    let handlers = vec![
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}}),
    ];
    let (state, id, port) = start_sgp(handlers, "Be an SGP").await;
    let capture = LiveCapture::start(&[port]).await;

    let lines = originate(
        port,
        "sri-sm,ati,ussd,mo-fsm,mt-fsm,idp",
        &["ussd=*123#", "sms_text=Grüße aus jSS7"],
    )
    .await;
    // jSS7 decoded every one of the model's answers, field for field.
    let sri = line(&lines, "RESULT scenario=sri-sm");
    assert_eq!(field(sri, "imsi"), Some("262019876543210"), "{sri}");
    assert_eq!(field(sri, "nnn"), Some("491720000001"), "{sri}");
    assert_eq!(field(sri, "lmsi"), Some("01020304"), "{sri}");
    let ati = line(&lines, "RESULT scenario=ati");
    assert_eq!(field(ati, "state"), Some("camelBusy"), "{ati}");
    assert_eq!(field(ati, "vlr"), Some("491720000002"), "{ati}");
    assert_eq!(field(ati, "age"), Some("7"), "{ati}");
    assert_eq!(field(ati, "cgi"), Some("262-01-4097-8193"), "{ati}");
    let ussd = line(&lines, "RESULT scenario=ussd");
    assert_eq!(
        pct_decode(field(ussd, "text").unwrap()),
        "Saldo: 12,50 EUR for *123#",
        "{ussd}"
    );
    assert!(line(&lines, "RESULT scenario=mo-fsm").contains("ok=true"));
    assert!(line(&lines, "RESULT scenario=mt-fsm").contains("ok=true"));
    // CAMEL: the gsmSCF armed oAnswer/oDisconnect and connected; jSS7's gsmSSF reported both
    // events on NetGet's transaction, and the oDisconnect was answered with releaseCall.
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("CAP scenario=idp op=connect")
                && field(l, "dest") == Some("491729999999")),
        "{lines:#?}"
    );
    assert!(
        lines.iter().any(
            |l| l.starts_with("CAP scenario=idp op=requestReportBCSMEvent")
                && field(l, "events") == Some("oAnswer:notifyAndContinue,oDisconnect:interrupted")
        ),
        "{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("CAP scenario=idp op=releaseCall")
                && field(l, "cause") == Some("16")),
        "{lines:#?}"
    );
    let idp = line(&lines, "RESULT scenario=idp");
    assert_eq!(field(idp, "ended"), Some("end"), "{idp}");
    assert!(lines.iter().any(|l| l == "DONE results=6"), "{lines:#?}");

    // What the model was shown: jSS7's requests, decoded.
    let maps = events(&state, id, "m3ua_map_received").await;
    let arg = |op: &str| -> Value {
        maps.iter()
            .flat_map(|e| e["components"].as_array().cloned().unwrap_or_default())
            .find(|c| c["operation"] == op)
            .map(|c| c["argument"].clone())
            .unwrap_or_else(|| panic!("no {op} reached the model: {maps:#?}"))
    };
    assert_eq!(
        arg("sendRoutingInfoForSM")["msisdn"]["digits"],
        "31628838002"
    );
    assert_eq!(arg("processUnstructuredSS-Request")["ussd_text"], "*123#");
    assert_eq!(
        arg("mo-forwardSM")["sms"]["user_data"]["text"],
        "Grüße aus jSS7"
    );
    assert_eq!(
        arg("mt-forwardSM")["sms"]["originator"]["digits"],
        "31633333333"
    );
    let caps = events(&state, id, "m3ua_cap_received").await;
    let reports: Vec<&Value> = caps
        .iter()
        .flat_map(|e| e["components"].as_array().into_iter().flatten())
        .filter(|c| c["operation"] == "eventReportBCSM")
        .collect();
    assert_eq!(reports.len(), 2, "{caps:#?}");
    let report = |event: &str| {
        reports
            .iter()
            .find(|r| r["argument"]["event_type_bcsm"] == event)
            .unwrap_or_else(|| panic!("no {event} report: {caps:#?}"))
    };
    assert_eq!(
        report("oAnswer")["argument"]["message_type"],
        "notification"
    );
    assert_eq!(report("oDisconnect")["argument"]["message_type"], "request");

    let frames = capture.finish().await;
    assert_capture(
        &frames,
        port,
        &[
            "ASPUP_ACK",
            "ASPAC_ACK",
            "NTFY",
            "returnResultLast sendRoutingInfoForSM",
            "returnResultLast anyTimeInterrogation",
            "returnResultLast processUnstructuredSS-Request",
            "invoke requestReportBCSMEvent",
            "invoke connect",
            "invoke releaseCall",
        ],
    );
}

#[tokio::test]
async fn jss7_sees_netgets_fail_closed_answers_never_a_fabricated_success() {
    // MAP events go to the (unreachable) model; only the M3UA admission is scripted.
    let admit = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]; a = []
if t == "m3ua_asp_up_received": a = [{"type": "send_m3ua_asp_up_ack"}]
elif t == "m3ua_asp_active_received":
    rc = e.get("routing_context")
    a = [{"type": "send_m3ua_asp_active_ack", "routing_context": rc},
         {"type": "send_m3ua_notify", "status_type": "as_state_change", "status_info": "as_active", "routing_context": rc}]
elif t == "m3ua_cap_received":
    a = [{"type": "wait_for_more"}]
print(json.dumps({"actions": a}))"#;
    // Patterns are exact event ids or "*"; there is no prefix glob.
    let handlers = ["m3ua_asp_up_received", "m3ua_asp_active_received", "m3ua_cap_received"]
        .iter()
        .map(|p| json!({"event_pattern": p, "handler": {"type": "script", "language": "python", "code": admit}}))
        .collect();
    let (_state, _id, port) = start_sgp(handlers, "Be an HLR").await;
    let capture = LiveCapture::start(&[port]).await;
    // sri-sm: the model is unreachable, so NetGet answers systemFailure (34), never a result.
    // idp: the policy is silent on an initialDP, so the dialogue is aborted.
    let lines = originate(port, "sri-sm,idp", &[]).await;
    let sri = lines
        .iter()
        .find(|l| l.contains("scenario=sri-sm"))
        .unwrap();
    assert!(sri.starts_with("ERROR"), "{lines:#?}");
    assert_eq!(field(sri, "code"), Some("34"), "{sri}");
    let idp = line(&lines, "RESULT scenario=idp");
    assert_eq!(field(idp, "ended"), Some("abort"), "{lines:#?}");
    assert_eq!(field(idp, "ops"), Some("none"), "{lines:#?}");
    let frames = capture.finish().await;
    assert_capture(&frames, port, &["returnError"]);
}
