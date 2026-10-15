//! NetGet's ASP against **Restcomm jSS7 8.0.112** as the far end — an independent Java SS7 stack
//! acting as SGW with an HLR, MSC, USSD gateway and gsmSCF behind it (`Ss7Peer.java`, role
//! answer) — over a real SCTP association on Linux, with a live capture read back by tshark.
//!
//! The model (a python policy) opens a MAP dialogue, and every later dialogue is built from what
//! jSS7 answered: the mt-forwardSM goes to the IMSI and MSC the sendRoutingInfoForSM result
//! named, and its text quotes them. jSS7 prints what it decoded, so the model's use of the
//! answer is asserted on the far side of the wire.
//!
//! Fails rather than skips without the jSS7 driver (`install_peers.py`), Java, dumpcap or tshark.
use super::live::{
    assert_capture, field, free_port, jss7_command, pct_decode, LiveCapture, JSS7_HINT,
};
use crate::helpers::real_server::ToolProcess;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const POLICY: &str = r#"import json, sys
i = json.load(sys.stdin); t = i["event_type_id"]; e = i["event"]
a = []
def results(op):
    return [c for c in e.get("components", []) if c.get("component") == "return_result_last" and c.get("operation") == op]
if t == "m3ua_connected":
    a = [{"type": "send_map_request", "operation": "sendRoutingInfoForSM",
          "argument": {"msisdn": "31690000000", "service_centre_address": "31611111111"}},
         {"type": "send_map_request", "operation": "sendRoutingInfoForSM",
          "argument": {"msisdn": "31628838002", "service_centre_address": "31611111111"}}]
elif t == "m3ua_map_received" and results("sendRoutingInfoForSM"):
    r = results("sendRoutingInfoForSM")[0]["result"]
    a = [{"type": "send_map_request", "operation": "mt-forwardSM",
          "argument": {"sm_rp_da": {"imsi": r["imsi"]}, "sm_rp_oa": {"service_centre_address": "31611111111"},
                       "sms": {"originator": "31655500000", "text": "To " + r["imsi"] + " via " + r["network_node_number"]["digits"]}}}]
elif t == "m3ua_map_received" and results("mt-forwardSM"):
    a = [{"type": "send_map_request", "operation": "anyTimeInterrogation",
          "argument": {"subscriber": {"msisdn": "31628838002"}, "gsm_scf_address": "31699999999"}}]
elif t == "m3ua_map_received" and results("anyTimeInterrogation"):
    li = results("anyTimeInterrogation")[0]["result"]["location_information"]
    cgi = li["cell_global_id"]
    a = [{"type": "send_map_request", "operation": "processUnstructuredSS-Request",
          "argument": {"ussd_text": "*100*%d#" % cgi["lac"], "msisdn": "31628838002"}}]
elif t == "m3ua_map_received" and results("processUnstructuredSS-Request"):
    a = [{"type": "send_map_request", "operation": "mo-forwardSM",
          "argument": {"sm_rp_da": {"service_centre_address": "31611111111"}, "sm_rp_oa": {"msisdn": "31628838002"},
                       "sms": {"destination": "31622222222", "text": results("processUnstructuredSS-Request")[0]["result"]["ussd_text"]}}}]
elif t == "m3ua_map_received" and results("mo-forwardSM"):
    a = [{"type": "send_cap_operations", "operations": [{"operation": "initialDP", "service_key": 42,
          "called_party_number": "31644444441", "calling_party_number": "31655555555",
          "event_type_bcsm": "collectedInfo", "imsi": "001010123456789", "msc_address": "31600000003"}]}]
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
    .unwrap_or_else(|_| panic!("no matching {event} event within {secs}s"))
}

fn has_result(e: &Value, op: &str) -> bool {
    e["components"]
        .as_array()
        .map(|c| {
            c.iter()
                .any(|c| c["operation"] == op && c["component"] == "return_result_last")
        })
        .unwrap_or(false)
}

#[tokio::test]
async fn the_models_dialogues_are_answered_by_jss7_and_each_builds_on_the_last() {
    let jss7_port = free_port();
    let netget_port = free_port();
    let capture = LiveCapture::start(&[jss7_port]).await;
    let mut cmd = jss7_command();
    cmd.args([
        "role=answer",
        "transport=sctp",
        "association=server",
        "m3ua=sgw",
        &format!("local=127.0.0.1:{jss7_port}"),
        &format!("remote=127.0.0.1:{netget_port}"),
        "opc=2",
        "dpc=1",
        "rc=100",
        "max_dialogues=7",
        "timeout_secs=90",
    ]);
    let peer = ToolProcess::spawn(cmd, "java (jSS7 driver)", JSS7_HINT).unwrap();
    // The driver logs this once its SCTP server association is listening.
    peer.wait_for_line("jSS7 to listen", Duration::from_secs(30), |l| {
        l.contains("stack started")
    })
    .await
    .unwrap();

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    // jSS7 binds its server association before its M3UA stack is started, and an association
    // that arrives in between is accepted and closed again. NetGet's connect reports that as a
    // failure (correctly: the SGP closed it before ASPUP ACK), so the test redials, as an ASP
    // configured against a restarting SGP would, for up to fifteen seconds.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let id = loop {
        let (tx, _) = mpsc::unbounded_channel();
        let attempt = ClientForm {
            protocol: "m3ua".into(),
            remote_addr: Some(format!("127.0.0.1:{jss7_port}")),
            instruction: Some("Be an SMSC".into()),
            startup_params: Some(json!({"transport": "sctp", "local_port": netget_port, "opc": 1, "dpc": 2,
                "routing_context": 100, "local_ssn": 8, "remote_ssn": 6,
                "local_gt": "31600000100", "remote_gt": "31600000200"})),
            event_handlers: Some(vec![json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}})]),
            ..Default::default()
        }
        .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
        .await;
        match attempt {
            Ok(id) => break id,
            Err(e) if std::time::Instant::now() < deadline => {
                eprintln!("jSS7 not ready yet ({e:#}); redialling");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("{e:#}\n{}", peer.lines().join("\n")),
        }
    };

    // jSS7 answered the unknown subscriber with a MAP error, decoded for the model.
    let err = wait_event(&state, id, "m3ua_map_received", 60, |e| {
        e["components"][0]["component"] == "return_error"
    })
    .await;
    assert_eq!(err["components"][0]["error"], "unknownSubscriber", "{err}");
    assert_eq!(err["components"][0]["matched_own_invoke"], true, "{err}");
    let sri = wait_event(&state, id, "m3ua_map_received", 60, |e| {
        has_result(e, "sendRoutingInfoForSM")
    })
    .await;
    assert_eq!(
        sri["components"][0]["result"]["imsi"], "001010123456789",
        "{sri}"
    );
    assert_eq!(
        sri["components"][0]["result"]["network_node_number"]["digits"],
        "31600000001"
    );
    let ati = wait_event(&state, id, "m3ua_map_received", 60, |e| {
        has_result(e, "anyTimeInterrogation")
    })
    .await;
    let r = &ati["components"][0]["result"];
    assert_eq!(r["subscriber_state"], "assumedIdle", "{ati}");
    assert_eq!(
        r["location_information"]["vlr_number"]["digits"],
        "31600000002"
    );
    assert_eq!(
        r["location_information"]["cell_global_id"],
        json!({"mcc": "001", "mnc": "01", "lac": 4660, "cell_id": 22136})
    );
    let ussd = wait_event(&state, id, "m3ua_map_received", 60, |e| {
        has_result(e, "processUnstructuredSS-Request")
    })
    .await;
    assert_eq!(
        ussd["components"][0]["result"]["ussd_text"], "You sent *100*4660#",
        "{ussd}"
    );
    let cap = wait_event(&state, id, "m3ua_cap_received", 60, |e| e["tcap"] == "end").await;
    let connect = &cap["components"][0];
    assert_eq!(connect["operation"], "connect", "{cap}");
    assert_eq!(
        connect["argument"]["destination_routing_address"][0]["digits"],
        "31677777777"
    );

    // On jSS7's side: each request decoded, and the ones built from earlier answers carry them.
    peer.wait_for_line("all dialogues", Duration::from_secs(60), |l| {
        l.starts_with("DONE")
    })
    .await
    .unwrap();
    let lines = peer.lines();
    let recv = |op: &str| -> String {
        lines
            .iter()
            .find(|l| l.starts_with(&format!("RECV op={op} ")))
            .cloned()
            .unwrap_or_else(|| panic!("jSS7 never received {op}:\n{}", lines.join("\n")))
    };
    let mt = recv("mt-fsm");
    assert_eq!(field(&mt, "da"), Some("imsi:001010123456789"), "{mt}");
    assert_eq!(field(&mt, "from"), Some("31655500000"), "{mt}");
    assert_eq!(
        pct_decode(field(&mt, "text").unwrap()),
        "To 001010123456789 via 31600000001",
        "{mt}"
    );
    let ussd = recv("ussd");
    assert_eq!(
        pct_decode(field(&ussd, "text").unwrap()),
        "*100*4660#",
        "{ussd}"
    );
    let mo = recv("mo-fsm");
    assert_eq!(
        pct_decode(field(&mo, "text").unwrap()),
        "You sent *100*4660#",
        "{mo}"
    );
    assert_eq!(field(&mo, "to"), Some("31622222222"), "{mo}");
    let idp = recv("idp");
    assert_eq!(field(&idp, "service_key"), Some("42"), "{idp}");
    assert_eq!(field(&idp, "called"), Some("31644444441"), "{idp}");
    assert_eq!(field(&idp, "imsi"), Some("001010123456789"), "{idp}");
    assert!(lines
        .iter()
        .any(|l| l.starts_with("RECV op=ati") && field(l, "msisdn") == Some("31628838002")));
    drop(peer);

    let frames = capture.finish().await;
    assert_capture(
        &frames,
        netget_port,
        &[
            "ASPUP",
            "ASPAC",
            "invoke sendRoutingInfoForSM",
            "invoke mt-forwardSM",
            "invoke anyTimeInterrogation",
            "invoke processUnstructuredSS-Request",
            "invoke mo-forwardSM",
            "invoke initialDP",
        ],
    );
}
