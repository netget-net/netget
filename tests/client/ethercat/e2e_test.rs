//! NetGet's EtherCAT master against NetGet's own slave over EtherCAT-in-UDP, python policies on
//! both sides standing in for the model. Self-served: this proves the plumbing — scan, SII,
//! state walk, cyclic LRW, CoE in both directions, fail-closed — not interoperability, which
//! `real_server_test.rs` (KickCAT's simulator) is for. No LLM calls.
use super::support::*;
use netget::state::client_handles::ClientSendOutcome;
use serde_json::json;

const MASTER_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='ethercat_segment_scanned' and e['count']>0:
  a=[{'type':'ethercat_request_state','state':'safeop'}]
elif t=='ethercat_state_result' and e['requested']=='safeop' and e['ok']:
  a=[{'type':'ethercat_set_outputs','slave':0,'values':{'motor_on':True,'setpoint':300}},
     {'type':'ethercat_sdo_read','slave':0,'index':0x1018,'subindex':2,'data_type':'u32'},
     {'type':'ethercat_sdo_read','slave':0,'index':'0x2001','data_type':'string'},
     {'type':'ethercat_sdo_write','slave':0,'index':0x8000,'subindex':1,'data_type':'u16','value':1200},
     {'type':'ethercat_sdo_write','slave':0,'index':0x8000,'subindex':1,'data_type':'u16','value':4000},
     {'type':'ethercat_request_state','state':'op'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_master_walks_its_own_slave_to_op_and_talks_coe() {
    let mut params = slave_params();
    params["mailbox_size"] = json!(64);
    let seg = start_segment(script(SLAVE_POLICY), params).await;
    let (state, tx, log) = new_state();
    let m = start_master_in(
        state,
        tx,
        log,
        &seg.addr.to_string(),
        script(MASTER_POLICY),
        json!({"transport": "udp", "cycle_ms": 5}),
    )
    .await
    .unwrap();
    let scanned = m
        .wait_event("ethercat_segment_scanned", 30, |_| true)
        .await
        .unwrap_or_else(|| panic!("no scan\n{}", m.log_text()));
    assert_eq!(scanned["count"], json!(1));
    let s = &scanned["slaves"][0];
    assert_eq!(s["name"], json!("NetGet Test Slave"));
    assert_eq!(s["vendor_id"], json!(0xABC));
    assert_eq!(s["station_address"], json!(0x1001));
    assert_eq!(
        s["inputs"],
        json!([{"name": "count", "type": "u16"}, {"name": "ready", "type": "bool"}])
    );
    let op = m
        .wait_event("ethercat_state_result", 60, |e| e["requested"] == "op")
        .await
        .unwrap_or_else(|| panic!("no OP\n{}\n{}", m.log_text(), seg.log_text()));
    assert_eq!(op["ok"], json!(true), "{op}");
    let inputs = m
        .wait_event("ethercat_inputs_changed", 30, |e| {
            e["inputs"]["count"] == json!(301)
        })
        .await
        .unwrap_or_else(|| panic!("the slave's answer to the outputs\n{}", m.log_text()));
    assert_eq!(inputs["inputs"]["ready"], json!(true));
    let id = m
        .wait_event("ethercat_sdo_result", 30, |e| e["index"] == json!(0x1018))
        .await
        .unwrap();
    assert_eq!(id["value"], json!(0x12345));
    let text = m
        .wait_event("ethercat_sdo_result", 30, |e| e["index"] == json!(0x2001))
        .await
        .unwrap();
    assert_eq!(
        text["value"],
        json!("NetGet EtherCAT slave, serial text that needs SDO segments")
    );
    let refused = m
        .wait_event("ethercat_sdo_result", 30, |e| {
            e["value"] == json!(4000) || e["abort_code"].is_number()
        })
        .await
        .unwrap();
    assert_eq!(refused["abort_code"], json!(0x0609_0031u32), "{refused}");
    let out = seg
        .wait_event("ethercat_outputs_changed", |e| {
            e["outputs"]["setpoint"] == json!(300)
        })
        .await
        .expect("outputs reached the slave's model");
    assert_eq!(out["outputs"]["motor_on"], json!(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn op_is_refused_until_outputs_are_set_and_an_unreachable_model_moves_nothing() {
    let seg = start_segment(script(SLAVE_POLICY), slave_params()).await;
    let (state, tx, log) = new_state();
    // No handlers: the master's model is unreachable.
    let m = start_master_in(
        state,
        tx,
        log,
        &seg.addr.to_string(),
        None,
        json!({"transport": "udp"}),
    )
    .await
    .unwrap();
    assert!(
        wait_for(&m.log, "decision=fail_closed_llm_error", 60).await,
        "{}",
        m.log_text()
    );
    // Nothing was asked of the slave beyond the scan.
    assert!(seg.events("ethercat_state_change_request").await.is_empty());
    let r = m
        .send(json!({"type": "ethercat_request_state", "state": "safeop"}))
        .await;
    assert!(matches!(r, ClientSendOutcome::Executed { .. }), "{r:?}");
    let r = m
        .send(json!({"type": "ethercat_request_state", "state": "op"}))
        .await;
    match r {
        ClientSendOutcome::Rejected { error } => {
            assert!(error.contains("outputs were never set"), "{error}")
        }
        other => panic!("OP without outputs: {other:?}"),
    }
}
