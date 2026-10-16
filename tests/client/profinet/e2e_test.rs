//! NetGet's PROFINET IO controller against NetGet's own device over the lab transport, both
//! driven by python policies. This is the plumbing — discovery, DCP Set, Connect with a
//! parameter write, PrmEnd, ApplicationReady, cyclic data both ways, records, Release — and
//! the fail-closed paths; it is not independent evidence (that is `real_server_test.rs`, p-net
//! on Linux). No LLM calls.
use super::support::*;
use netget::state::AccessLogOwner;
use serde_json::{json, Value};

const DEVICE: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='profinet_connect_request':
  a=[{'type':'profinet_accept_connect'},{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'inputs':42}}]
elif t=='profinet_dcp_set_request':
  a=[{'type':'profinet_accept_dcp_set'}]
elif t=='profinet_read_record' and e['index']==0xAFF0:
  a=[{'type':'profinet_read_response','im0':{'order_id':'NG-PN-1','serial_number':'SN-0042','software_revision':'V2.1.0'}}]
elif t=='profinet_write_record':
  a=[{'type':'profinet_accept_write'}] if e['index']==123 else [{'type':'profinet_refuse_record','error':'access_denied'}]
elif t=='profinet_outputs_changed':
  for o in e['outputs']:
    if o['slot']==1 and o['iops']=='good':
      a=[{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'inputs':(o['values']['outputs']+1)%256}}]
print(json.dumps({'actions':a}))"#;

const CONTROLLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
layout=[{'slot':0,'subslot':1,'module_ident':'0x1','submodule_ident':'0x1'},
        {'slot':0,'subslot':32768,'module_ident':'0x1','submodule_ident':'0x8000'},
        {'slot':0,'subslot':32769,'module_ident':'0x1','submodule_ident':'0x8001'},
        {'slot':1,'subslot':1,'module_ident':'0x32','submodule_ident':'0x132',
         'inputs':[{'name':'inputs','type':'u8'}],'outputs':[{'name':'outputs','type':'u8'}]}]
a=[]
if t=='profinet_devices_discovered' and any(d.get('name_of_station')=='press-7' for d in e['devices']):
  a=[{'type':'profinet_connect','name_of_station':'press-7','submodules':layout,'cycle_ms':8,
      'parameters':[{'slot':1,'subslot':1,'index':123,'fields':[{'type':'u32','value':7}]}]}]
elif t=='profinet_ar_established':
  a=[{'type':'profinet_set_outputs','slot':1,'subslot':1,'values':{'outputs':5}},
     {'type':'profinet_read_record','index':'im0'}]
elif t=='profinet_inputs_changed':
  if any(x['slot']==1 and x['values'].get('inputs')==6 for x in e['inputs']):
    a=[{'type':'profinet_release'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn controller_discovers_connects_exchanges_data_and_releases() {
    let (state, tx, log) = new_state();
    let (dev, lab) = start_lab_device(
        &state,
        tx.clone(),
        &log,
        script(DEVICE),
        json!({"name_of_station": "press-7", "vendor_id": 42}),
    )
    .await;
    let rpc_port = state
        .get_server(dev)
        .await
        .unwrap()
        .local_addr
        .unwrap()
        .port();
    let ctl = start_controller(
        &state,
        tx,
        &lab.to_string(),
        script(CONTROLLER),
        json!({"transport": "udp", "rpc_port": rpc_port, "station_name": "plc-test"}),
    )
    .await
    .unwrap();
    let c = AccessLogOwner::Client(ctl.as_u32());
    let d = AccessLogOwner::Server(dev.as_u32());

    let found = wait_until(&state, c, "profinet_devices_discovered", 30, |_| true).await;
    assert_eq!(
        found[0]["devices"][0]["name_of_station"],
        "press-7",
        "{}",
        text(&log)
    );
    assert_eq!(found[0]["devices"][0]["vendor_id"], 42);

    let up = wait_until(&state, c, "profinet_ar_established", 30, |_| true).await;
    assert_eq!(up.len(), 1, "{}", text(&log));
    assert!(up[0]["module_diff"].as_array().unwrap().is_empty());
    let asked = events(&state, d, "profinet_connect_request").await;
    assert_eq!(asked[0]["controller"]["station_name"], "plc-test");
    assert_eq!(asked[0]["cycle_ms"], 8.0);
    // The parameter was written before PrmEnd, and the device saw it as a typed record.
    let written = events(&state, d, "profinet_write_record").await;
    assert_eq!(written[0]["index"], 123);
    assert_eq!(written[0]["decoded"]["u32"], 7);

    // Inputs flow: 42 from the connect answer, then 6 once the device sees output 5.
    let ins = wait_until(&state, c, "profinet_inputs_changed", 30, |e| {
        e["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["values"]["inputs"] == 6)
    })
    .await;
    assert!(
        ins.iter().any(|e| e["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["values"]["inputs"] == 42 && x["iops"] == "good")),
        "{ins:?}"
    );
    assert!(
        ins.iter().any(|e| e["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["values"]["inputs"] == 6)),
        "{ins:?}\n{}",
        text(&log)
    );
    let outs = wait_until(&state, d, "profinet_outputs_changed", 10, |e| {
        e["outputs"][0]["values"]["outputs"] == 5
    })
    .await;
    assert!(outs
        .iter()
        .any(|e| e["outputs"][0]["iops"] == "good" && e["outputs"][0]["values"]["outputs"] == 5));

    let read = wait_until(&state, c, "profinet_record_read", 30, |_| true).await;
    assert_eq!(read[0]["ok"], true, "{read:?}");
    assert_eq!(read[0]["im0"]["order_id"], "NG-PN-1");
    assert_eq!(read[0]["im0"]["vendor_id"], 42);
    assert_eq!(read[0]["im0"]["software_revision"], "V2.1.0");

    let closed = wait_until(&state, c, "profinet_ar_closed", 30, |_| true).await;
    assert_eq!(closed[0]["reason"], "released", "{}", text(&log));
    let dev_closed = wait_until(&state, d, "profinet_ar_closed", 30, |_| true).await;
    assert_eq!(dev_closed[0]["reason"], "released by the controller");

    // DCP Set from an operator: the device's model accepts, and a fresh Identify sees it.
    let out = state.send_to_client(ctl, json!({"type": "profinet_dcp_set", "name_of_station": "press-7", "new_name_of_station": "line-9"}), std::time::Duration::from_secs(10)).await.unwrap();
    assert!(
        matches!(
            out,
            netget::state::client_handles::ClientSendOutcome::Executed { .. }
        ),
        "{out:?}"
    );
    let set = wait_until(&state, c, "profinet_dcp_set_result", 30, |_| true).await;
    assert_eq!(
        set[0]["results"][0],
        json!({"option": "name_of_station", "ok": true, "error": "ok"})
    );
    state
        .send_to_client(
            ctl,
            json!({"type": "profinet_identify"}),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
    let again = wait_until(&state, c, "profinet_devices_discovered", 30, |e| {
        e["devices"][0]["name_of_station"] == "line-9"
    })
    .await;
    assert_eq!(
        again.last().unwrap()["devices"][0]["name_of_station"],
        "line-9"
    );
}

#[tokio::test]
async fn an_unreachable_model_sends_nothing_and_outputs_stay_bad() {
    let (state, tx, log) = new_state();
    let (dev, lab) = start_lab_device(
        &state,
        tx.clone(),
        &log,
        script(DEVICE),
        json!({"name_of_station": "press-7"}),
    )
    .await;
    let rpc_port = state
        .get_server(dev)
        .await
        .unwrap()
        .local_addr
        .unwrap()
        .port();
    // No handler: the controller's model is 127.0.0.1:1, which is not there.
    let ctl = start_controller(
        &state,
        tx,
        &lab.to_string(),
        None,
        json!({"transport": "udp", "rpc_port": rpc_port, "station_name": "plc-test"}),
    )
    .await
    .unwrap();
    let c = AccessLogOwner::Client(ctl.as_u32());
    let d = AccessLogOwner::Server(dev.as_u32());
    assert!(
        wait_for(&log, "decision=fail_closed_llm_error", 60).await,
        "{}",
        text(&log)
    );
    assert!(
        events(&state, d, "profinet_connect_request")
            .await
            .is_empty(),
        "the controller connected on its own"
    );

    // An operator connects by hand; the model never sets outputs, so the device sees them BAD.
    let layout: Value = json!([{"slot": 1, "subslot": 1, "module_ident": "0x32", "submodule_ident": "0x132",
        "inputs": [{"name": "inputs", "type": "u8"}], "outputs": [{"name": "outputs", "type": "u8"}]}]);
    let out = state
        .send_to_client(
            ctl,
            json!({"type": "profinet_connect", "name_of_station": "press-7", "submodules": layout}),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            out,
            netget::state::client_handles::ClientSendOutcome::Executed { .. }
        ),
        "{out:?}"
    );
    assert!(
        wait_for(&log, "PROFINET AR with press-7 is running", 30).await,
        "{}",
        text(&log)
    );
    let outs = wait_until(&state, d, "profinet_outputs_changed", 30, |_| true).await;
    assert!(!outs.is_empty(), "{}", text(&log));
    for e in &outs {
        for o in e["outputs"].as_array().unwrap() {
            assert_eq!(
                o["iops"], "bad",
                "the controller claimed good outputs nobody set: {e}"
            );
        }
    }
    // The device's input still arrives at the controller, which asks the absent model and
    // sends nothing in return.
    assert!(
        wait_for(
            &log,
            "profinet_inputs_changed not answered; nothing sent",
            30
        )
        .await,
        "{}",
        text(&log)
    );
    let _ = c;
}
