//! NetGet's M-Bus master against NetGet's own gateway. This is a **regression** suite, not
//! evidence — the two were written together and agreeing proves only that — but it is the one
//! place the master's wildcard search, collision narrowing, multi-telegram readouts and
//! write paths run against a slave that has them all. The independent slaves are in
//! `real_server_test.rs`.
use super::support::{self, Master};
use serde_json::json;

/// The master's model: search every secondary address, read every meter found, and stop.
const SEARCH_AND_READ: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='mbus_connected': a=[{'type':'mbus_scan_secondary'}]
elif t=='mbus_scan_result': a=[{'type':'mbus_read','secondary_address':m['secondary_address']} for m in e['found']]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn a_wildcard_search_narrows_collisions_and_every_meter_found_is_read() {
    let g = support::gateway(support::meters()).await;
    let m = support::connect(&g.addr(), support::script(SEARCH_AND_READ), 200).await;
    let scans = m.wait_for_events("mbus_scan_result", 1, 120).await;
    assert_eq!(scans.len(), 1, "{}", m.log_text());
    let found: Vec<String> = scans[0]["found"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["secondary_address"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = found.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        ["00000777F4380102", "123456782D2C0104", "1234567993150207"],
        "{scans:?}"
    );
    assert!(scans[0]["collisions"].as_array().unwrap().is_empty());
    let data = m.wait_for_events("mbus_data", 3, 60).await;
    assert_eq!(data.len(), 3, "{}", m.log_text());
    let heat = data
        .iter()
        .find(|d| d["meter"]["id"] == "12345678")
        .expect("the heat meter was read");
    assert_eq!(heat["meter"]["manufacturer"], "KAM");
    assert_eq!(heat["meter"]["medium"], "heat");
    assert_eq!(heat["records"][0]["value"], json!(8000));
    assert_eq!(heat["records"][0]["unit"], "Wh");
    assert_eq!(heat["records"][1]["value"], json!(12.5));
    // The big meter's 120 records came in several telegrams, all of them.
    let big = data
        .iter()
        .find(|d| d["meter"]["id"] == "00000777")
        .unwrap();
    assert!(big["telegrams"].as_u64().unwrap() > 1);
    assert_eq!(big["records"].as_array().unwrap().len(), 120);
    assert_eq!(big["truncated"], json!(false));
    // Exactly one fresh readout per meter on the slave side: the search's reads plus the
    // model's, nothing repeated by a stale FCB.
    assert!(g.events("mbus_request_data").await.len() >= 3);
}

#[tokio::test]
async fn a_primary_scan_reports_meters_and_collisions() {
    let g = support::gateway(json!([
        {"primary_address": 1, "id": "11111111", "manufacturer": "KAM"},
        {"primary_address": 3, "id": "22222222", "manufacturer": "KAM"},
        {"primary_address": 3, "id": "33333333", "manufacturer": "KAM"}
    ]))
    .await;
    let m = support::connect(
        &g.addr(),
        support::script("import json\nprint(json.dumps({'actions':[]}))"),
        150,
    )
    .await;
    m.send(json!({"type": "mbus_scan_primary", "from": 0, "to": 5}))
        .await;
    let scans = m.wait_for_events("mbus_scan_result", 1, 60).await;
    assert_eq!(scans[0]["kind"], "primary");
    assert_eq!(scans[0]["found"], json!([1]));
    assert_eq!(scans[0]["collisions"], json!([3]));
    assert_eq!(scans[0]["probes"], json!(6));
    // Two meters under one mask, identical but for the id: the search narrows them apart.
    m.send(json!({"type": "mbus_scan_secondary", "mask": "FFFFFFFF2D2CFFFF"}))
        .await;
    let scans = m.wait_for_events("mbus_scan_result", 2, 120).await;
    assert_eq!(scans[1]["found"].as_array().unwrap().len(), 3, "{scans:?}");
    // Reading an address two meters share is reported as a collision, not as either reading.
    m.send(json!({"type": "mbus_read", "address": 3})).await;
    let errors = m.wait_for_events("mbus_error", 1, 30).await;
    assert_eq!(errors[0]["kind"], "collision", "{errors:?}");
}

#[tokio::test]
async fn a_readout_follows_more_records_and_stops_at_max_telegrams() {
    let g = support::gateway(support::meters()).await;
    let m = support::connect(
        &g.addr(),
        support::script("import json\nprint(json.dumps({'actions':[]}))"),
        500,
    )
    .await;
    m.send(json!({"type": "mbus_read", "address": 4, "max_telegrams": 2}))
        .await;
    let data = m.wait_for_events("mbus_data", 1, 60).await;
    assert_eq!(data[0]["telegrams"], json!(2));
    assert_eq!(data[0]["truncated"], json!(true));
    let n = data[0]["records"].as_array().unwrap().len();
    assert!(n > 0 && n < 120, "{n}");
    // A full read on the same connection is a fresh readout: SND_NKE once, FCB toggled.
    m.send(json!({"type": "mbus_read", "address": 4})).await;
    let data = m.wait_for_events("mbus_data", 2, 60).await;
    assert_eq!(data[1]["records"].as_array().unwrap().len(), 120);
    assert_eq!(data[1]["records"][119]["storage"], json!(119));
}

#[tokio::test]
async fn writes_resets_and_new_addresses_are_acknowledged_or_not() {
    let g = support::gateway(support::meters()).await;
    let m = support::connect(
        &g.addr(),
        support::script("import json\nprint(json.dumps({'actions':[]}))"),
        300,
    )
    .await;
    m.send(json!({"type": "mbus_write", "address": 1, "records": [{"quantity": "energy", "unit": "Wh", "value": 0}]}))
        .await;
    m.send(json!({"type": "mbus_write", "address": 2, "records": [{"quantity": "energy", "unit": "Wh", "value": 0}]}))
        .await;
    m.send(json!({"type": "mbus_set_primary_address", "secondary_address": "123456782D2C0104", "new_address": 9}))
        .await;
    m.send(json!({"type": "mbus_application_reset", "address": 9, "subcode": 3}))
        .await;
    m.send(json!({"type": "mbus_read", "address": 9})).await;
    m.send(json!({"type": "mbus_read", "address": 1})).await;
    let acks = m.wait_for_events("mbus_ack", 4, 60).await;
    let summary: Vec<(String, bool)> = acks
        .iter()
        .map(|a| {
            (
                a["operation"].as_str().unwrap().to_string(),
                a["acknowledged"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("mbus_write".to_string(), true),
            ("mbus_write".to_string(), false),
            ("mbus_set_primary_address".to_string(), true),
            ("mbus_application_reset".to_string(), true)
        ]
    );
    let data = m.wait_for_events("mbus_data", 1, 30).await;
    assert_eq!(data[0]["meter"]["id"], "12345678");
    assert_eq!(data[0]["target"]["address"], json!(9));
    let errors = m.wait_for_events("mbus_error", 1, 30).await;
    assert_eq!(errors[0]["kind"], "timeout");
    assert_eq!(errors[0]["target"]["address"], json!(1));
    let writes = g.events("mbus_write_data").await;
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[2]["records"][0]["quantity"], "bus_address");
    assert_eq!(
        g.events("mbus_application_reset").await[0]["subcode"],
        json!(3)
    );
}

#[tokio::test]
async fn a_chain_of_model_turns_stops_at_the_follow_up_depth() {
    let g = support::gateway(support::meters()).await;
    // Every result is answered with another read, forever.
    let forever = r#"import json,sys
print(json.dumps({'actions':[{'type':'mbus_read','address':1}]}))"#;
    let m = support::connect(&g.addr(), support::script(forever), 300).await;
    let mut log_ok = false;
    for _ in 0..600 {
        if m.log_text().contains("chain of follow-ups reached") {
            log_ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(log_ok, "{}", m.log_text());
    // Connected (depth 0) asks for read 1; reads at depths 1-8 happen; depth 8's result is
    // not shown to the model.
    let depth = netget::client::mbus::MAX_FOLLOWUP_DEPTH as usize;
    assert_eq!(
        g.wait_for_events("mbus_request_data", depth, 30)
            .await
            .len(),
        depth
    );
    // And no more come after the chain stopped.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(g.events("mbus_request_data").await.len(), depth);
}

#[tokio::test]
async fn with_no_model_the_master_sends_nothing() {
    let g = support::gateway(support::meters()).await;
    let m: Master = support::connect(&g.addr(), None, 300).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    while !m.log_text().contains("decision=llm_error") && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(g.events("mbus_request_data").await.is_empty());
    assert!(g.events("mbus_write_data").await.is_empty());
    // Injected actions still work: the operator is not the model.
    m.send(json!({"type": "mbus_read", "address": 2})).await;
    assert_eq!(g.wait_for_events("mbus_request_data", 1, 30).await.len(), 1);
    // A malformed action is refused before it reaches the bus.
    let refused = m.send(json!({"type": "mbus_read", "address": 251})).await;
    assert!(
        matches!(
            refused,
            netget::state::client_handles::ClientSendOutcome::Rejected { .. }
        ),
        "{refused:?}"
    );
}
