//! The Z-Stack (ZNP) co-processor against the two independent Z-Stack hosts, failing rather
//! than skipping when either is absent:
//!
//! - **zigpy-znp 0.14.2** (on zigpy 0.84.0, through zigpy's application controller, as ZHA
//!   runs it): its own MT framing, NV helpers and NIB parser, and its BDB formation.
//! - **zigbee-herdsman 11.1.1's `zstack` adapter** (Zigbee2MQTT's): a separate TypeScript MT
//!   implementation, struct layouts, startup strategy and commissioning.
//!
//! Each forms a network on an empty co-processor and resumes the one the model described,
//! sees the model's device join, interviews it, switches it on and hears its report. What the
//! model was asked is counted: the permit once, the On command once, the interview and the
//! reads never. Every MT command the host sent is printed, and none may be one the firmware
//! refuses.
use super::bellows_test::{bellows_venv, run, shown};
use super::herdsman_test::{run_adapter, step};
use super::support::*;
use serde_json::{json, Value};
use std::path::PathBuf;

/// The venv with zigpy-znp (installed beside bellows by the same script).
fn znp_python() -> PathBuf {
    let venv = bellows_venv();
    let python = venv.join("bin/python");
    let ok = std::process::Command::new(&python)
        .args(["-c", "import zigpy_znp"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "zigpy-znp is required for the Z-Stack co-processor evidence: rerun \
         sh scripts/test-peers/install-zigbee-hosts.sh <dir> (it installs zigpy-znp 0.14.2 \
         into {}), or set NETGET_ZIGBEE_BELLOWS_VENV to a venv that has it",
        venv.display()
    );
    python
}

/// The MT census the server logs when the host disconnects; asserts nothing in it was refused.
async fn census(s: &mut Started, host: &str) -> String {
    let line = wait_for_log(&mut s.logs, "closed; MT commands", 30).await;
    println!("{host} MT census: {line}");
    assert!(
        !line.contains("unknown 0x"),
        "{host} sent an MT command this firmware refuses: {line}"
    );
    line
}

async fn zigpy(s: &Started, home: &std::path::Path) -> (Vec<Value>, String, bool) {
    let python = znp_python();
    let db = home.join("zigpy.db");
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/zigbee/zigpy_host.py");
    let out = run(
        python,
        &[
            script.to_str().unwrap(),
            &s.addr.port().to_string(),
            db.to_str().unwrap(),
            LAMP_IEEE,
            "znp",
        ],
        home,
        200,
    )
    .await;
    let text = shown("zigpy-znp application", &out);
    let steps = out
        .0
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    (steps, text, out.2)
}

fn zstep(steps: &[Value], name: &str, text: &str) -> Value {
    steps
        .iter()
        .find(|s| s["step"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("no {name} step:\n{text}"))
}

/// The model's bill for one host session: one permit, one cluster command, a free interview.
async fn one_permit_one_command(s: &Started) -> Value {
    let permits = model_calls(&s.state, s.id, "zigbee_permit_joining").await;
    assert_eq!(
        permits.len(),
        1,
        "one model call for the one permit: {permits:?}"
    );
    assert!(!permits[0].to_string().contains(NETWORK_KEY));
    let zcl = model_calls(&s.state, s.id, "zigbee_zcl_request").await;
    assert_eq!(
        zcl.len(),
        1,
        "only the On command reaches the model: {zcl:?}"
    );
    assert_eq!(
        (zcl[0]["cluster"].as_str(), zcl[0]["command"].as_str()),
        (Some("on_off"), Some("on"))
    );
    assert!(
        log_entries(&s.state, s.id, "zigbee_zdo_from_description")
            .await
            .len()
            >= 3,
        "node, active endpoints and simple descriptors from the description"
    );
    assert!(
        !log_entries(&s.state, s.id, "zigbee_zcl_from_description")
            .await
            .is_empty(),
        "the Basic and On/Off reads from the description"
    );
    permits[0].clone()
}

fn interviewed_lamp(i: &Value, text: &str) {
    assert_eq!(i["model"], "Lamp-1", "{text}");
    assert_eq!(i["manufacturer"], "NetGet", "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn zigpy_znp_resumes_the_models_network_interviews_switches_and_reads() {
    let home = tempfile::tempdir().unwrap();
    let mut s = start(
        POLICY,
        json!({"dialect": "znp", "network": formed(25), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let (steps, text, ok) = zigpy(&s, home.path()).await;
    assert!(ok, "{text}");
    let started = zstep(&steps, "started", &text);
    assert_eq!(started["channel"], 25, "{text}");
    assert_eq!(started["pan_id"], "0x1a62", "{text}");
    assert_eq!(
        started["extended_pan_id"], "dd:dd:dd:dd:dd:dd:dd:dd",
        "{text}"
    );
    assert_eq!(started["network_key"], NETWORK_KEY, "{text}");
    assert_eq!(started["manufacturer"], "Texas Instruments", "{text}");
    assert_eq!(
        started["model"], "CC2652",
        "zigpy-znp detected Z-Stack 3.30+: {text}"
    );
    let i = zstep(&steps, "interviewed", &text);
    interviewed_lamp(&i, &text);
    assert_eq!(i["nwk"], format!("0x{LAMP_NWK:04x}"));
    assert_eq!(i["in_clusters"], json!([0, 3, 6, 8]));
    assert_eq!(i["out_clusters"], json!([25]));
    assert_eq!(zstep(&steps, "reported", &text)["on_off"], true);
    assert_eq!(zstep(&steps, "read", &text)["on_off"], true);
    assert_eq!(zstep(&steps, "done", &text)["ok"], true);
    one_permit_one_command(&s).await;
    let line = census(&mut s, "zigpy-znp").await;
    for sent in [
        "SYS_OSAL_NV_READ_EXT",
        "APP_CNF_BDB_START_COMMISSIONING",
        "AF_DATA_REQUEST_EXT",
        "ZDO_MGMT_PERMIT_JOIN_REQ",
    ] {
        assert!(line.contains(sent), "{sent} missing from {line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn zigpy_znp_forms_a_network_on_an_empty_co_processor() {
    let home = tempfile::tempdir().unwrap();
    let mut s = start(POLICY, json!({"dialect": "znp", "devices": devices()})).await;
    let (steps, text, ok) = zigpy(&s, home.path()).await;
    assert!(ok, "{text}");
    let started = zstep(&steps, "started", &text);
    assert_eq!(zstep(&steps, "done", &text)["ok"], true, "{text}");
    // zigpy chose the network (from an energy scan NetGet's coordinator answered) and wrote
    // it into NV; the model is told about that network.
    let permit = one_permit_one_command(&s).await;
    assert_eq!(permit["channel"], started["channel"], "{text}");
    assert_eq!(permit["pan_id"], started["pan_id"], "{text}");
    let line = census(&mut s, "zigpy-znp").await;
    for sent in [
        "SYS_OSAL_NV_WRITE_EXT",
        "SYS_OSAL_NV_DELETE",
        "APP_CNF_BDB_SET_CHANNEL",
        "SYS_RESET_REQ",
    ] {
        assert!(line.contains(sent), "{sent} missing from {line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn herdsman_zstack_resumes_the_models_network_interviews_switches_and_hears_the_report() {
    let data = tempfile::tempdir().unwrap();
    let mut s = start(
        POLICY,
        json!({"dialect": "znp", "network": formed(15), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let (steps, text, ok) = run_adapter(&s, 15, data.path(), "zstack").await;
    assert!(ok, "{text}");
    let started = step(&steps, "started", &text);
    assert_eq!(started["result"], "resumed", "{text}");
    assert_eq!(started["coordinator"]["type"], "ZStack3x0", "{text}");
    assert_eq!(
        started["coordinator"]["meta"]["revision"], 20240710,
        "{text}"
    );
    let i = step(&steps, "interviewed", &text);
    interviewed_lamp(&i, &text);
    assert_eq!(i["type"], "Router");
    assert_eq!(i["nwk"], LAMP_NWK);
    assert_eq!(i["inputClusters"], json!([0, 3, 6, 8]));
    assert_eq!(i["outputClusters"], json!([25]));
    assert_eq!(step(&steps, "reported", &text)["data"]["onOff"], 1);
    assert_eq!(step(&steps, "read", &text)["data"]["onOff"], 1);
    one_permit_one_command(&s).await;
    let line = census(&mut s, "herdsman zstack").await;
    for sent in [
        "ZDO_STARTUP_FROM_APP",
        "ZDO_NODE_DESC_REQ",
        "ZDO_SIMPLE_DESC_REQ",
        "AF_DATA_REQUEST×",
        "ZDO_EXT_NWK_INFO",
    ] {
        assert!(line.contains(sent), "{sent} missing from {line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn herdsman_zstack_forms_a_network_on_an_empty_co_processor() {
    let data = tempfile::tempdir().unwrap();
    let mut s = start(POLICY, json!({"dialect": "znp", "devices": devices()})).await;
    let (steps, text, ok) = run_adapter(&s, 20, data.path(), "zstack").await;
    assert!(ok, "{text}");
    assert_eq!(step(&steps, "started", &text)["result"], "reset", "{text}");
    assert_eq!(step(&steps, "done", &text)["ok"], true);
    let backup: Value = serde_json::from_slice(
        &std::fs::read(data.path().join("coordinator_backup.json")).expect("herdsman's backup"),
    )
    .unwrap();
    assert_eq!(backup["channel"], 20, "{backup}");
    assert_eq!(backup["pan_id"], "1a62", "{backup}");
    assert_eq!(backup["network_key"]["key"], NETWORK_KEY, "{backup}");
    let permit = one_permit_one_command(&s).await;
    assert_eq!(permit["channel"], 20);
    let line = census(&mut s, "herdsman zstack").await;
    for sent in [
        "APP_CNF_BDB_START_COMMISSIONING",
        "SYS_OSAL_NV_WRITE_EXT",
        "SYS_RESET_REQ",
    ] {
        assert!(line.contains(sent), "{sent} missing from {line}");
    }
}
