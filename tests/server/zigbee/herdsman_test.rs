//! zigbee-herdsman 11.1.1 — the library Zigbee2MQTT runs on — as an independent EZSP host,
//! through its `ember` adapter on tcp://, failing rather than skipping when it is absent.
//!
//! herdsman's ASH is a port of Silicon Labs' C host (its own CRC, randomisation, window and
//! timers) and its EZSP is a separate TypeScript implementation of every command it sends, so
//! it shares nothing with bellows or with NetGet.
use super::support::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

pub fn herdsman_dir() -> PathBuf {
    let dir = std::env::var_os("NETGET_ZIGBEE_HERDSMAN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "zigbee-herdsman is required for the Zigbee co-processor evidence: run \
                 sh scripts/test-peers/install-zigbee-hosts.sh <dir> (needs python3, node and npm) \
                 and set NETGET_ZIGBEE_HERDSMAN=<dir>/herdsman"
            )
        });
    assert!(
        dir.join("node_modules/zigbee-herdsman/package.json").exists(),
        "NETGET_ZIGBEE_HERDSMAN={} has no node_modules/zigbee-herdsman; rerun scripts/test-peers/install-zigbee-hosts.sh",
        dir.display()
    );
    dir
}

async fn run_host(s: &Started, channel: u8, data: &std::path::Path) -> (Vec<Value>, String, bool) {
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/zigbee/herdsman_host.js");
    let ieee = format!("0x{}", LAMP_IEEE.replace(':', ""));
    let child = tokio::process::Command::new("node")
        .arg(script)
        .arg(herdsman_dir())
        .arg(s.addr.port().to_string())
        .arg(data)
        .arg(&ieee)
        .arg(channel.to_string())
        .arg(NETWORK_KEY)
        .env("HOME", data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the herdsman evidence (and is installed with it)");
    let out = tokio::time::timeout(Duration::from_secs(150), child.wait_with_output())
        .await
        .expect("the herdsman host finished in 150 s")
        .expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let text = format!(
        "--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let steps = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    (steps, text, out.status.success())
}

fn step(steps: &[Value], name: &str, text: &str) -> Value {
    steps
        .iter()
        .find(|s| s["step"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("no {name} step:\n{text}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn herdsman_resumes_the_models_network_interviews_switches_and_hears_the_report() {
    let data = tempfile::tempdir().unwrap();
    let s = start(
        POLICY,
        json!({"network": formed(15), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let (steps, text, ok) = run_host(&s, 15, data.path()).await;
    assert!(ok, "{text}");
    // The co-processor's network matched herdsman's configuration: resumed, not re-formed.
    assert_eq!(
        step(&steps, "started", &text)["result"],
        "resumed",
        "{text}"
    );
    let i = step(&steps, "interviewed", &text);
    assert_eq!(i["type"], "Router", "{text}");
    assert_eq!(i["model"], "Lamp-1");
    assert_eq!(i["manufacturer"], "NetGet");
    assert_eq!(i["nwk"], LAMP_NWK);
    assert_eq!(i["inputClusters"], json!([0, 3, 6, 8]));
    assert_eq!(i["outputClusters"], json!([25]));
    assert_eq!(step(&steps, "reported", &text)["data"]["onOff"], 1);
    assert_eq!(step(&steps, "read", &text)["data"]["onOff"], 1);
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_permit_joining")
            .await
            .len(),
        1
    );
    let zcl = model_calls(&s.state, s.id, "zigbee_zcl_request").await;
    assert_eq!(
        zcl.len(),
        1,
        "only the On command reaches the model: {zcl:?}"
    );
    assert_eq!(zcl[0]["command"], "on");
}

#[tokio::test(flavor = "multi_thread")]
async fn herdsman_forms_a_network_on_an_empty_co_processor() {
    let data = tempfile::tempdir().unwrap();
    let s = start(POLICY, json!({"devices": devices()})).await;
    let (steps, text, ok) = run_host(&s, 20, data.path()).await;
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
}
