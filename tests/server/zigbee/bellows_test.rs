//! zigpy's bellows (0.46.2, zigpy 0.84.0) as an independent EZSP host against NetGet's
//! co-processor, through its own CLI and through a zigpy application, failing rather than
//! skipping when it is absent.
//!
//! bellows' ASH (CRC, randomisation, frame numbers, NAK handling) and its per-version EZSP
//! command tables are an implementation of Silicon Labs' UG101/UG100 that shares nothing with
//! NetGet: a frame or field NetGet gets wrong fails to parse on its side or raises on a
//! status it does not accept.
use super::support::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// The bellows venv: `NETGET_ZIGBEE_BELLOWS_VENV`, or the one a `bellows` on PATH lives in.
pub fn bellows_venv() -> PathBuf {
    let venv = std::env::var_os("NETGET_ZIGBEE_BELLOWS_VENV")
        .map(PathBuf::from)
        .or_else(|| {
            crate::helpers::real_server::find_binary("bellows")
                .and_then(|b| b.parent()?.parent().map(PathBuf::from))
        })
        .unwrap_or_else(|| {
            panic!(
                "bellows is required for the Zigbee co-processor evidence: run \
                 sh scripts/test-peers/install-zigbee-hosts.sh <dir> (needs python3 and npm) and \
                 set NETGET_ZIGBEE_BELLOWS_VENV=<dir>/venv"
            )
        });
    assert!(
        venv.join("bin/bellows").exists(),
        "NETGET_ZIGBEE_BELLOWS_VENV={} has no bin/bellows; rerun scripts/test-peers/install-zigbee-hosts.sh",
        venv.display()
    );
    venv
}

/// Run a bellows-venv program with a private HOME, under a deadline; returns stdout, stderr
/// and the exit status, printing both streams when asked.
pub async fn run(
    program: PathBuf,
    args: &[&str],
    home: &std::path::Path,
    secs: u64,
) -> (String, String, bool) {
    let child = tokio::process::Command::new(&program)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("running {}: {e}", program.display()));
    let out = tokio::time::timeout(Duration::from_secs(secs), child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("{} {args:?} did not finish in {secs}s", program.display()))
        .expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

pub fn shown(what: &str, out: &(String, String, bool)) -> String {
    format!(
        "{what}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.0, out.1
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn bellows_cli_info_form_permit_and_devices() {
    let venv = bellows_venv();
    let bellows = venv.join("bin/bellows");
    let home = tempfile::tempdir().unwrap();

    // info against a network the model formed (startup parameters).
    let s = start(
        POLICY,
        json!({"network": formed(15), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let device = format!("socket://127.0.0.1:{}", s.addr.port());
    let info = run(bellows.clone(), &["-d", &device, "info"], home.path(), 90).await;
    let text = shown("bellows info", &info);
    assert!(info.2, "{text}");
    for want in [
        "00:0d:6f:00:0a:1b:2c:3d",
        "JOINED_NETWORK",
        "panId=0x1A62",
        "radioChannel=15",
        "extendedPanId=dd:dd:dd:dd:dd:dd:dd:dd",
        "COORDINATOR",
        "Manufacturer: NetGet",
        "Board name: NetGet EZSP NCP",
        "EmberZNet version: 8.1.0.0 build 0",
    ] {
        assert!(text.contains(want), "{want:?} missing from:\n{text}");
    }
    assert!(
        model_calls(&s.state, s.id, "zigbee_permit_joining")
            .await
            .is_empty()
            && model_calls(&s.state, s.id, "zigbee_zcl_request")
                .await
                .is_empty(),
        "info costs no model call"
    );

    // form against a co-processor with no network, then info sees what bellows formed.
    let s = start(POLICY, json!({"devices": devices()})).await;
    let device = format!("socket://127.0.0.1:{}", s.addr.port());
    let db = home.path().join("form.db");
    std::fs::write(&db, b"").unwrap();
    let form = run(
        bellows.clone(),
        &[
            "-d",
            &device,
            "form",
            "-D",
            db.to_str().unwrap(),
            "-c",
            "20",
        ],
        home.path(),
        120,
    )
    .await;
    assert!(form.2, "{}", shown("bellows form", &form));
    let info = run(bellows.clone(), &["-d", &device, "info"], home.path(), 90).await;
    let text = shown("bellows info after form", &info);
    assert!(
        info.2 && text.contains("radioChannel=20") && text.contains("JOINED_NETWORK"),
        "{text}"
    );

    // permit: the model lets kitchen-lamp join; bellows' application interviews it into its
    // database. bellows 0.46.2's own `devices` command cannot open a database under zigpy
    // 0.84 (it validates its configuration twice); zigpy_devices.py is that command's body
    // with the configuration validated once, reading what bellows wrote.
    let permit = run(
        bellows.clone(),
        &[
            "-d",
            &device,
            "permit",
            "-D",
            db.to_str().unwrap(),
            "-t",
            "12",
        ],
        home.path(),
        120,
    )
    .await;
    assert!(permit.2, "{}", shown("bellows permit", &permit));
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/zigbee/zigpy_devices.py");
    let devices = run(
        venv.join("bin/python"),
        &[script.to_str().unwrap(), db.to_str().unwrap()],
        home.path(),
        60,
    )
    .await;
    let text = shown("devices in bellows' database", &devices);
    assert!(devices.2, "{text}");
    let listed: Value = serde_json::from_str(devices.0.lines().last().unwrap_or("[]"))
        .unwrap_or_else(|e| panic!("{e}: {text}"));
    let lamp = listed
        .as_array()
        .and_then(|a| a.iter().find(|d| d["ieee"] == LAMP_IEEE))
        .unwrap_or_else(|| panic!("the lamp is not in bellows' database: {text}"))
        .clone();
    assert_eq!(lamp["nwk"], format!("0x{LAMP_NWK:04x}"), "{text}");
    assert_eq!(
        (lamp["model"].as_str(), lamp["manufacturer"].as_str()),
        (Some("Lamp-1"), Some("NetGet")),
        "{text}"
    );
    assert_eq!(lamp["endpoints"][0]["profile"], 260, "{text}");
    assert_eq!(lamp["endpoints"][0]["in_clusters"]["6"], "On/Off", "{text}");
    assert_eq!(lamp["endpoints"][0]["out_clusters"]["25"], "Ota", "{text}");
    let permits = model_calls(&s.state, s.id, "zigbee_permit_joining").await;
    assert_eq!(permits.len(), 1, "one model call for the one permit");
    assert!(!permits[0].to_string().contains(NETWORK_KEY));
    assert!(
        model_calls(&s.state, s.id, "zigbee_zcl_request")
            .await
            .is_empty(),
        "the interview is answered from the description"
    );
    let free = log_entries(&s.state, s.id, "zigbee_zdo_from_description").await;
    assert!(
        free.len() >= 3,
        "node, active endpoints and simple descriptors: {free:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_zigpy_application_interviews_switches_and_reads_the_models_device() {
    let venv = bellows_venv();
    let home = tempfile::tempdir().unwrap();
    let s = start(
        POLICY,
        json!({"network": formed(25), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let db = home.path().join("zigpy.db");
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/zigbee/zigpy_host.py");
    let out = run(
        venv.join("bin/python"),
        &[
            script.to_str().unwrap(),
            &s.addr.port().to_string(),
            db.to_str().unwrap(),
            LAMP_IEEE,
        ],
        home.path(),
        150,
    )
    .await;
    let text = shown("zigpy application", &out);
    let steps: Vec<Value> = out
        .0
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let step = |name: &str| {
        steps
            .iter()
            .find(|s| s["step"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name} step:\n{text}"))
    };
    assert!(out.2, "{text}");
    let started = step("started");
    assert_eq!(
        (started["channel"].as_u64(), started["pan_id"].as_str()),
        (Some(25), Some("0x1a62")),
        "{text}"
    );
    let i = step("interviewed");
    assert_eq!(i["model"], "Lamp-1", "{text}");
    assert_eq!(i["manufacturer"], "NetGet", "{text}");
    assert_eq!(i["nwk"], format!("0x{LAMP_NWK:04x}"));
    assert_eq!(i["in_clusters"], json!([0, 3, 6, 8]));
    assert_eq!(i["out_clusters"], json!([25]));
    assert_eq!(step("reported")["on_off"], true);
    assert_eq!(step("read")["on_off"], true);
    assert_eq!(step("done")["ok"], true);

    // What each step cost the model: the permit once, the On command once; the interview,
    // the Basic reads and the final read none.
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_permit_joining")
            .await
            .len(),
        1
    );
    let zcl = model_calls(&s.state, s.id, "zigbee_zcl_request").await;
    assert_eq!(zcl.len(), 1, "{zcl:?}");
    assert_eq!(
        (zcl[0]["cluster"].as_str(), zcl[0]["command"].as_str()),
        (Some("on_off"), Some("on"))
    );
    assert!(
        log_entries(&s.state, s.id, "zigbee_zcl_from_description")
            .await
            .len()
            >= 2
    );
}
