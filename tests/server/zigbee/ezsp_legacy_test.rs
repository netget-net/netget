//! EZSP 8 to 13: the one-byte `EmberStatus`/`EzspStatus` encodings and the pre-14 layouts,
//! against bellows 0.46.2 (which has a command table for every version from 4) at every one
//! of them, and against zigbee-herdsman 11.1.1's `ember` adapter at 13 (its floor: it refuses
//! 12 and below). Then the encodings themselves on raw bytes.
use super::bellows_test::{bellows_venv, run, shown};
use super::herdsman_test::{run_adapter, step};
use super::support::*;
use netget::server::zigbee::ezsp;
use serde_json::{json, Value};
use std::path::PathBuf;

/// bellows' zigpy application at one EZSP version; returns the steps, the output and the
/// EZSP census the server logged.
async fn bellows_at(version: u8, formed_channel: Option<u8>) -> (Vec<Value>, String, String) {
    let venv = bellows_venv();
    let home = tempfile::tempdir().unwrap();
    let mut params = json!({"ezsp_version": version, "devices": devices()});
    if let Some(c) = formed_channel {
        params["network"] = formed(c);
        params["network_key"] = json!(NETWORK_KEY);
    }
    let mut s = start(POLICY, params).await;
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
            "bellows",
        ],
        home.path(),
        200,
    )
    .await;
    let text = shown(&format!("zigpy (bellows) at EZSP {version}"), &out);
    assert!(out.2, "{text}");
    let steps: Vec<Value> = out
        .0
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_permit_joining")
            .await
            .len(),
        1,
        "EZSP {version}: one permit"
    );
    let zcl = model_calls(&s.state, s.id, "zigbee_zcl_request").await;
    assert_eq!(zcl.len(), 1, "EZSP {version}: only the On command: {zcl:?}");
    let census = wait_for_log(
        &mut s.logs,
        &format!("closed; EZSP v{version} commands"),
        30,
    )
    .await;
    println!("bellows at EZSP {version}: {census}");
    assert!(
        !census.contains("unknown 0x"),
        "bellows sent a command NetGet refuses at EZSP {version}: {census}"
    );
    (steps, text, census)
}

fn steps_held(steps: &[Value], text: &str) {
    for name in ["started", "interviewed", "reported", "read"] {
        assert!(
            steps.iter().any(|s| s["step"] == name),
            "no {name} step:\n{text}"
        );
    }
    let done = steps.iter().find(|s| s["step"] == "done").expect("done");
    assert_eq!(done["ok"], true, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bellows_completes_a_session_at_every_ezsp_version_from_8_to_13() {
    let runs = (8u8..=13).map(|v| bellows_at(v, Some(25)));
    for (i, (steps, text, census)) in futures::future::join_all(runs)
        .await
        .into_iter()
        .enumerate()
    {
        let v = 8 + i as u8;
        steps_held(&steps, &text);
        let started = steps.iter().find(|s| s["step"] == "started").unwrap();
        assert_eq!(started["channel"], 25, "{text}");
        assert_eq!(started["network_key"], NETWORK_KEY, "{text}");
        // Each version reads the network key its own way: getKey before 13, the security
        // manager's exportKey and getNetworkKeyInfo from 13.
        if v < 13 {
            assert!(census.contains("getKey×"), "{census}");
            assert!(census.contains("addTransientLinkKey×"), "{census}");
        } else {
            assert!(
                census.contains("exportKey×") && census.contains("getNetworkKeyInfo×"),
                "{census}"
            );
            assert!(census.contains("importTransientKey×"), "{census}");
        }
        if v >= 9 {
            assert!(census.contains("getTokenData×"), "{census}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bellows_forms_a_network_at_ezsp_13_and_8() {
    for v in [13u8, 8] {
        let (steps, text, census) = bellows_at(v, None).await;
        steps_held(&steps, &text);
        // zigpy forms, writes its settings and forms again on them.
        assert!(census.contains("formNetwork×"), "{census}");
        assert!(census.contains("setInitialSecurityState×"), "{census}");
        assert!(
            census.contains("startScan×"),
            "the energy scan that chose the channel: {census}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn herdsman_ember_resumes_and_switches_at_ezsp_13() {
    let data = tempfile::tempdir().unwrap();
    let mut s = start(
        POLICY,
        json!({"ezsp_version": 13, "network": formed(15), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let (steps, text, ok) = run_adapter(&s, 15, data.path(), "ember").await;
    assert!(ok, "{text}");
    let started = step(&steps, "started", &text);
    assert_eq!(started["result"], "resumed", "{text}");
    assert_eq!(started["coordinator"]["meta"]["ezsp"], 13, "{text}");
    assert_eq!(
        started["coordinator"]["meta"]["revision"], "7.4.3 [GA]",
        "{text}"
    );
    assert_eq!(step(&steps, "interviewed", &text)["model"], "Lamp-1");
    assert_eq!(step(&steps, "reported", &text)["data"]["onOff"], 1);
    assert_eq!(step(&steps, "read", &text)["data"]["onOff"], 1);
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_permit_joining")
            .await
            .len(),
        1
    );
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_zcl_request")
            .await
            .len(),
        1
    );
    let census = wait_for_log(&mut s.logs, "closed; EZSP v13 commands", 30).await;
    println!("herdsman ember at EZSP 13: {census}");
    assert!(!census.contains("unknown 0x"), "{census}");
}

/// Reset and negotiate as bellows does, at the co-processor's own version.
async fn negotiated(version: u8) -> (Started, Host) {
    let s = start(
        POLICY,
        json!({"ezsp_version": version, "network": formed(15), "network_key": NETWORK_KEY, "devices": devices()}),
    )
    .await;
    let mut h = Host::connect(s.addr).await;
    assert_eq!(h.startup().await, version);
    (s, h)
}

#[tokio::test(flavor = "multi_thread")]
async fn statuses_are_one_byte_and_layouts_are_the_old_ones_before_14() {
    let (s, mut h) = negotiated(13).await;
    // invalidCommand: the EzspStatus in one byte.
    let (id, p) = h.command(0x0999, &[]).await;
    assert_eq!((id, p), (ezsp::id::INVALID_COMMAND, vec![0x31]));
    // getConfigurationValue: EzspStatus SUCCESS, then the value.
    let (_, p) = h.command(ezsp::id::GET_CONFIGURATION_VALUE, &[0x11]).await;
    assert_eq!(
        p,
        vec![0x00, 6, 0],
        "one-byte status, then MAX_END_DEVICE_CHILDREN"
    );
    let (_, p) = h.command(ezsp::id::GET_CONFIGURATION_VALUE, &[0xEE]).await;
    assert_eq!(
        p,
        vec![0x37, 0, 0],
        "EZSP_ERROR_INVALID_ID for a config id it lacks"
    );
    h.add_endpoint_v13().await;
    // networkInit: EmberStatus SUCCESS; stackStatusHandler: EMBER_NETWORK_UP (0x90).
    let (_, p) = h.command(ezsp::id::NETWORK_INIT, &[0, 0]).await;
    assert_eq!(p, vec![0x00]);
    let st = h
        .callback(ezsp::id::STACK_STATUS_HANDLER, 5.0)
        .await
        .expect("stackStatusHandler");
    assert_eq!(st, vec![0x90], "EMBER_NETWORK_UP in one byte");
    // permitJoining, then the join's callbacks and the device's announcement in the v13
    // incomingMessageHandler layout: type, APS frame, LQI, RSSI, sender, binding index,
    // address index, contents — no EUI-64.
    let (_, p) = h.command(ezsp::id::PERMIT_JOINING, &[30]).await;
    assert_eq!(p, vec![0x00]);
    let opened = h
        .callback(ezsp::id::STACK_STATUS_HANDLER, 5.0)
        .await
        .expect("network opened");
    assert_eq!(opened, vec![0x9C], "EMBER_NETWORK_OPENED");
    h.callback(ezsp::id::TRUST_CENTER_JOIN_HANDLER, 15.0)
        .await
        .expect("trustCenterJoinHandler");
    let annce = h
        .callback(ezsp::id::INCOMING_MESSAGE_HANDLER, 5.0)
        .await
        .expect("incomingMessageHandler");
    assert_eq!(annce[0], 0x04, "broadcast");
    assert_eq!(
        u16::from_le_bytes([annce[3], annce[4]]),
        0x0013,
        "Device_annce"
    );
    assert_eq!(
        (annce[12], annce[13] as i8),
        (0xFF, -42),
        "LQI and RSSI right after the APS frame"
    );
    let sender = u16::from_le_bytes([annce[14], annce[15]]);
    let len = annce[18] as usize;
    assert_eq!(annce.len(), 19 + len, "no EUI-64, no timestamp");
    // sendUnicast with an 8-bit tag; messageSentHandler: type, destination, APS, 8-bit tag,
    // one-byte status, contents.
    let mut p = vec![0x00];
    p.extend_from_slice(&sender.to_le_bytes());
    p.extend_from_slice(&0x0104u16.to_le_bytes());
    p.extend_from_slice(&0x0000u16.to_le_bytes());
    p.extend_from_slice(&[1, 1]);
    p.extend_from_slice(&0x0140u16.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.push(0);
    p.push(0x5A); // message tag, one byte
    let read = zcl_read(9, &[0x0004]);
    p.push(read.len() as u8);
    p.extend_from_slice(&read);
    let (_, r) = h.command(ezsp::id::SEND_UNICAST, &p).await;
    assert_eq!(r[0], 0x00, "EmberStatus SUCCESS");
    assert_eq!(r.len(), 2, "status and APS sequence");
    let sent = h
        .callback(ezsp::id::MESSAGE_SENT_HANDLER, 5.0)
        .await
        .expect("messageSentHandler");
    assert_eq!(sent[0], 0x00, "OUTGOING_DIRECT first");
    assert_eq!(u16::from_le_bytes([sent[1], sent[2]]), sender);
    assert_eq!(
        (sent[14], sent[15]),
        (0x5A, 0x00),
        "the 8-bit tag, then the status"
    );
    let _ = s;

    // Before 13: getKey hands bellows the network key; getNetworkKeyInfo did not exist yet.
    let (_s8, mut h) = negotiated(8).await;
    let (_, p) = h.command(0x006A, &[3]).await;
    assert_eq!(p[0], 0x00, "EmberStatus SUCCESS");
    assert_eq!(p.len(), 1 + 36, "status and EmberKeyStruct");
    assert_eq!(p[3], 3, "CURRENT_NETWORK_KEY");
    assert_eq!(hex::encode(&p[4..20]), NETWORK_KEY);
    let (id, p) = h.command(ezsp::id::GET_NETWORK_KEY_INFO, &[]).await;
    assert_eq!(
        (id, p),
        (ezsp::id::INVALID_COMMAND, vec![0x31]),
        "not a v8 command"
    );
}
