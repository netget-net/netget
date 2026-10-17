//! The network server over raw packet-forwarder datagrams: a join, uplinks answered in RX1,
//! MAC commands, the downlink queue, every refusal (MIC, replay, counter gap, DevNonce reuse,
//! unknown device) and every fail-closed path, and the datagram bounds.
use super::support::*;
use netget::server::lorawan::{mac, semtech};
use serde_json::{json, Value};
use std::time::Duration;

const QUIET: Duration = Duration::from_millis(1500);

fn join_request(dev_eui: &str, app_eui: &str, nonce: u16) -> Vec<u8> {
    mac::encode_join_request(
        &mac::JoinRequest {
            app_eui: eui(app_eui),
            dev_eui: eui(dev_eui),
            dev_nonce: nonce,
        },
        &key(APP_KEY),
    )
}

/// Join meter-1 with this DevNonce and return the device's side of the session.
async fn join(fwd: &Forwarder, nonce: u16) -> (Device, Value) {
    let ack = fwd
        .push(&join_request(DEV_EUI, APP_EUI, nonce), 1_000_000)
        .await
        .expect("PUSH_ACK");
    assert_eq!(ack, vec![2, 0xbe, 0xef, 0x01], "PUSH_ACK echoes the token");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("a Join Accept");
    let phy = Forwarder::phy_of(&txpk);
    let ja = mac::decode_join_accept(&phy, &key(APP_KEY)).expect("decrypts and verifies");
    let (nwk, app) = mac::session_keys(&key(APP_KEY), ja.app_nonce, ja.net_id, nonce);
    (
        Device {
            dev_addr: ja.dev_addr,
            nwk,
            app,
            fcnt_up: 0,
        },
        txpk,
    )
}

#[tokio::test]
async fn join_uplinks_downlinks_and_mac_commands() {
    let s = start(POLICY, json!({"devices": devices(), "net_id": "000013"})).await;
    let fwd = Forwarder::new(s.addr).await;
    assert_eq!(fwd.pull().await.unwrap(), vec![2, 0x12, 0x34, 0x04]);

    let (mut dev, txpk) = join(&fwd, 0x1234).await;
    // RX1 of a join: JOIN_ACCEPT_DELAY1 after the uplink, same channel and data rate.
    assert_eq!(txpk["tmst"], 6_000_000);
    assert_eq!(txpk["freq"], 868.1);
    assert_eq!(txpk["datr"], "SF7BW125");
    assert_eq!(txpk["ipol"], true);
    assert_eq!(txpk["modu"], "LORA");
    assert_eq!(txpk["size"], 17);
    assert_eq!(dev.dev_addr >> 25, 0x13, "NwkID from the NetID");
    let joins = events(&s.state, s.id, "lorawan_join_request").await;
    assert_eq!(joins.len(), 1, "{joins:?}");
    assert_eq!(joins[0]["dev_eui"], DEV_EUI);
    assert_eq!(joins[0]["app_eui"], APP_EUI);
    assert_eq!(joins[0]["dev_nonce"], 0x1234);
    assert_eq!(joins[0]["device"], "meter-1");
    assert_eq!(joins[0]["gateway"], hex::encode(GATEWAY));
    assert_eq!(joins[0]["rssi"], -57);
    // No key is ever shown to the model.
    let shown = serde_json::to_string(&joins).unwrap();
    assert!(!shown.contains(APP_KEY), "{shown}");

    // "hello" on port 2 → "world" on port 10, in RX1.
    let up = dev.uplink(2, b"hello", false, &[]);
    fwd.push(&up, 2_000_000).await.expect("PUSH_ACK");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("downlink");
    assert_eq!(txpk["tmst"], 3_000_000, "RECEIVE_DELAY1");
    let (f, plain, _) = dev.decode(&Forwarder::phy_of(&txpk), 0);
    assert_eq!(
        (f.mtype, f.f_port, plain.as_slice()),
        (mac::MTYPE_UNCONFIRMED_DOWN, Some(10), &b"world"[..])
    );
    assert!(!f.ack && !f.f_pending);
    let ups = wait_events(&s.state, s.id, "lorawan_uplink", 1).await;
    assert_eq!(ups[0]["payload"], "hello");
    assert_eq!(ups[0]["payload_encoding"], "utf8");
    assert_eq!(ups[0]["f_port"], 2);
    assert_eq!(ups[0]["f_cnt"], 0);
    assert_eq!(ups[0]["device"], "meter-1");
    assert_eq!(ups[0]["dev_eui"], DEV_EUI);
    assert_eq!(ups[0]["dev_addr"], mac::dev_addr_hex(dev.dev_addr));
    assert_eq!(ups[0]["max_downlink_payload"], 241);

    // The same frame again (a replay, or a retransmission) reaches nobody.
    fwd.push(&up, 2_500_000).await.expect("PUSH_ACK");
    assert!(fwd.pull_resp(QUIET).await.is_none());
    assert_eq!(events(&s.state, s.id, "lorawan_uplink").await.len(), 1);

    // A confirmed uplink with LinkCheckReq that asks for the device's status: the downlink
    // carries ACK, LinkCheckAns and DevStatusReq.
    let up = dev.uplink(2, b"status?", true, &[mac::CID_LINK_CHECK]);
    fwd.push(&up, 4_000_000).await.expect("PUSH_ACK");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("downlink");
    let (f, plain, cmds) = dev.decode(&Forwarder::phy_of(&txpk), 1);
    assert!(f.ack, "a confirmed uplink is acknowledged");
    assert!(plain.is_empty() && f.f_port.is_none());
    assert_eq!(cmds[0]["command"], "link_check_ans");
    assert_eq!(cmds[0]["gateway_count"], 1);
    assert_eq!(
        cmds[0]["margin_db"], 17,
        "9.5 dB SNR at SF7 is 17 dB above the floor"
    );
    assert_eq!(cmds[1], json!({"command": "dev_status_req"}));

    // The answer to DevStatusReq reaches the model decoded; nothing is due, nothing is sent.
    let up = dev.uplink(2, b"nothing", false, &mac::dev_status_ans(200, -3));
    fwd.push(&up, 6_000_000).await.expect("PUSH_ACK");
    assert!(fwd.pull_resp(QUIET).await.is_none());
    let ups = wait_events(&s.state, s.id, "lorawan_uplink", 3).await;
    assert_eq!(
        ups[2]["mac_commands"],
        json!([{"command": "dev_status_ans", "battery": 200, "margin_db": -3}])
    );

    // Two downlinks: the first now with FPending, the second (confirmed, hex) at the next uplink.
    let up = dev.uplink(2, b"twice", false, &[]);
    fwd.push(&up, 8_000_000).await.expect("PUSH_ACK");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("downlink");
    let (f, plain, _) = dev.decode(&Forwarder::phy_of(&txpk), 2);
    assert_eq!(
        (f.f_port, plain.as_slice(), f.f_pending),
        (Some(11), &b"one"[..], true)
    );
    let up = dev.uplink(2, b"nothing", false, &[]);
    fwd.push(&up, 10_000_000).await.expect("PUSH_ACK");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("queued downlink");
    let (f, plain, _) = dev.decode(&Forwarder::phy_of(&txpk), 3);
    assert_eq!(
        (f.mtype, f.f_port, plain),
        (mac::MTYPE_CONFIRMED_DOWN, Some(12), vec![2, 3])
    );
    assert!(!f.f_pending);

    // A model that answers nothing, or answers what NetGet cannot send: no downlink.
    for p in [&b"silent"[..], b"badport"] {
        let up = dev.uplink(2, p, false, &[]);
        fwd.push(&up, 12_000_000).await.expect("PUSH_ACK");
        assert!(
            fwd.pull_resp(QUIET).await.is_none(),
            "{}",
            String::from_utf8_lossy(p)
        );
    }

    // A forged MIC, then a counter beyond MAX_FCNT_GAP: dropped before the model.
    let before = events(&s.state, s.id, "lorawan_uplink").await.len();
    let mut forged = dev.uplink(2, b"hello", false, &[]);
    let n = forged.len();
    forged[n - 1] ^= 0xff;
    fwd.push(&forged, 13_000_000).await.expect("PUSH_ACK");
    dev.fcnt_up += mac::MAX_FCNT_GAP + 1;
    let far = dev.uplink(2, b"hello", false, &[]);
    fwd.push(&far, 14_000_000).await.expect("PUSH_ACK");
    assert!(fwd.pull_resp(QUIET).await.is_none());
    assert_eq!(events(&s.state, s.id, "lorawan_uplink").await.len(), before);
    // The session survives both: the next honest counter still works.
    dev.fcnt_up -= mac::MAX_FCNT_GAP + 2;
    let up = dev.uplink(2, b"hello", false, &[]);
    fwd.push(&up, 15_000_000).await.expect("PUSH_ACK");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("downlink");
    let (_, plain, _) = dev.decode(&Forwarder::phy_of(&txpk), 4);
    assert_eq!(plain, b"world");

    // Joining again with a used DevNonce is refused; with a fresh one the old session ends.
    fwd.push(&join_request(DEV_EUI, APP_EUI, 0x1234), 16_000_000)
        .await
        .expect("PUSH_ACK");
    assert!(fwd.pull_resp(QUIET).await.is_none(), "DevNonce reuse");
    let old = dev.dev_addr;
    let (mut dev2, _) = join(&fwd, 0x4321).await;
    let stale = Device {
        dev_addr: old,
        nwk: dev.nwk,
        app: dev.app,
        fcnt_up: dev.fcnt_up,
    };
    let mut stale = stale;
    fwd.push(&stale.uplink(2, b"hello", false, &[]), 17_000_000)
        .await
        .expect("PUSH_ACK");
    assert!(
        fwd.pull_resp(QUIET).await.is_none(),
        "the old session is gone"
    );
    fwd.push(&dev2.uplink(2, b"hello", false, &[]), 18_000_000)
        .await
        .expect("PUSH_ACK");
    let (_, txpk) = fwd
        .pull_resp(Duration::from_secs(10))
        .await
        .expect("downlink");
    assert_eq!(dev2.decode(&Forwarder::phy_of(&txpk), 0).1, b"world");
}

#[tokio::test]
async fn joins_fail_closed() {
    let s = start(POLICY, json!({"devices": devices()})).await;
    let fwd = Forwarder::new(s.addr).await;
    fwd.pull().await.expect("PULL_ACK");
    let zero = "0000000000000000";
    // Refused, unanswered and invalidly answered joins; an unknown device; a forged MIC; an
    // AppEUI the device is not configured with.
    let mut forged = join_request(DEV_EUI, APP_EUI, 9);
    forged[20] ^= 1;
    for phy in [
        join_request("1111111111111111", zero, 1),
        join_request("2222222222222222", zero, 2),
        join_request("3333333333333333", zero, 3),
        join_request("4444444444444444", zero, 4),
        forged,
        join_request(DEV_EUI, zero, 5),
    ] {
        fwd.push(&phy, 1_000_000).await.expect("PUSH_ACK");
    }
    assert!(fwd.pull_resp(Duration::from_secs(3)).await.is_none());
    // Only the three configured devices with valid MICs reached the model.
    let joins = wait_events(&s.state, s.id, "lorawan_join_request", 3).await;
    let names: Vec<&str> = joins.iter().filter_map(|j| j["device"].as_str()).collect();
    assert_eq!(names.len(), 3, "{joins:?}");
    for n in ["rejected", "silent", "invalid"] {
        assert!(names.contains(&n), "{names:?}");
    }
}

/// With no handler for joins, the unreachable model is asked, fails, and nobody joins.
#[tokio::test]
async fn model_failure_admits_nobody() {
    let state_policy = r#"import json,sys
print(json.dumps({'actions':[]}))"#;
    let state =
        netget::state::app_state::AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ServerForm {
        protocol: "lorawan".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Run the network".into()),
        event_handlers: Some(vec![json!({"event_pattern":"lorawan_uplink","handler":{"type":"script","language":"python","code":state_policy}})]),
        startup_params: Some(json!({"devices": devices()})),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let fwd = Forwarder::new(std::net::SocketAddr::from(([127, 0, 0, 1], addr.port()))).await;
    fwd.pull().await.expect("PULL_ACK");
    fwd.push(&join_request(DEV_EUI, APP_EUI, 7), 1_000_000)
        .await
        .expect("PUSH_ACK");
    assert!(fwd.pull_resp(Duration::from_secs(8)).await.is_none());
}

#[tokio::test]
async fn datagram_bounds() {
    let s = start(POLICY, json!({"devices": devices()})).await;
    let fwd = Forwarder::new(s.addr).await;
    fwd.pull().await.expect("PULL_ACK");
    let mut dev = Device::abp();

    // 16 rxpk are acknowledged; 17 are not.
    let up = dev.uplink(2, b"nothing", false, &[]);
    let one = rxpk(&up, 1, "SF7BW125");
    let ok = fwd.push_datagram(&json!({"rxpk": vec![one.clone(); semtech::MAX_RXPK]}), 1);
    assert!(fwd.push_raw(&ok).await.is_some());
    let over = fwd.push_datagram(&json!({"rxpk": vec![one; semtech::MAX_RXPK + 1]}), 2);
    assert!(fwd.push_raw(&over).await.is_none());
    // A datagram over 8 KiB, a depth bomb, a version 3 header: no PUSH_ACK.
    let mut big = fwd.push_datagram(&json!({"rxpk": []}), 3);
    big.resize(semtech::MAX_DATAGRAM + 1, b' ');
    assert!(fwd.push_raw(&big).await.is_none());
    let mut bomb = fwd.push_datagram(&json!({}), 4);
    bomb.truncate(12);
    bomb.extend(format!("{{\"x\":{}{}}}", "[".repeat(64), "]".repeat(64)).as_bytes());
    assert!(fwd.push_raw(&bomb).await.is_none());
    let mut v3 = fwd.push_datagram(&json!({}), 5);
    v3[0] = 3;
    assert!(fwd.push_raw(&v3).await.is_none());

    // At SF12 (DR0) a PHYPayload is at most 64 bytes: 65 is dropped, 64 reaches the model.
    let before = events(&s.state, s.id, "lorawan_uplink").await.len();
    let long = dev.uplink(3, &[b'a'; 52], false, &[]);
    assert_eq!(long.len(), 65);
    let d = fwd.push_datagram(&json!({"rxpk": [rxpk(&long, 1, "SF12BW125")]}), 6);
    assert!(fwd.push_raw(&d).await.is_some());
    let fits = dev.uplink(3, &[b'a'; 51], false, &[]);
    let d = fwd.push_datagram(&json!({"rxpk": [rxpk(&fits, 1, "SF12BW125")]}), 7);
    assert!(fwd.push_raw(&d).await.is_some());
    let ups = wait_events(&s.state, s.id, "lorawan_uplink", before + 1).await;
    assert_eq!(ups.len(), before + 1, "{ups:?}");
    assert_eq!(ups.last().unwrap()["payload"], "a".repeat(51));
    // A CRC-bad frame is not used.
    let bad = dev.uplink(3, b"nothing", false, &[]);
    let mut r = rxpk(&bad, 1, "SF7BW125");
    r["stat"] = json!(-1);
    assert!(fwd
        .push_raw(&fwd.push_datagram(&json!({"rxpk": [r]}), 8))
        .await
        .is_some());
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        events(&s.state, s.id, "lorawan_uplink").await.len(),
        before + 1
    );

    // The 65th gateway is refused.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut acked = 0;
    for i in 0..65u8 {
        let mut d = vec![2, 0, i, 0x02, 0xee, 0, 0, 0, 0, 0, 0, i];
        if i == 0 {
            d[11] = 0xff;
        }
        sock.send_to(&d, s.addr).await.unwrap();
        if recv(&sock, Duration::from_millis(500)).await.is_some() {
            acked += 1;
        }
    }
    assert_eq!(
        acked, 63,
        "64 gateways in all, one of them the forwarder above"
    );
}

/// A Join Accept and a data downlink, written into a LoRaTap capture, read by tshark's
/// LoRaWAN dissector with the device's keys: it must decrypt both, verify every MIC, and read
/// the payloads NetGet put there.
#[tokio::test]
async fn tshark_lorawan_dissector_oracle() {
    let tshark = crate::helpers::real_server::find_binary("tshark").unwrap_or_else(|| {
        panic!("tshark is required for the LoRaWAN oracle: brew install wireshark / apt-get install tshark")
    });
    let s = start(POLICY, json!({"devices": devices()})).await;
    let fwd = Forwarder::new(s.addr).await;
    fwd.pull().await.expect("PULL_ACK");
    let jr = join_request(DEV_EUI, APP_EUI, 0x0a0b);
    let (mut dev, txpk) = {
        let ack = fwd.push(&jr, 1_000_000).await;
        assert!(ack.is_some());
        let (_, txpk) = fwd.pull_resp(Duration::from_secs(10)).await.unwrap();
        let phy = Forwarder::phy_of(&txpk);
        let ja = mac::decode_join_accept(&phy, &key(APP_KEY)).unwrap();
        let (nwk, app) = mac::session_keys(&key(APP_KEY), ja.app_nonce, ja.net_id, 0x0a0b);
        (
            Device {
                dev_addr: ja.dev_addr,
                nwk,
                app,
                fcnt_up: 0,
            },
            txpk,
        )
    };
    let accept = Forwarder::phy_of(&txpk);
    let up = dev.uplink(2, b"hello", true, &[mac::CID_LINK_CHECK]);
    fwd.push(&up, 2_000_000).await.unwrap();
    let (_, txpk) = fwd.pull_resp(Duration::from_secs(10)).await.unwrap();
    let down = Forwarder::phy_of(&txpk);
    // The control: the same downlink with one MIC byte flipped must read as bad, or "good"
    // above means nothing.
    let mut forged = down.clone();
    let n = forged.len();
    forged[n - 1] ^= 0x01;
    let frames = [jr, accept, up, down, forged];
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("lorawan.pcap");
    std::fs::write(&pcap, loratap_pcap(&frames)).unwrap();
    let out = std::process::Command::new(&tshark)
        .args([
            "-r",
            pcap.to_str().unwrap(),
            "-T",
            "fields",
            "-E",
            "separator=|",
        ])
        .args([
            "-o",
            &format!("uat:root_keys_lorawan:\"{DEV_EUI}\",\"{APP_KEY}\""),
        ])
        .args([
            "-o",
            &format!(
                "uat:session_keys_lorawan:\"{}\",\"{}\",\"{}\"",
                mac::dev_addr_hex(dev.dev_addr),
                hex::encode(dev.nwk),
                hex::encode(dev.app)
            ),
        ])
        .args([
            "-e",
            "lorawan.msgtype",
            "-e",
            "lorawan.mic.status",
            "-e",
            "lorawan.join_accept.devaddr",
            "-e",
            "lorawan.frmpayload_decrypted",
            "-e",
            "lorawan.link_check_answer.gwcnt",
            "-e",
            "_ws.expert.severity",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{text}{err}");
    let rows: Vec<Vec<&str>> = text.lines().map(|l| l.split('|').collect()).collect();
    assert_eq!(rows.len(), 5, "{text}{err}");
    for row in &rows[..4] {
        assert_eq!(row[1], "1", "every MIC verifies in tshark: {text}");
    }
    assert_eq!(rows[4][1], "0", "the forged MIC reads as bad: {text}");
    assert!(rows[1][0].contains("Join Accept"), "{text}");
    assert_eq!(
        rows[1][2].trim_start_matches("0x"),
        mac::dev_addr_hex(dev.dev_addr),
        "{text}"
    );
    assert_eq!(rows[2][3], hex::encode(b"hello"), "{text}");
    assert_eq!(rows[3][3], hex::encode(b"world"), "{text}");
    assert_eq!(rows[3][4], "1", "{text}");
}

/// A pcap of LoRaTap (linktype 270) records, version 0 header with the LoRaWAN sync word.
fn loratap_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xa1b2c3d4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend(0i32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(65535u32.to_le_bytes());
    out.extend(270u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        let mut rec = vec![0u8, 0];
        rec.extend(15u16.to_be_bytes());
        rec.extend(868_100_000u32.to_be_bytes());
        rec.extend([1, 7, 139, 139, 139, 38, 0x34]);
        rec.extend(f);
        out.extend((i as u32 + 1).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((rec.len() as u32).to_le_bytes());
        out.extend((rec.len() as u32).to_le_bytes());
        out.extend(rec);
    }
    out
}
