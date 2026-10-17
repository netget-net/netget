//! LWN Simulator (UniCT-ARSLab, Go, on ChirpStack's `brocaar/lorawan`) as an independent
//! packet forwarder and end device against NetGet's network server, failing rather than
//! skipping when it is absent.
//!
//! The device joins over OTAA: LWN decrypts NetGet's Join Accept with its AppKey and checks its
//! MIC, derives its own session keys, and sends confirmed uplinks that NetGet must verify and
//! decrypt with the keys it derived. NetGet's first downlink (ACK, a payload and DevStatusReq)
//! must pass LWN's MIC and downlink-counter checks; LWN answers DevStatusReq in its next uplink,
//! which reaches the model decoded. Every one of those steps fails visibly on the device side
//! if NetGet's crypto or counters disagree with an independent implementation.
use super::support::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

const LWN_DEV_EUI: &str = "0102030405060709";

const LWN_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='lorawan_join_request':
  a=[{'type':'lorawan_accept_join'}]
elif e['f_cnt']==0:
  a=[{'type':'lorawan_send_downlink','f_port':10,'payload':'hi'},{'type':'lorawan_request_device_status'}]
else:
  a=[{'type':'lorawan_ignore'}]
print(json.dumps({'actions':a}))"#;

pub fn lwn_binary() -> PathBuf {
    std::env::var_os("NETGET_LWN_SIMULATOR")
        .map(PathBuf::from)
        .or_else(|| crate::helpers::real_server::find_binary("lwnsimulator"))
        .unwrap_or_else(|| {
            panic!(
                "LWN Simulator is required for the LoRaWAN network-server evidence: run \
                 scripts/test-peers/build-lwn-simulator.sh <dir> (needs Go) and set \
                 NETGET_LWN_SIMULATOR=<dir>/bin/lwnsimulator"
            )
        })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn post(client: &reqwest::Client, url: &str, body: Value) -> Value {
    let r = client.post(url).body(body.to_string()).send().await.unwrap();
    assert!(r.status().is_success(), "{url}: {}", r.status());
    r.json().await.unwrap()
}

#[tokio::test]
async fn lwn_device_joins_and_talks_through_lwn_gateway() {
    let binary = lwn_binary();
    let s = start(
        LWN_POLICY,
        json!({"devices": [{"name": "lwn-dev", "dev_eui": LWN_DEV_EUI, "app_eui": "0000000000000000", "app_key": APP_KEY}]}),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    std::fs::write(
        dir.path().join("config.json"),
        json!({"address": "127.0.0.1", "port": port, "metricsPort": free_port(),
               "configDirname": "lwn", "autoStart": false, "verbose": true})
        .to_string(),
    )
    .unwrap();
    let log_path = dir.path().join("lwn.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = tokio::process::Command::new(&binary)
        .current_dir(dir.path())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("starting {}: {e}", binary.display()));
    let api = format!("http://127.0.0.1:{port}/api");
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while http.get(format!("{api}/status")).send().await.is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("LWN Simulator's API came up");
    post(
        &http,
        &format!("{api}/bridge/save"),
        json!({"ip": "127.0.0.1", "port": s.addr.port().to_string()}),
    )
    .await;
    let location = json!({"latitude": 45.0, "longitude": 9.0, "altitude": 0});
    let gw = post(&http, &format!("{api}/add-gateway"), json!({"id": -1, "info": {
        "active": true, "name": "gw1", "macAddress": hex::encode(GATEWAY), "keepAlive": 5,
        "typeGateway": false, "ip": "", "port": "", "location": location}}))
    .await;
    assert_eq!(gw["code"], 0, "{gw}");
    // Region 1 is EU868 in LWN's numbering. Confirmed uplinks of "lwn-hello" on port 2 every
    // 4 s; RX windows held open for 3 s.
    let dev = post(&http, &format!("{api}/add-device"), json!({"id": -1, "info": {
        "name": "lwn-dev", "devEUI": LWN_DEV_EUI, "appKey": APP_KEY,
        "devAddr": "00000000", "nwkSKey": "0".repeat(32), "appSKey": "0".repeat(32),
        "location": location,
        "status": {"active": true, "base64": false, "infoUplink": {"fport": 2, "fcnt": 0},
                   "mtype": "ConfirmedDataUp", "payload": "lwn-hello", "fcntDown": 0},
        "configuration": {"region": 1, "ackTimeout": 2, "rx1DROffset": 0, "supportedADR": false,
            "supportedOtaa": true, "supportedFragment": false, "supportedClassB": false,
            "supportedClassC": false, "range": 10000, "dataRate": 5, "disableFCntDown": false,
            "sendInterval": 4, "nbRetransmission": 1},
        "rxs": [{"delay": 1000, "durationOpen": 3000},
                {"channel": {"active": true, "freqDownlink": 869525000}, "delay": 1000,
                 "durationOpen": 3000, "dataRate": 0}]}}))
    .await;
    assert_eq!(dev["code"], 0, "{dev}");
    let started = http.get(format!("{api}/start")).send().await.unwrap();
    assert!(started.status().is_success());

    // The status answer arrives in an uplink after the first downlink.
    let found = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let ups = events(&s.state, s.id, "lorawan_uplink").await;
            if ups.iter().any(|u| {
                u["mac_commands"]
                    .as_array()
                    .is_some_and(|c| c.iter().any(|c| c["command"] == "dev_status_ans"))
            }) {
                return ups;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    let lwn_log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = http.get(format!("{api}/stop")).send().await;
    let _ = child.kill().await;
    let ups = found.unwrap_or_else(|_| {
        panic!("no DevStatusAns reached the model.\nLWN log:\n{lwn_log}")
    });

    let joins = events(&s.state, s.id, "lorawan_join_request").await;
    assert!(!joins.is_empty(), "{lwn_log}");
    assert_eq!(joins[0]["dev_eui"], LWN_DEV_EUI);
    assert_eq!(joins[0]["gateway"], hex::encode(GATEWAY));
    // LWN decrypted the Join Accept and verified its MIC, then accepted the downlink.
    assert!(lwn_log.contains("Joined"), "{lwn_log}");
    assert!(lwn_log.contains("Downlink Received"), "{lwn_log}");
    for bad in ["Invalid MIC", "Invalid downlink counter", "MACPayload expected"] {
        assert!(!lwn_log.contains(bad), "LWN refused NetGet's frame ({bad}):\n{lwn_log}");
    }
    // NetGet verified and decrypted LWN's uplinks with the session keys both sides derived.
    let first = ups.iter().find(|u| u["f_cnt"] == 0).expect("FCnt 0");
    assert_eq!(first["payload"], "lwn-hello", "{ups:?}");
    assert_eq!(first["confirmed"], true);
    assert_eq!(first["f_port"], 2);
    // The confirmed uplink was acknowledged: LWN moved on rather than retransmitting FCnt 0,
    // and its status answer is decoded.
    let (status, ans) = ups
        .iter()
        .find_map(|u| {
            let c = u["mac_commands"].as_array()?;
            let a = c.iter().find(|c| c["command"] == "dev_status_ans")?;
            Some((u.clone(), a.clone()))
        })
        .expect("checked above");
    assert!(status["f_cnt"].as_u64() > Some(0), "{ups:?}");
    assert!(ans["battery"].is_u64(), "{ans}");
}
