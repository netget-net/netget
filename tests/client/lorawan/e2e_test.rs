//! The LoRaWAN gateway client against NetGet's own network server (policy from the server
//! suite), and against a raw network server written in the test for the TX_ACK checks, the
//! counter and MIC refusals, and the follow-up bound.
use base64::Engine;
use netget::cli::management::{ClientForm, ServerForm};
use netget::server::lorawan::mac;
use netget::state::{
    app_state::AppState, client_handles::ClientSendOutcome, AccessLogOwner, ClientId,
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const APP_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
pub const DEV_EUI: &str = "0102030405060708";

const NS_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='lorawan_join_request': a=[{'type':'lorawan_accept_join'}]
elif e['payload']=='hello': a=[{'type':'lorawan_send_downlink','f_port':10,'payload':'world','confirmed':True},{'type':'lorawan_request_device_status'}]
elif e['payload']=='ping': a=[{'type':'lorawan_send_downlink','f_port':10,'payload':'pong'}]
else: a=[{'type':'lorawan_ignore'}]
print(json.dumps({'actions':a}))"#;

pub fn devices() -> Value {
    json!([
        {"name": "meter-1", "dev_eui": DEV_EUI, "app_key": APP_KEY},
        {"name": "abp-node", "dev_addr": "26011bda", "nwk_s_key": "000102030405060708090a0b0c0d0e0f", "app_s_key": "0f0e0d0c0b0a09080706050403020100"},
    ])
}

async fn netget_ns(policy: &str) -> (AppState, netget::state::ServerId, String) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "lorawan".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Run the network".into()),
        startup_params: Some(json!({"devices": devices()})),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":policy}})]),
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
    (state, id, format!("127.0.0.1:{}", addr.port()))
}

/// A gateway client whose handlers are `handlers` (static or script), the model unreachable.
pub async fn client(remote: String, handlers: Vec<Value>, extra: Value) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let mut params = json!({"devices": devices(), "keepalive_secs": 1});
    if let Value::Object(m) = extra {
        for (k, v) in m {
            params[k] = v;
        }
    }
    let id = ClientForm {
        protocol: "lorawan".into(),
        remote_addr: Some(remote),
        instruction: Some("Be the gateway".into()),
        startup_params: Some(params),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !state.has_client_handle(id).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client connected");
    (state, id)
}

/// Every event of this type the client raised, oldest first.
pub async fn client_events(state: &AppState, id: ClientId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all
}

pub async fn wait_client_events(
    state: &AppState,
    id: ClientId,
    event_type: &str,
    n: usize,
    secs: u64,
) -> Vec<Value> {
    let _ = tokio::time::timeout(Duration::from_secs(secs), async {
        while client_events(state, id, event_type).await.len() < n {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    client_events(state, id, event_type).await
}

async fn server_events(state: &AppState, id: netget::state::ServerId, t: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == t)
        .map(|e| e["request"].clone())
        .collect()
}

#[tokio::test]
async fn against_netget_network_server() {
    let (ns_state, ns_id, addr) = netget_ns(NS_POLICY).await;
    let (state, id) = client(
        addr,
        vec![
            json!({"event_pattern":"lorawan_gateway_connected","handler":{"type":"static","actions":[{"type":"lorawan_send_join_request","device":"meter-1"}]}}),
            json!({"event_pattern":"lorawan_join_accepted","handler":{"type":"static","actions":[{"type":"lorawan_send_uplink","device":"meter-1","f_port":2,"payload":"hello","confirmed":true,"link_check":true}]}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ],
        json!({}),
    )
    .await;
    let joined = wait_client_events(&state, id, "lorawan_join_accepted", 1, 20).await;
    assert_eq!(joined.len(), 1, "no Join Accept");
    assert_eq!(joined[0]["device"], "meter-1");
    assert_eq!(joined[0]["net_id"], "000000");
    let downs = wait_client_events(&state, id, "lorawan_downlink", 1, 20).await;
    let d = &downs[0];
    assert_eq!(d["payload"], "world", "{d}");
    assert_eq!(d["f_port"], 10);
    assert_eq!(d["confirmed"], true);
    assert_eq!(d["ack"], true, "the confirmed uplink was acknowledged");
    assert_eq!(d["f_cnt"], 0);
    let cmds = d["mac_commands"].as_array().unwrap();
    assert_eq!(cmds[0]["command"], "link_check_ans");
    assert_eq!(cmds[1]["command"], "dev_status_req");
    let ups = server_events(&ns_state, ns_id, "lorawan_uplink").await;
    assert_eq!(ups[0]["payload"], "hello");
    assert_eq!(ups[0]["mac_commands"][0]["command"], "link_check_req");

    // Injected: the next uplink carries the ACK for the confirmed downlink and the
    // DevStatusAns the network asked for, with the battery level given.
    let sent = state
        .send_to_client(
            id,
            json!({"type":"lorawan_send_uplink","device":"meter-1","f_port":3,"payload":"0a0b","encoding":"hex","battery":77,"data_rate":"SF9BW125","frequency_mhz":868.3,"rssi":-101,"snr":-4}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");
    let ups = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let ups = server_events(&ns_state, ns_id, "lorawan_uplink").await;
            if let Some(u) = ups.iter().find(|u| u["f_port"] == 3) {
                return u.clone();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("second uplink");
    assert_eq!(ups["payload"], "0a0b");
    assert_eq!(ups["payload_encoding"], "hex");
    assert_eq!(ups["ack"], true);
    assert_eq!(ups["f_cnt"], 1);
    assert_eq!(ups["rssi"], -101);
    assert_eq!(ups["frequency_mhz"], 868.3);
    assert_eq!(ups["data_rate"], "SF9BW125 (DR3)");
    assert_eq!(
        ups["mac_commands"],
        json!([{"command": "dev_status_ans", "battery": 77, "margin_db": -4}])
    );

    // The ABP device needs no join.
    let sent = state
        .send_to_client(
            id,
            json!({"type":"lorawan_send_uplink","device":"abp-node","f_port":4,"payload":"ping"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");
    let downs = wait_client_events(&state, id, "lorawan_downlink", 2, 20).await;
    assert_eq!(downs[1]["device"], "abp-node");
    assert_eq!(downs[1]["payload"], "pong");

    // Refused before anything is sent.
    for (bad, why) in [
        (
            json!({"type":"lorawan_send_uplink","device":"nobody","f_port":2,"payload":"x"}),
            "no configured device",
        ),
        (
            json!({"type":"lorawan_send_join_request","device":"abp-node"}),
            "ABP",
        ),
        (
            json!({"type":"lorawan_send_uplink","device":"meter-1","f_port":2,"payload":"a".repeat(52),"data_rate":"SF12BW125"}),
            "does not fit DR0",
        ),
        (
            json!({"type":"lorawan_send_uplink","device":"meter-1","f_port":0,"payload":"x"}),
            "application port",
        ),
        (
            json!({"type":"lorawan_send_uplink","device":"meter-1","f_port":2,"payload":"x","frequency_mhz":915.0}),
            "outside EU868",
        ),
    ] {
        let out = state
            .send_to_client(id, bad.clone(), Duration::from_secs(10))
            .await
            .unwrap();
        match out {
            ClientSendOutcome::Rejected { error } => assert!(error.contains(why), "{bad}: {error}"),
            other => panic!("{bad}: {other:?}"),
        }
    }
    state.remove_client(id).await;
}

/// A network server written in the test: it acknowledges the gateway and sends whatever
/// PULL_RESP the test hands it, returning the gateway's TX_ACK.
struct RawNs {
    sock: UdpSocket,
    gateway: Option<std::net::SocketAddr>,
}

impl RawNs {
    async fn new() -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            gateway: None,
        }
    }
    fn addr(&self) -> String {
        self.sock.local_addr().unwrap().to_string()
    }
    /// Answer datagrams until a PUSH_DATA with an rxpk arrives; returns its PHYPayload and tmst.
    async fn next_uplink(&mut self) -> (Vec<u8>, u32) {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(10), self.sock.recv_from(&mut buf))
                    .await
                    .expect("an uplink")
                    .unwrap();
            let d = &buf[..n];
            match d[3] {
                0x02 => {
                    self.gateway = Some(from);
                    self.sock
                        .send_to(&[d[0], d[1], d[2], 0x04], from)
                        .await
                        .unwrap();
                }
                0x00 => {
                    self.sock
                        .send_to(&[d[0], d[1], d[2], 0x01], from)
                        .await
                        .unwrap();
                    let body: Value = serde_json::from_slice(&d[12..]).unwrap();
                    if let Some(r) = body["rxpk"].as_array().and_then(|r| r.first()) {
                        let phy = base64::engine::general_purpose::STANDARD
                            .decode(r["data"].as_str().unwrap())
                            .unwrap();
                        return (phy, r["tmst"].as_u64().unwrap() as u32);
                    }
                }
                _ => {}
            }
        }
    }
    /// Send a PULL_RESP and return the TX_ACK's error.
    async fn pull_resp(&self, txpk: Value, token: u16) -> String {
        let t = token.to_be_bytes();
        let mut d = vec![2, t[0], t[1], 0x03];
        d.extend(serde_json::to_vec(&json!({ "txpk": txpk })).unwrap());
        self.sock.send_to(&d, self.gateway.unwrap()).await.unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, _) =
                tokio::time::timeout(Duration::from_secs(5), self.sock.recv_from(&mut buf))
                    .await
                    .expect("a TX_ACK")
                    .unwrap();
            let d = &buf[..n];
            if d[3] == 0x05 {
                assert_eq!(&d[1..3], &t, "TX_ACK echoes the PULL_RESP token");
                let body: Value = serde_json::from_slice(&d[12..]).unwrap();
                return body["txpk_ack"]["error"].as_str().unwrap().to_string();
            }
            if d[3] == 0x02 {
                self.sock
                    .send_to(&[d[0], d[1], d[2], 0x04], self.gateway.unwrap())
                    .await
                    .unwrap();
            }
        }
    }
}

fn txpk(phy: &[u8], tmst: Option<u32>, freq: f64, powe: i32) -> Value {
    let mut t = json!({"freq": freq, "rfch": 0, "powe": powe, "modu": "LORA", "datr": "SF7BW125",
        "codr": "4/5", "ipol": true, "size": phy.len(),
        "data": base64::engine::general_purpose::STANDARD.encode(phy)});
    match tmst {
        Some(v) => t["tmst"] = json!(v),
        None => t["imme"] = json!(true),
    }
    t
}

/// The gateway's TX_ACK checks, and what it refuses of a network's downlinks: a forged Join
/// Accept, a forged or replayed data downlink.
#[tokio::test]
async fn tx_ack_and_downlink_refusals() {
    let mut ns = RawNs::new().await;
    let addr = ns.addr();
    let ns_task = async {
        let (state, id) = client(
            addr,
            vec![
                json!({"event_pattern":"lorawan_gateway_connected","handler":{"type":"static","actions":[{"type":"lorawan_send_join_request","device":"meter-1"}]}}),
                json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
            ],
            json!({}),
        )
        .await;
        (state, id)
    };
    // The client's first PULL_DATA must be acknowledged before it connects; answer it while
    // it is being created.
    let (client_side, (jr, tmst)) = tokio::join!(ns_task, ns.next_uplink());
    let (state, id) = client_side;
    let req = mac::parse_join_request(&jr).unwrap();
    assert_eq!(mac::eui_hex(&req.dev_eui), DEV_EUI);
    let key = mac::parse_key("k", APP_KEY).unwrap();
    assert!(mac::join_request_mic_ok(&jr, &key));

    let ja = mac::JoinAccept {
        app_nonce: 0x010203,
        net_id: 0x13,
        dev_addr: 0x2600_0001,
        rx1_dr_offset: 0,
        rx2_data_rate: 0,
        rx_delay: 1,
        cf_list: Some([0; 16]),
    };
    let accept = mac::encode_join_accept(&ja, &key);
    // Refused by the gateway: off-band, over power, already past.
    assert_eq!(
        ns.pull_resp(txpk(&accept, Some(tmst + 5_000_000), 915.0, 14), 1)
            .await,
        "TX_FREQ"
    );
    assert_eq!(
        ns.pull_resp(txpk(&accept, Some(tmst + 5_000_000), 868.1, 30), 2)
            .await,
        "TX_POWER"
    );
    assert_eq!(
        ns.pull_resp(txpk(&accept, Some(tmst.wrapping_sub(1)), 868.1, 14), 3)
            .await,
        "TOO_LATE"
    );
    // A Join Accept under another key is transmitted but no device takes it.
    let forged = mac::encode_join_accept(&ja, &[9; 16]);
    assert_eq!(
        ns.pull_resp(txpk(&forged, None, 868.1, 14), 4).await,
        "NONE"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(client_events(&state, id, "lorawan_join_accepted")
        .await
        .is_empty());
    // The real one (with a CFList, 33 bytes) joins.
    assert_eq!(
        ns.pull_resp(txpk(&accept, Some(tmst + 5_000_000), 868.1, 14), 5)
            .await,
        "NONE"
    );
    let joined = wait_client_events(&state, id, "lorawan_join_accepted", 1, 10).await;
    assert_eq!(joined[0]["dev_addr"], "26000001");

    let (nwk, app) = mac::session_keys(&key, ja.app_nonce, ja.net_id, req.dev_nonce);
    let down = |fcnt: u32, payload: &[u8], key: &mac::Key| {
        mac::encode_data(
            &mac::OutFrame {
                mtype: mac::MTYPE_UNCONFIRMED_DOWN,
                dev_addr: ja.dev_addr,
                adr: false,
                adr_ack_req: false,
                ack: false,
                f_pending: false,
                f_cnt: fcnt,
                f_opts: &[],
                f_port: Some(5),
                payload,
            },
            key,
            &app,
        )
        .unwrap()
    };
    // Forged MIC, then a good one, then the good one replayed, then a counter too far ahead.
    for (n, phy) in [
        (6, down(0, b"forged", &[1; 16])),
        (7, down(0, b"first", &nwk)),
        (8, down(0, b"first", &nwk)),
        (9, down(mac::MAX_FCNT_GAP + 5, b"far", &nwk)),
        (10, down(1, b"second", &nwk)),
    ] {
        assert_eq!(ns.pull_resp(txpk(&phy, None, 869.525, 27), n).await, "NONE");
    }
    wait_client_events(&state, id, "lorawan_downlink", 2, 10).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let downs = client_events(&state, id, "lorawan_downlink").await;
    let payloads: Vec<&str> = downs
        .iter()
        .map(|d| d["payload"].as_str().unwrap())
        .collect();
    assert_eq!(payloads, ["first", "second"], "{downs:?}");
    assert_eq!(downs[0]["immediate"], true);
    state.remove_client(id).await;
}

/// A device and a network that answer each other forever: the gateway stops the chain.
#[tokio::test]
async fn follow_up_chain_is_bounded() {
    let (ns_state, ns_id, addr) = netget_ns(
        r#"import json,sys
i=json.load(sys.stdin)
a=[{'type':'lorawan_accept_join'}] if i['event_type_id']=='lorawan_join_request' else [{'type':'lorawan_send_downlink','f_port':10,'payload':'again'}]
print(json.dumps({'actions':a}))"#,
    )
    .await;
    let (state, id) = client(
        addr,
        vec![
            json!({"event_pattern":"lorawan_gateway_connected","handler":{"type":"static","actions":[{"type":"lorawan_send_join_request","device":"meter-1"}]}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"lorawan_send_uplink","device":"meter-1","f_port":2,"payload":"more"}]}}),
        ],
        json!({}),
    )
    .await;
    // Settle: wait until the uplink count stops growing.
    let mut last = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let n = server_events(&ns_state, ns_id, "lorawan_uplink")
            .await
            .len();
        if n == last && n > 0 {
            break;
        }
        last = n;
    }
    let n = server_events(&ns_state, ns_id, "lorawan_uplink")
        .await
        .len();
    assert!(
        (1..=netget::client::lorawan::MAX_FOLLOWUP_DEPTH).contains(&n),
        "{n} uplinks: the chain was not bounded"
    );
    state.remove_client(id).await;
}
