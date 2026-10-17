//! NetGet's LoRaWAN gateway against ChirpStack v4 — the full network server, with its Gateway
//! Bridge turning the Semtech UDP protocol into MQTT through Mosquitto, and Redis for its
//! device sessions — failing rather than skipping when any of them is absent.
//!
//! ChirpStack is provisioned through its own gRPC API (`chirpstack_peer.py`, the official
//! `chirpstack-api` client) with one EU868 LoRaWAN 1.0.3 OTAA device. NetGet's gateway sends
//! that device's Join Request; ChirpStack verifies its MIC, answers with a Join Accept that
//! NetGet must decrypt and verify (ChirpStack's 33-byte form, with a CFList); NetGet's uplink
//! must pass ChirpStack's MIC and counter checks and reach its MQTT application integration
//! decrypted; a downlink queued through ChirpStack's API must come back as a PULL_RESP that
//! NetGet verifies and decrypts, and ChirpStack must accept NetGet's TX_ACK for it.
//!
//! The peers come from `scripts/test-peers/install-chirpstack.sh <dir>`, which prints the
//! environment this test reads (`NETGET_CHIRPSTACK`, `NETGET_CHIRPSTACK_GATEWAY_BRIDGE`,
//! `NETGET_CHIRPSTACK_PYTHON`); Redis and Mosquitto come from the system.
use super::e2e_test::{client, client_events, wait_client_events, APP_KEY};
use crate::helpers::real_server::{InstallHint, RealServer};
use base64::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

const DEV_EUI: &str = "0102030405060708";
const GATEWAY_EUI: &str = "4e65744765740001";

const INSTALL: &str = "scripts/test-peers/install-chirpstack.sh <dir> (downloads ChirpStack \
                       v4 and its Gateway Bridge, and makes a venv with chirpstack-api) and \
                       export what it prints";

fn env_path(var: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{var} is required for the ChirpStack evidence: run {INSTALL}"))
}

const REDIS: InstallHint = InstallHint {
    brew: "redis",
    apt: "redis-server",
};
const MOSQUITTO: InstallHint = InstallHint {
    brew: "mosquitto",
    apt: "mosquitto mosquitto-clients",
};
const CHIRPSTACK: InstallHint = InstallHint {
    brew: "(none: Linux only) — run scripts/test-peers/install-chirpstack.sh",
    apt: "(none) — run scripts/test-peers/install-chirpstack.sh",
};

fn chirpstack_toml(api_port: &str, redis: &str, mqtt: &str) -> String {
    format!(
        r#"[logging]
  level="info"
[sqlite]
  path="sqlite://{{dir}}/chirpstack.sqlite"
[redis]
  servers=["redis://{redis}/"]
[network]
  net_id="000013"
  enabled_regions=["eu868"]
[api]
  bind="127.0.0.1:{api_port}"
  secret="netget-test-secret"
[integration]
  enabled=["mqtt"]
  [integration.mqtt]
    server="tcp://{mqtt}/"
    json=true
"#
    )
}

fn region_toml(mqtt: &str) -> String {
    let channels: String = [868_100_000, 868_300_000, 868_500_000]
        .iter()
        .map(|f| {
            format!(
                "    [[regions.gateway.channels]]\n      frequency={f}\n      bandwidth=125000\n      modulation=\"LORA\"\n      spreading_factors=[7, 8, 9, 10, 11, 12]\n"
            )
        })
        .collect();
    format!(
        r#"[[regions]]
  id="eu868"
  description="EU868"
  common_name="EU868"
  [regions.gateway]
    force_gws_private=false
    [regions.gateway.backend]
      enabled="mqtt"
      [regions.gateway.backend.mqtt]
        topic_prefix="eu868"
        server="tcp://{mqtt}"
        qos=0
        clean_session=false
{channels}  [regions.network]
    installation_margin=10
    rx_window=0
    rx1_delay=1
    rx1_dr_offset=0
    rx2_dr=0
    rx2_frequency=869525000
    rx2_prefer_on_rx1_dr_lt=0
    rx2_prefer_on_link_budget=false
    downlink_tx_power=-1
    adr_disabled=true
    min_dr=0
    max_dr=5
    [regions.network.rejoin_request]
      enabled=false
      max_count_n=0
      max_time_n=0
    [regions.network.class_b]
      ping_slot_dr=0
      ping_slot_frequency=0
    [[regions.network.extra_channels]]
      frequency=867100000
      min_dr=0
      max_dr=5
"#
    )
}

fn bridge_toml(mqtt: &str) -> String {
    format!(
        r#"[general]
log_level=4
[backend]
type="semtech_udp"
  [backend.semtech_udp]
  udp_bind="127.0.0.1:{{port}}"
[integration]
marshaler="protobuf"
  [integration.mqtt]
  event_topic_template="eu868/gateway/{{{{ .GatewayID }}}}/event/{{{{ .EventType }}}}"
  state_topic_template="eu868/gateway/{{{{ .GatewayID }}}}/state/{{{{ .StateType }}}}"
  command_topic_template="eu868/gateway/{{{{ .GatewayID }}}}/command/#"
  [integration.mqtt.auth]
  type="generic"
    [integration.mqtt.auth.generic]
    servers=["tcp://{mqtt}"]
"#
    )
}

async fn peer(python: &PathBuf, args: &[&str]) -> Value {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/client/lorawan/chirpstack_peer.py");
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(python)
            .arg("-I")
            .arg(script)
            .args(args)
            .output(),
    )
    .await
    .expect("chirpstack_peer.py deadline")
    .unwrap_or_else(|e| panic!("running {}: {e}; {INSTALL}", python.display()));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "chirpstack_peer.py {args:?}: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(text.trim().lines().last().unwrap_or_default()).unwrap()
}

#[tokio::test]
async fn netget_gateway_against_chirpstack() {
    let chirpstack = env_path("NETGET_CHIRPSTACK");
    let bridge_bin = env_path("NETGET_CHIRPSTACK_GATEWAY_BRIDGE");
    let python = env_path("NETGET_CHIRPSTACK_PYTHON");
    let redis = RealServer::builder("redis-server", REDIS)
        .args([
            "--port", "{port}", "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir",
            "{dir}",
        ])
        .ready_when_log_matches("Ready to accept connections")
        .start()
        .await
        .expect("start redis-server");
    let mosquitto = RealServer::builder("mosquitto", MOSQUITTO)
        .config_file(
            "mosquitto.conf",
            "listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\nlog_dest stderr\nlog_type all\n",
        )
        .args(["-c", "{dir}/mosquitto.conf"])
        .ready_when_log_matches(r"mosquitto version \S+ running")
        .start()
        .await
        .expect("start mosquitto");
    let mqtt = mosquitto.addr();
    let cs = RealServer::builder(chirpstack.to_str().unwrap(), CHIRPSTACK)
        .config_file("chirpstack.toml", &chirpstack_toml("{port}", &redis.addr(), &mqtt))
        .config_file("region_eu868.toml", &region_toml(&mqtt))
        .args(["-c", "{dir}"])
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await
        .expect("start chirpstack");
    let bridge = RealServer::builder(bridge_bin.to_str().unwrap(), CHIRPSTACK)
        .config_file("bridge.toml", &bridge_toml(&mqtt))
        .args(["-c", "{dir}/bridge.toml"])
        .without_tcp_readiness()
        .ready_when_log_matches("connected to mqtt broker")
        .start()
        .await
        .expect("start chirpstack-gateway-bridge");

    // A global API key, then the application, device profile, device and gateway.
    let key_out = tokio::process::Command::new(&chirpstack)
        .args(["-c", cs.dir().to_str().unwrap(), "create-api-key", "--name", "netget"])
        .output()
        .await
        .unwrap();
    let key_text = String::from_utf8_lossy(&key_out.stdout).to_string();
    let token = key_text
        .lines()
        .find_map(|l| l.strip_prefix("token: "))
        .unwrap_or_else(|| panic!("no API token: {key_text}{}", String::from_utf8_lossy(&key_out.stderr)))
        .to_string();
    let api = cs.addr();
    let provisioned = peer(
        &python,
        &["provision", &api, &token, DEV_EUI, APP_KEY, GATEWAY_EUI],
    )
    .await;
    let app_id = provisioned["application_id"].as_str().unwrap().to_string();

    // ChirpStack's application events, as its MQTT integration publishes them.
    let mut sub = tokio::process::Command::new(
        crate::helpers::real_server::find_binary("mosquitto_sub")
            .unwrap_or_else(|| panic!("mosquitto_sub is required: apt-get install mosquitto-clients")),
    )
    .args([
        "-h", "127.0.0.1", "-p", mqtt.rsplit(':').next().unwrap(), "-v", "-t",
        &format!("application/{app_id}/device/{DEV_EUI}/event/#"),
    ])
    .stdout(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    let mut lines = BufReader::new(sub.stdout.take().unwrap()).lines();
    let (event_tx, mut events) = tokio::sync::mpsc::unbounded_channel::<(String, Value)>();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some((topic, body)) = line.split_once(' ') {
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    let _ = event_tx.send((topic.rsplit('/').next().unwrap_or_default().into(), v));
                }
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let devices = json!([{"name": "cs-dev", "dev_eui": DEV_EUI, "app_key": APP_KEY}]);
    let (state, id) = client(
        bridge.addr(),
        vec![
            json!({"event_pattern":"lorawan_gateway_connected","handler":{"type":"static","actions":[{"type":"lorawan_send_join_request","device":"cs-dev"}]}}),
            json!({"event_pattern":"lorawan_join_accepted","handler":{"type":"static","actions":[{"type":"lorawan_send_uplink","device":"cs-dev","f_port":2,"payload":"hello chirpstack"}]}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ],
        json!({"devices": devices, "gateway_eui": GATEWAY_EUI}),
    )
    .await;

    let mut seen: Vec<(String, Value)> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    // The join and the uplink, as ChirpStack saw them.
    let mut up_event: Option<Value> = None;
    let mut join_event: Option<Value> = None;
    while up_event.is_none() {
        let Ok(Some((kind, v))) = tokio::time::timeout_at(deadline, events.recv()).await else {
            panic!(
                "ChirpStack published no uplink. Events: {seen:?}\nNetGet: {:?}\nChirpStack log:\n{}\nBridge log:\n{}",
                client_events(&state, id, "lorawan_join_accepted").await,
                cs.log(),
                bridge.log()
            );
        };
        if kind == "join" {
            join_event = Some(v.clone());
        }
        if kind == "up" {
            up_event = Some(v.clone());
        }
        seen.push((kind, v));
    }
    let join_event = join_event.expect("a join event before the uplink");
    let up = up_event.unwrap();
    let joined = wait_client_events(&state, id, "lorawan_join_accepted", 1, 10).await;
    assert_eq!(
        joined[0]["dev_addr"], join_event["devAddr"],
        "NetGet's DevAddr is the one ChirpStack assigned"
    );
    assert_eq!(joined[0]["net_id"], "000013");
    let data = base64::engine::general_purpose::STANDARD
        .decode(up["data"].as_str().unwrap())
        .unwrap();
    assert_eq!(data, b"hello chirpstack", "ChirpStack decrypted NetGet's FRMPayload: {up}");
    assert_eq!(up["fPort"], 2);
    assert_eq!(up["deviceInfo"]["devEui"], DEV_EUI);
    assert_eq!(up["rxInfo"][0]["gatewayId"], GATEWAY_EUI);

    // A downlink queued in ChirpStack goes out on the device's next uplink.
    peer(&python, &["enqueue", &api, &token, DEV_EUI, "10", &hex::encode(b"from chirpstack")]).await;
    let mut got = None;
    for n in 0..5 {
        let sent = state
            .send_to_client(
                id,
                json!({"type":"lorawan_send_uplink","device":"cs-dev","f_port":2,"payload":format!("tick {n}")}),
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(
            matches!(sent, netget::state::client_handles::ClientSendOutcome::Sent { .. }),
            "{sent:?}"
        );
        let downs = wait_client_events(&state, id, "lorawan_downlink", 1, 4).await;
        if let Some(d) = downs.iter().find(|d| d["payload"] == "from chirpstack") {
            got = Some(d.clone());
            break;
        }
    }
    let Some(down) = got else {
        panic!(
            "no downlink from ChirpStack reached NetGet. NetGet downlinks: {:?}\nChirpStack log:\n{}\nBridge log:\n{}",
            client_events(&state, id, "lorawan_downlink").await,
            cs.log(),
            bridge.log()
        )
    };
    assert_eq!(down["f_port"], 10, "{down}");
    // ChirpStack heard NetGet's TX_ACK for it.
    let txack = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await {
                Some((k, v)) if k == "txack" => return v,
                Some((k, v)) => seen.push((k, v)),
                None => panic!("mosquitto_sub ended"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no txack event. Events: {seen:?}\nBridge log:\n{}", bridge.log()));
    assert_eq!(txack["deviceInfo"]["devEui"], DEV_EUI, "{txack}");
    state.remove_client(id).await;
}

