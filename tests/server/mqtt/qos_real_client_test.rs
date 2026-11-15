//! The MQTT 3.1.1 verbs the other real-client tests leave out, driven by two independent
//! clients through `recording_relay`, with the pcap oracle reading every session:
//!
//! - **Eclipse Mosquitto's C clients** (`mosquitto_pub`, `mosquitto_sub`): a subscriber at QoS 2
//!   with a five-second Keep Alive (libmosquitto's minimum); a QoS 1 and a QoS 2 PUBLISH (PUBACK; PUBREC → PUBREL →
//!   PUBCOMP) forwarded by the handler to the subscriber at the same QoS (the broker's QoS 2
//!   PUBLISH needs the broker's PUBREL before libmosquitto hands it over); PINGREQ; and an
//!   UNSUBSCRIBE (`-U`).
//! - **rumqttc** 0.24 (Rust, its own codec): the same, plus a DISCONNECT, read back from its
//!   event loop — SUBACK, PUBACK, PUBCOMP, both forwarded messages at their QoS, UNSUBACK and
//!   PINGRESP.
//!
//! Neither shares code with `src/server/mqtt/`, which frames every packet by hand. No LLM
//! calls: one Python handler answers every event. The mosquitto test fails rather than skips
//! when the clients are missing (`brew install mosquitto`, `apt-get install mosquitto-clients`).
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;

/// Forwards every PUBLISH to the client `qsub` (renamed per test by [`broker`]), at the QoS it
/// arrived with, under `fwd/`. The two tests use different subscriber ids because the broker's
/// client directory is process-wide and keyed by server id, which each test's `AppState`
/// numbers from 1.
const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='mqtt_connect':
  a=[{'type':'mqtt_connack','return_code':0}]
elif t=='mqtt_subscribe':
  a=[{'type':'mqtt_suback','packet_id':e['packet_id'],'granted_qos':[x['qos'] for x in e['topics']]}]
elif t=='mqtt_unsubscribe':
  a=[{'type':'mqtt_unsuback','packet_id':e['packet_id']}]
elif t=='mqtt_publish':
  q=e['qos']
  a=[{'type':'mqtt_publish','to_client_id':'qsub','topic':'fwd/'+e['topic'],'payload':e['payload'],'qos':q,'packet_id':40+q}]
  if q==1: a.append({'type':'mqtt_puback','packet_id':e['packet_id']})
  if q==2: a.append({'type':'mqtt_pubrec','packet_id':e['packet_id']})
print(json.dumps({'actions':a}))"#;

async fn broker(subscriber: &str) -> (AppState, ServerId, u16) {
    let handler = HANDLER.replace("'qsub'", &format!("'{subscriber}'"));
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":handler}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the MQTT broker never bound");
    (state, id, port)
}

async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

async fn wait_for(state: &AppState, id: ServerId, event_type: &str, n: usize) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while events(state, id, event_type).await.len() < n {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the broker never saw {n} {event_type}"));
}

type Streams = std::sync::Arc<std::sync::Mutex<Vec<crate::helpers::recording_relay::Recording>>>;

/// Wait until some recorded stream carried `needle` towards the broker.
async fn wait_for_bytes(streams: &Streams, needle: &[u8]) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let seen = crate::helpers::recording_relay::recorded(streams)
                .iter()
                .any(|s| {
                    s.iter().any(|(to_server, b)| {
                        *to_server && b.windows(needle.len()).any(|w| w == needle)
                    })
                });
            if seen {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no client sent {needle:02x?}"));
}

/// Every recorded session through Wireshark's `mqtt` dissector.
fn oracle(streams: &Streams) {
    use crate::helpers::pcap_oracle::PcapOracle;
    let sessions = crate::helpers::recording_relay::recorded(streams);
    assert!(!sessions.is_empty());
    for session in &sessions {
        crate::helpers::recording_relay::replay(
            PcapOracle::tcp("mqtt").require_named("mqtt"),
            session,
        )
        .assert_clean();
    }
}

fn mosquitto(bin: &str) -> Command {
    let mut c = Command::new(bin);
    c.kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

#[tokio::test]
async fn mosquitto_drives_qos_1_and_2_both_ways_pings_and_unsubscribes() {
    let (state, id, port) = broker("qsub-mosquitto").await;
    let (relay, streams) =
        crate::helpers::recording_relay::tcp_relay(format!("127.0.0.1:{port}").parse().unwrap())
            .await;
    let p = relay.port().to_string();
    let sub = mosquitto("mosquitto_sub")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &p,
            "-V",
            "mqttv311",
            "-i",
            "qsub-mosquitto",
            "-q",
            "2",
            "-k",
            "5",
            "-t",
            "fwd/#",
            "-C",
            "2",
            "-v",
        ])
        .spawn()
        .expect(
            "mosquitto_sub is required and is not installed: brew install mosquitto / apt-get \
             install mosquitto-clients — this test fails rather than skips without it",
        );
    wait_for(&state, id, "mqtt_subscribe", 1).await;
    // The subscriber's five-second Keep Alive: a PINGREQ crosses before anything is published.
    wait_for_bytes(&streams, &[0xC0, 0x00]).await;

    for (qos, topic, msg) in [("1", "q/one", "one"), ("2", "q/two", "two")] {
        let out = mosquitto("mosquitto_pub")
            .args([
                "-h",
                "127.0.0.1",
                "-p",
                &p,
                "-V",
                "mqttv311",
                "-i",
                &format!("qpub{qos}"),
                "-q",
                qos,
                "-t",
                topic,
                "-m",
                msg,
            ])
            .output()
            .await
            .expect("mosquitto_pub");
        assert!(
            out.status.success(),
            "mosquitto_pub -q {qos} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let Ok(out) = tokio::time::timeout(Duration::from_secs(60), sub.wait_with_output()).await
    else {
        let sessions = crate::helpers::recording_relay::recorded(&streams);
        panic!(
            "mosquitto_sub did not receive both forwarded messages; what crossed:\n{}",
            sessions
                .iter()
                .map(|s| s
                    .iter()
                    .map(|(up, b)| format!("{} {:02x?}", if *up { ">" } else { "<" }, b))
                    .collect::<Vec<_>>()
                    .join("\n"))
                .collect::<Vec<_>>()
                .join("\n--\n")
        );
    };
    let out = out.unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("fwd/q/one one"), "{text}");
    assert!(text.contains("fwd/q/two two"), "{text}");

    let publishes = events(&state, id, "mqtt_publish").await;
    let mut qos: Vec<u64> = publishes.iter().filter_map(|e| e["qos"].as_u64()).collect();
    qos.sort();
    assert_eq!(qos, vec![1, 2], "{publishes:#?}");

    // UNSUBSCRIBE: -U on a fresh client, which exits once its subscription is acknowledged.
    let out = mosquitto("mosquitto_sub")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &p,
            "-V",
            "mqttv311",
            "-i",
            "qunsub",
            "-t",
            "x/y",
            "-U",
            "x/y",
            "-E",
        ])
        .output()
        .await
        .expect("mosquitto_sub -U");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    wait_for(&state, id, "mqtt_unsubscribe", 1).await;
    let unsub = events(&state, id, "mqtt_unsubscribe").await;
    assert_eq!(unsub[0]["topics"], json!(["x/y"]), "{unsub:#?}");

    // What crossed: the subscriber's PUBREC and PUBCOMP for the broker's QoS 2 PUBLISH, and
    // the publisher's PUBREL for its own.
    wait_for_bytes(&streams, &[0x50, 0x02, 0x00, 42]).await; // PUBREC id 42
    wait_for_bytes(&streams, &[0x70, 0x02, 0x00, 42]).await; // PUBCOMP id 42
    wait_for_bytes(&streams, &[0x62, 0x02]).await; // PUBREL
    oracle(&streams);
}

#[tokio::test]
async fn rumqttc_drives_qos_1_and_2_both_ways_pings_unsubscribes_and_disconnects() {
    use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
    let (state, id, port) = broker("qsub-rumqttc").await;
    let (relay, streams) =
        crate::helpers::recording_relay::tcp_relay(format!("127.0.0.1:{port}").parse().unwrap())
            .await;
    let mut opts = MqttOptions::new("qsub-rumqttc", "127.0.0.1", relay.port());
    opts.set_keep_alive(Duration::from_secs(1));
    let (client, mut eventloop) = AsyncClient::new(opts, 16);

    let seen = tokio::spawn(async move {
        let mut seen: Vec<String> = Vec::new();
        let mut messages = 0;
        loop {
            match tokio::time::timeout(Duration::from_secs(20), eventloop.poll()).await {
                Ok(Ok(Event::Incoming(p))) => {
                    let name = match &p {
                        Packet::Publish(m) => {
                            messages += 1;
                            format!(
                                "publish {} {} {:?}",
                                m.topic,
                                String::from_utf8_lossy(&m.payload),
                                m.qos
                            )
                        }
                        other => format!("{other:?}")
                            .split(['(', ' '])
                            .next()
                            .unwrap_or("")
                            .to_string(),
                    };
                    seen.push(name);
                }
                Ok(Ok(Event::Outgoing(rumqttc::Outgoing::Disconnect))) => {
                    seen.push("sent Disconnect".into());
                    return seen;
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    seen.push(format!("error {e}"));
                    return seen;
                }
                Err(_) => {
                    seen.push(format!("stalled after {messages} messages"));
                    return seen;
                }
            }
        }
    });

    client.subscribe("fwd/#", QoS::ExactlyOnce).await.unwrap();
    wait_for(&state, id, "mqtt_subscribe", 1).await;
    client
        .publish("q/one", QoS::AtLeastOnce, false, "one")
        .await
        .unwrap();
    client
        .publish("q/two", QoS::ExactlyOnce, false, "two")
        .await
        .unwrap();
    wait_for(&state, id, "mqtt_publish", 2).await;
    // The one-second Keep Alive: a PINGREQ crosses.
    wait_for_bytes(&streams, &[0xC0, 0x00]).await;
    client.unsubscribe("fwd/#").await.unwrap();
    wait_for(&state, id, "mqtt_unsubscribe", 1).await;
    // Let the UNSUBACK and the last acknowledgements arrive before disconnecting.
    wait_for_bytes(&streams, &[0x70, 0x02, 0x00, 42]).await; // the client's PUBCOMP for id 42
    client.disconnect().await.unwrap();
    let seen = seen.await.unwrap();

    for want in [
        "ConnAck",
        "SubAck",
        "PubAck",
        "PubRec",
        "PubComp",
        "publish fwd/q/one one AtLeastOnce",
        "publish fwd/q/two two ExactlyOnce",
        "PubRel",
        "UnsubAck",
        "PingResp",
        "sent Disconnect",
    ] {
        assert!(
            seen.iter().any(|s| s == want),
            "{want} missing from {seen:#?}"
        );
    }
    oracle(&streams);
}
