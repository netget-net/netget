//! NetGet's MQTT client speaking **MQTT 5.0** (`protocol_version` "5.0", rumqttc's v5 stack)
//! to **Eclipse Mosquitto** 2, with Mosquitto's own v5 command-line clients on the far side.
//!
//! What the handler does, and how each part is read back from outside NetGet:
//!
//! 1. On `mqtt_connected` — whose event must say `protocol_version` 5.0 and CONNACK reason 0 —
//!    it subscribes to `v5/rpc/req` and `v5/out/#` with **No Local**, and publishes a status
//!    message with a Content Type and a User Property. `mosquitto_sub -V 5 -F` prints both
//!    properties as libmosquitto decoded them.
//! 2. `mosquitto_pub -V 5` sends a request with a Response Topic and Correlation Data. The
//!    message event carries both; the handler publishes the answer to that Response Topic with
//!    the Correlation Data echoed, and `mosquitto_sub` prints it.
//! 3. NetGet is subscribed to `v5/out/#`, where it publishes itself. With No Local honoured on
//!    the wire, Mosquitto never delivers those back — so no message event for `v5/out/…`
//!    exists. Without it, both of NetGet's own publishes would come back as events.
//!
//! No LLM calls: a Python handler is the model. Fails rather than skips when Mosquitto is
//! absent.
use crate::helpers::real_server::{InstallHint, RealServer, ToolProcess};
use crate::helpers::E2EResult;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;
use tokio::sync::mpsc;

const MOSQUITTO: InstallHint = InstallHint {
    brew: "mosquitto",
    apt: "mosquitto",
};
const MOSQUITTO_CLIENTS: InstallHint = InstallHint {
    brew: "mosquitto",
    apt: "mosquitto-clients",
};

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='mqtt_connected':
  a=[{'type':'subscribe','topics':['v5/rpc/req','v5/out/#'],'qos':1,'no_local':True},
     {'type':'publish','topic':'v5/out/status','payload':'up','qos':1,
      'properties':{'content_type':'text/plain','user_properties':[['proto',e['protocol_version']]]}}]
elif t=='mqtt_message_received':
  p=e.get('properties') or {}
  if 'response_topic' in p:
    a=[{'type':'publish','topic':p['response_topic'],'payload':'pong:'+e['payload'],'qos':1,
        'properties':{'correlation_data':p['correlation_data'],'correlation_data_encoding':p['correlation_data_encoding'],'content_type':'text/plain'}}]
print(json.dumps({'actions':a}))"#;

async fn start_mosquitto() -> E2EResult<RealServer> {
    RealServer::builder("mosquitto", MOSQUITTO)
        .config_file(
            "mosquitto.conf",
            "listener {port} 127.0.0.1\n\
             allow_anonymous true\n\
             persistence false\n\
             log_dest stderr\n\
             log_type all\n\
             connection_messages true\n",
        )
        .args(["-c", "{dir}/mosquitto.conf"])
        .ready_when_log_matches(r"mosquitto version \S+ running")
        .start()
        .await
}

async fn events(state: &AppState, id: ClientId) -> Vec<(String, Value)> {
    let mut rows: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    rows.sort_by_key(|e| e["id"].as_u64());
    rows.into_iter()
        .map(|e| {
            (
                e["event_type"].as_str().unwrap_or_default().to_string(),
                e["request"].clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn mqtt_v5_client_carries_properties_and_answers_a_request_through_mosquitto() -> E2EResult<()>
{
    let broker = start_mosquitto().await?;
    let result = exchange(&broker).await;
    broker.with_log(result)
}

async fn exchange(broker: &RealServer) -> E2EResult<()> {
    let port = broker.port.to_string();
    let mut cmd = Command::new("mosquitto_sub");
    cmd.args(["-V", "5", "-h", "127.0.0.1", "-p", &port, "-i", "v5-watch"])
        .args(["-t", "v5/out/#", "-q", "1", "-C", "2"])
        .args(["-F", "%t|%p|%C|%D|%P"]);
    let sub = ToolProcess::spawn(cmd, "mosquitto_sub", MOSQUITTO_CLIENTS)?;
    broker
        .wait_for_log("Sending SUBACK to v5-watch", Duration::from_secs(20))
        .await?;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "mqtt".into(),
        remote_addr: Some(broker.addr()),
        instruction: Some("Answer requests".into()),
        startup_params: Some(json!({"protocol_version": "5.0", "client_id": "netget-v5"})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()), tx)
    .await
    .map_err(|e| format!("connect: {e}"))?;

    // 1. The status publish, with its properties, as libmosquitto printed them.
    sub.wait_for_line("NetGet's status", Duration::from_secs(30), |l| {
        l == "v5/out/status|up|text/plain||proto:5.0"
    })
    .await?;
    assert!(
        broker.log().contains("Received SUBSCRIBE from netget-v5"),
        "Mosquitto never logged NetGet's v5 SUBSCRIBE"
    );

    // 2. A request with a Response Topic and Correlation Data; NetGet answers on that topic.
    let mut cmd = Command::new("mosquitto_pub");
    cmd.args([
        "-V",
        "5",
        "-h",
        "127.0.0.1",
        "-p",
        &port,
        "-i",
        "v5-requester",
    ])
    .args(["-t", "v5/rpc/req", "-m", "ping", "-q", "1"])
    .args(["-D", "publish", "response-topic", "v5/out/reply"])
    .args(["-D", "publish", "correlation-data", "corr-42"]);
    crate::helpers::real_server::run_tool(cmd, "mosquitto_pub", MOSQUITTO_CLIENTS).await?;
    sub.wait_for_line("NetGet's answer", Duration::from_secs(30), |l| {
        l == "v5/out/reply|pong:ping|text/plain|corr-42|"
    })
    .await?;

    let all = events(&state, id).await;
    let connected = all
        .iter()
        .find(|(k, _)| k == "mqtt_connected")
        .map(|(_, v)| v.clone())
        .ok_or("no mqtt_connected event")?;
    assert_eq!(connected["protocol_version"], "5.0", "{connected}");
    assert_eq!(connected["reason_code"], 0, "{connected}");
    let received: Vec<&Value> = all
        .iter()
        .filter(|(k, _)| k == "mqtt_message_received")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(received.len(), 1, "only the request comes back: {all:?}");
    assert_eq!(received[0]["topic"], "v5/rpc/req");
    assert_eq!(received[0]["properties"]["response_topic"], "v5/out/reply");
    assert_eq!(received[0]["properties"]["correlation_data"], "corr-42");

    // 3. No Local: NetGet's own two publishes to v5/out/# never came back. Give a stray
    // delivery time to arrive before concluding it did not.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let echoed: Vec<(String, Value)> = events(&state, id)
        .await
        .into_iter()
        .filter(|(k, v)| {
            k == "mqtt_message_received" && v["topic"].as_str().unwrap_or("").starts_with("v5/out/")
        })
        .collect();
    assert!(
        echoed.is_empty(),
        "No Local was not honoured, so NetGet heard itself: {echoed:?}"
    );
    Ok(())
}
