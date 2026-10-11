//! NetGet's MQTT broker speaking **MQTT 5.0** to two independent v5 clients:
//!
//! - **Eclipse Mosquitto's C clients** at `-V 5` (`mosquitto_sub`, `mosquitto_pub`): a
//!   message published with Content Type, Response Topic, Correlation Data, a User Property
//!   and a Message Expiry Interval is forwarded by the handler to a subscriber, and
//!   `mosquitto_sub -F` prints every one of those properties as libmosquitto decoded them. A
//!   CONNACK refused with reason 0x87 and a SUBACK refused with 0x87 are each reported by the
//!   client in its own words.
//! - **Eclipse Paho's Python client** (`paho-mqtt` 2, `MQTTv5`): the broker assigns a client id
//!   (CONNACK Assigned Client Identifier), grants one filter and refuses another in one SUBACK,
//!   answers a request on its Response Topic with binary Correlation Data echoed byte for byte
//!   (the hex path), resolves a Topic Alias, refuses a QoS 1 PUBLISH with PUBACK 0x87, answers
//!   an UNSUBSCRIBE with 0x11, and ends the session with a DISCONNECT carrying 0x98 and a
//!   Reason String — each read back from paho's own callbacks.
//!
//! Neither peer shares code with `src/server/mqtt/`, which encodes every v5 packet by hand.
//! No LLM calls: one Python handler answers every event. Both tests fail rather than skip
//! when a peer is missing — `NETGET_MQTT_PYTHON` comes from `install_v5_peers.py`.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; p=e.get('properties') or {}
a=[]
if t=='mqtt_connect':
  if e.get('username')=='intruder':
    a=[{'type':'mqtt_connack','reason_code':135,'reason_string':'intruders are not welcome'}]
  else:
    a=[{'type':'mqtt_connack','return_code':0,'user_properties':[['broker','netget']]}]
elif t=='mqtt_subscribe':
  codes=[135 if x['filter'].startswith('secret/') else x['qos'] for x in e['topics']]
  s={'type':'mqtt_suback','packet_id':e['packet_id'],'granted_qos':codes}
  if 135 in codes: s['reason_string']='secret is off limits'
  a=[s]
elif t=='mqtt_publish':
  top=e['topic']
  if top.startswith('deny/'):
    a=[{'type':'mqtt_puback','packet_id':e['packet_id'],'reason_code':135,'reason_string':'read only'}]
  elif top=='rpc/req':
    a=[{'type':'mqtt_publish','topic':p['response_topic'],'payload':'pong:'+e['payload'],'correlation_data':p['correlation_data'],'correlation_data_encoding':p['correlation_data_encoding'],'content_type':'text/plain','user_properties':[['echo-of',top]]}]
  elif top=='admin/kick':
    a=[{'type':'close_this_connection','reason_code':152,'reason_string':'kicked by admin'}]
  else:
    f={'type':'mqtt_publish','to_client_id':'v5-sub','topic':top,'payload':e['payload']}
    for k in ('content_type','response_topic','correlation_data','correlation_data_encoding','message_expiry_interval','user_properties'):
      if k in p: f[k]=p[k]
    a=[f]
  if e['qos']==1 and not top.startswith('deny/'): a.append({'type':'mqtt_puback','packet_id':e['packet_id']})
elif t=='mqtt_unsubscribe':
  a=[{'type':'mqtt_unsuback','packet_id':e['packet_id'],'reason_codes':[17]*len(e['topics'])}]
print(json.dumps({'actions':a}))"#;

const PAHO: &str = r#"import json, sys, threading
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.subscribeoptions import SubscribeOptions
port = int(sys.argv[1]); out = {}; done = {k: threading.Event() for k in ('conn','sub','msg','msg2','pub','unsub','disc')}
pubs = {}
def on_connect(c, u, flags, rc, props):
    out['connack'] = {'reason': rc.value, 'assigned': getattr(props, 'AssignedClientIdentifier', None),
        'max_packet': getattr(props, 'MaximumPacketSize', None), 'alias_max': getattr(props, 'TopicAliasMaximum', None),
        'user': getattr(props, 'UserProperty', None)}
    done['conn'].set()
def on_subscribe(c, u, mid, codes, props):
    out['suback'] = {'codes': [r.value for r in codes], 'reason_string': getattr(props, 'ReasonString', None)}
    done['sub'].set()
def on_message(c, u, msg):
    p = msg.properties
    m = {'topic': msg.topic, 'payload': msg.payload.decode(), 'corr': getattr(p, 'CorrelationData', b'').hex(),
         'content_type': getattr(p, 'ContentType', None), 'user': getattr(p, 'UserProperty', None)}
    out.setdefault('messages', []).append(m)
    (done['msg2'] if 'msg' in out else done['msg']).set(); out['msg'] = True
def on_publish(c, u, mid, rc, props):
    pubs[mid] = {'reason': rc.value, 'reason_string': getattr(props, 'ReasonString', None)}
    done['pub'].set()
def on_unsubscribe(c, u, mid, codes, props):
    out['unsuback'] = [r.value for r in codes]; done['unsub'].set()
def on_disconnect(c, u, flags, rc, props):
    out['disconnect'] = {'reason': rc.value, 'reason_string': getattr(props, 'ReasonString', None)}; done['disc'].set()
c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='', protocol=mqtt.MQTTv5)
c.on_connect, c.on_subscribe, c.on_message, c.on_publish = on_connect, on_subscribe, on_message, on_publish
c.on_unsubscribe, c.on_disconnect = on_unsubscribe, on_disconnect
c.connect('127.0.0.1', port, clean_start=True)
c.loop_start()
def wait(k):
    if not done[k].wait(15): raise SystemExit(json.dumps({'timeout': k, 'so_far': out}))
wait('conn')
sp = Properties(PacketTypes.SUBSCRIBE); sp.SubscriptionIdentifier = 7
c.subscribe([('rpc/resp/#', SubscribeOptions(qos=1, noLocal=True, retainHandling=2)), ('secret/x', SubscribeOptions(qos=0))], properties=sp)
wait('sub')
rq = Properties(PacketTypes.PUBLISH); rq.ResponseTopic = 'rpc/resp/9'; rq.CorrelationData = b'\x00\xffID'; rq.TopicAlias = 2
c.publish('rpc/req', 'ping', qos=1, properties=rq)
wait('msg')
rq2 = Properties(PacketTypes.PUBLISH); rq2.ResponseTopic = 'rpc/resp/9'; rq2.CorrelationData = b'second'; rq2.TopicAlias = 2
c.publish('', 'ping2', qos=0, properties=rq2)
wait('msg2')
done['pub'].clear()
info = c.publish('deny/x', 'no', qos=1)
wait('pub')
out['denied'] = pubs.get(info.mid)
c.unsubscribe(['rpc/resp/#'])
wait('unsub')
c.publish('admin/kick', 'bye', qos=0)
wait('disc')
c.loop_stop()
print(json.dumps(out))"#;

fn python() -> String {
    let v = std::env::var("NETGET_MQTT_PYTHON").unwrap_or_default();
    assert!(
        !v.is_empty(),
        "NETGET_MQTT_PYTHON is required (a Python with paho-mqtt 2): \
         python3 tests/server/mqtt/install_v5_peers.py <dir> and export what it prints"
    );
    v
}

async fn require(bin: &str) {
    let ok = Command::new(bin)
        .arg("--help")
        .output()
        .await
        .map(|o| !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false);
    assert!(
        ok,
        "{bin} is required and does not skip: apt-get install mosquitto-clients / brew install mosquitto"
    );
}

async fn broker() -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("MQTT 5 broker".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
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

/// Every event the broker handled, oldest first.
async fn events(state: &AppState, id: ServerId) -> Vec<(String, Value)> {
    let mut rows: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
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

async fn wait_for_event(state: &AppState, id: ServerId, kind: &str, client: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some((_, v)) = events(state, id)
                .await
                .into_iter()
                .find(|(k, v)| k == kind && v["client_id"] == client)
            {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} from {client}"))
}

#[tokio::test]
async fn mosquitto_v5_clients_carry_properties_and_read_reason_codes() {
    require("mosquitto_sub").await;
    require("mosquitto_pub").await;
    let (state, id, port) = broker().await;
    let port_s = port.to_string();

    let mut sub = Command::new("mosquitto_sub")
        .args(["-V", "5", "-h", "127.0.0.1", "-p", &port_s, "-i", "v5-sub"])
        .args(["-t", "news/#", "-C", "1", "-W", "30"])
        .args(["-F", "%t|%p|%C|%R|%D|%P|%E"])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("mosquitto_sub");
    let mut lines = BufReader::new(sub.stdout.take().unwrap()).lines();

    // The subscribe event proves the SUBSCRIBE parsed as v5 (no_local and friends exist only
    // there) before anything is published to it.
    let subscribe = wait_for_event(&state, id, "mqtt_subscribe", "v5-sub").await;
    assert_eq!(subscribe["topics"][0]["filter"], "news/#", "{subscribe}");
    assert_eq!(subscribe["topics"][0]["no_local"], false, "{subscribe}");
    let connect = wait_for_event(&state, id, "mqtt_connect", "v5-sub").await;
    assert_eq!(connect["protocol_level"], 5, "{connect}");
    assert_eq!(connect["protocol_version"], "5.0", "{connect}");
    // Give the SUBACK its moment on the wire: the event is logged as the handler is called.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let published = Command::new("mosquitto_pub")
        .args(["-V", "5", "-h", "127.0.0.1", "-p", &port_s, "-i", "v5-pub"])
        .args(["-t", "news/today", "-m", "hello", "-q", "1"])
        .args(["-D", "publish", "content-type", "text/plain"])
        .args(["-D", "publish", "response-topic", "replies/1"])
        .args(["-D", "publish", "correlation-data", "c-1"])
        .args(["-D", "publish", "user-property", "k", "v"])
        .args(["-D", "publish", "message-expiry-interval", "30"])
        .output()
        .await
        .unwrap();
    assert!(
        published.status.success(),
        "mosquitto_pub -V 5: {}",
        String::from_utf8_lossy(&published.stderr)
    );

    let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .expect("mosquitto_sub printed nothing")
        .unwrap()
        .expect("mosquitto_sub exited without a message");
    assert_eq!(line, "news/today|hello|text/plain|replies/1|c-1|k:v|30");

    // What the handler saw: the properties, decoded.
    let publish = wait_for_event(&state, id, "mqtt_publish", "v5-pub").await;
    assert_eq!(
        publish["properties"],
        json!({
            "content_type": "text/plain",
            "response_topic": "replies/1",
            "correlation_data": "c-1",
            "correlation_data_encoding": "utf8",
            "message_expiry_interval": 30,
            "user_properties": [["k", "v"]],
        }),
        "{publish}"
    );

    // CONNACK 0x87: libmosquitto names the reason itself.
    let refused = Command::new("mosquitto_pub")
        .args([
            "-V",
            "5",
            "-h",
            "127.0.0.1",
            "-p",
            &port_s,
            "-i",
            "v5-intruder",
        ])
        .args(["-u", "intruder", "-P", "x", "-t", "a", "-m", "b"])
        .output()
        .await
        .unwrap();
    let said = String::from_utf8_lossy(&refused.stderr).to_lowercase();
    assert!(
        !refused.status.success(),
        "a refused CONNECT must fail mosquitto_pub"
    );
    assert!(said.contains("not authori"), "{said}");

    // SUBACK 0x87 for the one filter: mosquitto_sub reports the refusal and gives up.
    let denied = Command::new("mosquitto_sub")
        .args([
            "-V",
            "5",
            "-h",
            "127.0.0.1",
            "-p",
            &port_s,
            "-i",
            "v5-denied",
        ])
        .args(["-t", "secret/plans", "-C", "1", "-W", "10"])
        .output()
        .await
        .unwrap();
    let said = String::from_utf8_lossy(&denied.stderr).to_lowercase()
        + &String::from_utf8_lossy(&denied.stdout).to_lowercase();
    assert!(
        said.contains("denied"),
        "mosquitto_sub on a refused filter said: {said}"
    );
}

#[tokio::test]
async fn paho_v5_reads_assigned_ids_reason_codes_correlation_data_and_disconnect() {
    let python = python();
    let (state, id, port) = broker().await;
    let out = tokio::time::timeout(
        Duration::from_secs(90),
        Command::new(python)
            .args(["-c", PAHO, &port.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("paho did not finish")
    .unwrap();
    assert!(
        out.status.success(),
        "paho: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();

    // CONNACK: the broker assigned the id the client left empty, and said what it takes.
    let connack = &r["connack"];
    assert_eq!(connack["reason"], 0, "{r}");
    let assigned = connack["assigned"].as_str().unwrap_or_default();
    assert!(assigned.starts_with("anon-"), "{r}");
    assert_eq!(connack["max_packet"], 256 * 1024, "{r}");
    assert_eq!(connack["alias_max"], 16, "{r}");
    assert_eq!(connack["user"], json!([["broker", "netget"]]), "{r}");
    let connect = wait_for_event(&state, id, "mqtt_connect", assigned).await;
    assert_eq!(connect["assigned_client_id"], true, "{connect}");

    // One SUBACK granting QoS 1 and refusing with 0x87, with its Reason String.
    assert_eq!(r["suback"]["codes"], json!([1, 135]), "{r}");
    assert_eq!(r["suback"]["reason_string"], "secret is off limits", "{r}");
    let subscribe = wait_for_event(&state, id, "mqtt_subscribe", assigned).await;
    assert_eq!(
        subscribe["topics"][0],
        json!({"filter": "rpc/resp/#", "qos": 1, "no_local": true, "retain_as_published": false, "retain_handling": 2}),
        "{subscribe}"
    );
    assert_eq!(
        subscribe["properties"]["subscription_identifiers"],
        json!([7])
    );

    // Request/response: binary correlation data went to the model as hex and came back as the
    // same four bytes; the second request used only the topic alias.
    let messages = r["messages"].as_array().cloned().unwrap_or_default();
    assert_eq!(messages.len(), 2, "{r}");
    assert_eq!(
        messages[0],
        json!({"topic": "rpc/resp/9", "payload": "pong:ping", "corr": "00ff4944",
               "content_type": "text/plain", "user": [["echo-of", "rpc/req"]]}),
        "{r}"
    );
    assert_eq!(
        messages[1]["payload"], "pong:ping2",
        "the alias resolved: {r}"
    );
    assert_eq!(messages[1]["corr"], hex_of(b"second"), "{r}");
    let requests: Vec<Value> = events(&state, id)
        .await
        .into_iter()
        .filter(|(k, v)| k == "mqtt_publish" && v["topic"] == "rpc/req")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(requests[0]["properties"]["correlation_data"], "00ff4944");
    assert_eq!(
        requests[0]["properties"]["correlation_data_encoding"],
        "hex"
    );
    assert_eq!(requests[1]["properties"]["topic_alias"], 2);

    // PUBACK 0x87, UNSUBACK 0x11, DISCONNECT 0x98 — each as paho decoded it.
    assert_eq!(
        r["denied"],
        json!({"reason": 135, "reason_string": "read only"}),
        "{r}"
    );
    assert_eq!(r["unsuback"], json!([17]), "{r}");
    assert_eq!(
        r["disconnect"],
        json!({"reason": 152, "reason_string": "kicked by admin"}),
        "{r}"
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
