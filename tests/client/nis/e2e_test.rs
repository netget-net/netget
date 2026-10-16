//! NetGet's NIS client against NetGet's own NIS server — a regression suite, not evidence
//! (the independent server is `real_server_test.rs`): the handler chain, the entries parsed
//! into fields, the follow-up depth bound, injected actions and their refusals, and finding
//! ypserv through NetGet's portmapper. No LLM calls: python chains play both models.
use super::server_support::{self as server, DOMAIN};
use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='nis_connected' and e['served']:
  a=[{'type':'nis_maplist'}]
elif t=='nis_reply':
  op=e['operation']
  if op=='nis_maplist':
    a=[{'type':'nis_match','map':'passwd.byname','key':'alice'}]
  elif op=='nis_match' and e['ok']:
    a=[{'type':'nis_match','map':'passwd.byname','key':'mallory'}]
  elif op=='nis_match':
    a=[{'type':'nis_cat','map':'group.byname'}]
  elif op=='nis_cat':
    a=[{'type':'nis_master','map':'passwd.byname'}]
  elif op=='nis_master':
    a=[{'type':'nis_order','map':'passwd.byname'}]
  elif op=='nis_order':
    a=[{'type':'nis_first','map':'hosts.byname'}]
  elif op=='nis_first':
    a=[{'type':'nis_next','map':'hosts.byname','key':e['entry']['key']}]
print(json.dumps({'actions':a}))"#;

fn chain(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

async fn client(
    remote: String,
    params: Value,
    handlers: Option<Vec<Value>>,
) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "nis".into(),
        remote_addr: Some(remote),
        instruction: Some("Read the NIS maps".into()),
        startup_params: Some(params),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect");
    (state, id)
}

async fn replies(state: &AppState, id: ClientId) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "nis_reply")
        .map(|e| e["request"].clone())
        .collect()
}

async fn wait_for(state: &AppState, id: ClientId, op: &str, nth: usize) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            // The access log lists newest first; count from the oldest.
            let mut hits: Vec<Value> = replies(state, id)
                .await
                .into_iter()
                .filter(|r| r["operation"] == op)
                .collect();
            hits.reverse();
            if let Some(r) = hits.get(nth) {
                return r.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {op} reply #{nth}"))
}

#[tokio::test]
async fn the_chain_reads_every_kind_of_answer() {
    let s = server::start(server::policy(), None).await;
    let (state, id) = client(
        format!("127.0.0.1:{}", s.port),
        json!({"domain": DOMAIN}),
        chain(CHAIN),
    )
    .await;
    let maps = wait_for(&state, id, "nis_maplist", 0).await;
    assert_eq!(maps["ok"], true, "{maps}");
    assert!(maps["maps"]
        .as_array()
        .unwrap()
        .contains(&json!("netgroup")));
    let alice = wait_for(&state, id, "nis_match", 0).await;
    assert_eq!(
        alice["entry"],
        json!({"key": "alice", "value": "alice:x:1000:1000:Alice Liddell:/home/alice:/bin/bash",
               "fields": {"name": "alice", "password": "x", "uid": 1000, "gid": 1000,
                          "gecos": "Alice Liddell", "home": "/home/alice", "shell": "/bin/bash"}}),
        "{alice}"
    );
    let missing = wait_for(&state, id, "nis_match", 1).await;
    assert_eq!(
        (&missing["ok"], &missing["status"]),
        (&json!(false), &json!("YP_NOKEY"))
    );
    let cat = wait_for(&state, id, "nis_cat", 0).await;
    assert_eq!(cat["ok"], true);
    assert_eq!(
        cat["entries"][0]["fields"],
        json!({"name": "staff", "password": "x", "gid": 100, "members": ["alice", "bob"]})
    );
    assert_eq!(cat["entries"].as_array().unwrap().len(), 2);
    let master = wait_for(&state, id, "nis_master", 0).await;
    assert_eq!(master["master"], "nis-master");
    let order = wait_for(&state, id, "nis_order", 0).await;
    assert_eq!(order["order"], 1_790_000_000u32);
    let first = wait_for(&state, id, "nis_first", 0).await;
    assert_eq!(
        first["entry"]["fields"],
        json!({"address": "10.0.0.1", "names": ["gateway", "gw"]}),
        "the tab between address and names reads as whitespace: {first}"
    );
    let next = wait_for(&state, id, "nis_next", 0).await;
    assert_eq!(next["entry"]["key"], "gw");

    // Injected actions run through the same session; a bad one is refused before sending.
    let send = |action: Value| {
        let state = state.clone();
        async move {
            state
                .send_to_client(id, action, Duration::from_secs(10))
                .await
                .unwrap()
        }
    };
    match send(json!({"type":"nis_match","map":"netgroup","key":"admins"})).await {
        ClientSendOutcome::Executed { detail } => {
            let v: Value = serde_json::from_str(&detail).unwrap();
            assert_eq!(v["entry"]["value"], "(gateway,alice,netget.test) others");
        }
        other => panic!("{other:?}"),
    }
    let bad = send(json!({"type":"nis_cat","map":"../passwd"})).await;
    assert!(
        matches!(&bad, ClientSendOutcome::Rejected { error } if error.contains("map name")),
        "{bad:?}"
    );
    let other =
        send(json!({"type":"nis_match","map":"passwd.byname","key":"alice","domain":"other.test"}))
            .await;
    match other {
        ClientSendOutcome::Executed { detail } => {
            let v: Value = serde_json::from_str(&detail).unwrap();
            assert_eq!(v["status"], "YP_NODOM", "{v}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_handler_chain_stops_at_the_depth_bound() {
    let s = server::start(server::policy(), None).await;
    let forever = r#"import json,sys
print(json.dumps({'actions':[{'type':'nis_order','map':'passwd.byname'}]}))"#;
    let (state, id) = client(
        format!("127.0.0.1:{}", s.port),
        json!({"domain": DOMAIN}),
        chain(forever),
    )
    .await;
    wait_for(
        &state,
        id,
        "nis_order",
        netget::client::nis::MAX_FOLLOWUP_DEPTH - 1,
    )
    .await;
    // Give a runaway chain time to show itself, then count what reached the server.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let asked = server::events(&s.state, s.id, "nis_map_info").await.len();
    assert_eq!(
        asked,
        netget::client::nis::MAX_FOLLOWUP_DEPTH,
        "one call per follow-up, and none past the bound"
    );
}

#[tokio::test]
async fn finds_ypserv_through_a_portmapper_and_refuses_a_bad_domain() {
    let s = server::start(server::policy(), None).await;
    // NetGet's portmapper, answering that ypserv is at the NIS server's port.
    let pm_state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    pm_state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let mapping = json!({"type":"sunrpc_mappings","mappings":[
        {"program":100004,"version":2,"protocol":"tcp","port":s.port},
        {"program":100004,"version":2,"protocol":"udp","port":s.port}]});
    let pm = ServerForm {
        protocol: "sunrpc".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a portmapper".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"static","actions":[mapping]}}),
        ]),
        ..Default::default()
    }
    .create(&pm_state, tx)
    .await
    .unwrap();
    let pm_port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = pm_state.get_server(pm).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (state, id) = client(
        format!("127.0.0.1:{pm_port}"),
        json!({"domain": "other.test", "use_portmapper": true}),
        Some(vec![
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ]),
    )
    .await;
    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(e) = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == "nis_connected")
            {
                return e["request"].clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        connected["remote_addr"],
        format!("127.0.0.1:{}", s.port),
        "{connected}"
    );
    assert_eq!(connected["portmapper"], format!("127.0.0.1:{pm_port}"));
    assert_eq!(
        connected["served"], false,
        "the server does not serve other.test"
    );
}
