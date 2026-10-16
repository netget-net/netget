//! NetGet's NIS client against **Linux ypserv 4.2** (an independent C server), serving maps
//! built by its own **makedbm** in a temporary domain and registered with the system
//! **rpcbind**. NetGet finds it through rpcbind (PMAP GETPORT), binds with DOMAIN and walks a
//! python chain through MAPLIST, MATCH, ALL, MASTER, ORDER, FIRST, NEXT and a missing key;
//! every answer is checked against what makedbm stored. A second client reaches ypserv through
//! a recording relay, and tshark's rpc/ypserv dissectors read both directions.
//!
//! ypserv reads maps only from /var/yp/<domain>, so the domain directory is created and
//! removed as root, and ypserv runs as root (`sudo -n`); `ypserv -d` logs each procedure,
//! which is how the test sees the model's actions arrive at the server. Needs root or
//! passwordless sudo, rpcbind running, and the ypserv package (ypserv, makedbm). Fails rather
//! than skips without them. Holds the lock the server suite's yp-tools test takes, since both
//! register program 100004. No LLM calls: python chains play the model.
use super::server_support::linux;
use crate::helpers::netns::privileged;
use crate::helpers::real_server::ToolProcess;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const DOMAIN: &str = "netget-client.test";
const MASTER: &str = "ypmaster.netget";
const PASSWD: &[(&str, &str)] = &[
    ("carol", "carol:x:2000:2000:Carol:/home/carol:/bin/zsh"),
    ("dave", "dave:*:2001:2000::/home/dave:/usr/sbin/nologin"),
];
const GROUP: &[(&str, &str)] = &[("devs", "devs:x:2000:carol,dave")];

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='nis_connected' and e['served']:
  a=[{'type':'nis_maplist'}]
elif t=='nis_reply':
  op=e['operation']
  if op=='nis_maplist':
    a=[{'type':'nis_match','map':'passwd.byname','key':'carol'}]
  elif op=='nis_match' and e['ok']:
    a=[{'type':'nis_cat','map':'passwd.byname'}]
  elif op=='nis_cat':
    a=[{'type':'nis_master','map':'passwd.byname'}]
  elif op=='nis_master':
    a=[{'type':'nis_order','map':'passwd.byname'}]
  elif op=='nis_order':
    a=[{'type':'nis_first','map':'group.byname'}]
  elif op=='nis_first':
    a=[{'type':'nis_next','map':'group.byname','key':e['entry']['key']}]
  elif op=='nis_next':
    a=[{'type':'nis_match','map':'passwd.byname','key':'mallory'}]
print(json.dumps({'actions':a}))"#;

/// The domain directory and the ypserv process, removed and killed as root on drop.
struct Ypserv {
    port: u16,
    process: Option<ToolProcess>,
}

impl Drop for Ypserv {
    fn drop(&mut self) {
        let _ = privileged("pkill")
            .args(["-f", &format!("ypserv -d -p {}", self.port)])
            .output();
        self.process.take();
        let _ = privileged("rm")
            .args(["-rf", &format!("/var/yp/{DOMAIN}")])
            .output();
        linux::clear_ypserv_registrations();
    }
}

fn makedbm() -> String {
    for p in ["/usr/lib/yp/makedbm", "/usr/lib64/yp/makedbm"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    panic!(
        "{}",
        crate::helpers::real_server::missing_binary("makedbm", linux::YPSERV, "not found")
    )
}

/// Build `map` from `entries` with makedbm, as root, into /var/yp/<domain>. Returns the
/// YP_LAST_MODIFIED makedbm wrote, which ypserv answers ORDER with.
fn build_map(map: &str, entries: &[(&str, &str)]) -> u32 {
    let input = tempfile::NamedTempFile::new().unwrap();
    let text: String = entries.iter().map(|(k, v)| format!("{k}\t{v}\n")).collect();
    std::fs::write(input.path(), text).unwrap();
    let mut c = privileged(&makedbm());
    c.args([
        "-m",
        MASTER,
        &input.path().to_string_lossy(),
        &format!("/var/yp/{DOMAIN}/{map}"),
    ]);
    let (ok, text) = linux::run(c, "makedbm", linux::YPSERV);
    assert!(ok, "makedbm: {text}");
    let mut dump = privileged(&makedbm());
    dump.args(["-u", &format!("/var/yp/{DOMAIN}/{map}")]);
    let (ok, text) = linux::run(dump, "makedbm", linux::YPSERV);
    assert!(ok, "makedbm -u: {text}");
    text.lines()
        .find_map(|l| l.strip_prefix("YP_LAST_MODIFIED"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no YP_LAST_MODIFIED in {text}"))
}

async fn start_ypserv() -> (Ypserv, u32) {
    linux::clear_ypserv_registrations();
    let mkdir = {
        let mut c = privileged("mkdir");
        c.args(["-p", &format!("/var/yp/{DOMAIN}")]);
        c
    };
    let (ok, text) = linux::run(mkdir, "mkdir", linux::YPSERV);
    assert!(ok, "{text}");
    let order = build_map("passwd.byname", PASSWD);
    build_map("group.byname", GROUP);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut c = privileged("ypserv");
    c.args(["-d", "-p", &port.to_string()]);
    let server = Ypserv {
        port,
        process: Some(ToolProcess::spawn(c, "ypserv", linux::YPSERV).expect("ypserv starts")),
    };
    // Ready once rpcbind knows it.
    let ready = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let (_, text) = linux::rpcinfo(&["-p", "127.0.0.1"]).await;
            if linux::ypserv_rows(&text)
                .iter()
                .any(|(v, n, p)| v == "2" && n == "tcp" && *p == port.to_string())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if ready.is_err() {
        let lines = server.process.as_ref().map(|p| p.lines()).unwrap_or_default();
        panic!("ypserv never registered with rpcbind: {lines:?}");
    }
    (server, order)
}

async fn client(remote: String, params: Value, code: &str) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "nis".into(),
        remote_addr: Some(remote),
        instruction: Some("Read the NIS maps".into()),
        startup_params: Some(params),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"script",
            "language":"python","code":code}})]),
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

async fn reply(state: &AppState, id: ClientId, op: &str, nth: usize) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hits: Vec<Value> = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .filter(|e| e["event_type"] == "nis_reply" && e["request"]["operation"] == op)
                .map(|e| e["request"].clone())
                .collect();
            // The access log lists newest first.
            if hits.len() > nth {
                return hits[hits.len() - 1 - nth].clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {op} reply #{nth}"))
}

#[tokio::test]
async fn netget_reads_ypserv_maps_through_rpcbind() {
    let _lock = linux::lock_program();
    linux::require_rpcbind();
    let (ypserv, order) = start_ypserv().await;

    let (state, id) = client("127.0.0.1:111".into(), json!({"domain": DOMAIN}), CHAIN).await;
    let maps = reply(&state, id, "nis_maplist", 0).await;
    let mut names: Vec<&str> = maps["maps"]
        .as_array()
        .unwrap_or_else(|| panic!("{maps}"))
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["group.byname", "passwd.byname"], "{maps}");
    let carol = reply(&state, id, "nis_match", 0).await;
    assert_eq!(carol["ok"], true, "{carol}");
    assert_eq!(carol["entry"]["value"], PASSWD[0].1);
    assert_eq!(
        carol["entry"]["fields"],
        json!({"name": "carol", "password": "x", "uid": 2000, "gid": 2000, "gecos": "Carol",
               "home": "/home/carol", "shell": "/bin/zsh"})
    );
    let cat = reply(&state, id, "nis_cat", 0).await;
    assert_eq!(cat["ok"], true, "{cat}");
    let mut got: Vec<(String, String)> = cat["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["key"].as_str().unwrap().to_string(),
                e["value"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    got.sort();
    let want: Vec<(String, String)> = PASSWD
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(got, want, "ypserv's ALL, without its YP_* keys: {cat}");
    let master = reply(&state, id, "nis_master", 0).await;
    assert_eq!(master["master"], MASTER, "{master}");
    let ord = reply(&state, id, "nis_order", 0).await;
    assert_eq!(ord["order"], order, "makedbm's YP_LAST_MODIFIED: {ord}");
    let first = reply(&state, id, "nis_first", 0).await;
    assert_eq!(first["entry"]["value"], GROUP[0].1, "{first}");
    assert_eq!(
        first["entry"]["fields"]["members"],
        json!(["carol", "dave"])
    );
    let next = reply(&state, id, "nis_next", 0).await;
    assert_eq!(
        next["status"], "YP_NOMORE",
        "group.byname has one entry: {next}"
    );
    let missing = reply(&state, id, "nis_match", 1).await;
    assert_eq!(missing["status"], "YP_NOKEY", "{missing}");

    // ypserv's own log saw each call the model's answers made.
    let lines = ypserv.process.as_ref().unwrap().lines().join("\n");
    for proc_ in [
        "maplist", "match", "all", "master", "order", "first", "next",
    ] {
        assert!(
            lines.to_lowercase().contains(&format!("ypproc_{proc_}")),
            "ypserv -d logged no {proc_}: {lines}"
        );
    }

    // A second client straight at ypserv through a recording relay, for the pcap oracle.
    let upstream: std::net::SocketAddr = format!("127.0.0.1:{}", ypserv.port).parse().unwrap();
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(upstream).await;
    let quick = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='nis_connected':
  a=[{'type':'nis_match','map':'passwd.byname','key':'dave'}]
elif t=='nis_reply' and e['operation']=='nis_match':
  a=[{'type':'nis_cat','map':'group.byname'}]
print(json.dumps({'actions':a}))"#;
    let (state2, id2) = client(
        relay.to_string(),
        json!({"domain": DOMAIN, "use_portmapper": false}),
        quick,
    )
    .await;
    let cat = reply(&state2, id2, "nis_cat", 0).await;
    assert_eq!(cat["entries"][0]["value"], GROUP[0].1, "{cat}");
    let recorded = streams.lock().unwrap().clone();
    let chunks = recorded[0].lock().unwrap().clone();
    let oracle = || {
        chunks.iter().fold(
            crate::helpers::pcap_oracle::PcapOracle::tcp("nis")
                .port(relay.port())
                .also_named("ypserv"),
            |o, (to_server, b)| {
                if *to_server {
                    o.to_server(b)
                } else {
                    o.from_server(b)
                }
            },
        )
    };
    oracle().assert_clean();
    let rows = oracle()
        .fields(&[
            "ypserv.procedure_v2",
            "ypserv.domain",
            "ypserv.map",
            "ypserv.key",
        ])
        .unwrap();
    let flat = format!("{rows:?}");
    assert!(
        flat.contains(DOMAIN) && flat.contains("dave") && flat.contains("group.byname"),
        "tshark read NetGet's calls: {flat}"
    );
}
