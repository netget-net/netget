//! NetGet's SNMPv3 manager against **Net-SNMP's `snmpd`**, a third-party agent, run
//! unprivileged on a loopback port in a temp dir of its own with two USM users:
//!
//! - `shaaes` (HMAC-SHA-256, AES-128) with write access, and
//! - `md5des` (HMAC-MD5, DES) with read access.
//!
//! NetGet discovers snmpd's engine at connect, then a static handler GETs sysDescr and
//! sysContact, and a script handler answers that response by SETting sysContact to text built
//! from the sysDescr it received. The SET is then read back with Net-SNMP's own `snmpget`, as
//! the *other* user — so what is asserted is snmpd's state, from snmpd's side, after it
//! accepted an authenticated, encrypted SET NetGet derived from an authenticated, encrypted
//! reply. The same is done with DES. A wrong password reaches the handler as snmpd's own
//! `usmStatsWrongDigests` report, and nothing is set.
//!
//! snmpd and snmpget are required; the test fails rather than skips without them.

use crate::helpers::real_server::{InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const NET_SNMP: InstallHint = InstallHint {
    brew: "net-snmp",
    apt: "snmpd snmp",
};

async fn snmpd() -> RealServer {
    let conf = r#"[snmp] persistentDir {dir}
createUser shaaes SHA-256 "shaaes-auth-pass" AES "shaaes-priv-pass"
createUser md5des MD5 "md5des-auth-pass" DES "md5des-priv-pass"
rwuser shaaes priv
rwuser md5des priv
sysDescr NetGet v3 test agent
sysLocation lab
"#;
    RealServer::builder("snmpd", NET_SNMP)
        .config_file("snmpd.conf", conf)
        .env("MIBS", "")
        .args([
            "-f",
            "-Lo",
            "-C",
            "-c",
            "{dir}/snmpd.conf",
            "-p",
            "{dir}/snmpd.pid",
            "-I",
            "-smux",
            "udp:127.0.0.1:{port}",
        ])
        .without_tcp_readiness()
        .ready_when_log_matches("NET-SNMP version")
        .startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .unwrap_or_else(|e| panic!("snmpd: {e}"))
}

/// What the agent holds, read with Net-SNMP's own manager as `md5des`.
async fn read_back(addr: &str, oid: &str) -> String {
    let persistent = tempfile::tempdir().unwrap();
    let out = tokio::process::Command::new("snmpget")
        .env("MIBS", "")
        .env("SNMP_PERSISTENT_DIR", persistent.path())
        .args([
            "-m",
            "",
            "-On",
            "-Oqv",
            "-v3",
            "-l",
            "authPriv",
            "-u",
            "md5des",
            "-a",
            "MD5",
            "-A",
            "md5des-auth-pass",
            "-x",
            "DES",
            "-X",
            "md5des-priv-pass",
            addr,
            oid,
        ])
        .kill_on_drop(true)
        .output()
        .await
        .expect("snmpget is required (apt install snmp / brew install net-snmp)");
    assert!(
        out.status.success(),
        "snmpget: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .trim_matches('"')
        .to_string()
}

/// GET sysDescr and sysContact on connect; answer the GET's response with a SET of sysContact
/// built from the sysDescr in it; do nothing with the SET's response.
const MANAGER: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
if e.get('request_type')!='GetRequest' or e.get('usm_report'):
  print(json.dumps({'actions':[]})); sys.exit()
v={x['oid']:x['value'] for x in e['variables']}
descr=v.get('1.3.6.1.2.1.1.1.0')
print(json.dumps({'actions':[{'type':'send_snmp_set','variables':[
  {'oid':'1.3.6.1.2.1.1.4.0','type':'string','value':'%s saw: %s' % (TAG, descr)}]}]}))"#;

async fn manager(addr: &str, user: Value, tag: &str) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let code = MANAGER.replace("TAG", &format!("{tag:?}"));
    let id = ClientForm {
        protocol: "snmp".into(),
        remote_addr: Some(addr.into()),
        instruction: Some(String::new()),
        startup_params: Some(json!({"version": "v3", "v3_user": user, "timeout_ms": 2000, "retries": 1})),
        event_handlers: Some(vec![
            json!({"event_pattern":"snmp_connected","handler":{"type":"static","actions":[
                {"type":"send_snmp_get","oids":["1.3.6.1.2.1.1.1.0","1.3.6.1.2.1.1.4.0"]}]}}),
            json!({"event_pattern":"snmp_response_received","handler":{"type":"script","language":"python","code":code}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap_or_else(|e| panic!("the v3 client could not start: {e:#}"));
    (state, id)
}

async fn responses(state: &AppState, id: ClientId, n: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let mut found: Vec<_> = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .into_iter()
                .filter(|e| e.event_type == "snmp_response_received")
                .collect();
            if found.len() >= n {
                found.sort_by_key(|e| e.id);
                break found.into_iter().map(|e| e.request).collect();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("fewer than {n} SNMP responses"))
}

#[tokio::test]
async fn netget_reads_and_sets_through_snmpd_over_v3() {
    let agent = snmpd().await;
    let addr = agent.addr();
    for (user, tag) in [
        (
            json!({"name":"shaaes","auth_protocol":"sha256","auth_password":"shaaes-auth-pass","priv_protocol":"aes","priv_password":"shaaes-priv-pass"}),
            "sha256+aes",
        ),
        (
            json!({"name":"md5des","auth_protocol":"md5","auth_password":"md5des-auth-pass","priv_protocol":"des","priv_password":"md5des-priv-pass"}),
            "md5+des",
        ),
    ] {
        let (state, id) = manager(&addr, user, tag).await;
        let events = responses(&state, id, 2).await;
        let get = &events[0];
        assert_eq!(get["request_type"], "GetRequest", "{get}");
        assert_eq!(get["error_status"], 0);
        assert_eq!(get["variables"][0]["oid"], "1.3.6.1.2.1.1.1.0");
        assert_eq!(get["variables"][0]["value"], "NetGet v3 test agent");
        let set = &events[1];
        assert_eq!(set["request_type"], "SetRequest", "{set}");
        assert_eq!(set["error_status"], 0, "snmpd refused the SET: {set}");
        // The model's answer, as the agent now holds it.
        assert_eq!(
            agent
                .with_log(Ok(read_back(&addr, "1.3.6.1.2.1.1.4.0").await))
                .unwrap(),
            format!("{tag} saw: NetGet v3 test agent")
        );
        for e in &events {
            assert!(!e.to_string().contains("auth-pass") && !e.to_string().contains("priv-pass"));
        }
        state.remove_client(id).await;
    }
}

/// A wrong password is snmpd's own wrongDigests report, handed to the handler as such; the
/// handler's empty answer means no SET, and the agent's sysContact is unchanged.
#[tokio::test]
async fn snmpd_reports_reach_the_handler_and_nothing_is_set() {
    let agent = snmpd().await;
    let addr = agent.addr();
    let before = read_back(&addr, "1.3.6.1.2.1.1.4.0").await;
    let (state, id) = manager(
        &addr,
        json!({"name":"shaaes","auth_protocol":"sha256","auth_password":"not-the-password","priv_protocol":"aes","priv_password":"shaaes-priv-pass"}),
        "wrong",
    )
    .await;
    let report = &responses(&state, id, 1).await[0];
    assert_eq!(
        report["usm_report"]["report"], "usmStatsWrongDigests",
        "{report}"
    );
    assert!(report["variables"].as_array().unwrap().is_empty());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(read_back(&addr, "1.3.6.1.2.1.1.4.0").await, before);
    state.remove_client(id).await;

    // An agent that never answers discovery cannot be talked to: the client refuses to start.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let created = ClientForm {
        protocol: "snmp".into(),
        remote_addr: Some(silent.local_addr().unwrap().to_string()),
        instruction: Some(String::new()),
        startup_params: Some(
            json!({"version": "v3", "v3_user": {"name": "x"}, "timeout_ms": 300, "retries": 0}),
        ),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await;
    let error = match created {
        Err(e) => format!("{e:#}"),
        Ok(id) => tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(c) = state.get_client(id).await {
                    if let netget::state::ClientStatus::Error(e) = c.status {
                        break e;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a v3 client to a silent agent never failed"),
    };
    assert!(error.contains("discovery"), "{error}");
}
