//! SNMP notifications against **Net-SNMP**, both ways.
//!
//! - NetGet as the manager: `snmptrap` sends it a v2c trap and a v1 trap, and `snmpinform` an
//!   inform. Each arrives as one `snmp_notification` event with its fields and typed bindings;
//!   the inform is acknowledged (snmpinform exits 0) when the handler accepts it and is not
//!   (snmpinform times out) when the handler ignores it.
//! - NetGet as the agent: asked a GET by `snmpget`, the handler answers and sends a v2c trap,
//!   a v2c inform and a v1 trap to `snmptrapd`, which prints each with its bindings; the inform
//!   comes back acknowledged.
//!
//! Net-SNMP's tools (`snmp` and `snmptrapd` packages) are required; the tests fail rather than
//! skip without them. MIB loading is switched off (`-m ''`) so everything is numeric. No LLM
//! calls: a python handler answers every event.

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

fn require(binary: &str) {
    let ok = std::process::Command::new(binary)
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success() || !o.stderr.is_empty());
    assert!(
        ok,
        "{binary} is required: apt install snmp snmptrapd / brew install net-snmp"
    );
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn snmp_server(handler: &str) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "snmp".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Manage notifications".into()),
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
    .expect("the SNMP server never bound");
    (state, id, port)
}

async fn events(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect()
}

async fn wait_for(
    state: &AppState,
    id: ServerId,
    kind: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(e) = events(state, id, kind).await.into_iter().find(|e| pred(e)) {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no matching {kind}"))
}

async fn net_snmp(binary: &str, args: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(binary)
            .env("MIBS", "")
            .args(["-m", ""])
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{binary} did not finish"))
    .unwrap()
}

/// Accept every notification except one sent with community `deny`.
const MANAGER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='snmp_notification':
  a=[{'type':'ignore_notification'}] if e['community']=='deny' else [{'type':'acknowledge_notification'}]
else:
  a=[{'type':'ignore_request'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn netget_receives_traps_and_informs_from_net_snmp() {
    require("snmptrap");
    let (state, id, port) = snmp_server(MANAGER).await;
    let target = format!("127.0.0.1:{port}");

    let out = net_snmp(
        "snmptrap",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            &target,
            "",
            "1.3.6.1.6.3.1.1.5.3",
            "1.3.6.1.2.1.2.2.1.1.2",
            "i",
            "2",
            "1.3.6.1.2.1.2.2.1.2.2",
            "s",
            "eth1",
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let trap = wait_for(&state, id, "snmp_notification", |e| {
        e["request"]["version"] == "v2c"
    })
    .await;
    let n = &trap["request"];
    assert_eq!(n["kind"], "trap", "{n}");
    assert_eq!(n["community"], "public", "{n}");
    assert_eq!(n["trap_oid"], "1.3.6.1.6.3.1.1.5.3", "{n}");
    assert!(n["uptime"].as_u64().is_some(), "{n}");
    assert_eq!(n["client_ip"], "127.0.0.1", "{n}");
    assert_eq!(
        n["variables"],
        json!([
            {"oid": "1.3.6.1.2.1.2.2.1.1.2", "type": "integer", "value": 2},
            {"oid": "1.3.6.1.2.1.2.2.1.2.2", "type": "string", "value": "eth1"},
        ]),
        "{n}"
    );

    let out = net_snmp(
        "snmptrap",
        &[
            "-v",
            "1",
            "-c",
            "public",
            &target,
            "1.3.6.1.4.1.8072.2.3",
            "192.0.2.7",
            "6",
            "17",
            "",
            "1.3.6.1.4.1.8072.2.3.2.1",
            "i",
            "42",
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let trap = wait_for(&state, id, "snmp_notification", |e| {
        e["request"]["version"] == "v1"
    })
    .await;
    let n = &trap["request"];
    assert_eq!(n["kind"], "trap", "{n}");
    assert_eq!(n["enterprise"], "1.3.6.1.4.1.8072.2.3", "{n}");
    assert_eq!(n["agent_addr"], "192.0.2.7", "{n}");
    assert_eq!(n["generic_trap"], 6, "{n}");
    assert_eq!(n["specific_trap"], 17, "{n}");
    assert_eq!(
        n["variables"],
        json!([{"oid": "1.3.6.1.4.1.8072.2.3.2.1", "type": "integer", "value": 42}]),
        "{n}"
    );

    // An inform the handler accepts is acknowledged: snmpinform exits 0.
    let out = net_snmp(
        "snmpinform",
        &[
            "-t",
            "2",
            "-r",
            "1",
            "-v",
            "2c",
            "-c",
            "public",
            &target,
            "",
            "1.3.6.1.6.3.1.1.5.4",
            "1.3.6.1.2.1.2.2.1.1.2",
            "i",
            "2",
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "snmpinform was not acknowledged: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let inform = wait_for(&state, id, "snmp_notification", |e| {
        e["request"]["kind"] == "inform"
    })
    .await;
    assert_eq!(
        inform["request"]["trap_oid"], "1.3.6.1.6.3.1.1.5.4",
        "{inform}"
    );

    // One it ignores is not: snmpinform retries, then times out.
    let out = net_snmp(
        "snmpinform",
        &[
            "-t",
            "1",
            "-r",
            "1",
            "-v",
            "2c",
            "-c",
            "deny",
            &target,
            "",
            "1.3.6.1.6.3.1.1.5.4",
        ],
    )
    .await;
    assert!(!out.status.success(), "an ignored inform was acknowledged");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Timeout"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn net_snmp_trapd_receives_what_netget_sends() {
    require("snmptrapd");
    require("snmpget");
    let dir = tempfile::tempdir().unwrap();
    let trapd_port = free_udp_port();
    let conf = dir.path().join("snmptrapd.conf");
    std::fs::write(
        &conf,
        "disableAuthorization yes\nauthCommunity log,execute,net public\n",
    )
    .unwrap();
    let log = dir.path().join("snmptrapd.log");
    let _trapd = tokio::process::Command::new("snmptrapd")
        .env("MIBS", "")
        .args(["-f", "-Lf"])
        .arg(&log)
        .args(["-On", "-m", "", "-C", "-c"])
        .arg(&conf)
        .arg(format!("udp:127.0.0.1:{trapd_port}"))
        .kill_on_drop(true)
        .spawn()
        .expect("snmptrapd");
    tokio::time::timeout(Duration::from_secs(20), async {
        while !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("NET-SNMP version")
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("snmptrapd never started");

    // Answer a GET for sysName, and on the way send three notifications to snmptrapd.
    let agent = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
m='127.0.0.1:{trapd_port}'
a=[]
if t=='snmp_request':
  a=[{{'type':'send_snmp_response','variables':[{{'oid':'1.3.6.1.2.1.1.5.0','type':'string','value':'netget-agent'}}]}},
     {{'type':'send_trap','target':m,'trap_oid':'1.3.6.1.6.3.1.1.5.3','uptime':4200,'variables':[{{'oid':'1.3.6.1.2.1.2.2.1.1.3','type':'integer','value':3}},{{'oid':'1.3.6.1.2.1.2.2.1.2.3','type':'string','value':'uplink'}},{{'oid':'1.3.6.1.2.1.2.2.1.10.3','type':'counter','value':12345}}]}},
     {{'type':'send_trap','target':m,'inform':True,'trap_oid':'1.3.6.1.6.3.1.1.5.4','variables':[{{'oid':'1.3.6.1.2.1.4.20.1.1.3','type':'ipaddress','value':'192.0.2.9'}}]}},
     {{'type':'send_trap','target':m,'version':'v1','enterprise':'1.3.6.1.4.1.8072.9999','agent_addr':'192.0.2.1','generic_trap':6,'specific_trap':7,'variables':[{{'oid':'1.3.6.1.4.1.8072.9999.1','type':'gauge','value':77}}]}}]
print(json.dumps({{'actions':a}}))"#
    );
    let (state, id, port) = snmp_server(&agent).await;
    let out = net_snmp(
        "snmpget",
        &[
            "-On",
            "-v",
            "2c",
            "-c",
            "public",
            &format!("127.0.0.1:{port}"),
            "1.3.6.1.2.1.1.5.0",
        ],
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(".1.3.6.1.2.1.1.5.0 = STRING: \"netget-agent\""),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sent = wait_for(&state, id, "snmp_notification_sent", |e| {
        e["request"]["kind"] == "inform"
    })
    .await;
    assert_eq!(
        sent["response"][0]["acknowledged"], true,
        "snmptrapd acknowledged the inform: {sent}"
    );

    let printed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.contains("Enterprise Specific Trap (7)")
                && text.matches(".1.3.6.1.6.3.1.1.4.1.0").count() >= 2
            {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "snmptrapd did not print all three:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        )
    });
    for expected in [
        // The v2c trap, with the uptime it was given and every binding typed.
        ".1.3.6.1.2.1.1.3.0 = Timeticks: (4200) 0:00:42.00",
        ".1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.3",
        ".1.3.6.1.2.1.2.2.1.1.3 = INTEGER: 3",
        ".1.3.6.1.2.1.2.2.1.2.3 = STRING: \"uplink\"",
        ".1.3.6.1.2.1.2.2.1.10.3 = Counter32: 12345",
        // The inform.
        ".1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.4",
        ".1.3.6.1.2.1.4.20.1.1.3 = IpAddress: 192.0.2.9",
        // The v1 trap.
        "192.0.2.1 [192.0.2.1]",
        "TRAP, SNMP v1, community public",
        ".1.3.6.1.4.1.8072.9999 Enterprise Specific Trap (7)",
        ".1.3.6.1.4.1.8072.9999.1 = Gauge32: 77",
    ] {
        assert!(
            printed.contains(expected),
            "snmptrapd did not print {expected:?}:\n{printed}"
        );
    }
}
