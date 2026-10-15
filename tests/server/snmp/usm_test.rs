//! SNMPv3 with the User-based Security Model on the agent.
//!
//! - **Keys** against RFC 3414 A.3's published vectors, so a localization bug cannot hide
//!   behind two ends that share it.
//! - **Net-SNMP** (`snmpget`, `snmpgetnext`, `snmpbulkget`, `snmpset`) at every security level,
//!   with every authentication protocol (MD5, SHA-1, SHA-224/256/384/512) and both privacy
//!   protocols (DES, AES-128). Each does engine discovery and the time synchronisation that
//!   follows it against NetGet, so those reports are exercised by every call. The handler
//!   echoes the user, level and context it was given, so each answer proves what the event
//!   carried.
//! - **The USM's refusals**, as Net-SNMP reports them: a wrong authentication password, a
//!   wrong privacy password, an unknown user, a level below the user's.
//! - **The time window**, from the wire: a correctly authenticated request 151 seconds off the
//!   agent's clock gets an *authenticated* usmStatsNotInTimeWindows report carrying the real
//!   clock, and the handler never sees it.
//!
//! Net-SNMP is required; the tests fail rather than skip without it. MIB loading is off and
//! `SNMP_PERSISTENT_DIR` points at a temp dir, so nothing is read from or written to the
//! machine's own Net-SNMP state. No LLM calls: a python handler answers every request.

use netget::cli::management::ServerForm;
use netget::server::snmp::usm::{self, AuthProtocol, ReportKind, User};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const ENGINE_ID: &str = "8000000005a1b2c3d4e5f60718";

/// One user per protocol pair Net-SNMP is asked to drive.
fn users() -> Value {
    json!([
        {"name": "noauth"},
        {"name": "md5", "auth_protocol": "md5", "auth_password": "md5-auth-pass"},
        {"name": "sha512", "auth_protocol": "sha512", "auth_password": "sha512-auth-pass"},
        {"name": "md5des", "auth_protocol": "md5", "auth_password": "md5des-auth", "priv_protocol": "des", "priv_password": "md5des-priv"},
        {"name": "shades", "auth_protocol": "sha", "auth_password": "shades-auth", "priv_protocol": "des", "priv_password": "shades-priv"},
        {"name": "shaaes", "auth_protocol": "sha", "auth_password": "shaaes-auth", "priv_protocol": "aes", "priv_password": "shaaes-priv"},
        {"name": "sha224aes", "auth_protocol": "sha224", "auth_password": "sha224-auth", "priv_protocol": "aes", "priv_password": "sha224-priv"},
        {"name": "sha256aes", "auth_protocol": "sha256", "auth_password": "sha256-auth", "priv_protocol": "aes", "priv_password": "sha256-priv"},
        {"name": "sha384des", "auth_protocol": "sha384", "auth_password": "sha384-auth", "priv_protocol": "des", "priv_password": "sha384-priv"},
        {"name": "sha512aes", "auth_protocol": "sha512", "auth_password": "sha512a-auth", "priv_protocol": "aes", "priv_password": "sha512a-priv"},
    ])
}

/// Echo who asked: a GET answers `user/level/context` as a string; a GETNEXT answers the next
/// OID; a GETBULK two; a SET echoes what was set.
const AGENT: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
who='%s/%s/%s' % (e.get('user'), e.get('security_level'), e.get('context_name'))
t=e['request_type']
if t=='GetRequest':
  v=[{'oid':o,'type':'string','value':who} for o in e['oids']]
elif t=='GetNextRequest':
  v=[{'oid':'1.3.6.1.2.1.1.5.0','type':'string','value':'next:'+who}]
elif t=='GetBulkRequest':
  v=[{'oid':'1.3.6.1.2.1.1.%d.0'%n,'type':'integer','value':n} for n in (5,6)]
else:
  v=[{'oid':o,'type':'string','value':'set'} for o in e['oids']]
print(json.dumps({'actions':[{'type':'send_snmp_response','variables':v}]}))"#;

async fn agent(params: Value) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "snmp".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("SNMPv3 agent".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":AGENT}}),
        ]),
        startup_params: Some(params),
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
    .expect("the SNMP agent never bound");
    (state, id, port)
}

async fn requests(state: &AppState, id: ServerId) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "snmp_request")
        .collect()
}

/// Run a Net-SNMP tool, numeric output, no MIBs, persistent state in a temp dir of its own.
async fn net_snmp(binary: &str, args: &[&str]) -> (bool, String, String) {
    let persistent = tempfile::tempdir().unwrap();
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(binary)
            .env("MIBS", "")
            .env("SNMP_PERSISTENT_DIR", persistent.path())
            .env("SNMPCONFPATH", persistent.path())
            .args(["-m", "", "-On", "-r", "1", "-t", "2"])
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{binary} did not finish"))
    .unwrap_or_else(|e| {
        panic!("{binary} is required (apt install snmp / brew install net-snmp): {e}")
    });
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

/// The `-v3 -l … -u … -a … -A … -x … -X …` arguments for a user of `users()`.
fn v3_args(user: &str) -> Vec<String> {
    let u = users()
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == user)
        .cloned()
        .unwrap();
    let mut args = vec!["-v3".into(), "-u".into(), user.into()];
    let auth = u["auth_protocol"].as_str();
    let privacy = u["priv_protocol"].as_str();
    args.extend([
        "-l".into(),
        match (auth, privacy) {
            (None, _) => "noAuthNoPriv".into(),
            (Some(_), None) => "authNoPriv".into(),
            _ => "authPriv".to_string(),
        },
    ]);
    if let Some(a) = auth {
        let name = match a {
            "md5" => "MD5",
            "sha" => "SHA",
            "sha224" => "SHA-224",
            "sha256" => "SHA-256",
            "sha384" => "SHA-384",
            "sha512" => "SHA-512",
            other => panic!("{other}"),
        };
        args.extend([
            "-a".into(),
            name.into(),
            "-A".into(),
            u["auth_password"].as_str().unwrap().into(),
        ]);
    }
    if let Some(p) = privacy {
        args.extend([
            "-x".into(),
            p.to_uppercase(),
            "-X".into(),
            u["priv_password"].as_str().unwrap().into(),
        ]);
    }
    args
}

#[test]
fn keys_match_rfc_3414_appendix_a3() {
    let engine = hex::decode("000000000000000000000002").unwrap();
    for (proto, ku, kul) in [
        (
            AuthProtocol::Md5,
            "9faf3283884e92834ebc9847d8edd963",
            "526f5eed9fcce26f8964c2930787d82b",
        ),
        (
            AuthProtocol::Sha1,
            "9fb5cc0381497b3793528939ff788d5d79145211",
            "6695febc9288e36282235fc7151f128497b38f3f",
        ),
    ] {
        let key = proto.password_to_key(b"maplesyrup");
        assert_eq!(hex::encode(&key), ku, "{proto:?} Ku");
        assert_eq!(
            hex::encode(proto.localize(&key, &engine)),
            kul,
            "{proto:?} Kul"
        );
    }
}

#[tokio::test]
async fn net_snmp_reads_every_level_and_protocol_pair() {
    let (state, id, port) = agent(json!({"v3_users": users(), "engine_id": ENGINE_ID})).await;
    let target = format!("127.0.0.1:{port}");
    for user in [
        "noauth",
        "md5",
        "sha512",
        "md5des",
        "shades",
        "shaaes",
        "sha224aes",
        "sha256aes",
        "sha384des",
        "sha512aes",
    ] {
        let mut args = v3_args(user);
        args.extend(["-Oqv".into(), target.clone(), "1.3.6.1.2.1.1.1.0".into()]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (ok, out, err) = net_snmp("snmpget", &args).await;
        let level = args[args.iter().position(|a| *a == "-l").unwrap() + 1];
        assert!(ok, "snmpget as {user}: {err}");
        assert_eq!(out, format!("\"{user}/{level}/\""), "snmpget as {user}");
    }
    // The context name reaches the handler; the other verbs carry the same security.
    let mut args = v3_args("sha256aes");
    args.extend([
        "-n".into(),
        "vlan-7".into(),
        "-Oqv".into(),
        target.clone(),
        "1.3.6.1.2.1.1.1.0".into(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, out, err) = net_snmp("snmpget", &args).await;
    assert!(ok, "{err}");
    assert_eq!(out, "\"sha256aes/authPriv/vlan-7\"");
    for (tool, extra, want) in [
        (
            "snmpgetnext",
            vec!["1.3.6.1.2.1.1.4.0"],
            ".1.3.6.1.2.1.1.5.0 = STRING: \"next:md5des/authPriv/\"",
        ),
        (
            "snmpbulkget",
            vec!["-Cn0", "-Cr2", "1.3.6.1.2.1.1.4.0"],
            ".1.3.6.1.2.1.1.5.0 = INTEGER: 5\n.1.3.6.1.2.1.1.6.0 = INTEGER: 6",
        ),
        (
            "snmpset",
            vec!["1.3.6.1.2.1.1.5.0", "s", "renamed"],
            ".1.3.6.1.2.1.1.5.0 = STRING: \"set\"",
        ),
    ] {
        let mut args = v3_args("md5des");
        args.push(target.clone());
        args.extend(extra.iter().map(|s| s.to_string()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (ok, out, err) = net_snmp(tool, &args).await;
        assert!(ok, "{tool}: {err}");
        assert_eq!(out, want, "{tool}");
    }
    let seen = requests(&state, id).await;
    assert!(seen.iter().all(|e| e["request"]["version"] == "v3"));
    assert!(seen
        .iter()
        .all(|e| !e.to_string().contains("auth-pass") && !e.to_string().contains("-priv\"")));
    state.remove_server(id).await;
}

#[tokio::test]
async fn the_usm_refuses_before_the_handler_sees_anything() {
    let (state, id, port) = agent(json!({"v3_users": users()})).await;
    let target = format!("127.0.0.1:{port}");
    let get = |args: Vec<String>| {
        let mut args = args;
        args.extend([target.clone(), "1.3.6.1.2.1.1.1.0".into()]);
        args
    };
    let swap = |user: &str, flag: &str, value: &str| {
        let mut a = v3_args(user);
        let at = a.iter().position(|x| x == flag).unwrap();
        a[at + 1] = value.into();
        a
    };
    for (what, args, expect) in [
        (
            "wrong auth password",
            swap("sha256aes", "-A", "not-the-password"),
            "Authentication failure",
        ),
        (
            "unknown user",
            swap("sha256aes", "-u", "nobody"),
            "Unknown user name",
        ),
        (
            "level below the user's",
            swap("sha256aes", "-l", "authNoPriv"),
            "Unsupported security level",
        ),
        (
            "authPriv for an authNoPriv user",
            {
                let mut a = v3_args("sha512");
                let at = a.iter().position(|x| x == "-l").unwrap();
                a[at + 1] = "authPriv".into();
                a.extend([
                    "-x".into(),
                    "AES".into(),
                    "-X".into(),
                    "whatever-pass".into(),
                ]);
                a
            },
            "Unsupported security level",
        ),
    ] {
        let args = get(args);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (ok, out, err) = net_snmp("snmpget", &args).await;
        assert!(!ok, "{what}: answered {out}");
        assert!(err.contains(expect), "{what}: {err}");
    }
    // A wrong privacy password authenticates and then fails to decrypt: Net-SNMP gets the
    // decryption report (or, being unable to read it either way, no usable answer).
    let args = get(swap("shaaes", "-X", "not-the-privpass"));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, out, err) = net_snmp("snmpget", &args).await;
    assert!(!ok, "wrong privacy password: answered {out}");
    assert!(
        err.contains("Decryption error") || err.contains("Timeout"),
        "{err}"
    );
    assert!(
        requests(&state, id).await.is_empty(),
        "the handler saw a refused request"
    );
    state.remove_server(id).await;
}

/// An authenticated request outside the time window gets an authenticated report with the
/// agent's real clock, and the handler never sees it; one inside the window is answered.
#[tokio::test]
async fn a_stale_clock_is_reported_with_the_real_one() {
    let (state, id, port) =
        agent(json!({"v3_users": users(), "engine_id": ENGINE_ID, "engine_boots": 7})).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(("127.0.0.1", port)).await.unwrap();
    let user = User::from_json(&users()[7]).unwrap();
    let manager = usm::Manager::new(user.clone());
    let (msg_id, probe) = manager.discovery().unwrap();
    socket.send(&probe).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    manager.learn(&buf[..n], msg_id).unwrap();
    assert_eq!(
        manager.engine_id().unwrap(),
        hex::decode(ENGINE_ID).unwrap()
    );

    let keys = user.localize(&hex::decode(ENGINE_ID).unwrap());
    let engine = hex::decode(ENGINE_ID).unwrap();
    let pdu = || {
        rasn_snmp::v2::Pdus::GetRequest(rasn_snmp::v2::GetRequest(rasn_snmp::v2::Pdu {
            request_id: 77,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![rasn_snmp::v2::VarBind {
                name: rasn::types::ObjectIdentifier::new_unchecked(
                    vec![1, 3, 6, 1, 2, 1, 1, 1, 0].into(),
                ),
                value: rasn_snmp::v2::VarBindValue::Unspecified,
            }],
        }))
    };
    for (time, want_report) in [(151, true), (149, false)] {
        let bytes = usm::encode(usm::Outgoing {
            msg_id: 900 + time,
            max_size: 65507,
            flags: usm::FLAG_AUTH | usm::FLAG_PRIV | usm::FLAG_REPORTABLE,
            engine_id: &engine,
            boots: 7,
            time,
            user: user.name.as_bytes(),
            keys: Some(&keys),
            salt: 1,
            context_engine_id: &engine,
            context_name: b"",
            pdu: pdu(),
        })
        .unwrap();
        socket.send(&bytes).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let rx = usm::decode(&buf[..n]).unwrap();
        assert_eq!(rx.msg_id, 900 + time);
        assert_eq!(
            rx.flags & usm::FLAG_AUTH != 0,
            true,
            "the reply is authenticated"
        );
        assert!(
            usm::verify(&buf[..n], &keys),
            "and its MAC verifies under the user's key"
        );
        match manager.unwrap(&buf[..n], 900 + time).unwrap() {
            usm::Reply::Report(kind, count) => {
                assert!(want_report, "time {time} was reported");
                assert_eq!(kind, ReportKind::NotInTimeWindows);
                assert_eq!(count, 1);
                let real: i64 = rx.usm.authoritative_engine_time.try_into().unwrap();
                assert!(real < 30, "the report carries the agent's clock, {real}");
                let boots: i64 = rx.usm.authoritative_engine_boots.try_into().unwrap();
                assert_eq!(boots, 7);
            }
            usm::Reply::Pdu(_) => {
                assert!(!want_report, "time {time} was answered");
            }
        }
    }
    // Only the in-window request reached the handler.
    assert_eq!(requests(&state, id).await.len(), 1);
    state.remove_server(id).await;
}

/// Each user-table bound and rule, refused at start-up rather than at the first request.
#[tokio::test]
async fn misconfigured_users_refuse_to_start() {
    let long = "x".repeat(usm::MAX_NAME_BYTES + 1);
    for (users, why) in [
        (
            json!([{"name": "a", "auth_protocol": "sha", "auth_password": "short"}]),
            "8 to 256",
        ),
        (
            json!([{"name": "a", "priv_protocol": "aes", "priv_password": "long-enough"}]),
            "no noAuthPriv",
        ),
        (
            json!([{"name": "a", "auth_protocol": "rot13", "auth_password": "long-enough"}]),
            "auth_protocol",
        ),
        (
            json!([{"name": "a", "auth_protocol": "sha", "auth_password": "long-enough", "priv_protocol": "aes256", "priv_password": "long-enough"}]),
            "priv_protocol",
        ),
        (json!([{"name": "a"}, {"name": "a"}]), "twice"),
        (json!([{"name": long}]), "user name"),
        (
            json!((0..=usm::MAX_USERS)
                .map(|i| json!({"name": format!("u{i}")}))
                .collect::<Vec<_>>()),
            "at most",
        ),
    ] {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        let (tx, _) = mpsc::unbounded_channel();
        let created = ServerForm {
            protocol: "snmp".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            startup_params: Some(json!({"v3_users": users})),
            ..Default::default()
        }
        .create(&state, tx)
        .await;
        let error = match created {
            Err(e) => format!("{e:#}"),
            Ok(id) => tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(s) = state.get_server(id).await {
                        if let netget::state::server::ServerStatus::Error(e) = s.status {
                            break e;
                        }
                        assert!(s.local_addr.is_none(), "started with {users}");
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap(),
        };
        assert!(error.contains(why), "{why}: {error}");
    }
    for (engine_id, why) in [("80000000", "5 to 32"), ("zz", "hexadecimal")] {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        let (tx, _) = mpsc::unbounded_channel();
        let created = ServerForm {
            protocol: "snmp".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            startup_params: Some(json!({"v3_users": [{"name": "a"}], "engine_id": engine_id})),
            ..Default::default()
        }
        .create(&state, tx)
        .await;
        let error = match created {
            Err(e) => format!("{e:#}"),
            Ok(id) => tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(netget::state::server::ServerStatus::Error(e)) =
                        state.get_server(id).await.map(|s| s.status)
                    {
                        break e;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap(),
        };
        assert!(error.contains(why), "{why}: {error}");
    }
}

/// pysnmp — a separate, pure-Python USM — reads, walks a step, bulks and sets, with each
/// authentication family and both privacy protocols, and sees the USM's refusals as the
/// report names they are.
#[tokio::test]
async fn pysnmp_reads_and_writes_and_sees_the_reports() {
    let python = std::env::var("NETGET_PYSNMP_PYTHON").expect(
        "NETGET_PYSNMP_PYTHON is required: a python3 with pysnmp==7.1.22, pyasn1==0.6.4 \
         and cryptography==46.0.3 installed",
    );
    let (state, id, port) = agent(json!({"v3_users": users()})).await;
    let script = r#"
import asyncio, sys, importlib.metadata
assert importlib.metadata.version('pysnmp') == '7.1.22'
from pysnmp.hlapi.v3arch.asyncio import *

A = {'md5': usmHMACMD5AuthProtocol, 'sha': usmHMACSHAAuthProtocol,
     'sha224': usmHMAC128SHA224AuthProtocol, 'sha256': usmHMAC192SHA256AuthProtocol,
     'sha384': usmHMAC256SHA384AuthProtocol, 'sha512': usmHMAC384SHA512AuthProtocol}
P = {'des': usmDESPrivProtocol, 'aes': usmAesCfb128Protocol}

def user(name, auth=None, ap=None, priv=None, pp=None):
    return UsmUserData(name, ap, pp,
                       authProtocol=A[auth] if auth else usmNoAuthProtocol,
                       privProtocol=P[priv] if priv else usmNoPrivProtocol)

SYS_DESCR = ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))

async def main(port):
    target = await UdpTransportTarget.create(('127.0.0.1', port), timeout=2, retries=1)
    cases = [
        (user('noauth'), 'noauth/noAuthNoPriv/'),
        (user('md5', 'md5', 'md5-auth-pass'), 'md5/authNoPriv/'),
        (user('sha512', 'sha512', 'sha512-auth-pass'), 'sha512/authNoPriv/'),
        (user('md5des', 'md5', 'md5des-auth', 'des', 'md5des-priv'), 'md5des/authPriv/'),
        (user('shaaes', 'sha', 'shaaes-auth', 'aes', 'shaaes-priv'), 'shaaes/authPriv/'),
        (user('sha224aes', 'sha224', 'sha224-auth', 'aes', 'sha224-priv'), 'sha224aes/authPriv/'),
        (user('sha384des', 'sha384', 'sha384-auth', 'des', 'sha384-priv'), 'sha384des/authPriv/'),
        (user('sha512aes', 'sha512', 'sha512a-auth', 'aes', 'sha512a-priv'), 'sha512aes/authPriv/'),
    ]
    for u, want in cases:
        # A fresh engine each time, so every user goes through discovery from scratch.
        err, status, _, vbs = await get_cmd(SnmpEngine(), u, target, ContextData(), SYS_DESCR)
        assert err is None and not status, (want, err, status)
        assert str(vbs[0][1]) == want, (want, vbs[0][1].prettyPrint())
    u = user('sha256aes', 'sha256', 'sha256-auth', 'aes', 'sha256-priv')
    engine = SnmpEngine()
    err, status, _, vbs = await get_cmd(engine, u, target, ContextData(contextName='rack-2'), SYS_DESCR)
    assert err is None and str(vbs[0][1]) == 'sha256aes/authPriv/rack-2', (err, vbs)
    err, status, _, vbs = await next_cmd(engine, u, target, ContextData(), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0')))
    assert err is None and str(vbs[0][0]) == '1.3.6.1.2.1.1.5.0' and str(vbs[0][1]) == 'next:sha256aes/authPriv/', (err, vbs)
    err, status, _, vbs = await bulk_cmd(engine, u, target, ContextData(), 0, 2, ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0')))
    assert err is None and [int(v[1]) for v in vbs] == [5, 6], (err, vbs)
    err, status, _, vbs = await set_cmd(engine, u, target, ContextData(), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'), OctetString('renamed')))
    assert err is None and str(vbs[0][1]) == 'set', (err, vbs)
    for bad, report in [
        (user('sha256aes', 'sha256', 'wrong-password', 'aes', 'sha256-priv'), 'wrongDigest'),
        (user('nobody', 'sha256', 'sha256-auth', 'aes', 'sha256-priv'), 'unknownUserName'),
        (user('sha256aes', 'sha256', 'sha256-auth'), 'unsupportedSecurityLevel'),
    ]:
        err, status, _, vbs = await get_cmd(SnmpEngine(), bad, target, ContextData(), SYS_DESCR)
        assert err is not None and report.lower() in repr(err).lower().replace(' ', ''), (report, repr(err))
    print('PYSNMP_OK')

asyncio.run(main(int(sys.argv[1])))
"#;
    let out = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new(&python)
            .args(["-c", script, &port.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("pysnmp did not finish")
    .expect("NETGET_PYSNMP_PYTHON could not run");
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("PYSNMP_OK"),
        "pysnmp: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = requests(&state, id).await;
    assert!(seen
        .iter()
        .any(|e| e["request"]["context_name"] == "rack-2"));
    assert!(seen.iter().all(|e| e["request"]["user"] != "nobody"));
    state.remove_server(id).await;
}
