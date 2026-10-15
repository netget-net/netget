//! NetGet's Kerberos client against **MIT krb5kdc**, in a temporary realm built with MIT's own
//! `kdb5_util` and `kadmin.local`. A python chain is the model: on ready it asks for a TGT
//! (two hours, forwardable, renewable), with the TGT a ticket for `host/svc`, and then one for a
//! service the realm does not have.
//!
//! The tickets are proved real by MIT's own tools, not NetGet's: `klist` reads the ccache
//! NetGet wrote; `kvno -k` decrypts the service ticket with the keytab `kadmin.local` exported
//! from the KDC's database; and `kvno` uses the TGT and session key NetGet obtained to ask
//! krb5kdc for a ticket NetGet never requested. krb5kdc's own log shows the AS_REQ and TGS_REQ
//! it issued. A wrong password is refused by krb5kdc (PREAUTH_FAILED), and for a principal that
//! needs no pre-authentication NetGet refuses the AS-REP it cannot decrypt. The password is in
//! no event and nothing NetGet printed. Traffic is relayed and dissected by tshark.
//!
//! Fails, not skips, without krb5kdc (`brew install krb5` / `apt-get install krb5-kdc
//! krb5-admin-server krb5-user`) or tshark. No LLM calls.

use crate::helpers::pcap_oracle::{require_tshark, PcapOracle};
use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::recording_relay::{tcp_relay, udp_relay, Recording};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const REALM: &str = "NETGET.TEST";
const ALICE_PW: &str = "alice-MIT-pw-7";
const PLAIN_PW: &str = "plain-pw-3";

const KDC: InstallHint = InstallHint {
    brew: "krb5",
    apt: "krb5-kdc krb5-admin-server krb5-user",
};

/// The model: TGT, then host/svc, then a service that does not exist.
const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='kerberos_client_ready':
  a=[{'type':'kerberos_request_tgt','lifetime_secs':7200,'forwardable':True,'renewable_lifetime_secs':86400}]
elif t=='kerberos_tgt_obtained':
  a=[{'type':'kerberos_request_service_ticket','service':'host/svc.netget.test','lifetime_secs':1800}]
elif t=='kerberos_service_ticket_obtained' and e['service'].startswith('host/svc'):
  a=[{'type':'kerberos_request_service_ticket','service':'host/nope.netget.test'}]
print(json.dumps({'actions':a}))"#;

/// A temporary MIT realm: alice (pre-authentication required), plain (none required),
/// host/svc and host/other with random keys, and svc's keytab exported for the test.
async fn mit_kdc() -> RealServer {
    let kdc_conf = format!(
        "[kdcdefaults]\n kdc_listen = 127.0.0.1:{{port}}\n kdc_tcp_listen = 127.0.0.1:{{port}}\n\
         [realms]\n {REALM} = {{\n  database_name = {{dir}}/principal\n  key_stash_file = {{dir}}/stash\n  \
         acl_file = {{dir}}/kadm5.acl\n  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n  \
         max_life = 10h\n  max_renewable_life = 7d\n }}\n[logging]\n kdc = STDERR\n"
    );
    let krb5_conf = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n rdns = false\n\
         [realms]\n {REALM} = {{\n  kdc = 127.0.0.1:{{port}}\n }}\n"
    );
    let q = |cmd: &str| {
        vec![
            "-r".to_string(),
            REALM.to_string(),
            "-q".to_string(),
            cmd.to_string(),
        ]
    };
    RealServer::builder("krb5kdc", KDC)
        .config_file("kdc.conf", &kdc_conf)
        .config_file("krb5.conf", &krb5_conf)
        .setup_env("KRB5_CONFIG", "{dir}/krb5.conf")
        .setup_env("KRB5_KDC_PROFILE", "{dir}/kdc.conf")
        .env("KRB5_CONFIG", "{dir}/krb5.conf")
        .env("KRB5_KDC_PROFILE", "{dir}/kdc.conf")
        .setup_command(
            "kdb5_util",
            KDC,
            ["-r", REALM, "create", "-s", "-P", "master-pw"],
        )
        .setup_command(
            "kadmin.local",
            KDC,
            q(&format!("addprinc -pw {ALICE_PW} +requires_preauth alice")),
        )
        .setup_command(
            "kadmin.local",
            KDC,
            q(&format!("addprinc -pw {PLAIN_PW} -requires_preauth plain")),
        )
        .setup_command(
            "kadmin.local",
            KDC,
            q("addprinc -randkey host/svc.netget.test"),
        )
        .setup_command(
            "kadmin.local",
            KDC,
            q("addprinc -randkey host/other.netget.test"),
        )
        .setup_command(
            "kadmin.local",
            KDC,
            q("ktadd -k {dir}/svc.keytab host/svc.netget.test"),
        )
        .args(["-n", "-r", REALM])
        .ready_when_log_matches("commencing operation")
        .start()
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

async fn client(
    kdc: std::net::SocketAddr,
    principal: &str,
    password: &str,
    transport: &str,
    ccache: Option<&Path>,
) -> (AppState, ClientId, Arc<Mutex<Vec<String>>>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(l) = rx.recv().await {
            sink.lock().unwrap().push(l);
        }
    });
    let mut params = json!({"principal": principal, "password": password, "transport": transport});
    if let Some(p) = ccache {
        params["ccache_path"] = json!(p);
    }
    let id = ClientForm {
        protocol: "kerberos".into(),
        remote_addr: Some(kdc.to_string()),
        instruction: Some("Get my tickets".into()),
        startup_params: Some(params),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap_or_else(|e| panic!("connect: {e:#}"));
    (state, id, log)
}

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .map(|e| e["request"].clone())
        .collect()
}

async fn wait_for(state: &AppState, id: ClientId, kind: &str, n: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let v = events(state, id, kind).await;
            if v.len() >= n {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {n} {kind} event(s)"))
}

fn mit(name: &str) -> PathBuf {
    // Ubuntu installs MIT's tools as `klist.mit` beside Heimdal's behind an alternative.
    crate::helpers::real_server::find_binary(&format!("{name}.mit"))
        .or_else(|| crate::helpers::real_server::find_binary(name))
        .unwrap_or_else(|| panic!("MIT {name} not found: install krb5 (brew) or krb5-user (apt)"))
}

async fn tool(program: &Path, args: &[&str], conf: &Path, ccache: &Path) -> (bool, String) {
    let out = tokio::process::Command::new(program)
        .args(args)
        .env("KRB5_CONFIG", conf)
        // MIT klist formats times with the locale's `%x %X`; C makes it `10/15/26 04:43:52`
        // on every machine, so the parser below has one shape to read.
        .env("LC_ALL", "C")
        .env("KRB5CCNAME", format!("FILE:{}", ccache.display()))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", program.display()));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("$ {} {}\n{text}", program.display(), args.join(" "));
    (out.status.success(), text)
}

fn oracle(chunks: &[(bool, Vec<u8>)], udp: bool) {
    let mut o = if udp {
        PcapOracle::udp("kerberos")
    } else {
        PcapOracle::tcp("kerberos")
    }
    .port(88)
    // tshark tries to decrypt with keys it does not have and says so at Warn; that is about
    // the capture, not the bytes.
    .allow_expert_containing("Missing keytype")
    .allow_expert_containing("Used keymap=");
    for (to_server, bytes) in chunks {
        o = if *to_server {
            o.to_server(bytes)
        } else {
            o.from_server(bytes)
        };
    }
    o.assert_clean();
}

#[tokio::test]
async fn netget_gets_tickets_from_mit_krb5kdc_that_mit_tools_accept() {
    require_tshark();
    let kdc = mit_kdc().await;
    let kdc_addr: std::net::SocketAddr = ([127, 0, 0, 1], kdc.port).into();
    let (relay, recording): (_, Recording) = udp_relay(kdc_addr).await;
    let dir = tempfile::tempdir().unwrap();
    let cc = dir.path().join("netget.ccache");
    let (state, id, log) =
        client(relay, &format!("alice@{REALM}"), ALICE_PW, "udp", Some(&cc)).await;

    let tgt = &wait_for(&state, id, "kerberos_tgt_obtained", 1).await[0];
    assert_eq!(tgt["client"], format!("alice@{REALM}"));
    assert_eq!(tgt["lifetime_secs"], 7200, "{tgt}");
    let flags: Vec<String> = serde_json::from_value(tgt["flags"].clone()).unwrap();
    for f in ["forwardable", "renewable", "initial", "pre_authent"] {
        assert!(flags.contains(&f.to_string()), "{f} missing: {tgt}");
    }
    let svc = &wait_for(&state, id, "kerberos_service_ticket_obtained", 1).await[0];
    assert_eq!(svc["service"], format!("host/svc.netget.test@{REALM}"));
    assert_eq!(svc["lifetime_secs"], 1800, "{svc}");
    let failed = &wait_for(&state, id, "kerberos_request_failed", 1).await[0];
    assert_eq!(failed["error"], "KDC_ERR_S_PRINCIPAL_UNKNOWN", "{failed}");
    assert_eq!(failed["stage"], "tgs");

    // krb5kdc's own account of what it issued.
    let kdc_log = kdc.log();
    assert!(
        kdc_log.contains("AS_REQ")
            && kdc_log.contains("ISSUE: authtime")
            && kdc_log.contains(&format!("alice@{REALM} for krbtgt/{REALM}@{REALM}")),
        "{kdc_log}"
    );
    assert!(
        kdc_log.contains(&format!("alice@{REALM} for host/svc.netget.test@{REALM}")),
        "{kdc_log}"
    );

    // MIT's tools read the ccache NetGet wrote...
    let conf = kdc.dir().join("krb5.conf");
    let (ok, text) = tool(&mit("klist"), &["-f"], &conf, &cc).await;
    assert!(
        ok && text.contains(&format!("krbtgt/{REALM}@{REALM}"))
            && text.contains("host/svc.netget.test"),
        "{text}"
    );
    // ...decrypt the service ticket with the keytab krb5kdc's database exported...
    let keytab = kdc.dir().join("svc.keytab");
    let (ok, text) = tool(
        &mit("kvno"),
        &["-k", keytab.to_str().unwrap(), "host/svc.netget.test"],
        &conf,
        &cc,
    )
    .await;
    assert!(
        ok && text.contains("keytab entry valid"),
        "{text}\n{}",
        kdc.log()
    );
    // ...and use NetGet's TGT and session key to get a ticket NetGet never asked for.
    let (ok, text) = tool(&mit("kvno"), &["host/other.netget.test"], &conf, &cc).await;
    assert!(ok && text.contains("kvno = "), "{text}\n{}", kdc.log());

    // The password reached no event and nothing NetGet printed.
    let shown = serde_json::to_string(&state.list_access_logs_for(None, None).await).unwrap();
    assert!(!shown.contains(ALICE_PW));
    assert!(!log.lock().unwrap().join("\n").contains(ALICE_PW));

    oracle(&recording.lock().unwrap(), true);
}

#[tokio::test]
async fn a_wrong_password_never_becomes_a_ticket() {
    require_tshark();
    let kdc = mit_kdc().await;
    let kdc_addr: std::net::SocketAddr = ([127, 0, 0, 1], kdc.port).into();
    let (relay, streams) = tcp_relay(kdc_addr).await;

    // Pre-authentication required: krb5kdc refuses the timestamp itself.
    let (state, id, _) = client(relay, &format!("alice@{REALM}"), "not alice's", "tcp", None).await;
    let failed = &wait_for(&state, id, "kerberos_request_failed", 1).await[0];
    assert_eq!(failed["kind"], "kdc_error", "{failed}");
    assert_eq!(failed["error"], "KDC_ERR_PREAUTH_FAILED", "{failed}");
    assert!(events(&state, id, "kerberos_tgt_obtained").await.is_empty());

    // No pre-authentication: krb5kdc answers, and NetGet refuses the reply it cannot decrypt.
    let (state, id, _) = client(relay, &format!("plain@{REALM}"), "not plain's", "tcp", None).await;
    let failed = &wait_for(&state, id, "kerberos_request_failed", 1).await[0];
    assert_eq!(failed["kind"], "integrity", "{failed}");
    assert!(events(&state, id, "kerberos_tgt_obtained").await.is_empty());

    // The right password for the same principal does get one.
    let (state, id, _) = client(relay, &format!("plain@{REALM}"), PLAIN_PW, "tcp", None).await;
    wait_for(&state, id, "kerberos_tgt_obtained", 1).await;

    for stream in streams.lock().unwrap().iter() {
        let chunks = stream.lock().unwrap().clone();
        if chunks.iter().any(|(to, _)| !*to) {
            oracle(&chunks, false);
        }
    }
}

const HEIMDAL_KDC: InstallHint = InstallHint {
    brew: "(nothing: macOS ships Heimdal's kdc in /System/Library/PrivateFrameworks/Heimdal.framework/Helpers)",
    apt: "heimdal-clients, plus heimdal-kdc (which conflicts with krb5-kdc: CI unpacks it with dpkg -x and puts its kdc on PATH, see the kerberos job in protocol-pairs.yml)",
};

/// The first of `candidates` that exists and says it is Heimdal.
fn heimdal_tool(candidates: &[&str]) -> PathBuf {
    heimdal_tool_opt(candidates).unwrap_or_else(|| {
        panic!(
            "no Heimdal tool among {candidates:?}: `sudo apt-get install {}` (macOS ships them). \
             This is independent evidence for the Kerberos client, so it fails rather than skips.",
            HEIMDAL_KDC.apt
        )
    })
}

fn heimdal_tool_opt(candidates: &[&str]) -> Option<PathBuf> {
    for c in candidates {
        let Some(p) = crate::helpers::real_server::find_binary(c) else {
            continue;
        };
        let banner = std::process::Command::new(&p)
            .arg("--version")
            .output()
            .map(|o| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_default();
        if banner.contains("Heimdal") {
            return Some(p);
        }
    }
    None
}

/// A temporary Heimdal realm, administered with Heimdal's own `kadmin -l`.
async fn heimdal_kdc() -> RealServer {
    let kadmin = heimdal_tool(&["kadmin.heimdal", "/usr/sbin/kadmin"]);
    // `log_file`: Heimdal 7.8's `kadmin -l` writes an iprop log, by default under
    // /var/lib/heimdal-kdc, which an unprivileged test cannot open ("Failed iprop log
    // initialization"); every principal it adds then fails. The realm keeps its own.
    let kadmin = kadmin.to_str().unwrap();
    let conf = format!(
        "[libdefaults]\n default_realm = {REALM}\n\
         [realms]\n {REALM} = {{\n  kdc = 127.0.0.1:{{port}}\n }}\n\
         [kdc]\n database = {{\n  dbname = {{dir}}/heimdal\n  realm = {REALM}\n  mkey_file = {{dir}}/m-key\n  log_file = {{dir}}/iprop.log\n }}\n\
         [logging]\n kdc = STDERR\n"
    );
    let admin = |args: &[&str]| -> Vec<String> {
        let mut v = vec![
            "-l".to_string(),
            "-c".to_string(),
            "{dir}/krb5.conf".to_string(),
        ];
        v.extend(args.iter().map(|a| a.to_string()));
        v
    };
    let mut args = vec![
        "-c".to_string(),
        "{dir}/krb5.conf".to_string(),
        "--ports={port}".to_string(),
        "--addresses=127.0.0.1".to_string(),
    ];
    let kdc_path = crate::helpers::real_server::find_binary("kdc").unwrap_or_default();
    if kdc_path.to_string_lossy().contains("Heimdal.framework") {
        // macOS confines its KDC to the system's own ports and paths unless told otherwise.
        args.push("--no-sandbox".to_string());
    }
    RealServer::builder("kdc", HEIMDAL_KDC)
        .config_file("krb5.conf", &conf)
        .setup_command(
            kadmin,
            HEIMDAL_KDC,
            admin(&[
                "init",
                "--realm-max-ticket-life=1d",
                "--realm-max-renewable-life=7d",
                REALM,
            ]),
        )
        .setup_command(
            kadmin,
            HEIMDAL_KDC,
            admin(&[
                "add",
                &format!("--password={ALICE_PW}"),
                "--use-defaults",
                "alice",
            ]),
        )
        .setup_command(
            kadmin,
            HEIMDAL_KDC,
            admin(&[
                "add",
                "--random-key",
                "--use-defaults",
                "host/svc.netget.test",
            ]),
        )
        .setup_command(
            kadmin,
            HEIMDAL_KDC,
            admin(&[
                "add",
                "--random-key",
                "--use-defaults",
                "host/other.netget.test",
            ]),
        )
        .setup_command(
            kadmin,
            HEIMDAL_KDC,
            admin(&[
                "ext_keytab",
                "-k",
                "{dir}/svc.keytab",
                "host/svc.netget.test",
            ]),
        )
        .args(args)
        .env("KRB5_CONFIG", "{dir}/krb5.conf")
        .ready_when_log_matches("KDC started")
        .start()
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

#[tokio::test]
async fn netget_gets_tickets_from_a_heimdal_kdc_that_heimdal_tools_accept() {
    let kdc = heimdal_kdc().await;
    let kdc_addr: std::net::SocketAddr = ([127, 0, 0, 1], kdc.port).into();
    let dir = tempfile::tempdir().unwrap();
    let cc = dir.path().join("netget.ccache");
    let (state, id, _) = client(
        kdc_addr,
        &format!("alice@{REALM}"),
        ALICE_PW,
        "tcp",
        Some(&cc),
    )
    .await;

    let tgt = &wait_for(&state, id, "kerberos_tgt_obtained", 1).await[0];
    let flags: Vec<String> = serde_json::from_value(tgt["flags"].clone()).unwrap();
    assert!(
        flags.contains(&"pre_authent".to_string()),
        "{tgt}\n{}",
        kdc.log()
    );
    let svc = &wait_for(&state, id, "kerberos_service_ticket_obtained", 1).await[0];
    assert_eq!(svc["service"], format!("host/svc.netget.test@{REALM}"));
    let failed = &wait_for(&state, id, "kerberos_request_failed", 1).await[0];
    assert_eq!(failed["error"], "KDC_ERR_S_PRINCIPAL_UNKNOWN", "{failed}");

    // Heimdal's klist reads the ccache, and kgetcred uses NetGet's TGT and session key for a
    // ticket NetGet never asked for; MIT's kvno decrypts the service ticket with the keytab
    // Heimdal's database exported.
    let conf = kdc.dir().join("krb5.conf");
    // Heimdal 7's klist is `heimtools klist` (see tests/server/kerberos/support.rs).
    let (klist, klist_args): (PathBuf, &[&str]) = match heimdal_tool_opt(&["heimtools"]) {
        Some(h) => (h, &["klist"]),
        None => (heimdal_tool(&["/usr/bin/klist"]), &[]),
    };
    let (ok, text) = tool(&klist, klist_args, &conf, &cc).await;
    assert!(ok && text.contains("host/svc.netget.test"), "{text}");
    let kgetcred = heimdal_tool(&["kgetcred"]);
    let (ok, text) = tool(
        &kgetcred,
        &[&format!("host/other.netget.test@{REALM}")],
        &conf,
        &cc,
    )
    .await;
    assert!(ok, "kgetcred with NetGet's TGT: {text}\n{}", kdc.log());
    let keytab = kdc.dir().join("svc.keytab");
    let (ok, text) = tool(
        &mit("kvno"),
        &["-k", keytab.to_str().unwrap(), "host/svc.netget.test"],
        &conf,
        &cc,
    )
    .await;
    assert!(ok && text.contains("keytab entry valid"), "{text}");

    // A wrong password: Heimdal answers a timestamp that does not decrypt with
    // PREAUTH_REQUIRED again (older builds) or PREAUTH_FAILED, and logs why; either way the
    // client reports a refusal and has no TGT.
    let (state, id, _) = client(kdc_addr, &format!("alice@{REALM}"), "wrong", "udp", None).await;
    let failed = &wait_for(&state, id, "kerberos_request_failed", 1).await[0];
    assert!(
        failed["error"] == "KDC_ERR_PREAUTH_FAILED"
            || failed["error"] == "KDC_ERR_PREAUTH_REQUIRED",
        "{failed}\n{}",
        kdc.log()
    );
    assert!(events(&state, id, "kerberos_tgt_obtained").await.is_empty());
    kdc.wait_for_log("Failed to decrypt PA-DATA", Duration::from_secs(10))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
}
