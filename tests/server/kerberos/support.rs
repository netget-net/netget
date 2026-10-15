//! Shared harness for the KDC suites: an in-process KDC with a python policy standing in for
//! the model, the third-party client tools (found, version-checked, or the test fails), a
//! temporary `krb5.conf`, and UDP/TCP relays that record both directions for the pcap oracle.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub const REALM: &str = "NETGET.TEST";
pub const ALICE_PASSWORD: &str = "wonder land 42";
pub const SERVICE: &str = "host/svc.netget.test";
pub const SERVICE_PASSWORD: &str = "svc-key-Xq81";
/// A principal exempt from pre-authentication: the one for which "fail open" would hand out a
/// ticket on the very first request, so the fail-closed tests use it.
pub const LEGACY: &str = "legacy";
pub const LEGACY_PASSWORD: &str = "legacy-pw-55";

/// The model, as a python script: alice and bob are admitted once pre-authenticated (two-hour
/// forwardable, renewable tickets), mallory is revoked, everyone else is unknown; host/
/// services that exist get one-hour tickets, anything else is unknown.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='kerberos_as_request':
  if e['client'] in ('alice','bob') and e['client_known']:
    if e['preauth']=='verified':
      a=[{'type':'kerberos_issue_ticket','lifetime_secs':7200,'forwardable':True,'renewable':True,'renewable_lifetime_secs':86400}]
    else:
      a=[{'type':'kerberos_require_preauth'}]
  elif e['client']=='mallory':
    a=[{'type':'kerberos_refuse','error':'CLIENT_REVOKED','text':'mallory is revoked'}]
  else:
    a=[{'type':'kerberos_refuse','error':'C_PRINCIPAL_UNKNOWN'}]
elif t=='kerberos_tgs_request':
  if e['service_known'] and e['service'].startswith('host/'):
    a=[{'type':'kerberos_issue_ticket','lifetime_secs':3600,'forwardable':True}]
  else:
    a=[{'type':'kerberos_refuse','error':'S_PRINCIPAL_UNKNOWN'}]
print(json.dumps({'actions':a}))"#;

pub fn policy() -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": POLICY}
    })])
}

pub fn params() -> Value {
    json!({
        "realm": REALM,
        "principal_passwords": {
            "alice": ALICE_PASSWORD,
            "bob": "bob-pw",
            "mallory": "mallory-pw",
            SERVICE: SERVICE_PASSWORD,
            LEGACY: LEGACY_PASSWORD,
        },
        "no_preauth_principals": [LEGACY]
    })
}

/// A running in-process KDC and everything it printed.
pub struct Kdc {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Kdc {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    /// Wait until the KDC's status stream contains `needle`.
    pub async fn wait_for_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !self.log_text().contains(needle) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Every event of `kind` the KDC raised, oldest first.
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        let mut v: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == kind)
            .collect();
        v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
        v
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }
}

/// Start a KDC. `handlers` is the routing table (the python policy, a static rule, or `None`
/// to send every event to a model that is not there).
pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> Kdc {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    let id = ServerForm {
        protocol: "kerberos".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be the realm's KDC".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the KDC never reported its address");
    Kdc {
        state,
        id,
        port,
        log,
    }
}

// ---------------------------------------------------------------------------------------------
// Third-party tools
// ---------------------------------------------------------------------------------------------

/// MIT krb5's and Heimdal's client tools.
pub struct Tools {
    pub mit_kinit: PathBuf,
    pub mit_klist: PathBuf,
    pub mit_kvno: PathBuf,
    pub mit_ktutil: PathBuf,
    pub heimdal_kinit: PathBuf,
    pub heimdal_klist: PathBuf,
    /// Arguments that select `klist` inside Heimdal 7's multi-call `heimtools` (empty for a
    /// standalone `klist`). See [`Tools::heimdal_klist_args`].
    pub heimdal_klist_prefix: Vec<&'static str>,
    pub heimdal_kgetcred: PathBuf,
}

const INSTALL: &str =
    "Install MIT krb5 (`brew install krb5`, or `sudo apt-get install krb5-user`) \
     and Heimdal's clients (macOS ships them in /usr/bin; `sudo apt-get install heimdal-clients` \
     installs kinit.heimdal, klist.heimdal and kgetcred beside MIT's kinit.mit). Override with \
     NETGET_KRB5_MIT_DIR / NETGET_KRB5_HEIMDAL_DIR. These are the two independent clients the \
     KDC's evidence rests on, so a missing one FAILS this test rather than skipping it.";

fn version_of(program: &Path, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default()
}

/// Where each tool is looked for, in order, after `NETGET_KRB5_MIT_DIR` /
/// `NETGET_KRB5_HEIMDAL_DIR`. Homebrew's keg-only MIT krb5 first (macOS's /usr/bin tools are
/// Heimdal); Ubuntu installs MIT's as `*.mit` and Heimdal's as `*.heimdal` side by side.
const MIT_KINIT: &[&str] = &[
    "/opt/homebrew/opt/krb5/bin/kinit",
    "/usr/local/opt/krb5/bin/kinit",
    "/usr/bin/kinit.mit",
];
const MIT_KLIST: &[&str] = &[
    "/opt/homebrew/opt/krb5/bin/klist",
    "/usr/local/opt/krb5/bin/klist",
    "/usr/bin/klist.mit",
];
const MIT_KVNO: &[&str] = &[
    "/opt/homebrew/opt/krb5/bin/kvno",
    "/usr/local/opt/krb5/bin/kvno",
    "/usr/bin/kvno",
];
const MIT_KTUTIL: &[&str] = &[
    "/opt/homebrew/opt/krb5/bin/ktutil",
    "/usr/local/opt/krb5/bin/ktutil",
    "/usr/bin/ktutil.mit",
];
const HEIMDAL_KINIT: &[&str] = &["/usr/bin/kinit.heimdal", "/usr/bin/kinit"];
/// Heimdal 7's `klist` is a command of the multi-call `heimtools`, which picks the command from
/// `argv[0]` only when the name is exactly `klist` (kuser/heimtools.c, `command_alias`). Ubuntu's
/// `klist.heimdal` is a symlink to it under the suffixed name, so run as such it prints
/// `Usage: klist.heimdal [--version] [--help] command ..`: call `heimtools klist` instead. macOS
/// ships a standalone `klist` (Heimdal 1.5).
const HEIMDAL_KLIST: &[&str] = &["/usr/bin/heimtools", "/usr/bin/klist"];
const HEIMDAL_KGETCRED: &[&str] = &["/usr/bin/kgetcred"];

/// The first candidate that exists, after the override directory.
fn locate(env: &str, candidates: &[&str]) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(env) {
        if !dir.is_empty() {
            for c in candidates {
                let name = Path::new(c).file_name()?;
                let p = Path::new(&dir).join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// Find both implementations' tools and prove each is the implementation it claims to be:
/// MIT's `klist -V` says "Kerberos 5 version", Heimdal's `kinit --version` says "Heimdal".
pub fn tools() -> Tools {
    let need = |what: &str, p: Option<PathBuf>| -> PathBuf {
        p.unwrap_or_else(|| panic!("{what} not found. {INSTALL}"))
    };
    let mit = |c: &[&str]| locate("NETGET_KRB5_MIT_DIR", c);
    let heimdal = |c: &[&str]| locate("NETGET_KRB5_HEIMDAL_DIR", c);
    let mit_klist = need("MIT klist", mit(MIT_KLIST));
    let banner = version_of(&mit_klist, &["-V"]);
    assert!(
        banner.contains("Kerberos 5 version"),
        "{} is not MIT krb5's klist (its -V printed {banner:?}). {INSTALL}",
        mit_klist.display()
    );
    let heimdal_kinit = need("Heimdal kinit", heimdal(HEIMDAL_KINIT));
    let banner = version_of(&heimdal_kinit, &["--version"]);
    assert!(
        banner.contains("Heimdal"),
        "{} is not Heimdal's kinit (its --version printed {banner:?}). {INSTALL}",
        heimdal_kinit.display()
    );
    let mut tools = Tools {
        mit_kinit: need("MIT kinit", mit(MIT_KINIT)),
        mit_klist,
        mit_kvno: need("MIT kvno", mit(MIT_KVNO)),
        mit_ktutil: need("MIT ktutil", mit(MIT_KTUTIL)),
        heimdal_klist_prefix: Vec::new(),
        heimdal_klist: need("Heimdal klist", heimdal(HEIMDAL_KLIST)),
        heimdal_kgetcred: need("Heimdal kgetcred", heimdal(HEIMDAL_KGETCRED)),
        heimdal_kinit,
    };
    if tools
        .heimdal_klist
        .file_name()
        .is_some_and(|n| n == "heimtools")
    {
        tools.heimdal_klist_prefix = vec!["klist"];
    }
    tools
}

impl Tools {
    /// `args` for Heimdal's klist, behind `klist` when it is `heimtools`.
    pub fn heimdal_klist_args<'a>(&self, args: &[&'a str]) -> Vec<&'a str> {
        let mut v: Vec<&'a str> = self.heimdal_klist_prefix.clone();
        v.extend_from_slice(args);
        v
    }
}

/// How a `krb5.conf` reaches the KDC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Udp,
    /// MIT: `udp_preference_limit = 1` sends everything over TCP.
    MitTcp,
    /// Heimdal: the `tcp/` prefix on the KDC address.
    HeimdalTcp,
}

/// A `krb5.conf` naming `kdc` for the test realm.
pub fn krb5_conf(dir: &Path, kdc: std::net::SocketAddr, via: Via) -> PathBuf {
    let (kdc_line, limit) = match via {
        Via::Udp => (format!("kdc = {kdc}"), 1465),
        Via::MitTcp => (format!("kdc = {kdc}"), 1),
        Via::HeimdalTcp => (format!("kdc = tcp/{kdc}"), 1),
    };
    let conf = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n rdns = false\n udp_preference_limit = {limit}\n\
         [realms]\n {REALM} = {{\n  {kdc_line}\n }}\n"
    );
    let path = dir.join(format!("krb5-{via:?}.conf"));
    std::fs::write(&path, conf).unwrap();
    path
}

/// The output of a finished tool run.
pub struct Run {
    pub ok: bool,
    pub text: String,
}

/// Run a tool with its own `KRB5_CONFIG` and `KRB5CCNAME`, feeding `stdin`.
pub async fn run(program: &Path, args: &[&str], conf: &Path, ccache: &Path, stdin: &str) -> Run {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env("KRB5_CONFIG", conf)
        // MIT klist formats times with the locale's `%x %X`; C makes it `10/15/26 04:43:52`
        // on every machine, so the parser below has one shape to read.
        .env("LC_ALL", "C")
        .env("KRB5CCNAME", format!("FILE:{}", ccache.display()))
        .env_remove("KRB5_KTNAME")
        .env_remove("KRB5_CLIENT_KTNAME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("{}: {e}. {INSTALL}", program.display()));
    if let Some(mut input) = child.stdin.take() {
        let _ = input.write_all(stdin.as_bytes()).await;
    }
    let out = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("{} did not finish", program.display()))
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("$ {} {}\n{text}", program.display(), args.join(" "));
    Run {
        ok: out.status.success(),
        text,
    }
}

pub use crate::helpers::recording_relay::{tcp_relay, udp_relay, Recording};
