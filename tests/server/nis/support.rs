//! Shared harness for the NIS server suites: an in-process server with a python policy
//! playing the model, and `yp_raw.py`, a YP caller written from `yp.x` with python's struct
//! module rather than NetGet's codec.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

pub const DOMAIN: &str = "netget.test";

/// The model, as a python script: one domain, `netget.test`, holding passwd, group, hosts,
/// netgroup and a generic mail.aliases. Every other domain is refused (no_domain, and false
/// to DOMAIN), and every other map is no_map.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
D='netget.test'
users=[{'name':'alice','password':'x','uid':1000,'gid':1000,'gecos':'Alice Liddell','home':'/home/alice','shell':'/bin/bash'},
       {'name':'bob','uid':1001,'gid':100,'home':'/home/bob','shell':'/bin/sh'}]
groups=[{'name':'staff','gid':100,'members':['alice','bob']},{'name':'wheel','gid':10,'members':['alice']}]
hosts=[{'address':'10.0.0.1','names':['gateway','gw']},{'address':'10.0.0.2','names':['files']}]
maps={'passwd.byname':users,'passwd.byuid':users,'group.byname':groups,'group.bygid':groups,
 'hosts.byname':hosts,'hosts.byaddr':hosts,
 'netgroup':[{'name':'admins','members':[{'host':'gateway','user':'alice','domain':D},'others']},{'name':'others','members':[{'user':'bob'}]}],
 'mail.aliases':[{'key':'postmaster','value':'alice'},{'key':'root','value':'alice, bob'}]}
if t=='nis_domain_query':
  a=[{'type':'nis_domain','served':e['domain']==D}]
elif e['domain']!=D:
  a=[{'type':'nis_error','status':'no_domain'}]
elif t=='nis_maplist':
  a=[{'type':'nis_maps','maps':sorted(maps)}]
elif e['map']=='broken.byname':
  a=[{'type':'nis_entries','entries':[{'name':'eve','uid':1,'gid':1,'gecos':'x:0:0','home':'/','shell':'/bin/sh'}]}]
elif e['map']=='big.map':
  a=[{'type':'nis_entries','entries':[{'key':'k%d'%n,'value':'v'*1000} for n in range(100)]}]
elif e['map']=='huge.map':
  a=[{'type':'nis_entries','entries':[{'key':'k%d'%n,'value':'v'} for n in range(10001)]}]
elif e['map'] not in maps:
  a=[{'type':'nis_error','status':'no_map'}]
elif t=='nis_map_info':
  a=[{'type':'nis_map_info','master':'nis-master','order':1790000000}]
else:
  a=[{'type':'nis_entries','entries':maps[e['map']]}]
print(json.dumps({'actions':a}))"#;

pub fn policy() -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
    ])
}

pub struct Started {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
}

/// Start a NIS server on 127.0.0.1 with an unreachable model, so only `handlers` answer.
pub async fn start(handlers: Option<Vec<Value>>, params: Option<Value>) -> Started {
    try_start(handlers, params).await.unwrap()
}

pub async fn try_start(
    handlers: Option<Vec<Value>>,
    params: Option<Value>,
) -> anyhow::Result<Started> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "nis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a NIS server".into()),
        event_handlers: handlers,
        startup_params: params,
        ..Default::default()
    }
    .create(&state, tx)
    .await?;
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return Ok(a.port());
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    return Err(anyhow::anyhow!("{e}"));
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(Started { state, id, port })
}

/// What the model was shown, per event type.
pub async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

pub fn yp_raw_path() -> String {
    format!("{}/tests/server/nis/yp_raw.py", env!("CARGO_MANIFEST_DIR"))
}

/// Run `yp_raw.py` against 127.0.0.1:`port` and return its per-call results.
pub async fn yp_raw(port: u16, transport: &str, calls: Value) -> Vec<Value> {
    let out = tokio::process::Command::new("python3")
        .args([
            &yp_raw_path(),
            "127.0.0.1",
            &port.to_string(),
            transport,
            &calls.to_string(),
        ])
        .output()
        .await
        .expect("python3 runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "yp_raw.py failed: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{e}: {text}"))
}

pub fn s(v: &str) -> Value {
    json!(["s", v])
}

pub fn o(v: &str) -> Value {
    json!(["o", v])
}

/// One call for `yp_raw.py`.
pub fn call(proc_: u32, args: Vec<Value>, decode: &str) -> Value {
    json!({"proc": proc_, "args": args, "decode": decode})
}

pub fn nokey(proc_: u32, domain: &str, map: &str, decode: &str) -> Value {
    call(proc_, vec![s(domain), s(map)], decode)
}

pub fn key(proc_: u32, domain: &str, map: &str, k: &str, decode: &str) -> Value {
    call(proc_, vec![s(domain), s(map), o(k)], decode)
}

/// What the Linux suites (yp-tools against NetGet, NetGet against ypserv) share: the system
/// rpcbind, root through `sudo -n`, and one lock, because ONC RPC program 100004 can be
/// registered with a portmapper once — NetGet's server, a real ypserv and a stale entry from
/// a killed run all contend for the same row.
#[cfg(target_os = "linux")]
pub mod linux {
    use crate::helpers::netns::privileged;
    use crate::helpers::real_server::InstallHint;
    use std::process::Command;

    pub const YP_TOOLS: InstallHint = InstallHint {
        brew: "(none: yp-tools is not packaged for macOS; run on Linux)",
        apt: "yp-tools",
    };
    pub const YPBIND: InstallHint = InstallHint {
        brew: "(none: ypbind-mt is not packaged for macOS; run on Linux)",
        apt: "ypbind-mt",
    };
    pub const YPSERV: InstallHint = InstallHint {
        brew: "(none: ypserv is not packaged for macOS; run on Linux)",
        apt: "ypserv",
    };
    pub const RPCBIND: InstallHint = InstallHint {
        brew: "rpcbind",
        apt: "rpcbind",
    };

    /// Held for a whole test: one process at a time owns program 100004 in rpcbind.
    pub struct ProgramLock(#[allow(dead_code)] std::fs::File);

    pub fn lock_program() -> ProgramLock {
        use fs2::FileExt;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(std::env::temp_dir().join("netget-nis-program-100004.lock"))
            .expect("lock file");
        f.lock_exclusive().expect("lock");
        ProgramLock(f)
    }

    /// rpcbind must be listening on 127.0.0.1:111; fails, naming how to get it, otherwise.
    pub fn require_rpcbind() {
        assert!(
            std::net::TcpStream::connect("127.0.0.1:111").is_ok(),
            "rpcbind must be running on 127.0.0.1:111. This test is independent evidence for \
             NIS, so it fails rather than skips: sudo apt-get install {} && sudo systemctl \
             start rpcbind (or run `rpcbind -w` as root)",
            RPCBIND.apt
        );
    }

    /// Remove any ypserv registration left by a killed run or another ypserv, as root (an
    /// entry NetGet made over TCP is owned by "unknown", which only the superuser may unset).
    pub fn clear_ypserv_registrations() {
        for v in ["1", "2"] {
            let _ = privileged("rpcinfo").args(["-d", "100004", v]).output();
        }
    }

    /// Run a command; (success, stdout+stderr). Missing binaries fail naming the package.
    pub fn run(mut c: Command, binary: &str, hint: InstallHint) -> (bool, String) {
        let out = c.output().unwrap_or_else(|e| {
            panic!(
                "{}",
                crate::helpers::real_server::missing_binary(binary, hint, e)
            )
        });
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    pub async fn run_async(c: Command, binary: &'static str, hint: InstallHint) -> (bool, String) {
        tokio::task::spawn_blocking(move || run(c, binary, hint))
            .await
            .unwrap()
    }

    /// rpcinfo -p's rows for program 100004: (version, netid, port).
    pub fn ypserv_rows(rpcinfo_p: &str) -> Vec<(String, String, String)> {
        rpcinfo_p
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .filter(|c| c.len() >= 4 && c[0] == "100004")
            .map(|c| (c[1].to_string(), c[2].to_string(), c[3].to_string()))
            .collect()
    }

    pub fn rpcinfo(args: &[&str]) -> (bool, String) {
        let mut c = Command::new("rpcinfo");
        c.args(args);
        run(c, "rpcinfo", RPCBIND)
    }
}
