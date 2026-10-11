//! Shared by the TCP, zone-transfer and DNSSEC tests: an in-process DNS server whose every
//! event a script handler answers from one zone, so no model is involved and every count is
//! exact.
//!
//! The zone is `example.com.`, serial [`SERIAL`]:
//!
//! - apex NS, MX and TXT; `ns1`, `www`, `mail` A; `_sip._tcp` SRV; `ptr` PTR;
//! - `big` TXT: eight 200-octet strings, too large for 512 bytes of UDP;
//! - `huge` TXT: thirty, too large even for the 4096 bytes a client may ask for;
//! - `host0`..`host599` A — [`FILLER`] names, so an AXFR needs more than one message.
//!
//! Queries are answered with `send_dns_records`: the records at the name and type; NOERROR
//! with the SOA when the name exists without that type; NXDOMAIN with the SOA when it does not
//! exist. AXFR of the zone is `send_dns_zone`; IXFR from `SERIAL - 1` is one change (`www`
//! moves from .80 to .81) — even for a signed zone, where the server must refuse it — from
//! `SERIAL` it is "current", from anything else the full zone.
//! A transfer of any other zone is refused.

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

pub const SERIAL: u32 = 2026101102;
pub const FILLER: usize = 600;

pub const HANDLER: &str = r#"import json,sys
SERIAL=2026101102
Z='example.com.'
SOA={'mname':'ns1.example.com.','rname':'hostmaster.example.com.','serial':SERIAL,'refresh':3600,'retry':600,'expire':604800,'minimum':300}
R=[{'name':'@','type':'NS','target':'ns1.example.com.'},
   {'name':'@','type':'MX','preference':10,'exchange':'mail.example.com.'},
   {'name':'@','type':'TXT','text':'v=spf1 -all'},
   {'name':'ns1','type':'A','ip':'192.0.2.53'},
   {'name':'www','type':'A','ip':'192.0.2.81'},
   {'name':'mail','type':'A','ip':'192.0.2.25'},
   {'name':'_sip._tcp','type':'SRV','priority':10,'weight':5,'port':5060,'target':'www.example.com.'},
   {'name':'ptr','type':'PTR','target':'www.example.com.'},
   {'name':'big','type':'TXT','text':[chr(97+i)*200 for i in range(8)]},
   {'name':'huge','type':'TXT','text':[chr(97+i%26)*200 for i in range(30)]}]
R+=[{'name':'host%d'%i,'type':'A','ip':'10.%d.%d.%d'%(i//65536,(i//256)%256,i%256)} for i in range(600)]
def fq(n): return Z if n=='@' else n+'.'+Z
def soa_rec(): d=dict(SOA); d['name']=Z; d['type']='SOA'; return d
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='dns_query':
    q=e['domain'].lower(); qt=e['query_type']
    at=[dict(r,name=fq(r['name'])) for r in R if fq(r['name'])==q]
    if q==Z and qt=='SOA': ans=[soa_rec()]
    else: ans=[r for r in at if r['type']==qt]
    base={'type':'send_dns_records','query_id':e['query_id'],'domain':e['domain'],'query_type':qt}
    if ans: a=[dict(base,answers=ans)]
    elif at or q==Z: a=[dict(base,authority=[soa_rec()])]
    else: a=[dict(base,authority=[soa_rec()],rcode='NXDOMAIN')]
elif t=='dns_zone_transfer':
    zone=e['zone'].lower(); cs=e.get('client_serial')
    if zone!=Z: a=[{'type':'send_dns_refused','query_id':e['query_id'],'domain':e['zone'],'query_type':e['transfer_type']}]
    elif e['transfer_type']=='IXFR' and cs==SERIAL: a=[{'type':'send_dns_ixfr','query_id':e['query_id'],'zone':Z,'soa':SOA,'changes':[]}]
    elif e['transfer_type']=='IXFR' and cs==SERIAL-1:
        a=[{'type':'send_dns_ixfr','query_id':e['query_id'],'zone':Z,'soa':SOA,'changes':[{'serial':SERIAL,
           'deleted':[{'name':'www','type':'A','ip':'192.0.2.80'}],'added':[{'name':'www','type':'A','ip':'192.0.2.81'}]}]}]
    else: a=[{'type':'send_dns_zone','query_id':e['query_id'],'zone':Z,'soa':SOA,'records':R}]
else: a=[]
print(json.dumps({'actions':a}))"#;

pub struct DnsDevice {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
}

impl DnsDevice {
    pub async fn start(startup_params: Option<Value>) -> DnsDevice {
        Self::start_with_handler(startup_params, HANDLER).await
    }

    /// The same server, every event answered by `handler` (a Python script) instead.
    pub async fn start_with_handler(startup_params: Option<Value>, handler: &str) -> DnsDevice {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        let (tx, _) = mpsc::unbounded_channel();
        let id = ServerForm {
            protocol: "dns".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            instruction: Some("Authoritative for example.com".into()),
            startup_params,
            event_handlers: Some(vec![json!({
                "event_pattern": "*",
                "handler": {"type": "script", "language": "python", "code": handler}
            })]),
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .expect("the DNS server did not start");
        let port = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                    break a.port();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the DNS server never bound");
        DnsDevice { state, id, port }
    }

    /// Every event the handler answered, oldest first: (event type, event data).
    pub async fn events(&self) -> Vec<(String, Value)> {
        let mut rows: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
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
}

/// Run a tool to completion and return its stdout. Fails, never skips, when it is missing.
pub async fn run(program: &str, args: &[String], package: &str) -> String {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{program} {args:?} did not finish"))
    .unwrap_or_else(|e| {
        panic!("`{program}` is not available ({e}): install {package}. This test does not skip.")
    });
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    println!("[{program} {}]\n{stdout}", args.join(" "));
    if !out.status.success() {
        println!(
            "[{program} stderr] {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    stdout
}

/// `dig @127.0.0.1 -p PORT ...`, one try.
pub async fn dig(port: u16, args: &[&str]) -> String {
    let mut argv: Vec<String> = vec![
        "@127.0.0.1".into(),
        "-p".into(),
        port.to_string(),
        "+tries=1".into(),
        "+time=10".into(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    run("dig", &argv, "bind9-dnsutils (dig)").await
}

/// `kdig @127.0.0.1 -p PORT ...`.
pub async fn kdig(port: u16, args: &[&str]) -> String {
    let mut argv: Vec<String> = vec![
        "@127.0.0.1".into(),
        "-p".into(),
        port.to_string(),
        "+retry=0".into(),
        "+time=10".into(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    run("kdig", &argv, "knot-dnsutils (kdig)").await
}

/// Resource-record lines of a zone listing (dig/kdig presentation), comments dropped.
pub fn rr_lines(output: &str) -> Vec<Vec<String>> {
    output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with(';'))
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .collect()
}
