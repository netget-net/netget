//! Shared harness for the r-service suites: an in-process server with a python policy playing
//! the model (the LLM endpoint is unreachable, so only the policy answers and a request it does
//! not answer exercises the fail-closed path), and a raw client that writes the handshakes from
//! literal bytes rather than through NetGet's encoder.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The rsh model: alice/alice is trusted, everyone else refused; a few commands are scripted
/// to exercise stderr, silence and an invalid answer.
pub const RSH_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); e=i['event']
c=e['command']
if not (e['client_user']=='alice' and e['server_user']=='alice'):
  a=[{'type':'rsh_refuse','message':'Permission denied.'}]
elif c=='silent':
  a=[]
elif c=='bad':
  a=[{'type':'rsh_output','stdout':5}]
elif c=='big':
  a=[{'type':'rsh_output','stdout':'x'*(1024*1024+1)}]
elif c.startswith('size '):
  a=[{'type':'rsh_output','stdout':'%d\n'%len(c)}]
else:
  a=[{'type':'rsh_output','stdout':'ran '+c+'\n','stderr':'warn '+c+'\n'}]
print(json.dumps({'actions':a}))"#;

/// The rexec model: runs everything but rm.
pub const REXEC_POLICY: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
if e['command'].startswith('rm'):
  a=[{'type':'rexec_refuse','message':'rm: Permission denied'}]
else:
  a=[{'type':'rexec_output','stdout':e['user']+' ran '+e['command']+'\n','stderr':'note\n'}]
print(json.dumps({'actions':a}))"#;

/// The rlogin model: alice trusted, bob asked for a password, anyone else refused; then a tiny
/// shell.
pub const RLOGIN_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='rlogin_login':
  u=e['client_user']
  if u=='alice':
    a=[{'type':'rlogin_trust','banner':'Welcome alice\n','prompt':'$ '}]
  elif u=='bob':
    a=[{'type':'rlogin_ask_password','banner':'Welcome bob\n','prompt':'$ '}]
  elif u=='silent':
    a=[]
  else:
    a=[{'type':'rlogin_refuse','message':'rlogind: Permission denied.'}]
elif e['interrupt']:
  a=[{'type':'rlogin_send_text','text':'$ '}]
elif e['line']=='exit':
  a=[{'type':'rlogin_send_line','line':'logout'},{'type':'close_connection'}]
elif e['line']=='size':
  w=e.get('window') or {}
  a=[{'type':'rlogin_send_text','text':'rows=%s cols=%s\n$ '%(w.get('rows'),w.get('cols'))}]
elif e['line']=='secret':
  a=[{'type':'rlogin_set_echo','echo':False},{'type':'rlogin_send_text','text':'Secret: '}]
elif e['line']=='echo-on':
  a=[{'type':'rlogin_set_echo','echo':True},{'type':'rlogin_send_text','text':'$ '}]
else:
  a=[{'type':'rlogin_send_text','text':'you typed '+e['line']+'\n$ '}]
print(json.dumps({'actions':a}))"#;

pub fn policy(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub struct Started {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
}

/// Start `protocol` on `host`:`port` (0 for any) with an unreachable model, so only
/// `handlers` answer.
pub async fn start_on(
    protocol: &str,
    host: &str,
    port: u16,
    handlers: Option<Vec<Value>>,
    params: Option<Value>,
) -> Started {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: protocol.into(),
        port: Some(port),
        host: Some(host.into()),
        instruction: Some("Be the remote host".into()),
        event_handlers: handlers,
        startup_params: params,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("starting {protocol}: {e}"));
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return a.port();
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    panic!("{protocol} failed to start: {e}");
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server started");
    Started { state, id, port }
}

pub async fn start(protocol: &str, handlers: Option<Vec<Value>>, params: Option<Value>) -> Started {
    start_on(protocol, "127.0.0.1", 0, handlers, params).await
}

/// What the model was shown, per event type, oldest first.
pub async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all
}

/// Everything the access log holds for the server, as one string.
pub async fn access_log_text(state: &AppState, id: ServerId) -> String {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Read until the peer closes (bounded by 15 s).
pub async fn read_to_end(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), s.read_to_end(&mut out)).await;
    out
}

/// Read until `out` contains `needle` (bounded by 15 s); everything read so far.
pub async fn read_until(s: &mut TcpStream, out: &mut Vec<u8>, needle: &[u8]) -> bool {
    let found = tokio::time::timeout(Duration::from_secs(15), async {
        let mut buf = [0u8; 4096];
        loop {
            if out.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    found.unwrap_or(false)
}

/// One rsh/rexec exchange from literal bytes: connect, write `handshake`, read everything.
pub async fn exchange(port: u16, handshake: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(handshake).await.unwrap();
    read_to_end(&mut s).await
}

/// `field\0` for each field, written out by hand.
pub fn nul_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(f);
        out.push(0);
    }
    out
}

// Blocking versions, for rlogin: its peer reads urgent data, and a tokio stream on macOS can
// miss the wake-up for data that follows an urgent byte.

/// An urgent byte the server sent, waiting up to 5 s for one.
pub fn b_urgent(s: &std::net::TcpStream) -> Option<u8> {
    for _ in 0..250 {
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1];
        if let Ok(1) = socket2::SockRef::from(s).recv_out_of_band(&mut buf) {
            // SAFETY: one byte was received into the buffer.
            return Some(unsafe { buf[0].assume_init() });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Read until `out` contains `needle`, for at most 15 s.
pub fn b_read_until(s: &mut std::net::TcpStream, out: &mut Vec<u8>, needle: &[u8]) -> bool {
    use std::io::Read;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 4096];
    while !out.windows(needle.len()).any(|w| w == needle) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        s.set_read_timeout(Some(left)).unwrap();
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    true
}

/// Read until the server closes, for at most 15 s.
pub fn b_read_to_end(s: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read;
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}
