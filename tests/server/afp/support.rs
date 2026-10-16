//! Shared harness for the AFP server suites: an in-process server with a python policy playing
//! the model, and a raw DSI client written against `src/server/afp/{dsi,wire}.rs` that records
//! every byte both ways for the pcap oracle.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::server::afp::dsi;
use netget::server::afp::wire::{self, AfpPath, Request};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

/// The bytes README.txt holds.
pub const README: &str = "Hello from NetGet\n";
/// The bytes docs/notes.txt holds.
pub const NOTES: &str = "first note\nsecond note\n";

/// The model, as a python script. One volume tree:
///
/// ```text
/// Share/
///   README.txt        (readable)
///   secret.txt        (the model refuses to read it)
///   docs/notes.txt
///   docs/empty/
/// ```
///
/// Creates are allowed except of anything named `forbidden*`; writes are allowed except to
/// `nope.txt`; deletes are allowed except of README.txt.
pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='afp_list_volumes':
  a=[{'type':'afp_volumes','volumes':[{'name':'Share'},{'name':'Archive','read_only':True}]}]
elif t=='afp_list_directory':
  p=e['path']
  if p=='':
    a=[{'type':'afp_directory_listing','entries':[
      {'name':'README.txt','type':'file','size':18,'created':'2026-01-02T03:04:05Z','modified':'2026-02-03T04:05:06Z'},
      {'name':'secret.txt','type':'file','size':6,'permissions':'600'},
      {'name':'docs','type':'directory'}]}]
  elif p=='docs':
    a=[{'type':'afp_directory_listing','entries':[
      {'name':'notes.txt','type':'file','size':23},
      {'name':'empty','type':'directory'}]}]
  elif p=='docs/empty' or e['volume']=='Archive':
    a=[{'type':'afp_directory_listing','entries':[]}]
  else:
    a=[{'type':'afp_deny','error':'not_found'}]
elif t=='afp_read_file':
  p=e['path']
  if p=='README.txt':
    a=[{'type':'afp_file_content','content':'Hello from NetGet\n'}]
  elif p=='docs/notes.txt':
    a=[{'type':'afp_file_content','content':'first note\nsecond note\n'}]
  else:
    a=[{'type':'afp_deny','error':'access_denied','reason':'private'}]
elif t=='afp_create':
  if e['path'].split('/')[-1].startswith('forbidden'):
    a=[{'type':'afp_deny','error':'access_denied'}]
  else:
    a=[{'type':'afp_allow'}]
elif t=='afp_write_file':
  if e['path'].endswith('nope.txt'):
    a=[{'type':'afp_deny','error':'disk_full'}]
  else:
    a=[{'type':'afp_allow'}]
elif t=='afp_delete':
  if e['path']=='README.txt':
    a=[{'type':'afp_deny','error':'locked'}]
  else:
    a=[{'type':'afp_allow'}]
print(json.dumps({'actions':a}))"#;

pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

pub fn policy() -> Option<Vec<Value>> {
    script(POLICY)
}

pub fn static_rule(actions: Value) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": actions}}),
    ])
}

/// A running in-process server and everything it printed.
pub struct Server {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Server {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    /// Wait until the server's status stream contains `needle`.
    pub async fn wait_for_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !self.log_text().contains(needle) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Every event of `kind` the server raised, oldest first, as the model saw it.
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
        v.into_iter().map(|e| e["request"].clone()).collect()
    }

    /// Every event the server raised, of any kind.
    pub async fn all_events(&self) -> Vec<Value> {
        self.state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }
}

/// Start a server. `handlers` is the routing table (a python policy, a static rule, or `None`
/// to send every event to a model that is not there).
pub async fn start(handlers: Option<Vec<Value>>, params: Value) -> Server {
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
        protocol: "afp".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a file server".into()),
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
    .expect("the AFP server never reported its address");
    Server {
        state,
        id,
        port,
        log,
    }
}

/// A raw DSI client: every byte it sent and received is kept, in order, as
/// `(to_server, bytes)`.
pub struct RawClient {
    r: OwnedReadHalf,
    w: OwnedWriteHalf,
    next_id: u16,
    pub chunks: Vec<(bool, Vec<u8>)>,
}

/// A reply: the DSI result code and payload.
#[derive(Debug)]
pub struct Reply {
    pub code: i32,
    pub body: Vec<u8>,
}

impl RawClient {
    pub async fn connect(addr: std::net::SocketAddr) -> RawClient {
        let s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (r, w) = s.into_split();
        RawClient {
            r,
            w,
            next_id: 0,
            chunks: Vec::new(),
        }
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.chunks.push((true, bytes.to_vec()));
        let _ = self.w.write_all(bytes).await;
    }

    /// The next message, or None on EOF or after `within`.
    pub async fn recv_within(&mut self, within: Duration) -> Option<(dsi::Header, Vec<u8>)> {
        let mut h = [0u8; dsi::HEADER_LEN];
        match tokio::time::timeout(within, self.r.read_exact(&mut h)).await {
            Ok(Ok(_)) => {}
            _ => return None,
        }
        let header = dsi::Header::parse(&h);
        let mut body = vec![0u8; header.length as usize];
        self.r.read_exact(&mut body).await.ok()?;
        let mut raw = h.to_vec();
        raw.extend_from_slice(&body);
        self.chunks.push((false, raw));
        Some((header, body))
    }

    /// Whether the server closed the connection within `within` (reading and discarding
    /// anything it sent first).
    pub async fn closed_within(&mut self, within: Duration) -> bool {
        let mut buf = [0u8; 4096];
        tokio::time::timeout(within, async {
            loop {
                match self.r.read(&mut buf).await {
                    Ok(0) | Err(_) => return true,
                    Ok(_) => continue,
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Send one DSI request and wait for its reply, skipping the server's tickles.
    pub async fn call(&mut self, command: u8, code: u32, payload: &[u8]) -> Reply {
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let m = dsi::message(dsi::FLAG_REQUEST, command, id, code, payload);
        self.send_raw(&m).await;
        loop {
            let (h, body) = self
                .recv_within(Duration::from_secs(30))
                .await
                .unwrap_or_else(|| panic!("no reply to {} {id}", dsi::command_name(command)));
            if h.flags == dsi::FLAG_REPLY && h.request_id == id {
                return Reply {
                    code: h.result(),
                    body,
                };
            }
        }
    }

    pub async fn afp(&mut self, req: &Request) -> Reply {
        self.call(dsi::command::COMMAND, 0, &wire::encode_request(req))
            .await
    }

    pub async fn afp_write(&mut self, req: &Request, data: &[u8]) -> Reply {
        let block = wire::encode_request(req);
        let mut p = block.clone();
        p.extend_from_slice(data);
        self.call(dsi::command::WRITE, block.len() as u32, &p).await
    }

    pub async fn open_session(&mut self) -> u32 {
        let r = self
            .call(
                dsi::command::OPEN_SESSION,
                0,
                &dsi::encode_options(&[(1, 1024u32.to_be_bytes().to_vec())]),
            )
            .await;
        assert_eq!(r.code, 0);
        let opts = dsi::parse_options(&r.body).unwrap();
        dsi::quantum_option(&opts, dsi::option::SERVER_REQUEST_QUANTUM).unwrap()
    }

    pub async fn login(&mut self, user: Option<(&str, &str)>) -> i32 {
        let login = match user {
            Some((u, p)) => wire::Login {
                ext: false,
                version: "AFP3.4".into(),
                uam: wire::uam::CLEARTXT_PASSWRD.into(),
                user: Some(u.into()),
                password: Some(p.as_bytes().to_vec()),
            },
            None => wire::Login {
                ext: false,
                version: "AFP3.4".into(),
                uam: wire::uam::NO_USER_AUTHENT.into(),
                user: None,
                password: None,
            },
        };
        self.afp(&Request::Login(login)).await.code
    }

    /// Open a session, log in as a guest and open `volume`; its ID.
    pub async fn guest_volume(addr: std::net::SocketAddr, volume: &str) -> (RawClient, u16) {
        let mut c = RawClient::connect(addr).await;
        c.open_session().await;
        assert_eq!(c.login(None).await, 0);
        let vol = c.open_vol(volume).await;
        (c, vol)
    }

    pub async fn open_vol(&mut self, name: &str) -> u16 {
        let bitmap = wire::vol_bit::VOLUME_ID | wire::vol_bit::NAME;
        let r = self
            .afp(&Request::OpenVol {
                bitmap,
                name: name.into(),
                has_password: false,
            })
            .await;
        assert_eq!(r.code, 0, "FPOpenVol {name}: {}", wire::error_name(r.code));
        let (bm, rest) = wire::be16_prefixed(&r.body).unwrap();
        wire::decode_vol_params(bm, rest).unwrap().id
    }

    pub async fn enumerate(&mut self, vol: u16, path: &[&str]) -> (i32, Vec<wire::NodeParams>) {
        let fb = wire::file_bit::SUPPORTED;
        let db = wire::dir_bit::SUPPORTED;
        let r = self
            .afp(&Request::Enumerate {
                kind: wire::EnumerateKind::Ext2,
                vol,
                dir: wire::ROOT_DID,
                file_bitmap: fb,
                dir_bitmap: db,
                req_count: 1000,
                start_index: 1,
                max_reply: 65_536,
                path: AfpPath::names(path),
            })
            .await;
        if r.code != 0 {
            return (r.code, Vec::new());
        }
        (
            0,
            wire::decode_enumerate_reply(wire::EnumerateKind::Ext2, &r.body).unwrap(),
        )
    }

    /// Open a fork; its reference number, or the error.
    pub async fn open_fork(
        &mut self,
        vol: u16,
        path: &[&str],
        mode: u16,
    ) -> Result<(u16, u64), i32> {
        let r = self
            .afp(&Request::OpenFork {
                resource: false,
                vol,
                dir: wire::ROOT_DID,
                bitmap: wire::file_bit::EXT_DATA_FORK_LEN,
                mode,
                path: AfpPath::names(path),
            })
            .await;
        if r.code != 0 {
            return Err(r.code);
        }
        Ok(wire::decode_open_fork_reply(&r.body).unwrap())
    }

    /// The recorded conversation through tshark's dsi and afp dissectors.
    pub fn oracle(&self) -> crate::helpers::pcap_oracle::PcapOracle {
        oracle_of(&self.chunks)
    }
}

/// A recorded conversation through tshark's dsi and afp dissectors.
pub fn oracle_of(chunks: &[(bool, Vec<u8>)]) -> crate::helpers::pcap_oracle::PcapOracle {
    let mut o = crate::helpers::pcap_oracle::PcapOracle::tcp("afp")
        .also_named("afp")
        .port(548);
    for (to_server, bytes) in chunks {
        o = if *to_server {
            o.to_server(bytes)
        } else {
            o.from_server(bytes)
        };
    }
    o
}
