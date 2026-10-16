//! AFP server — NetGet is an Apple file server whose volumes, directories and files the model
//! describes.
//!
//! A client opens a DSI session over TCP, logs in, opens a volume and walks it: it asks for a
//! directory's entries (FPEnumerate*), an item's parameters (FPGetFileDirParms), opens a file's
//! fork and reads it, and perhaps creates, writes and deletes. Rust runs all of that — framing,
//! request IDs, the login, CNIDs, reference numbers, bitmaps, names and dates — and asks the
//! model only for what a file server would read from its disk.
//!
//! ## What the model is asked
//!
//! - **Volumes** (`afp_list_volumes`) once per session, unless the `volumes` startup parameter
//!   fixes them.
//! - **A directory's entries** (`afp_list_directory`) the first time a session looks inside
//!   it, through whatever command does. The answer is kept for the session: enumerating it
//!   again, paging through it, or asking for one entry's parameters costs no model call.
//! - **A file's content** (`afp_read_file`) when a fork is opened for reading. Reads from that
//!   fork are served from the answer.
//! - **Each write, length change, create and delete** (`afp_write_file`, `afp_create`,
//!   `afp_delete`). An accepted one changes the listing NetGet keeps for the session — a
//!   created file appears empty, a deleted one disappears, a write changes the size — so the
//!   client sees the effect of what the model approved, and nothing it did not.
//!
//! The password of the Cleartxt Passwrd UAM is checked here against the configured one and
//! never reaches the model; a guest (No User Authent) login is admitted when `guest_access`
//! allows it.
//!
//! ## CNIDs
//!
//! Every file and directory has a catalog node ID, which clients keep (FPResolveID, a DID
//! passed back as the base of a path). NetGet assigns them per server from 17 upward, keyed by
//! volume and path, so an item keeps its ID across sessions while the server runs; the root is
//! 2 and its parent 1, as AFP defines.
//!
//! ## Failing closed
//!
//! A model call that fails, answers with something NetGet cannot use, or answers nothing is
//! answered kFPMiscErr — for a listing, a read, a volume list, a write, a create and a delete
//! alike — and never with an invented listing, invented content or a success nobody approved.
//! A refusal (`afp_deny`) answers the error the model named. Every event logs one `decision=`:
//! `model_answer`, `model_reject`, `model_silent`, `fail_closed_bad_action`,
//! `fail_closed_llm_error`, `fail_closed_llm_overloaded`.
pub mod actions;
pub mod dsi;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use actions::{AfpProtocol, EntryConfig, VolumeConfig};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use wire::{err, AfpPath, NodeParams, PathElement, Request};

/// Concurrent client sessions.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;
/// The read deadline before a new connection's first byte.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the rest of a message may take once its first byte arrived.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// NetGet sends a DSITickle after this long without sending anything, as AFP servers do, so a
/// client knows the server is alive.
pub const TICKLE_INTERVAL: Duration = Duration::from_secs(30);
/// How long a reply may take to leave: a client that stops reading is closed.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Forks one session may hold open.
pub const MAX_OPEN_FORKS: usize = 64;
/// Directory listings one session remembers; past this the memory is cleared and directories
/// are asked about again.
pub const MAX_CACHED_LISTINGS: usize = 256;
/// CNIDs one server assigns over its lifetime; past this, new items are refused kFPMiscErr.
pub const MAX_CNIDS: usize = 65_536;
/// Failed logins one connection may make before it is closed.
pub const MAX_LOGIN_FAILURES: u32 = 5;
/// The Unix IDs NetGet reports: the configured user, and a guest.
pub const USER_UID: u32 = 1000;
pub const GUEST_UID: u32 = 65_534;

/// What `actions.rs` validated from the startup parameters.
pub struct Config {
    pub server_name: String,
    pub volumes: Option<Vec<VolumeConfig>>,
    pub credentials: Option<(String, String)>,
    pub guest: bool,
    pub idle: Duration,
}

pub struct AfpServer;

/// Catalog node IDs, per server.
#[derive(Default)]
struct Cnids {
    by_key: HashMap<(String, String), u32>,
    by_id: HashMap<u32, (String, String, bool)>,
    next: u32,
}

impl Cnids {
    fn id(&mut self, vol: &str, path: &str, is_dir: bool) -> Option<u32> {
        let key = (vol.to_string(), path.to_string());
        if let Some(id) = self.by_key.get(&key) {
            if let Some(entry) = self.by_id.get_mut(id) {
                entry.2 = is_dir;
            }
            return Some(*id);
        }
        if self.by_id.len() >= MAX_CNIDS {
            return None;
        }
        if self.next < wire::FIRST_CNID {
            self.next = wire::FIRST_CNID;
        }
        let id = self.next;
        self.next = self.next.checked_add(1)?;
        self.by_key.insert(key, id);
        self.by_id
            .insert(id, (vol.to_string(), path.to_string(), is_dir));
        Some(id)
    }

    fn lookup(&self, id: u32) -> Option<(String, String, bool)> {
        self.by_id.get(&id).cloned()
    }
}

struct Shared {
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    config: Config,
    cnids: std::sync::Mutex<Cnids>,
    signature: [u8; 16],
}

/// An open fork.
struct Fork {
    vol: String,
    path: Vec<String>,
    resource: bool,
    mode: u16,
    /// The content the model gave, for a fork opened for reading (and kept current by
    /// accepted writes).
    content: Option<Vec<u8>>,
    length: u64,
}

/// One session's state.
#[derive(Default)]
struct Session {
    opened: bool,
    /// Who logged in: the configured user name or "guest".
    user: Option<String>,
    uid: u32,
    failures: u32,
    volumes: Option<Vec<VolumeConfig>>,
    open_vols: HashMap<u16, String>,
    listings: HashMap<(String, String), Vec<EntryConfig>>,
    /// Files created empty in this session (their content is known without asking).
    fresh: HashSet<(String, String)>,
    forks: HashMap<u16, Fork>,
    next_fork: u16,
    close: bool,
}

/// Where a path led.
#[derive(Debug, Clone)]
enum Item {
    Root,
    Entry(EntryConfig),
    Missing,
}

struct Resolved {
    vol: VolumeConfig,
    /// The item's full path from the volume root (for `Missing`, the name it would have).
    path: Vec<String>,
    item: Item,
}

fn join(path: &[String]) -> String {
    path.join("/")
}

struct Conn {
    shared: Arc<Shared>,
    connection_id: ConnectionId,
    remote: SocketAddr,
    local: SocketAddr,
    s: Session,
}

/// What an event's answer came to.
enum Decided {
    Answer(Value),
    Code(i32),
}

impl AfpServer {
    pub async fn spawn(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        config: Config,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let mut signature = [0u8; 16];
        rand::Rng::fill(&mut rand::thread_rng(), &mut signature[..]);
        let uams = uams(&config).join(", ");
        // The E2E harness parses the port out of everything after the last "on ".
        Log::new(Some(&status_tx)).info(format!(
            "AFP server \"{}\" ({uams}) listening on {local_addr}",
            config.server_name
        ));
        let shared = Arc::new(Shared {
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            server_id,
            config,
            cnids: std::sync::Mutex::new(Cnids::default()),
            signature,
        });
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let registrar = app_state.clone();
        let accept = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    // DSI has no "busy" a client reads before it has sent anything.
                    b"",
                    "AFP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote, permit)) => {
                        let shared = shared.clone();
                        let local = stream.local_addr().unwrap_or(local_addr);
                        let owner = app_state.clone();
                        owner
                            .spawn_server_task(server_id, async move {
                                let _permit = permit;
                                if let Err(e) =
                                    handle_connection(shared.clone(), stream, remote, local).await
                                {
                                    Log::new(Some(&shared.status_tx)).debug(format!(
                                        "AFP connection from {remote} ended: {e:#}"
                                    ));
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("AFP accept failed, stopping loop: {e}"));
                        break;
                    }
                }
            }
        });
        registrar.register_server_task(server_id, accept).await;
        Ok(local_addr)
    }
}

fn uams(config: &Config) -> Vec<String> {
    let mut v = Vec::new();
    if config.guest {
        v.push(wire::uam::NO_USER_AUTHENT.to_string());
    }
    if config.credentials.is_some() {
        v.push(wire::uam::CLEARTXT_PASSWRD.to_string());
    }
    v
}

/// What one read from the socket produced.
enum Incoming {
    Message(dsi::Header, Vec<u8>),
    Closed,
}

async fn handle_connection(
    shared: Arc<Shared>,
    stream: TcpStream,
    remote: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let app_state = shared.app_state.clone();
    let server_id = shared.server_id;
    let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = tokio::io::split(stream);
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id: connection_id,
                remote_addr: remote,
                local_addr: local,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::empty(),
            },
        )
        .await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    let idle = shared.config.idle;
    let mut conn = Conn {
        shared: shared.clone(),
        connection_id,
        remote,
        local,
        s: Session {
            next_fork: 1,
            ..Default::default()
        },
    };
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    let mut first = true;
    let mut tickle_id: u16 = 0;
    let result: Result<()> = async {
        let mut last_heard = tokio::time::Instant::now();
        let mut last_sent = tokio::time::Instant::now();
        let mut partial_since: Option<tokio::time::Instant> = None;
        loop {
            // A whole message in the buffer?
            let incoming = loop {
                if buf.len() >= dsi::HEADER_LEN {
                    let mut h = [0u8; dsi::HEADER_LEN];
                    h.copy_from_slice(&buf[..dsi::HEADER_LEN]);
                    let header = dsi::Header::parse(&h);
                    let len = match header.check_length() {
                        Ok(n) => n,
                        Err(e) => {
                            conn.log().warn(format!(
                                "AFP {remote}: {e}; closing decision=protocol_error"
                            ));
                            return Ok(());
                        }
                    };
                    if buf.len() >= dsi::HEADER_LEN + len {
                        let payload = buf[dsi::HEADER_LEN..dsi::HEADER_LEN + len].to_vec();
                        buf.drain(..dsi::HEADER_LEN + len);
                        partial_since = (!buf.is_empty()).then(tokio::time::Instant::now);
                        break Incoming::Message(header, payload);
                    }
                }
                let wake = if let Some(since) = partial_since {
                    since + MESSAGE_TIMEOUT
                } else if first {
                    last_heard + FIRST_BYTE_TIMEOUT.min(idle)
                } else {
                    (last_heard + idle).min(last_sent + TICKLE_INTERVAL)
                };
                match tokio::time::timeout_at(wake, rd.read(&mut chunk)).await {
                    Ok(Ok(0)) => break Incoming::Closed,
                    Ok(Ok(n)) => {
                        if buf.is_empty() {
                            partial_since = Some(tokio::time::Instant::now());
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        last_heard = tokio::time::Instant::now();
                        first = false;
                        app_state
                            .update_connection_stats(
                                server_id,
                                connection_id,
                                Some(n as u64),
                                None,
                                Some(1),
                                None,
                            )
                            .await;
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {
                        let now = tokio::time::Instant::now();
                        if partial_since.is_some() {
                            conn.log().info(format!(
                                "AFP {remote}: a message started and did not finish within \
                                 {MESSAGE_TIMEOUT:?}; closing decision=protocol_timeout"
                            ));
                            return Ok(());
                        }
                        if first || now >= last_heard + idle {
                            conn.log().info(format!(
                                "AFP client {remote} silent for {:?}; closing \
                                 decision=protocol_timeout",
                                now - last_heard
                            ));
                            return Ok(());
                        }
                        // Quiet, but not for long enough to give up: tickle.
                        tickle_id = tickle_id.wrapping_add(1);
                        let t = dsi::message(
                            dsi::FLAG_REQUEST,
                            dsi::command::TICKLE,
                            tickle_id,
                            0,
                            &[],
                        );
                        send(&mut wr, &t).await?;
                        last_sent = now;
                    }
                }
            };
            let (header, payload) = match incoming {
                Incoming::Closed => return Ok(()),
                Incoming::Message(h, p) => (h, p),
            };
            if header.flags != dsi::FLAG_REQUEST {
                // A client's reply to our tickle, or noise: nothing to answer.
                conn.log().debug(format!(
                    "AFP {remote}: {} reply ignored",
                    dsi::command_name(header.command)
                ));
                continue;
            }
            let reply = match conn.dsi(&header, &payload).await {
                Some(r) => r,
                None => return Ok(()),
            };
            if !reply.is_empty() {
                send(&mut wr, &reply).await?;
                last_sent = tokio::time::Instant::now();
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(reply.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
            }
            if conn.s.close {
                return Ok(());
            }
        }
    }
    .await;
    let _ = wr.shutdown().await;
    app_state
        .remove_connection_from_server(server_id, connection_id)
        .await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    result
}

impl Conn {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.shared.status_tx))
    }

    fn user(&self) -> String {
        self.s.user.clone().unwrap_or_else(|| "guest".into())
    }

    /// One DSI request: the bytes to send back (empty for none), or `None` to close.
    async fn dsi(&mut self, h: &dsi::Header, payload: &[u8]) -> Option<Vec<u8>> {
        match h.command {
            dsi::command::GET_STATUS => {
                // A status request outside a session is the whole conversation: the server
                // answers and closes, as netatalk does (asip-status reads until EOF).
                if !self.s.opened {
                    self.s.close = true;
                }
                Some(dsi::reply(h, 0, &self.server_info()))
            }
            dsi::command::OPEN_SESSION => {
                if let Err(e) = dsi::parse_options(payload) {
                    self.log().warn(format!(
                        "AFP {}: DSIOpenSession options unreadable ({e}); refused \
                         decision=protocol_error",
                        self.remote
                    ));
                    return Some(dsi::reply(h, err::PARAM_ERR, &[]));
                }
                self.s.opened = true;
                let options = dsi::encode_options(&[(
                    dsi::option::SERVER_REQUEST_QUANTUM,
                    dsi::REQUEST_QUANTUM.to_be_bytes().to_vec(),
                )]);
                Some(dsi::reply(h, 0, &options))
            }
            dsi::command::CLOSE_SESSION => {
                self.log()
                    .debug(format!("AFP {}: DSICloseSession", self.remote));
                None
            }
            dsi::command::TICKLE => Some(Vec::new()),
            dsi::command::COMMAND | dsi::command::WRITE => {
                let (block, data) = if h.command == dsi::command::WRITE {
                    match dsi::split_write(h, payload) {
                        Ok((n, _)) => (&payload[..n], &payload[n..]),
                        Err(e) => {
                            self.log()
                                .warn(format!("AFP {}: {e} decision=protocol_error", self.remote));
                            return Some(dsi::reply(h, err::PARAM_ERR, &[]));
                        }
                    }
                } else {
                    (payload, &payload[payload.len()..])
                };
                if block.len() > dsi::MAX_COMMAND_LEN {
                    self.log().warn(format!(
                        "AFP {}: a {}-byte command block exceeds {} decision=protocol_error",
                        self.remote,
                        block.len(),
                        dsi::MAX_COMMAND_LEN
                    ));
                    return Some(dsi::reply(h, err::PARAM_ERR, &[]));
                }
                if !self.s.opened {
                    self.log().warn(format!(
                        "AFP {}: {} before DSIOpenSession; closing decision=protocol_error",
                        self.remote,
                        dsi::command_name(h.command)
                    ));
                    return None;
                }
                let (code, out) = self.afp(block, data).await;
                Some(dsi::reply(h, code, &out))
            }
            other => {
                self.log().info(format!(
                    "AFP {}: {} ({other}) is not a request a server answers; ignored",
                    self.remote,
                    dsi::command_name(other)
                ));
                Some(Vec::new())
            }
        }
    }

    fn server_info(&self) -> Vec<u8> {
        let mut addresses = Vec::new();
        if let SocketAddr::V4(a) = self.local {
            if !a.ip().is_unspecified() {
                let mut b = a.ip().octets().to_vec();
                if a.port() == 548 {
                    addresses.push((1u8, b));
                } else {
                    b.extend_from_slice(&a.port().to_be_bytes());
                    addresses.push((2u8, b));
                }
            }
        } else if let SocketAddr::V6(a) = self.local {
            let mut b = a.ip().octets().to_vec();
            if a.port() == 548 {
                addresses.push((6u8, b));
            } else {
                b.extend_from_slice(&a.port().to_be_bytes());
                addresses.push((7u8, b));
            }
        }
        // Directory services is advertised (with no directory names), as netatalk does: clients
        // such as asip-status read the UTF-8 server name's offset after the directory names'
        // only when this bit says that offset is there.
        let mut flags = wire::srvr_flag::SERVER_SIGNATURE
            | wire::srvr_flag::UTF8_SERVER_NAME
            | wire::srvr_flag::DIRECTORY_SERVICES;
        if !addresses.is_empty() {
            flags |= wire::srvr_flag::TCP_IP;
        }
        wire::encode_server_info(&wire::ServerInfo {
            machine_type: "NetGet".into(),
            versions: wire::AFP_VERSIONS.iter().map(|s| s.to_string()).collect(),
            uams: uams(&self.shared.config),
            flags,
            server_name: self.shared.config.server_name.clone(),
            signature: Some(self.shared.signature),
            addresses,
            utf8_server_name: Some(self.shared.config.server_name.clone()),
        })
    }

    /// One AFP command: result code and reply payload.
    async fn afp(&mut self, block: &[u8], data: &[u8]) -> (i32, Vec<u8>) {
        let req = match wire::parse_request(block) {
            Ok(r) => r,
            Err(e) => {
                self.log().warn(format!(
                    "AFP {} {}: {e} decision=protocol_error",
                    self.remote,
                    wire::command_name(block.first().copied().unwrap_or(0))
                ));
                return (e.code, Vec::new());
            }
        };
        let name = req.name();
        let public = matches!(
            req,
            Request::GetSrvrInfo
                | Request::Login(_)
                | Request::LoginCont
                | Request::Unsupported { .. }
        );
        if !public && self.s.user.is_none() {
            self.log().info(format!(
                "AFP {} {name} before a login: kFPUserNotAuth",
                self.remote
            ));
            return (err::USER_NOT_AUTH, Vec::new());
        }
        let (code, out) = match req {
            Request::GetSrvrInfo => (0, self.server_info()),
            Request::Login(l) => self.login(l),
            Request::LoginCont => (err::CALL_NOT_SUPPORTED, Vec::new()),
            Request::Logout => {
                let opened = self.s.opened;
                self.s = Session {
                    opened,
                    next_fork: 1,
                    ..Default::default()
                };
                (0, Vec::new())
            }
            Request::GetSrvrParms => match self.volumes().await {
                Ok(v) => (
                    0,
                    wire::encode_srvr_parms(
                        wire::now(),
                        &v.iter()
                            .map(|v| wire::VolumeListing {
                                name: v.name.clone(),
                                has_password: false,
                            })
                            .collect::<Vec<_>>(),
                    ),
                ),
                Err(code) => (code, Vec::new()),
            },
            Request::OpenVol { bitmap, name, .. } => self.open_vol(bitmap, &name).await,
            Request::CloseVol { vol } => {
                if self.s.open_vols.remove(&vol).is_some() {
                    let still_open: HashSet<String> = self.s.open_vols.values().cloned().collect();
                    self.s.forks.retain(|_, f| still_open.contains(&f.vol));
                    (0, Vec::new())
                } else {
                    (err::PARAM_ERR, Vec::new())
                }
            }
            Request::GetVolParms { vol, bitmap } => match self.open_volume(vol) {
                Ok(v) => match wire::encode_vol_params(bitmap, &self.vol_params(vol, &v)) {
                    Ok(p) => {
                        let mut out = bitmap.to_be_bytes().to_vec();
                        out.extend(p);
                        (0, out)
                    }
                    Err(c) => (c, Vec::new()),
                },
                Err(c) => (c, Vec::new()),
            },
            Request::GetFileDirParms {
                vol,
                dir,
                file_bitmap,
                dir_bitmap,
                path,
            } => self
                .get_file_dir_parms(vol, dir, file_bitmap, dir_bitmap, &path)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::Enumerate {
                kind,
                vol,
                dir,
                file_bitmap,
                dir_bitmap,
                req_count,
                start_index,
                max_reply,
                path,
            } => self
                .enumerate(
                    kind,
                    vol,
                    dir,
                    file_bitmap,
                    dir_bitmap,
                    req_count,
                    start_index,
                    max_reply,
                    &path,
                )
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::OpenFork {
                resource,
                vol,
                dir,
                bitmap,
                mode,
                path,
            } => self
                .open_fork(resource, vol, dir, bitmap, mode, &path)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::Read {
                fork,
                offset,
                count,
                ..
            } => self.read(fork, offset, count),
            Request::Write {
                ext,
                from_end,
                fork,
                offset,
                count,
            } => self
                .write(ext, from_end, fork, offset, count, data)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::GetForkParms { fork, bitmap } => self
                .get_fork_parms(fork, bitmap)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::SetForkParms {
                fork,
                bitmap,
                length,
            } => self
                .set_fork_parms(fork, bitmap, length)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::FlushFork { fork } => {
                if self.s.forks.contains_key(&fork) {
                    (0, Vec::new())
                } else {
                    (err::PARAM_ERR, Vec::new())
                }
            }
            Request::Flush { vol } => match self.open_volume(vol) {
                Ok(_) => (0, Vec::new()),
                Err(c) => (c, Vec::new()),
            },
            Request::CloseFork { fork } => {
                if self.s.forks.remove(&fork).is_some() {
                    (0, Vec::new())
                } else {
                    (err::PARAM_ERR, Vec::new())
                }
            }
            Request::CreateFile {
                hard,
                vol,
                dir,
                path,
            } => self
                .create(vol, dir, &path, false, hard)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::CreateDir { vol, dir, path } => self
                .create(vol, dir, &path, true, false)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::Delete { vol, dir, path } => self
                .delete(vol, dir, &path)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::ResolveId { vol, id, bitmap } => self
                .resolve_id(vol, id, bitmap)
                .await
                .unwrap_or_else(|c| (c, Vec::new())),
            Request::GetUserInfo {
                this_user,
                user_id,
                bitmap,
            } => self.user_info(this_user, user_id, bitmap),
            Request::Unsupported { code } => {
                self.log().info(format!(
                    "AFP {} {} ({code}) is not implemented: kFPCallNotSupported",
                    self.remote,
                    wire::command_name(code)
                ));
                (err::CALL_NOT_SUPPORTED, Vec::new())
            }
        };
        if code != 0 && code != err::EOF_ERR {
            self.log().debug(format!(
                "AFP {} {name}: {} ({code})",
                self.remote,
                wire::error_name(code)
            ));
        }
        (code, out)
    }

    fn login(&mut self, l: wire::Login) -> (i32, Vec<u8>) {
        if !wire::AFP_VERSIONS.contains(&l.version.as_str()) {
            self.log().info(format!(
                "AFP {} login with {:?}: kFPBadVersNum (NetGet speaks {})",
                self.remote,
                l.version,
                wire::AFP_VERSIONS.join(", ")
            ));
            return (err::BAD_VERS_NUM, Vec::new());
        }
        let config = &self.shared.config;
        let outcome = match l.uam.as_str() {
            wire::uam::NO_USER_AUTHENT if config.guest => Ok(("guest".to_string(), GUEST_UID)),
            wire::uam::CLEARTXT_PASSWRD => match &config.credentials {
                Some((user, password)) => {
                    let given_user = l.user.clone().unwrap_or_default();
                    let given = l.password.clone().unwrap_or_default();
                    // AFP's cleartext password is eight bytes: a longer one is compared on
                    // what fits, as every AFP server does.
                    let want = &password.as_bytes()[..password.len().min(wire::PASSWORD_LEN)];
                    if given_user == *user && constant_time_eq(&given, want) {
                        Ok((user.clone(), USER_UID))
                    } else {
                        Err(err::USER_NOT_AUTH)
                    }
                }
                None => Err(err::BAD_UAM),
            },
            _ => Err(err::BAD_UAM),
        };
        match outcome {
            Ok((user, uid)) => {
                self.log().info(format!(
                    "AFP {} logged in as {user} ({}, {}) decision=login_accepted",
                    self.remote, l.uam, l.version
                ));
                self.s.user = Some(user);
                self.s.uid = uid;
                (0, Vec::new())
            }
            Err(code) => {
                if code == err::USER_NOT_AUTH {
                    self.s.failures += 1;
                    if self.s.failures >= MAX_LOGIN_FAILURES {
                        self.s.close = true;
                    }
                }
                self.log().warn(format!(
                    "AFP {} login refused ({} for user {:?}): {} decision=login_refused{}",
                    self.remote,
                    l.uam,
                    l.user.as_deref().unwrap_or(""),
                    wire::error_name(code),
                    if self.s.close {
                        "; closing after repeated failures"
                    } else {
                        ""
                    }
                ));
                (code, Vec::new())
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Asking the model
    // ---------------------------------------------------------------------------------------

    /// Raise `event` and reduce the model's answer to the action named `expected` or an AFP
    /// error. Logs the decision.
    async fn decide(&self, event: &Event, expected: &str, what: &str) -> Decided {
        let log = self.log();
        let x = match call_llm(
            &self.shared.llm_client,
            &self.shared.app_state,
            self.shared.server_id,
            Some(self.connection_id),
            event,
            &AfpProtocol::new(),
        )
        .await
        {
            Ok(x) => x,
            Err(e) => {
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                log.debug(format!("AFP {what}: model call failed: {e:#}"));
                log.error(format!(
                    "AFP {what} not answered by the model; kFPMiscErr decision={tag}"
                ));
                return Decided::Code(err::MISC_ERR);
            }
        };
        for m in x.messages {
            let _ = self.shared.status_tx.send(m);
        }
        let mut results = Vec::new();
        flatten(x.protocol_results, &mut results);
        let chosen = results.into_iter().find_map(|r| match r {
            ActionResult::Custom { name, data } => Some((name, data)),
            _ => None,
        });
        let refused = x
            .failures
            .iter()
            .map(|f| format!("{}: {}", f.action, f.error))
            .collect::<Vec<_>>()
            .join("; ");
        match chosen {
            Some((name, data)) if name == expected => {
                log.info(format!("AFP {what} decision=model_answer"));
                Decided::Answer(data)
            }
            Some((name, data)) if name == actions::RESULT_DENY => {
                let code = actions::deny_code(&data).unwrap_or(err::ACCESS_DENIED);
                log.info(format!(
                    "AFP {what} decision=model_reject: {} ({})",
                    wire::error_name(code),
                    data["reason"].as_str().unwrap_or("no reason given")
                ));
                Decided::Code(code)
            }
            Some((name, _)) => {
                log.error(format!(
                    "AFP {what}: the model answered {name}, which does not answer it; \
                     kFPMiscErr decision=fail_closed_bad_action"
                ));
                Decided::Code(err::MISC_ERR)
            }
            None if !refused.is_empty() => {
                log.error(format!(
                    "AFP {what} produced no usable action ({refused}); kFPMiscErr \
                     decision=fail_closed_bad_action"
                ));
                Decided::Code(err::MISC_ERR)
            }
            None => {
                log.warn(format!(
                    "AFP {what} produced no action; kFPMiscErr decision=model_silent"
                ));
                Decided::Code(err::MISC_ERR)
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Volumes, listings, resolution
    // ---------------------------------------------------------------------------------------

    async fn volumes(&mut self) -> Result<Vec<VolumeConfig>, i32> {
        if let Some(v) = &self.shared.config.volumes {
            return Ok(v.clone());
        }
        if let Some(v) = &self.s.volumes {
            return Ok(v.clone());
        }
        let event = Event::new(&actions::LIST_VOLUMES_EVENT, json!({"user": self.user()}));
        match self
            .decide(&event, actions::RESULT_VOLUMES, "volume list")
            .await
        {
            Decided::Answer(data) => {
                match actions::volumes_from_json(&data["volumes"], wire::now()) {
                    Ok(v) => {
                        self.s.volumes = Some(v.clone());
                        Ok(v)
                    }
                    Err(e) => {
                        self.log().error(format!(
                            "AFP volume list unusable ({e:#}); kFPMiscErr \
                             decision=fail_closed_bad_action"
                        ));
                        Err(err::MISC_ERR)
                    }
                }
            }
            Decided::Code(c) => Err(c),
        }
    }

    fn open_volume(&self, vol: u16) -> Result<VolumeConfig, i32> {
        let name = self.s.open_vols.get(&vol).ok_or(err::PARAM_ERR)?;
        let all = self
            .shared
            .config
            .volumes
            .as_ref()
            .or(self.s.volumes.as_ref())
            .ok_or(err::PARAM_ERR)?;
        all.iter()
            .find(|v| v.name == *name)
            .cloned()
            .ok_or(err::PARAM_ERR)
    }

    fn vol_params(&self, id: u16, v: &VolumeConfig) -> wire::VolumeParams {
        use wire::vol_attr::*;
        let mut attributes =
            SUPPORTS_FILE_IDS | SUPPORTS_UNIX_PRIVS | SUPPORTS_UTF8_NAMES | NO_NETWORK_USER_IDS;
        if v.read_only {
            attributes |= READ_ONLY;
        }
        wire::VolumeParams {
            attributes,
            signature: wire::VOLUME_SIGNATURE_FIXED,
            created: v.created,
            modified: v.created,
            backup: wire::DATE_NEVER,
            id,
            bytes_free: if v.read_only { 0 } else { 32 << 30 },
            bytes_total: 64 << 30,
            name: v.name.clone(),
            block_size: 4096,
        }
    }

    async fn open_vol(&mut self, bitmap: u16, name: &str) -> (i32, Vec<u8>) {
        if bitmap & wire::vol_bit::VOLUME_ID == 0 || bitmap & !wire::vol_bit::ALL != 0 {
            return (err::BITMAP_ERR, Vec::new());
        }
        let vols = match self.volumes().await {
            Ok(v) => v,
            Err(c) => return (c, Vec::new()),
        };
        let wanted = wire::normalize(name);
        let Some((i, v)) = vols.iter().enumerate().find(|(_, v)| {
            v.name == wanted
                || wire::mac_roman_decode(&wire::mac_roman_encode(&v.name, 255))
                    .eq_ignore_ascii_case(&wanted)
                || v.name.to_lowercase() == wanted.to_lowercase()
        }) else {
            self.log().info(format!(
                "AFP {} FPOpenVol {wanted:?}: no such volume",
                self.remote
            ));
            return (err::OBJECT_NOT_FOUND, Vec::new());
        };
        let id = (i + 1) as u16;
        self.s.open_vols.insert(id, v.name.clone());
        match wire::encode_vol_params(bitmap, &self.vol_params(id, v)) {
            Ok(p) => {
                let mut out = bitmap.to_be_bytes().to_vec();
                out.extend(p);
                (0, out)
            }
            Err(c) => (c, Vec::new()),
        }
    }

    /// A directory's entries: remembered, or asked of the model.
    async fn listing(
        &mut self,
        vol: &VolumeConfig,
        path: &[String],
    ) -> Result<Vec<EntryConfig>, i32> {
        let key = (vol.name.clone(), join(path));
        if let Some(l) = self.s.listings.get(&key) {
            return Ok(l.clone());
        }
        let event = Event::new(
            &actions::LIST_DIRECTORY_EVENT,
            json!({"user": self.user(), "volume": vol.name, "path": join(path)}),
        );
        let what = format!("listing of {}:/{}", vol.name, join(path));
        match self.decide(&event, actions::RESULT_LISTING, &what).await {
            Decided::Answer(data) => match actions::entries_from_json(&data, wire::now()) {
                Ok(entries) => {
                    if self.s.listings.len() >= MAX_CACHED_LISTINGS {
                        self.s.listings.clear();
                    }
                    self.s.listings.insert(key, entries.clone());
                    Ok(entries)
                }
                Err(e) => {
                    self.log().error(format!(
                        "AFP {what} unusable ({e:#}); kFPMiscErr decision=fail_closed_bad_action"
                    ));
                    Err(err::MISC_ERR)
                }
            },
            Decided::Code(c) => Err(c),
        }
    }

    /// The entry naming the directory at `path` (`None` for the root).
    async fn dir_entry(
        &mut self,
        vol: &VolumeConfig,
        path: &[String],
    ) -> Result<Option<EntryConfig>, i32> {
        let Some((name, parent)) = path.split_last() else {
            return Ok(None);
        };
        let l = self.listing(vol, parent).await?;
        l.into_iter()
            .find(|e| e.name == *name)
            .map(Some)
            .ok_or(err::OBJECT_NOT_FOUND)
    }

    async fn resolve(&mut self, vol_id: u16, did: u32, path: &AfpPath) -> Result<Resolved, i32> {
        let vol = self.open_volume(vol_id)?;
        let mut elements = path.elements.as_slice();
        let (mut cur, mut item) = match did {
            wire::ROOT_DID => (Vec::new(), Item::Root),
            wire::ROOT_PARENT_DID => match elements.first() {
                Some(PathElement::Name(n)) if n.eq_ignore_ascii_case(&vol.name) => {
                    elements = &elements[1..];
                    (Vec::new(), Item::Root)
                }
                _ => return Err(err::OBJECT_NOT_FOUND),
            },
            id => {
                let found = self.shared.cnids.lock().ok().and_then(|c| c.lookup(id));
                match found {
                    Some((v, p, true)) if v == vol.name => {
                        let parts: Vec<String> = p.split('/').map(str::to_string).collect();
                        let e = self.dir_entry(&vol, &parts).await?;
                        (parts, e.map(Item::Entry).unwrap_or(Item::Root))
                    }
                    _ => return Err(err::OBJECT_NOT_FOUND),
                }
            }
        };
        for el in elements {
            let in_dir = matches!(&item, Item::Root) || matches!(&item, Item::Entry(e) if e.is_dir);
            if !in_dir {
                return Err(err::OBJECT_NOT_FOUND);
            }
            match el {
                PathElement::Name(n) => {
                    let l = self.listing(&vol, &cur).await?;
                    let found = l
                        .iter()
                        .find(|e| e.name == *n)
                        .or_else(|| l.iter().find(|e| e.name.to_lowercase() == n.to_lowercase()))
                        .cloned();
                    match found {
                        Some(e) => {
                            cur.push(e.name.clone());
                            item = Item::Entry(e);
                        }
                        None => {
                            cur.push(n.clone());
                            item = Item::Missing;
                        }
                    }
                }
                PathElement::Parent => {
                    if cur.pop().is_none() {
                        return Err(err::PARAM_ERR);
                    }
                    item = match self.dir_entry(&vol, &cur).await? {
                        Some(e) => Item::Entry(e),
                        None => Item::Root,
                    };
                }
            }
        }
        Ok(Resolved {
            vol,
            path: cur,
            item,
        })
    }

    fn cnid(&self, vol: &str, path: &[String], is_dir: bool) -> Result<u32, i32> {
        if path.is_empty() {
            return Ok(wire::ROOT_DID);
        }
        let id = self
            .shared
            .cnids
            .lock()
            .ok()
            .and_then(|mut c| c.id(vol, &join(path), is_dir));
        id.ok_or_else(|| {
            self.log().error(format!(
                "AFP: {MAX_CNIDS} catalog node IDs are in use; kFPMiscErr \
                 decision=fail_closed_cnid_exhausted"
            ));
            err::MISC_ERR
        })
    }

    fn node(
        &self,
        vol: &VolumeConfig,
        path: &[String],
        entry: Option<&EntryConfig>,
    ) -> Result<NodeParams, i32> {
        let uid = self.s.uid;
        let (is_dir, name, created, modified, perms, read_only, size) = match entry {
            None => (
                true,
                vol.name.clone(),
                vol.created,
                vol.created,
                if vol.read_only { 0o555 } else { 0o755 },
                vol.read_only,
                0,
            ),
            Some(e) => (
                e.is_dir,
                e.name.clone(),
                e.created,
                e.modified,
                e.permissions,
                e.read_only || vol.read_only,
                e.size,
            ),
        };
        let node_id = self.cnid(&vol.name, path, is_dir)?;
        let parent_id = match path.split_last() {
            None => wire::ROOT_PARENT_DID,
            Some((_, parent)) => self.cnid(&vol.name, parent, true)?,
        };
        let mode = (if is_dir { 0o040000 } else { 0o100000 }) | perms;
        let access = wire::access_rights(mode, !read_only);
        let mut attributes = 0;
        if read_only && !is_dir {
            attributes |=
                wire::attr::WRITE_INHIBIT | wire::attr::RENAME_INHIBIT | wire::attr::DELETE_INHIBIT;
        }
        if name.starts_with('.') {
            attributes |= wire::attr::INVISIBLE;
        }
        let offspring = if is_dir {
            self.s
                .listings
                .get(&(vol.name.clone(), join(path)))
                .map(|l| l.len().min(u16::MAX as usize) as u16)
                .unwrap_or(0)
        } else {
            0
        };
        Ok(NodeParams {
            is_dir,
            attributes,
            parent_id,
            created,
            modified,
            backup: wire::DATE_NEVER,
            finder_info: [0; 32],
            name,
            node_id,
            data_len: size,
            rsrc_len: 0,
            offspring,
            owner_id: uid,
            group_id: uid,
            access,
            unix: wire::UnixPrivs {
                uid,
                gid: uid,
                mode,
                access,
            },
        })
    }

    fn node_of(&self, r: &Resolved) -> Result<NodeParams, i32> {
        match &r.item {
            Item::Root => self.node(&r.vol, &r.path, None),
            Item::Entry(e) => self.node(&r.vol, &r.path, Some(e)),
            Item::Missing => Err(err::OBJECT_NOT_FOUND),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Commands
    // ---------------------------------------------------------------------------------------

    async fn get_file_dir_parms(
        &mut self,
        vol: u16,
        dir: u32,
        file_bitmap: u16,
        dir_bitmap: u16,
        path: &AfpPath,
    ) -> Result<(i32, Vec<u8>), i32> {
        if file_bitmap == 0 && dir_bitmap == 0 {
            return Err(err::BITMAP_ERR);
        }
        let r = self.resolve(vol, dir, path).await?;
        let n = self.node_of(&r)?;
        Ok((0, wire::encode_file_dir_reply(file_bitmap, dir_bitmap, &n)?))
    }

    #[allow(clippy::too_many_arguments)]
    async fn enumerate(
        &mut self,
        kind: wire::EnumerateKind,
        vol: u16,
        dir: u32,
        file_bitmap: u16,
        dir_bitmap: u16,
        req_count: u16,
        start_index: u32,
        max_reply: u32,
        path: &AfpPath,
    ) -> Result<(i32, Vec<u8>), i32> {
        if file_bitmap == 0 && dir_bitmap == 0 {
            return Err(err::BITMAP_ERR);
        }
        if req_count == 0 || start_index == 0 {
            return Err(err::PARAM_ERR);
        }
        let r = self.resolve(vol, dir, path).await?;
        match &r.item {
            Item::Root => {}
            Item::Entry(e) if e.is_dir => {}
            Item::Entry(_) => return Err(err::OBJECT_TYPE_ERR),
            Item::Missing => return Err(err::OBJECT_NOT_FOUND),
        }
        let entries: Vec<EntryConfig> = self
            .listing(&r.vol, &r.path)
            .await?
            .into_iter()
            .filter(|e| {
                if e.is_dir {
                    dir_bitmap != 0
                } else {
                    file_bitmap != 0
                }
            })
            .collect();
        let start = (start_index - 1) as usize;
        if start >= entries.len() {
            return Err(err::OBJECT_NOT_FOUND);
        }
        let take = (req_count as usize).min(wire::MAX_ENUMERATE_ENTRIES);
        let mut nodes = Vec::with_capacity(take.min(entries.len() - start));
        for e in entries.iter().skip(start).take(take) {
            let mut p = r.path.clone();
            p.push(e.name.clone());
            nodes.push(self.node(&r.vol, &p, Some(e))?);
        }
        let max_size = (max_reply as usize).min(dsi::REQUEST_QUANTUM as usize);
        let (out, count) =
            wire::encode_enumerate_reply(kind, file_bitmap, dir_bitmap, &nodes, take, max_size)?;
        self.log().debug(format!(
            "AFP {} enumerate {}:/{} from {start_index}: {count} of {} entries",
            self.remote,
            r.vol.name,
            join(&r.path),
            entries.len()
        ));
        Ok((0, out))
    }

    async fn open_fork(
        &mut self,
        resource: bool,
        vol: u16,
        dir: u32,
        bitmap: u16,
        mode: u16,
        path: &AfpPath,
    ) -> Result<(i32, Vec<u8>), i32> {
        if bitmap & !wire::file_bit::SUPPORTED != 0 {
            return Err(err::BITMAP_ERR);
        }
        let r = self.resolve(vol, dir, path).await?;
        let entry = match &r.item {
            Item::Entry(e) if !e.is_dir => e.clone(),
            Item::Entry(_) | Item::Root => return Err(err::OBJECT_TYPE_ERR),
            Item::Missing => return Err(err::OBJECT_NOT_FOUND),
        };
        if self.s.forks.len() >= MAX_OPEN_FORKS {
            self.log().warn(format!(
                "AFP {}: {MAX_OPEN_FORKS} forks already open; kFPTooManyFilesOpen",
                self.remote
            ));
            return Err(err::TOO_MANY_FILES_OPEN);
        }
        let wants_write = mode & wire::open_mode::WRITE != 0;
        if wants_write && (r.vol.read_only || entry.read_only) {
            return Err(err::ACCESS_DENIED);
        }
        let key = (r.vol.name.clone(), join(&r.path));
        let (content, length) = if resource {
            (Some(Vec::new()), 0)
        } else if mode & wire::open_mode::READ != 0 {
            let bytes = if self.s.fresh.contains(&key) {
                Vec::new()
            } else {
                let event = Event::new(
                    &actions::READ_FILE_EVENT,
                    json!({
                        "user": self.user(),
                        "volume": r.vol.name,
                        "path": join(&r.path),
                        "size": entry.size,
                    }),
                );
                let what = format!("read of {}:/{}", r.vol.name, join(&r.path));
                match self.decide(&event, actions::RESULT_CONTENT, &what).await {
                    Decided::Answer(data) => match actions::content_from_json(&data) {
                        Ok(b) => b,
                        Err(e) => {
                            self.log().error(format!(
                                "AFP {what} unusable ({e:#}); kFPMiscErr \
                                 decision=fail_closed_bad_action"
                            ));
                            return Err(err::MISC_ERR);
                        }
                    },
                    Decided::Code(c) => return Err(c),
                }
            };
            let n = bytes.len() as u64;
            self.set_size(&r.vol.name, &r.path, n, false);
            (Some(bytes), n)
        } else {
            (None, entry.size)
        };
        let refnum = self.next_refnum();
        let mut n = self.node_of(&r)?;
        n.data_len = if resource { entry.size } else { length };
        let params = wire::encode_node_params(bitmap, &n)?;
        self.s.forks.insert(
            refnum,
            Fork {
                vol: r.vol.name.clone(),
                path: r.path.clone(),
                resource,
                mode,
                content,
                length,
            },
        );
        let mut out = bitmap.to_be_bytes().to_vec();
        out.extend_from_slice(&refnum.to_be_bytes());
        out.extend(params);
        Ok((0, out))
    }

    fn next_refnum(&mut self) -> u16 {
        loop {
            let r = self.s.next_fork;
            self.s.next_fork = self.s.next_fork.wrapping_add(1).max(1);
            if r != 0 && !self.s.forks.contains_key(&r) {
                return r;
            }
        }
    }

    /// Record a file's size in the remembered listing (after a read or an accepted write).
    fn set_size(&mut self, vol: &str, path: &[String], size: u64, modified: bool) {
        let Some((name, parent)) = path.split_last() else {
            return;
        };
        if let Some(l) = self.s.listings.get_mut(&(vol.to_string(), join(parent))) {
            if let Some(e) = l.iter_mut().find(|e| e.name == *name) {
                e.size = size;
                if modified {
                    e.modified = wire::now();
                }
            }
        }
    }

    fn read(&mut self, fork: u16, offset: u64, count: u64) -> (i32, Vec<u8>) {
        let Some(f) = self.s.forks.get(&fork) else {
            return (err::PARAM_ERR, Vec::new());
        };
        if f.mode & wire::open_mode::READ == 0 {
            return (err::ACCESS_DENIED, Vec::new());
        }
        let content = f.content.as_deref().unwrap_or(&[]);
        let len = content.len() as u64;
        if offset >= len {
            return (err::EOF_ERR, Vec::new());
        }
        let n = count.min(dsi::REQUEST_QUANTUM as u64).min(len - offset) as usize;
        let data = content[offset as usize..offset as usize + n].to_vec();
        let code = if offset.saturating_add(count) > len {
            err::EOF_ERR
        } else {
            0
        };
        (code, data)
    }

    async fn write(
        &mut self,
        ext: bool,
        from_end: bool,
        fork: u16,
        offset: u64,
        count: u64,
        data: &[u8],
    ) -> Result<(i32, Vec<u8>), i32> {
        let f = self.s.forks.get(&fork).ok_or(err::PARAM_ERR)?;
        if f.resource || f.mode & wire::open_mode::WRITE == 0 {
            return Err(err::ACCESS_DENIED);
        }
        if count != data.len() as u64 {
            self.log().warn(format!(
                "AFP {}: a write of {count} bytes carried {} decision=protocol_error",
                self.remote,
                data.len()
            ));
            return Err(err::PARAM_ERR);
        }
        let start = if from_end {
            (f.length as i64)
                .checked_add(offset as i64)
                .ok_or(err::PARAM_ERR)?
        } else {
            offset as i64
        };
        if start < 0 {
            return Err(err::PARAM_ERR);
        }
        let start = start as u64;
        let end = start.checked_add(count).ok_or(err::PARAM_ERR)?;
        if end > actions::MAX_FILE_BYTES as u64 {
            return Err(err::DISK_FULL);
        }
        let (vol, path) = (f.vol.clone(), f.path.clone());
        let (text, encoding) = actions::data_for_model(data);
        let event = Event::new(
            &actions::WRITE_FILE_EVENT,
            json!({
                "user": self.user(),
                "volume": vol,
                "path": join(&path),
                "operation": "write",
                "offset": start,
                "length": count,
                "data": text,
                "encoding": encoding,
            }),
        );
        let what = format!(
            "write of {count} bytes at {start} to {vol}:/{}",
            join(&path)
        );
        match self.decide(&event, actions::RESULT_ALLOW, &what).await {
            Decided::Answer(_) => {}
            Decided::Code(c) => return Err(c),
        }
        let f = self.s.forks.get_mut(&fork).ok_or(err::PARAM_ERR)?;
        if let Some(c) = f.content.as_mut() {
            if c.len() < end as usize {
                c.resize(end as usize, 0);
            }
            c[start as usize..end as usize].copy_from_slice(data);
        }
        f.length = f.length.max(end);
        let length = f.length;
        self.set_size(&vol, &path, length, true);
        self.s.fresh.remove(&(vol, join(&path)));
        Ok((
            0,
            if ext {
                end.to_be_bytes().to_vec()
            } else {
                (end.min(u32::MAX as u64) as u32).to_be_bytes().to_vec()
            },
        ))
    }

    async fn fork_node(&mut self, fork: u16) -> Result<NodeParams, i32> {
        let f = self.s.forks.get(&fork).ok_or(err::PARAM_ERR)?;
        let (vol_name, path, length, resource) =
            (f.vol.clone(), f.path.clone(), f.length, f.resource);
        let vol_id = self
            .s
            .open_vols
            .iter()
            .find(|(_, v)| **v == vol_name)
            .map(|(id, _)| *id)
            .ok_or(err::PARAM_ERR)?;
        let vol = self.open_volume(vol_id)?;
        let entry = self
            .dir_entry(&vol, &path)
            .await?
            .ok_or(err::OBJECT_NOT_FOUND)?;
        let mut n = self.node(&vol, &path, Some(&entry))?;
        if !resource {
            n.data_len = length;
        }
        Ok(n)
    }

    async fn get_fork_parms(&mut self, fork: u16, bitmap: u16) -> Result<(i32, Vec<u8>), i32> {
        if bitmap & !wire::file_bit::SUPPORTED != 0 {
            return Err(err::BITMAP_ERR);
        }
        let n = self.fork_node(fork).await?;
        let mut out = bitmap.to_be_bytes().to_vec();
        out.extend(wire::encode_node_params(bitmap, &n)?);
        Ok((0, out))
    }

    async fn set_fork_parms(
        &mut self,
        fork: u16,
        bitmap: u16,
        length: u64,
    ) -> Result<(i32, Vec<u8>), i32> {
        use wire::file_bit::*;
        let data_bits = DATA_FORK_LEN | EXT_DATA_FORK_LEN;
        let rsrc_bits = RSRC_FORK_LEN | EXT_RSRC_FORK_LEN;
        if bitmap == 0 || bitmap & !(data_bits | rsrc_bits) != 0 {
            return Err(err::BITMAP_ERR);
        }
        let f = self.s.forks.get(&fork).ok_or(err::PARAM_ERR)?;
        if bitmap & rsrc_bits != 0 {
            // Resource forks are always empty; emptying one is a no-op.
            return if f.resource && length == 0 {
                Ok((0, Vec::new()))
            } else {
                Err(err::ACCESS_DENIED)
            };
        }
        if f.resource || f.mode & wire::open_mode::WRITE == 0 {
            return Err(err::ACCESS_DENIED);
        }
        if length > actions::MAX_FILE_BYTES as u64 {
            return Err(err::DISK_FULL);
        }
        if length == f.length {
            return Ok((0, Vec::new()));
        }
        let (vol, path) = (f.vol.clone(), f.path.clone());
        let event = Event::new(
            &actions::WRITE_FILE_EVENT,
            json!({
                "user": self.user(),
                "volume": vol,
                "path": join(&path),
                "operation": "set_length",
                "length": length,
            }),
        );
        let what = format!("length change to {length} of {vol}:/{}", join(&path));
        match self.decide(&event, actions::RESULT_ALLOW, &what).await {
            Decided::Answer(_) => {}
            Decided::Code(c) => return Err(c),
        }
        let f = self.s.forks.get_mut(&fork).ok_or(err::PARAM_ERR)?;
        if let Some(c) = f.content.as_mut() {
            c.resize(length as usize, 0);
        }
        f.length = length;
        self.set_size(&vol, &path, length, true);
        Ok((0, Vec::new()))
    }

    async fn create(
        &mut self,
        vol: u16,
        dir: u32,
        path: &AfpPath,
        is_dir: bool,
        hard: bool,
    ) -> Result<(i32, Vec<u8>), i32> {
        let r = self.resolve(vol, dir, path).await?;
        if r.vol.read_only {
            return Err(err::VOL_LOCKED);
        }
        let Some((name, parent)) = r.path.split_last() else {
            return Err(err::OBJECT_EXISTS);
        };
        match &r.item {
            Item::Missing => {}
            Item::Entry(e) if !is_dir && hard && !e.is_dir => {
                if e.read_only {
                    return Err(err::ACCESS_DENIED);
                }
            }
            _ => return Err(err::OBJECT_EXISTS),
        }
        if wire::check_name(name).is_err() {
            return Err(err::PARAM_ERR);
        }
        if let Some(p) = self.dir_entry(&r.vol, parent).await? {
            if p.read_only {
                return Err(err::ACCESS_DENIED);
            }
        }
        let kind = if is_dir { "directory" } else { "file" };
        let event = Event::new(
            &actions::CREATE_EVENT,
            json!({
                "user": self.user(),
                "volume": r.vol.name,
                "path": join(&r.path),
                "kind": kind,
                "replace": hard && matches!(r.item, Item::Entry(_)),
            }),
        );
        let what = format!("create of {kind} {}:/{}", r.vol.name, join(&r.path));
        match self.decide(&event, actions::RESULT_ALLOW, &what).await {
            Decided::Answer(_) => {}
            Decided::Code(c) => return Err(c),
        }
        let now = wire::now();
        let entry = EntryConfig {
            name: name.clone(),
            is_dir,
            size: 0,
            created: now,
            modified: now,
            permissions: if is_dir { 0o755 } else { 0o644 },
            read_only: false,
        };
        let parent_key = (r.vol.name.clone(), join(parent));
        let l = self.s.listings.entry(parent_key).or_default();
        l.retain(|e| e.name != *name);
        l.push(entry);
        let key = (r.vol.name.clone(), join(&r.path));
        if is_dir {
            // The model approved an empty directory; that is what it holds.
            self.s.listings.insert(key, Vec::new());
            let id = self.cnid(&r.vol.name, &r.path, true)?;
            Ok((0, id.to_be_bytes().to_vec()))
        } else {
            self.s.fresh.insert(key);
            self.cnid(&r.vol.name, &r.path, false)?;
            Ok((0, Vec::new()))
        }
    }

    async fn delete(&mut self, vol: u16, dir: u32, path: &AfpPath) -> Result<(i32, Vec<u8>), i32> {
        let r = self.resolve(vol, dir, path).await?;
        if r.vol.read_only {
            return Err(err::VOL_LOCKED);
        }
        let entry = match &r.item {
            Item::Missing => return Err(err::OBJECT_NOT_FOUND),
            Item::Root => return Err(err::ACCESS_DENIED),
            Item::Entry(e) => e.clone(),
        };
        if entry.read_only {
            return Err(err::OBJECT_LOCKED);
        }
        if self
            .s
            .forks
            .values()
            .any(|f| f.vol == r.vol.name && f.path == r.path)
        {
            return Err(err::FILE_BUSY);
        }
        if entry.is_dir && !self.listing(&r.vol, &r.path).await?.is_empty() {
            return Err(err::DIR_NOT_EMPTY);
        }
        let kind = if entry.is_dir { "directory" } else { "file" };
        let event = Event::new(
            &actions::DELETE_EVENT,
            json!({
                "user": self.user(),
                "volume": r.vol.name,
                "path": join(&r.path),
                "kind": kind,
            }),
        );
        let what = format!("delete of {kind} {}:/{}", r.vol.name, join(&r.path));
        match self.decide(&event, actions::RESULT_ALLOW, &what).await {
            Decided::Answer(_) => {}
            Decided::Code(c) => return Err(c),
        }
        if let Some((name, parent)) = r.path.split_last() {
            if let Some(l) = self.s.listings.get_mut(&(r.vol.name.clone(), join(parent))) {
                l.retain(|e| e.name != *name);
            }
        }
        let key = (r.vol.name.clone(), join(&r.path));
        self.s.listings.remove(&key);
        self.s.fresh.remove(&key);
        Ok((0, Vec::new()))
    }

    async fn resolve_id(&mut self, vol: u16, id: u32, bitmap: u16) -> Result<(i32, Vec<u8>), i32> {
        if bitmap & !wire::file_bit::SUPPORTED != 0 {
            return Err(err::BITMAP_ERR);
        }
        let v = self.open_volume(vol)?;
        let found = self.shared.cnids.lock().ok().and_then(|c| c.lookup(id));
        let path: Vec<String> = match found {
            Some((name, p, false)) if name == v.name => p.split('/').map(str::to_string).collect(),
            Some((_, _, true)) => return Err(err::OBJECT_TYPE_ERR),
            _ => return Err(err::ID_NOT_FOUND),
        };
        let entry = match self.dir_entry(&v, &path).await {
            Ok(Some(e)) => e,
            Ok(None) | Err(err::OBJECT_NOT_FOUND) => return Err(err::ID_NOT_FOUND),
            Err(c) => return Err(c),
        };
        let n = self.node(&v, &path, Some(&entry))?;
        let mut out = bitmap.to_be_bytes().to_vec();
        out.extend(wire::encode_node_params(bitmap, &n)?);
        Ok((0, out))
    }

    fn user_info(&self, this_user: bool, user_id: u32, bitmap: u16) -> (i32, Vec<u8>) {
        if bitmap & !0x07 != 0 || bitmap == 0 {
            return (err::BITMAP_ERR, Vec::new());
        }
        if !this_user && user_id != self.s.uid {
            return (err::ITEM_NOT_FOUND, Vec::new());
        }
        let uid = self.s.uid;
        let mut out = bitmap.to_be_bytes().to_vec();
        if bitmap & 0x01 != 0 {
            out.extend_from_slice(&uid.to_be_bytes());
        }
        if bitmap & 0x02 != 0 {
            out.extend_from_slice(&uid.to_be_bytes());
        }
        if bitmap & 0x04 != 0 {
            // A local-user UUID in netatalk's style: a fixed prefix and the uid.
            let mut uuid = [
                0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa, 0, 0, 0, 0,
            ];
            uuid[12..16].copy_from_slice(&uid.to_be_bytes());
            out.extend_from_slice(&uuid);
        }
        (0, out)
    }
}

/// Write one message, within [`WRITE_TIMEOUT`].
async fn send<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("the client stopped reading for {WRITE_TIMEOUT:?}"))??;
    Ok(())
}

fn flatten(results: Vec<ActionResult>, out: &mut Vec<ActionResult>) {
    for r in results {
        match r {
            ActionResult::Multiple(inner) => flatten(inner, out),
            other => out.push(other),
        }
    }
}

/// Compare two byte strings in time that depends only on their lengths.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
