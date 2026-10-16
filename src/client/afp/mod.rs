//! AFP client: NetGet logs in to an AFP file server and the model decides what to list, read
//! and write.
//!
//! Three tasks per connection, all registered with the client:
//!
//! * **transport** owns the DSI session: one AFP request on the wire at a time, each operation
//!   a short sequence of them (open the volume, enumerate page by page, open a fork, read it
//!   in quantum-sized pieces, close it). It tickles the server every
//!   [`TICKLE_INTERVAL`](crate::server::afp::TICKLE_INTERVAL) while it waits for work, and
//!   never waits on the model.
//! * **turns** asks the model about each result, in order, and hands its actions back to the
//!   transport. A result produced by an action the model gave in answer to a result is one
//!   turn deeper; at [`MAX_FOLLOWUP_DEPTH`] the chain stops and says so.
//! * **commands** runs injected actions (`[ send ]`, MCP `send_to_client`) down the same path.
//!
//! The login happens in `connect`, before any of them start: FPGetSrvrInfo on a connection of
//! its own (DSIGetStatus ends the session it is sent on), then DSIOpenSession and FPLogin with
//! the configured user's Cleartxt Passwrd, or No User Authent. A refused login fails the
//! connect; the model never sees the password.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::afp::wire::{self, err, AfpPath, EnumerateKind, NodeParams, Request};
use crate::server::afp::{dsi, TICKLE_INTERVAL};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use actions::{AfpClientProtocol, Operation};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

/// Operations accepted and not yet finished; the next is refused.
pub const MAX_QUEUED: usize = 16;
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// The most data NetGet puts in one FPWriteExt or asks for in one FPReadExt, whatever quantum
/// the server allows.
pub const MAX_CHUNK: u32 = 128 * 1024;
/// Server requests (tickles, attentions) skipped while waiting for one reply before NetGet
/// decides the server is not answering.
const MAX_INTERLEAVED: usize = 64;

const TURN_QUEUE_CAPACITY: usize = 64;

/// The bitmaps NetGet asks for when it lists or describes items.
const FILE_BITMAP: u16 = wire::file_bit::ATTRIBUTES
    | wire::file_bit::PARENT_DIR_ID
    | wire::file_bit::CREATE_DATE
    | wire::file_bit::MOD_DATE
    | wire::file_bit::NODE_ID
    | wire::file_bit::EXT_DATA_FORK_LEN
    | wire::file_bit::UTF8_NAME
    | wire::file_bit::UNIX_PRIVS;
const DIR_BITMAP: u16 = wire::dir_bit::ATTRIBUTES
    | wire::dir_bit::PARENT_DIR_ID
    | wire::dir_bit::CREATE_DATE
    | wire::dir_bit::MOD_DATE
    | wire::dir_bit::NODE_ID
    | wire::dir_bit::OFFSPRING_COUNT
    | wire::dir_bit::UTF8_NAME
    | wire::dir_bit::UNIX_PRIVS;

struct Job {
    operation: Operation,
    depth: u32,
}

enum Outbound {
    Job(Job),
    Disconnect(oneshot::Sender<()>),
}

/// One event for the model, and how deep in a chain it is.
struct Turn {
    event: Event,
    depth: u32,
}

/// An AFP-level refusal: the server answered, with an error.
struct Refused {
    code: i32,
    message: String,
}

/// Why an operation failed: refused by the server, or the connection is gone.
enum Failure {
    Afp(Refused),
    Connection(anyhow::Error),
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::Connection(e)
    }
}

fn refused(code: i32, what: &str) -> Failure {
    Failure::Afp(Refused {
        code,
        message: format!("{what}: {}", wire::error_name(code)),
    })
}

/// The DSI session.
pub struct Session<S> {
    r: ReadHalf<S>,
    w: WriteHalf<S>,
    next_id: u16,
    timeout: Duration,
    quantum: u32,
    volumes: HashMap<String, u16>,
}

impl<S: AsyncRead + AsyncWrite> Session<S> {
    fn new(stream: S, timeout: Duration) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            r,
            w,
            next_id: 0,
            timeout,
            quantum: MAX_CHUNK,
            volumes: HashMap::new(),
        }
    }

    /// Send one DSI request and wait for its reply: the result code and payload.
    async fn call(&mut self, command: u8, code: u32, payload: &[u8]) -> Result<(i32, Vec<u8>)> {
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let msg = dsi::message(dsi::FLAG_REQUEST, command, id, code, payload);
        self.w.write_all(&msg).await?;
        self.w.flush().await?;
        for _ in 0..MAX_INTERLEAVED {
            let (h, body) = tokio::time::timeout(self.timeout, self.read_message())
                .await
                .map_err(|_| {
                    anyhow!(
                        "the server did not answer {} within {:?}",
                        dsi::command_name(command),
                        self.timeout
                    )
                })??;
            if h.flags == dsi::FLAG_REPLY && h.request_id == id && h.command == command {
                return Ok((h.result(), body));
            }
            // A tickle or an attention from the server, or a stale reply: not ours.
        }
        bail!("the server sent {MAX_INTERLEAVED} messages without answering")
    }

    async fn read_message(&mut self) -> Result<(dsi::Header, Vec<u8>)> {
        let mut h = [0u8; dsi::HEADER_LEN];
        self.r
            .read_exact(&mut h)
            .await
            .context("the server closed the connection")?;
        let header = dsi::Header::parse(&h);
        let len = header.check_length()?;
        let mut body = vec![0u8; len];
        self.r.read_exact(&mut body).await?;
        Ok((header, body))
    }

    async fn afp(&mut self, req: &Request) -> Result<(i32, Vec<u8>)> {
        self.call(dsi::command::COMMAND, 0, &wire::encode_request(req))
            .await
    }

    async fn afp_write(&mut self, req: &Request, data: &[u8]) -> Result<(i32, Vec<u8>)> {
        let block = wire::encode_request(req);
        let mut payload = block.clone();
        payload.extend_from_slice(data);
        self.call(dsi::command::WRITE, block.len() as u32, &payload)
            .await
    }

    async fn tickle(&mut self) -> Result<()> {
        self.next_id = self.next_id.wrapping_add(1);
        let msg = dsi::message(
            dsi::FLAG_REQUEST,
            dsi::command::TICKLE,
            self.next_id,
            0,
            &[],
        );
        self.w.write_all(&msg).await?;
        Ok(())
    }

    async fn open_session(&mut self) -> Result<()> {
        let options = dsi::encode_options(&[(
            dsi::option::ATTENTION_QUANTUM,
            1024u32.to_be_bytes().to_vec(),
        )]);
        let (code, body) = self.call(dsi::command::OPEN_SESSION, 0, &options).await?;
        if code != 0 {
            bail!("DSIOpenSession refused: {}", wire::error_name(code));
        }
        let opts = dsi::parse_options(&body)?;
        if let Some(q) = dsi::quantum_option(&opts, dsi::option::SERVER_REQUEST_QUANTUM) {
            // Leave room for the command block in front of a write's data.
            self.quantum = q.saturating_sub(1024).clamp(512, MAX_CHUNK);
        }
        Ok(())
    }

    async fn volume(&mut self, name: &str) -> std::result::Result<u16, Failure> {
        if let Some(id) = self.volumes.get(name) {
            return Ok(*id);
        }
        let bitmap = wire::vol_bit::VOLUME_ID | wire::vol_bit::ATTRIBUTES | wire::vol_bit::NAME;
        let (code, body) = self
            .afp(&Request::OpenVol {
                bitmap,
                name: name.to_string(),
                has_password: false,
            })
            .await?;
        if code != 0 {
            return Err(refused(code, &format!("FPOpenVol {name:?}")));
        }
        let got = wire::be16_prefixed(&body)
            .and_then(|(bm, rest)| wire::decode_vol_params(bm, rest))
            .context("FPOpenVol reply")?;
        self.volumes.insert(name.to_string(), got.id);
        Ok(got.id)
    }
}

pub struct AfpClient;

impl AfpClient {
    pub async fn connect(
        remote_addr: String,
        credentials: Option<(String, String)>,
        timeout: Duration,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        if remote_addr.trim().is_empty() {
            return Err(anyhow!(
                "the AFP client needs a remote_addr (the server's host:port); refusing to \
                 connect without one"
            ));
        }
        // FPGetSrvrInfo first, on its own connection: a server ends the session DSIGetStatus
        // arrives on.
        let info = {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(&remote_addr))
                .await
                .map_err(|_| anyhow!("connecting to {remote_addr} timed out"))?
                .with_context(|| format!("failed to connect to the AFP server at {remote_addr}"))?;
            let mut s = Session::new(stream, timeout);
            let (code, body) = s.call(dsi::command::GET_STATUS, 0, &[]).await?;
            if code != 0 {
                bail!("DSIGetStatus refused: {}", wire::error_name(code));
            }
            wire::decode_server_info(&body).context("the FPGetSrvrInfo reply")?
        };
        let version = ["AFP3.4", "AFP3.3", "AFP3.2", "AFP3.1", "AFPX03"]
            .into_iter()
            .find(|v| info.versions.iter().any(|s| s == v))
            .ok_or_else(|| {
                anyhow!(
                    "the server speaks {} and NetGet only AFP 3.x",
                    info.versions.join(", ")
                )
            })?;
        let (uam, user, password) = match &credentials {
            Some((u, p)) => {
                if !info.uams.iter().any(|x| x == wire::uam::CLEARTXT_PASSWRD) {
                    bail!(
                        "the server does not offer Cleartxt Passwrd (it offers {}); NetGet \
                         logs in with a password only that way",
                        info.uams.join(", ")
                    );
                }
                (
                    wire::uam::CLEARTXT_PASSWRD,
                    Some(u.clone()),
                    Some(p.as_bytes().to_vec()),
                )
            }
            None => {
                if !info.uams.iter().any(|x| x == wire::uam::NO_USER_AUTHENT) {
                    bail!(
                        "the server offers no guest login (it offers {}); configure a username \
                         and password",
                        info.uams.join(", ")
                    );
                }
                (wire::uam::NO_USER_AUTHENT, None, None)
            }
        };

        let stream = tokio::time::timeout(timeout, TcpStream::connect(&remote_addr))
            .await
            .map_err(|_| anyhow!("connecting to {remote_addr} timed out"))?
            .with_context(|| format!("failed to connect to the AFP server at {remote_addr}"))?;
        let _ = stream.set_nodelay(true);
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let mut session = Session::new(stream, timeout);
        session.open_session().await?;
        let (code, _) = session
            .afp(&Request::Login(wire::Login {
                ext: false,
                version: version.to_string(),
                uam: uam.to_string(),
                user: user.clone(),
                password,
            }))
            .await?;
        if code != 0 {
            bail!(
                "the server refused the login ({uam}{}): {}",
                user.as_deref()
                    .map(|u| format!(" as {u}"))
                    .unwrap_or_default(),
                wire::error_name(code)
            );
        }
        let who = user.unwrap_or_else(|| "guest".into());
        info!("AFP client {client_id} logged in to {peer} as {who} ({uam}, {version})");
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] AFP client {client_id} logged in to {peer} as {who}"
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(AfpClientProtocol::new());
        let (outbound_tx, outbound_rx) = mpsc::channel::<Outbound>(MAX_QUEUED);
        let (turn_tx, turn_rx) = mpsc::channel::<Turn>(TURN_QUEUE_CAPACITY);

        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        app_state
            .spawn_client_task(
                client_id,
                command_loop(
                    command_rx,
                    protocol.clone(),
                    outbound_tx.clone(),
                    client_id,
                    app_state.clone(),
                    status_tx.clone(),
                ),
            )
            .await;
        let turn_abort = app_state
            .spawn_client_task(
                client_id,
                run_turns(
                    turn_rx,
                    outbound_tx,
                    protocol,
                    llm_client,
                    app_state.clone(),
                    status_tx.clone(),
                    client_id,
                ),
            )
            .await;
        let _ = turn_tx.try_send(Turn {
            event: Event::new(
                &actions::CONNECTED_EVENT,
                json!({
                    "server": {
                        "name": info.utf8_server_name.clone().unwrap_or(info.server_name.clone()),
                        "machine_type": info.machine_type,
                        "versions": info.versions,
                        "uams": info.uams,
                        "addresses": info.address_strings(),
                    },
                    "user": who,
                    "uam": uam,
                    "version": version,
                }),
            ),
            depth: 0,
        });
        app_state
            .spawn_client_task(
                client_id,
                run_transport(
                    session,
                    outbound_rx,
                    turn_tx,
                    app_state.clone(),
                    status_tx,
                    client_id,
                    turn_abort,
                ),
            )
            .await;
        Ok(local_addr)
    }
}

/// An item as the model sees it.
pub fn entry_json(n: &NodeParams) -> Value {
    let mut v = json!({
        "name": n.name,
        "type": if n.is_dir { "directory" } else { "file" },
        "id": n.node_id,
        "created": wire::date_to_text(n.created),
        "modified": wire::date_to_text(n.modified),
    });
    if n.is_dir {
        v["offspring"] = json!(n.offspring);
    } else {
        v["size"] = json!(n.data_len);
    }
    if n.unix.mode != 0 {
        v["permissions"] = json!(format!("{:o}", n.unix.mode & 0o7777));
    }
    if n.attributes & wire::attr::WRITE_INHIBIT != 0 {
        v["read_only"] = json!(true);
    }
    v
}

/// Content as the model sees it: text when it is text, hex otherwise.
fn content_json(bytes: &[u8]) -> (String, &'static str) {
    crate::server::afp::actions::data_for_model(bytes)
}

async fn list_directory<S: AsyncRead + AsyncWrite>(
    s: &mut Session<S>,
    vol: u16,
    path: &[String],
) -> std::result::Result<(Vec<NodeParams>, bool), Failure> {
    let mut out = Vec::new();
    let mut start = 1u32;
    loop {
        let (code, body) = s
            .afp(&Request::Enumerate {
                kind: EnumerateKind::Ext2,
                vol,
                dir: wire::ROOT_DID,
                file_bitmap: FILE_BITMAP,
                dir_bitmap: DIR_BITMAP,
                req_count: 256,
                start_index: start,
                max_reply: s.quantum,
                path: AfpPath::names(path),
            })
            .await?;
        if code == err::OBJECT_NOT_FOUND && start > 1 {
            return Ok((out, false));
        }
        if code == err::OBJECT_NOT_FOUND && out.is_empty() {
            // An empty directory, or no such directory: FPGetFileDirParms says which.
            let (c, _) = s
                .afp(&Request::GetFileDirParms {
                    vol,
                    dir: wire::ROOT_DID,
                    file_bitmap: 0,
                    dir_bitmap: wire::dir_bit::NODE_ID,
                    path: AfpPath::names(path),
                })
                .await?;
            return if c == 0 {
                Ok((out, false))
            } else {
                Err(refused(c, "FPGetFileDirParms"))
            };
        }
        if code != 0 {
            return Err(refused(code, "FPEnumerateExt2"));
        }
        let page = wire::decode_enumerate_reply(EnumerateKind::Ext2, &body)
            .context("FPEnumerateExt2 reply")?;
        if page.is_empty() {
            return Ok((out, false));
        }
        start = start.saturating_add(page.len() as u32);
        for n in page {
            if out.len() >= actions::MAX_LIST_ENTRIES {
                return Ok((out, true));
            }
            out.push(n);
        }
    }
}

async fn read_file<S: AsyncRead + AsyncWrite>(
    s: &mut Session<S>,
    vol: u16,
    path: &[String],
    max: u64,
) -> std::result::Result<(Vec<u8>, u64), Failure> {
    let bitmap = wire::file_bit::EXT_DATA_FORK_LEN;
    let (code, body) = s
        .afp(&Request::OpenFork {
            resource: false,
            vol,
            dir: wire::ROOT_DID,
            bitmap,
            mode: wire::open_mode::READ,
            path: AfpPath::names(path),
        })
        .await?;
    if code != 0 {
        return Err(refused(code, "FPOpenFork"));
    }
    let (fork, size) = wire::decode_open_fork_reply(&body).context("FPOpenFork reply")?;
    let mut data = Vec::new();
    let want = size.min(max);
    let mut result = Ok(());
    while (data.len() as u64) < want {
        let count = (want - data.len() as u64).min(s.quantum as u64);
        let (code, chunk) = s
            .afp(&Request::Read {
                ext: true,
                fork,
                offset: data.len() as u64,
                count,
            })
            .await?;
        if code != 0 && code != err::EOF_ERR {
            result = Err(refused(code, "FPReadExt"));
            break;
        }
        if chunk.len() as u64 > count {
            result = Err(Failure::Connection(anyhow!(
                "FPReadExt returned {} bytes for a {count}-byte read",
                chunk.len()
            )));
            break;
        }
        let eof = code == err::EOF_ERR || chunk.is_empty();
        data.extend_from_slice(&chunk);
        if eof {
            break;
        }
    }
    let (code, _) = s.afp(&Request::CloseFork { fork }).await?;
    result?;
    if code != 0 {
        return Err(refused(code, "FPCloseFork"));
    }
    Ok((data, size))
}

async fn write_file<S: AsyncRead + AsyncWrite>(
    s: &mut Session<S>,
    vol: u16,
    path: &[String],
    data: &[u8],
) -> std::result::Result<u64, Failure> {
    let (code, _) = s
        .afp(&Request::CreateFile {
            hard: false,
            vol,
            dir: wire::ROOT_DID,
            path: AfpPath::names(path),
        })
        .await?;
    if code != 0 && code != err::OBJECT_EXISTS {
        return Err(refused(code, "FPCreateFile"));
    }
    let (code, body) = s
        .afp(&Request::OpenFork {
            resource: false,
            vol,
            dir: wire::ROOT_DID,
            bitmap: 0,
            mode: wire::open_mode::READ | wire::open_mode::WRITE,
            path: AfpPath::names(path),
        })
        .await?;
    if code != 0 {
        return Err(refused(code, "FPOpenFork"));
    }
    let (fork, _) = wire::decode_open_fork_reply(&body).context("FPOpenFork reply")?;
    let mut result = Ok(0u64);
    let (code, _) = s
        .afp(&Request::SetForkParms {
            fork,
            bitmap: wire::file_bit::EXT_DATA_FORK_LEN,
            length: 0,
        })
        .await?;
    if code != 0 {
        result = Err(refused(code, "FPSetForkParms"));
    } else {
        let mut offset = 0usize;
        while offset < data.len() {
            let n = (data.len() - offset).min(s.quantum as usize);
            let (code, _) = s
                .afp_write(
                    &Request::Write {
                        ext: true,
                        from_end: false,
                        fork,
                        offset: offset as u64,
                        count: n as u64,
                    },
                    &data[offset..offset + n],
                )
                .await?;
            if code != 0 {
                result = Err(refused(code, "FPWriteExt"));
                break;
            }
            offset += n;
        }
        if result.is_ok() {
            result = Ok(offset as u64);
        }
    }
    let (code, _) = s.afp(&Request::CloseFork { fork }).await?;
    let written = result?;
    if code != 0 {
        return Err(refused(code, "FPCloseFork"));
    }
    Ok(written)
}

/// Carry out one operation: the event it produces, or `Err` when the connection is gone.
async fn perform<S: AsyncRead + AsyncWrite>(s: &mut Session<S>, op: &Operation) -> Result<Event> {
    let (volume, path) = op.target();
    let outcome: std::result::Result<Event, Failure> = async {
        Ok(match op {
            Operation::ListVolumes => {
                let (code, body) = s.afp(&Request::GetSrvrParms).await?;
                if code != 0 {
                    return Err(refused(code, "FPGetSrvrParms"));
                }
                let (_, vols) =
                    wire::decode_srvr_parms(&body).context("FPGetSrvrParms reply")?;
                Event::new(
                    &actions::VOLUMES_EVENT,
                    json!({"volumes": vols.iter().map(|v| json!({"name": v.name, "has_password": v.has_password})).collect::<Vec<_>>()}),
                )
            }
            Operation::ListDirectory { volume, path } => {
                let vol = s.volume(volume).await?;
                let (entries, truncated) = list_directory(s, vol, path).await?;
                Event::new(
                    &actions::DIRECTORY_EVENT,
                    json!({
                        "volume": volume,
                        "path": path.join("/"),
                        "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
                        "truncated": truncated,
                    }),
                )
            }
            Operation::Read {
                volume,
                path,
                max_bytes,
            } => {
                let vol = s.volume(volume).await?;
                let (data, size) = read_file(s, vol, path, *max_bytes).await?;
                let (content, encoding) = content_json(&data);
                Event::new(
                    &actions::FILE_EVENT,
                    json!({
                        "volume": volume,
                        "path": path.join("/"),
                        "size": size,
                        "content": content,
                        "encoding": encoding,
                        "truncated": (data.len() as u64) < size,
                    }),
                )
            }
            Operation::Write { volume, path, data } => {
                let vol = s.volume(volume).await?;
                let written = write_file(s, vol, path, data).await?;
                Event::new(
                    &actions::DONE_EVENT,
                    json!({
                        "operation": op.name(),
                        "volume": volume,
                        "path": path.join("/"),
                        "bytes_written": written,
                    }),
                )
            }
            Operation::CreateDirectory { volume, path } => {
                let vol = s.volume(volume).await?;
                let (code, _) = s
                    .afp(&Request::CreateDir {
                        vol,
                        dir: wire::ROOT_DID,
                        path: AfpPath::names(path),
                    })
                    .await?;
                if code != 0 {
                    return Err(refused(code, "FPCreateDir"));
                }
                Event::new(
                    &actions::DONE_EVENT,
                    json!({"operation": op.name(), "volume": volume, "path": path.join("/")}),
                )
            }
            Operation::Delete { volume, path } => {
                let vol = s.volume(volume).await?;
                let (code, _) = s
                    .afp(&Request::Delete {
                        vol,
                        dir: wire::ROOT_DID,
                        path: AfpPath::names(path),
                    })
                    .await?;
                if code != 0 {
                    return Err(refused(code, "FPDelete"));
                }
                Event::new(
                    &actions::DONE_EVENT,
                    json!({"operation": op.name(), "volume": volume, "path": path.join("/")}),
                )
            }
            Operation::Info { volume, path } => {
                let vol = s.volume(volume).await?;
                let (code, body) = s
                    .afp(&Request::GetFileDirParms {
                        vol,
                        dir: wire::ROOT_DID,
                        file_bitmap: FILE_BITMAP,
                        dir_bitmap: DIR_BITMAP,
                        path: AfpPath::names(path),
                    })
                    .await?;
                if code != 0 {
                    return Err(refused(code, "FPGetFileDirParms"));
                }
                let n = wire::decode_file_dir_reply(&body).context("FPGetFileDirParms reply")?;
                Event::new(
                    &actions::INFO_EVENT,
                    json!({"volume": volume, "path": path.join("/"), "item": entry_json(&n)}),
                )
            }
        })
    }
    .await;
    match outcome {
        Ok(e) => Ok(e),
        Err(Failure::Afp(r)) => Ok(Event::new(
            &actions::ERROR_EVENT,
            json!({
                "operation": op.name(),
                "volume": volume,
                "path": path,
                "code": r.code,
                "error": wire::error_name(r.code),
                "message": r.message,
            }),
        )),
        Err(Failure::Connection(e)) => Err(e),
    }
}

async fn run_transport(
    mut session: Session<TcpStream>,
    mut outbound_rx: mpsc::Receiver<Outbound>,
    turn_tx: mpsc::Sender<Turn>,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    turn_abort: tokio::task::AbortHandle,
) {
    let mut tickle = tokio::time::interval_at(
        tokio::time::Instant::now() + TICKLE_INTERVAL,
        TICKLE_INTERVAL,
    );
    let status = loop {
        let out = tokio::select! {
            out = outbound_rx.recv() => out,
            _ = tickle.tick() => {
                if let Err(e) = session.tickle().await {
                    error!("AFP client {client_id}: tickle failed: {e:#}");
                    break ClientStatus::Error(format!("{e:#}"));
                }
                continue;
            }
        };
        let Some(out) = out else {
            break ClientStatus::Disconnected;
        };
        let job = match out {
            Outbound::Disconnect(ack) => {
                let _ = session.afp(&Request::Logout).await;
                let msg = dsi::message(
                    dsi::FLAG_REQUEST,
                    dsi::command::CLOSE_SESSION,
                    session.next_id.wrapping_add(1),
                    0,
                    &[],
                );
                let _ = session.w.write_all(&msg).await;
                let _ = session.w.shutdown().await;
                let _ = ack.send(());
                info!("AFP client {client_id} logged out and disconnected on request");
                break ClientStatus::Disconnected;
            }
            Outbound::Job(job) => job,
        };
        let name = job.operation.name();
        match perform(&mut session, &job.operation).await {
            Ok(event) => {
                info!(
                    "AFP client {client_id} {name} finished with {}",
                    event.event_type.id
                );
                if turn_tx
                    .try_send(Turn {
                        event,
                        depth: job.depth,
                    })
                    .is_err()
                {
                    warn!(
                        "AFP client {client_id} dropped the result of {name}: the model is \
                         {TURN_QUEUE_CAPACITY} events behind decision=turn_queue_full"
                    );
                }
            }
            Err(e) => {
                error!("AFP client {client_id} {name}: connection failed: {e:#}");
                break ClientStatus::Error(format!("{e:#}"));
            }
        }
        tickle.reset();
    };
    turn_abort.abort();
    app_state.remove_client_handle(client_id).await;
    app_state.update_client_status(client_id, status).await;
    let _ = status_tx.send(format!("[CLIENT] AFP client {client_id} disconnected"));
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

enum Applied {
    Queued,
    Disconnect,
}

/// Validate one action and hand it to the transport. Shared by the model's turns and injected
/// commands.
async fn apply_action(
    protocol: &AfpClientProtocol,
    outbound_tx: &mpsc::Sender<Outbound>,
    action: Value,
    depth: u32,
) -> Result<Applied> {
    match protocol.execute_action(action)? {
        ClientActionResult::Custom { name, data } if name == actions::OPERATION_RESULT => {
            let operation = actions::require_operation(&data)?;
            outbound_tx
                .try_send(Outbound::Job(Job { operation, depth }))
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => {
                        anyhow!("{MAX_QUEUED} AFP operations are already waiting")
                    }
                    mpsc::error::TrySendError::Closed(_) => anyhow!("the connection is closed"),
                })?;
            Ok(Applied::Queued)
        }
        ClientActionResult::Disconnect => {
            let (ack, done) = oneshot::channel();
            if outbound_tx.send(Outbound::Disconnect(ack)).await.is_ok() {
                let _ = done.await;
            }
            Ok(Applied::Disconnect)
        }
        _ => Ok(Applied::Queued),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_turns(
    mut turn_rx: mpsc::Receiver<Turn>,
    outbound_tx: mpsc::Sender<Outbound>,
    protocol: Arc<AfpClientProtocol>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
) {
    while let Some(turn) = turn_rx.recv().await {
        let id = turn.event.event_type.id.clone();
        if turn.depth >= MAX_FOLLOWUP_DEPTH {
            warn!(
                "AFP client {client_id} {id} not sent to the model: {} turns deep \
                 decision=followup_depth",
                turn.depth
            );
            let _ = status_tx.send(format!(
                "[WARN] AFP client {client_id}: {id} not sent to the model, the chain of \
                 follow-ups reached {MAX_FOLLOWUP_DEPTH}"
            ));
            continue;
        }
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            continue;
        };
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&turn.event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                info!(
                    "AFP client {client_id} {id} decision={} actions={}",
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    match apply_action(protocol.as_ref(), &outbound_tx, action, turn.depth + 1)
                        .await
                    {
                        Ok(Applied::Disconnect) => return,
                        Ok(Applied::Queued) => {}
                        Err(e) => {
                            error!("AFP client {client_id} action refused: {e:#}");
                            let _ = status_tx.send(format!(
                                "[ERROR] AFP client {client_id} action refused: {e:#}"
                            ));
                        }
                    }
                }
            }
            Err(e) => error!("AFP client {client_id} {id} decision=llm_error: {e:#}"),
        }
    }
}

async fn command_loop(
    mut command_rx: mpsc::Receiver<ClientCommand>,
    protocol: Arc<AfpClientProtocol>,
    outbound_tx: mpsc::Sender<Outbound>,
    client_id: ClientId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
) {
    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome = match apply_action(protocol.as_ref(), &outbound_tx, action.clone(), 0).await {
            Ok(Applied::Queued) => ClientSendOutcome::Executed {
                detail: "queued; the result arrives as an event".to_string(),
            },
            Ok(Applied::Disconnect) => ClientSendOutcome::Disconnected,
            Err(e) => ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
            },
        };
        app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                protocol.protocol_name(),
                None,
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or_default()],
            )
            .await;
        let disconnect = matches!(outcome, ClientSendOutcome::Disconnected);
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, Ok(outcome));
        if disconnect {
            break;
        }
    }
}
