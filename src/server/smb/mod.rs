//! SMB/CIFS server implementation
//!
//! Provides an SMB2 file server where the LLM controls the virtual filesystem. Sessions are
//! guest or anonymous: the NTLMSSP exchange is walked so a real client finishes SESSION_SETUP,
//! but no password is checked (see `auth.rs`).
//!
//! `wire.rs` owns every byte layout; this file owns the connection, the per-connection state
//! and the model.

pub mod actions;
pub mod auth;
pub mod wire;

use anyhow::{Context, Result};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::SmbProtocol;
use crate::state::app_state::AppState;
use crate::state::server::{
    ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
};
use crate::state::ServerId;

use crate::logging::emit::Log;
use actions::SMB_OPERATION_EVENT;
use wire::{command, status, FileMeta, RequestHeader, ResponseHeader, HEADER_LEN};

/// How long to wait for a peer's first SMB2 message after it has connected.
///
/// SMB2 is client-speaks-first: NEGOTIATE is the first message and the server says nothing
/// before it. `smbclient`, the Windows redirector and `mount -t cifs` all send it inside the
/// connect path, so a peer that has connected and sent nothing has begun no session — which is
/// the state an unauthenticated flood lives in, and the one this bound exists for.
const FIRST_MESSAGE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* message once a session exists.
///
/// Fifteen minutes, which is not a number invented here: it is Windows' `autodisconnect`
/// default — the interval after which a server disconnects an idle SMB session — expressed in
/// seconds. A mounted share with no I/O is genuinely idle for long stretches and must not be
/// torn down for it, and copying the number every Windows client already expects is the one
/// choice a real deployment cannot be surprised by.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// How long a peer may stall part-way through a message it has already announced.
///
/// Separate from the two above, and much shorter, because it is a different claim: the peer has
/// said "this many bytes are coming" in the transport header and the server has already
/// allocated for them. Nothing legitimate takes half a minute to finish delivering a message
/// whose length has landed.
const BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The three read deadlines of one server, each a startup parameter defaulting to the constant
/// above it (`first_byte_timeout_secs`, `idle_timeout_secs`, `body_timeout_secs`).
///
/// Configurable because the idle one is fifteen minutes, which no test can wait out, and a
/// deadline nobody can test is a comment. The defaults are the numbers argued beside each
/// constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    /// Silence allowed before any session has been admitted.
    pub first_message: std::time::Duration,
    /// Silence allowed between messages once a session has been admitted.
    pub idle: std::time::Duration,
    /// How long a peer may stall part-way through a message it has announced.
    pub body: std::time::Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            first_message: FIRST_MESSAGE_READ_TIMEOUT,
            idle: IDLE_BETWEEN_MESSAGES_TIMEOUT,
            body: BODY_READ_TIMEOUT,
        }
    }
}

/// Concurrent connections this server admits.
pub const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// Sessions one connection may hold at once, those still mid-NTLMSSP and those the model has
/// admitted counted together.
///
/// The first SESSION_SETUP of an NTLMSSP exchange opens a session **before anyone is asked**
/// — nothing has been said about who is logging in yet — and a peer that never sends the
/// second leg leaves it open until the connection closes. Without this bound a peer grows the
/// session table by one entry per NEGOTIATE leg it sends, at no cost to itself. A real client
/// holds one session per user on a connection and has one exchange in flight at a time; a
/// multi-user redirector holds a handful. Sixteen leaves room for every legitimate shape. The
/// refusal is `STATUS_INSUFFICIENT_RESOURCES`, the status Samba returns when its session table
/// is full, logged `decision=fail_closed_session_cap`, and it is decided before the model.
pub const MAX_SESSIONS_PER_CONNECTION: usize = 16;

/// Tree connects one connection may hold at once.
///
/// TREE_CONNECT asks no one — the share is a name for the root of the tree the model invents —
/// so nothing else stops one admitted session growing the tree table by a request at a time. A
/// client connects `IPC$` and the shares it browses; 64 is far past that. Refused
/// `STATUS_INSUFFICIENT_RESOURCES` (Samba's answer when its tree table is full), logged
/// `decision=fail_closed_tree_cap`. TREE_DISCONNECT and LOGOFF return slots.
pub const MAX_TREES_PER_CONNECTION: usize = 64;

/// Open handles one connection may hold at once.
///
/// Each CREATE the model admits records a handle, including its path. The model stands in
/// front of every one, but a `static` handler answering every CREATE does not, and a client
/// that opens and never closes would grow the table until the connection ends. 1024 is far
/// past what one smbclient, smbprotocol or Explorer session holds open. Refused
/// `STATUS_TOO_MANY_OPENED_FILES` (what Samba answers past `max open files`) before the model
/// is asked, logged `decision=fail_closed_open_file_cap`. CLOSE returns a slot.
pub const MAX_OPEN_FILES_PER_CONNECTION: usize = 1024;

/// A peer over [`MAX_CONNECTIONS`] gets a plain close, as a real SMB server does.
///
/// Every SMB2 response — an error response included — echoes the request's MessageId, TreeId
/// and SessionId, and this peer has sent no request to echo. A response with those fields
/// invented is a protocol violation rather than a diagnosis. Samba past `max smbd processes`
/// and Windows past its connection limit both close without a message; the reason is in the
/// log, tagged `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// The largest WRITE this server accepts, advertised as `MaxWriteSize` in the NEGOTIATE
/// response. MS-SMB2 3.3.5.13: a WRITE longer than the negotiated `MaxWriteSize` MUST fail with
/// `STATUS_INVALID_PARAMETER`, and it does, before the model is asked.
pub const MAX_WRITE_SIZE: u32 = 1024 * 1024;

/// The largest SMB2 message (one Direct TCP frame) this server reads, and its declared
/// `max_inbound_bytes`.
///
/// The transport header announces the whole message's length before any of it is read, so this
/// is the one number that bounds what a peer can make the server allocate: `MAX_WRITE_SIZE` of
/// data plus 64 KiB for the header, the WRITE's fixed body and anything compounded with it. A
/// frame announcing more is refused after reading only its 64-byte SMB2 header — enough to
/// answer `STATUS_INVALID_PARAMETER` to the right MessageId — and the connection then closes,
/// because the rest of the frame is unread and reading on would parse it as the next message.
pub const MAX_MESSAGE_BYTES: usize = MAX_WRITE_SIZE as usize + 64 * 1024;

/// Requests one compound frame may carry that the server will act on.
///
/// A frame of `MAX_MESSAGE_BYTES` has room for ~17 000 64-byte headers linked by
/// `NextCommand`, and every one could be a CREATE or READ the model is asked about — one frame
/// buying thousands of model calls. Real clients compound a handful (smbprotocol's stat is
/// seven; the Windows and Linux redirectors stay under ten). Requests past this many are each
/// answered `STATUS_INSUFFICIENT_RESOURCES` to their own MessageId without being acted on,
/// logged `decision=fail_closed_compound_cap`, so the client can still correlate every reply.
pub const MAX_COMPOUND_REQUESTS: usize = 32;

/// The most response bytes one compound reply carries before further responses in it are
/// replaced by `STATUS_INSUFFICIENT_RESOURCES`.
///
/// The Direct TCP header can announce at most 2^24 - 1 bytes, and a compound of READs can ask
/// for more than that (32 x `MaxReadSize` is 32 MiB). Without this the reply could not be framed
/// at all. The headroom is what the refusals themselves can cost: at most
/// `MAX_MESSAGE_BYTES / 64` requests in a frame, each refused in 80 padded bytes, is ~1.4 MB,
/// so 2 MiB below the frame limit keeps the whole chain frameable whatever follows. Logged
/// `decision=fail_closed_response_too_large`.
pub const MAX_RESPONSE_FRAME_BYTES: usize = wire::NBSS_MAX_LEN - 2 * 1024 * 1024;

/// The largest READ this server answers, advertised as `MaxReadSize`. MS-SMB2 3.3.5.12: a READ
/// asking for more MUST fail with `STATUS_INVALID_PARAMETER`, and it does, before the model is
/// asked, logged `decision=fail_closed_read_too_large`.
pub const MAX_READ_SIZE: u32 = 1024 * 1024;

/// The largest output buffer a QUERY_INFO or QUERY_DIRECTORY may ask for, advertised as
/// `MaxTransactSize`. MS-SMB2 3.3.5.18 and 3.3.5.20: an `OutputBufferLength` past it MUST fail
/// with `STATUS_INVALID_PARAMETER`, before the model is asked.
pub const MAX_TRANSACT_SIZE: u32 = 1024 * 1024;

/// A fixed server GUID. Clients key cached connection state on it; one per process is enough.
const SERVER_GUID: [u8; 16] = [
    0x4e, 0x65, 0x74, 0x47, 0x65, 0x74, 0x53, 0x4d, 0x42, 0x32, 0x2d, 0x73, 0x72, 0x76, 0x01, 0x00,
];

/// `STATUS_NOT_A_DIRECTORY`: the client asked for a directory and the model said file.
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
/// `STATUS_FILE_IS_A_DIRECTORY`: the client asked for a non-directory and the model said dir.
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
/// `STATUS_INFO_LENGTH_MISMATCH`: the client's output buffer cannot hold the answer.
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

// CREATE request fields (MS-SMB2 2.2.13).
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

// QUERY_DIRECTORY request flags (MS-SMB2 2.2.33).
const RESTART_SCANS: u8 = 0x01;
const RETURN_SINGLE_ENTRY: u8 = 0x02;
const REOPEN: u8 = 0x10;

/// The dialects this server speaks, best first.
const DIALECT_SMB_2_1: u16 = 0x0210;
const DIALECT_SMB_2_0_2: u16 = 0x0202;

/// SMB server that provides LLM-controlled file system
pub struct SmbServer;

/// An SMB2 session. It exists from the first SESSION_SETUP of an NTLMSSP exchange, and becomes
/// `authenticated` only when the model has admitted the user.
#[derive(Debug, Clone)]
struct SmbSession {
    username: String,
    authenticated: bool,
}

/// SMB2 tree connection state
#[derive(Debug, Clone)]
struct SmbTreeConnect {
    session_id: u64,
    share_name: String,
    is_pipe: bool,
}

/// An open file or directory.
#[derive(Debug, Clone)]
struct SmbFileHandle {
    path: String,
    tree_id: u32,
    meta: FileMeta,
    /// Whether `meta.size` came from the model, so a later QUERY_INFO on the same handle need
    /// not ask again.
    size_known: bool,
    /// An enumeration in progress on a directory handle: the entries not yet returned.
    listing: Option<VecDeque<(String, FileMeta)>>,
}

/// Per-connection SMB state
struct SmbConnectionState {
    sessions: HashMap<u64, SmbSession>,
    trees: HashMap<u32, SmbTreeConnect>,
    files: HashMap<[u8; 16], SmbFileHandle>,
    next_session_id: u64,
    next_tree_id: u32,
    next_file_index: u64,
}

impl SmbConnectionState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            trees: HashMap::new(),
            files: HashMap::new(),
            next_session_id: 1,
            next_tree_id: 1,
            next_file_index: 1,
        }
    }

    fn has_authenticated_session(&self) -> bool {
        self.sessions.values().any(|s| s.authenticated)
    }

    fn allocate_session(&mut self, username: String, authenticated: bool) -> u64 {
        let sid = self.next_session_id;
        self.next_session_id += 1;
        self.sessions.insert(
            sid,
            SmbSession {
                username,
                authenticated,
            },
        );
        sid
    }
}

/// Everything a command handler needs besides the request itself.
struct Ctx<'a> {
    llm_client: &'a OllamaClient,
    app_state: &'a Arc<AppState>,
    server_id: ServerId,
    connection_id: ConnectionId,
    protocol: &'a Arc<SmbProtocol>,
    state: &'a Mutex<SmbConnectionState>,
    status_tx: &'a mpsc::UnboundedSender<String>,
    deadlines: Deadlines,
}

/// What earlier requests in the same compound chain established, for a request flagged
/// `RELATED_OPERATIONS` (MS-SMB2 3.3.5.2.7.2).
#[derive(Debug, Default, Clone, Copy)]
struct Chain {
    session_id: u64,
    tree_id: u32,
    file_id: Option<[u8; 16]>,
}

/// A FileId of all ones in a related request means "the handle the chain just opened".
const RELATED_FILE_ID: [u8; 16] = [0xFF; 16];

impl SmbServer {
    /// Spawn SMB server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        deadlines: Deadlines,
    ) -> Result<SocketAddr> {
        Log::new(Some(&status_tx)).info(format!(
            "SMB server (LLM-controlled, guest-only) starting on {}",
            listen_addr
        ));

        let protocol = Arc::new(SmbProtocol::new());

        // Bind TCP listener
        let listener = TcpListener::bind(listen_addr)
            .await
            .context("Failed to bind SMB TCP listener")?;

        let actual_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("SMB server listening on {}", actual_addr));

        // Spawn connection acceptor
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            info!("SMB server connection acceptor started");

            loop {
                trace!("SMB acceptor: waiting for connection");

                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "SMB",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, peer_addr, permit)) => {
                        Log::new(Some(&status_tx))
                            .info(format!("SMB connection accepted from {}", peer_addr));

                        // Spawn per-connection handler
                        let llm_client = llm_client.clone();
                        let app_state = app_state.clone();
                        let protocol = protocol.clone();
                        let status_tx = status_tx.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // peers rather than accepts.
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    peer_addr,
                                    llm_client,
                                    app_state,
                                    server_id,
                                    protocol,
                                    status_tx.clone(),
                                    deadlines,
                                )
                                .await
                                {
                                    Log::new(Some(&status_tx)).error(format!(
                                        "SMB connection error from {}: {}",
                                        peer_addr, e
                                    ));
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("SMB accept error: {}", e));
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(actual_addr)
    }

    /// Handle a single SMB connection
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: ServerId,
        protocol: Arc<SmbProtocol>,
        status_tx: mpsc::UnboundedSender<String>,
        deadlines: Deadlines,
    ) -> Result<()> {
        // Generate connection ID
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);

        Log::new(Some(&status_tx)).info(format!(
            "SMB connection {} from {}",
            connection_id, peer_addr
        ));

        // Get local address for tracking
        let local_addr = stream
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

        // Track connection in app state
        let now = crate::utils::clock::Instant::now();
        let conn_state = ServerConnectionState {
            id: connection_id,
            remote_addr: peer_addr,
            local_addr,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::empty(),
        };

        app_state
            .add_connection_to_server(server_id, conn_state)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split the socket (never clone it): the read half stays with the session loop while
        // the write half is shared, through an `Arc<Mutex<..>>`, with the dashboard's
        // peer-command task. Both write through the same lock, so an injected message cannot
        // interleave with a response half-way through an SMB2 frame.
        let (reader, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(Mutex::new(write_half));
        let mut reader = SmbReader::new(reader);

        // Peer messaging: the dashboard's "[ message this peer ]" / "[ disconnect this peer ]"
        // inject an action into THIS connection through the same executor the LLM path uses.
        // Registered BEFORE the first read, because SMB2 is client-speaks-first and a manual
        // `*` rule parks the very first NEGOTIATE for a human — the operator must be able to
        // reach, or hang up, a connection that has not said anything yet.
        let peer_rx = crate::server::peer_support::register_peer_channel(
            &app_state,
            server_id,
            connection_id.as_u32(),
        )
        .await;
        crate::server::peer_support::spawn_peer_command_task(
            peer_rx,
            protocol.clone(),
            app_state.clone(),
            server_id,
            connection_id.as_u32(),
            write_half.clone(),
            status_tx.clone(),
        );

        let ctx_state = Mutex::new(SmbConnectionState::new());
        let ctx = Ctx {
            llm_client: &llm_client,
            app_state: &app_state,
            server_id,
            connection_id,
            protocol: &protocol,
            state: &ctx_state,
            status_tx: &status_tx,
            deadlines,
        };
        Self::run_smb_session(&mut reader, &write_half, peer_addr, &ctx).await;

        // Every exit path — EOF, an idle timeout, a read or write error, a refused frame —
        // lands here. Dropping the handle also ends the peer command task, which releases its
        // clone of the write half; the explicit shutdown makes the FIN immediate rather than
        // waiting on it.
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        let _ = write_half.lock().await.shutdown().await;

        // Mark connection as closed
        app_state
            .update_connection_status(server_id, connection_id, ConnectionStatus::Closed)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        Log::new(Some(&status_tx)).info(format!("SMB connection {} closed", connection_id));

        Ok(())
    }

    /// The read/dispatch/reply loop. Every exit is a `break`, so the caller's teardown always
    /// runs; writes go through the shared `write_half` and are counted there.
    ///
    /// **Transport.** SMB2 over TCP is framed (MS-SMB2 2.1): each message, or compound chain of
    /// messages, is preceded by a byte of zero and a 24-bit big-endian length. The SMB2 header
    /// itself carries no length, so this frame is the only thing that says where one request
    /// ends — every request is read whole before anything is decided about it, which is what
    /// keeps the stream in step when a request is refused.
    async fn run_smb_session<R, W>(
        reader: &mut SmbReader<R>,
        write_half: &Arc<Mutex<W>>,
        peer_addr: SocketAddr,
        ctx: &Ctx<'_>,
    ) where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            // The deadline wraps this read and nothing else. The LLM round-trip that decides a
            // login or answers a request, and a `manual` rule parking either for a human
            // (`src/state/intercepts.rs`, 300s by default), all happen below once a whole
            // message has been read — outside every deadline by construction. What is bounded
            // is a peer holding the connection while sending nothing.
            let header_timeout = if ctx.state.lock().await.has_authenticated_session() {
                ctx.deadlines.idle
            } else {
                ctx.deadlines.first_message
            };
            let mut transport = [0u8; 4];
            match tokio::time::timeout(header_timeout, reader.read_exact_counted(&mut transport))
                .await
            {
                Err(_) => {
                    Log::new(Some(ctx.status_tx)).info(format!(
                        "SMB peer {} sent nothing for {}s; closing idle connection",
                        peer_addr,
                        header_timeout.as_secs()
                    ));
                    break;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    Log::new(Some(ctx.status_tx))
                        .info(format!("SMB client {} disconnected", peer_addr));
                    break;
                }
                Ok(Err(e)) => {
                    error!("SMB read error from {}: {}", peer_addr, e);
                    break;
                }
                Ok(Ok(_)) => {}
            }
            flush_read_stats(reader, ctx.app_state, ctx.server_id, ctx.connection_id).await;

            let (kind, len) = wire::parse_frame_header(transport);
            match kind {
                wire::NBSS_SESSION_MESSAGE => {}
                wire::NBSS_KEEPALIVE => continue,
                wire::NBSS_SESSION_REQUEST if len <= 256 => {
                    // A client that dialled port 139 names the called and calling NetBIOS
                    // names first. Any name is this server's; say yes and carry on.
                    let mut names = vec![0u8; len];
                    if read_body_exact(reader, &mut names, ctx.deadlines.body)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let positive = [wire::NBSS_POSITIVE_RESPONSE, 0, 0, 0];
                    if write_counted(write_half, &positive, ctx).await.is_err() {
                        break;
                    }
                    continue;
                }
                _ => {
                    Log::new(Some(ctx.status_tx)).warn(format!(
                        "SMB peer {} sent {:02x?}, which is not a Direct TCP session message \
                         (MS-SMB2 2.1: 0x00 and a 24-bit length); closing",
                        peer_addr, transport
                    ));
                    break;
                }
            }

            if len < HEADER_LEN {
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "SMB peer {} framed a {}-byte message, shorter than an SMB2 header; closing",
                    peer_addr, len
                ));
                break;
            }

            if len > MAX_MESSAGE_BYTES {
                // Refused before the frame is allocated. Only the SMB2 header is read, so the
                // refusal can name the request it refuses; the rest is unread, so the stream
                // is out of step and the connection closes after the reply.
                let mut header = [0u8; HEADER_LEN];
                if read_body_exact(reader, &mut header, ctx.deadlines.body)
                    .await
                    .is_ok()
                {
                    if let Some(req) = RequestHeader::parse(&header) {
                        Log::new(Some(ctx.status_tx)).warn(format!(
                            "SMB2 command 0x{:04x} in a {} byte frame refused \
                             (decision=fail_closed_message_too_large, limit {}); replying \
                             STATUS_INVALID_PARAMETER and closing",
                            req.command, len, MAX_MESSAGE_BYTES
                        ));
                        let reply = wire::error_response(&ResponseHeader::for_request(
                            &req,
                            status::INVALID_PARAMETER,
                        ));
                        let _ = write_counted(write_half, &wire::frame(&reply), ctx).await;
                    }
                }
                flush_read_stats(reader, ctx.app_state, ctx.server_id, ctx.connection_id).await;
                break;
            }

            let mut message = vec![0u8; len];
            if let Err(e) = read_body_exact(reader, &mut message, ctx.deadlines.body).await {
                debug!(
                    "SMB peer {} did not deliver its announced frame: {}",
                    peer_addr, e
                );
                break;
            }
            flush_read_stats(reader, ctx.app_state, ctx.server_id, ctx.connection_id).await;

            let responses = match Self::process_frame(&message, peer_addr, ctx).await {
                Some(responses) => responses,
                None => break,
            };
            if responses.is_empty() {
                continue;
            }
            let framed = wire::frame(&wire::chain(responses));
            match write_counted(write_half, &framed, ctx).await {
                Ok(()) => trace!(
                    "SMB2 response sent to {}, {} bytes",
                    peer_addr,
                    framed.len()
                ),
                Err(e) => {
                    error!("Failed to send SMB2 response to {}: {}", peer_addr, e);
                    break;
                }
            }
        }
    }

    /// Answer every request in one frame. A frame carries one request, or a compound chain
    /// linked by `NextCommand` (MS-SMB2 3.3.5.2.7); the responses are chained the same way.
    ///
    /// `None` means the frame is not SMB2 at all and the connection should close.
    async fn process_frame(
        frame: &[u8],
        peer_addr: SocketAddr,
        ctx: &Ctx<'_>,
    ) -> Option<Vec<Vec<u8>>> {
        let mut responses = Vec::new();
        let mut chain = Chain::default();
        let mut offset = 0usize;
        let mut requests = 0usize;
        let mut response_bytes = 0usize;

        loop {
            let rest = &frame[offset..];
            let located = match wire::next_in_chain(rest) {
                Ok(located) => located,
                Err(wire::ChainError::NotSmb2) if offset == 0 => {
                    let what = if rest.starts_with(b"\xFFSMB") {
                        "an SMB1 message; this server speaks SMB2 only"
                    } else {
                        "not an SMB2 message"
                    };
                    Log::new(Some(ctx.status_tx)).warn(format!(
                        "Invalid SMB2 signature from {} ({})",
                        peer_addr, what
                    ));
                    return None;
                }
                Err(wire::ChainError::NotSmb2) => {
                    warn!(
                        "SMB2 compound chain from {} ends in a malformed request",
                        peer_addr
                    );
                    break;
                }
                Err(wire::ChainError::BadNextCommand(req)) => {
                    warn!(
                        "SMB2 NextCommand {} from {} does not point at a request; refusing",
                        req.next_command, peer_addr
                    );
                    responses.push(wire::error_response(&ResponseHeader::for_request(
                        &req,
                        status::INVALID_PARAMETER,
                    )));
                    break;
                }
            };
            let mut req = located.header;
            let message = located.message;

            if req.is_related() && offset > 0 {
                req.session_id = chain.session_id;
                req.tree_id = chain.tree_id;
            }
            chain.session_id = req.session_id;
            chain.tree_id = req.tree_id;

            debug!("SMB2 command 0x{:04x} from {}", req.command, peer_addr);
            requests += 1;
            let response = if requests > MAX_COMPOUND_REQUESTS {
                if requests == MAX_COMPOUND_REQUESTS + 1 {
                    Log::new(Some(ctx.status_tx)).warn(format!(
                        "SMB2 compound from {} carries more than {} requests \
                         (decision=fail_closed_compound_cap); answering the rest \
                         STATUS_INSUFFICIENT_RESOURCES without acting on them",
                        peer_addr, MAX_COMPOUND_REQUESTS
                    ));
                }
                Some(wire::error_response(&ResponseHeader::for_request(
                    &req,
                    status::INSUFFICIENT_RESOURCES,
                )))
            } else {
                match Self::handle_request(&req, message, &mut chain, ctx).await {
                    Ok(response) => response,
                    Err(e) => {
                        error!("SMB2 command 0x{:04x} failed: {}", req.command, e);
                        Some(wire::error_response(&ResponseHeader::for_request(
                            &req,
                            status::INTERNAL_ERROR,
                        )))
                    }
                }
            };
            if let Some(mut response) = response {
                // Each response but the last is padded to 8 bytes in the chain.
                if response_bytes + response.len().div_ceil(8) * 8 > MAX_RESPONSE_FRAME_BYTES {
                    Log::new(Some(ctx.status_tx)).warn(format!(
                        "SMB2 command 0x{:04x} from {}: its {} byte response would take the \
                         compound reply past {} bytes (decision=fail_closed_response_too_large); \
                         replying STATUS_INSUFFICIENT_RESOURCES",
                        req.command,
                        peer_addr,
                        response.len(),
                        MAX_RESPONSE_FRAME_BYTES
                    ));
                    response = wire::error_response(&ResponseHeader::for_request(
                        &req,
                        status::INSUFFICIENT_RESOURCES,
                    ));
                }
                response_bytes += response.len().div_ceil(8) * 8;
                responses.push(response);
            }

            match located.next {
                Some(next) => offset += next,
                None => break,
            }
        }
        Some(responses)
    }

    /// Answer one SMB2 request. `message` is the request's header and body, and nothing past
    /// it. `Ok(None)` is the one command that gets no response (CANCEL).
    async fn handle_request(
        req: &RequestHeader,
        message: &[u8],
        chain: &mut Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let body = &message[HEADER_LEN..];
        let error = |code: u32| -> Result<Option<Vec<u8>>> {
            Ok(Some(wire::error_response(&ResponseHeader::for_request(
                req, code,
            ))))
        };

        // Nothing but the handshake may be served on a session the model has not admitted.
        //
        // `SmbConnectionState.sessions` was once written by the successful auth path and read
        // by nothing but a log line, so the authentication decision governed exactly one
        // response: a peer could open a socket and send CREATE or READ straight away, and a
        // peer whose login the model had just *denied* could send CREATE on the same
        // connection and be served. The SessionId in the header has to name a session the
        // model admitted, or asking the model was decorative.
        let exempt = matches!(
            req.command,
            command::NEGOTIATE | command::SESSION_SETUP | command::ECHO | command::CANCEL
        );
        if !exempt {
            let admitted = ctx
                .state
                .lock()
                .await
                .sessions
                .get(&req.session_id)
                .is_some_and(|s| s.authenticated);
            if !admitted {
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "SMB2 command 0x{:04x} refused (decision=fail_closed_no_session): session \
                     {} is not an authenticated session on this connection; replying \
                     STATUS_USER_SESSION_DELETED",
                    req.command, req.session_id
                ));
                return error(status::USER_SESSION_DELETED);
            }
        }

        // Commands addressed to a share need a tree the same session connected.
        let needs_tree = !matches!(
            req.command,
            command::NEGOTIATE
                | command::SESSION_SETUP
                | command::LOGOFF
                | command::TREE_CONNECT
                | command::ECHO
                | command::CANCEL
        );
        if needs_tree {
            let connected = ctx
                .state
                .lock()
                .await
                .trees
                .get(&req.tree_id)
                .is_some_and(|t| t.session_id == req.session_id);
            if !connected {
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "SMB2 command 0x{:04x} refused: tree {} is not connected on session {}; \
                     replying STATUS_NETWORK_NAME_DELETED",
                    req.command, req.tree_id, req.session_id
                ));
                return error(status::NETWORK_NAME_DELETED);
            }
        }

        match req.command {
            command::NEGOTIATE => Self::negotiate(req, body, ctx),
            command::SESSION_SETUP => Self::session_setup(req, message, ctx).await,
            command::LOGOFF => {
                let mut s = ctx.state.lock().await;
                if let Some(session) = s.sessions.remove(&req.session_id) {
                    debug!(
                        "SMB2 LOGOFF: session {} ({:?})",
                        req.session_id, session.username
                    );
                }
                s.trees.retain(|_, t| t.session_id != req.session_id);
                // Handles on the trees just dropped can never be reached again.
                let trees: std::collections::HashSet<u32> = s.trees.keys().copied().collect();
                s.files.retain(|_, f| trees.contains(&f.tree_id));
                Ok(Some(wire::empty_response(&ResponseHeader::for_request(
                    req,
                    status::SUCCESS,
                ))))
            }
            command::TREE_CONNECT => Self::tree_connect(req, message, ctx).await,
            command::TREE_DISCONNECT => {
                let mut s = ctx.state.lock().await;
                s.trees.remove(&req.tree_id);
                s.files.retain(|_, f| f.tree_id != req.tree_id);
                Ok(Some(wire::empty_response(&ResponseHeader::for_request(
                    req,
                    status::SUCCESS,
                ))))
            }
            command::CREATE => Self::create(req, message, chain, ctx).await,
            command::CLOSE => Self::close(req, body, chain, ctx).await,
            command::FLUSH => {
                let Some(file_id) = wire::parse_flush(body) else {
                    return error(status::INVALID_PARAMETER);
                };
                if Self::handle(ctx, req, file_id, chain).await.is_none() {
                    return error(status::FILE_CLOSED);
                }
                Ok(Some(wire::empty_response(&ResponseHeader::for_request(
                    req,
                    status::SUCCESS,
                ))))
            }
            command::READ => Self::read(req, body, chain, ctx).await,
            command::WRITE => Self::write(req, message, chain, ctx).await,
            command::QUERY_INFO => Self::query_info(req, body, chain, ctx).await,
            command::QUERY_DIRECTORY => Self::query_directory(req, message, chain, ctx).await,
            command::ECHO => Ok(Some(wire::empty_response(&ResponseHeader::for_request(
                req,
                status::SUCCESS,
            )))),
            // MS-SMB2 3.3.5.16: a CANCEL is never answered.
            command::CANCEL => Ok(None),
            command::IOCTL => {
                // No FSCTL is implemented: no DFS referrals, no pipe transceive, and
                // VALIDATE_NEGOTIATE_INFO belongs to SMB 3.x, which this server does not offer.
                debug!("SMB2 IOCTL refused: no FSCTL is implemented");
                error(status::INVALID_DEVICE_REQUEST)
            }
            other => {
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "Unsupported SMB2 command 0x{:04x}; replying STATUS_NOT_SUPPORTED",
                    other
                ));
                error(status::NOT_SUPPORTED)
            }
        }
    }

    /// NEGOTIATE (MS-SMB2 3.3.5.4). Picks SMB 2.1 if offered, else 2.0.2, and offers SPNEGO
    /// with NTLMSSP as the only mechanism.
    fn negotiate(req: &RequestHeader, body: &[u8], ctx: &Ctx<'_>) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(offered) = wire::parse_negotiate(body) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        let Some(dialect) = [DIALECT_SMB_2_1, DIALECT_SMB_2_0_2]
            .into_iter()
            .find(|d| offered.contains(d))
        else {
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 NEGOTIATE offered no dialect this server speaks ({:04x?}); it speaks \
                 0x0210 and 0x0202",
                offered
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::NOT_SUPPORTED),
            )));
        };
        Log::new(Some(ctx.status_tx)).debug(format!(
            "SMB2 NEGOTIATE: choosing dialect 0x{:04x}",
            dialect
        ));

        let params = wire::NegotiateParams {
            dialect,
            server_guid: SERVER_GUID,
            // No DFS, no leasing, no multi-credit: none is implemented, and each one is a
            // promise a client acts on.
            capabilities: 0,
            max_transact_size: MAX_TRANSACT_SIZE,
            max_read_size: MAX_READ_SIZE,
            // The bound the WRITE arm enforces, so a client never sends a write it will refuse.
            max_write_size: MAX_WRITE_SIZE,
            system_time: filetime_now(),
            security_blob: auth::negotiate_blob(),
        };
        Ok(Some(wire::negotiate_response(&hdr, &params)))
    }

    /// SESSION_SETUP (MS-SMB2 3.3.5.5).
    ///
    /// A real client sends two: an NTLMSSP NEGOTIATE, answered with a CHALLENGE and
    /// `STATUS_MORE_PROCESSING_REQUIRED` without asking anyone, then an AUTHENTICATE naming the
    /// user, which is what the model decides on. A SESSION_SETUP with an empty security buffer
    /// is a one-step guest login, decided the same way.
    async fn session_setup(
        req: &RequestHeader,
        message: &[u8],
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(blob) = wire::parse_session_setup(message) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };

        if blob.is_empty() {
            // A one-step login allocates a session if the model admits it, so the cap is
            // checked before the model is asked: a refusal it would have to make anyway must
            // not cost a model call.
            if let Some(refusal) = Self::session_cap_refusal(req, ctx).await {
                return Ok(Some(refusal));
            }
            return Self::decide_login(
                req,
                None,
                "guest",
                "",
                "guest",
                false,
                auth::Wrapping::Raw,
                ctx,
            )
            .await;
        }

        let Some((token, wrapping)) = auth::find_ntlmssp(blob) else {
            Log::new(Some(ctx.status_tx)).warn(
                "SMB2 SESSION_SETUP refused (decision=fail_closed_unsupported_mechanism): the \
                 security buffer carries no NTLMSSP token, and NTLMSSP is the only mechanism \
                 this server offers; replying STATUS_LOGON_FAILURE",
            );
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::LOGON_FAILURE),
            )));
        };

        match auth::message_type(token) {
            Some(auth::NTLMSSP_NEGOTIATE) => {
                // A NEGOTIATE leg naming a session whose exchange is still in progress restarts
                // that exchange (MS-SMB2 3.3.5.5) rather than opening another; anything else
                // opens a new session, which is where the per-connection cap applies.
                let restarted = {
                    let s = ctx.state.lock().await;
                    s.sessions
                        .get(&req.session_id)
                        .is_some_and(|s| !s.authenticated)
                        .then_some(req.session_id)
                };
                let session_id = match restarted {
                    Some(sid) => sid,
                    None => {
                        if let Some(refusal) = Self::session_cap_refusal(req, ctx).await {
                            return Ok(Some(refusal));
                        }
                        ctx.state
                            .lock()
                            .await
                            .allocate_session(String::new(), false)
                    }
                };
                let challenge = auth::challenge(
                    auth::negotiate_flags(token),
                    server_challenge(),
                    filetime_now(),
                );
                debug!(
                    "SMB2 SESSION_SETUP: NTLMSSP NEGOTIATE on new session {}; sending CHALLENGE",
                    session_id
                );
                let hdr = hdr
                    .with_status(status::MORE_PROCESSING_REQUIRED)
                    .with_session_id(session_id);
                Ok(Some(wire::session_setup_response(
                    &hdr,
                    0,
                    &auth::wrap_challenge(&challenge, wrapping),
                )))
            }
            Some(auth::NTLMSSP_AUTHENTICATE) => {
                let pending = ctx
                    .state
                    .lock()
                    .await
                    .sessions
                    .get(&req.session_id)
                    .is_some_and(|s| !s.authenticated);
                if !pending {
                    Log::new(Some(ctx.status_tx)).warn(format!(
                        "SMB2 SESSION_SETUP: NTLMSSP AUTHENTICATE for session {}, which has no \
                         exchange in progress; replying STATUS_USER_SESSION_DELETED",
                        req.session_id
                    ));
                    return Ok(Some(wire::error_response(
                        &hdr.with_status(status::USER_SESSION_DELETED),
                    )));
                }
                let Some(who) = auth::parse_authenticate(token) else {
                    ctx.state.lock().await.sessions.remove(&req.session_id);
                    return Ok(Some(wire::error_response(
                        &hdr.with_status(status::INVALID_PARAMETER),
                    )));
                };
                let auth_type = if who.anonymous { "anonymous" } else { "ntlm" };
                Self::decide_login(
                    req,
                    Some(req.session_id),
                    &who.user,
                    &who.domain,
                    auth_type,
                    who.anonymous,
                    wrapping,
                    ctx,
                )
                .await
            }
            _ => Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            ))),
        }
    }

    /// Ask the model whether `username` may log in, and answer the SESSION_SETUP accordingly.
    /// `pending` is the session an NTLMSSP exchange already allocated; `None` allocates one.
    #[allow(clippy::too_many_arguments)]
    async fn decide_login(
        req: &RequestHeader,
        pending: Option<u64>,
        username: &str,
        domain: &str,
        auth_type: &str,
        anonymous: bool,
        wrapping: auth::Wrapping,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        Log::new(Some(ctx.status_tx)).info(format!(
            "SMB2 SESSION_SETUP for user: {:?} ({})",
            username, auth_type
        ));

        let mut params = serde_json::json!({
            "username": username,
            "auth_type": auth_type,
        });
        if !domain.is_empty() {
            params["domain"] = serde_json::json!(domain);
        }
        if auth_type == "ntlm" {
            // Said to the model in as many words: nothing checked the password.
            params["password_verified"] = serde_json::json!(false);
        }

        let actions = match Self::consult_llm(ctx, "session_setup", params).await {
            Ok(actions) => actions,
            Err(e) => {
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "LLM error during SMB authentication for user {:?} \
                     (decision=fail_closed_llm_error) - denying auth: {}",
                    username, e
                ));
                return Self::deny_login(req, pending, ctx).await;
            }
        };

        // `smb_auth_success` only: the model's affirmative answer is the one way in.
        let auth_allowed = actions
            .iter()
            .any(|a| a.get("type").and_then(|t| t.as_str()) == Some("smb_auth_success"));

        if !auth_allowed {
            // Kept apart in the log because the wire cannot carry the difference: both answers
            // refuse the login, but only one of them is a decision.
            let decision = if actions.is_empty() {
                "fail_closed_no_action"
            } else {
                "model_reject"
            };
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB authentication denied for user {:?} (decision={}); replying \
                 STATUS_ACCESS_DENIED",
                username, decision
            ));
            return Self::deny_login(req, pending, ctx).await;
        }

        let session_id = {
            let mut s = ctx.state.lock().await;
            match pending {
                Some(sid) => {
                    if let Some(session) = s.sessions.get_mut(&sid) {
                        session.username = username.to_string();
                        session.authenticated = true;
                    }
                    sid
                }
                None => s.allocate_session(username.to_string(), true),
            }
        };
        Log::new(Some(ctx.status_tx)).info(format!(
            "SMB authentication successful for user: {:?} (session {})",
            username, session_id
        ));
        let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());

        // Nothing verified the password, so no session is anything but a guest (or, for an
        // anonymous login, a null) session — which is also what tells the client there is no
        // key to sign with.
        let flags = if anonymous {
            wire::SESSION_FLAG_IS_NULL
        } else {
            wire::SESSION_FLAG_IS_GUEST
        };
        let hdr = ResponseHeader::for_request(req, status::SUCCESS).with_session_id(session_id);
        Ok(Some(wire::session_setup_response(
            &hdr,
            flags,
            &auth::accept_completed(wrapping),
        )))
    }

    /// Refuse a login: forget the session the exchange allocated and answer ACCESS_DENIED.
    async fn deny_login(
        req: &RequestHeader,
        pending: Option<u64>,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(sid) = pending {
            ctx.state.lock().await.sessions.remove(&sid);
        }
        let hdr = ResponseHeader::for_request(req, status::ACCESS_DENIED);
        Ok(Some(wire::session_setup_response(&hdr, 0, &[])))
    }

    /// The refusal for a SESSION_SETUP that would open a session past
    /// [`MAX_SESSIONS_PER_CONNECTION`], or `None` if there is room.
    async fn session_cap_refusal(req: &RequestHeader, ctx: &Ctx<'_>) -> Option<Vec<u8>> {
        let (held, pending) = {
            let s = ctx.state.lock().await;
            let pending = s.sessions.values().filter(|s| !s.authenticated).count();
            (s.sessions.len(), pending)
        };
        if held < MAX_SESSIONS_PER_CONNECTION {
            return None;
        }
        Log::new(Some(ctx.status_tx)).warn(format!(
            "SMB2 SESSION_SETUP refused (decision=fail_closed_session_cap): this connection \
             already holds {} sessions ({} still mid-exchange), the most one connection may \
             hold is {}; replying STATUS_INSUFFICIENT_RESOURCES",
            held, pending, MAX_SESSIONS_PER_CONNECTION
        ));
        Some(wire::error_response(&ResponseHeader::for_request(
            req,
            status::INSUFFICIENT_RESOURCES,
        )))
    }

    /// TREE_CONNECT (MS-SMB2 3.3.5.7). Every share name is accepted without asking the model:
    /// the share is only a name for the root of the tree the model invents, and admission was
    /// decided at SESSION_SETUP. `IPC$` connects as a pipe share, and every operation on it is
    /// refused, because no named pipe is implemented.
    async fn tree_connect(
        req: &RequestHeader,
        message: &[u8],
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(path) = wire::parse_tree_connect(message) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        let share = path.rsplit('\\').next().unwrap_or("").to_string();
        let is_pipe = share.eq_ignore_ascii_case("IPC$");

        let tree_id = {
            let mut s = ctx.state.lock().await;
            // No model call stands in front of a TREE_CONNECT, so nothing but this bound stops
            // one admitted session from growing the table by a tree per request.
            if s.trees.len() >= MAX_TREES_PER_CONNECTION {
                let held = s.trees.len();
                drop(s);
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "SMB2 TREE_CONNECT {} refused (decision=fail_closed_tree_cap): this \
                     connection already holds {} tree connects, the most one connection may \
                     hold is {}; replying STATUS_INSUFFICIENT_RESOURCES",
                    path, held, MAX_TREES_PER_CONNECTION
                ));
                return Ok(Some(wire::error_response(
                    &hdr.with_status(status::INSUFFICIENT_RESOURCES),
                )));
            }
            let tid = s.next_tree_id;
            s.next_tree_id += 1;
            s.trees.insert(
                tid,
                SmbTreeConnect {
                    session_id: req.session_id,
                    share_name: share.clone(),
                    is_pipe,
                },
            );
            tid
        };
        Log::new(Some(ctx.status_tx)).info(format!(
            "SMB2 TREE_CONNECT {} -> tree {} ({})",
            path,
            tree_id,
            if is_pipe { "pipe" } else { "disk" }
        ));
        let share_type = if is_pipe {
            wire::SHARE_TYPE_PIPE
        } else {
            wire::SHARE_TYPE_DISK
        };
        Ok(Some(wire::tree_connect_response(
            &hdr.with_tree_id(tree_id),
            share_type,
            0x001F_01FF,
        )))
    }

    /// Resolve a FileId from a request body, following a related compound's "the handle just
    /// opened". Returns the FileId and a copy of the handle.
    async fn handle(
        ctx: &Ctx<'_>,
        req: &RequestHeader,
        mut file_id: [u8; 16],
        chain: &Chain,
    ) -> Option<([u8; 16], SmbFileHandle)> {
        if req.is_related() && file_id == RELATED_FILE_ID {
            file_id = chain.file_id?;
        }
        let s = ctx.state.lock().await;
        let handle = s.files.get(&file_id)?;
        (handle.tree_id == req.tree_id).then(|| (file_id, handle.clone()))
    }

    /// CREATE (MS-SMB2 3.3.5.9): the model decides whether the path opens, and as what.
    async fn create(
        req: &RequestHeader,
        message: &[u8],
        chain: &mut Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(wire::CreateRequest {
            disposition,
            options,
            path,
        }) = wire::parse_create(message)
        else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        let (is_pipe, open) = {
            let s = ctx.state.lock().await;
            let is_pipe = s.trees.get(&req.tree_id).is_some_and(|t| t.is_pipe);
            (is_pipe, s.files.len())
        };
        if is_pipe {
            debug!("SMB2 CREATE on a pipe share refused: no named pipe is implemented");
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::NOT_SUPPORTED),
            )));
        }
        // Checked before the model is asked, so a refusal the server would have to make anyway
        // costs no model call — and a static handler answering every CREATE cannot grow the
        // handle table without limit.
        if open >= MAX_OPEN_FILES_PER_CONNECTION {
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 CREATE {} refused (decision=fail_closed_open_file_cap): this connection \
                 already holds {} open handles, the most one connection may hold is {}; \
                 replying STATUS_TOO_MANY_OPENED_FILES",
                path, open, MAX_OPEN_FILES_PER_CONNECTION
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::TOO_MANY_OPENED_FILES),
            )));
        }

        Log::new(Some(ctx.status_tx)).info(format!("SMB2 CREATE request for: {}", path));

        let mut params = serde_json::json!({
            "path": path,
            "disposition": disposition_name(disposition),
            "directory_requested": options & FILE_DIRECTORY_FILE != 0,
        });
        // SMB2 has no DELETE command: a client deletes by opening with FILE_DELETE_ON_CLOSE and
        // closing (smbclient's `rm` and `rmdir`), so an open carrying it is a delete request and
        // the model has to be told so. Admitting the open admits the delete; CLOSE then answers
        // success without asking again.
        if options & FILE_DELETE_ON_CLOSE != 0 {
            params["delete_on_close"] = serde_json::json!(true);
        }
        let actions = match Self::consult_llm(ctx, "create", params).await {
            Ok(actions) => actions,
            Err(e) => {
                return Ok(Some(Self::llm_failure_response(
                    req, "CREATE", &path, &e, ctx,
                )))
            }
        };

        // Opening a handle is an access decision, so it takes an affirmative answer. Which of
        // the two the model picks reaches the wire as FILE_ATTRIBUTE_DIRECTORY, which is what
        // makes a client issue QUERY_DIRECTORY instead of READ. Neither present is a refusal:
        // silence must not become consent for an admission decision.
        let action_type =
            |a: &serde_json::Value| a.get("type").and_then(|t| t.as_str()).map(String::from);
        let dir_action = actions
            .iter()
            .find(|a| action_type(a).as_deref() == Some("smb_create_directory"));
        let file_action = actions
            .iter()
            .find(|a| action_type(a).as_deref() == Some("smb_create_file"));
        let is_directory = dir_action.is_some();
        if dir_action.is_none() && file_action.is_none() {
            let decision = if actions.is_empty() {
                "fail_closed_no_action"
            } else {
                "model_reject"
            };
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 CREATE refused for {} (decision={}): no smb_create_file or \
                 smb_create_directory in the answer; replying STATUS_ACCESS_DENIED",
                path, decision
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::ACCESS_DENIED),
            )));
        }
        if is_directory && options & FILE_NON_DIRECTORY_FILE != 0 {
            return Ok(Some(wire::error_response(
                &hdr.with_status(STATUS_FILE_IS_A_DIRECTORY),
            )));
        }
        if !is_directory && options & FILE_DIRECTORY_FILE != 0 {
            return Ok(Some(wire::error_response(
                &hdr.with_status(STATUS_NOT_A_DIRECTORY),
            )));
        }

        // The size the open reports as EndOfFile. A client may trust it and read no further
        // (smbprotocol does), so without it the file reads as empty until a QUERY_INFO asks.
        let declared_size = file_action
            .filter(|_| !is_directory)
            .and_then(|a| a.get("size"))
            .and_then(|v| v.as_u64());
        let (file_id, meta) = {
            let mut s = ctx.state.lock().await;
            let index = s.next_file_index;
            s.next_file_index += 1;
            let file_id = file_id_for(index);
            let meta = FileMeta {
                is_directory,
                size: declared_size.unwrap_or(0),
                time: 0,
                file_index: index,
            };
            s.files.insert(
                file_id,
                SmbFileHandle {
                    path: path.clone(),
                    tree_id: req.tree_id,
                    meta,
                    size_known: is_directory || declared_size.is_some(),
                    listing: None,
                },
            );
            (file_id, meta)
        };
        chain.file_id = Some(file_id);

        debug!(
            "SMB2 CREATE: allocated {} handle for {}",
            if is_directory { "directory" } else { "file" },
            path
        );
        let create_action = if disposition == FILE_CREATE {
            wire::FILE_CREATED
        } else {
            wire::FILE_OPENED
        };
        Ok(Some(wire::create_response(
            &hdr,
            &file_id,
            &meta,
            create_action,
        )))
    }

    /// CLOSE (MS-SMB2 3.3.5.10).
    async fn close(
        req: &RequestHeader,
        body: &[u8],
        chain: &Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some((flags, file_id)) = wire::parse_close(body) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        let Some((file_id, handle)) = Self::handle(ctx, req, file_id, chain).await else {
            Log::new(Some(ctx.status_tx)).warn("SMB2 CLOSE: unknown file handle");
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::FILE_CLOSED),
            )));
        };
        ctx.state.lock().await.files.remove(&file_id);
        Log::new(Some(ctx.status_tx)).info(format!("SMB2 CLOSE: {}", handle.path));
        let meta = (flags & wire::CLOSE_FLAG_POSTQUERY_ATTRIB != 0).then_some(&handle.meta);
        Ok(Some(wire::close_response(&hdr, meta)))
    }

    /// READ (MS-SMB2 3.3.5.12): the model supplies the whole file; the server answers the
    /// range the client asked for.
    async fn read(
        req: &RequestHeader,
        body: &[u8],
        chain: &Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(request) = wire::parse_read(body) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        if request.length > MAX_READ_SIZE {
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 READ of {} bytes refused (decision=fail_closed_read_too_large, \
                 MaxReadSize {}); replying STATUS_INVALID_PARAMETER",
                request.length, MAX_READ_SIZE
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        }
        let length = request.length;
        let offset = request.offset;
        let Some((_, handle)) = Self::handle(ctx, req, request.file_id, chain).await else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::FILE_CLOSED),
            )));
        };
        let path = handle.path;
        if handle.meta.is_directory {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_DEVICE_REQUEST),
            )));
        }
        Log::new(Some(ctx.status_tx)).info(format!(
            "SMB2 READ: {} (offset={}, length={})",
            path, offset, length
        ));

        // On an LLM failure the READ is refused with an NTSTATUS rather than answered with
        // invented content.
        let actions = match Self::consult_llm(
            ctx,
            "read",
            serde_json::json!({ "path": path, "offset": offset, "length": length }),
        )
        .await
        {
            Ok(actions) => actions,
            Err(e) => {
                return Ok(Some(Self::llm_failure_response(
                    req, "READ", &path, &e, ctx,
                )))
            }
        };

        // `content` is only base64 or hex when the action says so, because "SGVsbG8=" is
        // simultaneously valid text and valid base64 and only the sender knows which it means.
        let Some(action) = actions
            .iter()
            .find(|a| a.get("type").and_then(|t| t.as_str()) == Some("smb_read_file"))
        else {
            // A READ answered with no `smb_read_file` is refused. Answering STATUS_SUCCESS with
            // placeholder bytes would tell the client those bytes are the file.
            let decision = if actions.is_empty() {
                "fail_closed_no_action"
            } else {
                "model_reject"
            };
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 READ refused for {} (decision={}): no smb_read_file in the answer; \
                 replying STATUS_ACCESS_DENIED",
                path, decision
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::ACCESS_DENIED),
            )));
        };
        let payload = action
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        let encoding = action.get("encoding").and_then(|e| e.as_str());
        let content = match actions::decode_smb_payload(payload, encoding) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Refuse rather than putting the undecodable string on the wire.
                Log::new(Some(ctx.status_tx))
                    .warn(format!("SMB read: {} - refusing with STATUS_DATA_ERROR", e));
                return Ok(Some(wire::error_response(
                    &hdr.with_status(status::DATA_ERROR),
                )));
            }
        };

        // MS-SMB2 3.3.5.12: a read starting at or past the end of the file is END_OF_FILE.
        let len = content.len() as u64;
        if offset >= len && !(offset == 0 && length == 0) {
            debug!(
                "SMB2 READ at {} of a {} byte file: END_OF_FILE",
                offset, len
            );
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::END_OF_FILE),
            )));
        }
        let start = offset as usize;
        let end = (offset.saturating_add(length as u64)).min(len) as usize;
        let data = &content[start..end];
        debug!("SMB2 READ: returning {} bytes of {}", data.len(), path);
        Ok(Some(wire::read_response(&hdr, data)))
    }

    /// WRITE (MS-SMB2 3.3.5.13): the model authorises the write; nothing is stored.
    async fn write(
        req: &RequestHeader,
        message: &[u8],
        chain: &Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(request) = wire::parse_write(message) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        let length = request.length;
        let offset = request.offset;

        if length > MAX_WRITE_SIZE {
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 WRITE: refusing {} byte write (MaxWriteSize {}) \
                 decision=fail_closed_write_too_large",
                length, MAX_WRITE_SIZE
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        }
        let Some(data) = request.data else {
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 WRITE declares {} bytes past the end of a {} byte message; replying \
                 STATUS_INVALID_PARAMETER",
                length,
                message.len()
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };

        let Some((_, handle)) = Self::handle(ctx, req, request.file_id, chain).await else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::FILE_CLOSED),
            )));
        };
        let path = handle.path;
        Log::new(Some(ctx.status_tx)).info(format!(
            "SMB2 WRITE: {} (offset={}, length={})",
            path, offset, length
        ));

        // Printable payloads stay readable; anything else is base64, and `encoding` says which,
        // matching what smb_read_file accepts so the model can hand the same bytes back.
        let (content, data_encoding) = actions::encode_smb_payload(data);

        // The write is refused unless the model returns smb_write_file: an LLM outage or a
        // model that says nothing must not read as an approval.
        let actions = match Self::consult_llm(
            ctx,
            "write",
            serde_json::json!({
                "path": path,
                "offset": offset,
                "data": content,
                "encoding": data_encoding
            }),
        )
        .await
        {
            Ok(actions) => actions,
            Err(e) => {
                return Ok(Some(Self::llm_failure_response(
                    req, "WRITE", &path, &e, ctx,
                )))
            }
        };

        let Some(write_action) = actions
            .iter()
            .find(|a| a.get("type").and_then(|t| t.as_str()) == Some("smb_write_file"))
        else {
            let decision = if actions.is_empty() {
                "fail_closed_no_action"
            } else {
                "model_reject"
            };
            Log::new(Some(ctx.status_tx)).warn(format!(
                "SMB2 WRITE refused for {} (decision={}): no smb_write_file in the answer; \
                 replying STATUS_ACCESS_DENIED",
                path, decision
            ));
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::ACCESS_DENIED),
            )));
        };

        // The model may report a short write; clamp to what the client actually sent.
        let bytes_written = write_action
            .get("bytes_written")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(length as u64) as u32)
            .unwrap_or(length);
        debug!(
            "SMB2 WRITE: accepted {} of {} bytes to {}",
            bytes_written, length, path
        );
        Ok(Some(wire::write_response(&hdr, bytes_written)))
    }

    /// QUERY_INFO (MS-SMB2 3.3.5.20). File-system classes and every class that does not need
    /// the file's size are answered from the handle; the size is the model's.
    async fn query_info(
        req: &RequestHeader,
        body: &[u8],
        chain: &Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(request) = wire::parse_query_info(body) else {
            warn!("SMB2 QUERY_INFO: invalid request size");
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        if request.output_len > MAX_TRANSACT_SIZE {
            return Ok(Some(Self::transact_too_large(req, request.output_len, ctx)));
        }
        let info_type = request.info_type;
        let class = request.class;
        let output_len = request.output_len as usize;
        let Some((file_id, handle)) = Self::handle(ctx, req, request.file_id, chain).await else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::FILE_CLOSED),
            )));
        };
        let path = handle.path.clone();

        let buffer = match info_type {
            wire::INFO_FILESYSTEM => {
                let share = ctx
                    .state
                    .lock()
                    .await
                    .trees
                    .get(&req.tree_id)
                    .map(|t| t.share_name.clone())
                    .unwrap_or_default();
                match wire::fs_info(class, &share, 0) {
                    Some(buffer) => buffer,
                    None => {
                        return Ok(Some(wire::error_response(
                            &hdr.with_status(status::INVALID_INFO_CLASS),
                        )))
                    }
                }
            }
            wire::INFO_FILE => {
                let mut meta = handle.meta;
                if wire::file_class_needs_size(class) && !handle.size_known {
                    Log::new(Some(ctx.status_tx)).info(format!("SMB2 QUERY_INFO: {}", path));
                    let actions = match Self::consult_llm(
                        ctx,
                        "query_info",
                        serde_json::json!({ "path": path }),
                    )
                    .await
                    {
                        Ok(actions) => actions,
                        Err(e) => {
                            return Ok(Some(Self::llm_failure_response(
                                req,
                                "QUERY_INFO",
                                &path,
                                &e,
                                ctx,
                            )))
                        }
                    };
                    // No `smb_get_file_info` with a size is a refusal, not a zero-byte file.
                    let info = actions.iter().find(|a| {
                        a.get("type").and_then(|t| t.as_str()) == Some("smb_get_file_info")
                    });
                    let Some(size) = info.and_then(|a| a.get("size")).and_then(|s| s.as_u64())
                    else {
                        let decision = if actions.is_empty() {
                            "fail_closed_no_action"
                        } else {
                            "model_reject"
                        };
                        Log::new(Some(ctx.status_tx)).warn(format!(
                            "SMB2 QUERY_INFO refused for {} (decision={}): no \
                             smb_get_file_info with a size in the answer; replying \
                             STATUS_ACCESS_DENIED",
                            path, decision
                        ));
                        return Ok(Some(wire::error_response(
                            &hdr.with_status(status::ACCESS_DENIED),
                        )));
                    };
                    meta.size = size;
                    if let Some(time) = info
                        .and_then(|a| a.get("modified_time"))
                        .and_then(|t| t.as_str())
                        .and_then(parse_time)
                    {
                        meta.time = time;
                    }
                    if let Some(h) = ctx.state.lock().await.files.get_mut(&file_id) {
                        h.meta = meta;
                        h.size_known = true;
                    }
                }
                match wire::file_info(class, &meta) {
                    Some(buffer) => buffer,
                    None => {
                        return Ok(Some(wire::error_response(
                            &hdr.with_status(status::INVALID_INFO_CLASS),
                        )))
                    }
                }
            }
            _ => {
                // Security descriptors and quotas: neither exists here.
                return Ok(Some(wire::error_response(
                    &hdr.with_status(status::NOT_SUPPORTED),
                )));
            }
        };

        if buffer.len() > output_len {
            return Ok(Some(wire::error_response(
                &hdr.with_status(STATUS_INFO_LENGTH_MISMATCH),
            )));
        }
        Ok(Some(wire::query_info_response(&hdr, &buffer)))
    }

    /// QUERY_DIRECTORY (MS-SMB2 3.3.5.18). The first call of an enumeration asks the model for
    /// the listing; the entries are handed out across as many calls as the client's buffer
    /// needs, and the call after the last entry answers `STATUS_NO_MORE_FILES`.
    async fn query_directory(
        req: &RequestHeader,
        message: &[u8],
        chain: &Chain,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let hdr = ResponseHeader::for_request(req, status::SUCCESS);
        let Some(wire::QueryDirectoryRequest {
            class,
            flags,
            file_id,
            pattern,
            output_len,
        }) = wire::parse_query_directory(message)
        else {
            warn!("SMB2 QUERY_DIRECTORY: invalid request");
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        };
        if output_len > MAX_TRANSACT_SIZE {
            return Ok(Some(Self::transact_too_large(req, output_len, ctx)));
        }
        let output_len = output_len as usize;
        if !wire::directory_class_supported(class) {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_INFO_CLASS),
            )));
        }
        let Some((file_id, handle)) = Self::handle(ctx, req, file_id, chain).await else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::FILE_CLOSED),
            )));
        };
        if !handle.meta.is_directory {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::INVALID_PARAMETER),
            )));
        }
        let path = handle.path.clone();

        let restart = flags & (RESTART_SCANS | REOPEN) != 0 || handle.listing.is_none();
        if restart {
            Log::new(Some(ctx.status_tx))
                .info(format!("SMB2 QUERY_DIRECTORY: {} ({})", path, pattern));
            let actions = match Self::consult_llm(
                ctx,
                "query_directory",
                serde_json::json!({ "path": path, "pattern": pattern }),
            )
            .await
            {
                Ok(actions) => actions,
                Err(e) => {
                    return Ok(Some(Self::llm_failure_response(
                        req,
                        "QUERY_DIRECTORY",
                        &path,
                        &e,
                        ctx,
                    )))
                }
            };

            // No `smb_list_directory` is a refusal: an empty listing with STATUS_SUCCESS reads
            // to the client as "the directory is empty", a positive assertion the model never
            // made. An empty `files` array is how the model says the directory is empty.
            let Some(files) = actions
                .iter()
                .find(|a| a.get("type").and_then(|t| t.as_str()) == Some("smb_list_directory"))
                .and_then(|a| a.get("files"))
                .and_then(|f| f.as_array())
                .cloned()
            else {
                let decision = if actions.is_empty() {
                    "fail_closed_no_action"
                } else {
                    "model_reject"
                };
                Log::new(Some(ctx.status_tx)).warn(format!(
                    "SMB2 QUERY_DIRECTORY refused for {} (decision={}): no smb_list_directory \
                     in the answer; replying STATUS_ACCESS_DENIED",
                    path, decision
                ));
                return Ok(Some(wire::error_response(
                    &hdr.with_status(status::ACCESS_DENIED),
                )));
            };

            let mut entries = VecDeque::new();
            let mut s = ctx.state.lock().await;
            let mut next_index = || {
                let i = s.next_file_index;
                s.next_file_index += 1;
                i
            };
            for dot in [".", ".."] {
                if wildcard_match(&pattern, dot) {
                    let meta = FileMeta {
                        is_directory: true,
                        file_index: next_index(),
                        ..FileMeta::default()
                    };
                    entries.push_back((dot.to_string(), meta));
                }
            }
            for file in &files {
                let Some(name) = file.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                // A listing names children, not paths.
                let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
                if name.is_empty() || name == "." || name == ".." || !wildcard_match(&pattern, name)
                {
                    continue;
                }
                let meta = FileMeta {
                    is_directory: file
                        .get("is_directory")
                        .and_then(|d| d.as_bool())
                        .unwrap_or(false),
                    size: file.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                    time: file
                        .get("modified_time")
                        .and_then(|t| t.as_str())
                        .and_then(parse_time)
                        .unwrap_or(0),
                    file_index: next_index(),
                };
                entries.push_back((name.to_string(), meta));
            }
            debug!(
                "SMB2 QUERY_DIRECTORY: {} entries for {}",
                entries.len(),
                path
            );
            if let Some(h) = s.files.get_mut(&file_id) {
                h.listing = Some(entries);
            }
        }

        // Hand out as many pending entries as fit.
        let mut s = ctx.state.lock().await;
        let Some(pending) = s.files.get_mut(&file_id).and_then(|h| h.listing.as_mut()) else {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::FILE_CLOSED),
            )));
        };
        if pending.is_empty() {
            return Ok(Some(wire::error_response(
                &hdr.with_status(status::NO_MORE_FILES),
            )));
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut used = 0usize;
        while let Some((name, meta)) = pending.front() {
            let entry = wire::directory_entry(class, name, meta);
            // Every entry already in `out` gets padded once this one follows it.
            let cost = used + entry.len();
            if cost > output_len {
                break;
            }
            used += wire::padded_len(&entry);
            out.push(entry);
            pending.pop_front();
            if flags & RETURN_SINGLE_ENTRY != 0 {
                break;
            }
        }
        if out.is_empty() {
            return Ok(Some(wire::error_response(
                &hdr.with_status(STATUS_INFO_LENGTH_MISMATCH),
            )));
        }
        Ok(Some(wire::query_directory_response(
            &hdr,
            &wire::join_directory_entries(&out),
        )))
    }

    /// The refusal for a QUERY_INFO or QUERY_DIRECTORY whose `OutputBufferLength` is past
    /// [`MAX_TRANSACT_SIZE`] (MS-SMB2 3.3.5.18, 3.3.5.20).
    fn transact_too_large(req: &RequestHeader, output_len: u32, ctx: &Ctx<'_>) -> Vec<u8> {
        Log::new(Some(ctx.status_tx)).warn(format!(
            "SMB2 command 0x{:04x} asks for a {} byte output buffer \
             (decision=fail_closed_transact_too_large, MaxTransactSize {}); replying \
             STATUS_INVALID_PARAMETER",
            req.command, output_len, MAX_TRANSACT_SIZE
        ));
        wire::error_response(&ResponseHeader::for_request(req, status::INVALID_PARAMETER))
    }

    /// Consult the LLM for SMB file system operations
    async fn consult_llm(
        ctx: &Ctx<'_>,
        operation: &str,
        params: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        Log::new(Some(ctx.status_tx)).debug(format!(
            "Consulting LLM for SMB {} operation: {:?}",
            operation, params
        ));

        let mut event_data = serde_json::json!({
            "operation": operation,
        });
        if let Some(obj) = params.as_object() {
            for (key, value) in obj {
                if key == "path" && value.as_str().is_some_and(str::is_empty) {
                    continue;
                }
                if key != "operation" {
                    event_data[key] = value.clone();
                }
            }
        }

        let event = Event::new(&SMB_OPERATION_EVENT, event_data);

        Log::new(Some(ctx.status_tx)).trace(format!("Calling LLM for SMB {} operation", operation));

        let execution_result = call_llm(
            ctx.llm_client,
            ctx.app_state,
            ctx.server_id,
            None, // SMB doesn't use connection-specific context yet
            &event,
            ctx.protocol.as_ref(),
        )
        .await?;

        for message in &execution_result.messages {
            Log::new(Some(ctx.status_tx)).info(message.to_string());
        }

        debug!(
            "LLM returned {} actions for SMB {}",
            execution_result.raw_actions.len(),
            operation
        );

        Ok(execution_result.raw_actions)
    }

    /// Refuse an operation because the LLM call failed, in SMB2's own vocabulary.
    ///
    /// Fail closed: the request is answered with an NTSTATUS failure, never with
    /// STATUS_SUCCESS and invented content, and never with silence.
    ///
    /// `STATUS_INSUFFICIENT_RESOURCES` (0xC000009A) is used when
    /// `crate::llm::is_overload_error` identifies capacity exhaustion, because it is the
    /// closest NTSTATUS to "retryable"; every other failure is `STATUS_INTERNAL_ERROR`
    /// (0xC00000E5). Both stay distinguishable from the model's own refusal
    /// (STATUS_ACCESS_DENIED) and from an undecodable payload (STATUS_DATA_ERROR).
    fn llm_failure_response(
        req: &RequestHeader,
        operation: &str,
        path: &str,
        err: &anyhow::Error,
        ctx: &Ctx<'_>,
    ) -> Vec<u8> {
        let overloaded = crate::llm::is_overload_error(err);
        let code = status_for_llm_failure(err);

        Log::new(Some(ctx.status_tx)).warn(format!(
            "SMB {} {}: LLM {} (decision=fail_closed_llm_error) - refusing with NTSTATUS \
             0x{:08X}: {}",
            operation,
            path,
            if overloaded {
                "overloaded"
            } else {
                "backend failure"
            },
            code,
            err
        ));

        wire::error_response(&ResponseHeader::for_request(req, code))
    }
}

fn disposition_name(disposition: u32) -> &'static str {
    match disposition {
        0 => "supersede",
        1 => "open",
        2 => "create",
        3 => "open_if",
        4 => "overwrite",
        5 => "overwrite_if",
        _ => "unknown",
    }
}

/// A FileId for the `index`th open: persistent and volatile halves derived from one counter.
fn file_id_for(index: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&index.to_le_bytes());
    id[8..].copy_from_slice(&(index ^ 0x4E47_5342_0000_0000).to_le_bytes());
    id
}

/// The NTSTATUS a request is refused with when the model could not be asked:
/// `STATUS_INSUFFICIENT_RESOURCES` when `crate::llm::is_overload_error` recognises a capacity
/// refusal (the closest NTSTATUS to "retryable"), `STATUS_INTERNAL_ERROR` for everything else.
/// Neither is `STATUS_ACCESS_DENIED`, which is the model's own refusal.
pub fn status_for_llm_failure(err: &anyhow::Error) -> u32 {
    if crate::llm::is_overload_error(err) {
        status::INSUFFICIENT_RESOURCES
    } else {
        status::INTERNAL_ERROR
    }
}

/// Case-insensitive match of an SMB search pattern with `*` and `?`.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// An RFC 3339 timestamp as a FILETIME.
fn parse_time(s: &str) -> Option<u64> {
    let t = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(wire::filetime_from_unix(
        t.timestamp(),
        t.timestamp_subsec_nanos(),
    ))
}

fn filetime_now() -> u64 {
    let now = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .unwrap_or_default();
    wire::filetime_from_unix(now.as_secs() as i64, now.subsec_nanos())
}

/// The NTLMSSP server challenge. Nothing is ever verified against it, so it needs to vary, not
/// to be secret.
fn server_challenge() -> [u8; 8] {
    let t = filetime_now();
    (t ^ t.rotate_left(29) ^ 0x9E37_79B9_7F4A_7C15).to_le_bytes()
}

/// The connection's read half plus the counters the dashboard's `↓` column reads.
///
/// Reads accumulate here and the session loop flushes them to `AppState` once per frame.
struct SmbReader<R> {
    inner: R,
    /// Bytes read since the last flush.
    pending_bytes: u64,
    /// Completed reads since the last flush.
    pending_reads: u64,
}

impl<R: tokio::io::AsyncRead + Unpin> SmbReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            pending_bytes: 0,
            pending_reads: 0,
        }
    }

    /// `read_exact`, counting the bytes on success. A cancelled read (the caller's timeout
    /// firing) has already lost whatever it consumed, so there is nothing honest to count.
    async fn read_exact_counted(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = self.inner.read_exact(buf).await;
        if let Ok(n) = result {
            self.pending_bytes += n as u64;
            self.pending_reads += 1;
        }
        result
    }

    /// Take and clear the counters.
    fn take_pending(&mut self) -> (u64, u64) {
        (
            std::mem::take(&mut self.pending_bytes),
            std::mem::take(&mut self.pending_reads),
        )
    }
}

/// Fold whatever the reader has counted since the last call into the connection's stats.
async fn flush_read_stats<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut SmbReader<R>,
    app_state: &AppState,
    server_id: ServerId,
    connection_id: ConnectionId,
) {
    let (bytes, reads) = reader.take_pending();
    if bytes == 0 && reads == 0 {
        return;
    }
    app_state
        .update_connection_stats(
            server_id,
            connection_id,
            Some(bytes),
            None,
            Some(reads),
            None,
        )
        .await;
}

/// Write one frame to the peer and count it. The guard is dropped before the stats update so
/// nothing awaits `AppState` while holding the write half — the peer command task needs the
/// same lock to inject a message or a disconnect.
async fn write_counted<W>(
    write_half: &Arc<Mutex<W>>,
    data: &[u8],
    ctx: &Ctx<'_>,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    {
        let mut writer = write_half.lock().await;
        writer.write_all(data).await?;
        writer.flush().await?;
    }
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            None,
            Some(data.len() as u64),
            None,
            Some(1),
        )
        .await;
    Ok(())
}

/// Read exactly `buf.len()` bytes of a message the peer has already announced, bounded by
/// `deadline` ([`BODY_READ_TIMEOUT`] unless configured).
async fn read_body_exact<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut SmbReader<R>,
    buf: &mut [u8],
    deadline: std::time::Duration,
) -> std::io::Result<()> {
    match tokio::time::timeout(deadline, stream.read_exact_counted(buf)).await {
        Ok(read) => read.map(|_| ()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "peer stalled part-way through an announced SMB2 message",
        )),
    }
}
