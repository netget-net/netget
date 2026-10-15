//! SPICE server — the remote display protocol of QEMU/KVM, spoken by hand over TCP.
//!
//! A SPICE session is several TCP connections, one per **channel**, each opened with its own
//! link handshake: the client links a **main** channel first (connection id 0), learns its
//! session id from `SPICE_MSG_MAIN_INIT`, asks for the channel list, and then links a
//! **display** and an **inputs** channel carrying that session id. This module owns all of it:
//! the link (`SpiceLinkMess` → `SpiceLinkReply` with an RSA-1024 key → auth mechanism → the
//! RSA-OAEP ticket → link result), the data framing, the channels, and every pixel.
//!
//! The model owns three things, and never a pixel or the password:
//!
//! - **admission** — `spice_connection_request` is raised once per session, after Rust has
//!   checked the ticket against the configured password; only `spice_accept_connection`
//!   admits.
//! - **the screen** — `spice_render_display` with VNC's drawing-command vocabulary, rendered
//!   here and sent as uncompressed 32-bit bitmaps on the one primary surface.
//! - **reactions** to `spice_key_event` / `spice_mouse_event`, and notifications.
//!
//! ## Failing closed
//!
//! - Admission with no usable answer (backend down, nothing usable, an executor refusal)
//!   **refuses the link** (`SPICE_LINK_ERR_PERMISSION_DENIED`): an outage must never admit.
//! - The first screen with no usable answer draws a **placeholder** with a fixed caption. A
//!   SPICE surface is created black, so a client left with nothing could not tell "the model
//!   drew black" from "the model never answered".
//! - An input event with no usable answer **keeps the last frame** and sends a fixed-text
//!   `SPICE_MSG_NOTIFY` (WARN) on the main channel. SPICE's display is server-push — no request
//!   is waiting on an answer — so painting a placeholder over a screen the user is working in
//!   would destroy what the model last decided, while the notify keeps "no answer" distinct
//!   from `spice_no_change` on the wire as well as in the log.
//!
//! Every outcome writes exactly one `decision=` line.
pub mod actions;
pub mod keys;
pub mod wire;

use crate::display::{Color, DisplayCanvas, DisplayCommand};
use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::{Log, Sink};
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use actions::SpiceProtocol;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use wire::{channel, common_cap, link_err, msg, msgc, ReadError};

/// How long to wait for a new connection's link message. SPICE is client-speaks-first: a
/// viewer writes its `SpiceLinkMess` as soon as the socket opens.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a channel may be silent once it has spoken. A viewer watching an unchanging screen
/// sends nothing on any channel — the display is server-push and the main channel is idle — so
/// a short bound would close healthy sessions. Half an hour, as VNC, turns "forever" into a
/// bound on connections that may be unauthenticated (a server with no password).
const IDLE_BETWEEN_MESSAGES_TIMEOUT: Duration = Duration::from_secs(1800);

/// Concurrent TCP connections, counting every channel of every session.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// The largest message body a client may send on any channel, and this server's declared
/// `max_inbound_bytes`. Client messages are small — the largest a real client sends is agent
/// data (2 KiB chunks) — and the size is a peer-chosen `u32` refused before allocation.
pub const MAX_CLIENT_MESSAGE_BYTES: u32 = 64 * 1024;

/// What a peer over [`MAX_CONNECTIONS`] is told: an error-only link reply
/// (`SPICE_LINK_ERR_ERROR`). SPICE is client-speaks-first, so the reply is ahead of the
/// client's link message; a viewer that reads it reports a link error rather than a reset.
const CONNECTION_CAP_REFUSAL: &[u8] = &cap_refusal();

const fn cap_refusal() -> [u8; wire::LINK_HEADER_BYTES + wire::LINK_REPLY_BYTES] {
    let mut b = [0u8; wire::LINK_HEADER_BYTES + wire::LINK_REPLY_BYTES];
    b[0] = b'R';
    b[1] = b'E';
    b[2] = b'D';
    b[3] = b'Q';
    b[4] = wire::VERSION_MAJOR as u8;
    b[8] = wire::VERSION_MINOR as u8;
    b[12] = wire::LINK_REPLY_BYTES as u8;
    b[16] = link_err::ERROR as u8;
    // Capability counts 0 and the offset: the bytes after the key.
    b[16 + 4 + wire::TICKET_PUBKEY_BYTES + 8] = wire::LINK_REPLY_BYTES as u8;
    b
}

/// The placeholder screen's colours: a background no colour name produces by accident.
pub const PLACEHOLDER_BACKGROUND: Color = Color::rgb(24, 26, 34);
const PLACEHOLDER_FOREGROUND: Color = Color::rgb(203, 213, 225);
/// The notify text for an input event the model gave no usable answer to. Fixed: nothing
/// NetGet knows about the failure reaches the peer.
pub const NO_ANSWER_NOTICE: &str = "NetGet: no answer for this input; the screen is unchanged";

type Reader = crate::server::accept_bounded::IdleTimeoutReader<ReadHalf<TcpStream>>;
type Writer = Arc<Mutex<WriteHalf<TcpStream>>>;

/// Startup configuration, validated by `actions.rs`.
pub struct Config {
    pub width: u32,
    pub height: u32,
    pub password: Option<String>,
    pub name: String,
}

pub struct SpiceServer;

struct Shared {
    config: Config,
    key: rsa::RsaPrivateKey,
    pubkey: Vec<u8>,
    sessions: std::sync::Mutex<HashMap<u32, Arc<Session>>>,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    image_ids: AtomicU64,
}

/// One client's session: the main channel and the display and inputs channels linked to it.
struct Session {
    id: u32,
    main: Mutex<Option<Arc<ChannelWriter>>>,
    display: Mutex<DisplayState>,
    display_attached: AtomicBool,
    inputs_attached: AtomicBool,
    mouse_mode: AtomicU32,
    closed: watch::Sender<bool>,
}

/// The display channel's writer and the current frame. The mutex is the display's write lock:
/// a frame's strips and the MARK after the first one go out under it, so two frames never
/// interleave and a frame never precedes SURFACE_CREATE.
#[derive(Default)]
struct DisplayState {
    writer: Option<Arc<ChannelWriter>>,
    frame: Option<Arc<Vec<u8>>>,
    marked: bool,
}

impl Session {
    fn close(&self) {
        let _ = self.closed.send(true);
    }
}

/// One channel's write side: the framing (mini or full header) and the serial.
struct ChannelWriter {
    half: Writer,
    mini: bool,
    serial: AtomicU64,
    app_state: Arc<AppState>,
    server_id: ServerId,
    connection_id: ConnectionId,
}

impl ChannelWriter {
    async fn send(&self, msg_type: u16, body: &[u8]) -> std::io::Result<()> {
        let len = {
            let mut w = self.half.lock().await;
            let serial = self.serial.fetch_add(1, Ordering::SeqCst) + 1;
            let mut buf = wire::data_header(self.mini, serial, msg_type, body.len() as u32);
            buf.extend_from_slice(body);
            w.write_all(&buf).await?;
            w.flush().await?;
            buf.len()
        };
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                None,
                Some(len as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }
}

/// What the model said about one event.
#[derive(Default)]
struct Decision {
    accept: bool,
    reject: bool,
    redraw: Option<Vec<DisplayCommand>>,
    no_change: bool,
    notify: Vec<(u32, String)>,
    close: bool,
    /// Set when no usable answer arrived; the reason stays in the log.
    no_answer: bool,
}

impl SpiceServer {
    pub async fn spawn(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        config: Config,
    ) -> Result<SocketAddr> {
        // One key per server, generated off the async workers: RSA key generation is the most
        // expensive thing this module does, and spice-server pays it on every link.
        let key = tokio::task::spawn_blocking(wire::generate_ticket_key)
            .await
            .context("ticket key generation")??;
        let pubkey = wire::ticket_public_key(&key)?;
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        // The E2E harness parses the port out of everything after the last "on ".
        Log::new(Some(&status_tx)).info(format!("SPICE server listening on {local_addr}"));
        Log::new(Some(&status_tx)).debug(format!(
            "SPICE surface {}x{}, name '{}', password {}",
            config.width,
            config.height,
            config.name,
            if config.password.is_some() {
                "required"
            } else {
                "not required"
            }
        ));
        let shared = Arc::new(Shared {
            config,
            key,
            pubkey,
            sessions: std::sync::Mutex::new(HashMap::new()),
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            server_id,
            image_ids: AtomicU64::new(1),
        });
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let registrar = app_state.clone();
        let accept = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "SPICE",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote, permit)) => {
                        let shared = shared.clone();
                        let local = stream.local_addr().unwrap_or(local_addr);
                        let owner = app_state.clone();
                        // Tracked, not detached: stop_server aborts this task too.
                        owner
                            .spawn_server_task(server_id, async move {
                                let _permit = permit;
                                if let Err(e) =
                                    Self::handle_connection(shared.clone(), stream, remote, local)
                                        .await
                                {
                                    Log::new(Some(&shared.status_tx)).debug(format!(
                                        "SPICE connection from {remote} ended: {e}"
                                    ));
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("SPICE accept failed, stopping loop: {e}"));
                        break;
                    }
                }
            }
        });
        registrar.register_server_task(server_id, accept).await;
        Ok(local_addr)
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
        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader: Reader = crate::server::accept_bounded::IdleTimeoutReader::with_first(
            read_half,
            FIRST_BYTE_READ_TIMEOUT,
            IDLE_BETWEEN_MESSAGES_TIMEOUT,
        );
        let writer: Writer = Arc::new(Mutex::new(write_half));
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
        // `[ disconnect this peer ]` half-closes this channel's socket through the generic peer
        // task; the client then closes its end and this channel's loop reads EOF. The drawing
        // verbs are not executed there: a frame belongs to the session's display channel.
        let peer_rx = crate::server::peer_support::register_peer_channel(
            &app_state,
            server_id,
            connection_id.as_u32(),
        )
        .await;
        crate::server::peer_support::spawn_peer_command_task(
            peer_rx,
            Arc::new(SpiceProtocol::new()),
            app_state.clone(),
            server_id,
            connection_id.as_u32(),
            writer.clone(),
            shared.status_tx.clone(),
        );

        let result = Self::serve(&shared, &mut reader, &writer, connection_id, remote).await;

        {
            let mut w = writer.lock().await;
            let _ = w.shutdown().await;
        }
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .remove_connection_from_server(server_id, connection_id)
            .await;
        let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
        result
    }

    /// The link stage, then the channel.
    async fn serve(
        shared: &Arc<Shared>,
        reader: &mut Reader,
        writer: &Writer,
        connection_id: ConnectionId,
        remote: SocketAddr,
    ) -> Result<()> {
        let log = Log::new(Some(&shared.status_tx));
        let mut header = [0u8; wire::LINK_HEADER_BYTES];
        reader.read_exact(&mut header).await?;
        let size = match wire::parse_link_header(&header, wire::LINK_MESS_BYTES) {
            Ok(size) => size,
            Err(wire::LinkHeaderError(code)) => {
                log.warn(format!(
                    "SPICE link from {remote} refused decision=protocol_error: {}",
                    link_err::name(code)
                ));
                write_raw(writer, &wire::LinkReply::error(code)).await?;
                return Ok(());
            }
        };
        let mut body = vec![0u8; size as usize];
        reader.read_exact(&mut body).await?;
        let link = match wire::LinkMess::decode(&body) {
            Ok(l) => l,
            Err(e) => {
                log.warn(format!(
                    "SPICE link from {remote} refused decision=protocol_error: {e}"
                ));
                write_raw(writer, &wire::LinkReply::error(link_err::INVALID_DATA)).await?;
                return Ok(());
            }
        };
        let channel_caps = if link.channel_type == channel::MAIN {
            vec![wire::caps_word(&[wire::main_cap::NAME_AND_UUID])]
        } else {
            Vec::new()
        };
        write_raw(
            writer,
            &wire::LinkReply {
                error: link_err::OK,
                pubkey: shared.pubkey.clone(),
                common_caps: vec![wire::caps_word(&[
                    common_cap::AUTH_SELECTION,
                    common_cap::AUTH_SPICE,
                    common_cap::MINI_HEADER,
                ])],
                channel_caps,
            }
            .encode(),
        )
        .await?;

        if wire::has_cap(&link.common_caps, common_cap::AUTH_SELECTION) {
            let mechanism = reader.read_u32_le().await?;
            if mechanism != wire::AUTH_MECHANISM_SPICE {
                log.warn(format!(
                    "SPICE link from {remote} refused decision=protocol_error: auth mechanism \
                     {mechanism} (only SPICE tickets are offered)"
                ));
                write_raw(writer, &link_err::INVALID_DATA.to_le_bytes()).await?;
                return Ok(());
            }
        }
        let mut ticket = [0u8; wire::TICKET_BYTES];
        reader.read_exact(&mut ticket).await?;
        if let Some(password) = &shared.config.password {
            let good = wire::decrypt_ticket(&shared.key, &ticket)
                .is_some_and(|t| wire::secrets_equal(&t, password.as_bytes()));
            if !good {
                // The protocol refused this peer before any model was asked; the password
                // itself is never logged.
                log.warn(format!(
                    "SPICE {} link from {remote} refused decision=protocol_reject_bad_ticket: \
                     the ticket does not carry the configured password",
                    channel::name(link.channel_type)
                ));
                write_raw(writer, &link_err::PERMISSION_DENIED.to_le_bytes()).await?;
                return Ok(());
            }
        }
        let mini = wire::has_cap(&link.common_caps, common_cap::MINI_HEADER);
        let channel_writer = Arc::new(ChannelWriter {
            half: writer.clone(),
            mini,
            serial: AtomicU64::new(0),
            app_state: shared.app_state.clone(),
            server_id: shared.server_id,
            connection_id,
        });

        match link.channel_type {
            channel::MAIN => {
                Self::admit_main(shared, reader, channel_writer, &link, connection_id, remote).await
            }
            channel::DISPLAY | channel::INPUTS => {
                let session = shared
                    .sessions
                    .lock()
                    .ok()
                    .and_then(|s| s.get(&link.connection_id).cloned());
                let Some(session) = session else {
                    log.warn(format!(
                        "SPICE {} link from {remote} refused decision=protocol_error: no session \
                         {:#010x}",
                        channel::name(link.channel_type),
                        link.connection_id
                    ));
                    write_raw(writer, &link_err::BAD_CONNECTION_ID.to_le_bytes()).await?;
                    return Ok(());
                };
                let slot = if link.channel_type == channel::DISPLAY {
                    &session.display_attached
                } else {
                    &session.inputs_attached
                };
                if link.channel_id != 0 || slot.swap(true, Ordering::SeqCst) {
                    log.warn(format!(
                        "SPICE {} channel {} link from {remote} refused decision=protocol_error: \
                         not available",
                        channel::name(link.channel_type),
                        link.channel_id
                    ));
                    write_raw(writer, &link_err::CHANNEL_NOT_AVAILABLE.to_le_bytes()).await?;
                    return Ok(());
                }
                write_raw(writer, &link_err::OK.to_le_bytes()).await?;
                log.info(format!(
                    "SPICE {} channel linked for session {:#010x}",
                    channel::name(link.channel_type),
                    session.id
                ));
                let result = if link.channel_type == channel::DISPLAY {
                    Self::run_display(shared, &session, reader, channel_writer, connection_id).await
                } else {
                    Self::run_inputs(shared, &session, reader, channel_writer, connection_id).await
                };
                slot.store(false, Ordering::SeqCst);
                result
            }
            other => {
                log.warn(format!(
                    "SPICE {} link from {remote} refused decision=protocol_error: channel not \
                     offered",
                    channel::name(other)
                ));
                write_raw(writer, &link_err::CHANNEL_NOT_AVAILABLE.to_le_bytes()).await?;
                Ok(())
            }
        }
    }

    /// Ask the model whether to admit a main channel, then run it.
    async fn admit_main(
        shared: &Arc<Shared>,
        reader: &mut Reader,
        writer: Arc<ChannelWriter>,
        link: &wire::LinkMess,
        connection_id: ConnectionId,
        remote: SocketAddr,
    ) -> Result<()> {
        let caps: Vec<&str> = [
            (common_cap::AUTH_SELECTION, "auth_selection"),
            (common_cap::AUTH_SPICE, "auth_spice"),
            (common_cap::AUTH_SASL, "auth_sasl"),
            (common_cap::MINI_HEADER, "mini_header"),
        ]
        .iter()
        .filter(|(bit, _)| wire::has_cap(&link.common_caps, *bit))
        .map(|(_, n)| *n)
        .collect();
        let event = Event::new(
            &actions::CONNECTION_REQUEST_EVENT,
            json!({
                "client": remote.to_string(),
                "password_configured": shared.config.password.is_some(),
                "width": shared.config.width,
                "height": shared.config.height,
                "client_capabilities": caps,
            }),
        );
        let decision = consult(shared, connection_id, &event).await;
        if !decision.accept || decision.reject || decision.close {
            write_raw(&writer.half, &link_err::PERMISSION_DENIED.to_le_bytes()).await?;
            return Ok(());
        }
        let frame = match decision.redraw {
            Some(commands) => {
                match render_bgrx(shared.config.width, shared.config.height, commands).await {
                    Ok(f) => Some(Arc::new(f)),
                    Err(e) => {
                        Log::new(Some(&shared.status_tx))
                            .error(format!("SPICE first screen could not be rendered: {e:#}"));
                        None
                    }
                }
            }
            None => None,
        };
        let (closed, _) = watch::channel(false);
        let session = {
            let Ok(mut sessions) = shared.sessions.lock() else {
                anyhow::bail!("the session table is poisoned");
            };
            let mut id = rand::random::<u32>();
            while id == 0 || sessions.contains_key(&id) {
                id = rand::random::<u32>();
            }
            let session = Arc::new(Session {
                id,
                main: Mutex::new(None),
                display: Mutex::new(DisplayState {
                    frame,
                    ..Default::default()
                }),
                display_attached: AtomicBool::new(false),
                inputs_attached: AtomicBool::new(false),
                mouse_mode: AtomicU32::new(wire::MOUSE_MODE_CLIENT),
                closed,
            });
            sessions.insert(id, session.clone());
            session
        };
        write_raw(&writer.half, &link_err::OK.to_le_bytes()).await?;
        Log::new(Some(&shared.status_tx)).info(format!(
            "SPICE session {:#010x} opened for {remote}",
            session.id
        ));
        let result = Self::run_main(
            shared,
            &session,
            reader,
            writer,
            link,
            connection_id,
            decision.notify,
        )
        .await;
        // The main channel is the session: when it goes, every channel goes.
        session.close();
        if let Ok(mut sessions) = shared.sessions.lock() {
            sessions.remove(&session.id);
        }
        *session.main.lock().await = None;
        Log::new(Some(&shared.status_tx))
            .info(format!("SPICE session {:#010x} closed", session.id));
        result
    }

    async fn run_main(
        shared: &Arc<Shared>,
        session: &Arc<Session>,
        reader: &mut Reader,
        writer: Arc<ChannelWriter>,
        link: &wire::LinkMess,
        connection_id: ConnectionId,
        notices: Vec<(u32, String)>,
    ) -> Result<()> {
        let supported = wire::MOUSE_MODE_SERVER | wire::MOUSE_MODE_CLIENT;
        writer
            .send(
                msg::MAIN_INIT,
                &wire::main_init(
                    session.id,
                    1,
                    supported,
                    session.mouse_mode.load(Ordering::SeqCst),
                    0,
                    0,
                    multimedia_time(),
                    0,
                ),
            )
            .await?;
        if wire::has_cap(&link.channel_caps, wire::main_cap::NAME_AND_UUID) {
            writer
                .send(msg::MAIN_NAME, &wire::main_name(&shared.config.name))
                .await?;
        }
        *session.main.lock().await = Some(writer.clone());
        for (severity, text) in notices {
            send_notify(session, severity, &text).await;
        }
        let mut closed = session.closed.subscribe();
        loop {
            let message = tokio::select! {
                m = wire::read_message(reader, writer.mini, MAX_CLIENT_MESSAGE_BYTES) => m,
                _ = closed.wait_for(|c| *c) => return Ok(()),
            };
            let (msg_type, body) = match message {
                Ok(m) => m,
                Err(e) => return end_of_channel(shared, "main", e),
            };
            count_in(shared, connection_id, &body).await;
            match msg_type {
                msgc::MAIN_ATTACH_CHANNELS => {
                    writer
                        .send(
                            msg::MAIN_CHANNELS_LIST,
                            &wire::channels_list(&[(channel::DISPLAY, 0), (channel::INPUTS, 0)]),
                        )
                        .await?;
                }
                msgc::MAIN_MOUSE_MODE_REQUEST => {
                    let mode = wire::Cursor::new(&body).u16("mouse mode")? as u32;
                    if mode & supported != 0 && mode.count_ones() == 1 {
                        session.mouse_mode.store(mode, Ordering::SeqCst);
                    }
                    writer
                        .send(
                            msg::MAIN_MOUSE_MODE,
                            &wire::mouse_mode(
                                supported as u16,
                                session.mouse_mode.load(Ordering::SeqCst) as u16,
                            ),
                        )
                        .await?;
                }
                other => tracing::trace!("SPICE main channel message {other} ignored"),
            }
        }
    }

    async fn run_display(
        shared: &Arc<Shared>,
        session: &Arc<Session>,
        reader: &mut Reader,
        writer: Arc<ChannelWriter>,
        connection_id: ConnectionId,
    ) -> Result<()> {
        let (w, h) = (shared.config.width, shared.config.height);
        let have_frame = {
            let mut display = session.display.lock().await;
            writer
                .send(
                    msg::DISPLAY_SURFACE_CREATE,
                    &wire::surface_create(
                        0,
                        w,
                        h,
                        wire::SURFACE_FMT_32_XRGB,
                        wire::SURFACE_FLAGS_PRIMARY,
                    ),
                )
                .await?;
            if let Some(frame) = display.frame.clone() {
                send_frame(shared, &writer, &frame).await?;
                writer.send(msg::DISPLAY_MARK, &[]).await?;
                display.marked = true;
            }
            display.writer = Some(writer.clone());
            display.frame.is_some()
        };
        if !have_frame {
            let event = Event::new(
                &actions::DISPLAY_READY_EVENT,
                json!({"width": w, "height": h}),
            );
            let decision = consult(shared, connection_id, &event).await;
            apply(shared, session, decision, true).await;
        }
        let mut closed = session.closed.subscribe();
        let result = loop {
            let message = tokio::select! {
                m = wire::read_message(reader, writer.mini, MAX_CLIENT_MESSAGE_BYTES) => m,
                _ = closed.wait_for(|c| *c) => break Ok(()),
            };
            match message {
                Ok((msg_type, body)) => {
                    count_in(shared, connection_id, &body).await;
                    tracing::trace!("SPICE display channel message {msg_type} ignored");
                }
                Err(e) => break end_of_channel(shared, "display", e),
            }
        };
        let mut display = session.display.lock().await;
        display.writer = None;
        display.marked = false;
        result
    }

    async fn run_inputs(
        shared: &Arc<Shared>,
        session: &Arc<Session>,
        reader: &mut Reader,
        writer: Arc<ChannelWriter>,
        connection_id: ConnectionId,
    ) -> Result<()> {
        let log = Log::new(Some(&shared.status_tx));
        writer.send(msg::INPUTS_INIT, &0u16.to_le_bytes()).await?;
        let (w, h) = (shared.config.width as i64, shared.config.height as i64);
        let (mut x, mut y) = (w / 2, h / 2);
        let mut decoder = keys::Decoder::default();
        let mut held: Vec<(u8, bool)> = Vec::new();
        let mut motions: u32 = 0;
        let mut closed = session.closed.subscribe();
        loop {
            let message = tokio::select! {
                m = wire::read_message(reader, writer.mini, MAX_CLIENT_MESSAGE_BYTES) => m,
                _ = closed.wait_for(|c| *c) => return Ok(()),
            };
            let (msg_type, body) = match message {
                Ok(m) => m,
                Err(e) => return end_of_channel(shared, "inputs", e),
            };
            count_in(shared, connection_id, &body).await;
            let mut c = wire::Cursor::new(&body);
            let strokes = match msg_type {
                msgc::INPUTS_KEY_DOWN | msgc::INPUTS_KEY_UP => {
                    decoder.feed_code(c.u32("key code")?)
                }
                msgc::INPUTS_KEY_SCANCODE => body.iter().filter_map(|b| decoder.feed(*b)).collect(),
                msgc::INPUTS_MOUSE_MOTION | msgc::INPUTS_MOUSE_POSITION => {
                    if msg_type == msgc::INPUTS_MOUSE_MOTION {
                        let dx = c.i32("dx")? as i64;
                        let dy = c.i32("dy")? as i64;
                        x = (x + dx).clamp(0, w - 1);
                        y = (y + dy).clamp(0, h - 1);
                    } else {
                        x = (c.u32("x")? as i64).clamp(0, w - 1);
                        y = (c.u32("y")? as i64).clamp(0, h - 1);
                    }
                    // Movement is logged, not modelled: a viewer sends one per pixel.
                    log.debug_to(Sink::Both, format!("SPICE pointer at {x},{y}"));
                    motions += 1;
                    if motions.is_multiple_of(4) {
                        // SPICE_INPUT_MOTION_ACK_BUNCH: a viewer stops sending motion when
                        // eight go unacknowledged.
                        writer.send(msg::INPUTS_MOUSE_MOTION_ACK, &[]).await?;
                    }
                    Vec::new()
                }
                msgc::INPUTS_MOUSE_PRESS | msgc::INPUTS_MOUSE_RELEASE => {
                    let b = c.u8("button")?;
                    let state = c.u16("buttons state")?;
                    if msg_type == msgc::INPUTS_MOUSE_RELEASE {
                        log.debug(format!(
                            "SPICE {} button released at {x},{y}",
                            wire::button::name(b)
                        ));
                    } else {
                        let mode = if session.mouse_mode.load(Ordering::SeqCst)
                            == wire::MOUSE_MODE_CLIENT
                        {
                            "client"
                        } else {
                            "server"
                        };
                        let event = Event::new(
                            &actions::MOUSE_EVENT,
                            json!({
                                "x": x, "y": y,
                                "button": wire::button::name(b),
                                "buttons": wire::button::names_in(state | wire::button::mask(b)),
                                "mouse_mode": mode,
                            }),
                        );
                        let decision = consult(shared, connection_id, &event).await;
                        if !apply(shared, session, decision, false).await {
                            return Ok(());
                        }
                    }
                    Vec::new()
                }
                other => {
                    tracing::trace!("SPICE inputs channel message {other} ignored");
                    Vec::new()
                }
            };
            for stroke in strokes {
                let key = (stroke.scancode, stroke.extended);
                if stroke.released {
                    held.retain(|k| *k != key);
                    continue;
                }
                if !held.contains(&key) {
                    held.push(key);
                }
                if keys::modifier(stroke.scancode, stroke.extended).is_some() {
                    continue;
                }
                let has =
                    |m: keys::Modifier| held.iter().any(|(s, e)| keys::modifier(*s, *e) == Some(m));
                let shift = has(keys::Modifier::Shift);
                let text = (!stroke.extended)
                    .then(|| keys::char_for(stroke.scancode, shift))
                    .flatten();
                let event = Event::new(
                    &actions::KEY_EVENT,
                    json!({
                        "key": keys::key_name(stroke.scancode, stroke.extended, shift),
                        "text": text.map(|c| c.to_string()),
                        "scancode": stroke.scancode,
                        "extended": stroke.extended,
                        "shift": shift,
                        "ctrl": has(keys::Modifier::Ctrl),
                        "alt": has(keys::Modifier::Alt),
                    }),
                );
                let decision = consult(shared, connection_id, &event).await;
                if !apply(shared, session, decision, false).await {
                    return Ok(());
                }
            }
        }
    }
}

/// Write link-stage bytes, which have no data header.
async fn write_raw(writer: &Writer, bytes: &[u8]) -> std::io::Result<()> {
    let mut w = writer.lock().await;
    w.write_all(bytes).await?;
    w.flush().await
}

async fn count_in(shared: &Shared, connection_id: ConnectionId, body: &[u8]) {
    shared
        .app_state
        .update_connection_stats(
            shared.server_id,
            connection_id,
            Some(body.len() as u64 + 6),
            None,
            Some(1),
            None,
        )
        .await;
}

/// How a channel's read loop ended. EOF is the client leaving; an oversized message is
/// refused here, before its body was read.
fn end_of_channel(shared: &Shared, name: &str, e: ReadError) -> Result<()> {
    let log = Log::new(Some(&shared.status_tx));
    match e {
        ReadError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            log.info(format!("SPICE {name} channel closed by the client"));
            Ok(())
        }
        ReadError::TooLarge { .. } | ReadError::SubList => {
            log.warn(format!(
                "SPICE {name} channel closed decision=fail_closed_message_too_large: {e}"
            ));
            Ok(())
        }
        ReadError::Io(e) => Err(e.into()),
    }
}

fn multimedia_time() -> u32 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(0)
}

/// Send a notification on the session's main channel, if it has one.
async fn send_notify(session: &Session, severity: u32, text: &str) {
    let main = session.main.lock().await.clone();
    if let Some(main) = main {
        let stamp = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let _ = main
            .send(msg::NOTIFY, &wire::notify(stamp, severity, 0, text))
            .await;
    }
}

/// Make `pixels` the session's screen, and send it if a display channel is attached.
async fn publish_frame(shared: &Shared, session: &Session, pixels: Vec<u8>) {
    let pixels = Arc::new(pixels);
    let mut display = session.display.lock().await;
    display.frame = Some(pixels.clone());
    let Some(writer) = display.writer.clone() else {
        return;
    };
    let sent = async {
        send_frame(shared, &writer, &pixels).await?;
        if !display.marked {
            writer.send(msg::DISPLAY_MARK, &[]).await?;
        }
        std::io::Result::Ok(())
    }
    .await;
    match sent {
        Ok(()) => display.marked = true,
        Err(e) => {
            Log::new(Some(&shared.status_tx)).debug(format!("SPICE frame not sent: {e}"));
            display.writer = None;
        }
    }
}

/// The whole surface as one DRAW_COPY of an uncompressed bitmap, as spice-server sends a
/// full-screen update: one message, so a client sees the frame land at once (spice-gtk's
/// `spicy-screenshot` writes its file on the first invalidation it sees).
async fn send_frame(shared: &Shared, writer: &ChannelWriter, pixels: &[u8]) -> std::io::Result<()> {
    let (w, h) = (shared.config.width, shared.config.height);
    let id = shared.image_ids.fetch_add(1, Ordering::SeqCst);
    let body = wire::draw_copy_bitmap(0, 0, 0, w, h, id, pixels);
    writer.send(msg::DISPLAY_DRAW_COPY, &body).await
}

/// Carry out a decision about the screen. `first_screen` draws the placeholder when there is
/// no usable answer; otherwise the last frame stays and a notify says so. Returns false when
/// the session was closed.
async fn apply(shared: &Shared, session: &Session, decision: Decision, first_screen: bool) -> bool {
    for (severity, text) in &decision.notify {
        send_notify(session, *severity, text).await;
    }
    if decision.close {
        session.close();
        return false;
    }
    let (w, h) = (shared.config.width, shared.config.height);
    if let Some(commands) = decision.redraw {
        match render_bgrx(w, h, commands).await {
            Ok(pixels) => publish_frame(shared, session, pixels).await,
            Err(e) => Log::new(Some(&shared.status_tx))
                .error(format!("SPICE screen could not be rendered: {e:#}")),
        }
    } else if decision.no_answer {
        if first_screen {
            match render_bgrx(w, h, placeholder("the model gave no screen to draw", h)).await {
                Ok(pixels) => publish_frame(shared, session, pixels).await,
                Err(e) => Log::new(Some(&shared.status_tx))
                    .error(format!("SPICE placeholder could not be rendered: {e:#}")),
            }
        } else {
            send_notify(session, wire::NOTIFY_SEVERITY_WARN, NO_ANSWER_NOTICE).await;
        }
    } else if first_screen && !decision.no_change && session.display.lock().await.frame.is_none() {
        // Only a notification came back for the first screen: something must be on it.
        if let Ok(pixels) = render_bgrx(w, h, placeholder("no screen has been drawn yet", h)).await
        {
            publish_frame(shared, session, pixels).await;
        }
    }
    true
}

fn placeholder(reason: &str, height: u32) -> Vec<DisplayCommand> {
    vec![
        DisplayCommand::SetBackground {
            color: PLACEHOLDER_BACKGROUND,
        },
        DisplayCommand::DrawText {
            x: 24,
            y: height / 2,
            text: format!("NetGet SPICE: {reason}"),
            font_size: 18,
            color: PLACEHOLDER_FOREGROUND,
        },
    ]
}

/// Rasterise drawing commands into the surface's pixels: BGRX, `width * 4` bytes a row, which
/// is SPICE's 32-bit bitmap format (a little-endian xRGB word per pixel). Off the async
/// workers, so a panic in the canvas is an error here rather than a dead task.
async fn render_bgrx(width: u32, height: u32, commands: Vec<DisplayCommand>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut canvas = DisplayCanvas::new(width, height);
        canvas.add_commands(commands);
        let image = canvas
            .try_render()
            .context("invalid SPICE display commands")?;
        let mut out = Vec::new();
        out.try_reserve_exact(width as usize * height as usize * 4)
            .context("unable to allocate the SPICE surface")?;
        for px in image.pixels() {
            out.extend_from_slice(&[px[2], px[1], px[0], 0]);
        }
        Ok(out)
    })
    .await
    .context("SPICE rendering failed")?
}

/// Ask the handlers (script → static → model) about `event`. Never fails: the outcome,
/// including "no usable answer", is in the decision, and exactly one `decision=` line is
/// logged for it.
async fn consult(shared: &Shared, connection_id: ConnectionId, event: &Event) -> Decision {
    let log = Log::new(Some(&shared.status_tx));
    let mut d = Decision::default();
    let id = &event.event_type.id;
    let execution = match call_llm(
        &shared.llm_client,
        &shared.app_state,
        shared.server_id,
        Some(connection_id),
        event,
        &SpiceProtocol::new(),
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                crate::utils::wire_failure::WireFailure::Overloaded => "fail_closed_llm_overloaded",
                crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
            };
            log.error(format!(
                "SPICE {id} on {connection_id} not answered decision={tag}: {e}"
            ));
            d.no_answer = true;
            return d;
        }
    };
    for m in execution.messages {
        let _ = shared.status_tx.send(m);
    }
    let mut results = Vec::new();
    flatten(execution.protocol_results, &mut results);
    let mut usable = false;
    let mut undecodable = false;
    for r in results {
        match r {
            ActionResult::Custom { name, data } => {
                usable = true;
                match name.as_str() {
                    actions::RESULT_ACCEPT => d.accept = true,
                    actions::RESULT_REJECT => d.reject = true,
                    actions::RESULT_NO_CHANGE => d.no_change = true,
                    actions::RESULT_NOTIFY => d.notify.push((
                        data["severity"].as_u64().unwrap_or(0) as u32,
                        data["message"].as_str().unwrap_or_default().to_string(),
                    )),
                    actions::RESULT_DISPLAY => {
                        match serde_json::from_value::<Vec<DisplayCommand>>(
                            data["commands"].clone(),
                        ) {
                            Ok(c) => d.redraw = Some(c),
                            Err(_) => undecodable = true,
                        }
                    }
                    _ => usable = false,
                }
            }
            ActionResult::CloseConnection => {
                usable = true;
                d.close = true;
            }
            _ => {}
        }
    }
    let admission = event.event_type.id == actions::CONNECTION_REQUEST_EVENT.id;
    if undecodable {
        log.error(format!(
            "SPICE {id} on {connection_id} decision=fail_closed_bad_action: the render result \
             could not be decoded"
        ));
        d.no_answer = true;
        d.accept = false;
    } else if !usable {
        let detail = execution
            .failures
            .iter()
            .map(|f| format!("{}: {}", f.action, f.error))
            .collect::<Vec<_>>()
            .join("; ");
        if detail.is_empty() {
            log.warn(format!(
                "SPICE {id} on {connection_id} produced no usable action decision=model_silent"
            ));
        } else {
            log.error(format!(
                "SPICE {id} on {connection_id} produced no usable action \
                 decision=fail_closed_bad_action ({detail})"
            ));
        }
        d.no_answer = true;
    } else if d.close || d.reject || (admission && !d.accept) {
        log.info(format!(
            "SPICE {id} on {connection_id} decision=model_reject"
        ));
    } else {
        log.info(format!(
            "SPICE {id} on {connection_id} decision=model_answer"
        ));
    }
    d
}

fn flatten(results: Vec<ActionResult>, out: &mut Vec<ActionResult>) {
    for r in results {
        match r {
            ActionResult::Multiple(inner) => flatten(inner, out),
            other => out.push(other),
        }
    }
}
