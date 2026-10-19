//! VNC (Remote Framebuffer) client implementation
pub mod actions;

pub use actions::VncClientProtocol;

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::client::vnc::actions::{
    VNC_CLIENT_CONNECTED_EVENT, VNC_CLIENT_FRAMEBUFFER_UPDATE_EVENT,
    VNC_CLIENT_SERVER_CUT_TEXT_EVENT,
};
use crate::llm::actions::client_trait::ClientActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use serde_json::Value as JsonValue;

/// Maximum length of server names, failure explanations and clipboard text.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Largest raw rectangle accepted (enough for an 8K 32-bit display).
pub const MAX_RAW_RECTANGLE_BYTES: u64 = 256 * 1024 * 1024;

/// Read a server-controlled string length only after bounding its allocation.
pub async fn read_server_text<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    length: u32,
) -> Result<Vec<u8>> {
    if u64::from(length) > MAX_TEXT_BYTES as u64 {
        bail!("VNC text length {length} exceeds the {MAX_TEXT_BYTES}-byte cap");
    }
    let mut text = vec![0; length as usize];
    reader.read_exact(&mut text).await?;
    Ok(text)
}

/// Consume raw pixels with bounded scratch space; the client reports update metadata
/// rather than pixels, so retaining a full rectangle has no purpose.
pub async fn discard_raw_rectangle<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    width: u16,
    height: u16,
) -> Result<()> {
    let length = u64::from(width) * u64::from(height) * 4;
    if length > MAX_RAW_RECTANGLE_BYTES {
        bail!("VNC raw rectangle is {length} bytes, over the {MAX_RAW_RECTANGLE_BYTES}-byte cap");
    }
    let consumed = tokio::io::copy(&mut reader.take(length), &mut tokio::io::sink()).await?;
    if consumed != length {
        bail!("truncated VNC raw rectangle: expected {length} bytes, received {consumed}");
    }
    Ok(())
}

/// Resolve the `key` field of `send_key_event` to an X11 keysym.
///
/// Accepts a number (a keysym directly) or a **name** — a single character such as `"a"`, or a
/// named key such as `"Enter"`, `"Escape"`, `"Tab"`, `"F1"`. The action originally took a bare
/// number described as an "X11 keysym value", which asks a model to recall an encoding table;
/// CLAUDE.md's action-design rule is explicit that models cannot reliably produce encoded
/// values, and a model answering `"a"` silently sent keysym 0 because `as_u64()` on a string is
/// `None` and the code fell through to `unwrap_or(0)`. A wrong keysym is invisible: the server
/// receives a well-formed KeyEvent for a key nobody pressed.
///
/// Returns `None` for an unrecognised name so the caller can refuse rather than send keysym 0.
pub fn resolve_keysym(value: &serde_json::Value) -> Option<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).ok();
    }
    let name = value.as_str()?;

    // ASCII printables are their own keysym (X11 keysymdef).
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        if c.is_ascii_graphic() || c == ' ' {
            return Some(c as u32);
        }
    }

    Some(match name.to_ascii_lowercase().as_str() {
        "enter" | "return" => 0xff0d,
        "backspace" => 0xff08,
        "tab" => 0xff09,
        "escape" | "esc" => 0xff1b,
        "space" => 0x0020,
        "delete" | "del" => 0xffff,
        "home" => 0xff50,
        "left" => 0xff51,
        "up" => 0xff52,
        "right" => 0xff53,
        "down" => 0xff54,
        "pageup" => 0xff55,
        "pagedown" => 0xff56,
        "end" => 0xff57,
        "insert" => 0xff63,
        "shift" => 0xffe1,
        "control" | "ctrl" => 0xffe3,
        "alt" => 0xffe9,
        "meta" | "super" | "cmd" => 0xffeb,
        other => {
            // F1..F35
            let n: u32 = other.strip_prefix('f')?.parse().ok()?;
            if (1..=35).contains(&n) {
                0xffbe + (n - 1)
            } else {
                return None;
            }
        }
    })
}

/// Per-client data for LLM handling.
///
/// There used to be an `Idle`/`Processing` state here whose `Processing` arm skipped a
/// framebuffer update. Nothing could reach it: the model was called inline in the read loop, so
/// the state was always `Idle` when an update was examined. What the server sent during a call
/// waited unread in the socket. The reader is now its own task (see `connect_with_llm_actions`).
struct ClientData {
    memory: String,
    fb_width: u16,
    fb_height: u16,
}

/// How many server messages may wait while the model answers an earlier one; past it the
/// reader stops and TCP holds the server back.
const READ_QUEUE_MESSAGES: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    /// A whole server message the model is told about.
    Event(Event),
    /// The session is over: EOF, a read error or a message that cannot be framed.
    Ended(String),
}

/// VNC client that connects to a VNC server
/// RFB security type 2: DES-ECB encrypt both challenge blocks with the first
/// eight password bytes, zero padded and bit reversed for VNC's DES key order.
pub fn vnc_auth_response(password: &[u8], mut challenge: [u8; 16]) -> [u8; 16] {
    use des::cipher::{Block, BlockEncrypt, KeyInit};
    let mut key = [0u8; 8];
    for (target, source) in key.iter_mut().zip(password.iter()) {
        *target = source.reverse_bits();
    }
    let cipher = des::Des::new_from_slice(&key).expect("DES uses an eight-byte key");
    for block in challenge.chunks_exact_mut(8) {
        let mut encrypted = Block::<des::Des>::default();
        encrypted.copy_from_slice(block);
        cipher.encrypt_block(&mut encrypted);
        block.copy_from_slice(&encrypted);
    }
    challenge
}

pub struct VncClient;

impl VncClient {
    /// Connect to a VNC server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // Resolve and connect
        let mut stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to {}", remote_addr))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "VNC client {} connecting to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Extract password if provided
        let password = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("password"))
            .transpose()?
            .flatten();

        // Perform VNC handshake
        let (fb_width, fb_height, server_name) = tokio::time::timeout(
            crate::client::response_reader::RESPONSE_DEADLINE,
            Self::perform_handshake(&mut stream, password.as_deref()),
        )
        .await
        .context("VNC handshake deadline exceeded")??;

        info!(
            "VNC client {} connected: {}x{} ({})",
            client_id, fb_width, fb_height, server_name
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] VNC client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(VncClientProtocol::new());

        // Split the stream now so the write half is a shared `Arc<Mutex<_>>`: the read loop, the
        // connected-event actions, and the injected-command task all write through it.
        let (read_half, write_half) = tokio::io::split(stream);
        let mut read_half = crate::client::response_reader::FrameReader::new(read_half);
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Command channel for injected actions (the dashboard's [ send_key_event ] etc.).
        // Registered - and drained - BEFORE the connected-event LLM call, which a manual `*` rule
        // can park for minutes: the operator must be able to reach the client while it waits.
        // The read loop uses `read_exact` (not cancellation-safe), so commands are drained by a
        // separate task rather than a `select!` arm; both share the write half.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_protocol = protocol.clone();
        let cmd_write = write_half_arc.clone();
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_protocol,
                cmd_write,
                client_id,
                fb_width,
                fb_height,
                cmd_state,
                cmd_tx,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Fire connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &VNC_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                    "width": fb_width,
                    "height": fb_height,
                    "server_name": server_name,
                }),
            );

            // Call LLM with connected event
            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates: _,
                }) => {
                    // Execute initial actions through the shared write half.
                    for action in actions {
                        let mut guard = write_half_arc.lock().await;
                        if let Err(e) = Self::execute_vnc_action_with_writer(
                            &mut *guard,
                            &protocol,
                            action,
                            fb_width,
                            fb_height,
                        )
                        .await
                        {
                            error!("Failed to execute VNC action: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for VNC client {}: {}", client_id, e);
                }
            }
        }

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
            fb_width,
            fb_height,
        }));

        // The reader runs on its own task and frames whole server messages into a bounded
        // queue, so what the server sends while the model is answering keeps its message
        // boundaries instead of waiting unread in the socket: with batching on, everything
        // waiting is answered in one call (one event per message), with it off one message per
        // call. Registered, so stop_client aborts it.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(READ_QUEUE_MESSAGES);
        let reader = app_state
            .spawn_client_task(client_id, async move {
                loop {
                    let message = match Self::read_server_message(&mut read_half, client_id).await {
                        Ok(Some(event)) => Inbound::Event(event),
                        Ok(None) => continue,
                        Err(e) => Inbound::Ended(e.to_string()),
                    };
                    let last = matches!(message, Inbound::Ended(_));
                    if inbound_tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        // The answering loop. Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            'session: loop {
                let first = inbound_rx
                    .recv()
                    .await
                    .unwrap_or_else(|| Inbound::Ended("reader stopped".to_string()));

                // This message, plus — with batching on — every message already waiting.
                let mut events = Vec::new();
                let mut ended = None;
                match first {
                    Inbound::Event(event) => events.push(event),
                    Inbound::Ended(reason) => ended = Some(reason),
                }
                if ended.is_none()
                    && app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                {
                    while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        match inbound_rx.try_recv() {
                            Ok(Inbound::Event(event)) => events.push(event),
                            Ok(Inbound::Ended(reason)) => {
                                ended = Some(reason);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }

                if !events.is_empty() {
                    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await
                    {
                        let memory = client_data.lock().await.memory.clone();
                        match call_llm_for_client_batch(
                            &llm_client,
                            &app_state,
                            client_id.to_string(),
                            &instruction,
                            &memory,
                            &events,
                            protocol.as_ref(),
                            &status_tx,
                        )
                        .await
                        {
                            Ok(ClientLlmResult {
                                actions,
                                memory_updates,
                            }) => {
                                let (fb_width, fb_height) = {
                                    let mut data = client_data.lock().await;
                                    if let Some(mem) = memory_updates {
                                        data.memory = mem;
                                    }
                                    (data.fb_width, data.fb_height)
                                };
                                for action in actions {
                                    use crate::llm::actions::client_trait::Client;
                                    if matches!(
                                        protocol.as_ref().execute_action(action.clone()),
                                        Ok(ClientActionResult::Disconnect)
                                    ) {
                                        // Half-close: the server answers with EOF, which the
                                        // reader reports as the end of the session.
                                        info!("VNC client {} disconnecting", client_id);
                                        let _ = write_half_arc.lock().await.shutdown().await;
                                        break;
                                    }
                                    let mut guard = write_half_arc.lock().await;
                                    if let Err(e) = Self::execute_vnc_action_with_writer(
                                        &mut *guard,
                                        &protocol,
                                        action,
                                        fb_width,
                                        fb_height,
                                    )
                                    .await
                                    {
                                        error!("Failed to execute VNC action: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("LLM error for VNC client {}: {}", client_id, e);
                            }
                        }
                    }
                }

                if let Some(reason) = ended {
                    info!("VNC client {} disconnected: {}", client_id, reason);
                    break 'session;
                }
            }
            reader.abort();
            // A framing failure is terminal too: its unconsumed payload cannot be
            // interpreted as a new message, and its command handle must disappear.
            app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            app_state.remove_client_handle(client_id).await;
            let _ = status_tx.send(format!("[CLIENT] VNC client {} disconnected", client_id));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Perform VNC handshake (ProtocolVersion, Security, ClientInit, ServerInit)
    async fn perform_handshake(
        stream: &mut TcpStream,
        password: Option<&str>,
    ) -> Result<(u16, u16, String)> {
        // 1. ProtocolVersion handshake
        let mut version_buf = [0u8; 12];
        stream.read_exact(&mut version_buf).await?;
        let version_str = std::str::from_utf8(&version_buf)?;

        if !version_str.starts_with("RFB ") {
            bail!("Invalid VNC protocol version: {}", version_str);
        }

        debug!("VNC server version: {}", version_str.trim());

        // Send version (use 003.008 for modern VNC)
        stream.write_all(b"RFB 003.008\n").await?;

        // 2. Security handshake
        let mut num_security_types = [0u8; 1];
        stream.read_exact(&mut num_security_types).await?;

        if num_security_types[0] == 0 {
            // Connection failed
            let mut reason_len = [0u8; 4];
            stream.read_exact(&mut reason_len).await?;
            let len = u32::from_be_bytes(reason_len);
            let reason = read_server_text(stream, len).await?;
            bail!(
                "VNC connection failed: {}",
                String::from_utf8_lossy(&reason)
            );
        }

        let mut security_types = vec![0u8; num_security_types[0] as usize];
        stream.read_exact(&mut security_types).await?;

        debug!("VNC security types: {:?}", security_types);

        // Choose security type (prefer None=1, then VNC=2)
        let chosen_security = if password.is_some() && security_types.contains(&2) {
            2
        } else if security_types.contains(&1) {
            1 // None
        } else if security_types.contains(&2) {
            if password.is_none() {
                bail!("VNC server requires password authentication but no password provided");
            }
            2 // VNC authentication
        } else {
            bail!(
                "No supported security type (server offers: {:?})",
                security_types
            );
        };

        stream.write_all(&[chosen_security]).await?;

        // Handle VNC authentication if needed
        if chosen_security == 2 {
            let password = password.ok_or_else(|| anyhow!("Password required but not provided"))?;
            Self::perform_vnc_auth(stream, password).await?;
        }

        // Read SecurityResult
        let mut security_result = [0u8; 4];
        stream.read_exact(&mut security_result).await?;
        let result = u32::from_be_bytes(security_result);

        if result != 0 {
            // Authentication failed
            let mut reason_len = [0u8; 4];
            stream.read_exact(&mut reason_len).await?;
            let len = u32::from_be_bytes(reason_len);
            let reason = read_server_text(stream, len).await?;
            bail!(
                "VNC authentication failed: {}",
                String::from_utf8_lossy(&reason)
            );
        }

        // 3. ClientInit (shared-flag = 1 for shared access)
        stream.write_all(&[1]).await?;

        // 4. ServerInit
        let mut server_init = [0u8; 24];
        stream.read_exact(&mut server_init).await?;

        let fb_width = u16::from_be_bytes([server_init[0], server_init[1]]);
        let fb_height = u16::from_be_bytes([server_init[2], server_init[3]]);

        // Skip pixel format (16 bytes)
        let name_length = u32::from_be_bytes([
            server_init[20],
            server_init[21],
            server_init[22],
            server_init[23],
        ]);

        let name_bytes = read_server_text(stream, name_length).await?;
        let server_name = String::from_utf8_lossy(&name_bytes).to_string();

        // Request the 32-bit true-color format the raw rectangle reader consumes.
        // A server's default may be 8 or 16 bits, so assuming 32 without negotiating
        // it would consume the next message as pixel data and lose framing.
        stream
            .write_all(&[
                0, 0, 0, 0, // SetPixelFormat and padding
                32, 24, 0, 1, // bits per pixel, depth, little endian, true color
                0, 255, 0, 255, 0, 255, // red, green, blue maxima
                16, 8, 0, 0, 0, 0, // shifts and padding
            ])
            .await?;

        // Send SetEncodings (support Raw encoding only for simplicity)
        let set_encodings = [
            2u8, // SetEncodings message type
            0,   // padding
            0, 1, // number of encodings (1)
            0, 0, 0, 0, // Raw encoding (0)
        ];
        stream.write_all(&set_encodings).await?;

        Ok((fb_width, fb_height, server_name))
    }

    /// Perform VNC authentication (DES challenge-response)
    async fn perform_vnc_auth(stream: &mut TcpStream, password: &str) -> Result<()> {
        // Read 16-byte challenge
        let mut challenge = [0u8; 16];
        stream.read_exact(&mut challenge).await?;

        stream
            .write_all(&vnc_auth_response(password.as_bytes(), challenge))
            .await?;

        Ok(())
    }

    /// Handle SetColourMapEntries message (read and consume data)
    async fn handle_set_colour_map_entries<R>(read_half: &mut R) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read padding + first-color + number-of-colors
        let mut header = [0u8; 5];
        read_half.read_exact(&mut header).await?;

        let first_color = u16::from_be_bytes([header[1], header[2]]);
        let num_colors = u16::from_be_bytes([header[3], header[4]]);

        trace!(
            "SetColourMapEntries: first={}, count={}",
            first_color,
            num_colors
        );

        // Each color is 6 bytes (RGB as u16 each)
        let color_data_size = (num_colors as usize) * 6;
        let mut color_data = vec![0u8; color_data_size];
        read_half.read_exact(&mut color_data).await?;

        // Color map entries are now consumed and discarded
        // Modern VNC servers rarely use this message
        Ok(())
    }

    /// Read one whole server message. `Ok(Some(event))` is a message the model is told about,
    /// `Ok(None)` one consumed silently (colour map, bell), `Err` the end of the session: EOF,
    /// a read error, a frame past its deadline or a message that cannot be framed, whose
    /// unconsumed payload cannot be read as a new message.
    async fn read_server_message<R>(
        read_half: &mut crate::client::response_reader::FrameReader<R>,
        client_id: ClientId,
    ) -> Result<Option<Event>>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        read_half.end_frame();
        let mut msg_type_buf = [0u8; 1];
        read_half.read_exact(&mut msg_type_buf).await?;
        read_half.start_frame(crate::client::response_reader::RESPONSE_DEADLINE);
        let msg_type = msg_type_buf[0];
        trace!(
            "VNC client {} received message type: {}",
            client_id,
            msg_type
        );
        match msg_type {
            0 => Ok(Some(Self::read_framebuffer_update(read_half).await?)),
            1 => {
                Self::handle_set_colour_map_entries(read_half).await?;
                Ok(None)
            }
            2 => {
                debug!("VNC client {}: Bell received", client_id);
                Ok(None)
            }
            3 => Ok(Some(Self::read_server_cut_text(read_half).await?)),
            other => {
                warn!("VNC client {}: Unknown message type: {}", client_id, other);
                bail!("unknown VNC server message type {other}")
            }
        }
    }

    /// Read a FramebufferUpdate (after its type byte) and describe it.
    async fn read_framebuffer_update<R>(read_half: &mut R) -> Result<Event>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read padding + number of rectangles
        let mut header = [0u8; 3];
        read_half.read_exact(&mut header).await?;

        let num_rects = u16::from_be_bytes([header[1], header[2]]);
        trace!("FramebufferUpdate: {} rectangles", num_rects);

        // Read each rectangle header and consume pixel data
        // We don't parse the actual pixels but must consume the data from the stream
        for _ in 0..num_rects {
            // Rectangle: x-pos (u16), y-pos (u16), width (u16), height (u16), encoding-type (i32)
            let mut rect_header = [0u8; 12];
            read_half.read_exact(&mut rect_header).await?;

            let x = u16::from_be_bytes([rect_header[0], rect_header[1]]);
            let y = u16::from_be_bytes([rect_header[2], rect_header[3]]);
            let width = u16::from_be_bytes([rect_header[4], rect_header[5]]);
            let height = u16::from_be_bytes([rect_header[6], rect_header[7]]);
            let encoding = i32::from_be_bytes([
                rect_header[8],
                rect_header[9],
                rect_header[10],
                rect_header[11],
            ]);

            trace!(
                "Rectangle: {}x{} at ({}, {}), encoding={}",
                width,
                height,
                x,
                y,
                encoding
            );

            if encoding != 0 {
                bail!("unsupported VNC rectangle encoding {encoding}; only Raw was negotiated");
            }
            discard_raw_rectangle(read_half, width, height).await?;
        }

        Ok(Event::new(
            &VNC_CLIENT_FRAMEBUFFER_UPDATE_EVENT,
            serde_json::json!({
                "rectangles": num_rects,
                "update_summary": format!("{} rectangle(s) updated", num_rects),
            }),
        ))
    }

    /// Read a ServerCutText (after its type byte) and describe it.
    async fn read_server_cut_text<R>(read_half: &mut R) -> Result<Event>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read padding + text length
        let mut header = [0u8; 7];
        read_half.read_exact(&mut header).await?;

        let text_length = u32::from_be_bytes([header[3], header[4], header[5], header[6]]);

        let text_bytes = read_server_text(read_half, text_length).await?;

        let text = String::from_utf8_lossy(&text_bytes).to_string();
        debug!("VNC ServerCutText: {}", text);

        Ok(Event::new(
            &VNC_CLIENT_SERVER_CUT_TEXT_EVENT,
            serde_json::json!({
                "text": text,
            }),
        ))
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary because every wire verb yields `ClientActionResult::Custom`, so the action is
    /// encoded by [`Self::apply_injected_action`] - which reuses `send_vnc_message_with_writer`,
    /// the exact encoder the read loop uses for LLM actions - and the outcome is logged and
    /// replied the way the generic arm does it.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop<W>(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        protocol: Arc<VncClientProtocol>,
        write_half: Arc<Mutex<W>>,
        client_id: ClientId,
        fb_width: u16,
        fb_height: u16,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) where
        W: AsyncWriteExt + Unpin + Send + 'static,
    {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = Self::apply_injected_action(
                action.clone(),
                &protocol,
                &write_half,
                fb_width,
                fb_height,
            )
            .await;

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.as_ref().protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!("VNC client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // Half-close so the server reads EOF and the read loop runs its normal
                // disconnect path (status → Disconnected, handle removed).
                let _ = write_half.lock().await.shutdown().await;
                break;
            }
        }
    }

    /// Encode one injected action onto the wire, reusing the read loop's encoder.
    ///
    /// A rejected action (bad JSON) becomes `Rejected`; a `Disconnect` becomes `Disconnected`
    /// (the caller half-closes); a `Custom` verb is encoded into a buffer with
    /// `send_vnc_message_with_writer` so the byte count is exact and the write happens once.
    async fn apply_injected_action<W>(
        action: JsonValue,
        protocol: &Arc<VncClientProtocol>,
        write_half: &Arc<Mutex<W>>,
        fb_width: u16,
        fb_height: u16,
    ) -> Result<crate::state::client_handles::ClientSendOutcome>
    where
        W: AsyncWriteExt + Unpin,
    {
        use crate::llm::actions::client_trait::Client;
        use crate::state::client_handles::ClientSendOutcome;

        match protocol.as_ref().execute_action(action) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(ClientActionResult::Custom { name, data }) => {
                // Encode into a buffer (Vec<u8> is an AsyncWrite) with the same function the LLM
                // path uses, so injected and model-produced messages are byte-identical.
                let mut buf: Vec<u8> = Vec::new();
                Self::send_vnc_message_with_writer(&mut buf, &name, &data, fb_width, fb_height)
                    .await?;
                let bytes_sent = buf.len();
                {
                    let mut guard = write_half.lock().await;
                    guard.write_all(&buf).await?;
                    guard.flush().await?;
                }
                Ok(ClientSendOutcome::Sent { bytes_sent })
            }
            Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
            // WaitForMore / NoAction / (nested) Multiple: nothing to write.
            Ok(_) => Ok(ClientSendOutcome::Executed {
                detail: "executed (nothing to write)".to_string(),
            }),
        }
    }

    /// Execute a VNC action with a writer
    async fn execute_vnc_action_with_writer<W>(
        writer: &mut W,
        protocol: &Arc<VncClientProtocol>,
        action: JsonValue,
        fb_width: u16,
        fb_height: u16,
    ) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        use crate::llm::actions::client_trait::Client;

        match protocol.as_ref().execute_action(action)? {
            ClientActionResult::Custom { name, data } => {
                Self::send_vnc_message_with_writer(writer, &name, &data, fb_width, fb_height)
                    .await?;
            }
            ClientActionResult::Disconnect => {
                return Err(anyhow!("Disconnect requested"));
            }
            _ => {}
        }

        Ok(())
    }

    /// Send a VNC protocol message with a writer.
    ///
    /// `pub` so `tests/client/vnc/coordinate_range_test.rs` can drive it against a `Vec<u8>`
    /// and assert the exact bytes: the guards on the model's coordinates live here, and a test
    /// of the guard functions alone would not prove they are wired in.
    pub async fn send_vnc_message_with_writer<W>(
        writer: &mut W,
        action_name: &str,
        data: &JsonValue,
        fb_width: u16,
        fb_height: u16,
    ) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        match action_name {
            "request_framebuffer_update" => {
                let incremental = data["incremental"].as_bool().unwrap_or(true);
                let x = rfb_u16(data, "x", 0)?;
                let y = rfb_u16(data, "y", 0)?;
                let width = rfb_u16(data, "width", fb_width)?;
                let height = rfb_u16(data, "height", fb_height)?;

                let msg = [
                    3u8, // FramebufferUpdateRequest
                    if incremental { 1 } else { 0 },
                    (x >> 8) as u8,
                    (x & 0xff) as u8,
                    (y >> 8) as u8,
                    (y & 0xff) as u8,
                    (width >> 8) as u8,
                    (width & 0xff) as u8,
                    (height >> 8) as u8,
                    (height & 0xff) as u8,
                ];
                writer.write_all(&msg).await?;
            }
            "send_pointer_event" => {
                let x = rfb_u16(data, "x", 0)?;
                let y = rfb_u16(data, "y", 0)?;
                let button_mask = rfb_u8(data, "button_mask", 0)?;

                let msg = [
                    5u8, // PointerEvent
                    button_mask,
                    (x >> 8) as u8,
                    (x & 0xff) as u8,
                    (y >> 8) as u8,
                    (y & 0xff) as u8,
                ];
                writer.write_all(&msg).await?;
            }
            "send_key_event" => {
                let Some(key) = resolve_keysym(&data["key"]) else {
                    anyhow::bail!(
                        "send_key_event: unrecognised 'key' {}. Use a keysym number, a single \
                         character like \"a\", or a name like \"Enter\"/\"Escape\"/\"F1\"",
                        data["key"]
                    );
                };
                let down = data["down"].as_bool().unwrap_or(false);

                let msg = [
                    4u8, // KeyEvent
                    if down { 1 } else { 0 },
                    0,
                    0, // padding
                    (key >> 24) as u8,
                    (key >> 16) as u8,
                    (key >> 8) as u8,
                    (key & 0xff) as u8,
                ];
                writer.write_all(&msg).await?;
            }
            "send_client_cut_text" => {
                let text = data["text"].as_str().unwrap_or("");
                let text_bytes = text.as_bytes();
                if text_bytes.len() > MAX_TEXT_BYTES {
                    anyhow::bail!("VNC clipboard exceeds byte cap");
                }
                let length =
                    u32::try_from(text_bytes.len()).context("VNC clipboard length exceeds u32")?;

                let mut msg = vec![
                    6u8, // ClientCutText
                    0,
                    0,
                    0, // padding
                    (length >> 24) as u8,
                    (length >> 16) as u8,
                    (length >> 8) as u8,
                    (length & 0xff) as u8,
                ];
                msg.extend_from_slice(text_bytes);
                writer.write_all(&msg).await?;
            }
            _ => {
                warn!("Unknown VNC action: {}", action_name);
            }
        }

        Ok(())
    }
}

/// Read a model-supplied RFB coordinate, refusing anything the field cannot hold.
///
/// Every one of these was `data["x"].as_u64().unwrap_or(0) as u16`. RFB's x, y, width and
/// height are two bytes each, so `as u16` silently rewrites the number: **`65736` becomes
/// `200`** and `70000` becomes `4464`. The client then asks the server for a rectangle nobody
/// named, and nothing anywhere records that the request differs from the answer — the same
/// arithmetic fail-open `tests/narrowing_cast_drift_test.rs` exists for.
///
/// Refusing beats clamping: 65535 is not what the model asked for either, and the message is
/// what the repair loop reads.
fn rfb_u16(data: &JsonValue, key: &str, default: u16) -> Result<u16> {
    match data.get(key) {
        None | Some(JsonValue::Null) => Ok(default),
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                anyhow::anyhow!("'{key}' must be a non-negative whole number, got {value}")
            })?;
            u16::try_from(raw).map_err(|_| {
                anyhow::anyhow!(
                    "'{key}' is {raw}; RFB carries coordinates and extents in two bytes, so \
                     0-65535 is the whole of what this field can say"
                )
            })
        }
    }
}

/// The same for a one-byte RFB field (the pointer button mask).
///
/// RFB 3.8 defines bits 0-7, so `257` is not "button 1 again" — it is a number the field cannot
/// hold, and `as u8` turned it into 1.
fn rfb_u8(data: &JsonValue, key: &str, default: u8) -> Result<u8> {
    match data.get(key) {
        None | Some(JsonValue::Null) => Ok(default),
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                anyhow::anyhow!("'{key}' must be a non-negative whole number, got {value}")
            })?;
            u8::try_from(raw).map_err(|_| {
                anyhow::anyhow!(
                    "'{key}' is {raw}; the RFB button mask is one byte (0-255), one bit per \
                     button"
                )
            })
        }
    }
}
