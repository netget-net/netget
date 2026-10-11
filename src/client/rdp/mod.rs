//! RDP client. IronRDP runs the connection sequence (X.224 negotiation, TLS, CredSSP for NLA,
//! MCS/GCC, licensing, capabilities, finalization) and decodes the server's graphics into a
//! framebuffer. The model's actions become fast-path input; `rdp_read_screen` describes the
//! framebuffer as colours once the server has stopped drawing.
pub mod actions;
pub mod keys;
pub mod screen;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use actions::Input;
pub use actions::RdpClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionResult, ConnectorResult, Credentials,
    DesktopSize,
};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, WheelRotations};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::{FramedWrite as _, NetworkClient, TokioFramed};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// The whole connection sequence, TCP connect to the first frame.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Input operations per fast-path PDU (the PDU counts its events in one byte).
const OPS_PER_PDU: usize = 32;
const TURNS: usize = 64;

type Framed = TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;

/// sspi asks a network client to reach a Kerberos KDC. NetGet authenticates with NTLM only.
struct NoKerberos;
impl NetworkClient for NoKerberos {
    async fn send(&mut self, _: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(ironrdp_connector::custom_err!(
            "Kerberos",
            std::io::Error::other("this client authenticates with NTLM only")
        ))
    }
}

struct Settings {
    username: String,
    password: String,
    domain: Option<String>,
    tls: bool,
    nla: bool,
    width: u16,
    height: u16,
}

fn settings(ctx: &ConnectContext) -> Result<Settings> {
    let params = ctx.startup_params.as_ref();
    let get = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    let side = |k: &str, default: u16| -> Result<u16> {
        let v = params
            .map(|p| p.get_optional_u64(k))
            .transpose()?
            .flatten()
            .unwrap_or(u64::from(default));
        ensure!(
            (u64::from(actions::MIN_SIDE)..=u64::from(actions::MAX_SIDE)).contains(&v),
            "{k} must be between {} and {}",
            actions::MIN_SIDE,
            actions::MAX_SIDE
        );
        Ok(v as u16)
    };
    let (tls, nla) = match get("security")?.as_deref().unwrap_or("any") {
        "any" => (true, true),
        "tls" => (true, false),
        "nla" => (false, true),
        other => bail!("security is any, tls or nla, not {other:?}"),
    };
    Ok(Settings {
        username: get("username")?.unwrap_or_default(),
        password: get("password")?.unwrap_or_default(),
        domain: get("domain")?,
        tls,
        nla,
        // Even widths: some servers refuse odd ones.
        width: side("width", actions::DEFAULT_WIDTH)? & !1,
        height: side("height", actions::DEFAULT_HEIGHT)?,
    })
}

fn config(s: &Settings) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        credentials: Credentials::UsernamePassword {
            username: s.username.clone(),
            password: s.password.clone(),
        },
        domain: s.domain.clone(),
        enable_tls: s.tls,
        enable_credssp: s.nla,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        // US English.
        keyboard_layout: 0x0409,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize {
            width: s.width,
            height: s.height,
        },
        bitmap: None,
        client_build: 0,
        client_name: "netget".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::UNIX,
        enable_server_pointer: false,
        request_data: None,
        // Log straight on with the credentials given, rather than at the server's login screen.
        autologon: !s.username.is_empty(),
        enable_audio_playback: false,
        compression_type: None,
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// TCP, X.224, TLS and the rest of the connection sequence. Returns which security the server
/// selected.
async fn establish(
    server: SocketAddr,
    host: &str,
    config: ironrdp_connector::Config,
) -> Result<(ConnectionResult, Framed, &'static str)> {
    // In-process callers (tests, an embedding) may not have run main's provider install.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tcp = TcpStream::connect(server)
        .await
        .with_context(|| format!("cannot reach {server}"))?;
    let local = tcp.local_addr()?;
    let mut framed = TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config, local);
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.report()))
        .context("connection negotiation")?;
    let security = match &connector.state {
        ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol }
            if selected_protocol
                .intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) =>
        {
            "nla"
        }
        _ => "tls",
    };
    let tcp = framed.into_inner_no_leftover();
    let (tls, cert) = ironrdp_tls::upgrade(tcp, host)
        .await
        .context("TLS upgrade")?;
    let public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .context("the server's certificate carries no public key")?
        .to_vec();
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = TokioFramed::new(tls);
    let result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoKerberos,
        host.into(),
        public_key,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}", e.report()))
    .context("connection sequence")?;
    Ok((result, framed, security))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let s = settings(&ctx)?;
    let raw = ctx
        .remote_addr
        .trim()
        .trim_start_matches("rdp://")
        .trim_end_matches('/');
    let with_port = if raw.parse::<SocketAddr>().is_ok()
        || raw
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.ends_with(':') && p.parse::<u16>().is_ok())
    {
        raw.to_string()
    } else {
        format!("{raw}:3389")
    };
    let server = tokio::net::lookup_host(&with_port)
        .await
        .with_context(|| format!("cannot resolve {with_port}"))?
        .next()
        .with_context(|| format!("{with_port} resolved to no address"))?;
    let host = with_port
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']).to_string())
        .unwrap_or_default();
    let (result, framed, security) =
        tokio::time::timeout(CONNECT_TIMEOUT, establish(server, &host, config(&s)))
            .await
            .context("the RDP connection sequence timed out")??;
    let size = result.desktop_size;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "RDP client {} connected to {server} ({security}, {}x{})",
        ctx.client_id, size.width, size.height
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({"server": server.to_string(), "security": security,
                   "width": size.width, "height": size.height}),
        ),
        0,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut session = Session::new(result, framed);
        let reason = session
            .run(&session_ctx, external, internal, event_tx.clone())
            .await;
        Log::new(Some(&session_ctx.status_tx)).info(format!(
            "RDP client {} disconnected: {reason}",
            session_ctx.client_id
        ));
        // The model hears the end of the session before the dispatcher stops.
        let _ = event_tx
            .send((
                Event::new(&actions::DISCONNECTED_EVENT, json!({"reason": reason})),
                0,
            ))
            .await;
        drop(event_tx);
        let _ = tokio::time::timeout(Duration::from_secs(30), async {
            while !dispatcher_abort.is_finished() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        dispatcher_abort.abort();
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(server)
}

/// A screen read waiting for the server to stop drawing.
struct PendingRead {
    grid: u64,
    settle: Duration,
    give_up: Instant,
    command: Option<ClientCommand>,
    depth: u32,
}

struct Session {
    stage: ActiveStage,
    image: DecodedImage,
    framed: Framed,
    input: Database,
    activation: ironrdp_connector::connection_activation::ConnectionActivationFactory,
    updates: u64,
    last_update: Instant,
}

impl Session {
    fn new(result: ConnectionResult, framed: Framed) -> Self {
        let size = result.desktop_size;
        let stage = ActiveStageBuilder {
            static_channels: result.static_channels,
            user_channel_id: result.user_channel_id,
            io_channel_id: result.io_channel_id,
            message_channel_id: result.message_channel_id,
            share_id: result.share_id,
            compression_type: result.compression_type,
            enable_server_pointer: result.enable_server_pointer,
            pointer_software_rendering: result.pointer_software_rendering,
        }
        .build();
        Self {
            stage,
            image: DecodedImage::new(PixelFormat::RgbA32, size.width, size.height),
            framed,
            input: Database::new(),
            activation: result.activation_factory,
            updates: 0,
            last_update: Instant::now(),
        }
    }

    /// Runs until the session ends; returns why.
    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
        events: mpsc::Sender<(Event, u32)>,
    ) -> String {
        let mut pending: Option<PendingRead> = None;
        let emit = |event: &'static EventType, data: Value, depth: u32| {
            if events.try_send((Event::new(event, data), depth)).is_err() {
                tracing::warn!("RDP client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full", ctx.client_id);
            }
        };
        loop {
            // A pending read answers once the screen has been quiet long enough, or at its limit.
            let wake = pending
                .as_ref()
                .map(|p| (self.last_update + p.settle).min(p.give_up))
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
            let (action, depth, command) = tokio::select! {
                frame = self.framed.read_pdu() => {
                    match frame {
                        Ok((action, payload)) => match self.on_frame(action, &payload).await {
                            Ok(None) => continue,
                            Ok(Some(reason)) => return reason,
                            Err(e) => return format!("{e:#}"),
                        },
                        Err(e) => return format!("the connection ended: {e}"),
                    }
                }
                _ = tokio::time::sleep_until(wake), if pending.is_some() => {
                    let p = pending.take().expect("guarded by the branch condition");
                    let settled = Instant::now() < p.give_up || self.last_update + p.settle <= Instant::now();
                    let mut data = screen::describe(&self.image, p.grid as usize);
                    data["graphics_updates"] = json!(self.updates);
                    data["settled"] = json!(settled);
                    if let Some(c) = p.command {
                        crate::client::command_support::reply(c, Ok(ClientSendOutcome::Executed { detail: data.to_string() }));
                    }
                    emit(&actions::SCREEN_EVENT, data, p.depth);
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => {
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "RDP", None,
                            "injected_action", c.action.clone(), vec![]).await;
                        (c.action.clone(), 0, Some(c))
                    }
                    None => return "the client was stopped".into(),
                },
                a = internal.recv() => match a {
                    Some((a, d)) => (a, d, None),
                    None => return "the client was stopped".into(),
                },
            };
            let reply = |command: Option<ClientCommand>, outcome: ClientSendOutcome| {
                if let Some(c) = command {
                    crate::client::command_support::reply(c, Ok(outcome));
                }
            };
            let kind = action["type"].as_str().unwrap_or_default().to_string();
            match RdpClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    let _ = self.shutdown().await;
                    reply(command, ClientSendOutcome::Disconnected);
                    return "the client disconnected".into();
                }
                Ok(_) => {}
                Err(e) => {
                    reply(
                        command,
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            }
            let input = actions::check(&action).expect("execute_action validated it");
            if let Input::ReadScreen { grid, settle_ms } = input {
                if let Some(old) = pending.take() {
                    if let Some(c) = old.command {
                        crate::client::command_support::reply(
                            c,
                            Ok(ClientSendOutcome::Rejected {
                                error: "replaced by a newer rdp_read_screen".into(),
                            }),
                        );
                    }
                }
                let settle = Duration::from_millis(settle_ms);
                pending = Some(PendingRead {
                    grid,
                    settle,
                    give_up: Instant::now()
                        + settle
                        + Duration::from_millis(actions::MAX_SETTLE_WAIT_MS),
                    command,
                    depth,
                });
                continue;
            }
            match self.send_input(&input).await {
                Ok(n) => {
                    Log::new(Some(&ctx.status_tx)).info(format!(
                        "RDP client {}: {kind} ({n} input events)",
                        ctx.client_id
                    ));
                    reply(
                        command,
                        ClientSendOutcome::Executed {
                            detail: json!({"action": kind, "input_events": n}).to_string(),
                        },
                    );
                }
                Err(e) => {
                    let message = format!("{e:#}");
                    reply(
                        command,
                        ClientSendOutcome::Executed {
                            detail: json!({"action": kind, "error": message}).to_string(),
                        },
                    );
                    emit(
                        &actions::ERROR_EVENT,
                        json!({"action": kind, "message": message}),
                        depth,
                    );
                }
            }
        }
    }

    /// Process one frame from the server. `Some(reason)` ends the session.
    async fn on_frame(
        &mut self,
        action: ironrdp_pdu::Action,
        payload: &[u8],
    ) -> Result<Option<String>> {
        let outputs = self
            .stage
            .process(&mut self.image, action, payload)
            .map_err(|e| anyhow::anyhow!("{}", e.report()))
            .context("a frame from the server")?;
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => {
                    self.framed.write_all(&frame).await?;
                }
                ActiveStageOutput::GraphicsUpdate(_) => {
                    self.updates += 1;
                    self.last_update = Instant::now();
                }
                ActiveStageOutput::Terminate(reason) => {
                    return Ok(Some(reason.description()));
                }
                ActiveStageOutput::DeactivateAll => self.reactivate().await?,
                _ => {}
            }
        }
        Ok(None)
    }

    /// The Deactivation-Reactivation Sequence: capabilities again, then finalization; the
    /// server may change the desktop size on the way.
    async fn reactivate(&mut self) -> Result<()> {
        let mut sequence = self.activation.create();
        let mut buf = ironrdp_pdu::WriteBuf::new();
        loop {
            if let ConnectionActivationState::Finalized {
                desktop_size,
                share_id,
                enable_server_pointer,
                ..
            } = sequence.connection_activation_state()
            {
                self.image =
                    DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                self.stage.set_share_id(share_id);
                self.stage.set_enable_server_pointer(enable_server_pointer);
                return Ok(());
            }
            ironrdp_tokio::single_sequence_step(&mut self.framed, &mut sequence, &mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.report()))
                .context("reactivation")?;
        }
    }

    async fn send_input(&mut self, input: &Input) -> Result<usize> {
        let ops = match input {
            Input::Text(text) => keys::type_text(text),
            Input::Keys(list) => {
                let mut ops = Vec::new();
                for k in list {
                    ops.extend(keys::press(&keys::combo(k)?));
                }
                ops
            }
            Input::Mouse {
                x,
                y,
                action,
                button,
            } => {
                ensure!(
                    *x < self.image.width() && *y < self.image.height(),
                    "({x}, {y}) is outside the {}x{} desktop",
                    self.image.width(),
                    self.image.height()
                );
                let button = match button.as_str() {
                    "right" => MouseButton::Right,
                    "middle" => MouseButton::Middle,
                    _ => MouseButton::Left,
                };
                let mut ops = vec![Operation::MouseMove(MousePosition { x: *x, y: *y })];
                let click = [
                    Operation::MouseButtonPressed(button),
                    Operation::MouseButtonReleased(button),
                ];
                let wheel = |units| {
                    Operation::WheelRotations(WheelRotations {
                        is_vertical: true,
                        rotation_units: units,
                    })
                };
                match action.as_str() {
                    "click" => ops.extend(click.clone()),
                    "double_click" => {
                        ops.extend(click.clone());
                        ops.extend(click);
                    }
                    "press" => ops.push(Operation::MouseButtonPressed(button)),
                    "release" => ops.push(Operation::MouseButtonReleased(button)),
                    "scroll_up" => ops.push(wheel(120)),
                    "scroll_down" => ops.push(wheel(-120)),
                    _ => {}
                }
                ops
            }
            Input::ReadScreen { .. } => Vec::new(),
        };
        let mut sent = 0;
        for chunk in ops.chunks(OPS_PER_PDU) {
            let events = self.input.apply(chunk.iter().cloned());
            sent += events.len();
            let outputs = self
                .stage
                .process_fastpath_input(&mut self.image, &events)
                .map_err(|e| anyhow::anyhow!("{}", e.report()))?;
            for out in outputs {
                if let ActiveStageOutput::ResponseFrame(frame) = out {
                    self.framed.write_all(&frame).await?;
                }
            }
        }
        Ok(sent)
    }

    async fn shutdown(&mut self) -> Result<()> {
        let outputs = self
            .stage
            .graceful_shutdown()
            .map_err(|e| anyhow::anyhow!("{}", e.report()))?;
        for out in outputs {
            if let ActiveStageOutput::ResponseFrame(frame) = out {
                self.framed.write_all(&frame).await?;
            }
        }
        Ok(())
    }
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = RdpClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!("RDP client {} not asking the model about {}: {depth} turns deep decision=followup_depth", ctx.client_id, event.id());
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                for action in result.actions {
                    // The session may be gone (disconnected); the rest of the answer has
                    // nowhere to go.
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("RDP client handler: {e}")),
        }
    }
}
