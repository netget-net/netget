//! M3UA / SIGTRAN server (RFC 4666) — an SGP that an ASP connects to.
//!
//! # The transport problem, stated plainly
//!
//! **M3UA runs over SCTP.** RFC 4666 section 1.4.1 says so and IANA assigns it SCTP port 2905.
//! macOS has no SCTP stack — no kernel support, no headers — and macOS is the machine that
//! tests this code. Two of the three possible responses are implemented here, and the third is
//! recorded rather than hidden:
//!
//! 1. **SCTP is the default, and a host without it gets a refusal that says so.** [`bind_listener`]
//!    asks the kernel for a `SOCK_STREAM`/`IPPROTO_SCTP` socket; where that fails, `spawn()`
//!    returns an `Err` naming SCTP, and `server_startup` puts the server in
//!    `ServerStatus::Error`. This is the `bluetooth_ble_beacon` precedent: *hiding a protocol is
//!    not the same as refusing to start it* — refused, the operator learns exactly why; hidden,
//!    nobody does. It is a **probe, not a `cfg`**: the socket is actually requested, so a Linux
//!    kernel with the `sctp` module unloaded is diagnosed the same way as macOS.
//! 2. **`transport: "tcp"` is a lab affordance and is labelled as one everywhere** — in the
//!    startup parameter description, in `metadata().notes`, in the startup log line, in the
//!    connection's `protocol_info` and in every event's `transport` field. **No real SIGTRAN
//!    peer speaks M3UA over TCP.** It exists so the layers above the transport can be exercised
//!    at all on this machine, and nothing else.
//! 3. **Userspace SCTP** — `webrtc-rs` is already in the tree and carries an implementation — is
//!    the real fix and is out of scope here. See `CLAUDE.md` in this directory.
//!
//! Everything above the socket is transport-agnostic: M3UA is length-delimited, so the framing
//! is identical whether the octets arrive on an SCTP association or a TCP connection. That is
//! what makes the lab transport useful and is also exactly why it must be labelled — the code
//! path being exercised is real, and the transport under it is not.
//!
//! # Division of labour
//!
//! Rust owns everything that is not a decision: framing, header and parameter validity, the ASP
//! state machine's mechanics, BEAT → BEAT ACK, ASPDN → ASPDN ACK, ASPIA → ASPIA ACK, and every
//! refusal that follows from the protocol rather than from policy.
//!
//! The model owns the two decisions M3UA actually has — **may this ASP come up, and may it go
//! active** — plus what SS7 traffic to answer with. Those are admission decisions into a
//! signalling network, so they **fail closed**: an ASP is never admitted because nothing
//! answered. Silence, a backend failure and "no policy was ever configured" are three distinct
//! things and all three end in ERR, tagged apart in the log the way `src/server/radius/` does.
//!
//! # Session
//!
//! ```text
//! accept                       -> ASP-DOWN
//! ASPUP  -> m3ua_asp_up_received     -> ASPUP ACK  -> ASP-INACTIVE   (or ERR, stay DOWN)
//! ASPAC  -> m3ua_asp_active_received -> ASPAC ACK  -> ASP-ACTIVE     (or ERR, stay INACTIVE)
//! DATA   -> m3ua_data_received       -> optional DATA back
//! BEAT   -> BEAT ACK                                (Rust, no LLM call)
//! ASPIA  -> ASPIA ACK                -> ASP-INACTIVE (Rust, no LLM call)
//! ASPDN  -> ASPDN ACK, then m3ua_asp_down_received -> ASP-DOWN
//! ERR    -> m3ua_error_received                     (observational)
//! ```
//!
//! BEAT is answered in Rust deliberately. It is a keepalive, not a decision: routing it through
//! a parked manual handler would let the association time out while a human read a question.

pub mod actions;
pub mod ber;
pub mod cap;
pub mod codec;
pub mod gsm;
pub mod map;
pub mod sccp;
pub mod ss7;
pub mod ss7_actions;
pub mod tcap;
pub mod transport;

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};
use transport::{Reader, Writer};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::M3uaProtocol;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::utils::WireFailure;

use actions::{
    M3UA_ASP_ACTIVE_EVENT, M3UA_ASP_DOWN_EVENT, M3UA_ASP_UP_EVENT, M3UA_DATA_EVENT,
    M3UA_ERROR_EVENT,
};

/// IANA protocol number for SCTP. Named here rather than taken from `libc` because the
/// constant is absent on the platforms that lack the stack, which is precisely where this code
/// has to compile in order to produce the refusal.
const IPPROTO_SCTP: i32 = 132;

/// How long to wait for a peer's first message after the association comes up.
///
/// RFC 4666 has the ASP send ASPUP as soon as the association is established — the SG says
/// nothing first, and nothing legitimate precedes it. A peer that has connected and sent
/// nothing is not mid-handshake; it is holding an association slot on no request at all.
const FIRST_MESSAGE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* message once one has arrived.
///
/// Fifteen minutes, and it is long on purpose: a signalling link with no traffic is the normal
/// case, not a suspicious one, so this must not be a traffic timer. The protocol's own answer
/// to "is this quiet link still alive" is BEAT (RFC 4666 section 3.5.5), which exists precisely
/// so an idle-but-live ASP can prove it and which deployments configure at tens of seconds —
/// so fifteen minutes is on the order of thirty missed beats. A peer that sends neither
/// traffic nor a single BEAT for that long is indistinguishable from one that has gone away,
/// and over TCP (this server's transport here) there is no SCTP heartbeat underneath to tell
/// the difference.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Concurrent associations this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// An M3UA ERR carrying error code `Refused - Management Blocking`
/// ([`codec::ERR_REFUSED_MANAGEMENT_BLOCKING`], 0x0d) — which is what that code is for, and
/// which this server already sends elsewhere when it declines an ASP. ERR is a Management-class
/// message either end may send unsolicited at any time, so unlike most protocols here there is
/// a *correct* thing to say to a peer that has not spoken yet.
///
/// Encoded by hand rather than through [`codec::Message::encode`] because a `const` cannot call
/// it: version 1, reserved 0, class MGMT(0), type ERR(0), length 16; then parameter tag
/// `TAG_ERROR_CODE` (0x000c), parameter length 8, value 0x0000000d.
const CONNECTION_CAP_REFUSAL: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, // version, reserved, class MGMT, type ERR
    0x00, 0x00, 0x00, 0x10, // message length: 16
    0x00, 0x0c, 0x00, 0x08, // parameter: Error Code, length 8
    0x00, 0x00, 0x00, 0x0d, // Refused - Management Blocking
];

/// M3UA server: an SGP that ASPs connect to.
pub struct M3uaServer;

/// Which transport the association runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M3uaTransport {
    /// The real one (RFC 4666 section 1.4.1). Requires an operating system with SCTP.
    Sctp,
    /// **Non-standard.** A lab affordance so the M3UA layer can be exercised on a host with no
    /// SCTP stack. No real SIGTRAN peer speaks this.
    Tcp,
}

impl M3uaTransport {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sctp" => Ok(Self::Sctp),
            "tcp" => Ok(Self::Tcp),
            other => Err(anyhow!(
                "transport must be \"sctp\" (the transport RFC 4666 defines) or \"tcp\" \
                 (non-standard, for local protocol work only), got {other:?}"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sctp => "sctp",
            Self::Tcp => "tcp",
        }
    }

    /// How the transport is described wherever an operator or the model can see it.
    ///
    /// The TCP wording carries its own warning because this string travels: it is in the
    /// startup log, in the connection's `protocol_info`, and in every event handed to the
    /// model. Somebody reading any one of those must not come away believing they have SCTP.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sctp => "sctp (RFC 4666)",
            Self::Tcp => "tcp (NON-STANDARD lab transport, not SIGTRAN)",
        }
    }
}

/// Bind the listening socket for `transport`.
///
/// Public because the SCTP refusal is a feature with its own test: on a host without an SCTP
/// stack this must fail, and fail with a message that names SCTP rather than an errno.
pub async fn bind_listener(addr: SocketAddr, transport: M3uaTransport) -> Result<TcpListener> {
    match transport {
        M3uaTransport::Tcp => {
            crate::server::socket_helpers::create_reusable_tcp_listener(addr).await
        }
        M3uaTransport::Sctp => bind_sctp_listener(addr),
    }
}

/// Ask the kernel for a one-to-one SCTP socket and listen on it.
///
/// The SCTP one-to-one style (`SOCK_STREAM` with `IPPROTO_SCTP`) presents the ordinary
/// accept/read/write socket API, so the association is driven by the same code as the TCP lab
/// transport once it exists. What differs is that on a host without SCTP, `socket(2)` fails
/// here — and that failure is the whole point of this function.
fn bind_sctp_listener(addr: SocketAddr) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket =
        Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP))).map_err(|e| {
            anyhow!(
                "M3UA cannot open an SCTP socket on this host: {e}. M3UA's transport is SCTP \
                 (RFC 4666 section 1.4.1, IANA port 2905) and this operating system has no SCTP \
                 stack available to this process — macOS ships neither kernel support nor \
                 headers for SCTP, and a Linux kernel without the sctp module fails the same \
                 way. NetGet refuses to start rather than pretend it is speaking SIGTRAN. \
                 Either run this server on a host with SCTP, or, for local protocol work only, \
                 pass the startup parameter transport=\"tcp\" — a NON-STANDARD framing that \
                 exercises the M3UA layer and that no real SIGTRAN peer speaks."
            )
        })?;

    socket
        .set_reuse_address(true)
        .map_err(|e| anyhow!("M3UA could not set SO_REUSEADDR on the SCTP socket: {e}"))?;
    socket
        .bind(&addr.into())
        .map_err(|e| anyhow!("M3UA could not bind the SCTP socket to {addr}: {e}"))?;
    socket
        .listen(128)
        .map_err(|e| anyhow!("M3UA could not listen on the SCTP socket at {addr}: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| anyhow!("M3UA could not put the SCTP socket in non-blocking mode: {e}"))?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .map_err(|e| anyhow!("M3UA could not register the SCTP listener with tokio: {e}"))
}

/// Operator configuration for one SGP instance.
#[derive(Clone, Copy, Debug)]
pub struct M3uaConfig {
    pub transport: M3uaTransport,
    /// When set, an ASPAC or DATA naming a different Routing Context is refused in Rust.
    pub routing_context: Option<u32>,
    /// When set, a DATA naming a different Network Appearance is refused in Rust.
    pub network_appearance: Option<u32>,
}

impl M3uaConfig {
    /// Validate startup parameters before anything binds.
    ///
    /// Errors propagate with `?`; nothing here unwraps. An undeclared key or a wrong-typed
    /// value fails startup with a message naming the key rather than killing the task that is
    /// starting the server.
    fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        let Some(params) = params else {
            return Ok(Self {
                transport: M3uaTransport::Sctp,
                routing_context: None,
                network_appearance: None,
            });
        };

        let transport = match params.get_optional_string("transport")? {
            Some(s) => M3uaTransport::parse(&s)?,
            None => M3uaTransport::Sctp,
        };

        Ok(Self {
            transport,
            routing_context: params.get_optional_u32("routing_context")?,
            network_appearance: params.get_optional_u32("network_appearance")?,
        })
    }
}

/// Where one ASP sits in the RFC 4666 section 4.3.1 state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AspState {
    Down,
    Inactive,
    Active,
}

impl AspState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Down => "ASP-DOWN",
            Self::Inactive => "ASP-INACTIVE",
            Self::Active => "ASP-ACTIVE",
        }
    }
}

impl M3uaServer {
    /// Spawn the M3UA listener.
    ///
    /// Awaits readiness: the socket is bound before this returns, so `server_startup` reports a
    /// real failure — including "this host has no SCTP" — instead of parking the server in
    /// `Running` having bound nothing.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        let config = M3uaConfig::from_params(startup_params.as_ref())?;
        let listener = bind_listener(listen_addr, config.transport).await?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!(
            "M3UA SGP listening on {} over {}",
            local_addr,
            config.transport.label()
        ));
        if config.transport == M3uaTransport::Tcp {
            Log::new(Some(&status_tx)).warn(
                "M3UA is running over TCP. This is NOT SIGTRAN: RFC 4666 defines M3UA over \
                 SCTP only, and no real ASP will connect over TCP. Use it for local protocol \
                 work and nothing else.",
            );
        }

        let protocol = Arc::new(M3uaProtocol::new());
        let task_registrar = app_state.clone();

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "M3UA",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        Log::new(Some(&status_tx)).info(format!(
                            "M3UA association {} from {} ({})",
                            connection_id,
                            remote_addr,
                            config.transport.as_str()
                        ));

                        register_connection(
                            &app_state,
                            server_id,
                            connection_id,
                            remote_addr,
                            config.transport,
                        )
                        .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the association, so the cap counts live
                                // associations rather than accepts.
                                let _permit = permit;
                                if let Err(e) = run_session(
                                    stream,
                                    connection_id,
                                    server_id,
                                    remote_addr,
                                    llm_clone,
                                    state_clone.clone(),
                                    status_clone.clone(),
                                    protocol_clone,
                                    config,
                                )
                                .await
                                {
                                    Log::new(Some(&status_clone))
                                        .error(format!("M3UA association error: {}", e));
                                }

                                state_clone
                                    .remove_peer_handle(server_id, connection_id.as_u32())
                                    .await;
                                state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                Log::new(Some(&status_clone))
                                    .info(format!("M3UA association {} closed", connection_id));
                                let _ = status_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept M3UA association: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

async fn register_connection(
    app_state: &AppState,
    server_id: ServerId,
    connection_id: ConnectionId,
    remote_addr: SocketAddr,
    transport: M3uaTransport,
) {
    use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id: connection_id,
                remote_addr,
                local_addr: remote_addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                    "asp_state": AspState::Down.as_str(),
                    // The rail shows this, and it must never let someone believe an association
                    // over the lab transport is an SCTP association.
                    "transport": transport.label(),
                })),
            },
        )
        .await;
}

/// One M3UA association.
struct M3uaSession {
    connection_id: ConnectionId,
    server_id: ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<M3uaProtocol>,
    config: M3uaConfig,
    state: AspState,
    /// The ASP Identifier from ASPUP, if it sent one — reported in later events so a handler
    /// can tell two ASPs apart.
    asp_identifier: Option<u32>,
    writer: Arc<Mutex<Writer>>,
    /// TCAP dialogues on this association (the SCCP / TCAP / MAP / CAP layer).
    engine: ss7::Engine,
}

/// Outcome of reading one framed message.
pub enum Incoming {
    Message(codec::Message),
    /// The common header was unusable. There is no way to find the next message boundary after
    /// this, so the association ends.
    HeaderError(codec::WireError),
    /// The header was fine and the parameters were not. One ERR, association continues.
    BodyError(codec::WireError),
    Eof,
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    stream: TcpStream,
    connection_id: ConnectionId,
    server_id: ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<M3uaProtocol>,
    config: M3uaConfig,
) -> Result<()> {
    // Split rather than clone: the read half stays here, the write half is shared with the
    // dashboard's peer command task. Over SCTP each write is one message with PPID 3, on stream
    // 0 for management and stream 1 for DATA (`transport.rs`).
    let (mut reader, writer) = transport::split(stream, config.transport == M3uaTransport::Sctp);
    let writer = Arc::new(Mutex::new(writer));

    // Registered before the first read so "message this peer" and "disconnect this peer" work
    // even while a manual rule has the ASPUP event parked for a human.
    let peer_rx = crate::server::peer_support::register_peer_channel(
        &app_state,
        server_id,
        connection_id.as_u32(),
    )
    .await;
    crate::server::peer_support::spawn_peer_command_task(
        peer_rx,
        Arc::new(M3uaProtocol::for_peer_commands()),
        app_state.clone(),
        server_id,
        connection_id.as_u32(),
        writer.clone(),
        status_tx.clone(),
    );

    let mut session = M3uaSession {
        connection_id,
        server_id,
        remote_addr,
        llm_client,
        app_state,
        status_tx,
        protocol,
        config,
        state: AspState::Down,
        asp_identifier: None,
        writer,
        engine: ss7::Engine::new(),
    };

    session.run(&mut reader).await
}

impl M3uaSession {
    async fn run(&mut self, reader: &mut Reader) -> Result<()> {
        debug!(
            "M3UA association {} open, ASP in {}",
            self.connection_id,
            self.state.as_str()
        );

        let mut received_one = false;

        loop {
            // The deadline wraps `read_message` and nothing else. Everything that can
            // legitimately take minutes — the LLM round-trip that decides whether an ASP may
            // come up, and a `manual` rule parking that decision for a human
            // (`src/state/intercepts.rs`, 300s by default) — happens below, once a whole
            // message has been read. So neither sits inside a read deadline. What is bounded is
            // a peer holding the association while sending nothing, and a peer that announces a
            // message length and stalls part-way through delivering it.
            let read_timeout = if received_one {
                IDLE_BETWEEN_MESSAGES_TIMEOUT
            } else {
                FIRST_MESSAGE_READ_TIMEOUT
            };
            let (incoming, bytes_in) = read_message(reader, read_timeout).await;
            if !matches!(incoming, Incoming::Eof) {
                received_one = true;
            }
            if bytes_in > 0 {
                self.app_state
                    .update_connection_stats(
                        self.server_id,
                        self.connection_id,
                        Some(bytes_in as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            }

            match incoming {
                Incoming::Eof => {
                    debug!("M3UA association {} closed by peer", self.connection_id);
                    break;
                }
                Incoming::HeaderError(e) => {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "M3UA header rejected from {}: {}",
                        self.remote_addr, e
                    ));
                    self.send_error(e.error_code).await;
                    break;
                }
                Incoming::BodyError(e) => {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "M3UA message from {} rejected: {}",
                        self.remote_addr, e
                    ));
                    self.send_error(e.error_code).await;
                }
                Incoming::Message(message) => {
                    if !self.dispatch(message).await? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle one decoded message. Returns `false` when the association must close.
    async fn dispatch(&mut self, message: codec::Message) -> Result<bool> {
        trace!(
            "M3UA {} from {} in {}",
            message.name(),
            self.remote_addr,
            self.state.as_str()
        );

        match (message.class, message.msg_type) {
            (codec::CLASS_ASPSM, codec::ASPSM_ASPUP) => self.on_asp_up(&message).await,
            (codec::CLASS_ASPSM, codec::ASPSM_ASPDN) => self.on_asp_down(&message).await,
            (codec::CLASS_ASPSM, codec::ASPSM_BEAT) => {
                // Answered in Rust with no LLM call: a keepalive is not a decision, and parking
                // it behind a manual handler would drop the association while a human read the
                // question. The Heartbeat Data is echoed verbatim, which is what makes it
                // useful to the ASP.
                let heartbeat = message
                    .param(codec::TAG_HEARTBEAT_DATA)
                    .map(|p| p.value.clone());
                trace!("M3UA BEAT from {} -> BEAT ACK", self.remote_addr);
                // "Verbatim" has a ceiling: the peer chooses this data, and a BEAT carrying a
                // maximal Heartbeat Data parameter cannot be echoed inside the 65535-octet
                // message the header can describe. That is the one wire-reachable encode
                // refusal in this protocol, so it gets ERR rather than silence — the ASP is
                // told its keepalive was rejected instead of watching it disappear.
                match codec::beat_ack(heartbeat.as_deref()) {
                    Ok(bytes) => self.send(bytes).await,
                    Err(e) => {
                        error!(
                            "M3UA decision=fail_closed_encode: BEAT from {} carries Heartbeat \
                             Data that cannot be echoed within the message ceiling: {}",
                            self.remote_addr, e
                        );
                        self.send_error(codec::ERR_PROTOCOL_ERROR).await;
                    }
                }
                Ok(true)
            }
            (codec::CLASS_ASPTM, codec::ASPTM_ASPAC) => self.on_asp_active(&message).await,
            (codec::CLASS_ASPTM, codec::ASPTM_ASPIA) => {
                // Taking an ASP out of service needs no permission — the risk runs entirely the
                // other way — so this is mechanical too.
                self.state = AspState::Inactive;
                self.set_connection_state().await;
                Log::new(Some(&self.status_tx)).info(format!(
                    "M3UA ASPIA from {}, ASP is now {}",
                    self.remote_addr,
                    self.state.as_str()
                ));
                self.send_encoded(
                    "ASPIA ACK",
                    codec::aspia_ack(message.param_u32(codec::TAG_ROUTING_CONTEXT)),
                )
                .await;
                Ok(true)
            }
            (codec::CLASS_TRANSFER, codec::TRANSFER_DATA) => self.on_data(&message).await,
            (codec::CLASS_MGMT, codec::MGMT_ERR) => self.on_error_received(&message).await,
            (codec::CLASS_MGMT, codec::MGMT_NTFY) => {
                // An SGP receiving NTFY is unusual but harmless; it carries no request.
                Log::new(Some(&self.status_tx)).info(format!(
                    "M3UA NTFY from {} status=0x{:08x}",
                    self.remote_addr,
                    message.param_u32(codec::TAG_STATUS).unwrap_or(0)
                ));
                Ok(true)
            }
            (codec::CLASS_RKM, _) => {
                // Dynamic registration means keeping a routing key table, and a routing key
                // table is storage — which the root CLAUDE.md forbids a protocol from
                // implementing. Refusing explicitly is better than accepting and forgetting:
                // an ASP that believes it registered a routing key will send traffic for it.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA {} from {} refused: NetGet implements no routing key table \
                     (dynamic registration is storage; configure routing_context instead)",
                    message.name(),
                    self.remote_addr
                ));
                self.send_error(codec::ERR_UNSUPPORTED_MESSAGE_TYPE).await;
                Ok(true)
            }
            (codec::CLASS_SSNM, _) => {
                // SSNM travels SGP -> ASP. One arriving here is an ASP speaking out of turn.
                warn!(
                    "M3UA {} from {} is an SGP-to-ASP message; refusing",
                    message.name(),
                    self.remote_addr
                );
                self.send_error(codec::ERR_UNEXPECTED_MESSAGE).await;
                Ok(true)
            }
            (class, msg_type) => {
                let known_class = matches!(
                    class,
                    codec::CLASS_MGMT
                        | codec::CLASS_TRANSFER
                        | codec::CLASS_SSNM
                        | codec::CLASS_ASPSM
                        | codec::CLASS_ASPTM
                        | codec::CLASS_RKM
                );
                let code = if known_class {
                    codec::ERR_UNSUPPORTED_MESSAGE_TYPE
                } else {
                    codec::ERR_UNSUPPORTED_MESSAGE_CLASS
                };
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA class {} ({}) type {} from {} is not supported",
                    class,
                    codec::class_name(class),
                    msg_type,
                    self.remote_addr
                ));
                self.send_error(code).await;
                Ok(true)
            }
        }
    }

    // -----------------------------------------------------------------------
    // ASPSM / ASPTM
    // -----------------------------------------------------------------------

    async fn on_asp_up(&mut self, message: &codec::Message) -> Result<bool> {
        self.asp_identifier = message.param_u32(codec::TAG_ASP_IDENTIFIER);

        // RFC 4666 section 4.3.4.3: an ASPUP for an ASP that is already up is acknowledged and
        // nothing else happens. Not an admission — this ASP was admitted already — so no policy
        // is consulted for the retransmission.
        if self.state != AspState::Down {
            debug!(
                "M3UA duplicate ASPUP from {} while {}; re-acknowledging",
                self.remote_addr,
                self.state.as_str()
            );
            self.send_encoded("ASPUP ACK", codec::aspup_ack(None)).await;
            return Ok(true);
        }

        let info_string = message
            .param(codec::TAG_INFO_STRING)
            .map(|p| String::from_utf8_lossy(&p.value).to_string());

        Log::new(Some(&self.status_tx)).info(format!(
            "M3UA ASPUP from {} (asp_id={:?})",
            self.remote_addr, self.asp_identifier
        ));

        let event = Event {
            event_type: &M3UA_ASP_UP_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
                "transport": self.config.transport.label(),
                "asp_identifier": self.asp_identifier,
                "info_string": info_string,
                "asp_state": self.state.as_str(),
            }),
        };

        self.decide_admission(
            &event,
            (codec::CLASS_ASPSM, codec::ASPSM_ASPUP_ACK),
            AspState::Inactive,
        )
        .await
    }

    async fn on_asp_active(&mut self, message: &codec::Message) -> Result<bool> {
        // Protocol validity is decided in Rust and never delegated: an ASP that never came up
        // cannot go active, whatever a policy would have said.
        if self.state == AspState::Down {
            Log::new(Some(&self.status_tx)).warn(format!(
                "M3UA ASPAC from {} while ASP-DOWN; refusing without consulting policy",
                self.remote_addr
            ));
            self.send_error(codec::ERR_UNEXPECTED_MESSAGE).await;
            return Ok(true);
        }

        let routing_context = message.param_u32(codec::TAG_ROUTING_CONTEXT);
        if let Some(expected) = self.config.routing_context {
            if let Some(offered) = routing_context {
                if offered != expected {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "M3UA ASPAC from {} names routing context {} but this SGP serves {}",
                        self.remote_addr, offered, expected
                    ));
                    self.send_error(codec::ERR_INVALID_ROUTING_CONTEXT).await;
                    return Ok(true);
                }
            }
        }

        // Already active: acknowledge the retransmission without re-asking.
        if self.state == AspState::Active {
            debug!(
                "M3UA duplicate ASPAC from {} while ASP-ACTIVE; re-acknowledging",
                self.remote_addr
            );
            self.send_encoded(
                "ASPAC ACK",
                codec::aspac_ack(
                    message.param_u32(codec::TAG_TRAFFIC_MODE_TYPE),
                    routing_context,
                    None,
                ),
            )
            .await;
            return Ok(true);
        }

        let traffic_mode = message.param_u32(codec::TAG_TRAFFIC_MODE_TYPE);
        Log::new(Some(&self.status_tx)).info(format!(
            "M3UA ASPAC from {} (rc={:?}, traffic_mode={:?})",
            self.remote_addr, routing_context, traffic_mode
        ));

        let event = Event {
            event_type: &M3UA_ASP_ACTIVE_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
                "transport": self.config.transport.label(),
                "asp_identifier": self.asp_identifier,
                "routing_context": routing_context,
                "traffic_mode": traffic_mode,
                "traffic_mode_name": traffic_mode.map(traffic_mode_name),
                "asp_state": self.state.as_str(),
            }),
        };

        self.decide_admission(
            &event,
            (codec::CLASS_ASPTM, codec::ASPTM_ASPAC_ACK),
            AspState::Active,
        )
        .await
    }

    /// The two admission decisions M3UA has, and the one place they may be made.
    ///
    /// Every path that is not an explicit acknowledgement ends in ERR and leaves the ASP where
    /// it was. That is the fail-closed rule, and the four ways of not answering are kept apart
    /// in the log rather than collapsed: an operator has to be able to tell a policy that
    /// refused from a backend that fell over.
    async fn decide_admission(
        &mut self,
        event: &Event,
        ack: (u8, u8),
        next_state: AspState,
    ) -> Result<bool> {
        let event_id = event.event_type.id.clone();
        let outcome = self.call_llm_and_send(event).await;

        match outcome {
            HandlerOutcome::Ran { ref sent, closed } if sent.contains(&ack) => {
                self.state = next_state;
                self.set_connection_state().await;
                Log::new(Some(&self.status_tx)).info(format!(
                    "M3UA {} admitted {} to {}",
                    event_id,
                    self.remote_addr,
                    self.state.as_str()
                ));
                Ok(!closed)
            }
            HandlerOutcome::Ran { ref sent, closed }
                if sent.contains(&(codec::CLASS_MGMT, codec::MGMT_ERR)) =>
            {
                // The policy refused explicitly, and its own ERR is already on the wire. This
                // path is structurally distinct from silence on purpose: a refusal must not be
                // readable as an outage, nor an outage as a refusal.
                info!(
                    "M3UA {} decision=model_reject peer={} asp stays {}",
                    event_id,
                    self.remote_addr,
                    self.state.as_str()
                );
                Ok(!closed)
            }
            HandlerOutcome::Ran { closed, .. } => {
                // The policy ran and produced no acknowledgement — wait_for_more, an empty
                // handler, or a NTFY and nothing else. For an admission that is a refusal:
                // silence must never open a signalling gateway.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA {} produced no acknowledgement for {} (decision=model_silent); \
                     refusing, ASP stays {}",
                    event_id,
                    self.remote_addr,
                    self.state.as_str()
                ));
                self.send_error(codec::ERR_REFUSED_MANAGEMENT_BLOCKING)
                    .await;
                Ok(!closed)
            }
            HandlerOutcome::Failed(failure) => {
                // The operator configured a policy and it could not be evaluated. Admitting
                // anyway would turn a backend outage into "any ASP may join the signalling
                // network", which is the fail-open pattern the root CLAUDE.md calls the most
                // dangerous in this codebase.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA {} could not be evaluated for {} (decision=fail_closed_llm_error, \
                     {}); refusing, ASP stays {}",
                    event_id,
                    self.remote_addr,
                    failure_category(failure),
                    self.state.as_str()
                ));
                self.send_error(codec::ERR_REFUSED_MANAGEMENT_BLOCKING)
                    .await;
                Ok(true)
            }
            HandlerOutcome::NoPolicy => {
                // Nobody ever said who may use this gateway. There is no safe default for
                // that question, so it is answered with a refusal and a log line that says
                // exactly what is missing.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA {} refused for {} (decision=no_policy_configured): this server has \
                     no instruction and no event handler, so nothing decides which ASPs may \
                     join. Give the server an instruction, or a handler for {}.",
                    event_id, self.remote_addr, event_id
                ));
                self.send_error(codec::ERR_REFUSED_MANAGEMENT_BLOCKING)
                    .await;
                Ok(true)
            }
        }
    }

    async fn on_asp_down(&mut self, _message: &codec::Message) -> Result<bool> {
        // Acknowledged first and unconditionally. Taking a peer *out* of service is the safe
        // direction, so it needs no policy — and an ASP that cannot leave cleanly is a worse
        // failure than one that cannot join.
        self.send_encoded("ASPDN ACK", codec::aspdn_ack()).await;
        self.state = AspState::Down;
        self.set_connection_state().await;
        Log::new(Some(&self.status_tx)).info(format!(
            "M3UA ASPDN from {}, ASP is now {}",
            self.remote_addr,
            self.state.as_str()
        ));

        let event = Event {
            event_type: &M3UA_ASP_DOWN_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
                "transport": self.config.transport.label(),
                "asp_identifier": self.asp_identifier,
                "asp_state": self.state.as_str(),
            }),
        };
        let outcome = self.call_llm_and_send(&event).await;
        self.log_observational_outcome("m3ua_asp_down_received", outcome);
        Ok(true)
    }

    async fn on_error_received(&mut self, message: &codec::Message) -> Result<bool> {
        let code = message.param_u32(codec::TAG_ERROR_CODE).unwrap_or(0);
        Log::new(Some(&self.status_tx)).warn(format!(
            "M3UA ERR from {}: 0x{:02x} {}",
            self.remote_addr,
            code,
            codec::error_code_name(code)
        ));

        let event = Event {
            event_type: &M3UA_ERROR_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
                "transport": self.config.transport.label(),
                "error_code": code,
                "error_name": codec::error_code_name(code),
                "routing_context": message.param_u32(codec::TAG_ROUTING_CONTEXT),
                "asp_state": self.state.as_str(),
            }),
        };
        let outcome = self.call_llm_and_send(&event).await;
        self.log_observational_outcome("m3ua_error_received", outcome);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Transfer
    // -----------------------------------------------------------------------

    async fn on_data(&mut self, message: &codec::Message) -> Result<bool> {
        if self.state != AspState::Active {
            Log::new(Some(&self.status_tx)).warn(format!(
                "M3UA DATA from {} while {}; refusing",
                self.remote_addr,
                self.state.as_str()
            ));
            self.send_error(codec::ERR_UNEXPECTED_MESSAGE).await;
            return Ok(true);
        }

        let routing_context = message.param_u32(codec::TAG_ROUTING_CONTEXT);
        if let (Some(expected), Some(offered)) = (self.config.routing_context, routing_context) {
            if expected != offered {
                self.send_error(codec::ERR_INVALID_ROUTING_CONTEXT).await;
                return Ok(true);
            }
        }
        let network_appearance = message.param_u32(codec::TAG_NETWORK_APPEARANCE);
        if let (Some(expected), Some(offered)) =
            (self.config.network_appearance, network_appearance)
        {
            if expected != offered {
                self.send_error(codec::ERR_INVALID_NETWORK_APPEARANCE).await;
                return Ok(true);
            }
        }

        let Some(parameter) = message.param(codec::TAG_PROTOCOL_DATA) else {
            Log::new(Some(&self.status_tx)).warn(format!(
                "M3UA DATA from {} carries no Protocol Data parameter",
                self.remote_addr
            ));
            self.send_error(codec::ERR_MISSING_PARAMETER).await;
            return Ok(true);
        };
        let protocol_data = match codec::ProtocolData::parse(&parameter.value) {
            Ok(pd) => pd,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA DATA from {} has malformed Protocol Data: {}",
                    self.remote_addr, e
                ));
                self.send_error(e.error_code).await;
                return Ok(true);
            }
        };

        // SCCP (Service Indicator 3) is decoded through TCAP down to MAP or CAP. Everything that
        // follows from the protocol is answered in Rust; a dialogue message the model must
        // answer becomes m3ua_map_received / m3ua_cap_received instead of an opaque payload.
        let now = crate::utils::clock::Instant::now();
        self.expire_dialogues(now).await;
        let mut sccp_note = None;
        match self
            .engine
            .on_data(&protocol_data, routing_context, network_appearance, now)
        {
            ss7::Inbound::NotSccp => {}
            ss7::Inbound::Undecoded(reason) => sccp_note = Some(reason),
            ss7::Inbound::Handled { replies, note } => {
                Log::new(Some(&self.status_tx)).info(format!(
                    "M3UA SCCP from {} opc={} handled without the model: {}",
                    self.remote_addr, protocol_data.opc, note
                ));
                for reply in replies {
                    self.send_ss7(reply).await;
                }
                return Ok(true);
            }
            ss7::Inbound::Event(event) => return Ok(self.on_ss7_event(event).await),
        }

        let (payload, encoding) = render_payload(&protocol_data.payload);
        info!(
            "M3UA DATA from {} opc={} dpc={} si={} ({}) sls={}",
            self.remote_addr,
            protocol_data.opc,
            protocol_data.dpc,
            protocol_data.si,
            codec::si_name(protocol_data.si),
            protocol_data.sls
        );

        let event = Event {
            event_type: &M3UA_DATA_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
                "transport": self.config.transport.label(),
                "opc": protocol_data.opc,
                "dpc": protocol_data.dpc,
                "si": protocol_data.si,
                "si_name": codec::si_name(protocol_data.si),
                "ni": protocol_data.ni,
                "mp": protocol_data.mp,
                "sls": protocol_data.sls,
                "payload": payload,
                // Stated, never left to be guessed. "48656c6c6f" is simultaneously valid text
                // and valid hex, and only the sender knows which it is.
                "encoding": encoding,
                "payload_bytes": protocol_data.payload.len(),
                "routing_context": routing_context,
                "network_appearance": network_appearance,
                "correlation_id": message.param_u32(codec::TAG_CORRELATION_ID),
                "sccp_note": sccp_note,
            }),
        };

        let outcome = self.call_llm_and_send(&event).await;
        match outcome {
            HandlerOutcome::Ran { closed, .. } => Ok(!closed),
            // Answering nothing would tell the ASP its MSU reached the SS7 network, which is a
            // worse lie than a refusal: M3UA has an ERR message, so the peer gets a category
            // and the log gets the error. Nothing derived from the error reaches the wire —
            // ERR's Diagnostic Information parameter is left empty by `codec::error`.
            HandlerOutcome::Failed(failure) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA m3ua_data_received could not be evaluated for {} \
                     (decision=fail_closed_llm_error, {}); answering ERR",
                    self.remote_addr,
                    failure_category(failure)
                ));
                self.send_error(codec::ERR_REFUSED_MANAGEMENT_BLOCKING)
                    .await;
                Ok(true)
            }
            HandlerOutcome::NoPolicy => {
                // Unreachable in practice — with no policy the ASP could never have been
                // admitted — but a refusal is still the right answer if it ever is reached.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA m3ua_data_received refused for {} (decision=no_policy_configured)",
                    self.remote_addr
                ));
                self.send_error(codec::ERR_REFUSED_MANAGEMENT_BLOCKING)
                    .await;
                Ok(true)
            }
        }
    }

    /// Log what an observational event decided.
    ///
    /// Nothing is written on any branch beyond what the handler itself produced, and that is
    /// correct: M3UA defines no reply to an ASPDN acknowledgement or to a peer's ERR. The three
    /// cases are still tagged so an operator can see an outage in one grep.
    fn log_observational_outcome(&self, event_id: &str, outcome: HandlerOutcome) {
        match outcome {
            HandlerOutcome::Failed(failure) => Log::new(Some(&self.status_tx)).warn(format!(
                "M3UA {} could not be evaluated for {} (decision=fail_closed_llm_error, {}); \
                 nothing sent",
                event_id,
                self.remote_addr,
                failure_category(failure)
            )),
            HandlerOutcome::NoPolicy => debug!(
                "M3UA {} peer={}: no operator policy configured, no LLM call",
                event_id, self.remote_addr
            ),
            HandlerOutcome::Ran { ref sent, .. } if sent.is_empty() => debug!(
                "M3UA {} decision=model_silent peer={}: nothing sent",
                event_id, self.remote_addr
            ),
            HandlerOutcome::Ran { .. } => debug!(
                "M3UA {} peer={}: handler answered",
                event_id, self.remote_addr
            ),
        }
    }

    /// Run the handler for `event` and write whatever M3UA messages it produced.
    async fn call_llm_and_send(&mut self, event: &Event) -> HandlerOutcome {
        if !operator_wants_dynamic(&self.app_state, self.server_id, &event.event_type.id).await {
            debug!(
                "M3UA {}: no operator policy configured, no LLM call",
                event.event_type.id
            );
            return HandlerOutcome::NoPolicy;
        }

        let result = match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            event,
            &*self.protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                // The whole error goes to the log and the operator's status stream. The peer
                // gets a category mapped onto an RFC 4666 error code, and nothing else.
                let failure = WireFailure::classify(&e);
                error!(
                    "M3UA {} decision=fail_closed_llm_error category={:?} peer={}: {:#}",
                    event.event_type.id, failure, self.remote_addr, e
                );
                return HandlerOutcome::Failed(failure);
            }
        };

        let mut sent = Vec::new();
        let mut closed = false;
        let mut queue: Vec<ActionResult> = result.protocol_results;
        queue.reverse();
        while let Some(item) = queue.pop() {
            match item {
                ActionResult::Multiple(inner) => {
                    for nested in inner.into_iter().rev() {
                        queue.push(nested);
                    }
                }
                ActionResult::Output(bytes) => {
                    // Read the class/type back off the octets rather than tracking it beside
                    // them: what is on the wire is what the state machine must follow.
                    if let Some(kind) = codec::peek_class_type(&bytes) {
                        sent.push(kind);
                    }
                    self.send(bytes).await;
                }
                ActionResult::CloseConnection => {
                    let mut writer = self.writer.lock().await;
                    let _ = writer.shutdown().await;
                    drop(writer);
                    closed = true;
                }
                ActionResult::Custom { name, data } if name == ss7::SS7_INTENT => {
                    let route = self.engine.last_route.clone();
                    match self.engine.apply(
                        &data,
                        route.as_ref(),
                        0,
                        crate::utils::clock::Instant::now(),
                    ) {
                        Ok((_, out)) => {
                            sent.push((codec::CLASS_TRANSFER, codec::TRANSFER_DATA));
                            self.send_ss7(out).await;
                        }
                        Err(e) => {
                            // The dialogue's own fail-closed rule (below, in on_ss7_event)
                            // still applies: an intent that could not be honoured answers
                            // nothing, so an invoke it was meant to answer stays unanswered.
                            Log::new(Some(&self.status_tx)).warn(format!(
                                "M3UA {} refused for {}: {} (decision=action_refused)",
                                data["type"].as_str().unwrap_or("SS7 action"),
                                self.remote_addr,
                                e
                            ));
                        }
                    }
                }
                ActionResult::WaitForMore | ActionResult::NoAction => {}
                other => debug!("M3UA ignoring action result {other:?}"),
            }
        }

        HandlerOutcome::Ran { sent, closed }
    }

    /// Wrap an SS7 message in M3UA DATA and send it.
    async fn send_ss7(&self, out: ss7::Outgoing) {
        trace!(
            "M3UA SS7 {} to {} opc={} dpc={}",
            out.label,
            self.remote_addr,
            out.protocol_data.opc,
            out.protocol_data.dpc
        );
        self.send_encoded(
            &out.label,
            codec::data(
                &out.protocol_data,
                out.network_appearance,
                out.routing_context,
                None,
            ),
        )
        .await;
    }

    /// Abort and forget dialogues that have been idle past `ss7::DIALOGUE_IDLE_TIMEOUT`.
    async fn expire_dialogues(&mut self, now: crate::utils::clock::Instant) {
        for (dialogue, abort) in self.engine.expire(now) {
            Log::new(Some(&self.status_tx)).info(format!(
                "M3UA dialogue {} with {} idle for {}s; aborted (decision=dialogue_idle_timeout)",
                dialogue.id,
                self.remote_addr,
                ss7::DIALOGUE_IDLE_TIMEOUT.as_secs()
            ));
            if let Some(out) = abort {
                self.send_ss7(out).await;
            }
        }
    }

    /// A decoded MAP or CAP dialogue message: ask the model, then hold it to an answer.
    ///
    /// Returns whether the association stays open.
    async fn on_ss7_event(&mut self, ev: ss7::Ss7Event) -> bool {
        for reply in ev.replies {
            self.send_ss7(reply).await;
        }
        let event_type: &'static crate::protocol::EventType = match ev.family {
            ss7::Family::Map => &ss7_actions::SGP_MAP_EVENT,
            ss7::Family::Cap => &ss7_actions::SGP_CAP_EVENT,
        };
        let mut data = ev.data;
        data["connection_id"] = serde_json::json!(self.connection_id.to_string());
        data["remote_addr"] = serde_json::json!(self.remote_addr.to_string());
        data["transport"] = serde_json::json!(self.config.transport.label());
        Log::new(Some(&self.status_tx)).info(format!(
            "M3UA {} TC-{} dialogue {} from {}",
            ev.family.name().to_uppercase(),
            ev.kind.name().to_uppercase(),
            ev.dialogue_id,
            self.remote_addr
        ));
        let event = Event { event_type, data };
        let outcome = self.call_llm_and_send(&event).await;
        let closed = matches!(outcome, HandlerOutcome::Ran { closed: true, .. });
        if ev.ended || !self.engine.awaiting_answer(ev.dialogue_id) {
            if ev.ended {
                self.log_observational_outcome(event_type.id.as_str(), outcome);
            }
            return !closed;
        }
        // The dialogue still owes the peer an answer. Leaving it open would have the far end's
        // invoke timer decide; answering something here is the honest alternative, and what is
        // answered depends on why there was no answer.
        let (fail_closed, decision) = match &outcome {
            HandlerOutcome::Ran { .. } => (false, "model_silent".to_string()),
            HandlerOutcome::Failed(f) => (
                true,
                format!("fail_closed_llm_error, {}", failure_category(*f)),
            ),
            HandlerOutcome::NoPolicy => (true, "no_policy_configured".to_string()),
        };
        if let Some(out) = self.engine.close_unanswered(ev.dialogue_id, fail_closed) {
            Log::new(Some(&self.status_tx)).warn(format!(
                "M3UA {} dialogue {} from {} left unanswered (decision={}); sending {}",
                ev.family.name().to_uppercase(),
                ev.dialogue_id,
                self.remote_addr,
                decision,
                out.label
            ));
            self.send_ss7(out).await;
        }
        !closed
    }

    async fn send(&self, bytes: Vec<u8>) {
        let written = {
            let mut writer = self.writer.lock().await;
            match writer.write_all(&bytes).await {
                Ok(()) => writer.flush().await.is_ok(),
                Err(_) => false,
            }
        };
        if !written {
            debug!(
                "M3UA write failed on association {}; peer has gone",
                self.connection_id
            );
            return;
        }
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
    }

    /// Send a message the codec has just built, or log why it would not build one.
    ///
    /// The encoders refuse anything `parse_header` would reject at the far end, so a refusal
    /// here means the message could not have been understood — sending a truncated or
    /// wrong-length version of it would be strictly worse than sending nothing. Tagged
    /// `decision=fail_closed_encode` so it is distinguishable from the model's own silence,
    /// which is the rule the rest of this protocol follows.
    async fn send_encoded(&self, what: &str, encoded: Result<Vec<u8>, codec::WireError>) {
        match encoded {
            Ok(bytes) => self.send(bytes).await,
            Err(e) => {
                error!(
                    "M3UA decision=fail_closed_encode: refusing to send {} to {}: {}",
                    what, self.remote_addr, e
                );
                Log::new(Some(&self.status_tx)).warn(format!(
                    "M3UA could not encode {what} for {}",
                    self.remote_addr
                ));
            }
        }
    }

    async fn send_error(&self, error_code: u32) {
        Log::new(Some(&self.status_tx)).warn(format!(
            "M3UA ERR 0x{:02x} ({}) to {}",
            error_code,
            codec::error_code_name(error_code),
            self.remote_addr
        ));
        self.send_encoded("ERR", codec::error(error_code, self.config.routing_context))
            .await;
    }

    async fn set_connection_state(&self) {
        let server_id = self.server_id;
        let connection_id = self.connection_id;
        let value = serde_json::json!({
            "asp_state": self.state.as_str(),
            "transport": self.config.transport.label(),
        });
        self.app_state
            .with_server_mut(server_id, |server| {
                if let Some(connection) = server.connections.get_mut(&connection_id) {
                    connection.protocol_info =
                        crate::state::server::ProtocolConnectionInfo::new(value.clone());
                }
            })
            .await;
    }
}

/// What a handler's actions amounted to.
#[derive(Debug, Clone)]
enum HandlerOutcome {
    /// No operator policy exists for this event, so nothing was consulted. Distinct from a
    /// policy that ran and said nothing: nobody has answered the question at all.
    NoPolicy,
    /// The handler could not be run — the backend errored, timed out or was saturated. Distinct
    /// from silence on purpose: a caller that treats silence as an answer must not treat this
    /// the same way.
    Failed(WireFailure),
    /// The handler ran. `sent` is the (class, type) of every message it put on the wire, in
    /// order; empty means it chose to say nothing.
    Ran { sent: Vec<(u8, u8)>, closed: bool },
}

fn failure_category(failure: WireFailure) -> &'static str {
    // M3UA's error code registry (RFC 4666 section 3.8.1) has no resource-exhaustion code, so
    // both categories map onto Refused - Management Blocking on the wire. The distinction the
    // wire cannot carry is kept in the log, which is the rule the root CLAUDE.md states for
    // exactly this case.
    if failure.is_overloaded() {
        "resource"
    } else {
        "unavailable"
    }
}

fn traffic_mode_name(mode: u32) -> &'static str {
    match mode {
        codec::TRAFFIC_MODE_OVERRIDE => "override",
        codec::TRAFFIC_MODE_LOADSHARE => "loadshare",
        codec::TRAFFIC_MODE_BROADCAST => "broadcast",
        _ => "unassigned",
    }
}

/// Render an SS7 user part for the model, declaring how it was rendered.
///
/// Text payloads are common in a lab and unheard-of in a real network, so both are supported —
/// but the choice is reported in the event's `encoding` field rather than left to be inferred,
/// and `send_m3ua_data` takes the same field on the way out. That symmetry is the point: an
/// echo handler can feed the event's `payload` and `encoding` straight back.
fn render_payload(payload: &[u8]) -> (String, &'static str) {
    let printable = std::str::from_utf8(payload).ok().filter(|s| {
        s.chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
    });
    match printable {
        Some(text) if !payload.is_empty() => (text.to_string(), "utf8"),
        _ => (hex::encode(payload), "hex"),
    }
}

/// True when the operator opted into dynamic handling — a non-empty server instruction, or an
/// event handler matching this event.
///
/// M3UA treats `false` as a refusal rather than as a static default, unlike BGP: an ASP coming
/// up is an admission into a signalling network, and there is no configuration-free answer to
/// "who may join" that is not a guess.
async fn operator_wants_dynamic(state: &AppState, server_id: ServerId, event_id: &str) -> bool {
    state
        .with_server_mut(server_id, |server| {
            let has_instruction = !server.instruction.trim().is_empty();
            let has_handler = server
                .event_handler_config
                .as_ref()
                .map(|c| c.find_handler(event_id).is_some())
                .unwrap_or(false);
            has_instruction || has_handler
        })
        .await
        .unwrap_or(false)
}

/// Read one M3UA message: the 8-octet common header, then exactly the declared body.
///
/// Nothing is allocated before the length has been validated, so a peer cannot choose the
/// buffer size, and `length - HEADER_LEN` cannot underflow.
///
/// The second element is the number of octets consumed, for the connection's inbound counters.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    read_timeout: std::time::Duration,
) -> (Incoming, usize) {
    let mut header = [0u8; codec::HEADER_LEN];
    let header_read = match tokio::time::timeout(read_timeout, reader.read_exact(&mut header)).await
    {
        Ok(read) => read,
        Err(_) => {
            debug!(
                "M3UA peer sent nothing for {}s; closing idle association",
                read_timeout.as_secs()
            );
            return (Incoming::Eof, 0);
        }
    };
    match header_read {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return (Incoming::Eof, 0),
        Err(e) => {
            debug!("M3UA read error: {e}");
            return (Incoming::Eof, 0);
        }
    }

    let parsed = match codec::parse_header(&header) {
        Ok(h) => h,
        Err(e) => return (Incoming::HeaderError(e), codec::HEADER_LEN),
    };

    let total = parsed.length as usize;
    let mut full = vec![0u8; total];
    full[..codec::HEADER_LEN].copy_from_slice(&header);
    if total > codec::HEADER_LEN {
        match tokio::time::timeout(
            read_timeout,
            reader.read_exact(&mut full[codec::HEADER_LEN..]),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!("M3UA truncated message body: {e}");
                return (Incoming::Eof, codec::HEADER_LEN);
            }
            Err(_) => {
                debug!(
                    "M3UA peer announced {total} octets and stalled for {}s without \
                     delivering them; closing",
                    read_timeout.as_secs()
                );
                return (Incoming::Eof, codec::HEADER_LEN);
            }
        }
    }

    // A sender that excludes the final parameter's padding from the Message Length still writes
    // those octets (RFC 4666 section 3.2), so consume them or the next header starts mid-word.
    // NetGet's own messages always have zero slack.
    let slack = codec::alignment_slack(parsed.length);
    if slack > 0 {
        let mut padding = [0u8; 3];
        match tokio::time::timeout(read_timeout, reader.read_exact(&mut padding[..slack])).await {
            Ok(Ok(_)) => {}
            _ => return (Incoming::Eof, total),
        }
    }

    let consumed = total + slack;
    match codec::Message::parse(&full) {
        Ok(message) => (Incoming::Message(message), consumed),
        Err(e) => (Incoming::BodyError(e), consumed),
    }
}
