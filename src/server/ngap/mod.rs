//! NGAP (3GPP TS 38.413) — NetGet as an **AMF** on the 5G N2 interface, which a gNB connects to.
//!
//! # Division of labour
//!
//! Rust owns everything that is not a decision: the SCTP association (PPID 60, stream 0 for
//! non-UE-associated signalling and stream 1 for UE-associated), ALIGNED PER encoding and
//! decoding, procedure codes, IE structure and constraints, AMF UE NGAP ID allocation, the UE
//! context table, and every refusal that follows from the protocol rather than from policy — a
//! PDU that does not decode, a message before NG Setup, an unknown UE id, an NG Reset (answered
//! mechanically: resetting is the safe direction).
//!
//! The model owns the decisions an AMF actually makes: **whether this gNB may set up N2** (NG
//! Setup Response with the AMF's name, GUAMIs and supported slices, or NG Setup Failure with a
//! cause), and **what to say to each UE** — an Identity Request, an Authentication Request, a
//! Registration Reject with a 5GMM cause, a UE Context Release. NAS is decoded into structure for
//! it (see [`nas`]) and its answers are encoded by Rust.
//!
//! # Fail closed
//!
//! An NG Setup Request is an admission into a 5G core and a Registration Request an admission
//! into a network, so neither has a default answer. Every path that is not an explicit answer is
//! a refusal, tagged apart in the log:
//!
//! | Situation | NG Setup | Initial UE Message |
//! |---|---|---|
//! | model answered | its Response or Failure | its NAS / release |
//! | model refused explicitly | its Failure (`decision=model_reject`) | its Reject |
//! | model said nothing | Failure misc/unspecified (`decision=model_silent`) | Registration/Service Reject #111, then release |
//! | model could not be run | Failure misc/control-processing-overload + Time to Wait, or misc/unspecified (`decision=fail_closed_llm_error`) | Reject #22 (congestion) or #111, then release |
//! | no policy configured | Failure misc/om-intervention (`decision=no_policy_configured`) | Reject #111, then release |
//!
//! # Transport
//!
//! See [`transport`]: SCTP by default and refused by name where there is none; `transport: "tcp"`
//! is a non-standard, length-prefixed lab framing labelled as such everywhere it appears.
//!
//! # Registration with security, and PDU sessions
//!
//! When the operator gives subscriber credentials (`subscribers`), a UE whose SUCI resolves to
//! one of them is taken through 5G-AKA, the security mode procedure and registration by Rust
//! ([`amf`]), and the model is asked exactly twice per UE: whether to admit the *authenticated*
//! subscriber (`ngap_registration_request`) and what to do with each PDU session it asks for
//! (`ngap_pdu_session_establishment_request`). With `user_plane_address`, an accepted session
//! gets a GTP-U tunnel on this server ([`upf`]) that answers ICMP echo for the addresses the
//! model chose. Without credentials the pre-security behaviour above is unchanged.

pub mod actions;
mod amf;
pub mod aper;
pub mod codec;
pub mod nas;
pub mod security;
pub mod snow3g;
pub mod sm;
pub mod subscribers;
pub mod suci;
pub mod transport;
pub mod upf;
pub mod zuc;

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::utils::WireFailure;

use actions::{
    NgapProtocol, NGAP_ERROR_INDICATION_EVENT, NGAP_INITIAL_UE_MESSAGE_EVENT, NGAP_NG_SETUP_EVENT,
    NGAP_UPLINK_NAS_EVENT,
};
use codec::{Cause, PduKind};
use subscribers::Credentials;
use transport::{MessageWriter, ReadOutcome, Transport};
use upf::UserPlane;

/// How long a new association may stay silent. TS 38.413 section 8.7.1 has the gNB send NG Setup
/// Request as soon as the TNL association is up; nothing legitimate precedes it.
const FIRST_MESSAGE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long an established association may stay silent. An hour, deliberately: N2 has no
/// application keepalive and an idle cell with no UEs is the normal case, so this must not be a
/// traffic timer. Over SCTP the kernel's own HEARTBEAT detects a dead peer long before this; over
/// the lab TCP framing nothing else would.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// Concurrent associations admitted.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What an association over [`MAX_CONNECTIONS`] is told: nothing. NGAP's only message a node may
/// send before NG Setup is Error Indication, and over SCTP it would need PPID 60 and a stream the
/// generic refusal path cannot set; over the lab transport it would need the length prefix. The
/// association is closed (an SCTP SHUTDOWN), which a gNB treats as a TNL failure and retries.
const CONNECTION_CAP_REFUSAL: &[u8] = &[];

/// UE contexts one association may hold. A gNB serving more is refused per UE with an Error
/// Indication (misc/control-processing-overload) rather than growing the table without bound.
pub const MAX_UE_CONTEXTS: usize = 4096;

/// NGAP AMF server.
pub struct NgapServer;

impl NgapServer {
    /// Spawn the AMF listener. Awaits readiness, so "this host has no SCTP" is a startup error.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        let transport = Transport::from_params(startup_params.as_ref())?;
        let listener = transport::bind_listener(listen_addr, transport).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "NGAP AMF listening on {} over {}",
            local_addr,
            transport.label()
        ));
        if transport == Transport::Tcp {
            Log::new(Some(&status_tx)).warn(
                "NGAP is running over TCP with a NetGet length prefix. This is NOT N2: TS 38.412 \
                 defines NGAP over SCTP only, and no real gNB will connect. Use it for local \
                 protocol work and nothing else.",
            );
        }

        let core = Arc::new(Core::from_params(startup_params.as_ref()).await?);
        if !core.credentials_empty() {
            Log::new(Some(&status_tx)).info(format!(
                "NGAP AMF holds credentials for {} subscriber(s): their UEs are authenticated \
                 with 5G-AKA and registered under NAS security (NIA2, {})",
                core.subscriber_count(),
                security::ciphering_name(core.ciphering)
            ));
        }
        if let Some(up) = core.user_plane.clone() {
            Log::new(Some(&status_tx)).info(format!(
                "NGAP AMF user plane (GTP-U) on {}, advertised as {}",
                up.local_addr()?,
                up.advertised()
            ));
            let st = status_tx.clone();
            app_state
                .spawn_server_task(server_id, async move { up.run(st).await })
                .await;
        }

        let protocol = Arc::new(NgapProtocol::new());
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "NGAP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        Log::new(Some(&status_tx)).info(format!(
                            "NGAP association {} from {} ({})",
                            connection_id,
                            remote_addr,
                            transport.as_str()
                        ));
                        register_connection(
                            &app_state,
                            server_id,
                            connection_id,
                            remote_addr,
                            transport,
                        )
                        .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        let conn = transport::Conn::new(stream, transport);
                        let llm = llm_client.clone();
                        let state = app_state.clone();
                        let status = status_tx.clone();
                        let protocol = protocol.clone();
                        let core = core.clone();
                        let owner = app_state.clone();
                        owner
                            .spawn_server_task(server_id, async move {
                                let _permit = permit;
                                if let Err(e) = run_session(
                                    conn,
                                    connection_id,
                                    server_id,
                                    remote_addr,
                                    llm,
                                    state.clone(),
                                    status.clone(),
                                    protocol,
                                    transport,
                                    core,
                                )
                                .await
                                {
                                    Log::new(Some(&status))
                                        .error(format!("NGAP association error: {e}"));
                                }
                                state
                                    .remove_peer_handle(server_id, connection_id.as_u32())
                                    .await;
                                state
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                Log::new(Some(&status))
                                    .info(format!("NGAP association {connection_id} closed"));
                                let _ = status.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept NGAP association: {e}"));
                        break;
                    }
                }
            }
        });
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
    transport: Transport,
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
                protocol_info: ProtocolConnectionInfo::new(json!({
                    "state": "awaiting NG Setup",
                    "transport": transport.label(),
                })),
            },
        )
        .await;
}

/// The NAS ciphering algorithm used when the operator names none: NEA0, so the protected NAS is
/// readable on the wire (integrity is always NIA2). Open5GS's AMF defaults the same way.
pub const DEFAULT_NAS_CIPHERING: &str = "nea0";

/// What every association of one AMF shares: the subscriber credentials, whose SQNs advance as
/// vectors are used, and the user plane.
pub(crate) struct Core {
    credentials: std::sync::Mutex<Credentials>,
    user_plane: Option<Arc<UserPlane>>,
    /// NEA0 or NEA2, the operator's preference. A UE without NEA2 gets NEA0.
    ciphering: u8,
}

impl Core {
    async fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Core> {
        let (subs, keys, ciphering, up) = match params {
            Some(p) => (
                p.get_optional_array("subscribers")?.cloned(),
                p.get_optional_array("suci_keys")?.cloned(),
                p.get_optional_string("nas_ciphering")?,
                p.get_optional_string("user_plane_address")?,
            ),
            None => (None, None, None, None),
        };
        let credentials = Credentials::from_params(subs.as_deref(), keys.as_deref())
            .map_err(|e| anyhow::anyhow!("NGAP startup parameter {e}"))?;
        let ciphering = match ciphering
            .as_deref()
            .unwrap_or(DEFAULT_NAS_CIPHERING)
            .to_ascii_lowercase()
            .as_str()
        {
            "nea0" => security::NEA0,
            "nea2" => security::NEA2,
            other => anyhow::bail!(
                "nas_ciphering {other:?} must be \"nea0\" or \"nea2\" (NEA1 and NEA3 are not \
                 implemented)"
            ),
        };
        let user_plane = match up {
            None => None,
            Some(raw) => {
                let raw = raw.trim();
                let addr: SocketAddr = match raw.parse::<SocketAddr>() {
                    Ok(a) => a,
                    Err(_) => SocketAddr::new(
                        raw.parse().map_err(|_| {
                            anyhow::anyhow!(
                                "user_plane_address {raw:?} must be an IP address, or IP:port"
                            )
                        })?,
                        crate::server::gtp::codec::GTPU_PORT,
                    ),
                };
                anyhow::ensure!(
                    !addr.ip().is_unspecified(),
                    "user_plane_address must be an address the gNB can reach, not {}",
                    addr.ip()
                );
                Some(UserPlane::bind(addr, addr.ip()).await?)
            }
        };
        Ok(Core {
            credentials: std::sync::Mutex::new(credentials),
            user_plane,
            ciphering,
        })
    }

    fn credentials(&self) -> std::sync::MutexGuard<'_, Credentials> {
        self.credentials.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn credentials_empty(&self) -> bool {
        self.credentials().is_empty()
    }

    fn subscriber_count(&self) -> usize {
        self.credentials().subscriber_count()
    }
}

/// One UE's context on this association.
struct Ue {
    ran_ue_ngap_id: u64,
    /// The 5GMM message type the UE opened with, so a fail-closed answer can be the matching
    /// reject.
    initial_nas: Option<u8>,
    /// The UE's first NAS message, kept until the security procedure starts (a UE that opens
    /// with an unknown 5G-GUTI is identified first, then authenticated from it).
    initial_nas_bytes: Vec<u8>,
    user_location: Value,
    /// Present once Rust took the UE into 5G-AKA; see [`amf`].
    sec: Option<Box<amf::UeSec>>,
}

struct Session {
    connection_id: ConnectionId,
    server_id: ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<NgapProtocol>,
    transport: Transport,
    writer: Arc<Mutex<MessageWriter>>,
    /// The gNB as it presented itself, once NG Setup succeeded.
    gnb: Option<Value>,
    ues: BTreeMap<u64, Ue>,
    next_amf_ue_ngap_id: u64,
    core: Arc<Core>,
    /// The first GUAMI and the PLMN support this AMF announced in its NG Setup Response, read
    /// back off its own octets: 5G-GUTIs are allocated under it.
    guami: Option<Value>,
    plmn_support: Vec<Value>,
}

/// One PDU a handler put on the wire, read back off its own octets.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sent {
    kind: PduKind,
    code: u8,
    amf_ue_ngap_id: Option<u64>,
}

#[derive(Debug, Clone)]
enum HandlerOutcome {
    NoPolicy,
    Failed(WireFailure),
    Ran {
        sent: Vec<Sent>,
        closed: bool,
        /// `(AMF UE NGAP ID, PDU session ID)` of every PDU session decision the model's actions
        /// carried out.
        pdu_answers: Vec<(u64, u8)>,
    },
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    conn: transport::Conn,
    connection_id: ConnectionId,
    server_id: ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<NgapProtocol>,
    transport: Transport,
    core: Arc<Core>,
) -> Result<()> {
    let mut reader = conn.reader();
    let writer = Arc::new(Mutex::new(conn.writer()));
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
        writer.clone(),
        status_tx.clone(),
    );
    let mut session = Session {
        connection_id,
        server_id,
        remote_addr,
        llm_client,
        app_state,
        status_tx,
        protocol,
        transport,
        writer,
        gnb: None,
        ues: BTreeMap::new(),
        next_amf_ue_ngap_id: 1,
        core,
        guami: None,
        plmn_support: Vec::new(),
    };

    let mut received_one = false;
    loop {
        // The deadline covers the read only; the model round-trip (and a manual rule parking
        // a decision for a human) happens after a whole message has arrived.
        let deadline = if received_one {
            IDLE_BETWEEN_MESSAGES_TIMEOUT
        } else {
            FIRST_MESSAGE_READ_TIMEOUT
        };
        match reader.next(deadline).await {
            ReadOutcome::Message(bytes) => {
                received_one = true;
                session
                    .app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        Some(bytes.len() as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
                if !session.dispatch(&bytes).await {
                    break;
                }
            }
            ReadOutcome::TooLarge(n) => {
                received_one = true;
                Log::new(Some(&session.status_tx)).warn(format!(
                    "NGAP message of {n} octets from {} exceeds {} (decision=refused_oversize)",
                    remote_addr,
                    codec::MAX_PDU_LEN
                ));
                session
                    .send_error_indication(
                        None,
                        None,
                        Cause::protocol(codec::PROTOCOL_TRANSFER_SYNTAX_ERROR),
                    )
                    .await;
                if transport == Transport::Tcp {
                    // The lab framing cannot skip a declared length safely.
                    break;
                }
            }
            ReadOutcome::TimedOut => {
                debug!("NGAP association {connection_id} idle past its deadline; closing");
                break;
            }
            ReadOutcome::Eof => break,
            ReadOutcome::Error(e) => {
                debug!("NGAP association {connection_id} read error: {e}");
                break;
            }
        }
    }
    session.writer.lock().await.close();
    Ok(())
}

impl Session {
    /// Handle one PDU. Returns `false` when the association must close.
    async fn dispatch(&mut self, bytes: &[u8]) -> bool {
        let pdu = match codec::decode_pdu(bytes) {
            Ok(p) => p,
            Err(e) => {
                // Refused before the model: 38.413 section 10.2, transfer syntax error.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP PDU from {} refused: {e} (decision=refused_malformed)",
                    self.remote_addr
                ));
                self.send_error_indication(None, None, e.cause).await;
                return true;
            }
        };
        debug!("NGAP {} from {}", pdu.label(), self.remote_addr);
        match (pdu.kind, pdu.procedure_code) {
            (PduKind::Initiating, codec::PROC_NG_SETUP) => self.on_ng_setup(&pdu).await,
            (PduKind::Initiating, codec::PROC_ERROR_INDICATION) => {
                self.on_error_indication(&pdu).await
            }
            (PduKind::Initiating, _) if self.gnb.is_none() => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {} from {} before NG Setup completed; refusing",
                    pdu.label(),
                    self.remote_addr
                ));
                self.send_error_indication(
                    None,
                    None,
                    Cause::protocol(codec::PROTOCOL_MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE),
                )
                .await;
                true
            }
            (PduKind::Initiating, codec::PROC_INITIAL_UE_MESSAGE) => self.on_initial_ue(&pdu).await,
            (PduKind::Initiating, codec::PROC_UPLINK_NAS_TRANSPORT) => {
                self.on_uplink_nas(&pdu).await
            }
            (PduKind::Initiating, codec::PROC_NG_RESET) => self.on_ng_reset(&pdu).await,
            (PduKind::Initiating, codec::PROC_UE_CONTEXT_RELEASE_REQUEST) => {
                self.on_release_request(&pdu).await
            }
            (PduKind::Successful | PduKind::Unsuccessful, codec::PROC_INITIAL_CONTEXT_SETUP) => {
                self.on_initial_context_setup_answer(&pdu).await
            }
            (PduKind::Successful, codec::PROC_PDU_SESSION_RESOURCE_SETUP) => {
                self.on_pdu_session_setup_response(&pdu).await
            }
            (PduKind::Successful, codec::PROC_UE_CONTEXT_RELEASE) => {
                self.on_release_complete(&pdu).await
            }
            (PduKind::Successful, codec::PROC_NG_RESET) => {
                let n = self.ues.len();
                self.clear_ues(None);
                self.set_connection_state().await;
                info!(
                    "NGAP NG Reset acknowledged by {}; {n} UE contexts cleared",
                    self.remote_addr
                );
                true
            }
            (PduKind::Initiating, _) => {
                // 38.413 section 10.3.4.1: a procedure this AMF does not implement. A reject or
                // notify criticality earns an Error Indication; ignore earns nothing.
                let cause = match pdu.criticality {
                    codec::Criticality::Reject => {
                        Some(codec::PROTOCOL_ABSTRACT_SYNTAX_ERROR_REJECT)
                    }
                    codec::Criticality::Notify => Some(2),
                    codec::Criticality::Ignore => None,
                };
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {} from {} is not implemented by NetGet's AMF",
                    pdu.label(),
                    self.remote_addr
                ));
                if let Some(c) = cause {
                    self.send_error_indication(None, None, Cause::protocol(c))
                        .await;
                }
                true
            }
            _ => {
                debug!(
                    "NGAP {} from {} answers nothing NetGet asked; ignored",
                    pdu.label(),
                    self.remote_addr
                );
                true
            }
        }
    }

    // ------------------------------------------------------------------------

    async fn on_ng_setup(&mut self, pdu: &codec::Pdu) -> bool {
        let info = match codec::parse_ng_setup_request(pdu) {
            Ok(v) => v,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP NG Setup Request from {} refused before the model: {e}",
                    self.remote_addr
                ));
                self.send_encoded("NG Setup Failure", codec::ng_setup_failure(&e.cause, None))
                    .await;
                return true;
            }
        };
        let mut data = info.clone();
        data["transport"] = json!(self.transport.label());
        let event = Event::new(&NGAP_NG_SETUP_EVENT, data);
        let event_id = event.event_type.id.clone();
        match self.call_llm_and_send(&event).await {
            HandlerOutcome::Ran {
                ref sent, closed, ..
            } if sent
                .iter()
                .any(|s| s.kind == PduKind::Successful && s.code == codec::PROC_NG_SETUP) =>
            {
                self.gnb = Some(json!({
                    "global_ran_node_id": info["global_ran_node_id"],
                    "ran_node_name": info["ran_node_name"],
                }));
                self.set_connection_state().await;
                Log::new(Some(&self.status_tx)).info(format!(
                    "NGAP NG Setup accepted for {} ({})",
                    self.remote_addr,
                    info["ran_node_name"].as_str().unwrap_or("unnamed gNB")
                ));
                !closed
            }
            HandlerOutcome::Ran {
                ref sent, closed, ..
            } if sent
                .iter()
                .any(|s| s.kind == PduKind::Unsuccessful && s.code == codec::PROC_NG_SETUP) =>
            {
                info!(
                    "NGAP {event_id} decision=model_reject peer={}",
                    self.remote_addr
                );
                !closed
            }
            HandlerOutcome::Ran { closed, .. } => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} produced no NG Setup answer for {} (decision=model_silent); \
                     refusing with misc/unspecified",
                    self.remote_addr
                ));
                self.send_encoded(
                    "NG Setup Failure",
                    codec::ng_setup_failure(&Cause::misc(codec::MISC_UNSPECIFIED), None),
                )
                .await;
                !closed
            }
            HandlerOutcome::Failed(failure) => {
                let (cause, wait) = if failure.is_overloaded() {
                    (Cause::misc(codec::MISC_CONTROL_PROCESSING_OVERLOAD), "v5s")
                } else {
                    (Cause::misc(codec::MISC_UNSPECIFIED), "v10s")
                };
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} could not be evaluated for {} \
                     (decision=fail_closed_llm_error, {}); refusing with {}",
                    self.remote_addr,
                    failure_category(failure),
                    cause.label()
                ));
                self.send_encoded(
                    "NG Setup Failure",
                    codec::ng_setup_failure(&cause, Some(wait)),
                )
                .await;
                true
            }
            HandlerOutcome::NoPolicy => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} refused for {} (decision=no_policy_configured): this AMF has \
                     no instruction and no event handler, so nothing decides which gNBs may set \
                     up N2. Give the server an instruction, or a handler for {event_id}.",
                    self.remote_addr
                ));
                self.send_encoded(
                    "NG Setup Failure",
                    codec::ng_setup_failure(&Cause::misc(codec::MISC_OM_INTERVENTION), None),
                )
                .await;
                true
            }
        }
    }

    async fn on_initial_ue(&mut self, pdu: &codec::Pdu) -> bool {
        let ue = match codec::parse_initial_ue_message(pdu) {
            Ok(u) => u,
            Err(e) => {
                let ran = pdu
                    .ie(codec::IE_RAN_UE_NGAP_ID)
                    .and_then(|ie| codec::decode_ran_ue_ngap_id(ie).ok());
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP Initial UE Message from {} refused before the model: {e}",
                    self.remote_addr
                ));
                self.send_error_indication(None, ran, e.cause).await;
                return true;
            }
        };
        if self.ues.len() >= MAX_UE_CONTEXTS {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP Initial UE Message from {} refused: {MAX_UE_CONTEXTS} UE contexts already \
                 held on this association (decision=fail_closed_ue_cap)",
                self.remote_addr
            ));
            self.send_error_indication(
                None,
                Some(ue.ran_ue_ngap_id),
                Cause::misc(codec::MISC_CONTROL_PROCESSING_OVERLOAD),
            )
            .await;
            return true;
        }
        let amf_id = self.next_amf_ue_ngap_id;
        self.next_amf_ue_ngap_id = (self.next_amf_ue_ngap_id + 1) % (codec::MAX_AMF_UE_NGAP_ID + 1);
        let initial_nas = nas::message_type(&ue.nas);
        self.ues.insert(
            amf_id,
            Ue {
                ran_ue_ngap_id: ue.ran_ue_ngap_id,
                initial_nas,
                initial_nas_bytes: ue.nas.clone(),
                user_location: ue.user_location.clone(),
                sec: None,
            },
        );
        self.set_connection_state().await;
        // A Registration Request from a subscriber this AMF holds credentials for is
        // authenticated by Rust; the model is asked once the UE has proven who it is.
        if initial_nas == Some(nas::REGISTRATION_REQUEST) && self.try_start_aka(amf_id).await {
            return true;
        }
        let data = json!({
            "amf_ue_ngap_id": amf_id,
            "ran_ue_ngap_id": ue.ran_ue_ngap_id,
            "nas": nas::decode(&ue.nas),
            "user_location": ue.user_location,
            "rrc_establishment_cause": ue.rrc_establishment_cause,
            "five_g_s_tmsi": ue.five_g_s_tmsi,
            "uninterpreted_ies": ue.uninterpreted,
            "gnb": self.gnb.clone(),
            "transport": self.transport.label(),
        });
        let event = Event::new(&NGAP_INITIAL_UE_MESSAGE_EVENT, data);
        let outcome = self.call_llm_and_send(&event).await;
        self.settle_ue_outcome(&event.event_type.id, amf_id, outcome, true)
            .await
    }

    async fn on_uplink_nas(&mut self, pdu: &codec::Pdu) -> bool {
        let t = match codec::parse_nas_transport(pdu) {
            Ok(t) => t,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP Uplink NAS Transport from {} refused before the model: {e}",
                    self.remote_addr
                ));
                self.send_error_indication(None, None, e.cause).await;
                return true;
            }
        };
        match self.ues.get(&t.amf_ue_ngap_id) {
            None => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP Uplink NAS Transport from {} names unknown AMF UE NGAP ID {}",
                    self.remote_addr, t.amf_ue_ngap_id
                ));
                self.send_error_indication(
                    Some(t.amf_ue_ngap_id),
                    Some(t.ran_ue_ngap_id),
                    Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID),
                )
                .await;
                return true;
            }
            Some(ue) if ue.ran_ue_ngap_id != t.ran_ue_ngap_id => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP Uplink NAS Transport from {} pairs AMF UE NGAP ID {} with RAN UE NGAP \
                     ID {} (the context holds {})",
                    self.remote_addr, t.amf_ue_ngap_id, t.ran_ue_ngap_id, ue.ran_ue_ngap_id
                ));
                self.send_error_indication(
                    Some(t.amf_ue_ngap_id),
                    Some(t.ran_ue_ngap_id),
                    Cause::radio(codec::RADIO_INCONSISTENT_REMOTE_UE_NGAP_ID),
                )
                .await;
                return true;
            }
            Some(_) => {}
        }
        if let Some(uli) = &t.user_location {
            if let Some(ue) = self.ues.get_mut(&t.amf_ue_ngap_id) {
                ue.user_location = uli.clone();
            }
        }
        // A UE in Rust's security procedure is handled there, never by the model per message.
        if self
            .ues
            .get(&t.amf_ue_ngap_id)
            .map(|u| u.sec.is_some())
            .unwrap_or(false)
        {
            return self.on_secured_ue_nas(t.amf_ue_ngap_id, &t.nas).await;
        }
        // A UE identified only now (it opened with a 5G-GUTI this AMF never issued) whose SUCI
        // names a subscriber with credentials is authenticated from here.
        if nas::message_type(&t.nas) == Some(nas::IDENTITY_RESPONSE)
            && self
                .try_start_aka_from_identity(t.amf_ue_ngap_id, &t.nas)
                .await
        {
            return true;
        }
        let data = json!({
            "amf_ue_ngap_id": t.amf_ue_ngap_id,
            "ran_ue_ngap_id": t.ran_ue_ngap_id,
            "nas": nas::decode(&t.nas),
            "user_location": t.user_location,
            "uninterpreted_ies": t.uninterpreted,
            "transport": self.transport.label(),
        });
        let event = Event::new(&NGAP_UPLINK_NAS_EVENT, data);
        let outcome = self.call_llm_and_send(&event).await;
        self.settle_ue_outcome(&event.event_type.id, t.amf_ue_ngap_id, outcome, false)
            .await
    }

    /// Apply the fail-closed rule to a UE-associated event. `must_answer` is true for an Initial
    /// UE Message, where silence leaves a UE waiting on an admission decision.
    async fn settle_ue_outcome(
        &mut self,
        event_id: &str,
        amf_id: u64,
        outcome: HandlerOutcome,
        must_answer: bool,
    ) -> bool {
        match outcome {
            HandlerOutcome::Ran {
                ref sent, closed, ..
            } if sent.iter().any(|s| s.amf_ue_ngap_id == Some(amf_id)) => !closed,
            HandlerOutcome::Ran { closed, .. } if !must_answer => {
                debug!(
                    "NGAP {event_id} decision=model_silent amf_ue_ngap_id={amf_id}: nothing sent"
                );
                !closed
            }
            HandlerOutcome::Ran { closed, .. } => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} produced no answer for UE {amf_id} (decision=model_silent); \
                     rejecting"
                ));
                self.fail_closed_ue(amf_id, None).await;
                !closed
            }
            HandlerOutcome::Failed(failure) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} could not be evaluated for UE {amf_id} \
                     (decision=fail_closed_llm_error, {}); rejecting",
                    failure_category(failure)
                ));
                self.fail_closed_ue(amf_id, Some(failure)).await;
                true
            }
            HandlerOutcome::NoPolicy => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} for UE {amf_id} (decision=no_policy_configured): nothing \
                     decides what this AMF tells UEs; rejecting"
                ));
                self.fail_closed_ue(amf_id, None).await;
                true
            }
        }
    }

    /// Refuse a UE with the reject that matches what it asked for, then release its context. A
    /// UE is never told it is registered because nothing answered.
    async fn fail_closed_ue(&mut self, amf_id: u64, failure: Option<WireFailure>) {
        let Some(ue) = self.ues.get(&amf_id) else {
            return;
        };
        let ran = ue.ran_ue_ngap_id;
        let overloaded = failure.map(|f| f.is_overloaded()).unwrap_or(false);
        let nas_cause = if overloaded {
            nas::CAUSE_CONGESTION
        } else {
            nas::CAUSE_PROTOCOL_ERROR_UNSPECIFIED
        };
        let reject = match ue.initial_nas {
            Some(nas::REGISTRATION_REQUEST) => Some("registration_reject"),
            Some(nas::SERVICE_REQUEST) => Some("service_reject"),
            _ => None,
        };
        if let Some(message) = reject {
            let pdu = nas::encode(
                &json!({"message": message, "cause": nas_cause}),
                nas::DOWNLINK_MESSAGES,
            )
            .map_err(codec::EncodeError)
            .and_then(|n| codec::downlink_nas_transport(amf_id, ran, &n));
            self.send_encoded("Downlink NAS Transport (reject)", pdu)
                .await;
        }
        let cause = if overloaded {
            Cause::misc(codec::MISC_CONTROL_PROCESSING_OVERLOAD)
        } else {
            Cause::nas(codec::NAS_UNSPECIFIED)
        };
        self.send_encoded(
            "UE Context Release Command",
            codec::ue_context_release_command(amf_id, Some(ran), &cause),
        )
        .await;
    }

    async fn on_error_indication(&mut self, pdu: &codec::Pdu) -> bool {
        let mut data = match codec::parse_cause_message(pdu) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "NGAP Error Indication from {} did not decode: {e}",
                    self.remote_addr
                );
                return true;
            }
        };
        Log::new(Some(&self.status_tx)).warn(format!(
            "NGAP Error Indication from {}: {}",
            self.remote_addr,
            data.get("cause")
                .map(|c| c.to_string())
                .unwrap_or_else(|| "no cause".into())
        ));
        data["transport"] = json!(self.transport.label());
        let event = Event::new(&NGAP_ERROR_INDICATION_EVENT, data);
        match self.call_llm_and_send(&event).await {
            HandlerOutcome::Failed(f) => warn!(
                "NGAP ngap_error_indication decision=fail_closed_llm_error ({}); nothing sent — \
                 an Error Indication needs no answer",
                failure_category(f)
            ),
            HandlerOutcome::Ran { closed: true, .. } => return false,
            _ => {}
        }
        true
    }

    async fn on_ng_reset(&mut self, pdu: &codec::Pdu) -> bool {
        let mut budget = codec::Budget::default();
        let partial = match pdu
            .require(codec::IE_RESET_TYPE)
            .and_then(|ie| codec::decode_reset_type(ie, &mut budget))
        {
            Ok(p) => p,
            Err(e) => {
                self.send_error_indication(None, None, e.cause).await;
                return true;
            }
        };
        // Resetting is the safe direction, so it needs no policy: 38.413 section 8.7.4.
        let cleared = match &partial {
            None => {
                let n = self.ues.len();
                self.clear_ues(None);
                n
            }
            Some(items) => {
                let before = self.ues.len();
                for (amf, ran) in items {
                    match (amf, ran) {
                        (Some(a), _) => self.clear_ues(Some(&|id, _| id == *a)),
                        (None, Some(r)) => {
                            self.clear_ues(Some(&|_, u: &Ue| u.ran_ue_ngap_id == *r))
                        }
                        (None, None) => {}
                    }
                }
                before - self.ues.len()
            }
        };
        self.set_connection_state().await;
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP NG Reset from {}: {cleared} UE contexts cleared",
            self.remote_addr
        ));
        self.send_encoded(
            "NG Reset Acknowledge",
            codec::ng_reset_acknowledge(partial.as_deref()),
        )
        .await;
        true
    }

    async fn on_release_complete(&mut self, pdu: &codec::Pdu) -> bool {
        if let Some(amf) = pdu
            .ie(codec::IE_AMF_UE_NGAP_ID)
            .and_then(|ie| codec::decode_amf_ue_ngap_id(ie).ok())
        {
            if self.ues.contains_key(&amf) {
                self.clear_ues(Some(&|id, _| id == amf));
                info!("NGAP UE context {amf} released by {}", self.remote_addr);
                self.set_connection_state().await;
            }
        }
        true
    }

    /// Drop UE contexts — every one, or those `which` selects — and their user-plane sessions.
    fn clear_ues(&mut self, which: Option<&dyn Fn(u64, &Ue) -> bool>) {
        let gone: Vec<u64> = self
            .ues
            .iter()
            .filter(|(id, u)| which.map(|f| f(**id, u)).unwrap_or(true))
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            if let Some(ue) = self.ues.remove(&id) {
                self.release_user_plane(&ue);
            }
        }
    }

    // ------------------------------------------------------------------------

    async fn call_llm_and_send(&mut self, event: &Event) -> HandlerOutcome {
        if !operator_wants_dynamic(&self.app_state, self.server_id, &event.event_type.id).await {
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
            Ok(r) => r,
            Err(e) => {
                let failure = WireFailure::classify(&e);
                // The whole error goes to the operator; the peer only ever gets a Cause.
                Log::new(Some(&self.status_tx)).error(format!(
                    "NGAP {} decision=fail_closed_llm_error category={:?} peer={}: {:#}",
                    event.event_type.id, failure, self.remote_addr, e
                ));
                return HandlerOutcome::Failed(failure);
            }
        };
        let mut sent = Vec::new();
        let mut closed = false;
        let mut pdu_answers = Vec::new();
        let mut queue: Vec<ActionResult> = result.protocol_results;
        queue.reverse();
        while let Some(item) = queue.pop() {
            match item {
                ActionResult::Multiple(inner) => {
                    for nested in inner.into_iter().rev() {
                        queue.push(nested);
                    }
                }
                ActionResult::Custom { name, data } => {
                    // Decisions that need this session's state (keys, counts, the user plane):
                    // carried out here, or refused with the reason logged.
                    if let Some(s) = self.apply_decision(&name, &data, &mut pdu_answers).await {
                        sent.push(s);
                    }
                }
                ActionResult::Output(bytes) => {
                    // The model writes NAS as plain 5GMM; a UE under NAS security gets it
                    // protected with its context.
                    let bytes = self.protect_model_downlink(bytes);
                    if let Ok(p) = codec::decode_pdu(&bytes) {
                        if p.kind == PduKind::Successful && p.procedure_code == codec::PROC_NG_SETUP
                        {
                            self.remember_ng_setup_response(&p);
                        }
                        sent.push(Sent {
                            kind: p.kind,
                            code: p.procedure_code,
                            amf_ue_ngap_id: p
                                .ie(codec::IE_AMF_UE_NGAP_ID)
                                .and_then(|ie| codec::decode_amf_ue_ngap_id(ie).ok())
                                .or_else(|| {
                                    p.ie(codec::IE_UE_NGAP_IDS).and_then(|ie| {
                                        codec::decode_ue_ngap_ids(ie, &mut codec::Budget::default())
                                            .ok()
                                            .map(|(a, _)| a)
                                    })
                                }),
                        });
                    }
                    self.send(bytes).await;
                }
                ActionResult::CloseConnection => {
                    self.writer.lock().await.close();
                    closed = true;
                }
                ActionResult::WaitForMore | ActionResult::NoAction => {}
            }
        }
        HandlerOutcome::Ran {
            sent,
            closed,
            pdu_answers,
        }
    }

    /// Keep the GUAMI and PLMN support this AMF announced, to allocate 5G-GUTIs under.
    fn remember_ng_setup_response(&mut self, p: &codec::Pdu) {
        let mut budget = codec::Budget::default();
        if let Some(Ok(list)) = p
            .ie(codec::IE_SERVED_GUAMI_LIST)
            .map(|ie| codec::decode_served_guami_list(ie, &mut budget))
        {
            self.guami = list.into_iter().next();
        }
        if let Some(Ok(list)) = p
            .ie(codec::IE_PLMN_SUPPORT_LIST)
            .map(|ie| codec::decode_plmn_support_list(ie, &mut budget))
        {
            self.plmn_support = list;
        }
    }

    async fn send(&self, bytes: Vec<u8>) {
        let ok = self.writer.lock().await.send(&bytes).await.is_ok();
        if !ok {
            debug!(
                "NGAP write failed on association {}; peer has gone",
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

    async fn send_encoded(&self, what: &str, encoded: codec::EncodeResult<Vec<u8>>) {
        match encoded {
            Ok(bytes) => self.send(bytes).await,
            Err(e) => error!(
                "NGAP decision=fail_closed_encode: refusing to send {what} to {}: {e}",
                self.remote_addr
            ),
        }
    }

    async fn send_error_indication(&self, amf: Option<u64>, ran: Option<u64>, cause: Cause) {
        Log::new(Some(&self.status_tx)).warn(format!(
            "NGAP Error Indication ({}) to {}",
            cause.label(),
            self.remote_addr
        ));
        self.send_encoded(
            "Error Indication",
            codec::error_indication(amf, ran, Some(&cause)),
        )
        .await;
    }

    async fn set_connection_state(&self) {
        let value = json!({
            "state": if self.gnb.is_some() { "NG Setup complete" } else { "awaiting NG Setup" },
            "gnb": self.gnb,
            "ue_contexts": self.ues.len(),
            "transport": self.transport.label(),
        });
        let connection_id = self.connection_id;
        self.app_state
            .with_server_mut(self.server_id, |server| {
                if let Some(c) = server.connections.get_mut(&connection_id) {
                    c.protocol_info =
                        crate::state::server::ProtocolConnectionInfo::new(value.clone());
                }
            })
            .await;
    }
}

fn failure_category(failure: WireFailure) -> &'static str {
    if failure.is_overloaded() {
        "resource"
    } else {
        "unavailable"
    }
}

/// True when the operator opted into dynamic handling — an instruction or a matching handler.
/// `false` is a refusal for this AMF: who may join a 5G core has no configuration-free answer.
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
