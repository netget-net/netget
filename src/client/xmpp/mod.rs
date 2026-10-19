//! XMPP (Jabber) client implementation
pub mod actions;

pub use actions::XmppClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::client::xmpp::actions::{
    XMPP_CLIENT_CONNECTED_EVENT, XMPP_CLIENT_MESSAGE_RECEIVED_EVENT,
    XMPP_CLIENT_PRESENCE_RECEIVED_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::protocol::StartupParams;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

use crate::console_error;
use futures::StreamExt;
use sasl::common::ChannelBinding;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_xmpp::connect::{DnsConfig, ServerConnector, StartTlsServerConnector};
use tokio_xmpp::jid::Jid;
use tokio_xmpp::xmlstream::{PendingFeaturesRecv, Timeouts};
use tokio_xmpp::{Client as XmppClient, Event as XmppEvent};
use xmpp_parsers::{
    message::{Lang, Message, MessageType},
    presence::{Presence, Show as PresenceShow, Type as PresenceType},
};

/// Per-client data for LLM handling.
///
/// There used to be an `Idle`/`Processing`/`Accumulating` machine with a `queued_events`
/// list here. The event loop awaited every model call inline, so the machine was always
/// `Idle` when examined and nothing was ever queued; meanwhile the loop stopped polling the
/// stream and stopped writing the model's own stanzas until the call ended. Stanzas now go to
/// the answering task over a queue ([`EVENT_QUEUE`]).
struct ClientData {
    memory: String,
}

/// How many incoming stanzas may wait while the model answers an earlier one; past it the
/// event loop stops taking stanzas from tokio-xmpp, which holds them, and TCP the server.
const EVENT_QUEUE: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// How long `connect()` waits for the server to accept the session when the
/// `session_timeout_secs` startup parameter is not given.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest accepted `session_timeout_secs`.
pub const MAX_SESSION_TIMEOUT_SECS: u64 = 600;

/// XMPP's client-to-server port (RFC 6120 §14.7), used when `remote_addr` names no port.
pub const XMPP_CLIENT_PORT: u16 = 5222;

/// How long the event loop lets a stanza write or the orderly stream close run once the
/// session has been ended. Both wait on a peer that may never answer.
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// tokio-xmpp's STARTTLS connector, refusing to dial once the client has ended.
///
/// tokio-xmpp runs its connect-and-login loop in a task it spawns itself, retries every failed
/// attempt with a backoff (1s doubling to 30s) until a login succeeds, and is not stopped by
/// dropping the `Client`. Every attempt starts with [`ServerConnector::connect`], so this is the
/// one place a dial can be refused. Once `ended` is cancelled - the session timed out, an
/// injected or model-produced `disconnect`, the client stopped, or the event loop gone - an
/// attempt in progress is dropped (its socket with it) and every later one waits forever
/// without dialling. Returning an error instead would make the library log a failure and
/// retry every 30 seconds for the life of the process; waiting leaves one idle task, holding no
/// socket and no timer.
///
/// The cancellation covers the transport (TCP connect, stream header, STARTTLS, TLS). An attempt
/// that is already past it - in SASL or resource binding - runs to its end; if it then succeeds,
/// tokio-xmpp finds the client gone and closes that stream itself.
#[derive(Debug, Clone)]
struct EndableConnector {
    inner: StartTlsServerConnector,
    ended: CancellationToken,
    client_id: ClientId,
}

/// What [`ServerConnector::connect`] returns.
type ConnectResult<S> =
    std::result::Result<(PendingFeaturesRecv<S>, ChannelBinding), tokio_xmpp::Error>;

impl ServerConnector for EndableConnector {
    type Stream = <StartTlsServerConnector as ServerConnector>::Stream;

    async fn connect(
        &self,
        jid: &Jid,
        ns: &'static str,
        timeouts: Timeouts,
    ) -> ConnectResult<Self::Stream> {
        tokio::select! {
            biased;
            _ = self.ended.cancelled() => {
                debug!(
                    "XMPP client {} has ended; refusing tokio-xmpp's connection attempt",
                    self.client_id
                );
                return std::future::pending().await;
            }
            result = self.inner.connect(jid, ns, timeouts) => result,
        }
    }
}

/// The socket address the XMPP client connects to, taken from `remote_addr` alone.
///
/// Accepts `IP:port`, `[IPv6]:port`, a bare IP, `host:port` or a bare host; a missing port
/// is [`XMPP_CLIENT_PORT`]. A host name is resolved by the system resolver as an ordinary
/// address lookup. The JID plays no part: no SRV record is queried and the JID's domain is
/// never resolved, so the client connects where it was pointed or not at all.
///
/// An empty `remote_addr` is refused, and so is one containing `@`, which is an account
/// rather than an address; that error does not echo the value, since it may hold a password.
pub async fn resolve_target(remote_addr: &str) -> Result<SocketAddr> {
    let addr = remote_addr.trim();
    if addr.is_empty() {
        anyhow::bail!(
            "the XMPP client needs the server's address as remote_addr (\"host:port\", e.g. \
             \"127.0.0.1:5222\"); it does not look a server up from the JID's domain"
        );
    }
    if addr.contains('@') {
        anyhow::bail!(
            "remote_addr must be the XMPP server's address (\"host:port\"), not an account: \
             pass the account as the 'jid' and 'password' startup parameters"
        );
    }
    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Ok(socket);
    }
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, XMPP_CLIENT_PORT));
    }
    let (host, port) = match addr.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("remote_addr {:?} has an unusable port", addr))?;
            (host, port)
        }
        None => (addr, XMPP_CLIENT_PORT),
    };
    if host.is_empty() || host.contains(':') {
        anyhow::bail!(
            "remote_addr {:?} is not \"host:port\" (e.g. \"127.0.0.1:5222\")",
            addr
        );
    }
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("could not resolve XMPP server host {:?}", host))?
        .next()
        .with_context(|| format!("XMPP server host {:?} resolved to no address", host))
}

/// XMPP client that connects to an XMPP/Jabber server
pub struct XmppClientConnection;

impl XmppClientConnection {
    /// Connect to the XMPP server at `remote_addr` and run the session until it ends.
    ///
    /// Returns only once the server has accepted the session - tokio-xmpp's `Online` event,
    /// which follows the TCP connect, STARTTLS, SASL authentication and resource binding - or
    /// with `Err` when that does not happen within the session timeout. The generic startup
    /// path marks a client `Connected` as soon as this returns `Ok`, so returning earlier
    /// would report a session that does not exist.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        let (jid, password) = Self::credentials(startup_params.as_ref())?;
        let session_timeout = Self::session_timeout(startup_params.as_ref())?;
        let target = resolve_target(&remote_addr).await?;

        info!(
            "XMPP client {} connecting as {} to {}",
            client_id, jid, target
        );
        let _ = status_tx.send(format!(
            "[CLIENT] XMPP client {} connecting to {} as {}...",
            client_id, target, jid
        ));

        // Cancelled when the client ends, by whichever path ends it: the session timeout or a
        // dropped `connect()` (the guard below), an injected or model-produced `disconnect`
        // (`end_session`), the stream ending, or the event loop task being aborted or finishing
        // (its own guard). The event loop closes the stream on it, and the connector refuses
        // tokio-xmpp's reconnect attempts after it.
        let ended = CancellationToken::new();

        // `DnsConfig::Addr` is a plain TCP connect to exactly this socket address: no SRV
        // lookup and no resolution of the JID's domain, which only names the account and the
        // stream's `to`.
        let mut xmpp_client = XmppClient::new_with_connector(
            jid.clone(),
            password,
            EndableConnector {
                inner: StartTlsServerConnector::from(DnsConfig::addr(&target.to_string())),
                ended: ended.clone(),
                client_id,
            },
            Timeouts::default(),
        );

        // Store JID in app state
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("jid".to_string(), serde_json::json!(jid.to_string()));
            })
            .await;

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
        }));

        let protocol = Arc::new(crate::client::xmpp::actions::XmppClientProtocol::new());

        // Create channel for sending stanzas to the event loop
        let (stanza_tx, mut stanza_rx) = mpsc::unbounded_channel::<StanzaRequest>();
        let stanza_tx = Arc::new(stanza_tx);

        // The event loop answers this exactly once: the bound JID on the first `Online`, or
        // why the stream ended before one.
        let (session_tx, session_rx) =
            tokio::sync::oneshot::channel::<std::result::Result<Jid, String>>();

        // Command channel for injected actions (the dashboard's [ send ]). Registered before
        // the session is up, so [ send ] and `disconnect` are reachable while it is pending,
        // and before the connected-event LLM call, which a manual `*` rule can park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_stanza_tx = stanza_tx.clone();
        let cmd_state = app_state.clone();
        let cmd_status_tx = status_tx.clone();
        let cmd_ended = ended.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_stanza_tx,
                cmd_ended,
                client_id,
                cmd_state,
                cmd_status_tx,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // The answering task: the event loop hands it every stanza the model is asked about,
        // and it answers them in order - one per call, or with batching on everything waiting
        // in one call. Running it apart from the event loop keeps the loop polling the stream
        // and writing the model's stanzas while a call is in flight.
        let (event_tx, mut event_rx) = mpsc::channel::<Event>(EVENT_QUEUE);
        let answer_llm = llm_client.clone();
        let answer_state = app_state.clone();
        let answer_status_tx = status_tx.clone();
        let answer_protocol = protocol.clone();
        let answer_stanza_tx = stanza_tx.clone();
        let answer_data = client_data.clone();
        let answer_ended = ended.clone();
        app_state
            .spawn_client_task(client_id, async move {
                while let Some(event) = event_rx.recv().await {
                    let mut events = vec![event];
                    if answer_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                    {
                        while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                            match event_rx.try_recv() {
                                Ok(more) => events.push(more),
                                Err(_) => break,
                            }
                        }
                    }
                    // A session the model has ended asks it nothing more.
                    if answer_ended.is_cancelled() {
                        break;
                    }
                    Self::answer_events(
                        &events,
                        &answer_llm,
                        &answer_state,
                        client_id,
                        &answer_data,
                        answer_protocol.clone(),
                        answer_stanza_tx.clone(),
                        &answer_status_tx,
                        &answer_ended,
                    )
                    .await;
                }
            })
            .await;

        // Spawn event loop that handles both sending and receiving
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let loop_state = app_state.clone();
        let loop_status_tx = status_tx.clone();
        let loop_ended = ended.clone();
        let task_handle = tokio::spawn(async move {
            let app_state = loop_state;
            let status_tx = loop_status_tx;
            let ended = loop_ended;
            // Aborting this task (`remove_client`) drops the guard, which ends the client and
            // so stops tokio-xmpp dialling, even though the code below never runs.
            let _end_on_drop = ended.clone().drop_guard();
            let mut session_tx = Some(session_tx);
            let end_reason: &'static str = loop {
                tokio::select! {
                    // Stanzas first, then the end of the session: actions are queued in the
                    // order they were produced, so a `send_message` the model put before its
                    // `disconnect` is written before the stream closes.
                    biased;
                    // Handle outgoing stanzas
                    Some(request) = stanza_rx.recv() => {
                        // `send_stanza` resolves only once the stanza has been written to the
                        // XMPP transport, so an injected send can be reported truthfully
                        // rather than as "handed to a channel". It waits for a session that
                        // may never come, so once the client has ended it gets
                        // `STREAM_CLOSE_TIMEOUT` and no more.
                        let result = tokio::select! {
                            result = xmpp_client.send_stanza(request.stanza) => result
                                .map(|_token| ())
                                .map_err(|e| e.to_string()),
                            _ = async {
                                ended.cancelled().await;
                                tokio::time::sleep(STREAM_CLOSE_TIMEOUT).await;
                            } => Err(
                                "the client ended before the stanza could be written".to_string()
                            ),
                        };
                        if let Err(e) = &result {
                            console_error!(status_tx, "Failed to send XMPP stanza: {}", e);
                        }
                        if let Some(ack) = request.ack {
                            let _ = ack.send(result);
                        }
                    }
                    // Close the stream once the client has ended.
                    _ = ended.cancelled() => {
                        info!("XMPP client {} closing the stream on request", client_id);
                        break "the client was closed";
                    }
                    // Handle incoming events. Matched in the handler rather than the pattern: a pattern mismatch only
                    // disables the branch, and the select would then wait on the others for
                    // ever with the stream already gone.
                    next_event = xmpp_client.next() => {
                let Some(xmpp_event) = next_event else {
                    info!("XMPP client {} connection closed", client_id);
                    break "the XMPP stream ended";
                };
                trace!("XMPP client {} received event: {:?}", client_id, xmpp_event);

                // `Online` is stream lifecycle, not a stanza: it is acted on here, at once,
                // rather than queued behind an LLM call.
                let xmpp_event = match xmpp_event {
                    XmppEvent::Online { bound_jid, resumed } => {
                        info!(
                            "XMPP client {} online as {} (resumed={})",
                            client_id, bound_jid, resumed
                        );
                        let bound = bound_jid.to_string();
                        app_state
                            .with_client_mut(client_id, |client| {
                                client.set_protocol_field(
                                    "bound_jid".to_string(),
                                    serde_json::json!(bound),
                                );
                            })
                            .await;
                        // Neither the first `Online` nor a later one (tokio-xmpp's own
                        // reconnect to the same address) comes before the server has accepted
                        // the session, which is what `Connected` means.
                        app_state
                            .update_client_status(client_id, ClientStatus::Connected)
                            .await;
                        let _ = status_tx.send(format!(
                            "[CLIENT] XMPP client {} online as {}",
                            client_id, bound_jid
                        ));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        // The first `Online` releases `connect()`.
                        if let Some(tx) = session_tx.take() {
                            let _ = tx.send(Ok(bound_jid));
                        }
                        continue;
                    }
                    other => other,
                };

                // To the answering task. Waiting for room holds the stream (tokio-xmpp keeps
                // what it has not been asked for), but not the end of the session.
                if let Some(event) = Self::event_of(xmpp_event, client_id) {
                    tokio::select! {
                        sent = event_tx.send(event) => {
                            if sent.is_err() {
                                break "the answering task ended";
                            }
                        }
                        _ = ended.cancelled() => {
                            info!("XMPP client {} closing the stream on request", client_id);
                            break "the client was closed";
                        }
                    }
                }
                    }
                }
            };

            // Every exit path lands here. The client has ended whichever way it ended, so
            // tokio-xmpp may dial no more. Then drop the command handle so the dashboard stops
            // offering [ send ] on a dead connection, which also ends `command_loop`. Both are
            // done before the stream shutdown below, which waits on a peer that may be gone.
            ended.cancel();
            app_state.remove_client_handle(client_id).await;
            match session_tx.take() {
                // The session was never established. `connect()` is still waiting and turns
                // this into its `Err`, which is what sets the client's status, so the status
                // is left alone here.
                Some(tx) => {
                    info!(
                        "XMPP client {} stopped before the session was established: {}",
                        client_id, end_reason
                    );
                    let _ = tx.send(Err(end_reason.to_string()));
                }
                None => {
                    info!("XMPP client {} disconnected", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                }
            }
            // Orderly stream shutdown; harmless if the peer already went away, and bounded
            // because `close()` waits for a peer that never answers when the stream was never
            // established.
            match tokio::time::timeout(STREAM_CLOSE_TIMEOUT, xmpp_client.send_end()).await {
                Ok(Err(e)) => debug!("XMPP client {} stream close: {}", client_id, e),
                Err(_) => debug!("XMPP client {} stream close timed out", client_id),
                Ok(Ok(())) => {}
            }
            let _ = status_tx.send(format!("[CLIENT] XMPP client {} disconnected", client_id));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Every way out of this function short of a session ends the client, including the
        // caller dropping this future; the success path disarms it.
        let end_unless_online = ended.clone().drop_guard();

        // Wait for the server to accept the session.
        let bound_jid = match tokio::time::timeout(session_timeout, session_rx).await {
            Ok(Ok(Ok(bound_jid))) => bound_jid,
            Ok(Ok(Err(reason))) => {
                return Err(anyhow::anyhow!(
                    "XMPP client could not establish a session with {}: {}",
                    target,
                    reason
                ));
            }
            Ok(Err(_)) => {
                return Err(anyhow::anyhow!(
                    "XMPP client's event loop ended before a session with {} was established",
                    target
                ));
            }
            Err(_) => {
                ended.cancel();
                return Err(anyhow::anyhow!(
                    "XMPP server at {} did not establish a session within {}s (TCP connect, \
                     STARTTLS, SASL authentication and resource binding all have to succeed; \
                     tokio-xmpp's reason for a failed attempt is in netget.log)",
                    target,
                    session_timeout.as_secs()
                ));
            }
        };
        let _ = end_unless_online.disarm();

        // The connected-event LLM call runs in its own task, so a parked (manual-rule) or
        // slow call holds up neither `connect()` nor the event loop that writes stanzas.
        let connect_llm = llm_client.clone();
        let connect_state = app_state.clone();
        let connect_status_tx = status_tx.clone();
        let connect_protocol = protocol.clone();
        let connect_stanza_tx = stanza_tx.clone();
        let connect_data = client_data.clone();
        let connect_jid = bound_jid.to_string();
        let connect_ended = ended.clone();
        let connect_task = tokio::spawn(async move {
            let Some(instruction) = connect_state.get_instruction_for_client(client_id).await
            else {
                return;
            };
            let event = Event::new(
                &XMPP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "jid": connect_jid,
                }),
            );
            let memory = { connect_data.lock().await.memory.clone() };
            match call_llm_for_client(
                &connect_llm,
                &connect_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                connect_protocol.as_ref(),
                &connect_status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    if let Some(mem) = memory_updates {
                        connect_data.lock().await.memory = mem;
                    }

                    // Execute initial actions; nothing after a `disconnect` runs.
                    for action in actions {
                        if connect_ended.is_cancelled() {
                            break;
                        }
                        Self::execute_action_result(
                            action,
                            connect_protocol.clone(),
                            connect_stanza_tx.clone(),
                            client_id,
                            &connect_state,
                            &connect_status_tx,
                            &connect_ended,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    error!("LLM error on XMPP connect for client {}: {}", client_id, e);
                }
            }
        });
        app_state
            .register_client_task(client_id, connect_task)
            .await;

        // tokio-xmpp owns the socket and does not expose its local address.
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// The session timeout: the `session_timeout_secs` startup parameter, or
    /// [`SESSION_TIMEOUT`].
    fn session_timeout(startup_params: Option<&StartupParams>) -> Result<Duration> {
        let secs = match startup_params {
            Some(params) => params.get_optional_u64("session_timeout_secs")?,
            None => None,
        };
        match secs {
            None => Ok(SESSION_TIMEOUT),
            Some(secs) if (1..=MAX_SESSION_TIMEOUT_SECS).contains(&secs) => {
                Ok(Duration::from_secs(secs))
            }
            Some(secs) => Err(anyhow::anyhow!(
                "session_timeout_secs must be between 1 and {}, got {}",
                MAX_SESSION_TIMEOUT_SECS,
                secs
            )),
        }
    }

    /// The JID and password to authenticate with, from the `jid` and `password` startup
    /// parameters.
    ///
    /// `remote_addr` is never a source: it is the server's address and nothing else. Both
    /// parameters are declared required, so the startup path normally refuses their absence
    /// before `connect()` runs; the check here covers a direct call.
    fn credentials(startup_params: Option<&StartupParams>) -> Result<(Jid, String)> {
        // Propagated, never unwrapped: a wrong-typed value must name itself in the client's
        // Error status, not kill the task that started it.
        let (jid_str, password) = match startup_params {
            Some(params) => (
                params.get_optional_string("jid")?,
                params.get_optional_string("password")?,
            ),
            None => (None, None),
        };
        let jid_str = jid_str.context(
            "the XMPP client needs the 'jid' startup parameter (e.g. \"alice@example.com\")",
        )?;
        let password =
            password.context("the XMPP client needs the 'password' startup parameter")?;

        let jid: Jid = jid_str
            .parse()
            .with_context(|| format!("Invalid JID {:?}", jid_str))?;
        // A client logs in as an account, so the JID needs a local part. tokio-xmpp's login
        // unwraps it inside a task of its own, where a missing one panics instead of failing.
        anyhow::ensure!(
            jid.node().is_some(),
            "the JID {jid_str:?} has no local part; the XMPP client logs in as an account, \
             so 'jid' must look like \"alice@example.com\""
        );
        Ok((jid, password))
    }

    /// What the model is asked about for one incoming stream event, if anything.
    fn event_of(xmpp_event: XmppEvent, client_id: ClientId) -> Option<Event> {
        match xmpp_event {
            // Acted on by the event loop before an event gets here.
            XmppEvent::Online { .. } => None,
            XmppEvent::Disconnected(e) => {
                warn!("XMPP client {} disconnected: {}", client_id, e);
                None
            }
            XmppEvent::Stanza(stanza) => {
                // Match on stanza type to avoid clone
                use tokio_xmpp::Stanza;
                match stanza {
                    Stanza::Message(msg) => {
                        let from = msg.from.as_ref().map(|j| j.to_string()).unwrap_or_default();
                        let to = msg.to.as_ref().map(|j| j.to_string()).unwrap_or_default();
                        let body = msg
                            .bodies
                            .get(&Lang::default())
                            .cloned()
                            .unwrap_or_default();
                        let msg_type = format!("{:?}", msg.type_);

                        info!(
                            "XMPP client {} received message from {}: {}",
                            client_id, from, body
                        );

                        Some(Event::new(
                            &XMPP_CLIENT_MESSAGE_RECEIVED_EVENT,
                            serde_json::json!({
                                "from": from,
                                "to": to,
                                "body": body,
                                "message_type": msg_type,
                            }),
                        ))
                    }
                    Stanza::Presence(presence) => {
                        let from = presence
                            .from
                            .as_ref()
                            .map(|j| j.to_string())
                            .unwrap_or_default();
                        let presence_type = format!("{:?}", presence.type_);
                        let show = presence
                            .show
                            .as_ref()
                            .map(|s| format!("{:?}", s))
                            .unwrap_or_default();
                        let status = presence
                            .statuses
                            .get(&Lang::default())
                            .cloned()
                            .unwrap_or_default();

                        debug!(
                            "XMPP client {} received presence from {}: {:?}",
                            client_id, from, presence_type
                        );

                        Some(Event::new(
                            &XMPP_CLIENT_PRESENCE_RECEIVED_EVENT,
                            serde_json::json!({
                                "from": from,
                                "presence_type": presence_type,
                                "show": show,
                                "status": status,
                            }),
                        ))
                    }
                    Stanza::Iq(_iq) => {
                        debug!(
                            "XMPP client {} received IQ stanza (not yet supported)",
                            client_id
                        );
                        None
                    }
                }
            }
        }
    }

    /// Ask the model about one or more stanzas - several when they arrived during the previous
    /// call and the client batches - and run its actions.
    #[allow(clippy::too_many_arguments)]
    async fn answer_events(
        events: &[Event],
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        client_id: ClientId,
        client_data: &Arc<Mutex<ClientData>>,
        protocol: Arc<XmppClientProtocol>,
        stanza_tx: Arc<mpsc::UnboundedSender<StanzaRequest>>,
        status_tx: &mpsc::UnboundedSender<String>,
        ended: &CancellationToken,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        // Copied out first: a guard taken inline in the call's arguments would live to the end
        // of the `match` and deadlock the memory write in its arm.
        let memory = client_data.lock().await.memory.clone();
        match call_llm_for_client_batch(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            events,
            protocol.as_ref(),
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    client_data.lock().await.memory = mem;
                }

                // Execute actions; nothing after a `disconnect` runs.
                for action in actions {
                    if ended.is_cancelled() {
                        break;
                    }
                    Self::execute_action_result(
                        action,
                        protocol.clone(),
                        stanza_tx.clone(),
                        client_id,
                        app_state,
                        status_tx,
                        ended,
                    )
                    .await;
                }
            }
            Err(e) => {
                error!("LLM error for XMPP client {}: {}", client_id, e);
            }
        }
    }

    /// Execute an action and put whatever stanza it produced on the wire.
    ///
    /// Thin wrapper over [`Self::apply_action`] for the LLM paths, which have nowhere to
    /// report an outcome and only log. A `disconnect` ends the session through
    /// [`Self::end_session`], the same path an injected one takes.
    #[allow(clippy::too_many_arguments)]
    async fn execute_action_result(
        action: serde_json::Value,
        protocol: Arc<XmppClientProtocol>,
        stanza_tx: Arc<mpsc::UnboundedSender<StanzaRequest>>,
        client_id: ClientId,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
        ended: &CancellationToken,
    ) {
        use crate::llm::actions::client_trait::Client;

        match protocol.as_ref().execute_action(action) {
            Ok(result) => {
                // The LLM path does not wait for the write: it has no caller to answer, and
                // waiting would serialise every action behind the event loop's next turn.
                match Self::apply_action(result, &stanza_tx, client_id, false).await {
                    Ok(XmppApplied::Disconnect) => {
                        let _ = status_tx.send(format!(
                            "[CLIENT] XMPP client {} disconnecting at the model's request",
                            client_id
                        ));
                        Self::end_session(ended, app_state, client_id).await;
                    }
                    Ok(applied) => trace!("XMPP client {}: {}", client_id, applied.detail()),
                    Err(e) => {
                        console_error!(status_tx, "XMPP client {} action failed: {}", client_id, e)
                    }
                }
            }
            Err(e) => {
                error!(
                    "Action execution error for XMPP client {}: {}",
                    client_id, e
                );
            }
        }
    }

    /// Turn one executed action into a stanza and hand it to the event loop.
    ///
    /// Shared by the connected-event path, the incoming-stanza path and injected commands, so
    /// the mapping from `send_message`/`send_presence` onto `xmpp_parsers` stanzas exists
    /// exactly once. With `wait_for_write` set the caller is told whether the stanza actually
    /// reached the transport, which is what an injected command needs to answer honestly.
    async fn apply_action(
        action_result: crate::llm::actions::client_trait::ClientActionResult,
        stanza_tx: &Arc<mpsc::UnboundedSender<StanzaRequest>>,
        client_id: ClientId,
        wait_for_write: bool,
    ) -> Result<XmppApplied> {
        use crate::llm::actions::client_trait::ClientActionResult;
        use tokio_xmpp::Stanza;

        match action_result {
            ClientActionResult::Custom { name, data } => match name.as_str() {
                "send_message" => {
                    let to = data
                        .get("to")
                        .and_then(|v| v.as_str())
                        .context("send_message result has no 'to'")?;
                    let body = data
                        .get("body")
                        .and_then(|v| v.as_str())
                        .context("send_message result has no 'body'")?;
                    let jid: Jid = to.parse().context("Invalid JID")?;

                    let mut message = Message::new(Some(jid));
                    message.type_ = MessageType::Chat;
                    message.bodies.insert(Lang::default(), body.to_string());

                    Self::dispatch(
                        Stanza::Message(message),
                        stanza_tx,
                        wait_for_write,
                        format!("<message/> to {} ({} byte body)", to, body.len()),
                    )
                    .await
                }
                "send_presence" => {
                    let show = data.get("show").and_then(|v| v.as_str());
                    let status = data.get("status").and_then(|v| v.as_str());

                    let mut presence = Presence::new(PresenceType::None);
                    if let Some(show_str) = show {
                        presence.show = match show_str {
                            "away" => Some(PresenceShow::Away),
                            "chat" => Some(PresenceShow::Chat),
                            "dnd" => Some(PresenceShow::Dnd),
                            "xa" => Some(PresenceShow::Xa),
                            _ => None,
                        };
                    }
                    if let Some(status_str) = status {
                        presence
                            .statuses
                            .insert(Lang::default(), status_str.to_string());
                    }

                    Self::dispatch(
                        Stanza::Presence(presence),
                        stanza_tx,
                        wait_for_write,
                        format!("<presence/> show={:?} status={:?}", show, status),
                    )
                    .await
                }
                other => Err(anyhow::anyhow!(
                    "XMPP client cannot apply custom result '{}'",
                    other
                )),
            },
            ClientActionResult::Disconnect => {
                info!("XMPP client {} disconnecting", client_id);
                Ok(XmppApplied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(XmppApplied::NoWire(
                "waiting for the next stanza; nothing sent".to_string(),
            )),
            ClientActionResult::NoAction => {
                Ok(XmppApplied::NoWire("no_action: nothing sent".to_string()))
            }
            ClientActionResult::SendData(_) => Err(anyhow::anyhow!(
                "XMPP speaks stanzas, not raw bytes; use send_message"
            )),
            ClientActionResult::Multiple(_) => Err(anyhow::anyhow!(
                "XMPP client does not support Multiple action results"
            )),
        }
    }

    /// Hand one stanza to the event loop, optionally waiting until it has been written.
    async fn dispatch(
        stanza: tokio_xmpp::Stanza,
        stanza_tx: &Arc<mpsc::UnboundedSender<StanzaRequest>>,
        wait_for_write: bool,
        what: String,
    ) -> Result<XmppApplied> {
        if !wait_for_write {
            stanza_tx
                .send(StanzaRequest { stanza, ack: None })
                .map_err(|_| anyhow::anyhow!("XMPP connection is already closed"))?;
            return Ok(XmppApplied::Queued(format!("{what} queued for the stream")));
        }

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        stanza_tx
            .send(StanzaRequest {
                stanza,
                ack: Some(ack_tx),
            })
            .map_err(|_| anyhow::anyhow!("XMPP connection is already closed"))?;
        match ack_rx.await {
            Ok(Ok(())) => Ok(XmppApplied::Wrote(format!(
                "{what} written to the XMPP transport"
            ))),
            Ok(Err(e)) => Err(anyhow::anyhow!("send_stanza failed: {e}")),
            Err(_) => Err(anyhow::anyhow!(
                "the XMPP event loop ended before the stanza could be written"
            )),
        }
    }

    /// End the session on a `disconnect`, whether the model produced it or it was injected.
    ///
    /// Cancelling `ended` tells the event loop to close the stream, after which it runs its
    /// normal exit path (status, handle removal, status_tx), and stops tokio-xmpp dialling
    /// again. The command handle is dropped here as well, so \[ send \] disappears at once
    /// rather than after the stream shutdown, and the command loop ends.
    async fn end_session(ended: &CancellationToken, app_state: &AppState, client_id: ClientId) {
        info!("XMPP client {} ending its session on disconnect", client_id);
        ended.cancel();
        app_state.remove_client_handle(client_id).await;
    }

    /// Drain injected commands (the dashboard's \[ send \]) until the channel closes - the
    /// client was removed, or the event loop exited - or an injected `disconnect` ends the
    /// session.
    ///
    /// `tokio_xmpp::Client` is owned by the event loop task and is not clonable, so the
    /// command loop reaches the stream the way every other producer here does: through the
    /// stanza channel. What makes the outcome honest is the per-stanza ack - the event loop
    /// reports back what `send_stanza` returned, and `send_stanza` resolves only once the
    /// stanza has reached the transport.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        stanza_tx: Arc<mpsc::UnboundedSender<StanzaRequest>>,
        ended: CancellationToken,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::Client;
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = XmppClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => match Self::apply_action(result, &stanza_tx, client_id, true).await {
                    // Never `Sent`: the stanza really did reach the transport, but tokio-xmpp
                    // serialises and writes it internally and reports no byte count, so there
                    // is no honest number for `bytes_sent`.
                    Ok(XmppApplied::Wrote(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(XmppApplied::Queued(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(XmppApplied::NoWire(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(XmppApplied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Err(e) => Err(e),
                },
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!("XMPP client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::end_session(&ended, &app_state, client_id).await;
                break;
            }
        }
    }
}

/// One stanza on its way to the event loop, with an optional slot for the write result.
///
/// The ack is what lets an injected command report the truth: `Client::send_stanza` resolves
/// only once the stanza has been written to the transport, and this carries that result back
/// to whoever asked for the send.
struct StanzaRequest {
    stanza: tokio_xmpp::Stanza,
    ack: Option<tokio::sync::oneshot::Sender<std::result::Result<(), String>>>,
}

/// What [`XmppClientConnection::apply_action`] did with one executed action.
enum XmppApplied {
    /// Written to the XMPP transport (the caller asked to wait for it).
    Wrote(String),
    /// Handed to the event loop without waiting.
    Queued(String),
    /// Ran, but nothing goes on the wire.
    NoWire(String),
    /// The session should end.
    Disconnect,
}

impl XmppApplied {
    fn detail(&self) -> &str {
        match self {
            XmppApplied::Wrote(d) | XmppApplied::Queued(d) | XmppApplied::NoWire(d) => d,
            XmppApplied::Disconnect => "disconnect requested",
        }
    }
}
