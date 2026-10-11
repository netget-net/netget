//! CoAP (RFC 7252) server over UDP.
//!
//! Owns the message layer — types, message ids, tokens, and the mechanical replies the
//! specification leaves no room to decide — while the model owns the resource layer. See
//! `src/server/coap/CLAUDE.md`.

pub mod actions;
pub mod blockwise;
pub mod codec;
pub mod observe;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::utils::clock::Instant;
use crate::{console_debug, console_trace};

use actions::{CoapProtocol, COAP_REQUEST_EVENT, RESULT_IGNORE, RESULT_RESET, RESULT_RESPONSE};
use blockwise::{Representation, ResourceKey, Transfers, UploadKey, UploadStep, Uploads};
use codec::{BlockValue, CoapMessage, MessageType};
use observe::{Observer, Observers, Registered};

/// RFC 7252 §4.8 ACK_TIMEOUT, the default wait before a Confirmable notification is resent.
/// The `notification_ack_timeout_ms` startup parameter overrides it.
pub const DEFAULT_NOTIFICATION_ACK_TIMEOUT_MS: u64 = 2000;

/// RFC 7252 §4.8 MAX_RETRANSMIT: how often an unacknowledged Confirmable notification is
/// resent before the observer is presumed gone and removed (RFC 7641 §4.5).
pub const NOTIFICATION_MAX_RETRANSMIT: u32 = 4;

/// CoAP server.
pub struct CoapServer;

/// The running server, as the actions reach it.
///
/// Registered with [`AppState::register_server_handle`] so `coap_notify` — an action the model
/// may issue at any time, not only while answering a request — can find the socket and the
/// observers. Every lock here is a `std::sync::Mutex` and none is held across an `.await`.
pub struct CoapServerHandle {
    socket: Arc<UdpSocket>,
    server_id: crate::state::ServerId,
    status_tx: mpsc::UnboundedSender<String>,
    /// Message ids for messages the server originates: NON replies and notifications.
    next_message_id: AtomicU16,
    observers: Mutex<Observers>,
    transfers: Mutex<Transfers>,
    uploads: Mutex<Uploads>,
    ack_timeout: Duration,
}

/// What [`CoapServerHandle::notify`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotifyReport {
    /// Observers a notification was sent to.
    pub sent: usize,
    /// Observers whose observation the notification ended (a non-2.xx code, RFC 7641 §4.2).
    pub ended: usize,
}

impl CoapServerHandle {
    fn fresh_message_id(&self) -> u16 {
        self.next_message_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Every registration, for the dashboard and for tests. Expired ones are removed first.
    pub fn observers(&self) -> Vec<Observer> {
        self.expire_observers();
        lock(&self.observers).all()
    }

    /// Confirmable notifications still waiting for their ACK.
    pub fn pending_notifications(&self) -> usize {
        lock(&self.observers).pending_len()
    }

    /// Remove every registration unconfirmed for `observe::OBSERVER_MAX_AGE`, logging each.
    fn expire_observers(&self) {
        let expired = lock(&self.observers).expire(Instant::now());
        for observer in expired {
            info!(
                "CoAP observer {} of {} unconfirmed for {} s; observation removed decision={}",
                observer.peer,
                observer.path,
                observe::OBSERVER_MAX_AGE.as_secs(),
                Decision::ObserverExpired.as_str()
            );
        }
    }

    /// Representations cached for Block2 continuations.
    pub fn cached_transfers(&self) -> usize {
        lock(&self.transfers).len()
    }

    /// Block1 uploads in progress.
    pub fn uploads_in_progress(&self) -> usize {
        lock(&self.uploads).len()
    }

    /// Push `rep` to every observer of `path` (RFC 7641 §4.2).
    ///
    /// A 2.xx goes out with the next Observe sequence number and keeps the observation; any
    /// other code goes out *without* Observe and ends it, which is how the RFC says "this
    /// resource is gone". A representation over one block is sent as its first Block2 block
    /// and cached, so the client fetches the rest with ordinary GETs (RFC 7959 §2.6).
    ///
    /// `confirmable` is what the caller asked for; an observer unconfirmed for half of
    /// `observe::OBSERVER_MAX_AGE` gets a Confirmable notification regardless (RFC 7641 §4.5),
    /// so a live client renews its registration by acknowledging it and a dead or spoofed one
    /// is removed when the retransmissions run out.
    pub async fn notify(
        &self,
        app_state: &AppState,
        path: &str,
        rep: Representation,
        confirmable: bool,
    ) -> NotifyReport {
        let rep = Arc::new(rep);
        self.expire_observers();
        let observers = lock(&self.observers).of_path(path);
        let mut report = NotifyReport::default();
        for observer in observers {
            let keeps = codec::code_class(rep.code) == 2;
            let confirmable = confirmable
                || (keeps
                    && lock(&self.observers).needs_confirmation(
                        observer.peer,
                        &observer.token,
                        Instant::now(),
                    ));
            let mid = self.fresh_message_id();
            let mut message = CoapMessage {
                mtype: if confirmable {
                    MessageType::Confirmable
                } else {
                    MessageType::NonConfirmable
                },
                code: rep.code,
                message_id: mid,
                token: observer.token.clone(),
                options: Vec::new(),
                payload: Vec::new(),
            };
            if keeps {
                let seq = lock(&self.observers).next_sequence();
                message
                    .options
                    .push((codec::OPT_OBSERVE, codec::uint_option(seq)));
            }
            let key = ResourceKey {
                peer: observer.peer,
                path: observer.path.clone(),
                query: observer.query.clone(),
            };
            let szx = observer.block_szx.unwrap_or(codec::MAX_SZX);
            self.fill_representation(&mut message, &rep, key, None, szx);

            {
                let mut obs = lock(&self.observers);
                // Pending only when a retransmission task will wait for it.
                obs.record(observer.peer, mid, &observer.token, confirmable && keeps);
                if !keeps {
                    obs.deregister(observer.peer, &observer.token);
                    report.ended += 1;
                }
            }
            info!(
                "CoAP notification {} {} to {} (mid {mid}) decision={}",
                codec::code_to_string(rep.code),
                path,
                observer.peer,
                if keeps {
                    Decision::Notified.as_str()
                } else {
                    Decision::ObservationEnded.as_str()
                }
            );
            let sent = self
                .send(&message, observer.peer, observer.connection_id, app_state)
                .await;
            if confirmable && keeps {
                if sent {
                    self.retransmit_later(app_state, observer, message).await;
                } else {
                    lock(&self.observers).settle(observer.peer, mid);
                }
            }
            report.sent += usize::from(sent);
        }
        report
    }

    /// Resend a Confirmable notification until it is acknowledged; give up after
    /// [`NOTIFICATION_MAX_RETRANSMIT`] and remove the observer (RFC 7641 §4.5).
    async fn retransmit_later(
        &self,
        app_state: &AppState,
        observer: Observer,
        message: CoapMessage,
    ) {
        let Some(handle) = app_state
            .server_handle::<CoapServerHandle>(self.server_id)
            .await
        else {
            lock(&self.observers).settle(observer.peer, message.message_id);
            return;
        };
        let state = app_state.clone();
        let mut interval = self.ack_timeout.mul_f64(1.0 + rand::random::<f64>() * 0.5);
        app_state
            .spawn_server_task(self.server_id, async move {
                for attempt in 0..=NOTIFICATION_MAX_RETRANSMIT {
                    tokio::time::sleep(interval).await;
                    // Not pending means acknowledged, reset, superseded by a newer
                    // Confirmable notification, or its observer is gone. Pending entries are
                    // never evicted, so this is never true merely because time passed.
                    if !lock(&handle.observers).awaiting_ack(observer.peer, message.message_id) {
                        return;
                    }
                    if attempt == NOTIFICATION_MAX_RETRANSMIT {
                        break;
                    }
                    debug!(
                        "CoAP notification mid {} to {} unacknowledged; retransmission {}",
                        message.message_id,
                        observer.peer,
                        attempt + 1
                    );
                    handle
                        .send(&message, observer.peer, observer.connection_id, &state)
                        .await;
                    interval *= 2;
                }
                {
                    let mut obs = lock(&handle.observers);
                    obs.settle(observer.peer, message.message_id);
                    obs.deregister(observer.peer, &observer.token);
                }
                warn!(
                    "CoAP observer {} of {} never acknowledged notification mid {} after {} \
                     retransmissions; observation removed decision={}",
                    observer.peer,
                    observer.path,
                    message.message_id,
                    NOTIFICATION_MAX_RETRANSMIT,
                    Decision::ObserverTimeout.as_str()
                );
            })
            .await;
    }

    /// Put `rep` into `message`: the whole payload when it fits one block and nobody asked for
    /// blocks, otherwise block `wanted` (or 0) with Block2, Size2 on the first block and the
    /// ETag. A representation with blocks after this one is cached under `key`.
    ///
    /// Returns false when `wanted` starts past the end, and leaves `message` untouched so the
    /// caller can answer 4.02.
    fn fill_representation(
        &self,
        message: &mut CoapMessage,
        rep: &Arc<Representation>,
        key: ResourceKey,
        wanted: Option<BlockValue>,
        szx: u8,
    ) -> bool {
        let size = codec::szx_size(szx);
        if wanted.is_none() && rep.payload.len() <= size {
            if let Some(cf) = rep.content_format {
                message
                    .options
                    .push((codec::OPT_CONTENT_FORMAT, codec::uint_option(u32::from(cf))));
            }
            message.payload = rep.payload.clone();
            return true;
        }
        let block = BlockValue {
            num: wanted.map_or(0, |b| b.num),
            more: false,
            szx,
        };
        let Some((slice, more)) = rep.block(block) else {
            return false;
        };
        message.options.push((codec::OPT_ETAG, rep.etag.clone()));
        if let Some(cf) = rep.content_format {
            message
                .options
                .push((codec::OPT_CONTENT_FORMAT, codec::uint_option(u32::from(cf))));
        }
        message
            .options
            .push((codec::OPT_BLOCK2, BlockValue { more, ..block }.encode()));
        if block.num == 0 {
            message.options.push((
                codec::OPT_SIZE2,
                codec::uint_option(rep.payload.len() as u32),
            ));
        }
        message.payload = slice.to_vec();
        let mut transfers = lock(&self.transfers);
        if more {
            // A block served from the cache was charged by `Transfers::get`, and inserting the
            // same representation again leaves its entry as it is.
            if let Some(evicted) = transfers.insert(key, rep.clone(), slice.len(), Instant::now()) {
                debug!(
                    "CoAP Block2 cache full; evicted {}{} for {}",
                    evicted.path,
                    evicted.query.map(|q| format!("?{q}")).unwrap_or_default(),
                    evicted.peer
                );
            }
        } else {
            transfers.remove(&key);
        }
        true
    }

    /// Encode and send one message, updating counters and the dual logs. False when nothing
    /// went out.
    async fn send(
        &self,
        message: &CoapMessage,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        app_state: &AppState,
    ) -> bool {
        // A message the codec refuses is never patched up and sent anyway: a CoAP reply whose
        // token was shortened to fit matches nothing at the client, which is a silent drop
        // dressed as an answer.
        let bytes = match message.encode() {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    "CoAP decision=fail_closed_encode: refusing to send {} to {}: {}",
                    codec::code_to_string(message.code),
                    peer_addr,
                    e
                );
                let _ = self.status_tx.send(format!(
                    "✗ CoAP refused to encode a reply to {peer_addr}: {e}"
                ));
                return false;
            }
        };
        if let Err(e) = self.socket.send_to(&bytes, peer_addr).await {
            error!("CoAP send to {} failed: {}", peer_addr, e);
            let _ = self
                .status_tx
                .send(format!("✗ CoAP send to {peer_addr} failed: {e}"));
            return false;
        }

        app_state
            .update_connection_stats(
                self.server_id,
                connection_id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;

        let log = Log::new(Some(&self.status_tx));
        log.debug(format!(
            "CoAP sent {} {} ({} bytes) to {peer_addr}",
            message.mtype.as_str(),
            codec::code_to_string(message.code),
            bytes.len()
        ));
        log.trace(format!("CoAP sent (hex): {}", hex::encode(&bytes)));
        let _ = self
            .status_tx
            .send(format!("→ CoAP response to {peer_addr}"));
        true
    }
}

/// A poisoned lock is still the table: a panic elsewhere must not make every later request
/// panic too.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl CoapServer {
    /// Bind the UDP socket and start the receive loop.
    ///
    /// Returns `Err` when the socket cannot be bound, so `server_startup` records
    /// `ServerStatus::Error` instead of a server that never received anything.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        notification_ack_timeout: Duration,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("CoAP server listening on {local_addr}"));

        let protocol = Arc::new(CoapProtocol::new());
        let handle = Arc::new(CoapServerHandle {
            socket: socket.clone(),
            server_id,
            status_tx: status_tx.clone(),
            next_message_id: AtomicU16::new(rand::random::<u16>()),
            observers: Mutex::new(Observers::default()),
            transfers: Mutex::new(Transfers::default()),
            uploads: Mutex::new(Uploads::default()),
            ack_timeout: notification_ack_timeout,
        });
        app_state
            .register_server_handle(server_id, handle.clone())
            .await;

        let task_registrar = app_state.clone();
        let recv_handle = tokio::spawn(async move {
            Log::new(Some(&status_tx)).info(format!("CoAP receive loop started on {local_addr}"));

            // Deliberately larger than `codec::MAX_MESSAGE_LEN` (1152), and that is the
            // whole point of the number rather than headroom for its own sake: `recv_from`
            // silently discards whatever does not fit, so a buffer sized *at* the bound
            // would deliver a 5000-byte datagram as a legal-looking 1152-byte one and the
            // guard below could never fire. With 2048 anything over the bound is seen to
            // be over it.
            let mut buffer = vec![0u8; 2048];

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        app_state
                            .add_connection_to_server(
                                server_id,
                                ServerConnectionState {
                                    id: connection_id,
                                    remote_addr: peer_addr,
                                    local_addr,
                                    bytes_sent: 0,
                                    bytes_received: n as u64,
                                    packets_sent: 0,
                                    packets_received: 1,
                                    last_activity: now,
                                    status: ConnectionStatus::Active,
                                    status_changed_at: now,
                                    protocol_info: ProtocolConnectionInfo::empty(),
                                },
                            )
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        console_debug!(status_tx, "CoAP received {} bytes from {}", n, peer_addr);
                        console_trace!(status_tx, "CoAP received (hex): {}", hex::encode(&data));

                        let llm = llm_client.clone();
                        let st = app_state.clone();
                        let proto = protocol.clone();
                        let shared = handle.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_datagram(
                                    data,
                                    peer_addr,
                                    connection_id,
                                    llm,
                                    st,
                                    shared,
                                    proto,
                                )
                                .await;
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("CoAP receive error: {}", e);
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, recv_handle)
            .await;

        Ok(local_addr)
    }

    async fn handle_datagram(
        data: Vec<u8>,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        shared: Arc<CoapServerHandle>,
        protocol: Arc<CoapProtocol>,
    ) {
        let server_id = shared.server_id;
        let status_tx = shared.status_tx.clone();
        let send = |message: CoapMessage| {
            let shared = shared.clone();
            let app_state = app_state.clone();
            async move {
                shared
                    .send(&message, peer_addr, connection_id, &app_state)
                    .await;
            }
        };

        // --- The inbound size bound, before anything is decoded or asked -------------
        //
        // RFC 7252 §4.6 puts MAX_MESSAGE_SIZE at 1152 bytes when the path MTU is unknown, and
        // the legal way past it — Block1, whose largest block is 1024 bytes — fits under it.
        // So a larger datagram is refused in CoAP's own vocabulary (4.13 Request Entity Too
        // Large, §5.9.2.9) rather than decoded, and the model is never asked about it: an
        // oversize request must not become a prompt.
        if data.len() > codec::MAX_MESSAGE_LEN {
            warn!(
                "CoAP refusing a {}-byte datagram from {} (limit {}) decision={}",
                data.len(),
                peer_addr,
                codec::MAX_MESSAGE_LEN,
                Decision::RefusedTooLarge.as_str()
            );
            let _ = status_tx.send(format!(
                "✗ CoAP refused a {}-byte datagram from {peer_addr}: over the {}-byte limit",
                data.len(),
                codec::MAX_MESSAGE_LEN
            ));

            // The refusal still has to be matchable, so it carries the request's own
            // message id and token — read from the fixed-offset prefix, which needs no
            // option walk. Without that echo a client discards it and the refusal is
            // indistinguishable from the silence it exists to avoid.
            if let Some(prefix) = codec::message_prefix(&data) {
                let reply = if codec::method_name(prefix.code).is_some() {
                    let fresh = shared.fresh_message_id();
                    Some(codec::response_to_prefix(
                        &prefix,
                        fresh,
                        codec::CODE_REQUEST_ENTITY_TOO_LARGE,
                    ))
                } else if prefix.mtype == MessageType::Confirmable {
                    // Not a request, so 4.13 would be a category error; RFC 7252 §4.2
                    // rejects a Confirmable message that cannot be processed with a Reset.
                    Some(codec::reset_for(prefix.message_id))
                } else {
                    None
                };
                if let Some(reply) = reply {
                    send(reply).await;
                }
            }
            return;
        }

        let request = match CoapMessage::decode(&data) {
            Ok(m) => m,
            Err(e) => {
                warn!("CoAP malformed message from {}: {}", peer_addr, e);
                let _ = status_tx.send(format!("✗ CoAP malformed message from {peer_addr}: {e}"));

                // RFC 7252 §4.2: a Confirmable message that cannot be processed is
                // rejected with a Reset. The message id lives in bytes 2-3, which we
                // still have whenever the datagram reached the header length at all.
                if data.len() >= codec::HEADER_LEN
                    && MessageType::from_bits(data[0] >> 4) == MessageType::Confirmable
                {
                    let message_id = u16::from_be_bytes([data[2], data[3]]);
                    send(codec::reset_for(message_id)).await;
                }
                return;
            }
        };

        // --- Message-layer traffic the specification answers on its own -------------

        if request.is_empty_message() {
            match request.mtype {
                // RFC 7252 §4.3 CoAP Ping: an empty Confirmable message is answered with
                // a Reset. This is not a decision, so it does not reach the model.
                MessageType::Confirmable => {
                    debug!(
                        "CoAP ping from {}; replying RST decision={}",
                        peer_addr,
                        Decision::SpecReply.as_str()
                    );
                    send(codec::reset_for(request.message_id)).await;
                }
                // An ACK for a Confirmable notification: stop retransmitting it.
                MessageType::Acknowledgement => {
                    if lock(&shared.observers).acknowledge(
                        peer_addr,
                        request.message_id,
                        Instant::now(),
                    ) {
                        debug!(
                            "CoAP notification mid {} acknowledged by {}",
                            request.message_id, peer_addr
                        );
                    }
                }
                // A RST answering a notification: the client has forgotten the observation
                // (RFC 7641 §3.6), so the server forgets it too.
                MessageType::Reset => {
                    let removed = lock(&shared.observers).reset(peer_addr, request.message_id);
                    match removed {
                        Some(observer) => info!(
                            "CoAP observer {} of {} answered notification mid {} with RST; \
                             observation removed decision={}",
                            peer_addr,
                            observer.path,
                            request.message_id,
                            Decision::ObserverReset.as_str()
                        ),
                        None => debug!(
                            "CoAP RST from {} for mid {} matches no notification",
                            peer_addr, request.message_id
                        ),
                    }
                }
                MessageType::NonConfirmable => {
                    debug!("CoAP empty NON message from {} ignored", peer_addr);
                }
            }
            return;
        }

        if !request.is_request() {
            // A response code arriving at a server, or a method this version of CoAP does
            // not define. RFC 7252 §5.8 defines only GET/POST/PUT/DELETE.
            if codec::code_class(request.code) == 0 {
                warn!(
                    "CoAP unrecognised method {} from {}; replying 4.05 decision={}",
                    codec::code_to_string(request.code),
                    peer_addr,
                    Decision::SpecReply.as_str()
                );
                let fresh = shared.fresh_message_id();
                send(codec::response_to(
                    &request,
                    fresh,
                    codec::CODE_METHOD_NOT_ALLOWED,
                ))
                .await;
            } else {
                debug!(
                    "CoAP {} message with response code {} from {} ignored; this is a server",
                    request.mtype.as_str(),
                    codec::code_to_string(request.code),
                    peer_addr
                );
            }
            return;
        }

        let method = codec::method_name(request.code).unwrap_or("GET");
        let path = request.uri_path();
        let resource = ResourceKey {
            peer: peer_addr,
            path: path.clone(),
            query: request.uri_query(),
        };

        // A reply the specification determines, with no model involved.
        let spec_reply = |code: u8, decision: &'static str, why: String| {
            let fresh = shared.fresh_message_id();
            let response = codec::response_to(&request, fresh, code);
            info!(
                "CoAP {method} {path} from {peer_addr}: {} {why} decision={decision}",
                codec::code_to_string(code)
            );
            response
        };

        // --- Block-wise options (RFC 7959) -----------------------------------------

        let block2 = match request.block2() {
            None => None,
            Some(Some(b)) => Some(b),
            Some(None) => {
                let reply = spec_reply(
                    codec::CODE_BAD_OPTION,
                    Decision::SpecReply.as_str(),
                    "unreadable Block2 option".into(),
                );
                send(reply).await;
                return;
            }
        };

        // Block1: the request body arrives in pieces. Every piece but the last is answered
        // 2.31 Continue here; the last one carries the whole body on to the model.
        let mut payload = request.payload.clone();
        let mut upload: Option<(u32, BlockValue)> = None;
        match request.block1() {
            None => {}
            Some(None) => {
                let reply = spec_reply(
                    codec::CODE_BAD_OPTION,
                    Decision::SpecReply.as_str(),
                    "unreadable Block1 option".into(),
                );
                send(reply).await;
                return;
            }
            Some(Some(block)) => {
                let key = UploadKey {
                    resource: resource.clone(),
                    method: request.code,
                };
                let size1 = request.option_uint(codec::OPT_SIZE1);
                let step = lock(&shared.uploads).accept(
                    key,
                    block,
                    &request.payload,
                    size1,
                    Instant::now(),
                );
                match step {
                    UploadStep::Continue(echo) => {
                        let mut reply = spec_reply(
                            codec::CODE_CONTINUE,
                            Decision::UploadContinue.as_str(),
                            format!("block {} received", echo.num),
                        );
                        reply.options.push((codec::OPT_BLOCK1, echo.encode()));
                        send(reply).await;
                        return;
                    }
                    UploadStep::Refuse {
                        code,
                        size1,
                        decision,
                        reason,
                    } => {
                        let mut reply = spec_reply(code, decision, reason);
                        if let Some(max) = size1 {
                            reply
                                .options
                                .push((codec::OPT_SIZE1, codec::uint_option(max as u32)));
                        }
                        send(reply).await;
                        return;
                    }
                    UploadStep::Complete { body, blocks, last } => {
                        payload = body;
                        upload = Some((blocks, last));
                    }
                }
            }
        }

        // A later Block2 block of a representation the model already gave: served from the
        // cache. A miss falls through to the model, whose answer is sliced the same way. So
        // does a block that would take the entry past its serve budget
        // (`blockwise::TRANSFER_SERVE_FACTOR`): the cache answers a spoofable address without
        // the model, so what one answer can be made to send is bounded.
        if let Some(block) = block2.filter(|b| b.num > 0) {
            let cached = lock(&shared.transfers).get(&resource, block, Instant::now());
            if let Some(rep) = cached {
                let fresh = shared.fresh_message_id();
                let mut response = codec::response_to(&request, fresh, rep.code);
                if shared.fill_representation(&mut response, &rep, resource, Some(block), block.szx)
                {
                    debug!(
                        "CoAP {method} {path} block {} from {peer_addr} served from cache \
                         decision={}",
                        block.num,
                        Decision::BlockCache.as_str()
                    );
                    send(response).await;
                } else {
                    let reply = spec_reply(
                        codec::CODE_BAD_OPTION,
                        Decision::SpecReply.as_str(),
                        format!("block {} is past the end of the representation", block.num),
                    );
                    send(reply).await;
                }
                return;
            }
        }

        // Observe (RFC 7641): 0 asks to register, 1 to deregister. Only a GET observes, and a
        // Block2 continuation never re-registers (RFC 7959 §2.6).
        let observe = match (request.code, request.observe()) {
            (codec::CODE_GET, Some(0)) if block2.is_none_or(|b| b.num == 0) => {
                Some(ObserveRequest::Register)
            }
            (codec::CODE_GET, Some(1)) => {
                if lock(&shared.observers).deregister(peer_addr, &request.token) {
                    info!(
                        "CoAP {peer_addr} deregistered from {path} decision={}",
                        Decision::ObservationEnded.as_str()
                    );
                }
                Some(ObserveRequest::Deregister)
            }
            _ => None,
        };

        // --- Resource layer: the model decides -------------------------------------

        let answer_with = actions::answer_with_for_request(method, &path);

        let mut event_data = serde_json::json!({
            "method": method,
            "path": path,
            "path_segments": request.path_segments(),
            "message_type": request.mtype.as_str(),
            "message_id": request.message_id,
            "answer_with": answer_with,
        });
        if let Some(query) = request.uri_query() {
            event_data["query"] = serde_json::json!(query);
        }
        if let Some(observe) = observe {
            event_data["observe"] = serde_json::json!(observe.as_str());
        }
        if let Some((blocks, _)) = upload {
            event_data["blocks"] = serde_json::json!(blocks);
        }
        if let Some(cf) = request.option_uint(codec::OPT_CONTENT_FORMAT) {
            let id = cf as u16;
            event_data["content_format"] = serde_json::json!(
                codec::content_format_name(id).unwrap_or("application/octet-stream")
            );
        }
        if let Some(accept) = request.option_uint(codec::OPT_ACCEPT) {
            let id = accept as u16;
            event_data["accept"] = serde_json::json!(
                codec::content_format_name(id).unwrap_or("application/octet-stream")
            );
        }
        if !payload.is_empty() {
            event_data["payload_size"] = serde_json::json!(payload.len());
            let printable = payload
                .iter()
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
            if printable {
                event_data["payload"] =
                    serde_json::json!(String::from_utf8_lossy(&payload).to_string());
                event_data["payload_encoding"] = serde_json::json!("utf8");
            } else {
                event_data["payload"] = serde_json::json!(hex::encode(&payload));
                event_data["payload_encoding"] = serde_json::json!("hex");
            }
        }

        debug!(
            "CoAP {} {} {} from {} (mid={})",
            request.mtype.as_str(),
            method,
            path,
            peer_addr,
            request.message_id
        );

        let event = Event::new(&COAP_REQUEST_EVENT, event_data);

        let (decision, outcome) = match call_llm(
            &llm_client,
            &app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }
                Self::outcome_from_results(&request, &execution_result.protocol_results)
            }
            Err(e) => {
                // The error text stays in the log; the peer gets only the code.
                error!("CoAP LLM error for {} {}: {}", method, path, e);
                let _ = status_tx.send(format!("✗ CoAP LLM error: {e}"));
                // Fail closed with a code that means exactly what happened, rather than
                // inventing a representation or leaving the client to retransmit.
                (
                    Decision::FailClosedLlmError,
                    Outcome::Response {
                        code: codec::CODE_SERVICE_UNAVAILABLE,
                        payload: Vec::new(),
                        content_format: None,
                        observable: false,
                    },
                )
            }
        };

        // Log the decision before writing it, and make the fail-closed paths loud. 5.03 is
        // both what a backend outage produces and something the model may pick itself, so
        // the peer cannot tell them apart and an operator has to be able to.
        let summary = format!(
            "CoAP {method} {path} from {peer_addr} decision={}",
            decision.as_str()
        );
        if decision.is_fail_closed() {
            Log::new(Some(&status_tx)).error(format!(
                "{summary} (answered 5.03 because no usable answer was produced)"
            ));
        } else {
            debug!("{summary}");
        }

        let fresh = shared.fresh_message_id();
        let message = match outcome {
            Outcome::Ignore => {
                debug!(
                    "CoAP deliberately sending no reply to {} {} from {}",
                    method, path, peer_addr
                );
                return;
            }
            Outcome::Reset => codec::reset_for(request.message_id),
            Outcome::Response {
                code,
                payload,
                content_format,
                observable,
            } => {
                let mut response = codec::response_to(&request, fresh, code);
                let rep = Arc::new(Representation::new(code, payload, content_format));

                // The registration, if one was asked for and the model served the resource.
                if observe == Some(ObserveRequest::Register) && codec::code_class(code) == 2 {
                    if observable {
                        let observer = Observer {
                            peer: peer_addr,
                            token: request.token.clone(),
                            path: path.clone(),
                            query: request.uri_query(),
                            block_szx: block2.map(|b| b.szx),
                            connection_id,
                        };
                        shared.expire_observers();
                        let mut observers = lock(&shared.observers);
                        match observers.register(observer, Instant::now()) {
                            Registered::Added | Registered::Replaced => {
                                let seq = observers.next_sequence();
                                drop(observers);
                                response
                                    .options
                                    .push((codec::OPT_OBSERVE, codec::uint_option(seq)));
                                info!(
                                    "CoAP {peer_addr} now observes {path} decision={}",
                                    Decision::ObserveRegistered.as_str()
                                );
                            }
                            Registered::Full => {
                                drop(observers);
                                warn!(
                                    "CoAP {peer_addr} asked to observe {path}, but {} observers \
                                     are registered; served without Observe decision={}",
                                    observe::MAX_OBSERVERS,
                                    Decision::ObserveCapReached.as_str()
                                );
                            }
                            Registered::PeerFull => {
                                drop(observers);
                                warn!(
                                    "CoAP {peer_addr} asked to observe {path}, but its IP holds \
                                     {} observations; served without Observe decision={}",
                                    observe::MAX_OBSERVERS_PER_IP,
                                    Decision::ObservePeerCapReached.as_str()
                                );
                            }
                        }
                    } else {
                        info!(
                            "CoAP {peer_addr} asked to observe {path}; the model declined \
                             decision={}",
                            Decision::ObserveDeclined.as_str()
                        );
                    }
                }

                let szx = block2.map_or(codec::MAX_SZX, |b| b.szx);
                if !shared.fill_representation(&mut response, &rep, resource, block2, szx) {
                    let reply = spec_reply(
                        codec::CODE_BAD_OPTION,
                        Decision::SpecReply.as_str(),
                        format!(
                            "block {} is past the end of the representation",
                            block2.map_or(0, |b| b.num)
                        ),
                    );
                    send(reply).await;
                    return;
                }
                if let Some((_, last)) = upload {
                    response.options.push((codec::OPT_BLOCK1, last.encode()));
                }
                response
            }
        };

        send(message).await;
    }

    /// Interpret the model's structured answer.
    ///
    /// Fails closed: no usable action becomes 5.03 Service Unavailable, never a
    /// plausible-looking 2.05 with an empty body.
    fn outcome_from_results(
        request: &CoapMessage,
        results: &[ActionResult],
    ) -> (Decision, Outcome) {
        for result in results {
            let ActionResult::Custom { name, data } = result else {
                continue;
            };
            match name.as_str() {
                RESULT_RESPONSE => {
                    let code = data
                        .get("code")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(codec::CODE_INTERNAL_SERVER_ERROR as u64)
                        as u8;
                    let payload = data
                        .get("payload_hex")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .unwrap_or_default();
                    let content_format = data
                        .get("content_format")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u16);
                    // `execute_action` always writes it; absent only for a result built by
                    // hand, which is then an ordinary response that registers nobody.
                    let observable = data
                        .get("observable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    // A class-2 code is the model serving the resource; 4.xx and 5.xx are
                    // it refusing. `execute_action` has already rejected every other class.
                    let decision = if codec::code_class(code) == 2 {
                        Decision::ModelAnswer
                    } else {
                        Decision::ModelReject
                    };
                    return (
                        decision,
                        Outcome::Response {
                            code,
                            payload,
                            content_format,
                            observable,
                        },
                    );
                }
                RESULT_RESET => return (Decision::ModelReset, Outcome::Reset),
                RESULT_IGNORE => return (Decision::ModelSilent, Outcome::Ignore),
                _ => {}
            }
        }

        error!(
            "CoAP: no usable action returned for {} {}; answering 5.03 Service Unavailable",
            codec::method_name(request.code).unwrap_or("?"),
            request.uri_path()
        );
        (
            Decision::FailClosedNoAction,
            Outcome::Response {
                code: codec::CODE_SERVICE_UNAVAILABLE,
                payload: Vec::new(),
                content_format: None,
                observable: false,
            },
        )
    }
}

/// Why a request is being answered the way it is.
///
/// 5.03 Service Unavailable is what both fail-closed paths put on the wire, and it is also
/// a code the model may legitimately choose itself, so the three are indistinguishable to
/// the peer. The log carries the distinction instead, with stable tokens -
/// `decision=fail_closed_` finds every request the model did not actually answer. Mirrors
/// `src/server/radius/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// The model served the resource (a class-2 response).
    ModelAnswer,
    /// The model refused, with a class-4 or class-5 code of its choosing.
    ModelReject,
    /// The model chose a Reset - "this message makes no sense at all".
    ModelReset,
    /// The model chose to send nothing. A decision, not an absence of one.
    ModelSilent,
    /// The specification determined the reply; the model was never asked.
    SpecReply,
    /// The datagram was over `codec::MAX_MESSAGE_LEN` and was refused unread. A decision
    /// the server makes on its own, so not a `fail_closed_` — but loud, because it is the
    /// tag that says an oversize request never became a prompt.
    RefusedTooLarge,
    /// The LLM backend failed. Nobody decided anything.
    FailClosedLlmError,
    /// The model was asked and returned nothing this request could use.
    FailClosedNoAction,
    /// A Block1 block that is not the last: 2.31 Continue, decided by RFC 7959, not the model.
    UploadContinue,
    /// A later Block2 block served from the representation the model already gave.
    BlockCache,
    /// A GET with Observe 0 the model served with a 2.xx: the client is now an observer.
    ObserveRegistered,
    /// The model served an Observe registration but said the resource is not observable.
    ObserveDeclined,
    /// `observe::MAX_OBSERVERS` were registered, so a registration was served without Observe.
    ObserveCapReached,
    /// The peer's IP held `observe::MAX_OBSERVERS_PER_IP` registrations, so a registration
    /// was served without Observe.
    ObservePeerCapReached,
    /// A notification went out and the observation stands.
    Notified,
    /// An observation ended: deregistered, or a non-2.xx notification.
    ObservationEnded,
    /// A client answered a notification with RST (RFC 7641 §3.6).
    ObserverReset,
    /// A Confirmable notification was never acknowledged (RFC 7641 §4.5).
    ObserverTimeout,
    /// A registration went unconfirmed for `observe::OBSERVER_MAX_AGE`.
    ObserverExpired,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Decision::ModelAnswer => "model_answer",
            Decision::ModelReject => "model_reject",
            Decision::ModelReset => "model_reset",
            Decision::ModelSilent => "model_silent",
            Decision::SpecReply => "spec_reply",
            Decision::RefusedTooLarge => "refused_too_large",
            Decision::FailClosedLlmError => "fail_closed_llm_error",
            Decision::FailClosedNoAction => "fail_closed_no_action",
            Decision::UploadContinue => "upload_continue",
            Decision::BlockCache => "block_cache",
            Decision::ObserveRegistered => "observe_registered",
            Decision::ObserveDeclined => "observe_declined",
            Decision::ObserveCapReached => "observe_cap_reached",
            Decision::ObservePeerCapReached => "observe_peer_cap_reached",
            Decision::Notified => "notified",
            Decision::ObservationEnded => "observation_ended",
            Decision::ObserverReset => "observer_reset",
            Decision::ObserverTimeout => "observer_timeout",
            Decision::ObserverExpired => "observer_expired",
        }
    }

    fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Decision::FailClosedLlmError | Decision::FailClosedNoAction
        )
    }
}

/// What to put on the wire for a request.
enum Outcome {
    Response {
        code: u8,
        payload: Vec<u8>,
        content_format: Option<u16>,
        /// Whether an Observe registration this answers may stand.
        observable: bool,
    },
    Reset,
    Ignore,
}

/// What a request's Observe option asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObserveRequest {
    Register,
    Deregister,
}

impl ObserveRequest {
    fn as_str(self) -> &'static str {
        match self {
            ObserveRequest::Register => "register",
            ObserveRequest::Deregister => "deregister",
        }
    }
}
