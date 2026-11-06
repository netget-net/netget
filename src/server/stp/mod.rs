//! STP / RSTP (IEEE 802.1D-2004 / 802.1w) bridge server.
//!
//! NetGet owns the wire; the model owns every bridge parameter. There is **no spanning tree
//! state machine here**: nothing elects a root, nothing ages a timer, nothing transmits on its
//! own. A BPDU arrives, it is decoded into structured fields, an event is raised, and whatever
//! the operator's handler or the model answers is encoded and put back on the wire. That is
//! deliberate — the interesting and dangerous decision in this protocol is *which bridge
//! priority to claim*, and that is exactly the decision this server delegates.
//!
//! # Two transports
//!
//! * [`StpTransport::Raw`] — real 802.3 LLC frames through libpcap, filtered to the Bridge
//!   Group Address. Needs `CAP_NET_RAW` (Linux) or `/dev/bpf*` access (macOS/BSD). **This path
//!   has never been executed**: nothing in this tree runs privileged. See
//!   `src/server/stp/CLAUDE.md`.
//! * [`StpTransport::Udp`] — one complete 802.3 frame per UDP datagram. The frame is
//!   byte-identical to what the raw transport would emit, so the codec, the event, the
//!   handler/LLM dispatch and the response encoding are all the real ones; only the link layer
//!   is simulated. This is what makes the decision path testable without root, the same
//!   compromise `ospf` documents.
//!
//! # On failure, silence
//!
//! STP is in the deliberately-silent class, and its case is among the strongest in the tree.
//! Every BPDU this server can emit is a *positive assertion about topology* — "the root is X",
//! "the topology changed" — and a fabricated one does not merely mislead a peer, it can make
//! every switch on the segment recompute the spanning tree and stop forwarding while it does.
//! There is no error BPDU to send instead. So when the LLM call fails, **nothing goes on the
//! wire** and the failure is recorded in the log with a `decision=` tag, the way
//! `src/server/radius/` separates its cases. Nothing derived from the error ever reaches a
//! frame.

pub mod actions;
pub mod codec;

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::{console_debug, console_error, console_info, console_trace};
use actions::{
    StpBridgeConfig, StpProtocol, StpTransport, STP_BPDU_RECEIVED_EVENT, STP_TOPOLOGY_CHANGE_EVENT,
};

/// Where a response frame goes.
///
/// The pcap arm uses a Tokio channel rather than `std::sync::mpsc` on purpose: the sender is
/// held across an `.await` in [`Responder::send`], and `std::sync::mpsc::Sender` is `Send` but
/// not `Sync`, which would make every task holding one non-`Send` and refuse to compile under
/// `tokio::spawn`.
#[derive(Clone)]
enum Responder {
    Udp {
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
    },
    Pcap(mpsc::UnboundedSender<Vec<u8>>),
}

impl Responder {
    async fn send(&self, frame: Vec<u8>) -> Result<()> {
        match self {
            Responder::Udp { socket, peer } => {
                socket
                    .send_to(&frame, peer)
                    .await
                    .with_context(|| format!("failed to send STP frame to {peer}"))?;
                Ok(())
            }
            Responder::Pcap(tx) => tx
                .send(frame)
                .map_err(|_| anyhow!("STP injection thread has exited")),
        }
    }

    fn describe(&self) -> String {
        match self {
            Responder::Udp { peer, .. } => peer.to_string(),
            Responder::Pcap(_) => "the segment".to_string(),
        }
    }
}

/// STP / RSTP server.
pub struct StpServer;

impl StpServer {
    /// Start the server on whichever transport the configuration selects.
    ///
    /// Returns only once the transport is genuinely up — the UDP socket bound, or the pcap
    /// handle and its BPF filter open — so a failure lands in `ServerStatus::Error` instead of
    /// a server that reports `Running` while receiving nothing. That is the ARP/DataLink/ICMP
    /// fire-and-forget defect the root `CLAUDE.md` records; this protocol is written to avoid
    /// it rather than to be fixed for it later.
    pub async fn spawn_with_llm_actions(
        interface: Option<String>,
        listen_addr: SocketAddr,
        config: StpBridgeConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        // Fail before binding anything if the configured identity cannot be put on the wire.
        config.bridge_id()?;
        config.port_id()?;

        match config.transport {
            StpTransport::Udp => {
                Self::spawn_udp(
                    listen_addr,
                    config,
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                )
                .await
            }
            StpTransport::Raw => {
                let interface = interface
                    .context("STP raw transport requires a network interface (e.g. eth0, en0)")?;
                Self::spawn_raw(
                    interface,
                    listen_addr,
                    config,
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                )
                .await
            }
        }
    }

    // -----------------------------------------------------------------------
    // UDP transport
    // -----------------------------------------------------------------------

    async fn spawn_udp(
        listen_addr: SocketAddr,
        config: StpBridgeConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("failed to bind STP UDP transport to {listen_addr}"))?,
        );
        let local_addr = socket.local_addr()?;
        console_info!(
            status_tx,
            "STP server listening on {} (UDP transport: one complete 802.3 BPDU frame per datagram)",
            local_addr
        );

        let protocol = Arc::new(StpProtocol::new());
        let config = Arc::new(config);
        let task_registrar = app_state.clone();

        let recv_socket = socket.clone();
        let accept_handle = tokio::spawn(async move {
            // A padded BPDU frame is 60 octets; anything larger is not a BPDU, but read a full
            // Ethernet MTU so an oversized datagram is rejected by the decoder with a real
            // message rather than silently truncated into something that parses.
            let mut buffer = vec![0u8; 2048];
            loop {
                match recv_socket.recv_from(&mut buffer).await {
                    Ok((n, peer)) => {
                        let frame = buffer[..n].to_vec();
                        console_debug!(status_tx, "STP received {} byte frame from {}", n, peer);
                        console_trace!(status_tx, "STP frame (hex): {}", hex::encode(&frame));

                        let responder = Responder::Udp {
                            socket: socket.clone(),
                            peer,
                        };
                        let llm = llm_client.clone();
                        let state = app_state.clone();
                        let status = status_tx.clone();
                        let proto = protocol.clone();
                        let cfg = config.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_frame(
                                    frame, llm, state, status, proto, cfg, responder, server_id,
                                )
                                .await;
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "STP UDP receive error: {}", e);
                        break;
                    }
                }
            }
            warn!("STP UDP receive loop terminated");
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    // -----------------------------------------------------------------------
    // Raw 802.3 transport
    // -----------------------------------------------------------------------

    /// NEVER EXECUTED in this tree — needs `CAP_NET_RAW` / `/dev/bpf*`. Written to the same
    /// shape as `arp` and `isis`, including the readiness handshake and the cooperative stop.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_raw(
        interface: String,
        listen_addr: SocketAddr,
        config: StpBridgeConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        use pcap::{Capture, Device};

        console_info!(
            status_tx,
            "Starting STP capture on interface: {}",
            interface
        );

        let status_tx_ready = status_tx.clone();
        let protocol = Arc::new(StpProtocol::new());
        let config = Arc::new(config);

        // Opening the capture is the privileged step, so it must not be fire-and-forget: the
        // outcome comes back over this oneshot and `spawn` only returns Ok once the handle and
        // its filter are genuinely live.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in `next_packet()`, so the
        // capture loop is stopped cooperatively.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();
        let app_state_reg = app_state.clone();

        let interface_clone = interface.clone();
        tokio::task::spawn_blocking(move || {
            let open_captures = || -> Result<(Capture<pcap::Active>, Capture<pcap::Active>)> {
                let device = Device::list()
                    .context("failed to list capture devices")?
                    .into_iter()
                    .find(|d| d.name == interface_clone)
                    .with_context(|| format!("no such capture device '{interface_clone}'"))?;

                let mut cap_rx = Capture::from_device(device.clone())
                    .map(|c| c.promisc(true).snaplen(65535).timeout(1000))
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!(
                            "failed to open pcap capture on '{interface_clone}' (needs root, or \
                             read access to /dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux)"
                        )
                    })?;

                // Only frames addressed to the Bridge Group Address. Without the filter every
                // frame on the segment would be handed to the decoder, so a failure here has
                // to refuse the start rather than fall through.
                //
                // `ether dst` needs an Ethernet link layer, so this fails on loopback
                // (DLT_NULL/DLT_LOOP), tunnels and raw-IP devices — which is correct: there is
                // no bridged segment there and a spanning tree server would sit in Running
                // having seen nothing. Same trap `arp` and `isis` document.
                cap_rx
                    .filter("ether dst 01:80:c2:00:00:00", true)
                    .with_context(|| {
                        format!(
                            "failed to apply the BPDU BPF filter on '{interface_clone}'. BPDUs \
                             are 802.3 frames addressed to the Bridge Group Address, so this \
                             fails on any interface with no Ethernet link layer — loopback \
                             (lo/lo0), tunnels and raw-IP devices carry no spanning tree. Point \
                             this server at a real Ethernet interface, or use \
                             startup_params.transport = \"udp\"."
                        )
                    })?;

                let cap_tx = Capture::from_device(device)
                    .map(|c| c.promisc(true).snaplen(65535).timeout(1000))
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!("failed to open pcap injection handle on '{interface_clone}'")
                    })?;

                Ok((cap_rx, cap_tx))
            };

            let (mut cap_rx, mut cap_tx) = match open_captures() {
                Ok(handles) => {
                    let _ = ready_tx.send(Ok(()));
                    handles
                }
                Err(e) => {
                    console_error!(status_tx, "STP capture startup failed: {:#}", e);
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            let runtime = tokio::runtime::Handle::current();
            let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<Vec<u8>>();

            // Injection runs on its own thread because `sendpacket` blocks.
            std::thread::spawn(move || {
                while let Some(frame) = packet_rx.blocking_recv() {
                    if let Err(e) = cap_tx.sendpacket(frame) {
                        error!("STP failed to inject frame: {}", e);
                    }
                }
            });

            loop {
                if stop_in_loop.is_stopped() {
                    console_info!(status_tx, "STP capture on {} stopping", interface_clone);
                    break;
                }
                match cap_rx.next_packet() {
                    Ok(packet) => {
                        let frame = packet.data.to_vec();
                        console_debug!(
                            status_tx,
                            "STP captured {} byte frame on {}",
                            frame.len(),
                            interface_clone
                        );
                        console_trace!(status_tx, "STP frame (hex): {}", hex::encode(&frame));

                        let responder = Responder::Pcap(packet_tx.clone());
                        let llm = llm_client.clone();
                        let state = app_state.clone();
                        let status = status_tx.clone();
                        let proto = protocol.clone();
                        let cfg = config.clone();
                        runtime.spawn(async move {
                            Self::handle_frame(
                                frame, llm, state, status, proto, cfg, responder, server_id,
                            )
                            .await;
                        });
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        console_error!(status_tx, "STP packet capture error: {}", e);
                        break;
                    }
                }
            }

            // Dropping the last sender ends the injection thread and closes its handle.
            drop(packet_tx);
            drop(cap_rx);
        });

        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow!(
                    "STP capture task on '{}' exited before signalling readiness",
                    interface
                ))
            }
        }

        app_state_reg
            .register_server_task(server_id, stop.park_task())
            .await;

        console_info!(status_tx_ready, "STP capture active on {}", interface);

        // The raw transport binds no socket, so there is no address to report; port 0 is how
        // `server_startup` recognises that.
        Ok(listen_addr)
    }

    // -----------------------------------------------------------------------
    // Frame -> event
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn handle_frame(
        frame: Vec<u8>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<StpProtocol>,
        config: Arc<StpBridgeConfig>,
        responder: Responder,
        server_id: crate::state::ServerId,
    ) {
        let decoded = match codec::decode_frame(&frame) {
            Ok(decoded) => decoded,
            Err(e) => {
                console_debug!(status_tx, "STP ignoring frame: {:#}", e);
                return;
            }
        };

        let bpdu = match codec::Bpdu::decode(&decoded.payload) {
            Ok(bpdu) => bpdu,
            Err(e) => {
                console_debug!(status_tx, "STP ignoring malformed BPDU: {:#}", e);
                return;
            }
        };

        let source_mac = codec::format_mac(&decoded.source);
        let destination_mac = codec::format_mac(&decoded.destination);

        let (event_type, mut data) = match &bpdu {
            codec::Bpdu::TopologyChangeNotification => {
                let data = serde_json::json!({
                    "bpdu_type": "topology_change_notification",
                    "protocol_version": "stp",
                    "is_rstp": false,
                    "is_tcn": true,
                    "source_mac": source_mac,
                    "destination_mac": destination_mac,
                    "change_reason": "tcn_bpdu",
                });
                (&*STP_TOPOLOGY_CHANGE_EVENT, data)
            }
            codec::Bpdu::Config(config_bpdu) => {
                let mut data = serde_json::json!({
                    "bpdu_type": if config_bpdu.is_rstp() { "rst" } else { "configuration" },
                    "protocol_version": version_name(config_bpdu.version),
                    "is_rstp": config_bpdu.is_rstp(),
                    "is_tcn": false,
                    "source_mac": source_mac,
                    "destination_mac": destination_mac,
                    "root_bridge_mac": config_bpdu.root.mac_string(),
                    "root_priority": config_bpdu.root.priority,
                    "root_system_id_extension": config_bpdu.root.system_id_extension,
                    "root_path_cost": config_bpdu.root_path_cost,
                    "bridge_mac": config_bpdu.bridge.mac_string(),
                    "bridge_priority": config_bpdu.bridge.priority,
                    "bridge_system_id_extension": config_bpdu.bridge.system_id_extension,
                    "port_priority": config_bpdu.port.priority,
                    "port_number": config_bpdu.port.number,
                    "flags": {
                        "topology_change": config_bpdu.flags.topology_change,
                        "topology_change_ack": config_bpdu.flags.topology_change_ack,
                        "proposal": config_bpdu.flags.proposal,
                        "agreement": config_bpdu.flags.agreement,
                        "learning": config_bpdu.flags.learning,
                        "forwarding": config_bpdu.flags.forwarding,
                        "port_role": config_bpdu.flags.port_role.as_str(),
                    },
                    "message_age": config_bpdu.message_age_seconds,
                    "max_age": config_bpdu.max_age_seconds,
                    "hello_time": config_bpdu.hello_time_seconds,
                    "forward_delay": config_bpdu.forward_delay_seconds,
                });
                if config_bpdu.flags.topology_change {
                    if let Some(obj) = data.as_object_mut() {
                        obj.insert(
                            "change_reason".to_string(),
                            serde_json::json!("topology_change_flag"),
                        );
                    }
                    (&*STP_TOPOLOGY_CHANGE_EVENT, data)
                } else {
                    (&*STP_BPDU_RECEIVED_EVENT, data)
                }
            }
        };

        // Attach this bridge's own configuration so the model can compare what arrived with
        // what it is configured to claim — which is the entire root-election question.
        if let (Some(target), Some(local)) = (
            data.as_object_mut(),
            config.local_summary().as_object().cloned(),
        ) {
            for (key, value) in local {
                target.insert(key, value);
            }
        }

        info!(
            "STP {} from {} (root {}, cost {})",
            data.get("bpdu_type")
                .and_then(|v| v.as_str())
                .unwrap_or("bpdu"),
            data.get("source_mac")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            data.get("root_bridge_mac")
                .and_then(|v| v.as_str())
                .unwrap_or("n/a"),
            data.get("root_path_cost")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        );

        let event = Event::new(event_type, data);
        Self::dispatch_event(
            event, llm_client, app_state, status_tx, protocol, config, responder, server_id,
        )
        .await;
    }

    /// Ask the operator's handler or the model what to answer, and put exactly that — or
    /// nothing — on the wire.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_event(
        event: Event,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<StpProtocol>,
        config: Arc<StpBridgeConfig>,
        responder: Responder,
        server_id: crate::state::ServerId,
    ) {
        let event_id = event.event_type.id.clone();

        // Whether to take part in a spanning tree at all — and with what priority — is policy,
        // not something the received BPDU determines. With no operator policy (no instruction
        // and no handler) the safe answer is to observe and say nothing, and to do that
        // *without* an LLM round-trip per BPDU: a busy segment carries one every two seconds
        // per port.
        if !operator_wants_dynamic(&app_state, server_id, &event_id).await {
            debug!(
                "STP decision=no_policy: {} observed, no operator policy configured (no \
                 instruction and no handler), nothing transmitted and no LLM call",
                event_id
            );
            let _ = status_tx.send(format!(
                "STP decision=no_policy: {} observed passively (no policy configured, no LLM)",
                event_id
            ));
            return;
        }

        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            None,
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                for message in &execution_result.messages {
                    Log::to(&status_tx).info(message);
                }

                let mut frames_sent = 0usize;
                for result in execution_result.protocol_results {
                    let crate::llm::actions::protocol_trait::ActionResult::Custom { name, data } =
                        &result
                    else {
                        continue;
                    };
                    if name.as_str() != "stp_action" {
                        continue;
                    }

                    match Self::frame_from_action(&config, data) {
                        Ok(frame) => match responder.send(frame.clone()).await {
                            Ok(()) => {
                                frames_sent += 1;
                                debug!(
                                    "STP sent {} byte frame to {}",
                                    frame.len(),
                                    responder.describe()
                                );
                                trace!("STP sent (hex): {}", hex::encode(&frame));
                                let _ = status_tx.send(format!(
                                    "[DEBUG] STP sent {} byte frame to {}",
                                    frame.len(),
                                    responder.describe()
                                ));
                            }
                            Err(e) => {
                                error!("STP transmit failed: {:#}", e);
                                let _ = status_tx.send(format!("✗ STP transmit failed: {:#}", e));
                            }
                        },
                        Err(e) => {
                            // A BPDU we cannot build is a BPDU we must not approximate.
                            error!("STP could not build the requested BPDU: {:#}", e);
                            let _ = status_tx.send(format!(
                                "✗ STP decision=model_invalid: could not build the requested \
                                 BPDU, nothing transmitted: {:#}",
                                e
                            ));
                        }
                    }
                }

                if frames_sent == 0 {
                    // Nothing went out. STP has no error or NAK BPDU, so an explicit refusal,
                    // an empty answer and a build failure are all identical on the wire; the
                    // decision tag is the only place the difference survives.
                    let model_rejected = execution_result
                        .raw_actions
                        .iter()
                        .any(|a| a.get("type").and_then(|t| t.as_str()) == Some("no_bpdu"));
                    let decision = if model_rejected {
                        "model_reject"
                    } else {
                        "model_silent"
                    };
                    info!(
                        "STP {} answered with no BPDU: decision={} (STP has no error BPDU; \
                         staying silent is the protocol-correct response)",
                        event_id, decision
                    );
                    let _ = status_tx.send(format!(
                        "STP decision={}: {} answered with no BPDU",
                        decision, event_id
                    ));
                }
            }
            Err(e) => {
                // FAIL CLOSED, AND CLOSED MEANS SILENT. Every BPDU is a positive assertion
                // about topology: a configuration BPDU claims a root, a TCN claims something
                // changed. Emitting one to signal "netget is broken" would make the segment
                // re-converge on a bridge that cannot back the claim — strictly worse for the
                // network than silence, which every receiver already handles through its own
                // max-age timer. Nothing derived from `e` goes anywhere near a frame; it is
                // classified only to keep an overloaded backend distinguishable from a broken
                // one in the operator's log.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "STP decision={}: LLM call failed for {}, no BPDU transmitted (STP has no \
                     failure BPDU and a fabricated one can re-converge the segment): {}",
                    decision, event_id, e
                );
                let _ = status_tx.send(format!(
                    "✗ STP decision={}: {} unanswered ({}), nothing transmitted: {}",
                    decision,
                    event_id,
                    category.text(),
                    e
                ));
            }
        }
    }

    /// Turn one validated action into a complete 802.3 frame.
    ///
    /// The operator's configured identity is layered in first, so a model that names only
    /// `root_priority` still emits a BPDU carrying this bridge's MAC, port and timers.
    fn frame_from_action(config: &StpBridgeConfig, data: &serde_json::Value) -> Result<Vec<u8>> {
        let action_type = data
            .get("type")
            .and_then(|v| v.as_str())
            .context("STP action has no 'type'")?;

        match action_type {
            "send_stp_bpdu" => {
                let mut data = data.clone();
                config.apply_defaults(&mut data);
                let destination = StpProtocol::destination_from_action(&data)?;
                let source = StpProtocol::source_from_action(&data, config.bridge_mac)?;
                let body = StpProtocol::config_bpdu_from_action(&data)?.encode()?;
                codec::encode_frame(destination, source, &body)
            }
            "send_stp_tcn" => {
                let destination = StpProtocol::destination_from_action(data)?;
                let source = StpProtocol::source_from_action(data, config.bridge_mac)?;
                codec::encode_frame(destination, source, &codec::encode_tcn_bpdu())
            }
            other => bail!("unknown STP action '{other}'"),
        }
    }
}

fn version_name(version: u8) -> String {
    match version {
        codec::VERSION_STP => "stp".to_string(),
        codec::VERSION_RSTP => "rstp".to_string(),
        other => other.to_string(),
    }
}

/// True when the operator opted into dynamic (handler- or LLM-driven) responses for this
/// server: a non-empty instruction, or an event handler matching `event_id`.
///
/// When false the server observes and never consults the model. Sending a BPDU is a policy
/// decision with real consequences for somebody's network, and there is no policy to apply.
async fn operator_wants_dynamic(
    state: &AppState,
    server_id: crate::state::ServerId,
    event_id: &str,
) -> bool {
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
