//! Wake-on-LAN magic packet listener.
//!
//! # Wake-on-LAN has no response, and that shapes everything here
//!
//! A magic packet is one-way. A real target NIC that recognises its own MAC in the payload
//! pulls the machine's power up and says nothing at all — there is no acknowledgement frame,
//! no status code, no transaction id, nothing the sender waits for. AMD's original
//! "Magic Packet Technology" white paper defines a payload and a NIC behaviour; it defines no
//! protocol exchange.
//!
//! So a Wake-on-LAN *server* is a **listener**, and the model has no reply to author. What it
//! genuinely decides is: whether this packet is interesting (which MACs this host pretends to
//! know about), and what is recorded about it. Those are the two actions
//! (`record_wake_request`, `ignore_magic_packet`). A third, `announce_host_awake`, is
//! explicitly **not part of Wake-on-LAN** and is off unless the operator turns it on — see
//! `CLAUDE.md`.
//!
//! Because there is no reply, an LLM failure is naturally silent, and that silence is
//! protocol-correct rather than a defect. It must still be distinguishable after the fact from
//! a deliberate drop, so every datagram produces exactly one `decision=` line — see
//! [`WolServer::decision_tag`].
//!
//! # The one decoding subtlety
//!
//! The magic packet is 6 bytes of `0xFF` followed by the 6-byte target MAC repeated exactly 16
//! times (102 bytes), optionally followed by a 4- or 6-byte SecureON password. It may sit
//! **anywhere inside the datagram** — senders wrap it, pad it, or encapsulate a whole Ethernet
//! frame — so [`decode_magic_packet`] scans for the sync stream rather than assuming offset 0.

pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::WolProtocol;
use crate::state::app_state::AppState;
use crate::{console_debug, console_error, console_info, console_trace, console_warn};
use actions::WOL_MAGIC_PACKET_RECEIVED_EVENT;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

/// Bytes of `0xFF` that open a magic packet.
pub const SYNC_STREAM_LEN: usize = 6;

/// Length of an Ethernet MAC address.
pub const MAC_LEN: usize = 6;

/// How many times the target MAC is repeated. Exactly 16 — 15 is not a magic packet and
/// 17 is 16 followed by a stray six bytes.
pub const MAC_REPETITIONS: usize = 16;

/// 6 + 6*16 = 102 bytes.
pub const MAGIC_PACKET_LEN: usize = SYNC_STREAM_LEN + MAC_LEN * MAC_REPETITIONS;

/// The two SecureON password lengths defined by the vendors that implement it.
pub const SECURE_ON_PASSWORD_LENS: [usize; 2] = [4, 6];

/// EtherType assigned to Wake-on-LAN, as it appears in an Ethernet header.
const ETHERTYPE_WOL: [u8; 2] = [0x08, 0x42];

/// Bytes of Ethernet header preceding the payload: 6 destination + 6 source + 2 EtherType.
const ETHERNET_HEADER_LEN: usize = 14;

/// Largest datagram we will read. A magic packet is 102 bytes; the ceiling exists only so a
/// deliberately huge datagram cannot be used to make the scan expensive.
const RECV_BUFFER_LEN: usize = 2048;

/// How the magic packet reached us.
///
/// **Neither value means NetGet opened a raw socket** — it never does. See the
/// `EncapsulatedEthernet` docs and `CLAUDE.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The magic packet was the UDP payload (the ordinary case: ports 9 and 7).
    Udp,

    /// The UDP payload was itself a complete Ethernet frame whose EtherType is `0x0842`,
    /// with the magic packet as that frame's payload.
    ///
    /// This is what a relay or a capture-replay tool produces when it forwards the
    /// link-layer form of Wake-on-LAN over UDP. It is recognised by the two bytes
    /// immediately before the sync stream being `08 42` with a full 14-byte header in front
    /// of them — a precise structural check, not a guess.
    ///
    /// It is **not** the same thing as receiving a real EtherType `0x0842` frame off the
    /// wire: that needs a raw socket and NetGet's `wol` feature deliberately carries no
    /// packet-capture dependency.
    EncapsulatedEthernet,
}

impl Transport {
    /// The token used in the event's `transport` field and in the log.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::EncapsulatedEthernet => "ethernet",
        }
    }
}

/// A magic packet located inside a received datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicPacket {
    /// The target MAC, as the six raw bytes found on the wire.
    pub target_mac: [u8; MAC_LEN],

    /// Byte index of the first `0xFF` of the sync stream within the datagram.
    pub sync_offset: usize,

    /// 0, 4 or 6. See [`decode_magic_packet`] for when a trailer counts as a password.
    pub password_len: usize,

    /// How the packet was carried.
    pub transport: Transport,
}

impl MagicPacket {
    /// The target MAC formatted as `00:11:22:33:44:55`.
    ///
    /// The event never carries the raw bytes: models cannot reliably produce or parse them
    /// (see the action & event design rules in the root `CLAUDE.md`).
    pub fn mac_string(&self) -> String {
        self.target_mac
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Whether a SecureON password followed the magic packet.
    pub fn has_password(&self) -> bool {
        self.password_len > 0
    }
}

/// Find a magic packet anywhere inside `data`.
///
/// Returns the **first** offset at which a complete, fully-validated magic packet begins.
/// Scanning matters: a datagram may carry the packet at a non-zero offset, and a naive
/// "does it start with six 0xFF bytes" test both misses those and accepts near-misses.
///
/// # What is rejected
///
/// * fewer than 16 repetitions of the MAC (15 is the classic off-by-one, and is not a magic
///   packet — the NIC's pattern matcher requires all sixteen);
/// * a sync stream that is not exactly six `0xFF` bytes;
/// * any repetition that differs from the first by a single byte.
///
/// A candidate that fails validation does not end the scan: the search continues from the
/// next offset, because a datagram may contain a false sync stream before the real packet.
///
/// # SecureON password
///
/// SecureON is a vendor extension: 4 or 6 bytes appended after the 102. It is recognised
/// only when the trailing bytes run to the **end of the datagram** and number exactly 4 or 6.
/// Any other trailer length is reported as `password_len: 0` — with the packet anywhere in
/// the datagram there is no way to tell a password from padding, and claiming a password we
/// are not sure about would be worse than reporting none.
///
/// The password bytes themselves are deliberately not returned. Nothing here needs them, and
/// they must not reach the model as raw bytes.
pub fn decode_magic_packet(data: &[u8]) -> Option<MagicPacket> {
    if data.len() < MAGIC_PACKET_LEN {
        return None;
    }

    let last_possible_offset = data.len() - MAGIC_PACKET_LEN;
    for sync_offset in 0..=last_possible_offset {
        if data[sync_offset..sync_offset + SYNC_STREAM_LEN] != [0xFFu8; SYNC_STREAM_LEN] {
            continue;
        }

        let mac_start = sync_offset + SYNC_STREAM_LEN;
        let mut target_mac = [0u8; MAC_LEN];
        target_mac.copy_from_slice(&data[mac_start..mac_start + MAC_LEN]);

        // Repetition 0 is the MAC itself, so only 1..16 need comparing.
        let all_repetitions_match = (1..MAC_REPETITIONS).all(|repetition| {
            let start = mac_start + repetition * MAC_LEN;
            data[start..start + MAC_LEN] == target_mac
        });
        if !all_repetitions_match {
            continue;
        }

        let trailing = data.len() - (sync_offset + MAGIC_PACKET_LEN);
        let password_len = if SECURE_ON_PASSWORD_LENS.contains(&trailing) {
            trailing
        } else {
            0
        };

        // The EtherType sits in the two bytes immediately before the frame payload, and a
        // full Ethernet header must precede it.
        let transport = if sync_offset >= ETHERNET_HEADER_LEN
            && data[sync_offset - 2..sync_offset] == ETHERTYPE_WOL
        {
            Transport::EncapsulatedEthernet
        } else {
            Transport::Udp
        };

        return Some(MagicPacket {
            target_mac,
            sync_offset,
            password_len,
            transport,
        });
    }

    None
}

/// Wake-on-LAN magic packet listener.
pub struct WolServer;

impl WolServer {
    /// Bind the UDP socket and start listening for magic packets.
    ///
    /// Returns `Err` if the socket cannot be bound or a startup parameter is unusable, so
    /// `server_startup` sets `ServerStatus::Error` rather than showing a server that is
    /// "Running" and listening to nothing.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Propagated with `?`: an undeclared key or a wrong-typed value must fail the start
        // cleanly rather than panic the task (see the root CLAUDE.md on StartupParams).
        let allow_non_standard_ack = match startup_params {
            Some(ref params) => params
                .get_optional_bool("allow_non_standard_ack")?
                .unwrap_or(false),
            None => false,
        };

        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;

        info!(
            "Wake-on-LAN receive-only listener: magic packets are decoded, nothing is ever \
             sent back (non-standard announcements {})",
            if allow_non_standard_ack {
                "ENABLED"
            } else {
                "disabled"
            }
        );
        // Keep the address last in this line: the e2e harness recognises a bound server by
        // "listening on ADDR:PORT" and reads back from the end of it.
        console_info!(status_tx, "Wake-on-LAN listening on {}", local_addr);
        if allow_non_standard_ack {
            console_warn!(
                status_tx,
                "Wake-on-LAN: allow_non_standard_ack=true - announce_host_awake will put \
                 datagrams on the network. This is NOT part of Wake-on-LAN"
            );
        }

        let protocol = Arc::new(WolProtocol::new());

        let task_registrar = app_state.clone();
        let listen_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; RECV_BUFFER_LEN];

            loop {
                let (n, peer_addr) = match socket.recv_from(&mut buffer).await {
                    Ok(received) => received,
                    Err(e) => {
                        console_error!(status_tx, "Wake-on-LAN receive error: {}", e);
                        break;
                    }
                };

                // Guarded, because `console_trace!` renders its arguments and pushes a line
                // onto the *unbounded* status channel whatever the level is set to. Port 9 is
                // the discard port: this runs once per stray datagram from every scanner on
                // the segment, and per-datagram work on an unbounded channel is what the root
                // CLAUDE.md warns against.
                if tracing::enabled!(tracing::Level::TRACE) {
                    console_trace!(
                        status_tx,
                        "Wake-on-LAN read {} bytes from {}: {}",
                        n,
                        peer_addr,
                        hex_summary(&buffer[..n])
                    );
                }

                // Port 9 is the discard port and attracts scanners and stray traffic. A
                // datagram that is not a magic packet raises no event and costs no LLM call
                // - it is not something the model can decide anything about.
                let Some(packet) = decode_magic_packet(&buffer[..n]) else {
                    console_debug!(
                        status_tx,
                        "Wake-on-LAN discarded {} bytes from {}: not a magic packet (needs \
                         6x0xFF then the same MAC 16 times = {} bytes, at any offset)",
                        n,
                        peer_addr,
                        MAGIC_PACKET_LEN
                    );
                    continue;
                };

                let target_mac = packet.mac_string();
                console_info!(
                    status_tx,
                    "Wake-on-LAN magic packet for {} from {} (offset {}, {}, password_length={})",
                    target_mac,
                    peer_addr,
                    packet.sync_offset,
                    packet.transport.as_str(),
                    packet.password_len
                );

                // A "connection" here is a recent sender, kept for the dashboard's counters
                // only. The protocol declares `.connectionless()`, so the 10-second idle
                // sweep is what removes these; nothing else ever closes them.
                let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
                {
                    use crate::state::server::{
                        ConnectionState as ServerConnectionState, ConnectionStatus,
                        ProtocolConnectionInfo,
                    };
                    let now = crate::utils::clock::Instant::now();
                    let conn_state = ServerConnectionState {
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
                    };
                    app_state
                        .add_connection_to_server(server_id, conn_state)
                        .await;
                }
                let _ = status_tx.send("__UPDATE_UI__".to_string());

                let llm_clone = llm_client.clone();
                let state_clone = app_state.clone();
                let status_clone = status_tx.clone();
                let protocol_clone = protocol.clone();

                // Tracked, not detached: stop_server must abort this task too.
                let task_owner = app_state.clone();
                task_owner
                    .spawn_server_task(server_id, async move {
                        let event = Event::new(
                            &WOL_MAGIC_PACKET_RECEIVED_EVENT,
                            serde_json::json!({
                                "target_mac": target_mac,
                                "source_address": peer_addr.to_string(),
                                "has_password": packet.has_password(),
                                "password_length": packet.password_len,
                                "transport": packet.transport.as_str(),
                                "sync_offset": packet.sync_offset,
                            }),
                        );

                        match call_llm(
                            &llm_clone,
                            &state_clone,
                            server_id,
                            Some(connection_id),
                            &event,
                            protocol_clone.as_ref(),
                        )
                        .await
                        {
                            Ok(execution_result) => {
                                for message in &execution_result.messages {
                                    Log::to(&status_clone).info(message);
                                }

                                let decision = Self::decision_tag(&execution_result);
                                info!(
                                    "Wake-on-LAN magic packet for {} from {} decision={} \
                                 ({} action(s), {} failed)",
                                    target_mac,
                                    peer_addr,
                                    decision,
                                    execution_result.raw_actions.len(),
                                    execution_result.failures.len()
                                );
                                let _ = status_clone.send(format!(
                                    "[INFO] Wake-on-LAN {} from {} decision={}",
                                    target_mac, peer_addr, decision
                                ));

                                Self::process_announcements(
                                    &execution_result.raw_actions,
                                    allow_non_standard_ack,
                                    peer_addr,
                                    &target_mac,
                                    &status_clone,
                                )
                                .await;
                            }
                            Err(e) => {
                                // Nothing goes on the wire, and that is protocol-correct rather
                                // than a compromise: Wake-on-LAN defines no reply of any kind, so
                                // there is no error form to send and no peer waiting for one.
                                // What must NOT happen is that this silence looks identical to a
                                // deliberate `ignore_magic_packet` afterwards - hence the
                                // distinct tag, and the category split so an overload is
                                // distinguishable from a hard failure.
                                let category = crate::utils::WireFailure::classify(&e);
                                let category_tag = if category.is_overloaded() {
                                    "overloaded"
                                } else {
                                    "unavailable"
                                };
                                error!(
                                    "Wake-on-LAN magic packet for {} from {} \
                                 decision=fail_closed_llm_error category={} \
                                 (no reply possible: Wake-on-LAN defines no response): {}",
                                    target_mac, peer_addr, category_tag, e
                                );
                                let _ = status_clone.send(format!(
                                    "✗ Wake-on-LAN {} from {} decision=fail_closed_llm_error \
                                 category={}: {}",
                                    target_mac, peer_addr, category_tag, e
                                ));
                            }
                        }
                    })
                    .await;
            }
        });

        task_registrar
            .register_server_task(server_id, listen_handle)
            .await;

        Ok(local_addr)
    }

    /// Classify what the model decided about one magic packet, for the log.
    ///
    /// Wake-on-LAN cannot answer its sender, so "the model recognised the host", "the model
    /// dropped it", "the model said nothing" and "the LLM call failed" are all indis-
    /// tinguishable on the wire — all four are silence. They must not be indistinguishable in
    /// the log as well: the first two are decisions, the last two are NetGet failing to make
    /// one. The failure case is tagged at the call site as `decision=fail_closed_llm_error`;
    /// this covers the three successful-call outcomes.
    ///
    /// The tokens are stable so an operator can grep `decision=model_silent` and
    /// `decision=fail_closed_llm_error` for every packet NetGet did not really handle.
    fn decision_tag(result: &crate::llm::ExecutionResult) -> &'static str {
        let mut recognised = false;
        let mut ignored = false;

        for action in &result.raw_actions {
            match action.get("type").and_then(|v| v.as_str()) {
                Some(actions::RECORD_WAKE_REQUEST) | Some(actions::ANNOUNCE_HOST_AWAKE) => {
                    recognised = true
                }
                Some(actions::IGNORE_MAGIC_PACKET) => ignored = true,
                // Generic actions (notify_operator, update_instruction, …) say nothing about
                // this packet, so they do not count as a decision either way.
                _ => {}
            }
        }

        if recognised {
            "model_accept"
        } else if ignored {
            "model_reject"
        } else {
            // The call succeeded but produced nothing that decides the packet - either no
            // actions at all, or only generic ones. Dropping it is what happens anyway, but
            // it was not a decision.
            "model_silent"
        }
    }

    /// Perform any `announce_host_awake` actions the model returned.
    ///
    /// This is the only path in the whole protocol that puts bytes on the network, and it is
    /// **not part of Wake-on-LAN**. It runs here rather than in `execute_action` for two
    /// reasons: the gate (`allow_non_standard_ack`) is a per-server startup parameter that
    /// the stateless protocol struct cannot see, and the default destination is the magic
    /// packet's own source address, which only this loop knows.
    ///
    /// `WolProtocol::execute_action` therefore validates the action and returns
    /// `ActionResult::NoAction`; the send happens exactly once, here.
    async fn process_announcements(
        raw_actions: &[serde_json::Value],
        allow_non_standard_ack: bool,
        peer_addr: SocketAddr,
        target_mac: &str,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        for action in raw_actions {
            if action.get("type").and_then(|v| v.as_str()) != Some(actions::ANNOUNCE_HOST_AWAKE) {
                continue;
            }

            if !allow_non_standard_ack {
                warn!(
                    "Wake-on-LAN refused announce_host_awake for {}: it is not part of \
                     Wake-on-LAN and allow_non_standard_ack is false (the default). Nothing \
                     was sent",
                    target_mac
                );
                console_warn!(
                    status_tx,
                    "Wake-on-LAN refused announce_host_awake for {}: start the server with \
                     allow_non_standard_ack=true to enable it",
                    target_mac
                );
                continue;
            }

            match Self::send_announcement(action, peer_addr, target_mac).await {
                Ok((destination, bytes)) => {
                    info!(
                        "Wake-on-LAN sent a NON-STANDARD awake announcement for {} to {} \
                         ({} bytes)",
                        target_mac, destination, bytes
                    );
                    console_info!(
                        status_tx,
                        "→ Wake-on-LAN announced {} awake to {} (non-standard)",
                        target_mac,
                        destination
                    );
                }
                Err(e) => {
                    error!(
                        "Wake-on-LAN announce_host_awake for {} failed: {}",
                        target_mac, e
                    );
                    console_error!(
                        status_tx,
                        "✗ Wake-on-LAN announce_host_awake for {} failed: {}",
                        target_mac,
                        e
                    );
                }
            }
        }
    }

    /// Send one awake announcement, returning the destination and the byte count.
    async fn send_announcement(
        action: &serde_json::Value,
        peer_addr: SocketAddr,
        target_mac: &str,
    ) -> Result<(SocketAddr, usize)> {
        let destination = match action.get("announce_to").and_then(|v| v.as_str()) {
            Some(target) => actions::resolve_announce_target(target)?,
            // No destination given: answer the machine that sent the magic packet. This is
            // the "simulated acknowledgement" shape, and it is still non-standard.
            None => peer_addr,
        };

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("netget-wol: host {} is awake", target_mac));

        let bind_addr = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        let sent = socket.send_to(message.as_bytes(), destination).await?;

        trace!("Wake-on-LAN announcement to {}: {:?}", destination, message);

        Ok((destination, sent))
    }
}

/// A short hex rendering of a datagram, for TRACE logging only.
///
/// Never reaches the model — the event carries structured fields, never bytes.
fn hex_summary(data: &[u8]) -> String {
    const MAX: usize = 64;
    let shown = data.len().min(MAX);
    let mut out = String::with_capacity(shown * 2 + 16);
    for byte in &data[..shown] {
        out.push_str(&format!("{:02x}", byte));
    }
    if data.len() > shown {
        out.push_str(&format!("… (+{} bytes)", data.len() - shown));
    }
    out
}
