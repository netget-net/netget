//! TFTP server implementation
pub mod actions;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::error;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::TftpProtocol;
use crate::state::app_state::AppState;
use actions::{
    TFTP_ACK_RECEIVED_EVENT, TFTP_DATA_BLOCK_EVENT, TFTP_READ_REQUEST_EVENT,
    TFTP_WRITE_REQUEST_EVENT,
};

/// RFC 1350 opcodes. Named rather than spelled as literals at each comparison, because the
/// read continuation used to test a packet's *length* where it meant to test its opcode.
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

/// How many consecutive `recv_from` failures on the main socket are tolerated before the
/// accept loop gives up.
///
/// One error is routine on UDP: an ICMP port-unreachable provoked by a datagram we sent to a
/// client that has gone away is delivered as an error on the *next* receive. A permanent one
/// is not, and `continue`ing on it turns this loop into a busy-wait that also floods the
/// unbounded status channel.
const MAX_CONSECUTIVE_SOCKET_ERRORS: u32 = 64;

/// Transfer ID (client address + transaction ID port)
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct TransferId {
    client_addr: SocketAddr,
}

impl TransferId {
    fn new(client_addr: SocketAddr) -> Self {
        Self { client_addr }
    }
}

/// TFTP transfer operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TftpOperation {
    Read,  // Server sends DATA, receives ACK
    Write, // Server receives DATA, sends ACK
}

/// Transfer state
#[allow(dead_code)]
struct TftpTransfer {
    transfer_id: TransferId,
    operation: TftpOperation,
    filename: String,
    mode: String,
    current_block: u16,
    connection_id: ConnectionId,
    server_socket: Arc<UdpSocket>, // Unique socket for this transfer (TID)
}

/// RFC 1350's block size. A DATA block shorter than this is the last one.
pub const BLOCK_SIZE: usize = 512;

/// How long to wait for the peer's answer to a packet before sending the packet again.
///
/// RFC 1350 §2: "If a packet gets lost in the network, the intended recipient will timeout
/// and may retransmit his last packet". A server that sends each DATA block once loses the
/// transfer to one dropped datagram.
const RETRANSMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How many times one packet is sent before the transfer is given up: the first send and
/// five retransmissions, twelve seconds of silence in all.
const MAX_SENDS: u32 = 6;

/// The `ActionResult::Custom` name `send_tftp_file` produces; `data.hex` carries the file.
pub const FILE_RESULT: &str = "tftp_file";

/// The ERROR a client gets when a step of its transfer was answered with nothing usable.
///
/// Code 0 ("not defined, see error message"), a fixed message, and the transfer ends: the
/// alternative is the client retransmitting into a socket nobody reads until its own timeout.
const UNANSWERED_MESSAGE: &str = "Request not answered by server";

/// Encode file bytes for a `netascii` transfer (RFC 1350 §5, RFC 764): every line ends in
/// CR LF, and a CR that does not end a line is sent as CR NUL. Text written with `\n` (or
/// `\r\n`) line endings comes out the same; a client in netascii mode decodes it back to its
/// own line ending.
pub fn netascii_encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 16);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            b'\r' => out.extend_from_slice(b"\r\0"),
            b'\n' => out.extend_from_slice(b"\r\n"),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// What a model's answer to one read step sends.
enum ReadAnswer {
    /// `send_tftp_file`: the whole file, which NetGet then sends block by block.
    File(Vec<u8>),
    /// One DATA or ERROR packet.
    Packet(Vec<u8>),
    Nothing,
}

/// One datagram from a transfer's peer, or why there is none.
enum Received {
    Packet(Vec<u8>),
    TimedOut,
    Failed,
}

/// Everything one transfer's steps need: its socket (the server's TID), its peer, and the
/// bookkeeping that has to be undone exactly once when it ends.
struct TransferCtx {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    transfer_id: TransferId,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    transfers: Arc<Mutex<HashMap<TransferId, TftpTransfer>>>,
}

impl TransferCtx {
    /// Send one packet to the peer and count it. `false` when the socket refused it.
    async fn send(&self, packet: &[u8]) -> bool {
        match self.socket.send_to(packet, self.peer_addr).await {
            Ok(sent) => {
                self.app_state
                    .update_connection_stats(
                        self.server_id,
                        self.connection_id,
                        None,
                        Some(sent as u64),
                        None,
                        Some(1),
                    )
                    .await;
                Log::new(Some(&self.status_tx))
                    .trace(format!("TFTP sent packet (hex): {}", hex::encode(packet)));
                true
            }
            Err(e) => {
                Log::new(Some(&self.status_tx))
                    .error(format!("TFTP failed to send to {}: {}", self.peer_addr, e));
                false
            }
        }
    }

    /// The next datagram from this transfer's peer, within `wait`.
    ///
    /// A datagram from any other address is answered `ERROR 5` (unknown transfer ID) and
    /// otherwise ignored, as RFC 1350 §4 requires: the TID is what keeps two transfers, or a
    /// stray sender, from writing into each other.
    async fn recv_from_peer(&self, wait: std::time::Duration) -> Received {
        let deadline = tokio::time::Instant::now() + wait;
        let mut buffer = vec![0u8; 4 + BLOCK_SIZE];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Received::TimedOut;
            }
            match tokio::time::timeout(remaining, self.socket.recv_from(&mut buffer)).await {
                Err(_) => return Received::TimedOut,
                Ok(Err(e)) => {
                    Log::new(Some(&self.status_tx))
                        .error(format!("TFTP socket error on transfer: {}", e));
                    return Received::Failed;
                }
                Ok(Ok((n, from))) if from != self.peer_addr => {
                    let _ = self
                        .socket
                        .send_to(
                            &TftpServer::build_error_packet(5, "Unknown transfer ID"),
                            from,
                        )
                        .await;
                    Log::new(Some(&self.status_tx)).debug(format!(
                        "TFTP {n} bytes from {from}, not this transfer's peer {}; answered \
                         ERROR 5",
                        self.peer_addr
                    ));
                }
                Ok(Ok((n, _))) if n < 4 => continue,
                Ok(Ok((n, _))) => {
                    self.app_state
                        .update_connection_stats(
                            self.server_id,
                            self.connection_id,
                            Some(n as u64),
                            None,
                            Some(1),
                            None,
                        )
                        .await;
                    return Received::Packet(buffer[..n].to_vec());
                }
            }
        }
    }

    /// Wait for the ACK of `block`, sending `packet` again whenever the peer is silent for
    /// [`RETRANSMIT_TIMEOUT`], up to [`MAX_SENDS`] sends in all (the caller made the first).
    ///
    /// An ACK for an earlier block is ignored rather than answered: retransmitting on a
    /// duplicate ACK is the "Sorcerer's Apprentice" bug (RFC 1123 §4.2.3.1), which doubles
    /// every packet for the rest of the transfer. `false` when the transfer cannot go on: the
    /// peer sent ERROR, went silent, or the socket failed.
    async fn await_ack(&self, packet: &[u8], block: u16) -> bool {
        let log = Log::new(Some(&self.status_tx));
        let mut sends = 1;
        let mut deadline = tokio::time::Instant::now() + RETRANSMIT_TIMEOUT;
        loop {
            let wait = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv_from_peer(wait).await {
                Received::Packet(reply) => match TftpServer::packet_opcode(&reply) {
                    Some(OP_ACK) if u16::from_be_bytes([reply[2], reply[3]]) == block => {
                        log.debug(format!("TFTP received ACK for block {}", block));
                        return true;
                    }
                    Some(OP_ERROR) => {
                        log.debug(format!(
                            "TFTP client sent ERROR {} ({}), transfer terminated",
                            u16::from_be_bytes([reply[2], reply[3]]),
                            String::from_utf8_lossy(&reply[4..]).trim_end_matches('\0')
                        ));
                        return false;
                    }
                    _ => continue,
                },
                Received::TimedOut if sends < MAX_SENDS => {
                    sends += 1;
                    log.debug(format!(
                        "TFTP no ACK for block {block}; retransmitting (send {sends} of \
                         {MAX_SENDS})"
                    ));
                    if !self.send(packet).await {
                        return false;
                    }
                    deadline = tokio::time::Instant::now() + RETRANSMIT_TIMEOUT;
                }
                Received::TimedOut => {
                    log.debug(format!(
                        "TFTP timeout waiting for ACK block {block} after {MAX_SENDS} sends"
                    ));
                    return false;
                }
                Received::Failed => return false,
            }
        }
    }

    /// Send a whole file, block by block, each retransmitted until it is acknowledged. A file
    /// that is an exact multiple of [`BLOCK_SIZE`] ends with an empty block (RFC 1350 §6).
    async fn serve_file(&self, content: &[u8]) {
        let log = Log::new(Some(&self.status_tx));
        let mut offset = 0usize;
        let mut block: u16 = 1;
        loop {
            let end = (offset + BLOCK_SIZE).min(content.len());
            let chunk = &content[offset..end];
            let mut packet = Vec::with_capacity(4 + chunk.len());
            packet.extend_from_slice(&OP_DATA.to_be_bytes());
            packet.extend_from_slice(&block.to_be_bytes());
            packet.extend_from_slice(chunk);
            if !self.send(&packet).await {
                break;
            }
            self.app_state
                .update_tftp_connection_block(
                    self.server_id,
                    self.connection_id,
                    block,
                    chunk.len(),
                )
                .await;
            if !self.await_ack(&packet, block).await {
                break;
            }
            if chunk.len() < BLOCK_SIZE {
                log.info(format!(
                    "TFTP sent {} bytes to {} in {} blocks; transfer complete",
                    content.len(),
                    self.peer_addr,
                    block
                ));
                break;
            }
            offset = end;
            block = block.wrapping_add(1);
        }
        self.teardown().await;
    }

    /// End a transfer whose step was answered with nothing usable: `ERROR 0`, then teardown.
    async fn end_unanswered(&self, stage: &str) {
        Log::new(Some(&self.status_tx)).warn(format!(
            "TFTP {} from {}: no packet to send; answering ERROR 0 and ending the transfer",
            stage, self.peer_addr
        ));
        self.send(&TftpServer::build_error_packet(0, UNANSWERED_MESSAGE))
            .await;
        self.teardown().await;
    }

    async fn fail_on_llm_error(&self, stage: &str, err: &anyhow::Error) {
        TftpServer::fail_transfer_on_llm_error(
            &self.socket,
            self.peer_addr,
            self.transfer_id,
            stage,
            err,
            self.server_id,
            self.connection_id,
            &self.app_state,
            &self.status_tx,
            &self.transfers,
        )
        .await;
    }

    /// Forget the transfer and close its connection entry.
    async fn teardown(&self) {
        self.transfers.lock().await.remove(&self.transfer_id);
        self.app_state
            .close_connection_on_server(self.server_id, self.connection_id)
            .await;
    }
}

/// A request's claim on its peer address, released when its handler task ends; by then the
/// transfer is in the transfer map (or never will be), which is what keeps later copies out.
struct PendingClaim(
    Arc<std::sync::Mutex<std::collections::HashSet<SocketAddr>>>,
    SocketAddr,
);

impl Drop for PendingClaim {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.0.lock() {
            pending.remove(&self.1);
        }
    }
}

/// TFTP server that forwards requests to LLM
pub struct TftpServer;

impl TftpServer {
    /// Spawn TFTP server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        // Main listening socket (port 69)
        let main_socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = main_socket.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("TFTP server listening on {}", local_addr));

        let protocol = Arc::new(TftpProtocol::new());

        // Active transfers (keyed by TransferId)
        let transfers: Arc<Mutex<HashMap<TransferId, TftpTransfer>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn main request listener (handles RRQ and WRQ)
        let main_socket_clone = main_socket.clone();
        let llm_clone = llm_client.clone();
        let state_clone = app_state.clone();
        let status_clone = status_tx.clone();
        let protocol_clone = protocol.clone();
        let transfers_clone = transfers.clone();

        let accept_handle = tokio::spawn(async move {
            Self::handle_main_requests(
                main_socket_clone,
                llm_clone,
                state_clone,
                status_clone,
                server_id,
                protocol_clone,
                transfers_clone,
            )
            .await;
        });

        app_state
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Handle incoming requests on main socket (RRQ and WRQ)
    async fn handle_main_requests(
        main_socket: Arc<UdpSocket>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<TftpProtocol>,
        transfers: Arc<Mutex<HashMap<TransferId, TftpTransfer>>>,
    ) {
        let mut buffer = vec![0u8; 516]; // Max TFTP packet (4 bytes header + 512 data)
        let log = Log::new(Some(&status_tx));
        let bind_ip = match main_socket.local_addr() {
            Ok(addr) => addr.ip(),
            Err(e) => {
                log.error(format!("TFTP main socket has no local address: {e}"));
                return;
            }
        };
        let mut consecutive_errors: u32 = 0;
        // Peers whose request has been accepted but whose transfer is not registered yet.
        let pending: Arc<std::sync::Mutex<std::collections::HashSet<SocketAddr>>> = Arc::default();

        loop {
            match main_socket.recv_from(&mut buffer).await {
                Ok((n, peer_addr)) => {
                    consecutive_errors = 0;
                    let data = buffer[..n].to_vec();

                    // Summary + full payload FileOnly: the tftp_*_request event
                    // templates render the equivalent lines to the TUI.
                    log.debug(format!("TFTP received {} bytes from {}", n, peer_addr));
                    log.trace(format!("TFTP packet (hex): {}", hex::encode(&data)));

                    // Parse TFTP opcode
                    if data.len() < 2 {
                        log.debug("TFTP packet too short, ignoring");
                        continue;
                    }

                    let opcode = u16::from_be_bytes([data[0], data[1]]);

                    if matches!(opcode, 1 | 2)
                        && !Self::claim_request(&pending, &transfers, peer_addr).await
                    {
                        log.debug(format!(
                            "TFTP request from {peer_addr} repeats one already being answered; \
                             ignored (the client retransmits while the handler thinks)"
                        ));
                        continue;
                    }

                    match opcode {
                        1 => {
                            // RRQ (Read Request)
                            let llm_clone = llm_client.clone();
                            let state_clone = app_state.clone();
                            let status_clone = status_tx.clone();
                            let protocol_clone = protocol.clone();
                            let transfers_clone = transfers.clone();
                            let pending_clone = pending.clone();

                            // Tracked, not detached: stop_server must abort this task too.
                            let task_owner = app_state.clone();
                            task_owner
                                .spawn_server_task(server_id, async move {
                                    let _claim = PendingClaim(pending_clone, peer_addr);
                                    if let Err(e) = Self::handle_read_request(
                                        data,
                                        peer_addr,
                                        bind_ip,
                                        llm_clone,
                                        state_clone,
                                        status_clone,
                                        server_id,
                                        protocol_clone,
                                        transfers_clone,
                                    )
                                    .await
                                    {
                                        error!("TFTP RRQ handling error: {}", e);
                                    }
                                })
                                .await;
                        }
                        2 => {
                            // WRQ (Write Request)
                            let llm_clone = llm_client.clone();
                            let state_clone = app_state.clone();
                            let status_clone = status_tx.clone();
                            let protocol_clone = protocol.clone();
                            let transfers_clone = transfers.clone();
                            let pending_clone = pending.clone();

                            // Tracked, not detached: stop_server must abort this task too.
                            let task_owner = app_state.clone();
                            task_owner
                                .spawn_server_task(server_id, async move {
                                    let _claim = PendingClaim(pending_clone, peer_addr);
                                    if let Err(e) = Self::handle_write_request(
                                        data,
                                        peer_addr,
                                        bind_ip,
                                        llm_clone,
                                        state_clone,
                                        status_clone,
                                        server_id,
                                        protocol_clone,
                                        transfers_clone,
                                    )
                                    .await
                                    {
                                        error!("TFTP WRQ handling error: {}", e);
                                    }
                                })
                                .await;
                        }
                        _ => {
                            log.debug(format!(
                                "TFTP unexpected opcode {} on main socket, ignoring",
                                opcode
                            ));
                        }
                    }
                }
                Err(e) => {
                    // A UDP socket reports transient per-datagram errors here — on Linux an
                    // ICMP port-unreachable from a client that has gone away surfaces as
                    // ECONNREFUSED on the *next* recv — so a single error must not stop the
                    // server. But `continue`ing on a permanent one (the socket closed under
                    // us) spins this loop at 100% CPU and floods the unbounded status
                    // channel, which is what it did. Tolerate a burst, then give up.
                    consecutive_errors += 1;
                    log.error(format!(
                        "TFTP main socket error ({consecutive_errors} in a row): {e}"
                    ));
                    if consecutive_errors >= MAX_CONSECUTIVE_SOCKET_ERRORS {
                        log.error(format!(
                            "TFTP main socket failed {MAX_CONSECUTIVE_SOCKET_ERRORS} times in a \
                             row; stopping the accept loop rather than spinning on it"
                        ));
                        return;
                    }
                }
            }
        }
    }

    /// Handle RRQ (Read Request)
    ///
    /// The whole download runs in this one task: the model's answer to the RRQ is either a
    /// whole file (`send_tftp_file`, after which NetGet sends every block itself) or block 1
    /// (`send_tftp_data`, after which each ACK asks the model for the next block). Either way
    /// every DATA packet is retransmitted until the client acknowledges it
    /// ([`Self::await_ack`]), and every way the transfer ends tells the client so.
    #[allow(clippy::too_many_arguments)]
    async fn handle_read_request(
        data: Vec<u8>,
        peer_addr: SocketAddr,
        bind_ip: std::net::IpAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<TftpProtocol>,
        transfers: Arc<Mutex<HashMap<TransferId, TftpTransfer>>>,
    ) -> Result<()> {
        // Parse RRQ: opcode(2) filename(string) 0 mode(string) 0
        let (filename, mode) = Self::parse_request(&data[2..])?;
        let log = Log::new(Some(&status_tx));

        log.debug(format!(
            "TFTP RRQ: filename='{}' mode='{}' from {}",
            filename, mode, peer_addr
        ));

        // The transfer's own socket (its TID), on the address the server was bound to: a
        // server on loopback must not answer from a socket every interface can reach.
        let transfer_socket = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
        let tid_addr = transfer_socket.local_addr()?;

        log.debug(format!("TFTP RRQ assigned TID {}", tid_addr.port()));

        // Create connection entry
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let now = crate::utils::clock::Instant::now();
        let conn_state = ServerConnectionState {
            id: connection_id,
            remote_addr: peer_addr,
            local_addr: tid_addr,
            bytes_sent: 0,
            bytes_received: data.len() as u64,
            packets_sent: 0,
            packets_received: 1,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                "operation": "read",
                "filename": filename.clone(),
                "current_block": 0,
                "total_bytes": 0,
            })),
        };
        app_state
            .add_connection_to_server(server_id, conn_state)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Create transfer state
        let transfer_id = TransferId::new(peer_addr);
        let transfer = TftpTransfer {
            transfer_id,
            operation: TftpOperation::Read,
            filename: filename.clone(),
            mode: mode.clone(),
            current_block: 0,
            connection_id,
            server_socket: transfer_socket.clone(),
        };

        transfers.lock().await.insert(transfer_id, transfer);

        let ctx = TransferCtx {
            socket: transfer_socket,
            peer_addr,
            transfer_id,
            server_id,
            connection_id,
            app_state,
            status_tx: status_tx.clone(),
            transfers,
        };

        // Call LLM with read request event
        let event = Event::new(
            &TFTP_READ_REQUEST_EVENT,
            serde_json::json!({
                "filename": filename,
                "mode": mode,
                "client_addr": peer_addr.to_string(),
            }),
        );

        log.debug(format!("TFTP calling LLM for RRQ: {}", filename));

        let answer = match call_llm(
            &llm_client,
            &ctx.app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                for message in &execution_result.messages {
                    log.info(message);
                }
                let decision = Self::classify_outcome(&execution_result);
                Self::log_decision(&log, decision, "RRQ", peer_addr, &execution_result);
                Self::read_answer(execution_result, &log)
            }
            Err(e) => {
                ctx.fail_on_llm_error("read request", &e).await;
                return Ok(());
            }
        };

        let mut packet = match answer {
            ReadAnswer::File(content) => {
                let content = if mode.eq_ignore_ascii_case("netascii") {
                    netascii_encode(&content)
                } else {
                    content
                };
                ctx.serve_file(&content).await;
                return Ok(());
            }
            ReadAnswer::Packet(packet) => packet,
            ReadAnswer::Nothing => {
                ctx.end_unanswered("RRQ").await;
                return Ok(());
            }
        };

        // The model sends the file a block at a time: one model call per ACK.
        loop {
            if !ctx.send(&packet).await {
                ctx.teardown().await;
                return Ok(());
            }
            if Self::packet_opcode(&packet) == Some(OP_ERROR) {
                log.debug("TFTP sent ERROR, transfer terminated");
                ctx.teardown().await;
                return Ok(());
            }
            let block_num = u16::from_be_bytes([packet[2], packet[3]]);
            let data_len = packet.len() - 4;
            if let Some(transfer) = ctx.transfers.lock().await.get_mut(&transfer_id) {
                transfer.current_block = block_num;
            }
            ctx.app_state
                .update_tftp_connection_block(server_id, connection_id, block_num, data_len)
                .await;
            log.debug(format!(
                "TFTP sent DATA block {} ({} bytes)",
                block_num, data_len
            ));

            if !ctx.await_ack(&packet, block_num).await {
                ctx.teardown().await;
                return Ok(());
            }
            if data_len < BLOCK_SIZE {
                log.debug(format!(
                    "TFTP transfer complete (final ACK received for block {})",
                    block_num
                ));
                ctx.teardown().await;
                return Ok(());
            }

            let event = Event::new(
                &TFTP_ACK_RECEIVED_EVENT,
                serde_json::json!({ "block_number": block_num }),
            );
            packet = match call_llm(
                &llm_client,
                &ctx.app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) => {
                    let decision = Self::classify_outcome(&execution_result);
                    Self::log_decision(
                        &log,
                        decision,
                        "ACK continuation",
                        peer_addr,
                        &execution_result,
                    );
                    match Self::read_answer(execution_result, &log) {
                        ReadAnswer::Packet(packet) => packet,
                        // A whole file is the answer to an RRQ, not to an ACK mid-transfer.
                        ReadAnswer::File(_) | ReadAnswer::Nothing => {
                            ctx.end_unanswered("ACK continuation").await;
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    // Mid-transfer failure: the client is waiting for the next DATA block,
                    // so it gets an ERROR packet instead of nothing.
                    ctx.fail_on_llm_error("read transfer", &e).await;
                    return Ok(());
                }
            };
        }
    }

    /// The one packet (or file) an answer to a read step sends.
    ///
    /// Only one: a second DATA packet in the same answer would be a block the client has not
    /// asked for yet, and the read path waits for one ACK per packet.
    fn read_answer(result: crate::llm::ExecutionResult, log: &Log<'_>) -> ReadAnswer {
        use crate::llm::actions::protocol_trait::ActionResult;
        let mut answer = ReadAnswer::Nothing;
        let mut extra = 0usize;
        for protocol_result in result.protocol_results {
            let candidate = match protocol_result {
                ActionResult::Custom { name, data } if name == FILE_RESULT => {
                    match data.get("hex").and_then(|h| h.as_str()).map(hex::decode) {
                        Some(Ok(bytes)) => ReadAnswer::File(bytes),
                        _ => continue,
                    }
                }
                ActionResult::Output(packet)
                    if matches!(Self::packet_opcode(&packet), Some(OP_DATA | OP_ERROR)) =>
                {
                    ReadAnswer::Packet(packet)
                }
                ActionResult::Output(packet) => {
                    log.warn(format!(
                        "TFTP handler answered a read with opcode {:?}, which is neither DATA \
                         nor ERROR; not sent",
                        Self::packet_opcode(&packet)
                    ));
                    continue;
                }
                _ => continue,
            };
            if matches!(answer, ReadAnswer::Nothing) {
                answer = candidate;
            } else {
                extra += 1;
            }
        }
        if extra > 0 {
            log.warn(format!(
                "TFTP decision=duplicate_response_dropped: {extra} more packet(s) in one answer \
                 not sent; a read sends one block per ACK"
            ));
        }
        answer
    }

    /// Handle WRQ (Write Request)
    #[allow(clippy::too_many_arguments)]
    async fn handle_write_request(
        data: Vec<u8>,
        peer_addr: SocketAddr,
        bind_ip: std::net::IpAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<TftpProtocol>,
        transfers: Arc<Mutex<HashMap<TransferId, TftpTransfer>>>,
    ) -> Result<()> {
        // Parse WRQ
        let (filename, mode) = Self::parse_request(&data[2..])?;
        let log = Log::new(Some(&status_tx));

        log.debug(format!(
            "TFTP WRQ: filename='{}' mode='{}' from {}",
            filename, mode, peer_addr
        ));

        // Create unique socket for this transfer, on the server's own address.
        let transfer_socket = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
        let tid_addr = transfer_socket.local_addr()?;

        log.debug(format!("TFTP WRQ assigned TID {}", tid_addr.port()));

        // Create connection entry
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let now = crate::utils::clock::Instant::now();
        let conn_state = ServerConnectionState {
            id: connection_id,
            remote_addr: peer_addr,
            local_addr: tid_addr,
            bytes_sent: 0,
            bytes_received: data.len() as u64,
            packets_sent: 0,
            packets_received: 1,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                "operation": "write",
                "filename": filename.clone(),
                "current_block": 0,
                "total_bytes": 0,
            })),
        };
        app_state
            .add_connection_to_server(server_id, conn_state)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Create transfer state
        let transfer_id = TransferId::new(peer_addr);
        let transfer = TftpTransfer {
            transfer_id,
            operation: TftpOperation::Write,
            filename: filename.clone(),
            mode: mode.clone(),
            current_block: 0,
            connection_id,
            server_socket: transfer_socket.clone(),
        };

        transfers.lock().await.insert(transfer_id, transfer);

        let ctx = TransferCtx {
            socket: transfer_socket,
            peer_addr,
            transfer_id,
            server_id,
            connection_id,
            app_state,
            status_tx: status_tx.clone(),
            transfers,
        };

        // Call LLM with write request event
        let event = Event::new(
            &TFTP_WRITE_REQUEST_EVENT,
            serde_json::json!({
                "filename": filename,
                "mode": mode,
                "client_addr": peer_addr.to_string(),
            }),
        );

        log.debug(format!("TFTP calling LLM for WRQ: {}", filename));

        let packet = match call_llm(
            &llm_client,
            &ctx.app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                for message in &execution_result.messages {
                    log.info(message);
                }
                let decision = Self::classify_outcome(&execution_result);
                Self::log_decision(&log, decision, "WRQ", peer_addr, &execution_result);
                Self::write_answer(execution_result)
            }
            Err(e) => {
                ctx.fail_on_llm_error("write request", &e).await;
                return Ok(());
            }
        };

        let Some(packet) = packet else {
            ctx.end_unanswered("WRQ").await;
            return Ok(());
        };
        if !ctx.send(&packet).await || Self::packet_opcode(&packet) == Some(OP_ERROR) {
            log.debug("TFTP answered the WRQ with ERROR, transfer denied");
            ctx.teardown().await;
            return Ok(());
        }
        log.debug("TFTP sent ACK block 0, ready to receive");
        Self::receive_write_data(&ctx, packet, llm_client, protocol).await;
        Ok(())
    }

    /// The one ACK or ERROR an answer to a write step sends; the first of them.
    fn write_answer(result: crate::llm::ExecutionResult) -> Option<Vec<u8>> {
        result.protocol_results.into_iter().find_map(|r| match r {
            crate::llm::actions::protocol_trait::ActionResult::Output(packet)
                if matches!(Self::packet_opcode(&packet), Some(OP_ACK | OP_ERROR)) =>
            {
                Some(packet)
            }
            _ => None,
        })
    }

    /// Receive DATA blocks for write transfer.
    ///
    /// `last_ack` is the packet that acknowledged the previous block (ACK 0 for the WRQ). A
    /// client retransmits a DATA block whose ACK it has not seen, which a slow model makes
    /// routine: that duplicate is answered with `last_ack` again and never reaches the model.
    /// Silence from the client is answered by resending `last_ack`, up to [`MAX_SENDS`]. After
    /// the final block the transfer dallies one [`RETRANSMIT_TIMEOUT`] (RFC 1350 §6), so a
    /// final ACK the client lost is sent again rather than leaving it to time out.
    async fn receive_write_data(
        ctx: &TransferCtx,
        mut last_ack: Vec<u8>,
        llm_client: OllamaClient,
        protocol: Arc<TftpProtocol>,
    ) {
        let log = Log::new(Some(&ctx.status_tx));
        let mut last_block: u16 = 0;
        let mut sends: u32 = 1;
        let mut finished = false;

        loop {
            let packet = match ctx.recv_from_peer(RETRANSMIT_TIMEOUT).await {
                Received::Packet(packet) => packet,
                Received::TimedOut if finished => break,
                Received::TimedOut if sends < MAX_SENDS => {
                    log.debug(format!(
                        "TFTP no DATA after ACK {last_block}; resending the ACK"
                    ));
                    sends += 1;
                    if !ctx.send(&last_ack).await {
                        break;
                    }
                    continue;
                }
                Received::TimedOut => {
                    log.debug("TFTP timeout waiting for DATA");
                    break;
                }
                Received::Failed => break,
            };

            match Self::packet_opcode(&packet) {
                Some(OP_DATA) => {}
                Some(OP_ERROR) => {
                    log.debug("TFTP client sent ERROR during upload, transfer terminated");
                    break;
                }
                other => {
                    log.debug(format!("TFTP expected DATA, got opcode {other:?}"));
                    continue;
                }
            }

            let block_num = u16::from_be_bytes([packet[2], packet[3]]);
            let block_data = &packet[4..];

            if block_num == last_block {
                // A retransmission: the client did not see our ACK. Answer it again.
                log.debug(format!(
                    "TFTP duplicate DATA block {block_num}; resending its ACK"
                ));
                if !ctx.send(&last_ack).await {
                    break;
                }
                continue;
            }
            if finished || block_num != last_block.wrapping_add(1) {
                log.debug(format!(
                    "TFTP DATA block {block_num} out of sequence (expected {}); ignored",
                    last_block.wrapping_add(1)
                ));
                continue;
            }

            // Summary FileOnly: the tftp_data_block event template renders
            // the equivalent line to the TUI.
            log.debug(format!(
                "TFTP received DATA block {} ({} bytes)",
                block_num,
                block_data.len()
            ));

            if let Some(transfer) = ctx.transfers.lock().await.get_mut(&ctx.transfer_id) {
                transfer.current_block = block_num;
            }
            ctx.app_state
                .update_tftp_connection_block(
                    ctx.server_id,
                    ctx.connection_id,
                    block_num,
                    block_data.len(),
                )
                .await;

            let is_final = block_data.len() < BLOCK_SIZE;
            let mut event_data = serde_json::json!({
                "block_number": block_num,
                "data_hex": hex::encode(block_data),
                "data_length": block_data.len(),
                "is_final": is_final,
            });
            if let Ok(text) = std::str::from_utf8(block_data) {
                event_data["data"] = text.into();
            }
            let event = Event::new(&TFTP_DATA_BLOCK_EVENT, event_data);

            match call_llm(
                &llm_client,
                &ctx.app_state,
                ctx.server_id,
                Some(ctx.connection_id),
                &event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) => {
                    let decision = Self::classify_outcome(&execution_result);
                    Self::log_decision(
                        &log,
                        decision,
                        "DATA block",
                        ctx.peer_addr,
                        &execution_result,
                    );
                    let Some(answer) = Self::write_answer(execution_result) else {
                        ctx.end_unanswered("DATA block").await;
                        return;
                    };
                    if !ctx.send(&answer).await {
                        break;
                    }
                    // The handler is allowed to abort an upload with send_tftp_error.
                    if Self::packet_opcode(&answer) == Some(OP_ERROR) {
                        log.debug("TFTP sent ERROR during upload, transfer terminated");
                        break;
                    }
                    log.debug(format!("TFTP sent ACK for block {}", block_num));
                    last_ack = answer;
                    last_block = block_num;
                    sends = 1;
                    if is_final {
                        log.debug(format!(
                            "TFTP write transfer complete (final block {} received)",
                            block_num
                        ));
                        finished = true;
                    }
                }
                Err(e) => {
                    // The client is waiting for an ACK for the block it just sent; answer
                    // with ERROR rather than leaving it to retransmit into a socket nobody is
                    // reading any more.
                    ctx.fail_on_llm_error("write data block", &e).await;
                    return;
                }
            }
        }
        ctx.teardown().await;
    }

    /// What the handler produced for one TFTP event, as a stable `decision=` token.
    ///
    /// Must be computed **before** `protocol_results` is consumed, because every call site
    /// moves them into a `for` loop.
    ///
    /// TFTP is not one of the deliberately-silent protocols: it has a real ERROR frame
    /// (opcode 5), so a model that refuses says so on the wire and a model that says nothing
    /// reaches the client as **no packet at all**. Those two used to leave the same trace in
    /// the log, and the second one additionally leaves the transfer registered until the
    /// client's own retransmit timeout expires.
    fn classify_outcome(result: &crate::llm::ExecutionResult) -> &'static str {
        let outputs: Vec<Vec<u8>> = result
            .protocol_results
            .iter()
            .flat_map(|r| r.get_all_output())
            .collect();

        let file = result.protocol_results.iter().any(|r| {
            matches!(r, crate::llm::actions::protocol_trait::ActionResult::Custom { name, .. }
                if name == FILE_RESULT)
        });
        if outputs
            .iter()
            .any(|p| Self::packet_opcode(p) == Some(OP_ERROR))
        {
            "model_reject"
        } else if file || !outputs.is_empty() {
            "model_answer"
        } else if !result.failures.is_empty() {
            "fail_closed_bad_action"
        } else {
            "model_silent"
        }
    }

    /// Emit the `decision=` line for one TFTP event at the level its token deserves.
    ///
    /// `stage` names which of the four LLM call sites produced it (`RRQ`, `WRQ`,
    /// `ACK continuation`, `DATA block`), so a grep tells an operator *where* a transfer
    /// stopped as well as why.
    fn log_decision(
        log: &Log<'_>,
        decision: &str,
        stage: &str,
        peer_addr: SocketAddr,
        result: &crate::llm::ExecutionResult,
    ) {
        match decision {
            "model_answer" => log.info(format!(
                "TFTP {} from {} decision=model_answer",
                stage, peer_addr
            )),
            "model_reject" => log.info(format!(
                "TFTP {} from {} decision=model_reject (handler answered with an ERROR packet)",
                stage, peer_addr
            )),
            "fail_closed_bad_action" => {
                let detail = result
                    .failures
                    .iter()
                    .map(|f| format!("{}: {}", f.action, f.error))
                    .collect::<Vec<_>>()
                    .join("; ");
                log.error(format!(
                    "TFTP {} from {} decision=fail_closed_bad_action ({}); the client is sent \
                     ERROR 0 and the transfer ends",
                    stage, peer_addr, detail
                ))
            }
            _ => log.warn(format!(
                "TFTP {} from {} decision=model_silent; the client is sent ERROR 0 and the \
                 transfer ends",
                stage, peer_addr
            )),
        }
    }

    /// Whether a request from `peer` starts a new transfer: not while one from the same
    /// address and port is registered or still being set up. A client retransmits its RRQ
    /// or WRQ when the first answer is slow, and a model is slow; each copy used to start a
    /// transfer of its own, on a TID of its own, and the client then received two streams.
    async fn claim_request(
        pending: &Arc<std::sync::Mutex<std::collections::HashSet<SocketAddr>>>,
        transfers: &Arc<Mutex<HashMap<TransferId, TftpTransfer>>>,
        peer: SocketAddr,
    ) -> bool {
        if transfers.lock().await.contains_key(&TransferId::new(peer)) {
            return false;
        }
        pending.lock().unwrap().insert(peer)
    }

    /// The opcode of a packet the handler produced, or `None` if it is too short to have one.
    ///
    /// Every action this protocol defines yields at least four bytes, so `None` means an
    /// action outside the declared set produced it — worth logging rather than indexing into.
    fn packet_opcode(packet: &[u8]) -> Option<u16> {
        if packet.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([packet[0], packet[1]]))
    }

    /// Parse RRQ/WRQ request packet
    fn parse_request(data: &[u8]) -> Result<(String, String)> {
        // Format: filename\0mode\0
        let null_positions: Vec<usize> = data
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| if b == 0 { Some(i) } else { None })
            .collect();

        if null_positions.len() < 2 {
            return Err(anyhow::anyhow!("Invalid TFTP request format"));
        }

        let filename = String::from_utf8_lossy(&data[..null_positions[0]]).to_string();
        let mode =
            String::from_utf8_lossy(&data[null_positions[0] + 1..null_positions[1]]).to_string();

        Ok((filename, mode))
    }

    /// Build the ERROR packet a client gets when the LLM call behind a transfer fails.
    ///
    /// RFC 1350 defines error codes 0-7 and none of them means "try again", so both cases
    /// use code 0 ("Not defined, see error message") and the message says which. The
    /// packet is never a plausible-looking DATA or ACK: an LLM outage must not be
    /// indistinguishable from a successful transfer.
    fn llm_failure_error_packet(err: &anyhow::Error) -> Vec<u8> {
        if crate::llm::is_overload_error(err) {
            Self::build_error_packet(0, "Server overloaded, retry later")
        } else {
            Self::build_error_packet(0, "Internal error: LLM backend failure")
        }
    }

    /// Answer an LLM failure with an ERROR packet and tear the transfer down.
    ///
    /// Every LLM call in a TFTP transfer routes its error branch through here. Two of the
    /// four used to write nothing at all, so the client sat in `recvfrom` until its own
    /// retransmit/timeout logic gave up with no indication of what went wrong - a partial
    /// transfer that simply stopped, which for a PXE boot looks like a corrupt image.
    #[allow(clippy::too_many_arguments)]
    async fn fail_transfer_on_llm_error(
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        transfer_id: TransferId,
        stage: &str,
        err: &anyhow::Error,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        transfers: &Arc<Mutex<HashMap<TransferId, TftpTransfer>>>,
    ) {
        let log = Log::new(Some(&status_tx));
        // The backend failed. The client still gets an ERROR packet (a category, never the
        // error text — see `llm_failure_error_packet`) and the transfer is torn down cleanly,
        // but this is the outcome an operator greps for, so it is tagged and logged at ERROR.
        // The two categories are kept apart because one is retryable and one is not.
        let decision = if crate::utils::WireFailure::classify(err).is_overloaded() {
            "fail_closed_llm_overloaded"
        } else {
            "fail_closed_llm_error"
        };
        log.error(format!(
            "TFTP {} from {} decision={}: {} - sending ERROR and ending transfer",
            stage, peer_addr, decision, err
        ));

        let packet = Self::llm_failure_error_packet(err);
        match socket.send_to(&packet, peer_addr).await {
            Ok(sent) => {
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(sent as u64),
                        None,
                        Some(1),
                    )
                    .await;
                log.trace(format!(
                    "TFTP sent ERROR packet (hex): {}",
                    hex::encode(&packet)
                ));
            }
            Err(send_err) => {
                // Could not deliver even the fallback ERROR: genuinely cannot proceed.
                log.error(format!(
                    "TFTP failed to deliver ERROR packet to {}: {}",
                    peer_addr, send_err
                ));
            }
        }

        transfers.lock().await.remove(&transfer_id);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
    }

    /// Build TFTP ERROR packet
    fn build_error_packet(error_code: u16, message: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(4 + message.len() + 1);
        packet.extend_from_slice(&5u16.to_be_bytes()); // Opcode ERROR
        packet.extend_from_slice(&error_code.to_be_bytes());
        packet.extend_from_slice(message.as_bytes());
        packet.push(0); // Null terminator
        packet
    }
}
