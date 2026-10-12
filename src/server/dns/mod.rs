//! DNS server: UDP and TCP on one port, EDNS0, zone transfers and DNSSEC for one zone.
//!
//! The model answers queries and transfers with structured actions (`actions.rs`); everything
//! the protocol decides on its own happens here, after the model has answered: echoing EDNS,
//! signing a `dnssec_zone`, proving non-existence, truncating what does not fit UDP, and
//! cutting a zone into transfer messages. See `src/server/dns/AGENTS.md`.
pub mod actions;
pub mod dnssec;
pub mod records;
pub mod transfer;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::DnsProtocol;
use crate::state::app_state::AppState;
use actions::{DNS_QUERY_EVENT, DNS_ZONE_TRANSFER_EVENT, RESULT_IXFR, RESULT_ZONE};
use anyhow::{Context, Result};
use dnssec::ZoneSigner;
use hickory_proto::op::{Edns, Message as DnsMessage, Query, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter};

/// How long a TCP connection may sit idle between queries (RFC 7766 §6.2.3 suggests seconds,
/// not minutes). The `tcp_idle_timeout_secs` startup parameter overrides it.
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Open TCP connections at once. One past it is closed on accept, unread.
pub const MAX_TCP_CONNECTIONS: usize = 64;

/// Open TCP connections one client address may hold at once; past it a new one from that
/// address is closed unread (`decision=fail_closed_per_source_cap`). Without it one host could
/// hold all [`MAX_TCP_CONNECTIONS`] slots — cheaply, since some messages are answered without
/// the model. IPv6 is counted per /64, which is what one host is usually given. The
/// `tcp_connections_per_ip` startup parameter overrides it, within 1..=`MAX_TCP_CONNECTIONS`.
pub const MAX_TCP_CONNECTIONS_PER_IP: usize = 8;

/// What a connection past the cap is told: nothing. DNS has no message a server sends
/// before a query, so it is closed unread and the client retries or moves on.
pub const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// The UDP payload size this server advertises in its OPT record: the 2020 DNS flag day's
/// 1232, which fits an IPv6 minimum MTU without fragmenting.
pub const EDNS_UDP_SIZE: u16 = 1232;

/// The largest UDP response to a query without EDNS (RFC 1035 §4.2.1).
pub const PLAIN_UDP_LIMIT: usize = 512;

/// The most a client's EDNS buffer size is believed; past it the response is truncated
/// anyway, so one query cannot ask for a 64 KiB datagram.
pub const MAX_UDP_RESPONSE: usize = 4096;

/// What `spawn` reads from the startup parameters.
pub struct DnsSettings {
    pub dnssec_zone: Option<String>,
    pub tcp_idle_timeout: Duration,
    /// See [`MAX_TCP_CONNECTIONS_PER_IP`].
    pub tcp_connections_per_ip: usize,
}

/// Open TCP connections per source address (IPv6 per /64), bounded at `max` each.
struct PerSourceLimiter {
    max: usize,
    open: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
}

/// One admitted connection's place in its source's count; released when dropped, so it lives
/// in the connection task.
struct SourceSlot {
    key: IpAddr,
    open: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
}

impl PerSourceLimiter {
    fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            open: Arc::default(),
        }
    }

    /// The source's slot, or `None` when it already holds `max` connections.
    fn try_acquire(&self, ip: IpAddr) -> Option<SourceSlot> {
        let key = source_key(ip);
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let count = open.entry(key).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(SourceSlot {
            key,
            open: self.open.clone(),
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.key);
            }
        }
    }
}

/// What a source is counted as: an IPv4 address (an IPv4-mapped IPv6 address is its IPv4
/// address), or an IPv6 address's /64.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// DNS server that integrates with LLM for query handling
pub struct DnsServer;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// Everything a query is answered with.
struct Shared {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    protocol: Arc<DnsProtocol>,
    signer: Option<Arc<ZoneSigner>>,
}

fn now_secs() -> u32 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or_default()
}

impl DnsServer {
    /// Bind UDP and TCP on the same port and start both loops.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        settings: DnsSettings,
    ) -> Result<SocketAddr> {
        // The same port for TCP (RFC 7766 §5: every server MUST serve TCP). When the OS picks the
        // port, the number it gave UDP can already be taken for TCP by another process, so a
        // fresh pair is tried; an explicitly requested port that TCP cannot have fails rather
        // than serving half the protocol.
        const PORT_PAIR_ATTEMPTS: usize = 16;
        let mut attempt = 0;
        let (socket, local_addr, listener) = loop {
            attempt += 1;
            let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
            let local_addr = socket.local_addr()?;
            match TcpListener::bind(local_addr).await {
                Ok(listener) => break (socket, local_addr, listener),
                Err(e)
                    if listen_addr.port() == 0
                        && e.kind() == std::io::ErrorKind::AddrInUse
                        && attempt < PORT_PAIR_ATTEMPTS =>
                {
                    continue
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("DNS over TCP cannot bind {local_addr}")))
                }
            }
        };
        let log = Log::new(Some(&status_tx));
        log.info(format!(
            "DNS server listening on {local_addr} (UDP and TCP)"
        ));

        let signer = match settings.dnssec_zone.as_deref() {
            None => None,
            Some(zone) => {
                let name = records::parse_name(zone, None)?;
                let signer = ZoneSigner::generate(name, now_secs())?;
                log.info(format!(
                    "DNS signing {} with DNSSEC (ECDSA P-256, key tag {})",
                    signer.zone(),
                    signer.key_tag()
                ));
                Some(Arc::new(signer))
            }
        };

        let shared = Arc::new(Shared {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            server_id,
            protocol: Arc::new(DnsProtocol::new()),
            signer,
        });

        let udp_shared = shared.clone();
        let udp_handle = tokio::spawn(async move {
            Self::udp_loop(socket, local_addr, udp_shared).await;
        });
        app_state.register_server_task(server_id, udp_handle).await;

        let tcp_shared = shared.clone();
        let idle = settings.tcp_idle_timeout;
        let per_source = PerSourceLimiter::new(settings.tcp_connections_per_ip);
        let tcp_handle = tokio::spawn(async move {
            Self::tcp_loop(listener, local_addr, tcp_shared, idle, per_source).await;
        });
        app_state.register_server_task(server_id, tcp_handle).await;

        Ok(local_addr)
    }

    async fn register_connection(
        shared: &Shared,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        received: u64,
    ) -> ConnectionId {
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let connection_id = ConnectionId::new(shared.app_state.get_next_unified_id().await);
        let now = crate::utils::clock::Instant::now();
        shared
            .app_state
            .add_connection_to_server(
                shared.server_id,
                ServerConnectionState {
                    id: connection_id,
                    remote_addr: peer_addr,
                    local_addr,
                    bytes_sent: 0,
                    bytes_received: received,
                    packets_sent: 0,
                    packets_received: u64::from(received > 0),
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::empty(),
                },
            )
            .await;
        let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
        connection_id
    }

    async fn udp_loop(socket: Arc<UdpSocket>, local_addr: SocketAddr, shared: Arc<Shared>) {
        // RFC 1035 caps plain UDP DNS at 512 bytes, but EDNS0 (RFC 6891) clients routinely
        // advertise 1232-4096 byte buffers. A short buffer would silently truncate those
        // datagrams, and the truncated bytes would then fail to parse as DNS.
        let mut buffer = vec![0u8; 4096];
        loop {
            let (n, peer_addr) = match socket.recv_from(&mut buffer).await {
                Ok(r) => r,
                Err(e) => {
                    Log::new(Some(&shared.status_tx)).error(format!("DNS receive error: {e}"));
                    break;
                }
            };
            let data = buffer[..n].to_vec();
            let connection_id =
                Self::register_connection(&shared, peer_addr, local_addr, n as u64).await;
            {
                let log = Log::new(Some(&shared.status_tx));
                log.debug(format!("DNS received {n} bytes from {peer_addr} over UDP"));
                log.trace(format!("DNS data (hex): {}", hex::encode(&data)));
            }
            let task_shared = shared.clone();
            let task_socket = socket.clone();
            // Tracked, not detached: stop_server must abort this task too.
            shared
                .app_state
                .spawn_server_task(shared.server_id, async move {
                    let replies = Self::answer(
                        &task_shared,
                        &data,
                        peer_addr,
                        connection_id,
                        Transport::Udp,
                    )
                    .await;
                    // UDP carries one message; a transfer never reaches here as more.
                    if let Some(reply) = replies.first() {
                        let _ = task_socket.send_to(reply, peer_addr).await;
                        Self::count_sent(&task_shared, connection_id, reply.len()).await;
                    }
                })
                .await;
        }
    }

    async fn tcp_loop(
        listener: TcpListener,
        local_addr: SocketAddr,
        shared: Arc<Shared>,
        idle: Duration,
        per_source: PerSourceLimiter,
    ) {
        // Two caps: past MAX_TCP_CONNECTIONS in all, or past `per_source.max` from one address,
        // a connection is closed unread, and a client retries or moves to another server.
        let limiter = ConnectionLimiter::new(MAX_TCP_CONNECTIONS);
        loop {
            let (stream, peer_addr, permit) = match accept_bounded(
                &listener,
                &limiter,
                CONNECTION_CAP_REFUSAL,
                "DNS",
                Some(&shared.status_tx),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    Log::new(Some(&shared.status_tx)).error(format!("DNS TCP accept error: {e}"));
                    continue;
                }
            };
            let Some(source_slot) = per_source.try_acquire(peer_addr.ip()) else {
                Log::new(Some(&shared.status_tx)).warn(format!(
                    "DNS connection from {peer_addr} refused decision=fail_closed_per_source_cap \
                     (limit {} concurrent per address)",
                    per_source.max
                ));
                // The global slot goes back at once; the socket is closed unread, as at the
                // global cap.
                drop(permit);
                let mut stream = stream;
                let _ = stream.shutdown().await;
                continue;
            };
            let connection_id = Self::register_connection(&shared, peer_addr, local_addr, 0).await;
            let task_shared = shared.clone();
            shared
                .app_state
                .spawn_server_task(shared.server_id, async move {
                    let _permit = permit;
                    let _source_slot = source_slot;
                    Self::tcp_connection(stream, peer_addr, connection_id, task_shared, idle).await;
                })
                .await;
        }
    }

    /// One TCP connection: two-byte length, message, answer, repeat (RFC 1035 §4.2.2). Queries
    /// are answered in order. The connection closes when the peer does, after `idle` with no
    /// query, or on a query this server cannot read.
    async fn tcp_connection(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        shared: Arc<Shared>,
        idle: Duration,
    ) {
        let log = Log::new(Some(&shared.status_tx));
        loop {
            let len = match tokio::time::timeout(idle, stream.read_u16()).await {
                Err(_) => {
                    log.debug(format!(
                        "DNS TCP {peer_addr} idle for {}s; closing decision=tcp_idle",
                        idle.as_secs()
                    ));
                    break;
                }
                Ok(Err(_)) => break, // the peer closed
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n as usize,
            };
            let mut data = vec![0u8; len];
            match tokio::time::timeout(idle, stream.read_exact(&mut data)).await {
                Ok(Ok(_)) => {}
                _ => {
                    log.debug(format!(
                        "DNS TCP {peer_addr} stopped part way through a {len}-byte message"
                    ));
                    break;
                }
            }
            shared
                .app_state
                .update_connection_stats(
                    shared.server_id,
                    connection_id,
                    Some(len as u64 + 2),
                    None,
                    Some(1),
                    None,
                )
                .await;
            log.debug(format!(
                "DNS received {len} bytes from {peer_addr} over TCP"
            ));
            let replies =
                Self::answer(&shared, &data, peer_addr, connection_id, Transport::Tcp).await;
            if replies.is_empty() && DnsMessage::from_vec(&data).is_err() {
                break; // unreadable: nothing on this stream can be trusted to be framed
            }
            for reply in &replies {
                // Every reply is a message hickory encoded, which stops at 65535 octets; one
                // that did not fit the two-byte length would be misframed, so it closes the
                // connection instead.
                let Ok(reply_len) = u16::try_from(reply.len()) else {
                    log.error(format!(
                        "DNS reply of {} bytes to {peer_addr} does not fit a TCP length prefix; \
                         closing decision=fail_closed_oversize_answer",
                        reply.len()
                    ));
                    let _ = stream.shutdown().await;
                    return;
                };
                let mut framed = Vec::with_capacity(reply.len() + 2);
                framed.extend_from_slice(&reply_len.to_be_bytes());
                framed.extend_from_slice(reply);
                if stream.write_all(&framed).await.is_err() {
                    return;
                }
                Self::count_sent(&shared, connection_id, framed.len()).await;
            }
        }
        let _ = stream.shutdown().await;
    }

    async fn count_sent(shared: &Shared, connection_id: ConnectionId, bytes: usize) {
        shared
            .app_state
            .update_connection_stats(
                shared.server_id,
                connection_id,
                None,
                Some(bytes as u64),
                None,
                Some(1),
            )
            .await;
    }

    /// Answer one query. Returns the messages to send: none, one, or — for a zone transfer
    /// over TCP — as many as the zone needs.
    async fn answer(
        shared: &Shared,
        data: &[u8],
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        transport: Transport,
    ) -> Vec<Vec<u8>> {
        let log = Log::new(Some(&shared.status_tx));
        let query = match DnsMessage::from_vec(data) {
            Ok(q) => q,
            Err(e) => {
                log.warn(format!("Failed to parse DNS query: {e}"));
                log.debug(format!(
                    "DNS malformed query from {peer_addr} ({} bytes, hex: {})",
                    data.len(),
                    hex::encode(data)
                ));
                return Vec::new();
            }
        };
        let edns = query.extensions().clone();
        let dnssec_ok = edns.as_ref().is_some_and(|e| e.dnssec_ok());
        let udp_limit = match (&edns, transport) {
            (_, Transport::Tcp) => u16::MAX as usize,
            (Some(e), Transport::Udp) => (e.max_payload() as usize)
                .max(PLAIN_UDP_LIMIT)
                .min(MAX_UDP_RESPONSE),
            (None, Transport::Udp) => PLAIN_UDP_LIMIT,
        };
        let reply = Reply {
            query: &query,
            edns: edns.is_some(),
            dnssec_ok,
            udp_limit,
            transport,
        };

        let Some(question) = query.queries().first().cloned() else {
            log.warn(format!(
                "DNS query from {peer_addr} has no question; FORMERR decision=spec_reply"
            ));
            return reply.rcode_only(ResponseCode::FormErr);
        };
        let qname = question.name().clone();
        let qtype = question.query_type();

        // The signed zone's DNSKEY is the server's, not the model's.
        if let Some(signer) = &shared.signer {
            if qtype == RecordType::DNSKEY && qname.to_lowercase() == signer.zone().to_lowercase() {
                log.debug(format!(
                    "DNS DNSKEY {qname} from {peer_addr} answered by the server decision=spec_reply"
                ));
                let mut message = transfer::response_shell(&query, ResponseCode::NoError);
                message.add_query(question.clone());
                message.add_answer(signer.dnskey_record());
                return reply.finish(message, shared.signer.as_deref(), &log);
            }
        }

        match qtype {
            RecordType::AXFR if transport == Transport::Udp => {
                // RFC 5936 §4.2: AXFR is a TCP exchange. Not the model's decision.
                log.info(format!(
                    "DNS AXFR {qname} from {peer_addr} over UDP; NOTIMP decision=spec_reply"
                ));
                reply.rcode_only(ResponseCode::NotImp)
            }
            RecordType::AXFR | RecordType::IXFR => {
                Self::transfer(shared, &reply, &question, peer_addr, connection_id, &log).await
            }
            _ => Self::query(shared, &reply, &question, peer_addr, connection_id, &log).await,
        }
    }

    async fn query(
        shared: &Shared,
        reply: &Reply<'_>,
        question: &Query,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        log: &Log<'_>,
    ) -> Vec<Vec<u8>> {
        let query = reply.query;
        log.debug(format!(
            "DNS query: {} {} {} over {}",
            question.name(),
            question.query_type(),
            question.query_class(),
            reply.transport.as_str()
        ));
        let event = Event::new(
            &DNS_QUERY_EVENT,
            serde_json::json!({
                "query_id": query.id(),
                "domain": question.name().to_string(),
                "query_type": question.query_type().to_string(),
                "transport": reply.transport.as_str(),
                "dnssec_ok": reply.dnssec_ok,
                "client_ip": peer_addr.ip().to_string(),
                "client_port": peer_addr.port(),
            }),
        );
        // `Some(connection_id)`, not `None`: it is what `call_llm_inner` uses to look up the
        // peer address for the `dns_query` event's INFO template, and what scopes
        // connection-scoped handlers and tasks.
        let result = call_llm(
            &shared.llm_client,
            &shared.app_state,
            shared.server_id,
            Some(connection_id),
            &event,
            shared.protocol.as_ref(),
        )
        .await;
        let execution = match result {
            Ok(r) => r,
            Err(e) => return reply.servfail_for_llm_error(&e, peer_addr, connection_id, log),
        };
        for message in &execution.messages {
            log.info(message);
        }
        // Three outcomes stay distinct, and two of them look identical on the wire: an answer
        // was written (model_answer), `ignore_query` (model_silent, a real decision), and
        // nothing usable came back (fail_closed_no_action) — a model answering only with
        // common actions, or with a DNS action `execute_action` refused.
        let mut model_chose_silence = false;
        for result in execution.protocol_results {
            match result {
                ActionResult::NoAction => model_chose_silence = true,
                ActionResult::Output(bytes) => {
                    let Ok(message) = DnsMessage::from_vec(&bytes) else {
                        // Only `send_dns_response`'s hand-assembled bytes can fail here. Bytes
                        // that are not a DNS message never go out: unparsed, they would skip
                        // truncation and could be any length at all.
                        log.error(format!(
                            "DNS answer to the query from {peer_addr} is not a DNS message \
                             ({} bytes); answering SERVFAIL \
                             decision=fail_closed_unparseable_answer",
                            bytes.len()
                        ));
                        return reply.servfail();
                    };
                    log.debug(format!("DNS query from {peer_addr} decision=model_answer"));
                    log.info(format!("DNS response to {peer_addr}"));
                    return reply.finish(message, shared.signer.as_deref(), log);
                }
                _ => {}
            }
        }
        if model_chose_silence {
            log.debug(format!(
                "DNS deliberately sending nothing to {peer_addr} decision=model_silent"
            ));
            return Vec::new();
        }
        log.error(format!(
            "DNS no usable action for the query from {peer_addr} ({connection_id}); answering \
             SERVFAIL decision=fail_closed_no_action (failures: {:?})",
            execution.failures
        ));
        reply.servfail()
    }

    async fn transfer(
        shared: &Shared,
        reply: &Reply<'_>,
        question: &Query,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        log: &Log<'_>,
    ) -> Vec<Vec<u8>> {
        let query = reply.query;
        let zone = question.name().clone();
        let kind = question.query_type();
        // IXFR carries the serial the client holds as an SOA in the authority section.
        let client_serial = query
            .name_servers()
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .and_then(transfer::serial_of);
        let signed = shared
            .signer
            .as_ref()
            .is_some_and(|s| s.zone().to_lowercase() == zone.to_lowercase());
        let mut data = serde_json::json!({
            "query_id": query.id(),
            "zone": zone.to_string(),
            "transfer_type": kind.to_string(),
            "transport": reply.transport.as_str(),
            "signed": signed,
            "client_ip": peer_addr.ip().to_string(),
            "client_port": peer_addr.port(),
        });
        if let Some(serial) = client_serial {
            data["client_serial"] = serde_json::json!(serial);
        }
        log.info(format!(
            "DNS {kind} {zone} from {peer_addr} over {}",
            reply.transport.as_str()
        ));
        let result = call_llm(
            &shared.llm_client,
            &shared.app_state,
            shared.server_id,
            Some(connection_id),
            &Event::new(&DNS_ZONE_TRANSFER_EVENT, data),
            shared.protocol.as_ref(),
        )
        .await;
        let execution = match result {
            Ok(r) => r,
            Err(e) => return reply.servfail_for_llm_error(&e, peer_addr, connection_id, log),
        };
        for message in &execution.messages {
            log.info(message);
        }
        for result in execution.protocol_results {
            let built = match &result {
                ActionResult::NoAction => {
                    log.debug(format!(
                        "DNS {kind} {zone} from {peer_addr}: sending nothing decision=model_silent"
                    ));
                    return Vec::new();
                }
                ActionResult::Output(bytes) => {
                    // A refusal (or any single-message answer) to the transfer.
                    let Ok(message) = DnsMessage::from_vec(bytes) else {
                        log.error(format!(
                            "DNS answer to the {kind} of {zone} from {peer_addr} is not a DNS \
                             message ({} bytes); answering SERVFAIL \
                             decision=fail_closed_unparseable_answer",
                            bytes.len()
                        ));
                        return reply.servfail();
                    };
                    let decision = if message.response_code() == ResponseCode::Refused {
                        "model_reject"
                    } else {
                        "model_answer"
                    };
                    log.info(format!(
                        "DNS {kind} {zone} from {peer_addr} decision={decision}"
                    ));
                    return reply.finish(message, None, log);
                }
                ActionResult::Custom { name, data } if name == RESULT_ZONE => {
                    if reply.transport == Transport::Udp {
                        log.info(format!(
                            "DNS {kind} {zone} from {peer_addr}: a full zone is never sent over \
                             UDP; answering with the SOA alone decision=udp_soa_only"
                        ));
                    }
                    Self::build_axfr(shared, reply, question, data)
                }
                ActionResult::Custom { name, data } if name == RESULT_IXFR => {
                    let has_changes = data
                        .get("changes")
                        .and_then(|c| c.as_array())
                        .is_some_and(|c| !c.is_empty());
                    // "You are current" is the SOA alone and carries nothing unsigned; a
                    // difference would.
                    if signed && has_changes {
                        Err(anyhow::anyhow!(
                            "{zone} is signed and its IXFR must be answered with the full zone \
                             (send_dns_zone); a diff would carry no signatures"
                        ))
                    } else {
                        Self::build_ixfr(reply, question, data, client_serial.unwrap_or(0))
                    }
                }
                _ => continue,
            };
            return match built {
                Ok(messages) => {
                    log.info(format!(
                        "DNS {kind} {zone} to {peer_addr}: {} message(s) decision=model_answer",
                        messages.len()
                    ));
                    messages
                }
                Err(e) => {
                    log.error(format!(
                        "DNS {kind} {zone} from {peer_addr}: cannot build the transfer ({e:#}); \
                         answering SERVFAIL decision=fail_closed_no_action"
                    ));
                    reply.servfail()
                }
            };
        }
        log.error(format!(
            "DNS no usable action for the {kind} of {zone} from {peer_addr}; answering SERVFAIL \
             decision=fail_closed_no_action (failures: {:?})",
            execution.failures
        ));
        reply.servfail()
    }

    /// The AXFR stream, signed when the zone is: SOA, records (and DNSKEY, NSEC chain and every
    /// RRSIG for a signed zone), SOA. Over UDP — an IXFR answered with the full zone — the
    /// answer is the SOA alone whatever the zone's size (RFC 1995 §2's "use TCP"): a UDP
    /// source address can be forged, so a full zone never goes to one.
    fn build_axfr(
        shared: &Shared,
        reply: &Reply<'_>,
        question: &Query,
        action: &serde_json::Value,
    ) -> Result<Vec<Vec<u8>>> {
        let zone = transfer::zone_from_action(action)?;
        if zone.origin.to_lowercase() != question.name().to_lowercase() {
            anyhow::bail!(
                "the answer transfers {} but the client asked for {}",
                zone.origin,
                question.name()
            );
        }
        if reply.transport == Transport::Udp {
            return Self::soa_only(reply, question, Some(zone.soa.clone()));
        }
        let mut sequence = transfer::axfr_sequence(&zone);
        if let Some(signer) = shared
            .signer
            .as_deref()
            .filter(|s| s.zone().to_lowercase() == zone.origin.to_lowercase())
        {
            sequence = Self::sign_zone(signer, &zone)?;
        }
        Self::transfer_messages(reply, question, sequence)
    }

    fn sign_zone(signer: &ZoneSigner, zone: &transfer::Zone) -> Result<Vec<Record>> {
        let now = now_secs();
        let mut body: Vec<Record> = vec![zone.soa.clone(), signer.dnskey_record()];
        for r in &zone.records {
            if r.record_type() == RecordType::NS && r.name() != &zone.origin {
                anyhow::bail!(
                    "{} NS is a delegation; a signed zone here holds no delegations",
                    r.name()
                );
            }
            body.push(r.clone());
        }
        let nsec = signer.nsec_chain(&body, dnssec::negative_ttl(&zone.soa))?;
        body.extend(nsec);
        let sigs = signer.signatures_for(&mut body, now)?;
        // The SOA (now with its signed TTL) opens and closes the stream; RRSIGs follow the
        // records they cover.
        let soa = body[0].clone();
        let mut out = body;
        out.extend(sigs);
        out.push(soa);
        Ok(out)
    }

    fn build_ixfr(
        reply: &Reply<'_>,
        question: &Query,
        action: &serde_json::Value,
        client_serial: u32,
    ) -> Result<Vec<Vec<u8>>> {
        let (origin, sequence) = transfer::ixfr_from_action(action, client_serial)?;
        if origin.to_lowercase() != question.name().to_lowercase() {
            anyhow::bail!(
                "the answer transfers {origin} but the client asked for {}",
                question.name()
            );
        }
        Self::transfer_messages(reply, question, sequence)
    }

    /// The current SOA alone: RFC 1995 §2's answer to an IXFR over UDP that is not sent there,
    /// which tells the client to ask again over TCP.
    fn soa_only(reply: &Reply<'_>, question: &Query, soa: Option<Record>) -> Result<Vec<Vec<u8>>> {
        let mut only_soa = transfer::response_shell(reply.query, ResponseCode::NoError);
        only_soa.add_query(question.clone());
        only_soa.add_answers(soa);
        if let Some(e) = reply.response_edns() {
            only_soa.set_edns(e);
        }
        Ok(vec![only_soa.to_vec()?])
    }

    fn transfer_messages(
        reply: &Reply<'_>,
        question: &Query,
        sequence: Vec<Record>,
    ) -> Result<Vec<Vec<u8>>> {
        let edns = reply.response_edns();
        let add_edns = |m: &mut DnsMessage| {
            if let Some(e) = &edns {
                m.set_edns(e.clone());
            }
        };
        if reply.transport == Transport::Udp {
            // RFC 1995 §2: an IXFR difference that does not fit UDP is replaced by the current
            // SOA.
            let mut whole = transfer::response_shell(reply.query, ResponseCode::NoError);
            whole.add_query(question.clone());
            let soa = sequence.first().cloned();
            whole.add_answers(sequence);
            add_edns(&mut whole);
            let bytes = whole.to_vec().ok();
            if let Some(bytes) = bytes.filter(|b| b.len() <= reply.udp_limit) {
                return Ok(vec![bytes]);
            }
            return Self::soa_only(reply, question, soa);
        }
        transfer::split_into_messages(
            reply.query,
            Some(question),
            sequence,
            transfer::TRANSFER_MESSAGE_BYTES,
            add_edns,
        )
    }
}

/// What every reply to one query shares.
struct Reply<'a> {
    query: &'a DnsMessage,
    edns: bool,
    dnssec_ok: bool,
    udp_limit: usize,
    transport: Transport,
}

impl Reply<'_> {
    /// The OPT this server answers an EDNS query with (RFC 6891 §6.1.1); `None` for a query
    /// without one, which must not get one back.
    fn response_edns(&self) -> Option<Edns> {
        self.edns.then(|| {
            let mut e = Edns::new();
            e.set_max_payload(EDNS_UDP_SIZE);
            e.set_version(0);
            e.set_dnssec_ok(self.dnssec_ok);
            e
        })
    }

    /// A reply with only a header, the question and (for EDNS) an OPT.
    fn rcode_only(&self, rcode: ResponseCode) -> Vec<Vec<u8>> {
        let mut message = transfer::response_shell(self.query, rcode);
        message.set_authoritative(false);
        for q in self.query.queries() {
            message.add_query(q.clone());
        }
        if let Some(e) = self.response_edns() {
            message.set_edns(e);
        }
        message.to_vec().map(|b| vec![b]).unwrap_or_default()
    }

    /// SERVFAIL, through the one builder every fail-closed path uses.
    fn servfail(&self) -> Vec<Vec<u8>> {
        match actions::build_servfail(self.query) {
            Ok(packet) => vec![packet],
            Err(_) => Vec::new(),
        }
    }

    fn servfail_for_llm_error(
        &self,
        e: &anyhow::Error,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        log: &Log<'_>,
    ) -> Vec<Vec<u8>> {
        // SERVFAIL is the same bytes whatever went wrong, so the log is the only place the
        // distinction survives (`src/server/radius/` is the model for this).
        let decision = if crate::llm::is_overload_error(e) {
            "fail_closed_llm_overload"
        } else {
            "fail_closed_llm_error"
        };
        log.warn(format!(
            "DNS LLM call failed for query from {peer_addr} ({connection_id}) decision={decision}: {e}"
        ));
        let out = self.servfail();
        if let Some(packet) = out.first() {
            log.info(format!(
                "DNS SERVFAIL to {peer_addr} ({} bytes)",
                packet.len()
            ));
        }
        out
    }

    /// Finish a one-message answer: DNSSEC for a signed name when the client asked, the OPT
    /// for an EDNS query, and truncation when it does not fit the client's UDP buffer.
    fn finish(
        &self,
        mut message: DnsMessage,
        signer: Option<&ZoneSigner>,
        log: &Log<'_>,
    ) -> Vec<Vec<u8>> {
        let qname = self.query.queries().first().map(|q| q.name().clone());
        if let (Some(signer), Some(qname)) = (signer, qname.as_ref()) {
            if self.dnssec_ok && signer.covers(qname) {
                if let Err(e) = Self::sign_answer(&mut message, signer, qname) {
                    log.error(format!(
                        "DNS cannot sign the answer for {qname} ({e:#}); answering SERVFAIL \
                         decision=fail_closed_dnssec"
                    ));
                    return self.servfail();
                }
            }
        }
        if let Some(e) = self.response_edns() {
            message.set_edns(e);
        }
        let bytes = match message.to_vec() {
            Ok(b) => b,
            Err(e) => {
                log.error(format!(
                    "DNS cannot encode the answer ({e}); answering SERVFAIL \
                     decision=fail_closed_no_action"
                ));
                return self.servfail();
            }
        };
        if self.transport == Transport::Udp && bytes.len() > self.udp_limit {
            // RFC 2181 §9 / RFC 7766: set TC and send what is certain to fit — the header and
            // the question — so the client retries over TCP.
            log.debug(format!(
                "DNS answer of {} bytes is over the client's {} over UDP; TC decision=truncated",
                bytes.len(),
                self.udp_limit
            ));
            let mut truncated = transfer::response_shell(self.query, message.response_code());
            truncated.set_truncated(true);
            for q in self.query.queries() {
                truncated.add_query(q.clone());
            }
            if let Some(e) = self.response_edns() {
                truncated.set_edns(e);
            }
            return truncated.to_vec().map(|b| vec![b]).unwrap_or_default();
        }
        vec![bytes]
    }

    /// Sign every in-zone RRset of an answer, and prove a negative one with compact denial.
    fn sign_answer(message: &mut DnsMessage, signer: &ZoneSigner, qname: &Name) -> Result<()> {
        let now = now_secs();
        let negative = message.response_code() == ResponseCode::NXDomain
            || (message.response_code() == ResponseCode::NoError && message.answers().is_empty());
        let mut answers = message.take_answers();
        let mut authority = message.take_name_servers();
        let mut additional = message.take_additionals();
        if negative {
            let soa = match authority
                .iter()
                .find(|r| r.record_type() == RecordType::SOA && signer.covers(r.name()))
            {
                Some(soa) => soa.clone(),
                None => {
                    let soa = signer.soa_record();
                    authority.push(soa.clone());
                    soa
                }
            };
            authority.push(signer.compact_denial(qname, dnssec::negative_ttl(&soa))?);
            // Compact denial answers NOERROR: the NSEC proves the name has no types at all.
            message.set_response_code(ResponseCode::NoError);
        }
        let answer_sigs = signer.signatures_for(&mut answers, now)?;
        let authority_sigs = signer.signatures_for(&mut authority, now)?;
        let additional_sigs = signer.signatures_for(&mut additional, now)?;
        answers.extend(answer_sigs);
        authority.extend(authority_sigs);
        additional.extend(additional_sigs);
        message.insert_answers(answers);
        message.insert_name_servers(authority);
        message.add_additionals(additional);
        message.set_authoritative(true);
        Ok(())
    }
}
