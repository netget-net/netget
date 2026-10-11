//! Kafka broker — Rust owns the wire format, the LLM owns the content.
//!
//! # What this broker supports
//!
//! A deliberately narrow subset of the Kafka protocol: enough for a client to complete
//! its opening sequence (ApiVersions → Metadata) and then produce and fetch records.
//!
//! | API | key | versions | answered by |
//! |---|---|---|---|
//! | ApiVersions  | 18 | 0–3  | Rust (pure transport negotiation, no LLM call) |
//! | Metadata     | 3  | 0–12 | LLM / script / static handler |
//! | Produce      | 0  | 0–11 | LLM / script / static handler |
//! | Fetch        | 1  | 0–16 | LLM / script / static handler |
//! | OffsetCommit | 8  | 0–9  | LLM / script / static handler |
//!
//! Everything else — `ListOffsets`, `FindCoordinator`, `JoinGroup`, `SyncGroup`,
//! `Heartbeat`, `OffsetFetch`, the admin APIs — is **not implemented**. Those keys are
//! not advertised in ApiVersions, and if a client sends one anyway the connection is
//! closed with an ERROR log rather than answered with a body this broker cannot build
//! correctly. The practical consequence: a consumer must use manual partition
//! assignment and an explicit fetch offset. Consumer *groups* do not work, because
//! group coordination needs the APIs above.
//!
//! The ceilings are the newest versions `kafka-protocol` 0.14 knows, flexible (tagged-field)
//! versions included; Apache Kafka's Java client and franz-go both complete at Metadata v12,
//! Produce v11 and Fetch v16. From Fetch v13 a topic is named by id: ids are derived from the
//! name ([`topic_id`]) because nothing is stored, and the broker remembers the ones it has
//! reported so an id-only request can be resolved.
//!
//! # Version handling
//!
//! `api_key` and `api_version` are read from the first four bytes of the frame, the
//! request header is decoded at `ApiKey::request_header_version(api_version)`, the body
//! at `api_version`, and the response header at
//! `ApiKey::response_header_version(api_version)`. Nothing is hardcoded to version 0.
//! `correlation_id` sits at a fixed offset in every request header version, so the error
//! paths can echo it without having decoded the header.
//!
//! # No storage
//!
//! This module keeps no topics, no log and no consumer offsets. Every produce, fetch,
//! metadata and offset-commit answer comes from an action returned by the LLM, a script
//! handler or a static handler. A Fetch returns exactly the records the model supplied
//! for that request. There is no per-connection or per-server bookkeeping of offsets:
//! the only state is `cluster_id`, `broker_id` and the advertised host, all fixed at
//! startup.
//!
//! # Failure is refusal, never a default answer
//!
//! If the model (or handler) returns nothing usable, the client gets the correct
//! response *type* carrying `UNKNOWN_SERVER_ERROR` (-1). A model that wants to refuse
//! uses the `error_response` action and picks its own Kafka error code, which is a
//! structurally different path from silence. Nothing is ever invented to keep a client
//! happy — with one documented exception: the broker list in a Metadata response
//! defaults to this server's own listen address, because that is transport truth the
//! model has no way to know and no client can proceed without it.

pub mod actions;

/// Re-export of the wire library.
///
/// Integration tests decode this broker's responses with `kafka-protocol`'s own
/// code-generated client-side decoders — the opposite direction from the encoders used
/// here — which is not possible from `tests/` unless the crate is reachable through
/// `netget`. It is not a dev-dependency and adding one would mean touching `Cargo.toml`.
pub use kafka_protocol;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::KafkaProtocol;
use crate::state::app_state::AppState;
use actions::{
    FETCH_REQUEST_EVENT, METADATA_REQUEST_EVENT, OFFSET_COMMIT_REQUEST_EVENT, PRODUCE_REQUEST_EVENT,
};
use anyhow::Result;
use bytes::Bytes;
use kafka_protocol::messages::{
    ApiKey, ApiVersionsResponse, BrokerId, FetchRequest, FetchResponse, MetadataRequest,
    MetadataResponse, OffsetCommitRequest, OffsetCommitResponse, ProduceRequest, ProduceResponse,
    RequestHeader, ResponseHeader,
};
use kafka_protocol::protocol::{Decodable, Encodable, StrBytes};
use kafka_protocol::records::{
    Compression, Record, RecordBatchDecoder, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, warn};

/// How long to wait for a peer's first request after it has connected.
///
/// Kafka is client-speaks-first with no broker greeting, and every real client opens with
/// `ApiVersions` before it does anything else — `librdkafka`, the Java client and `kcat` all
/// send it inside the connect path. A peer that has connected and sent nothing has made no
/// request at all, so it gets the short bound.
const FIRST_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* request once one has been answered.
///
/// Ten minutes, which is not a guess: it is `connections.max.idle.ms`, the broker setting real
/// Kafka ships with exactly this job, at exactly this default. A producer between batches or a
/// consumer between long polls is legitimately silent for minutes, and copying the broker's own
/// number is the one choice no real client can be surprised by.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Concurrent connections this server admits.
///
/// Each connection may buffer a request of up to [`MAX_REQUEST_BYTES`], so the cap is what
/// turns that per-connection bound into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a plain close, which is what a real broker does.
///
/// Every Kafka response is `(size)(correlation_id)(body)` and the correlation id belongs to the
/// *request* — this peer has sent none, so no well-formed response exists to write. Real
/// brokers hitting `max.connections` close the socket without a word for the same reason, and
/// `librdkafka` reports it as a broker transport failure and backs off. The reason is in the
/// log, tagged `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Smallest useful Kafka request: api_key (i16) + api_version (i16) + correlation_id (i32).
const MIN_REQUEST_BYTES: i32 = 8;

/// Largest request accepted from a client. Real brokers cap this with
/// `socket.request.max.bytes` (default 100 MiB); without a cap the wire-supplied
/// size is an allocation primitive for any unauthenticated peer.
pub const MAX_REQUEST_BYTES: usize = 100 * 1024 * 1024;

/// Cap on how much of a request is hex-dumped at TRACE level.
const MAX_TRACE_HEX_BYTES: usize = 4096;

/// Upper bound on a partition index this broker will talk about. Partition indices
/// arrive as unvalidated i32s and are used to size and index collections.
const MAX_PARTITIONS: i32 = 1024;

/// Upper bound on how many (topic, partition) units one request may contain. Each unit
/// costs one LLM round trip, so an attacker naming 100k partitions in one Produce would
/// otherwise be a request amplifier against the model backend.
const MAX_UNITS_PER_REQUEST: usize = 64;

/// Upper bound on records encoded into one Fetch response partition.
const MAX_RECORDS_PER_FETCH: usize = 1000;

/// Upper bound on the total record payload encoded into one Fetch response partition.
const MAX_FETCH_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// How many produced records are described to the model in one `kafka_produce_request`
/// event, and how many bytes of each. Prompts, not wire limits.
const MAX_EVENT_RECORDS: usize = 20;
const MAX_EVENT_VALUE_BYTES: usize = 1024;

// Kafka error codes used by this module. See
// <https://kafka.apache.org/protocol.html#protocol_error_codes>.
const ERR_UNKNOWN_SERVER_ERROR: i16 = -1;
const ERR_NONE: i16 = 0;
const ERR_CORRUPT_MESSAGE: i16 = 2;
const ERR_UNKNOWN_TOPIC_OR_PARTITION: i16 = 3;
/// Retriable in every Kafka client. Used when the *backend* is saturated rather than
/// when anything about the request was wrong, so the client backs off and tries again
/// instead of recording a permanent fault - the distinction `WireFailure` exists to draw.
const ERR_REQUEST_TIMED_OUT: i16 = 7;
const ERR_UNSUPPORTED_VERSION: i16 = 35;
/// A topic named by an id this broker has never reported (Fetch v13+, Metadata v12).
const ERR_UNKNOWN_TOPIC_ID: i16 = 100;

/// Topic ids remembered for resolving Fetch v13+ and Metadata v12 requests, which name
/// topics by id alone. Every id this broker hands out is derived from the name, so a
/// forgotten one costs a client one `UNKNOWN_TOPIC_ID` and a metadata refresh, never a wrong
/// answer. Past this the oldest one is forgotten, one at a time.
pub const MAX_KNOWN_TOPIC_IDS: usize = 4096;

/// Kafka's own limit on a topic name, in bytes (`Topic.MAX_NAME_LENGTH`). A Metadata answer
/// naming a longer topic leaves that topic out, and its name is never remembered.
pub const MAX_TOPIC_NAME_LEN: usize = 249;

/// The topic ids this broker has reported, oldest first, so a request naming a topic by id
/// alone can be answered. Holds at most [`MAX_KNOWN_TOPIC_IDS`] names of at most
/// [`MAX_TOPIC_NAME_LEN`] bytes each.
#[derive(Default)]
pub struct TopicIds {
    inner: std::sync::Mutex<TopicIdTable>,
}

#[derive(Default)]
struct TopicIdTable {
    names: std::collections::HashMap<uuid::Uuid, String>,
    order: std::collections::VecDeque<uuid::Uuid>,
}

impl TopicIds {
    /// Remember and return the id reported for `name`; `None`, remembering nothing, for a
    /// name over [`MAX_TOPIC_NAME_LEN`] bytes. At [`MAX_KNOWN_TOPIC_IDS`] the oldest id is
    /// forgotten to make room.
    pub fn report(&self, name: &str) -> Option<uuid::Uuid> {
        if name.len() > MAX_TOPIC_NAME_LEN {
            return None;
        }
        let id = topic_id(name);
        let mut table = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !table.names.contains_key(&id) {
            while table.names.len() >= MAX_KNOWN_TOPIC_IDS {
                let Some(oldest) = table.order.pop_front() else {
                    break;
                };
                table.names.remove(&oldest);
            }
            table.order.push_back(id);
        }
        table.names.insert(id, name.to_string());
        Some(id)
    }

    /// The topic a reported id stands for.
    pub fn name(&self, id: &uuid::Uuid) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .names
            .get(id)
            .cloned()
    }

    /// Ids remembered.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .names
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The id this broker reports for a topic (Metadata v10+, Fetch v13+).
///
/// NetGet keeps no topics, so there is nowhere to store an id assigned at creation; it is
/// derived from the name instead — two 64-bit FNV-1a hashes with different offsets, the
/// RFC 9562 version nibble set to 8 (custom). The same name always gets the same id, across
/// connections and restarts, which is what a real broker's stored id gives a client. The
/// nil id and Kafka's reserved `0…01` are never produced.
pub fn topic_id(name: &str) -> uuid::Uuid {
    let fnv = |offset: u64| {
        name.bytes().fold(offset, |h, b| {
            (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
        })
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&fnv(0xcbf2_9ce4_8422_2325).to_be_bytes());
    bytes[8..].copy_from_slice(&fnv(0x6c62_272e_07bb_0142).to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

/// The API keys this broker implements, with the version range it implements for each.
///
/// This table is the single source of truth: it is what ApiVersions advertises and what
/// the dispatcher validates against, so the two can never disagree.
pub const SUPPORTED_APIS: &[(i16, i16, i16)] = &[
    (ApiKey::Produce as i16, 0, 11),
    (ApiKey::Fetch as i16, 0, 16),
    (ApiKey::Metadata as i16, 0, 12),
    (ApiKey::OffsetCommit as i16, 0, 9),
    (ApiKey::ApiVersions as i16, 0, 3),
];

/// Version range this broker implements for `api_key`, if any.
pub fn supported_versions(api_key: i16) -> Option<(i16, i16)> {
    SUPPORTED_APIS
        .iter()
        .find(|(k, _, _)| *k == api_key)
        .map(|(_, min, max)| (*min, *max))
}

/// Kafka broker server state.
///
/// Deliberately tiny: everything here is fixed at startup and describes *this process*,
/// not the contents of any topic. There is no log and no offset store; see the module
/// docs.
pub struct KafkaServer {
    /// Cluster ID reported in Metadata (v2+ only; earlier versions have no such field).
    cluster_id: String,
    /// Broker ID reported in Metadata and used as the default partition leader.
    broker_id: i32,
    /// Host advertised to clients in Metadata when the model does not name one.
    advertised_host: String,
    /// Ids this broker has reported, so a request naming a topic by id alone can be
    /// answered.
    topic_ids: TopicIds,
}

impl KafkaServer {
    /// Remember (and return) the id reported for `name`; `None` for a name Kafka would refuse.
    fn report_topic(&self, name: &str) -> Option<uuid::Uuid> {
        self.topic_ids.report(name)
    }

    /// The topic a reported id stands for.
    fn topic_name(&self, id: &uuid::Uuid) -> Option<String> {
        self.topic_ids.name(id)
    }
}

/// What the model said about one request unit.
enum Reply {
    /// The expected response action, with its parameters.
    Data(Value),
    /// An explicit `error_response` with a model-chosen Kafka error code.
    Error(i16),
    /// Nothing usable came back. Never treated as approval.
    ///
    /// Carries the error code to report, because the two ways of getting here are not the
    /// same thing to a client: a saturated backend is transient and gets the retriable
    /// `REQUEST_TIMED_OUT`, while a handler that ran and produced nothing usable gets
    /// `UNKNOWN_SERVER_ERROR`, which clients treat as permanent. Collapsing both onto -1
    /// made an overloaded backend look like a broken broker.
    NoAnswer(i16),
}

/// The write half of one live connection.
///
/// Shared between the session below and the dashboard's peer-command task
/// (`server::peer_support`), so an injected send and the broker's own reply cannot interleave
/// bytes into the middle of each other's frame. Split from the socket with
/// `tokio::io::split`; never cloned.
type SharedWrite = Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>;

impl KafkaServer {
    /// Spawn Kafka broker with LLM integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        let cluster_id = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("cluster_id"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "netget-kafka-1".to_string());
        let broker_id = startup_params
            .as_ref()
            .map(|p| p.get_optional_i64("broker_id"))
            .transpose()?
            .flatten()
            .unwrap_or(0)
            .clamp(0, i32::MAX as i64) as i32;
        let advertised_host_param = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("advertised_host"))
            .transpose()?
            .flatten();

        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        // A client connects to whatever host the Metadata response names. If we are
        // bound to a wildcard address, the bound IP is not connectable, so fall back to
        // localhost rather than advertising 0.0.0.0.
        let advertised_host = advertised_host_param.unwrap_or_else(|| {
            if local_addr.ip().is_unspecified() {
                "localhost".to_string()
            } else {
                local_addr.ip().to_string()
            }
        });

        let log = Log::new(Some(&status_tx));
        log.info(format!(
            "Kafka broker listening on {} (cluster={}, broker_id={}, advertised_host={})",
            local_addr, cluster_id, broker_id, advertised_host
        ));
        // Generated from SUPPORTED_APIS, so the log cannot disagree with what is advertised.
        let supported = SUPPORTED_APIS
            .iter()
            .map(|(key, min, max)| match ApiKey::try_from(*key) {
                Ok(api) => format!("{api:?} v{min}-{max}"),
                Err(_) => format!("key {key} v{min}-{max}"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        log.info(format!(
            "Kafka supports {}. Other API keys (ListOffsets, FindCoordinator, JoinGroup, \
             SyncGroup, Heartbeat, OffsetFetch, admin) are not implemented, so consumer groups \
             do not work; consumers must assign partitions and fetch from an explicit offset. \
             Broker advertises host '{}'.",
            supported, advertised_host
        ));

        let server = Arc::new(KafkaServer {
            cluster_id,
            broker_id,
            advertised_host,
            topic_ids: Default::default(),
        });

        let protocol = Arc::new(KafkaProtocol::new());

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Kafka",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, peer_addr, permit)) => {
                        Log::new(Some(&status_tx))
                            .debug(format!("Kafka client connected from {}", peer_addr));

                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let server_clone = server.clone();
                        let protocol_clone = protocol.clone();

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
                            bytes_received: 0,
                            packets_sent: 0,
                            packets_received: 0,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::empty(),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_clone.send("__UPDATE_UI__".to_string());

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // clients rather than accepts.
                                let _permit = permit;
                                let result = Self::handle_connection(
                                    stream,
                                    peer_addr,
                                    local_addr,
                                    connection_id,
                                    server_clone,
                                    llm_clone,
                                    state_clone.clone(),
                                    status_clone.clone(),
                                    server_id,
                                    protocol_clone,
                                )
                                .await;

                                if let Err(e) = result {
                                    error!("Kafka connection error: {}", e);
                                }

                                // Connections used to be added and never removed, so the
                                // TUI accumulated Active entries for dead sockets.
                                //
                                // `close_connection_on_server`, not `update_connection_status`:
                                // both mark the row `Closed`, but only the former also runs
                                // `cleanup_connection_tasks`. A connection-scoped scheduled
                                // task belongs to a connection that no longer exists, and a
                                // recurring one keeps ticking after the socket is gone — each
                                // tick an LLM prompt about a peer that has hung up. Marking the
                                // row closed and leaving the tasks running is the defect
                                // `remove_server` was restructured to prevent, one level down.
                                state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                let _ = status_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        // Without a break this spun a hot loop on a persistent
                        // error (EMFILE), saturating a core and flooding the
                        // unbounded status channel.
                        Log::new(Some(&status_tx))
                            .error(format!("Kafka accept error, loop stopping: {}", e));
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

    /// Set one connection up, run it, and tear it down on every exit path.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        connection_id: ConnectionId,
        server: Arc<KafkaServer>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<KafkaProtocol>,
    ) -> Result<()> {
        let (reader, write_half) = tokio::io::split(stream);
        let write_half: SharedWrite = Arc::new(Mutex::new(write_half));

        // Peer messaging, registered BEFORE the first read. Kafka is client-speaks-first and
        // the broker says nothing until a request arrives, so a `*` manual rule parks the very
        // first request this connection makes - and the operator being asked to decide about it
        // must be able to reach, or hang up, the connection while it waits. Registering once
        // the session was under way would leave exactly that case unreachable.
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
            write_half.clone(),
            status_tx.clone(),
        );

        let result = Self::run_session(
            reader,
            &write_half,
            peer_addr,
            local_addr,
            connection_id,
            server,
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            server_id,
            protocol,
        )
        .await;

        // Every exit path lands here - clean EOF, an invalid size prefix, an unparseable
        // header, a write error, an injected disconnect. The `?`s all live in `run_session`,
        // so none of them can skip this. Dropping the handle also ends the peer command task;
        // the explicit shutdown makes the FIN immediate rather than waiting on it.
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        let _ = write_half.lock().await.shutdown().await;
        result
    }

    /// Read one length-prefixed request, answer it, repeat.
    #[allow(clippy::too_many_arguments)]
    async fn run_session(
        mut reader: tokio::io::ReadHalf<TcpStream>,
        write_half: &SharedWrite,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        connection_id: ConnectionId,
        server: Arc<KafkaServer>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<KafkaProtocol>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 8192];
        let mut answered_one = false;

        loop {
            // Both reads below are bounded by this deadline and nothing else is. The LLM
            // round-trip that answers the request, and a `manual` rule parking it for a human
            // (`src/state/intercepts.rs`, 300s by default), happen further down the loop body
            // once the whole request has arrived — so neither sits inside a read deadline and
            // neither can be cut short by one. What is bounded is a peer holding the connection
            // while sending nothing, and a peer that announces a request size and then stalls
            // part-way through delivering it.
            let read_timeout = if answered_one {
                IDLE_BETWEEN_REQUESTS_TIMEOUT
            } else {
                FIRST_REQUEST_READ_TIMEOUT
            };

            // Read the size prefix with read_exact. A plain read() may return 1-3
            // bytes, and the old code parsed all four regardless, mixing in stale
            // bytes from the previous message.
            let mut size_prefix = [0u8; 4];
            let prefix_read =
                match tokio::time::timeout(read_timeout, reader.read_exact(&mut size_prefix)).await
                {
                    Ok(read) => read,
                    Err(_) => {
                        Log::new(Some(&status_tx)).debug(format!(
                            "Kafka client {} sent nothing for {}s; closing idle connection",
                            peer_addr,
                            read_timeout.as_secs()
                        ));
                        break;
                    }
                };
            match prefix_read {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    Log::new(Some(&status_tx))
                        .debug(format!("Kafka client {} disconnected", peer_addr));
                    break;
                }
                Err(e) => return Err(e.into()),
            }

            // Validate the declared size before it reaches any allocator. This is
            // unauthenticated input: `i32 as usize` sign-extends, so a prefix of
            // 0x80000000 became ~1.8e19 and aborted the process on Vec::resize,
            // while 0x7fffffff zeroed 2 GiB per connection. Sizes below the 8-byte
            // request header are equally unusable. The comparison is done in i64 so
            // that `declared` can never wrap.
            let declared = i32::from_be_bytes(size_prefix);
            if declared < MIN_REQUEST_BYTES || declared as i64 > MAX_REQUEST_BYTES as i64 {
                Log::new(Some(&status_tx)).warn(format!(
                    "Kafka client {} declared an invalid request size of {} bytes (allowed {}..={}); closing connection",
                    peer_addr, declared, MIN_REQUEST_BYTES, MAX_REQUEST_BYTES
                ));
                break;
            }
            let message_size = declared as usize;

            // Grow only: the buffer must never shrink below the size prefix.
            if buffer.len() < message_size {
                buffer.resize(message_size, 0);
            }
            match tokio::time::timeout(read_timeout, reader.read_exact(&mut buffer[..message_size]))
                .await
            {
                Ok(read) => read?,
                Err(_) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "Kafka client {} announced a {}-byte request and stalled for {}s \
                         without delivering it; closing",
                        peer_addr,
                        message_size,
                        read_timeout.as_secs()
                    ));
                    break;
                }
            };
            // A whole request has arrived: from here on this peer is an established client and
            // the longer idle bound applies.
            answered_one = true;

            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    Some((message_size + 4) as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;

            let log = Log::new(Some(&status_tx));
            log.debug(format!(
                "Kafka received {} bytes from {}",
                message_size, peer_addr
            ));

            // TRACE: hex dump, capped — hex::encode doubles the payload, so a
            // maximum-size request would otherwise build a 200 MiB String.
            let hex_len = message_size.min(MAX_TRACE_HEX_BYTES);
            log.trace(format!(
                "Kafka raw request: {} bytes, first {} hex: {}",
                message_size,
                hex_len,
                hex::encode(&buffer[..hex_len])
            ));

            // api_key, api_version and correlation_id sit at fixed offsets in every
            // request header version, so they can be read before choosing a header
            // version to decode with. message_size >= MIN_REQUEST_BYTES (8) is already
            // enforced above, so these slices are always in bounds.
            let api_key_raw = i16::from_be_bytes([buffer[0], buffer[1]]);
            let api_version = i16::from_be_bytes([buffer[2], buffer[3]]);
            let correlation_id = i32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

            let api_key = match ApiKey::try_from(api_key_raw) {
                Ok(k) => k,
                Err(_) => {
                    Log::new(Some(&status_tx)).error(format!(
                        "Kafka client {} sent unknown API key {}; closing connection rather than \
                         inventing a response body",
                        peer_addr, api_key_raw
                    ));
                    break;
                }
            };

            let supported = supported_versions(api_key_raw);
            let version_ok =
                matches!(supported, Some((min, max)) if api_version >= min && api_version <= max);

            if !version_ok {
                if api_key == ApiKey::ApiVersions {
                    // Kafka's one special case: an ApiVersions request at a version the
                    // broker does not implement is answered with UNSUPPORTED_VERSION and
                    // the supported-API table, both encoded at v0, which every client
                    // knows how to read. That is how clients negotiate downwards.
                    Log::new(Some(&status_tx)).debug(format!(
                        "Kafka ApiVersions v{} unsupported; replying at v0 with error {}",
                        api_version, ERR_UNSUPPORTED_VERSION
                    ));
                    let body =
                        Self::api_versions_response(0, correlation_id, ERR_UNSUPPORTED_VERSION)?;
                    Self::write_frame(
                        write_half,
                        &body,
                        &app_state,
                        server_id,
                        connection_id,
                        &status_tx,
                        peer_addr,
                    )
                    .await?;
                    continue;
                }
                let range = supported
                    .map(|(min, max)| format!("v{}..=v{}", min, max))
                    .unwrap_or_else(|| "not implemented".to_string());
                Log::new(Some(&status_tx)).error(format!(
                    "Kafka client {} requested {:?} v{} which this broker does not implement ({}). \
                     Closing the connection — a wrong-shaped body would be worse than an error.",
                    peer_addr, api_key, api_version, range
                ));
                break;
            }

            // Decode the header at the version this (api_key, api_version) pair implies,
            // then continue with the same cursor so the body starts where the header
            // ended. Hardcoding 0 here left the cursor inside client_id for every real
            // client and garbled every field after it.
            let header_version = api_key.request_header_version(api_version);
            let mut cursor = std::io::Cursor::new(&buffer[..message_size]);
            let header = match RequestHeader::decode(&mut cursor, header_version) {
                Ok(h) => h,
                Err(e) => {
                    Log::new(Some(&status_tx)).error(format!(
                        "Kafka client {}: unparseable request header for {:?} v{} (header v{}): {}; closing",
                        peer_addr, api_key, api_version, header_version, e
                    ));
                    break;
                }
            };

            let client_id = header
                .client_id
                .as_ref()
                .map(|c| c.to_string())
                .unwrap_or_default();

            Log::new(Some(&status_tx)).debug(format!(
                "Kafka request: {:?} v{} correlation_id={} client_id={:?}",
                api_key, api_version, header.correlation_id, client_id
            ));

            let ctx = RequestCtx {
                api_version,
                correlation_id: header.correlation_id,
                client_id,
                peer_addr,
                local_addr,
                connection_id,
                server_id,
            };

            let response_bytes: Option<Vec<u8>> = match api_key {
                ApiKey::ApiVersions => Some(Self::api_versions_response(
                    api_version,
                    header.correlation_id,
                    ERR_NONE,
                )?),
                ApiKey::Metadata => Some(
                    Self::handle_metadata(
                        &mut cursor,
                        &ctx,
                        &server,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &protocol,
                    )
                    .await?,
                ),
                ApiKey::Produce => {
                    Self::handle_produce(
                        &mut cursor,
                        &ctx,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &protocol,
                    )
                    .await?
                }
                ApiKey::Fetch => Some(
                    Self::handle_fetch(
                        &mut cursor,
                        &ctx,
                        &server,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &protocol,
                    )
                    .await?,
                ),
                ApiKey::OffsetCommit => Some(
                    Self::handle_offset_commit(
                        &mut cursor,
                        &ctx,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &protocol,
                    )
                    .await?,
                ),
                // Unreachable: SUPPORTED_APIS gates the match above.
                other => {
                    Log::new(Some(&status_tx)).error(format!(
                        "Kafka: API {:?} is advertised but has no handler; closing connection",
                        other
                    ));
                    break;
                }
            };

            match response_bytes {
                Some(body) => {
                    Self::write_frame(
                        write_half,
                        &body,
                        &app_state,
                        server_id,
                        connection_id,
                        &status_tx,
                        peer_addr,
                    )
                    .await?;
                }
                None => {
                    // acks=0 Produce: the producer expects no reply at all.
                    Log::new(Some(&status_tx)).debug(format!(
                        "Kafka: no response written for correlation_id={} (acks=0)",
                        header.correlation_id
                    ));
                }
            }
        }

        Ok(())
    }

    async fn write_frame(
        write_half: &SharedWrite,
        body: &[u8],
        app_state: &Arc<AppState>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let size = i32::try_from(body.len()).map_err(|_| {
            anyhow::anyhow!(
                "Kafka response of {} bytes exceeds the i32 size prefix",
                body.len()
            )
        })?;
        // One lock for the whole frame: the size prefix and the body are a single unit on the
        // wire, and an injected write landing between them would desynchronise the client for
        // the rest of the connection. The guard is dropped before the stats update so nothing
        // awaits while holding the write half.
        {
            let mut writer = write_half.lock().await;
            writer.write_all(&size.to_be_bytes()).await?;
            writer.write_all(body).await?;
            writer.flush().await?;
        }

        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some((body.len() + 4) as u64),
                None,
                Some(1),
            )
            .await;

        let log = Log::new(Some(status_tx));
        log.debug(format!("Kafka sent {} bytes to {}", body.len(), peer_addr));
        let hex_len = body.len().min(MAX_TRACE_HEX_BYTES);
        log.trace(format!(
            "Kafka raw response: {} bytes, first {} hex: {}",
            body.len(),
            hex_len,
            hex::encode(&body[..hex_len])
        ));
        Ok(())
    }

    /// ApiVersions is answered by Rust, not the model: it advertises what this *code*
    /// can parse and encode, which is not a content decision.
    fn api_versions_response(
        api_version: i16,
        correlation_id: i32,
        error_code: i16,
    ) -> Result<Vec<u8>> {
        use kafka_protocol::messages::api_versions_response::ApiVersion;

        let api_keys: Vec<ApiVersion> = SUPPORTED_APIS
            .iter()
            .map(|(key, min, max)| {
                ApiVersion::default()
                    .with_api_key(*key)
                    .with_min_version(*min)
                    .with_max_version(*max)
            })
            .collect();

        let response = ApiVersionsResponse::default()
            .with_error_code(error_code)
            .with_api_keys(api_keys)
            .with_throttle_time_ms(0);

        let mut buf = Vec::new();
        ResponseHeader::default()
            .with_correlation_id(correlation_id)
            .encode(
                &mut buf,
                ApiKey::ApiVersions.response_header_version(api_version),
            )?;
        response.encode(&mut buf, api_version)?;
        Ok(buf)
    }

    /// Metadata: the model decides which topics exist and how they are partitioned.
    /// Rust decides which broker address to advertise, because only Rust knows it.
    #[allow(clippy::too_many_arguments)]
    async fn handle_metadata(
        cursor: &mut std::io::Cursor<&[u8]>,
        ctx: &RequestCtx,
        server: &Arc<KafkaServer>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<KafkaProtocol>,
    ) -> Result<Vec<u8>> {
        use kafka_protocol::messages::metadata_response::{
            MetadataResponseBroker, MetadataResponsePartition, MetadataResponseTopic,
        };

        let request = MetadataRequest::decode(cursor, ctx.api_version)?;

        // `topics: None` means "all topics"; `Some([])` means "no topics". From v12 a topic
        // may be named by id alone; an id this broker never reported is UNKNOWN_TOPIC_ID.
        let mut unknown_ids = Vec::new();
        let requested_topics: Vec<String> = request
            .topics
            .as_ref()
            .map(|ts| {
                ts.iter()
                    .filter_map(|t| match &t.name {
                        Some(n) => Some(n.to_string()),
                        None => {
                            let name = server.topic_name(&t.topic_id);
                            if name.is_none() {
                                unknown_ids.push(t.topic_id);
                            }
                            name
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let wants_all_topics = request.topics.is_none();

        Log::new(Some(status_tx)).debug(format!(
            "Kafka metadata request: all_topics={}, topics={:?}",
            wants_all_topics, requested_topics
        ));

        let event = Event::new(
            &METADATA_REQUEST_EVENT,
            json!({
                "requested_topics": requested_topics,
                "all_topics": wants_all_topics,
                "client_id": ctx.client_id,
                "api_version": ctx.api_version,
            }),
        );

        let reply = Self::ask_model(
            &event,
            "metadata_response",
            llm_client,
            app_state,
            status_tx,
            ctx,
            protocol,
        )
        .await;

        // Whatever happens, the client needs a reachable broker address or it cannot
        // proceed. This is the one default in the module and it is transport truth.
        let default_broker = MetadataResponseBroker::default()
            .with_node_id(BrokerId(server.broker_id))
            .with_host(StrBytes::from_string(server.advertised_host.clone()))
            .with_port(ctx.local_addr.port() as i32);

        let (brokers, mut response_topics) = match &reply {
            Reply::Data(data) => {
                let brokers = data
                    .get("brokers")
                    .and_then(|v| v.as_array())
                    .map(|list| {
                        list.iter()
                            .filter_map(|b| {
                                let host = b.get("host").and_then(|v| v.as_str())?;
                                let port = b.get("port").and_then(|v| v.as_i64())?;
                                if !(1..=65535).contains(&port) {
                                    warn!("Kafka metadata_response: broker port {} out of range, dropped", port);
                                    return None;
                                }
                                let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(server.broker_id as i64);
                                Some(
                                    MetadataResponseBroker::default()
                                        .with_node_id(BrokerId(id.clamp(0, i32::MAX as i64) as i32))
                                        .with_host(StrBytes::from_string(host.to_string()))
                                        .with_port(port as i32),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .filter(|v: &Vec<_>| !v.is_empty())
                    .unwrap_or_else(|| {
                        Log::new(Some(status_tx)).debug(format!(
                            "Kafka metadata_response named no usable broker; advertising this server ({}:{})",
                            server.advertised_host,
                            ctx.local_addr.port()
                        ));
                        vec![default_broker.clone()]
                    });

                let mut topics = Vec::new();
                if let Some(list) = data.get("topics").and_then(|v| v.as_array()) {
                    for t in list {
                        let Some(name) = t.get("name").and_then(|v| v.as_str()) else {
                            Log::new(Some(status_tx)).warn(
                                "Kafka metadata_response: topic entry without a 'name' ignored",
                            );
                            continue;
                        };
                        // Kafka refuses such a name; a requested one falls through to the
                        // unknown-topic answer below rather than being described.
                        if name.len() > MAX_TOPIC_NAME_LEN {
                            Log::new(Some(status_tx)).warn(format!(
                                "Kafka metadata_response: topic name of {} bytes ignored; \
                                 Kafka's limit is {MAX_TOPIC_NAME_LEN}",
                                name.len()
                            ));
                            continue;
                        }
                        let topic_error =
                            clamp_error_code(t.get("error_code").and_then(|v| v.as_i64()));

                        let mut partitions = Vec::new();
                        if let Some(plist) = t.get("partitions").and_then(|v| v.as_array()) {
                            for p in plist {
                                let idx = p.get("partition").and_then(|v| v.as_i64()).unwrap_or(0);
                                if !(0..=MAX_PARTITIONS as i64).contains(&idx) {
                                    Log::new(Some(status_tx)).warn(format!(
                                        "Kafka metadata_response: partition index {} for '{}' outside 0..={}, dropped",
                                        idx, name, MAX_PARTITIONS
                                    ));
                                    continue;
                                }
                                let leader = p
                                    .get("leader")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(server.broker_id as i64)
                                    .clamp(0, i32::MAX as i64)
                                    as i32;
                                let replicas: Vec<BrokerId> = p
                                    .get("replicas")
                                    .and_then(|v| v.as_array())
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|x| x.as_i64())
                                            .map(|x| BrokerId(x.clamp(0, i32::MAX as i64) as i32))
                                            .collect()
                                    })
                                    .filter(|v: &Vec<BrokerId>| !v.is_empty())
                                    .unwrap_or_else(|| vec![BrokerId(leader)]);
                                partitions.push(
                                    MetadataResponsePartition::default()
                                        .with_partition_index(idx as i32)
                                        .with_leader_id(BrokerId(leader))
                                        .with_replica_nodes(replicas.clone())
                                        .with_isr_nodes(replicas)
                                        .with_error_code(ERR_NONE),
                                );
                            }
                        }

                        if partitions.is_empty() && topic_error == ERR_NONE {
                            // A topic with no partitions is unusable to every client.
                            Log::new(Some(status_tx)).debug(format!(
                                "Kafka metadata_response: topic '{}' declared no partitions; assuming a single partition led by broker {}",
                                name, server.broker_id
                            ));
                            partitions.push(
                                MetadataResponsePartition::default()
                                    .with_partition_index(0)
                                    .with_leader_id(BrokerId(server.broker_id))
                                    .with_replica_nodes(vec![BrokerId(server.broker_id)])
                                    .with_isr_nodes(vec![BrokerId(server.broker_id)])
                                    .with_error_code(ERR_NONE),
                            );
                        }

                        let mut topic = MetadataResponseTopic::default()
                            .with_name(Some(StrBytes::from_string(name.to_string()).into()))
                            .with_partitions(partitions)
                            .with_error_code(topic_error);
                        if ctx.api_version >= 10 {
                            if let Some(id) = server.report_topic(name) {
                                topic = topic.with_topic_id(id);
                            }
                        }
                        topics.push(topic);
                    }
                }
                (brokers, topics)
            }
            Reply::Error(code) => {
                Log::new(Some(status_tx)).debug(format!(
                    "Kafka metadata: model refused with error code {}",
                    code
                ));
                (vec![default_broker.clone()], Vec::new())
            }
            Reply::NoAnswer(_) => (vec![default_broker.clone()], Vec::new()),
        };

        // Any topic the client explicitly asked about but the model did not describe is
        // reported as unknown (or with the model's chosen error code). Silence about a
        // requested topic must never look like success.
        let fallback_error = match &reply {
            Reply::Data(_) => ERR_UNKNOWN_TOPIC_OR_PARTITION,
            Reply::Error(code) => *code,
            Reply::NoAnswer(code) => *code,
        };
        for name in &requested_topics {
            let described = response_topics
                .iter()
                .any(|t| t.name.as_ref().map(|n| n.to_string()).as_deref() == Some(name.as_str()));
            if !described {
                response_topics.push(
                    MetadataResponseTopic::default()
                        .with_name(Some(StrBytes::from_string(name.clone()).into()))
                        .with_error_code(fallback_error),
                );
            }
        }
        for id in unknown_ids {
            response_topics.push(
                MetadataResponseTopic::default()
                    .with_name(None)
                    .with_topic_id(id)
                    .with_error_code(ERR_UNKNOWN_TOPIC_ID),
            );
        }

        if matches!(reply, Reply::NoAnswer(_)) && requested_topics.is_empty() {
            Log::new(Some(status_tx)).warn(
                "Kafka metadata: no answer from the model and no specific topic was requested; \
                 replying with the broker list and an empty topic list",
            );
        }

        Log::new(Some(status_tx)).info(format!(
            "Kafka metadata reply: {} broker(s), {} topic(s)",
            brokers.len(),
            response_topics.len()
        ));

        let response = MetadataResponse::default()
            .with_brokers(brokers)
            .with_cluster_id(Some(StrBytes::from_string(server.cluster_id.clone())))
            .with_controller_id(BrokerId(server.broker_id))
            .with_topics(response_topics)
            .with_throttle_time_ms(0);

        let mut buf = Vec::new();
        ResponseHeader::default()
            .with_correlation_id(ctx.correlation_id)
            .encode(
                &mut buf,
                ApiKey::Metadata.response_header_version(ctx.api_version),
            )?;
        response.encode(&mut buf, ctx.api_version)?;
        Ok(buf)
    }

    /// Produce: Rust decodes the record batch, the model decides whether it is accepted
    /// and at what offset. Nothing is stored.
    ///
    /// Returns `None` when `acks == 0`, because the producer is not waiting for a reply.
    #[allow(clippy::too_many_arguments)]
    async fn handle_produce(
        cursor: &mut std::io::Cursor<&[u8]>,
        ctx: &RequestCtx,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<KafkaProtocol>,
    ) -> Result<Option<Vec<u8>>> {
        use kafka_protocol::messages::produce_response::{
            PartitionProduceResponse, TopicProduceResponse,
        };

        let request = ProduceRequest::decode(cursor, ctx.api_version)?;
        let acks = request.acks;

        let mut topic_responses = Vec::new();
        let mut units = 0usize;

        for topic_data in &request.topic_data {
            let topic_name = topic_data.name.to_string();
            let mut partition_responses = Vec::new();

            for partition_data in &topic_data.partition_data {
                let partition_idx = partition_data.index;

                if !(0..=MAX_PARTITIONS).contains(&partition_idx) {
                    Log::new(Some(status_tx)).warn(format!(
                        "Kafka produce for '{}' names out-of-range partition {} (0..={}); rejected",
                        topic_name, partition_idx, MAX_PARTITIONS
                    ));
                    partition_responses.push(
                        PartitionProduceResponse::default()
                            .with_index(partition_idx)
                            .with_error_code(ERR_UNKNOWN_TOPIC_OR_PARTITION)
                            .with_base_offset(-1),
                    );
                    continue;
                }

                units += 1;
                if units > MAX_UNITS_PER_REQUEST {
                    Log::new(Some(status_tx)).warn(format!(
                        "Kafka produce names more than {} topic-partitions in one request; \
                         remaining ones rejected without consulting the model",
                        MAX_UNITS_PER_REQUEST
                    ));
                    partition_responses.push(
                        PartitionProduceResponse::default()
                            .with_index(partition_idx)
                            .with_error_code(ERR_UNKNOWN_SERVER_ERROR)
                            .with_base_offset(-1),
                    );
                    continue;
                }

                // Decode the batch. A batch we cannot parse is CORRUPT_MESSAGE — it used
                // to be replaced with an empty placeholder record and acknowledged as
                // success, which told the producer its data was durable when it had been
                // silently dropped.
                let records = match &partition_data.records {
                    Some(raw) => {
                        let owned = Bytes::copy_from_slice(raw.as_ref());
                        let mut rc = std::io::Cursor::new(owned);
                        match RecordBatchDecoder::decode_with_custom_compression::<
                            _,
                            fn(&mut Bytes, Compression) -> Result<std::io::Cursor<Bytes>>,
                        >(
                            &mut rc,
                            None::<fn(&mut Bytes, Compression) -> Result<std::io::Cursor<Bytes>>>,
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                Log::new(Some(status_tx)).warn(format!(
                                    "Kafka produce to '{}' partition {}: unparseable record batch ({}); \
                                     replying CORRUPT_MESSAGE",
                                    topic_name, partition_idx, e
                                ));
                                partition_responses.push(
                                    PartitionProduceResponse::default()
                                        .with_index(partition_idx)
                                        .with_error_code(ERR_CORRUPT_MESSAGE)
                                        .with_base_offset(-1),
                                );
                                continue;
                            }
                        }
                    }
                    None => Vec::new(),
                };

                let event_records: Vec<Value> = records
                    .iter()
                    .take(MAX_EVENT_RECORDS)
                    .map(|r| {
                        let (key, key_encoding) = r
                            .key
                            .as_ref()
                            .map(|k| encode_field(k, MAX_EVENT_VALUE_BYTES))
                            .unwrap_or((Value::Null, "utf8"));
                        let (value, value_encoding) = r
                            .value
                            .as_ref()
                            .map(|v| encode_field(v, MAX_EVENT_VALUE_BYTES))
                            .unwrap_or((Value::Null, "utf8"));
                        json!({
                            "offset": r.offset,
                            "timestamp": r.timestamp,
                            "key": key,
                            "key_encoding": key_encoding,
                            "value": value,
                            "value_encoding": value_encoding,
                        })
                    })
                    .collect();

                let first_key = records
                    .first()
                    .and_then(|r| r.key.as_ref())
                    .map(|k| encode_field(k, MAX_EVENT_VALUE_BYTES).0)
                    .unwrap_or(Value::Null);
                let first_value = records
                    .first()
                    .and_then(|r| r.value.as_ref())
                    .map(|v| encode_field(v, MAX_EVENT_VALUE_BYTES).0)
                    .unwrap_or(Value::String(String::new()));

                let event = Event::new(
                    &PRODUCE_REQUEST_EVENT,
                    json!({
                        "topic": topic_name,
                        "partition": partition_idx,
                        "record_count": records.len(),
                        "first_key": first_key,
                        "first_value_preview": first_value,
                        "records": event_records,
                        "acks": acks,
                        "client_id": ctx.client_id,
                        "api_version": ctx.api_version,
                    }),
                );

                let reply = Self::ask_model(
                    &event,
                    "produce_response",
                    llm_client,
                    app_state,
                    status_tx,
                    ctx,
                    protocol,
                )
                .await;

                let (error_code, base_offset) = match reply {
                    Reply::Data(data) => {
                        let code =
                            clamp_error_code(data.get("error_code").and_then(|v| v.as_i64()));
                        let offset = data
                            .get("offset")
                            .and_then(|v| v.as_i64())
                            .unwrap_or_else(|| {
                                if code == ERR_NONE {
                                    Log::new(Some(status_tx)).warn(format!(
                                        "Kafka produce_response for '{}' partition {} omitted 'offset'; using 0",
                                        topic_name, partition_idx
                                    ));
                                }
                                0
                            });
                        if code == ERR_NONE {
                            Log::new(Some(status_tx)).info(format!(
                                "Kafka produce accepted: '{}' partition {} at offset {} ({} record(s))",
                                topic_name, partition_idx, offset, records.len()
                            ));
                            (code, offset.max(0))
                        } else {
                            (code, -1)
                        }
                    }
                    Reply::Error(code) => (code, -1),
                    Reply::NoAnswer(code) => (code, -1),
                };

                partition_responses.push(
                    PartitionProduceResponse::default()
                        .with_index(partition_idx)
                        .with_base_offset(base_offset)
                        .with_error_code(error_code),
                );
            }

            topic_responses.push(
                TopicProduceResponse::default()
                    .with_name(StrBytes::from_string(topic_name).into())
                    .with_partition_responses(partition_responses),
            );
        }

        if acks == 0 {
            // Fire-and-forget producer: sending a response here would desynchronise it.
            return Ok(None);
        }

        let response = ProduceResponse::default()
            .with_responses(topic_responses)
            .with_throttle_time_ms(0);

        let mut buf = Vec::new();
        ResponseHeader::default()
            .with_correlation_id(ctx.correlation_id)
            .encode(
                &mut buf,
                ApiKey::Produce.response_header_version(ctx.api_version),
            )?;
        response.encode(&mut buf, ctx.api_version)?;
        Ok(Some(buf))
    }

    /// Fetch: the model supplies the records. There is no log to read from.
    #[allow(clippy::too_many_arguments)]
    async fn handle_fetch(
        cursor: &mut std::io::Cursor<&[u8]>,
        ctx: &RequestCtx,
        server: &Arc<KafkaServer>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<KafkaProtocol>,
    ) -> Result<Vec<u8>> {
        use kafka_protocol::messages::fetch_response::{FetchableTopicResponse, PartitionData};

        let request = FetchRequest::decode(cursor, ctx.api_version)?;
        let request_max_bytes = request.max_bytes;

        let mut topic_responses = Vec::new();
        let mut units = 0usize;

        for topic in &request.topics {
            // From v13 a fetch names its topic by id; one this broker never reported cannot
            // be asked about, and every partition of it is UNKNOWN_TOPIC_ID.
            let by_id = ctx.api_version >= 13;
            let topic_name = if by_id {
                match server.topic_name(&topic.topic_id) {
                    Some(name) => name,
                    None => {
                        topic_responses.push(
                            FetchableTopicResponse::default()
                                .with_topic_id(topic.topic_id)
                                .with_partitions(
                                    topic
                                        .partitions
                                        .iter()
                                        .map(|p| {
                                            PartitionData::default()
                                                .with_partition_index(p.partition)
                                                .with_error_code(ERR_UNKNOWN_TOPIC_ID)
                                                .with_records(Some(Bytes::new()))
                                        })
                                        .collect(),
                                ),
                        );
                        continue;
                    }
                }
            } else {
                topic.topic.to_string()
            };
            let mut partition_responses = Vec::new();

            for partition in &topic.partitions {
                let partition_idx = partition.partition;
                let fetch_offset = partition.fetch_offset;

                if !(0..=MAX_PARTITIONS).contains(&partition_idx) {
                    partition_responses.push(
                        PartitionData::default()
                            .with_partition_index(partition_idx)
                            .with_error_code(ERR_UNKNOWN_TOPIC_OR_PARTITION)
                            .with_records(Some(Bytes::new())),
                    );
                    continue;
                }

                units += 1;
                if units > MAX_UNITS_PER_REQUEST {
                    Log::new(Some(status_tx)).warn(format!(
                        "Kafka fetch names more than {} topic-partitions in one request; \
                         remaining ones rejected without consulting the model",
                        MAX_UNITS_PER_REQUEST
                    ));
                    partition_responses.push(
                        PartitionData::default()
                            .with_partition_index(partition_idx)
                            .with_error_code(ERR_UNKNOWN_SERVER_ERROR)
                            .with_records(Some(Bytes::new())),
                    );
                    continue;
                }

                let max_bytes = if partition.partition_max_bytes > 0 {
                    partition.partition_max_bytes
                } else {
                    request_max_bytes
                };

                let event = Event::new(
                    &FETCH_REQUEST_EVENT,
                    json!({
                        "topic": topic_name,
                        "partition": partition_idx,
                        "fetch_offset": fetch_offset,
                        "max_bytes": max_bytes,
                        "client_id": ctx.client_id,
                        "api_version": ctx.api_version,
                    }),
                );

                let reply = Self::ask_model(
                    &event,
                    "fetch_response",
                    llm_client,
                    app_state,
                    status_tx,
                    ctx,
                    protocol,
                )
                .await;

                let pd = match reply {
                    Reply::Data(data) => {
                        let list = data
                            .get("records")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        match encode_record_batch(&list, fetch_offset, status_tx) {
                            Ok((bytes, high_watermark)) => PartitionData::default()
                                .with_partition_index(partition_idx)
                                .with_high_watermark(high_watermark)
                                .with_last_stable_offset(high_watermark)
                                .with_log_start_offset(0)
                                .with_records(Some(bytes))
                                .with_error_code(ERR_NONE),
                            Err(e) => {
                                Log::new(Some(status_tx)).warn(format!(
                                    "Kafka fetch for '{}' partition {}: the model's records could not be \
                                     encoded ({}); replying UNKNOWN_SERVER_ERROR",
                                    topic_name, partition_idx, e
                                ));
                                PartitionData::default()
                                    .with_partition_index(partition_idx)
                                    .with_error_code(ERR_UNKNOWN_SERVER_ERROR)
                                    .with_records(Some(Bytes::new()))
                            }
                        }
                    }
                    Reply::Error(code) => PartitionData::default()
                        .with_partition_index(partition_idx)
                        .with_error_code(code)
                        .with_records(Some(Bytes::new())),
                    Reply::NoAnswer(code) => PartitionData::default()
                        .with_partition_index(partition_idx)
                        .with_error_code(code)
                        .with_records(Some(Bytes::new())),
                };

                partition_responses.push(pd);
            }

            let response = FetchableTopicResponse::default().with_partitions(partition_responses);
            topic_responses.push(if by_id {
                response.with_topic_id(topic.topic_id)
            } else {
                response.with_topic(StrBytes::from_string(topic_name).into())
            });
        }

        let response = FetchResponse::default()
            .with_responses(topic_responses)
            .with_throttle_time_ms(0);

        let mut buf = Vec::new();
        ResponseHeader::default()
            .with_correlation_id(ctx.correlation_id)
            .encode(
                &mut buf,
                ApiKey::Fetch.response_header_version(ctx.api_version),
            )?;
        response.encode(&mut buf, ctx.api_version)?;
        Ok(buf)
    }

    /// OffsetCommit: the model decides whether the commit is accepted. Nothing is stored,
    /// so a later OffsetFetch would not see it — and OffsetFetch is not implemented.
    #[allow(clippy::too_many_arguments)]
    async fn handle_offset_commit(
        cursor: &mut std::io::Cursor<&[u8]>,
        ctx: &RequestCtx,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<KafkaProtocol>,
    ) -> Result<Vec<u8>> {
        use kafka_protocol::messages::offset_commit_response::{
            OffsetCommitResponsePartition, OffsetCommitResponseTopic,
        };

        let request = OffsetCommitRequest::decode(cursor, ctx.api_version)?;
        let group_id = request.group_id.to_string();

        let mut topic_responses = Vec::new();
        let mut units = 0usize;

        for topic in &request.topics {
            let topic_name = topic.name.to_string();
            let mut partition_responses = Vec::new();

            for partition in &topic.partitions {
                let partition_idx = partition.partition_index;

                units += 1;
                if units > MAX_UNITS_PER_REQUEST {
                    Log::new(Some(status_tx)).warn(format!(
                        "Kafka offset commit names more than {} topic-partitions in one request; \
                         remaining ones rejected without consulting the model",
                        MAX_UNITS_PER_REQUEST
                    ));
                    partition_responses.push(
                        OffsetCommitResponsePartition::default()
                            .with_partition_index(partition_idx)
                            .with_error_code(ERR_UNKNOWN_SERVER_ERROR),
                    );
                    continue;
                }

                let event = Event::new(
                    &OFFSET_COMMIT_REQUEST_EVENT,
                    json!({
                        "group_id": group_id,
                        "topic": topic_name,
                        "partition": partition_idx,
                        "offset": partition.committed_offset,
                        "client_id": ctx.client_id,
                        "api_version": ctx.api_version,
                    }),
                );

                let reply = Self::ask_model(
                    &event,
                    "offset_commit_response",
                    llm_client,
                    app_state,
                    status_tx,
                    ctx,
                    protocol,
                )
                .await;

                let error_code = match reply {
                    Reply::Data(data) => {
                        clamp_error_code(data.get("error_code").and_then(|v| v.as_i64()))
                    }
                    Reply::Error(code) => code,
                    Reply::NoAnswer(code) => code,
                };

                partition_responses.push(
                    OffsetCommitResponsePartition::default()
                        .with_partition_index(partition_idx)
                        .with_error_code(error_code),
                );
            }

            topic_responses.push(
                OffsetCommitResponseTopic::default()
                    .with_name(StrBytes::from_string(topic_name).into())
                    .with_partitions(partition_responses),
            );
        }

        let response = OffsetCommitResponse::default()
            .with_topics(topic_responses)
            .with_throttle_time_ms(0);

        let mut buf = Vec::new();
        ResponseHeader::default()
            .with_correlation_id(ctx.correlation_id)
            .encode(
                &mut buf,
                ApiKey::OffsetCommit.response_header_version(ctx.api_version),
            )?;
        response.encode(&mut buf, ctx.api_version)?;
        Ok(buf)
    }

    /// Raise one event and reduce the returned actions to a single decision.
    ///
    /// `call_llm` is the entry point for all three handling modes, so a script or static
    /// `event_handler` short-circuits the model here exactly as it does for every other
    /// protocol.
    async fn ask_model(
        event: &Event,
        expected_action: &str,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        ctx: &RequestCtx,
        protocol: &Arc<KafkaProtocol>,
    ) -> Reply {
        let result = call_llm(
            llm_client,
            app_state,
            ctx.server_id,
            Some(ctx.connection_id),
            event,
            protocol.as_ref(),
        )
        .await;

        let execution = match result {
            Ok(r) => r,
            Err(e) => {
                // The peer gets a category, the log gets the error - and the two ways of
                // failing are tagged distinctly, as `src/server/radius/` does, because on
                // the wire Kafka can only carry an error code and the log is the only place
                // the difference survives.
                let failure = crate::utils::WireFailure::classify(&e);
                let (code, class) = if failure.is_overloaded() {
                    (ERR_REQUEST_TIMED_OUT, "overloaded")
                } else {
                    (ERR_UNKNOWN_SERVER_ERROR, "unavailable")
                };
                Log::new(Some(status_tx)).warn(format!(
                    "Kafka: handler failed for {}: decision=fail_closed_llm_error class={} \
                     error_code={} error={}",
                    event.id(),
                    class,
                    code,
                    e
                ));
                return Reply::NoAnswer(code);
            }
        };

        // First recognised action wins, so the model's ordering is respected and an
        // explicit refusal is never overridden by a later success.
        for result in execution.protocol_results {
            if let ActionResult::Custom { name, data } = result {
                if name == expected_action {
                    return Reply::Data(data);
                }
                // Falls through to `error_response` below; keeping the two apart in the log
                // is what makes a model's deliberate refusal distinguishable from silence.
                if name == "error_response" {
                    let mut code =
                        clamp_error_code(data.get("error_code").and_then(|v| v.as_i64()));
                    if code == ERR_NONE {
                        // "error_response" with error_code 0 is a contradiction; treating
                        // it as success would make a refusal indistinguishable from an ack.
                        Log::new(Some(status_tx)).warn(format!(
                            "Kafka: error_response for {} carried error_code 0; using \
                             UNKNOWN_SERVER_ERROR instead",
                            event.id()
                        ));
                        code = ERR_UNKNOWN_SERVER_ERROR;
                    }
                    Log::new(Some(status_tx)).info(format!(
                        "Kafka: {} refused: decision=model_reject error_code={}",
                        event.id(),
                        code
                    ));
                    return Reply::Error(code);
                }
                debug!(
                    "Kafka: ignoring action '{}' for {} (expected '{}' or 'error_response')",
                    name,
                    event.id(),
                    expected_action
                );
            }
        }

        // The handler ran and produced nothing this event can use. Distinct from the
        // backend failing above: permanent as far as the client is concerned, and tagged
        // so an operator can tell the two apart in the log.
        Log::new(Some(status_tx)).warn(format!(
            "Kafka: {} produced no '{}' and no 'error_response': decision=model_silent \
             error_code={}",
            event.id(),
            expected_action,
            ERR_UNKNOWN_SERVER_ERROR
        ));
        Reply::NoAnswer(ERR_UNKNOWN_SERVER_ERROR)
    }
}

/// Everything a handler needs about the request it is answering, so the handler
/// signatures stay readable.
struct RequestCtx {
    api_version: i16,
    correlation_id: i32,
    client_id: String,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
}

/// Clamp a model-supplied error code into i16, defaulting to success when absent.
fn clamp_error_code(v: Option<i64>) -> i16 {
    match v {
        Some(c) if c >= i16::MIN as i64 && c <= i16::MAX as i64 => c as i16,
        Some(_) => ERR_UNKNOWN_SERVER_ERROR,
        None => ERR_NONE,
    }
}

/// Render record bytes for an event, as text when that is faithful and hex otherwise.
///
/// Models cannot read base64 and cannot be trusted to notice that a "string" is really
/// binary, so the encoding is stated explicitly alongside the value — the same shape the
/// TCP protocol settled on.
///
/// Shared with the Kafka *client* (`src/client/kafka/`) so that "hex means hex" is decided
/// once for both directions of the same connection.
pub(crate) fn encode_field(bytes: &[u8], max_len: usize) -> (Value, &'static str) {
    let printable = std::str::from_utf8(bytes).ok().filter(|s| {
        !s.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    });
    match printable {
        Some(s) => {
            let truncated = crate::utils::truncate::truncate_for_llm(s, max_len);
            (Value::String(truncated), "utf8")
        }
        None => {
            let take = bytes.len().min(max_len / 2);
            (Value::String(hex::encode(&bytes[..take])), "hex")
        }
    }
}

/// Turn one action field into record bytes, honouring the declared encoding.
///
/// If a field is documented as accepting hex, the executor has to actually decode it —
/// anything else puts literal ASCII on the wire.
///
/// Shared with the Kafka *client* (`src/client/kafka/`), which has the same obligation on its
/// produce path.
pub(crate) fn decode_field(value: Option<&Value>, encoding: &str) -> Result<Option<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    match encoding {
        "hex" => {
            let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = hex::decode(&cleaned)
                .map_err(|e| anyhow::anyhow!("invalid hex in record field: {}", e))?;
            Ok(Some(bytes))
        }
        "utf8" => Ok(Some(text.into_bytes())),
        other => Err(anyhow::anyhow!(
            "unknown record encoding '{}' (expected 'utf8' or 'hex')",
            other
        )),
    }
}

/// Encode the model's records into a v2 record batch.
///
/// Returns the encoded batch and the high watermark the client should be told about
/// (one past the last offset in the batch).
///
/// Offsets are made contiguous from the batch's base. Kafka's v2 batch stores per-record
/// offset *deltas* from the base and the encoder requires `offset - sequence` to be
/// constant across a batch, so honouring arbitrary gaps would silently split or corrupt
/// the batch. A model-supplied offset below `fetch_offset` would be discarded by the
/// consumer, so it is raised to `fetch_offset` and logged.
fn encode_record_batch(
    records: &[Value],
    fetch_offset: i64,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<(Bytes, i64)> {
    if records.is_empty() {
        return Ok((Bytes::new(), fetch_offset.max(0)));
    }

    if records.len() > MAX_RECORDS_PER_FETCH {
        Log::new(Some(status_tx)).warn(format!(
            "Kafka fetch_response contained {} records; only the first {} are returned",
            records.len(),
            MAX_RECORDS_PER_FETCH
        ));
    }

    let base_offset = records
        .first()
        .and_then(|r| r.get("offset"))
        .and_then(|v| v.as_i64())
        .unwrap_or(fetch_offset)
        .max(fetch_offset.max(0));

    let now = chrono::Utc::now().timestamp_millis();
    let mut total_payload = 0usize;
    let mut out = Vec::new();

    for (idx, r) in records.iter().take(MAX_RECORDS_PER_FETCH).enumerate() {
        let key_encoding = r
            .get("key_encoding")
            .and_then(|v| v.as_str())
            .or_else(|| r.get("encoding").and_then(|v| v.as_str()))
            .unwrap_or("utf8");
        let value_encoding = r
            .get("value_encoding")
            .and_then(|v| v.as_str())
            .or_else(|| r.get("encoding").and_then(|v| v.as_str()))
            .unwrap_or("utf8");

        let key = decode_field(r.get("key"), key_encoding)?;
        let value = decode_field(r.get("value"), value_encoding)?;

        total_payload += key.as_ref().map(|k| k.len()).unwrap_or(0)
            + value.as_ref().map(|v| v.len()).unwrap_or(0);
        if total_payload > MAX_FETCH_PAYLOAD_BYTES {
            Log::new(Some(status_tx)).warn(format!(
                "Kafka fetch_response payload exceeded {} bytes; truncating the batch at {} record(s)",
                MAX_FETCH_PAYLOAD_BYTES, idx
            ));
            break;
        }

        let declared = r.get("offset").and_then(|v| v.as_i64());
        let offset = base_offset + idx as i64;
        if let Some(d) = declared {
            if d != offset {
                debug!(
                    "Kafka fetch_response: record offset {} rewritten to {} to keep the batch contiguous",
                    d, offset
                );
            }
        }

        out.push(Record {
            transactional: false,
            control: false,
            partition_leader_epoch: 0,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            offset,
            sequence: idx as i32,
            timestamp: r.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(now),
            key: key.map(Bytes::from),
            value: value.map(Bytes::from),
            headers: Default::default(),
        });
    }

    if out.is_empty() {
        return Ok((Bytes::new(), base_offset));
    }

    let mut buf = Vec::new();
    let options = RecordEncodeOptions {
        version: 2,
        compression: Compression::None,
    };
    RecordBatchEncoder::encode_with_custom_compression::<
        _,
        _,
        fn(&mut bytes::BytesMut, &mut Vec<u8>, Compression) -> Result<()>,
    >(&mut buf, &out, &options, None)?;

    let high_watermark = base_offset + out.len() as i64;
    Ok((Bytes::from(buf), high_watermark))
}
