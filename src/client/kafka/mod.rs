//! Kafka client — pure Rust, no librdkafka.
//!
//! # Wire format: shared with the broker, not reimplemented
//!
//! Every byte is produced and consumed by `kafka-protocol`'s code-generated codecs, reached
//! through the `pub use kafka_protocol` re-export in [`crate::server::kafka`]. Both halves
//! live behind the same `kafka` Cargo feature, so there is nothing extra to gate and no
//! second copy of the schemas to keep in sync — the same arrangement the BGP client has with
//! `src/server/bgp/wire.rs`.
//!
//! This client uses the codecs in the *client* direction: it encodes requests and decodes
//! responses, where the broker decodes requests and encodes responses. Nothing here calls a
//! function `src/server/kafka/mod.rs` wrote, apart from the two record-field encoding helpers
//! that decide how bytes are shown to (and taken from) a model.
//!
//! ## What this replaced
//!
//! An `rdkafka` (librdkafka) client that **was never reachable under `--features kafka`**:
//! `src/client/mod.rs` gated it on `#[cfg(all(feature = "kafka", feature = "rdkafka"))]`, and
//! only `all-protocols` turned the implicit `rdkafka` feature on — so a default build linked
//! a C library annotated in `Cargo.toml` as crashing in malloc, and every targeted
//! `--features kafka` build silently had no Kafka client at all. Its four E2E tests were
//! `#[ignore]`d for exactly that reason. `rdkafka` is now gone from the dependency list.
//!
//! # Supported surface
//!
//! Exactly the five APIs NetGet's broker implements, negotiated rather than assumed:
//!
//! | API | key | this client asks for at most | why that ceiling |
//! |---|---|---|---|
//! | ApiVersions  | 18 | v3 | falls back to decoding at v0 if the broker refuses, per Kafka's own rule |
//! | Metadata     | 3  | v12 | the newest `kafka-protocol` 0.14 knows; v9+ is flexible, v10+ reports topic ids |
//! | Produce      | 0  | v11 | the newest `kafka-protocol` 0.14 knows; v9+ is flexible |
//! | Fetch        | 1  | v16 | v12+ is flexible; v13+ names the topic by the id Metadata reported, and a broker that reports none is fetched by name at v12 |
//! | OffsetCommit | 8  | v9 | v8+ is flexible; a commit outside any group (generation/epoch -1) means the same at every version |
//!
//! The actual version used for each is `min(our ceiling, the broker's max)`, refused
//! outright if that falls below the broker's minimum.
//!
//! **No consumer groups.** `FindCoordinator`, `JoinGroup`, `SyncGroup` and `Heartbeat` are
//! implemented by neither half, so partitions are assigned manually and fetch offsets are
//! explicit. **No `ListOffsets`**, so there is no earliest/latest resolution — a consumer
//! starts at `start_offset` (default 0).
//!
//! # Why one mutex over the whole connection
//!
//! Kafka multiplexes requests on one TCP connection and matches replies by correlation id.
//! Rather than run a demultiplexer task, this client holds a `tokio::sync::Mutex` for the
//! duration of one request/response exchange, which makes the correlation id trivially
//! unambiguous. The lock is *not* held across an LLM call — events are built, the guard is
//! dropped, and only then is the model consulted. Every socket operation carries
//! [`IO_TIMEOUT`], so a silent broker cannot hold the lock forever.

pub mod actions;

pub use actions::KafkaClientProtocol;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::kafka::actions::{
    kafka_error_name, KAFKA_CLIENT_CONNECTED_EVENT, KAFKA_CLIENT_MESSAGE_DELIVERED_EVENT,
    KAFKA_CLIENT_METADATA_RECEIVED_EVENT, KAFKA_CLIENT_RECORDS_RECEIVED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

// The broker's copy of the wire library and its two record-field encoding helpers. Sharing
// them is what keeps "hex means hex" true on both sides of the same connection.
use crate::server::kafka::kafka_protocol;
use crate::server::kafka::{decode_field, encode_field};

use kafka_protocol::messages::{
    ApiKey, ApiVersionsRequest, ApiVersionsResponse, FetchRequest, FetchResponse, MetadataRequest,
    MetadataResponse, OffsetCommitRequest, OffsetCommitResponse, ProduceRequest, ProduceResponse,
    RequestHeader, ResponseHeader,
};
use kafka_protocol::protocol::{Decodable, Encodable, StrBytes};
use kafka_protocol::records::{
    Compression, Record, RecordBatchDecoder, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};

/// Every socket operation is bounded. Without this a broker that accepts a request and never
/// answers holds the exchange mutex for the life of the process.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response frame accepted. Mirrors the broker's own request cap; the size prefix
/// comes off the wire and is otherwise an allocation primitive.
const MAX_RESPONSE_BYTES: i64 = 100 * 1024 * 1024;

const CLIENT_MAX_API_VERSIONS: i16 = 3;
const CLIENT_MAX_METADATA: i16 = 12;
const CLIENT_MAX_PRODUCE: i16 = 11;
const CLIENT_MAX_FETCH: i16 = 16;
const CLIENT_MAX_OFFSET_COMMIT: i16 = 9;
/// The first Fetch version that names its topic by id rather than by name.
const FETCH_BY_TOPIC_ID: i16 = 13;
/// The first Metadata version that reports topic ids.
const METADATA_WITH_TOPIC_IDS: i16 = 10;
/// Topic ids remembered per connection.
const MAX_TOPIC_IDS: usize = 1024;

/// How many records of a batch are described to the model, and how much of each value.
/// Matches the broker's `MAX_EVENT_RECORDS` / `MAX_EVENT_VALUE_BYTES`.
const MAX_EVENT_RECORDS: usize = 20;
const MAX_EVENT_VALUE_BYTES: usize = 1024;

const DEFAULT_PARTITION_MAX_BYTES: i32 = 1024 * 1024;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const MIN_POLL_INTERVAL_MS: u64 = 50;
const DEFAULT_CLIENT_ID: &str = "netget-kafka-client";
const DEFAULT_GROUP_ID: &str = "netget-consumer-group";

/// Compression type parameters. `None` selects `kafka-protocol`'s built-in codecs (gzip,
/// snappy, lz4, zstd are all on by default); the function types still have to be nameable.
type Compressor = fn(&mut bytes::BytesMut, &mut Vec<u8>, Compression) -> Result<()>;
type Decompressor = fn(&mut Bytes, Compression) -> Result<std::io::Cursor<Bytes>>;

/// One partition this client is following, and where it will read from next.
#[derive(Clone, Debug)]
struct Assignment {
    topic: String,
    partition: i32,
    next_offset: i64,
}

/// The broker connection plus everything needed to frame a request on it.
struct KafkaConn {
    stream: TcpStream,
    next_correlation_id: i32,
    /// `api_key -> (min_version, max_version)` as the broker advertised it.
    versions: HashMap<i16, (i16, i16)>,
    client_id: StrBytes,
    /// Size of the last frame this connection actually put on the wire (4-byte length
    /// prefix included). Read while the connection mutex is still held, so an injected
    /// action can report a byte count that is genuinely its own rather than a snapshot
    /// racing the poll loop.
    last_request_bytes: usize,
    /// Topic ids the broker reported, for Fetch v13+. Looked up by name on first use.
    topic_ids: HashMap<String, uuid::Uuid>,
}

impl KafkaConn {
    /// The broker's id for `topic`, asked for with a Metadata request the first time.
    /// `None` when the broker reports none (Metadata below v10, or a nil id): the caller
    /// then fetches by name, at most v12.
    async fn topic_id(&mut self, topic: &str) -> Result<Option<uuid::Uuid>> {
        if let Some(id) = self.topic_ids.get(topic) {
            return Ok(Some(*id));
        }
        use kafka_protocol::messages::metadata_request::MetadataRequestTopic;
        let version = self.version_for(ApiKey::Metadata, CLIENT_MAX_METADATA)?;
        if version < METADATA_WITH_TOPIC_IDS {
            return Ok(None);
        }
        let response: MetadataResponse = self
            .exchange(
                ApiKey::Metadata,
                version,
                &MetadataRequest::default()
                    .with_topics(Some(vec![MetadataRequestTopic::default()
                        .with_name(Some(StrBytes::from_string(topic.to_string()).into()))])),
            )
            .await
            .context("Metadata request for a topic id failed")?;
        self.remember_topic_ids(&response);
        Ok(self.topic_ids.get(topic).copied())
    }

    /// Keep the non-nil ids of the topics a Metadata response described without error.
    fn remember_topic_ids(&mut self, response: &MetadataResponse) {
        for t in &response.topics {
            let Some(name) = t.name.as_ref() else {
                continue;
            };
            if t.error_code != 0 || t.topic_id.is_nil() {
                continue;
            }
            if self.topic_ids.len() >= MAX_TOPIC_IDS && !self.topic_ids.contains_key(name.as_str())
            {
                self.topic_ids.clear();
            }
            self.topic_ids.insert(name.to_string(), t.topic_id);
        }
    }

    /// The version to use for `api_key`: `min(our ceiling, the broker's max)`, refused if
    /// that lands below the broker's minimum or the broker does not implement the API at all.
    ///
    /// Guessing a version here is not a small mistake: a body encoded at a version the broker
    /// does not implement is not rejected cleanly, it is misparsed.
    fn version_for(&self, api_key: ApiKey, our_max: i16) -> Result<i16> {
        let (broker_min, broker_max) =
            *self.versions.get(&(api_key as i16)).with_context(|| {
                format!(
                    "broker does not advertise {api_key:?} (key {})",
                    api_key as i16
                )
            })?;
        let chosen = our_max.min(broker_max);
        if chosen < broker_min {
            bail!(
                "broker supports {api_key:?} v{broker_min}-v{broker_max}, but this client \
                 implements at most v{our_max}"
            );
        }
        Ok(chosen)
    }

    fn build_request<B: Encodable>(
        &mut self,
        api_key: ApiKey,
        api_version: i16,
        body: &B,
    ) -> Result<(i32, Vec<u8>)> {
        let correlation_id = self.next_correlation_id;
        self.next_correlation_id = self.next_correlation_id.wrapping_add(1);

        let mut buf = Vec::new();
        RequestHeader::default()
            .with_request_api_key(api_key as i16)
            .with_request_api_version(api_version)
            .with_correlation_id(correlation_id)
            .with_client_id(Some(self.client_id.clone()))
            .encode(&mut buf, api_key.request_header_version(api_version))
            .with_context(|| format!("encoding {api_key:?} v{api_version} request header"))?;
        body.encode(&mut buf, api_version)
            .with_context(|| format!("encoding {api_key:?} v{api_version} request body"))?;
        Ok((correlation_id, buf))
    }

    async fn write_frame(&mut self, body: &[u8]) -> Result<()> {
        let size = i32::try_from(body.len()).context("request does not fit in an i32 frame")?;
        tokio::time::timeout(IO_TIMEOUT, self.stream.write_all(&size.to_be_bytes()))
            .await
            .context("timed out writing Kafka frame size")??;
        tokio::time::timeout(IO_TIMEOUT, self.stream.write_all(body))
            .await
            .context("timed out writing Kafka frame body")??;
        self.last_request_bytes = 4 + body.len();
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut size = [0u8; 4];
        tokio::time::timeout(IO_TIMEOUT, self.stream.read_exact(&mut size))
            .await
            .context("timed out reading Kafka response size")??;
        // Validated in i64 so neither sign extension nor the length itself can wrap.
        let announced = i64::from(i32::from_be_bytes(size));
        if announced <= 0 || announced > MAX_RESPONSE_BYTES {
            bail!("broker announced an implausible response size of {announced} bytes");
        }
        let mut buf = vec![0u8; announced as usize];
        tokio::time::timeout(IO_TIMEOUT, self.stream.read_exact(&mut buf))
            .await
            .context("timed out reading Kafka response body")??;
        Ok(buf)
    }

    /// One request, one response, matched on correlation id.
    async fn exchange<B: Encodable, R: Decodable>(
        &mut self,
        api_key: ApiKey,
        api_version: i16,
        body: &B,
    ) -> Result<R> {
        let (correlation_id, request) = self.build_request(api_key, api_version, body)?;
        self.write_frame(&request).await?;
        let response = self.read_frame().await?;

        let mut cursor = std::io::Cursor::new(response.as_slice());
        let header =
            ResponseHeader::decode(&mut cursor, api_key.response_header_version(api_version))
                .with_context(|| format!("decoding {api_key:?} v{api_version} response header"))?;
        if header.correlation_id != correlation_id {
            bail!(
                "broker answered {api_key:?} with correlation id {} instead of {correlation_id}; \
                 the connection is desynchronised",
                header.correlation_id
            );
        }
        R::decode(&mut cursor, api_version)
            .with_context(|| format!("decoding {api_key:?} v{api_version} response body"))
    }

    /// Send a request and deliberately read nothing back. Only correct for `acks=0` Produce,
    /// where the broker is specified to write no reply at all.
    async fn send_only<B: Encodable>(
        &mut self,
        api_key: ApiKey,
        api_version: i16,
        body: &B,
    ) -> Result<()> {
        let (_, request) = self.build_request(api_key, api_version, body)?;
        self.write_frame(&request).await
    }
}

/// Everything one connected client needs to run its event loop.
#[derive(Clone)]
struct Session {
    conn: Arc<Mutex<KafkaConn>>,
    assignments: Arc<Mutex<Vec<Assignment>>>,
    memory: Arc<Mutex<String>>,
    client_id: ClientId,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    default_group_id: String,
    remote_addr: String,
}

/// Kafka client that connects to a broker.
pub struct KafkaClient;

impl KafkaClient {
    /// Connect to a broker, negotiate, fetch metadata, then hand the session to the model.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // Parameters are validated before the socket is opened, so a bad value fails the
        // connect with a message naming the key instead of half-starting a client.
        let params = startup_params.as_ref();
        let client_id_str = params
            .map(|p| p.get_optional_string("client_id"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());

        let topics: Vec<String> = params
            .map(|p| p.get_optional_array("topics"))
            .transpose()?
            .flatten()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let partition_raw = params
            .map(|p| p.get_optional_i64("partition"))
            .transpose()?
            .flatten()
            .unwrap_or(0);
        if !(0..=actions::MAX_PARTITION).contains(&partition_raw) {
            bail!(
                "Kafka client 'partition' must be between 0 and {}, got {partition_raw}",
                actions::MAX_PARTITION
            );
        }
        let partition = partition_raw as i32;

        let start_offset = params
            .map(|p| p.get_optional_i64("start_offset"))
            .transpose()?
            .flatten()
            .unwrap_or(0);
        if start_offset < 0 {
            bail!("Kafka client 'start_offset' must not be negative, got {start_offset}");
        }

        let poll_interval_raw = params
            .map(|p| p.get_optional_u64("poll_interval_ms"))
            .transpose()?
            .flatten()
            .unwrap_or(DEFAULT_POLL_INTERVAL_MS);
        if poll_interval_raw < MIN_POLL_INTERVAL_MS {
            bail!(
                "Kafka client 'poll_interval_ms' must be at least {MIN_POLL_INTERVAL_MS}, got \
                 {poll_interval_raw}"
            );
        }
        let poll_interval = Duration::from_millis(poll_interval_raw);

        let group_id = params
            .map(|p| p.get_optional_string("group_id"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| DEFAULT_GROUP_ID.to_string());

        info!(
            "Kafka client {} connecting to {} (client_id={}, topics={:?})",
            client_id, remote_addr, client_id_str, topics
        );

        let stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(&remote_addr))
            .await
            .with_context(|| format!("timed out connecting to Kafka broker {remote_addr}"))?
            .with_context(|| format!("failed to connect to Kafka broker {remote_addr}"))?;
        let local_addr = stream.local_addr()?;

        let mut conn = KafkaConn {
            stream,
            next_correlation_id: 1,
            versions: HashMap::new(),
            client_id: StrBytes::from_string(client_id_str.clone()),
            last_request_bytes: 0,
            topic_ids: HashMap::new(),
        };

        // ---- ApiVersions ------------------------------------------------------------
        conn.versions = Self::negotiate_api_versions(&mut conn).await?;

        let negotiated = serde_json::json!({
            "metadata": conn.version_for(ApiKey::Metadata, CLIENT_MAX_METADATA)?,
            "produce": conn.version_for(ApiKey::Produce, CLIENT_MAX_PRODUCE)?,
            "fetch": conn.version_for(ApiKey::Fetch, CLIENT_MAX_FETCH)?,
            "offset_commit": conn.version_for(ApiKey::OffsetCommit, CLIENT_MAX_OFFSET_COMMIT)?,
        });

        // ---- Metadata ---------------------------------------------------------------
        let requested: Option<Vec<String>> = if topics.is_empty() {
            None
        } else {
            Some(topics.clone())
        };
        let mut metadata = Self::request_metadata(&mut conn, requested.as_deref()).await?;

        info!(
            "Kafka client {} negotiated {} and read metadata for {} topic(s)",
            client_id,
            negotiated,
            metadata
                .get("topics")
                .and_then(|t| t.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        );

        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Kafka client {client_id} connected to {remote_addr}"
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        app_state
            .with_client_mut(client_id, |client_inst| {
                client_inst
                    .set_protocol_field("brokers".to_string(), serde_json::json!(remote_addr));
                client_inst.set_protocol_field(
                    "kafka_client_id".to_string(),
                    serde_json::json!(client_id_str),
                );
                client_inst.set_protocol_field("api_versions".to_string(), negotiated.clone());
            })
            .await;

        let assignments: Vec<Assignment> = topics
            .iter()
            .map(|topic| Assignment {
                topic: topic.clone(),
                partition,
                next_offset: start_offset,
            })
            .collect();
        let polling = !assignments.is_empty();

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        let session = Session {
            conn: Arc::new(Mutex::new(conn)),
            assignments: Arc::new(Mutex::new(assignments)),
            memory: Arc::new(Mutex::new(memory)),
            client_id,
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            default_group_id: group_id,
            remote_addr: remote_addr.clone(),
        };

        // The connected event and everything after it run in a task, so `connect` returns as
        // soon as the transport is genuinely up rather than blocking startup on the model.
        let connected_data = {
            let obj = metadata
                .as_object_mut()
                .expect("request_metadata builds an object");
            obj.insert("remote_addr".to_string(), serde_json::json!(remote_addr));
            obj.insert("api_versions".to_string(), negotiated);
            metadata
        };

        // The dashboard's `[ send ]` channel, registered BEFORE the connected-event LLM call
        // below. A dashboard-created client defaults to a `*` -> manual rule, so that call can
        // park for minutes waiting for a human; registering after it would leave the rail
        // reading "no command channel" for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let command_session = session.clone();
        let command_task = tokio::spawn(async move {
            command_session.command_loop(command_rx).await;
        });
        app_state
            .register_client_task(client_id, command_task)
            .await;

        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let stop = session
                .drive(Event::new(&KAFKA_CLIENT_CONNECTED_EVENT, connected_data))
                .await;

            if stop {
                session.close("handler asked to disconnect").await;
                return;
            }
            if !polling {
                debug!(
                    "Kafka client {} has no topics to poll; the connection stays open for \
                     scheduled tasks and further instructions",
                    session.client_id
                );
                return;
            }
            session.poll_loop(poll_interval).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Ask the broker what it speaks.
    ///
    /// Kafka's own negotiation rule: a broker that does not implement the requested
    /// ApiVersions version answers `UNSUPPORTED_VERSION` *plus the supported-API table*,
    /// encoded at v0 so the client can always read it. Both cases are handled from the same
    /// bytes — decoding at v3 first, then at v0 — because the reply is the only thing that
    /// says which version to step down to.
    async fn negotiate_api_versions(conn: &mut KafkaConn) -> Result<HashMap<i16, (i16, i16)>> {
        let request = ApiVersionsRequest::default()
            .with_client_software_name(StrBytes::from_static_str("netget"))
            .with_client_software_version(StrBytes::from_static_str(env!("CARGO_PKG_VERSION")));

        let (correlation_id, bytes) =
            conn.build_request(ApiKey::ApiVersions, CLIENT_MAX_API_VERSIONS, &request)?;
        conn.write_frame(&bytes).await?;
        let response = conn.read_frame().await?;

        let decoded = Self::decode_api_versions(&response, CLIENT_MAX_API_VERSIONS, correlation_id)
            .and_then(|(code, body)| {
                if code == 0 {
                    Ok(body)
                } else {
                    Err(anyhow!(
                        "ApiVersions v{CLIENT_MAX_API_VERSIONS} refused with error {code}"
                    ))
                }
            });

        let body = match decoded {
            Ok(body) => body,
            Err(first) => {
                debug!("Kafka client stepping ApiVersions down to v0: {}", first);
                let (code, body) = Self::decode_api_versions(&response, 0, correlation_id)
                    .context("broker's ApiVersions reply is unreadable at v3 and at v0")?;
                if code != 0 && body.api_keys.is_empty() {
                    bail!(
                        "broker refused ApiVersions with error {code} ({}) and sent no supported-API \
                         table, so there is no version to step down to",
                        kafka_error_name(code)
                    );
                }
                body
            }
        };

        if body.api_keys.is_empty() {
            bail!("broker advertised no APIs at all");
        }

        Ok(body
            .api_keys
            .iter()
            .map(|a| (a.api_key, (a.min_version, a.max_version)))
            .collect())
    }

    fn decode_api_versions(
        bytes: &[u8],
        api_version: i16,
        expected_correlation_id: i32,
    ) -> Result<(i16, ApiVersionsResponse)> {
        let mut cursor = std::io::Cursor::new(bytes);
        let header = ResponseHeader::decode(
            &mut cursor,
            ApiKey::ApiVersions.response_header_version(api_version),
        )
        .context("decoding ApiVersions response header")?;
        if header.correlation_id != expected_correlation_id {
            bail!(
                "broker answered ApiVersions with correlation id {} instead of {}",
                header.correlation_id,
                expected_correlation_id
            );
        }
        let body = ApiVersionsResponse::decode(&mut cursor, api_version)
            .context("decoding ApiVersions response body")?;
        Ok((body.error_code, body))
    }

    /// Metadata request → the structured shape a handler sees.
    async fn request_metadata(
        conn: &mut KafkaConn,
        topics: Option<&[String]>,
    ) -> Result<serde_json::Value> {
        use kafka_protocol::messages::metadata_request::MetadataRequestTopic;

        let version = conn.version_for(ApiKey::Metadata, CLIENT_MAX_METADATA)?;

        let named: Option<Vec<MetadataRequestTopic>> = match topics {
            Some(names) => Some(
                names
                    .iter()
                    .map(|n| {
                        MetadataRequestTopic::default()
                            .with_name(Some(StrBytes::from_string(n.clone()).into()))
                    })
                    .collect(),
            ),
            // v0 has no way to express "null topics"; there, an empty list means "everything".
            None if version == 0 => Some(Vec::new()),
            None => None,
        };

        let response: MetadataResponse = conn
            .exchange(
                ApiKey::Metadata,
                version,
                &MetadataRequest::default().with_topics(named),
            )
            .await
            .context("Metadata request failed")?;
        // Every Metadata answer from v10 carries topic ids; remember them, so a Fetch v13+
        // on a topic already described costs no extra round trip.
        conn.remember_topic_ids(&response);

        Ok(metadata_to_json(&response))
    }
}

impl Session {
    /// Run a handler for `event`, execute what it returns, and keep going for any event those
    /// actions produced. Returns true when the session should be torn down.
    ///
    /// Iterative, not recursive: the DNS client reached 211 model calls and then overflowed
    /// the stack doing this with recursion (`IMPROVEMENTS.md` item 49). The LLM budget in
    /// [`crate::client::llm_budget`] bounds the total; this shape bounds the stack.
    async fn drive(&self, first: Event) -> bool {
        let Some(instruction) = self
            .app_state
            .get_instruction_for_client(self.client_id)
            .await
        else {
            return false;
        };

        let mut queue: VecDeque<Event> = VecDeque::from([first]);
        while let Some(event) = queue.pop_front() {
            let memory = self.memory.lock().await.clone();
            let protocol = KafkaClientProtocol::new();

            let result = call_llm_for_client(
                &self.llm_client,
                &self.app_state,
                self.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                &protocol,
                &self.status_tx,
            )
            .await;

            let ClientLlmResult {
                actions,
                memory_updates,
            } = match result {
                Ok(r) => r,
                Err(e) => {
                    error!(
                        "Kafka client {} could not handle {}: {}",
                        self.client_id,
                        event.id(),
                        e
                    );
                    let _ = self
                        .status_tx
                        .send(format!("[CLIENT] Kafka handler failed: {e}"));
                    return false;
                }
            };
            if let Some(mem) = memory_updates {
                *self.memory.lock().await = mem;
            }

            for action in actions {
                match protocol.execute_action(action) {
                    Ok(ClientActionResult::Disconnect) => return true,
                    Ok(ClientActionResult::WaitForMore) | Ok(ClientActionResult::NoAction) => {}
                    Ok(ClientActionResult::Custom { name, data }) => {
                        match self.perform(&name, &data).await {
                            Ok((Some(follow_up), _)) => queue.push_back(follow_up),
                            Ok((None, _)) => {}
                            Err(e) => {
                                // A failed exchange is reported, never papered over with a
                                // plausible-looking success the handler would act on.
                                error!(
                                    "Kafka client {} action '{}' failed: {}",
                                    self.client_id, name, e
                                );
                                let _ = self
                                    .status_tx
                                    .send(format!("[CLIENT] Kafka {name} failed: {e}"));
                                if is_fatal(&e) {
                                    self.mark_error(&e.to_string()).await;
                                    return true;
                                }
                            }
                        }
                    }
                    Ok(other) => {
                        warn!(
                            "Kafka client {} ignoring unsupported action result {:?}",
                            self.client_id, other
                        );
                    }
                    Err(e) => {
                        error!("Kafka client {} rejected an action: {}", self.client_id, e);
                        let _ = self
                            .status_tx
                            .send(format!("[CLIENT] Kafka action rejected: {e}"));
                    }
                }
            }
        }
        false
    }

    /// Drain injected commands (the dashboard's `[ send ]`) until the channel closes - which
    /// happens when the client is removed or [`Self::close`] drops the handle - or an injected
    /// `disconnect` ends the session.
    ///
    /// Kafka frames are read with `read_exact`, which is **not** cancellation-safe, so this is
    /// its own task rather than a `select!` arm in the poll loop. The two are serialised by
    /// the connection mutex the exchange already takes, which is also what makes the byte
    /// count reported below unambiguously this command's own request.
    ///
    /// Injected actions go through [`Self::perform`] - the exact function the LLM path uses -
    /// so there is no second copy of the wire encoding. A follow-up event (a Produce ack, a
    /// Fetch result, Metadata) is handed to [`Self::drive`] in its own task rather than
    /// inline, so a handler that parks for a human cannot block the next injected command.
    async fn command_loop(
        &self,
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = KafkaClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let mut follow_up: Option<Event> = None;
            let mut disconnect = false;

            let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Disconnect) => {
                    disconnect = true;
                    Ok(ClientSendOutcome::Disconnected)
                }
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more: nothing was asked of the broker".to_string(),
                }),
                Ok(ClientActionResult::NoAction) => Ok(ClientSendOutcome::Executed {
                    detail: "no_action".to_string(),
                }),
                Ok(ClientActionResult::Custom { name, data }) => {
                    match self.perform(&name, &data).await {
                        Ok((event, wrote)) => {
                            follow_up = event;
                            Ok(ClientSendOutcome::Sent { bytes_sent: wrote })
                        }
                        Err(e) => {
                            // A refused exchange is reported as a failure, never as a
                            // plausible-looking `Sent` the operator would trust.
                            if is_fatal(&e) {
                                self.mark_error(&e.to_string()).await;
                            }
                            Err(e.context(format!("injected Kafka action '{name}'")))
                        }
                    }
                }
                Ok(other) => Ok(ClientSendOutcome::Executed {
                    detail: format!("unsupported action result {other:?}"),
                }),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            self.app_state
                .record_access_log(
                    AccessLogOwner::Client(self.client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            if let Err(e) = &outcome {
                error!(
                    "Kafka client {} injected action failed: {}",
                    self.client_id, e
                );
                let _ = self
                    .status_tx
                    .send(format!("[CLIENT] Kafka injected action failed: {e}"));
            }
            let _ = self.status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                self.close("injected disconnect").await;
                break;
            }

            if let Some(event) = follow_up {
                let session = self.clone();
                let handle = tokio::spawn(async move {
                    if session.drive(event).await {
                        session.close("handler asked to disconnect").await;
                    }
                });
                self.app_state
                    .register_client_task(self.client_id, handle)
                    .await;
            }
        }

        // The channel only ends here, so this is the one exit: drop the handle so a late
        // send fails fast instead of queueing into a dead session.
        self.app_state.remove_client_handle(self.client_id).await;
    }

    /// Perform one action against the broker. Returns the event it produced, if any, and
    /// the number of request bytes this action put on the wire.
    ///
    /// The byte count is read out while the connection mutex is still held by the operation
    /// that wrote it, so an injected command can report `ClientSendOutcome::Sent` with a
    /// figure that is genuinely its own request rather than a counter shared with the poll
    /// loop.
    async fn perform(
        &self,
        name: &str,
        data: &serde_json::Value,
    ) -> Result<(Option<Event>, usize)> {
        match name {
            "kafka_produce" => self.produce(data).await,
            "kafka_fetch" => {
                let topic = str_field(data, "topic")?;
                let partition = i64_field(data, "partition")? as i32;
                let offset = match data.get("offset").and_then(|v| v.as_i64()) {
                    Some(o) => o,
                    None => self.tracked_offset(&topic, partition).await.unwrap_or(0),
                };
                let max_bytes = data
                    .get("max_bytes")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::from(DEFAULT_PARTITION_MAX_BYTES))
                    as i32;
                self.fetch(&topic, partition, offset, max_bytes).await
            }
            "kafka_metadata" => {
                let topics: Option<Vec<String>> =
                    data.get("topics").and_then(|v| v.as_array()).map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_string())
                            .collect()
                    });
                let mut conn = self.conn.lock().await;
                let metadata = KafkaClient::request_metadata(&mut conn, topics.as_deref()).await?;
                let wrote = conn.last_request_bytes;
                drop(conn);
                Ok((
                    Some(Event::new(&KAFKA_CLIENT_METADATA_RECEIVED_EVENT, metadata)),
                    wrote,
                ))
            }
            "kafka_commit" => self.commit(data).await.map(|wrote| (None, wrote)),
            other => Err(anyhow!("unknown Kafka client action result '{other}'")),
        }
    }

    /// Publish one record.
    async fn produce(&self, data: &serde_json::Value) -> Result<(Option<Event>, usize)> {
        use kafka_protocol::messages::produce_request::{PartitionProduceData, TopicProduceData};

        let topic = str_field(data, "topic")?;
        let partition = i64_field(data, "partition")? as i32;
        let acks = i64_field(data, "acks")? as i16;

        // The declared encoding is honoured here, by the same decoder the broker uses for its
        // own outbound records. An action documented as accepting hex that puts literal ASCII
        // on the wire is the defect this codebase names as its reference case.
        let key = decode_field(
            data.get("key"),
            data.get("key_encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8"),
        )
        .context("record key")?;
        let value = decode_field(
            data.get("value"),
            data.get("value_encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8"),
        )
        .context("record value")?;

        let batch = encode_single_record(key, value)?;

        let request = ProduceRequest::default()
            .with_acks(acks)
            .with_timeout_ms(IO_TIMEOUT.as_millis() as i32)
            .with_topic_data(vec![TopicProduceData::default()
                .with_name(StrBytes::from_string(topic.clone()).into())
                .with_partition_data(vec![PartitionProduceData::default()
                    .with_index(partition)
                    .with_records(Some(batch))])]);

        let mut conn = self.conn.lock().await;
        let version = conn.version_for(ApiKey::Produce, CLIENT_MAX_PRODUCE)?;

        if acks == 0 {
            // Kafka specifies no reply for acks=0. Waiting for one would hang the exchange
            // until IO_TIMEOUT and then look like a broker failure.
            conn.send_only(ApiKey::Produce, version, &request).await?;
            let wrote = conn.last_request_bytes;
            drop(conn);
            info!(
                "Kafka client {} produced to {}/{} with acks=0 (no acknowledgement requested)",
                self.client_id, topic, partition
            );
            let _ = self.status_tx.send(format!(
                "[CLIENT] Kafka produced to {topic}/{partition} (acks=0, unacknowledged)"
            ));
            return Ok((None, wrote));
        }

        let response: ProduceResponse = conn.exchange(ApiKey::Produce, version, &request).await?;
        let wrote = conn.last_request_bytes;
        drop(conn);

        let topic_response = response
            .responses
            .iter()
            .find(|t| t.name.as_str() == topic)
            .or_else(|| response.responses.first())
            .context("Produce response named no topic")?;
        let partition_response = topic_response
            .partition_responses
            .iter()
            .find(|p| p.index == partition)
            .or_else(|| topic_response.partition_responses.first())
            .context("Produce response named no partition")?;

        let error_code = partition_response.error_code;
        let delivered = error_code == 0;
        if delivered {
            info!(
                "Kafka client {} produced to {}/{} at offset {}",
                self.client_id, topic, partition, partition_response.base_offset
            );
            let _ = self.status_tx.send(format!(
                "[CLIENT] Kafka produced to {topic}/{partition} at offset {}",
                partition_response.base_offset
            ));
        } else {
            // A rejected write is an error, not a quieter kind of success.
            error!(
                "Kafka client {} produce to {}/{} rejected: {} ({})",
                self.client_id,
                topic,
                partition,
                error_code,
                kafka_error_name(error_code)
            );
            let _ = self.status_tx.send(format!(
                "[CLIENT] Kafka produce to {topic}/{partition} rejected: {} ({error_code})",
                kafka_error_name(error_code)
            ));
        }

        Ok((
            Some(Event::new(
                &KAFKA_CLIENT_MESSAGE_DELIVERED_EVENT,
                serde_json::json!({
                    "topic": topic,
                    "partition": partition,
                    "base_offset": partition_response.base_offset,
                    "error_code": error_code,
                    "error_name": kafka_error_name(error_code),
                    "delivered": delivered,
                    "api_version": version,
                }),
            )),
            wrote,
        ))
    }

    /// Read one partition. Returns an event only when records actually came back, so an idle
    /// poll costs no model call.
    async fn fetch(
        &self,
        topic: &str,
        partition: i32,
        offset: i64,
        max_bytes: i32,
    ) -> Result<(Option<Event>, usize)> {
        use kafka_protocol::messages::fetch_request::{FetchPartition, FetchTopic};

        let mut conn = self.conn.lock().await;
        let mut version = conn.version_for(ApiKey::Fetch, CLIENT_MAX_FETCH)?;
        // From v13 a fetch names its topic by the id the broker gave it; without one, fetch
        // by name at the last version that allows it.
        let mut fetch_topic = FetchTopic::default();
        if version >= FETCH_BY_TOPIC_ID {
            match conn.topic_id(topic).await? {
                Some(id) => fetch_topic = fetch_topic.with_topic_id(id),
                None => version = conn.version_for(ApiKey::Fetch, FETCH_BY_TOPIC_ID - 1)?,
            }
        }
        if version < FETCH_BY_TOPIC_ID {
            fetch_topic = fetch_topic.with_topic(StrBytes::from_string(topic.to_string()).into());
        }
        let request = FetchRequest::default()
            .with_max_wait_ms(500)
            .with_min_bytes(1)
            .with_max_bytes(max_bytes)
            .with_topics(vec![fetch_topic.with_partitions(vec![
                FetchPartition::default()
                    .with_partition(partition)
                    .with_fetch_offset(offset)
                    .with_partition_max_bytes(max_bytes),
            ])]);
        let response: FetchResponse = conn.exchange(ApiKey::Fetch, version, &request).await?;
        let wrote = conn.last_request_bytes;
        drop(conn);

        if response.error_code != 0 {
            bail!(
                "Fetch failed at the response level: {} ({})",
                response.error_code,
                kafka_error_name(response.error_code)
            );
        }

        let Some(topic_response) = response.responses.first() else {
            debug!(
                "Kafka client {} fetched {}/{}: broker returned no topic",
                self.client_id, topic, partition
            );
            return Ok((None, wrote));
        };
        let Some(partition_data) = topic_response.partitions.first() else {
            return Ok((None, wrote));
        };

        if partition_data.error_code != 0 {
            bail!(
                "Fetch of {topic}/{partition} failed: {} ({})",
                partition_data.error_code,
                kafka_error_name(partition_data.error_code)
            );
        }

        let records = match partition_data.records.as_ref() {
            Some(raw) if !raw.is_empty() => {
                let owned = Bytes::copy_from_slice(raw.as_ref());
                let mut cursor = std::io::Cursor::new(owned);
                RecordBatchDecoder::decode_with_custom_compression::<_, Decompressor>(
                    &mut cursor,
                    None,
                )
                .context("broker's record batch did not decode")?
            }
            _ => Vec::new(),
        };

        if records.is_empty() {
            trace!(
                "Kafka client {} fetched {}/{} from offset {}: nothing new",
                self.client_id,
                topic,
                partition,
                offset
            );
            return Ok((None, wrote));
        }

        let last_offset = records.iter().map(|r| r.offset).max().unwrap_or(offset);
        let next_offset = last_offset + 1;
        self.set_tracked_offset(topic, partition, next_offset).await;

        info!(
            "Kafka client {} fetched {} record(s) from {}/{} at offset {}",
            self.client_id,
            records.len(),
            topic,
            partition,
            offset
        );
        let _ = self.status_tx.send(format!(
            "[CLIENT] Kafka received {} record(s) from {topic}/{partition}",
            records.len()
        ));

        Ok((
            Some(Event::new(
                &KAFKA_CLIENT_RECORDS_RECEIVED_EVENT,
                serde_json::json!({
                    "topic": topic,
                    "partition": partition,
                    "api_version": version,
                    "high_watermark": partition_data.high_watermark,
                    "next_offset": next_offset,
                    "record_count": records.len(),
                    "records": records.iter().take(MAX_EVENT_RECORDS).map(record_to_json).collect::<Vec<_>>(),
                }),
            )),
            wrote,
        ))
    }

    /// Commit an offset. No event: the answer is a bare error code, and raising an event for
    /// it would double the model round trips a consumer needs per batch.
    async fn commit(&self, data: &serde_json::Value) -> Result<usize> {
        use kafka_protocol::messages::offset_commit_request::{
            OffsetCommitRequestPartition, OffsetCommitRequestTopic,
        };

        let topic = str_field(data, "topic")?;
        let partition = i64_field(data, "partition")? as i32;
        let offset = i64_field(data, "offset")?;
        let group_id = data
            .get("group_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.default_group_id)
            .to_string();

        let request = OffsetCommitRequest::default()
            .with_group_id(StrBytes::from_string(group_id.clone()).into())
            // -1 / empty: this client is not a group member, and claiming a generation it
            // never joined would be rejected by any broker that implements groups.
            .with_generation_id_or_member_epoch(-1)
            .with_topics(vec![OffsetCommitRequestTopic::default()
                .with_name(StrBytes::from_string(topic.clone()).into())
                .with_partitions(vec![OffsetCommitRequestPartition::default()
                    .with_partition_index(partition)
                    .with_committed_offset(offset)])]);

        let mut conn = self.conn.lock().await;
        let version = conn.version_for(ApiKey::OffsetCommit, CLIENT_MAX_OFFSET_COMMIT)?;
        let response: OffsetCommitResponse = conn
            .exchange(ApiKey::OffsetCommit, version, &request)
            .await?;
        let wrote = conn.last_request_bytes;
        drop(conn);

        let error_code = response
            .topics
            .first()
            .and_then(|t| t.partitions.first())
            .map(|p| p.error_code)
            .context("OffsetCommit response named no partition")?;

        if error_code != 0 {
            bail!(
                "commit of {topic}/{partition} offset {offset} was refused: {error_code} ({})",
                kafka_error_name(error_code)
            );
        }

        info!(
            "Kafka client {} committed {}/{} offset {} for group {}",
            self.client_id, topic, partition, offset, group_id
        );
        let _ = self.status_tx.send(format!(
            "[CLIENT] Kafka committed {topic}/{partition} offset {offset}"
        ));
        Ok(wrote)
    }

    /// Poll every assigned partition until the client goes away or the connection breaks.
    ///
    /// The first round runs immediately. Sleeping first would make a consumer sit idle for a
    /// whole interval before its first read, and would hide records that were already there
    /// when it connected.
    async fn poll_loop(&self, interval: Duration) {
        let mut first = true;
        loop {
            if !first {
                tokio::time::sleep(interval).await;
            }
            first = false;

            if self.app_state.get_client(self.client_id).await.is_none() {
                info!("Kafka client {} stopped", self.client_id);
                return;
            }

            let assignments = self.assignments.lock().await.clone();
            for assignment in assignments {
                match self
                    .fetch(
                        &assignment.topic,
                        assignment.partition,
                        assignment.next_offset,
                        DEFAULT_PARTITION_MAX_BYTES,
                    )
                    .await
                {
                    Ok((Some(event), _)) => {
                        if self.drive(event).await {
                            self.close("handler asked to disconnect").await;
                            return;
                        }
                    }
                    Ok((None, _)) => {}
                    Err(e) => {
                        error!(
                            "Kafka client {} polling {}/{} failed: {}",
                            self.client_id, assignment.topic, assignment.partition, e
                        );
                        let _ = self
                            .status_tx
                            .send(format!("[CLIENT] Kafka poll failed: {e}"));
                        if is_fatal(&e) {
                            self.mark_error(&e.to_string()).await;
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn tracked_offset(&self, topic: &str, partition: i32) -> Option<i64> {
        self.assignments
            .lock()
            .await
            .iter()
            .find(|a| a.topic == topic && a.partition == partition)
            .map(|a| a.next_offset)
    }

    /// Record where to read next, adding the partition to the poll set if it is new. A
    /// handler that fetches a topic it was not configured with then keeps receiving it.
    async fn set_tracked_offset(&self, topic: &str, partition: i32, next_offset: i64) {
        let mut assignments = self.assignments.lock().await;
        match assignments
            .iter_mut()
            .find(|a| a.topic == topic && a.partition == partition)
        {
            Some(existing) => existing.next_offset = next_offset,
            None => assignments.push(Assignment {
                topic: topic.to_string(),
                partition,
                next_offset,
            }),
        }
    }

    async fn mark_error(&self, message: &str) {
        // The connection is unusable, so stop offering `[ send ]` on it.
        self.app_state.remove_client_handle(self.client_id).await;
        self.app_state
            .update_client_status(self.client_id, ClientStatus::Error(message.to_string()))
            .await;
        let _ = self.status_tx.send("__UPDATE_UI__".to_string());
    }

    async fn close(&self, why: &str) {
        info!(
            "Kafka client {} disconnecting from {}: {}",
            self.client_id, self.remote_addr, why
        );
        // Shutting the socket down explicitly makes the broker see a clean close rather than
        // waiting for its own idle timeout.
        let _ = self.conn.lock().await.stream.shutdown().await;
        // Dropping the handle also closes the command channel, which ends `command_loop`.
        self.app_state.remove_client_handle(self.client_id).await;
        self.app_state
            .update_client_status(self.client_id, ClientStatus::Disconnected)
            .await;
        let _ = self.status_tx.send(format!(
            "[CLIENT] Kafka client {} disconnected",
            self.client_id
        ));
        let _ = self.status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Whether an error means the connection is unusable, as opposed to one request being refused.
///
/// A refused Produce leaves the session healthy; a desynchronised correlation id or a broken
/// socket does not, and continuing to poll on it would spin.
fn is_fatal(e: &anyhow::Error) -> bool {
    let text = e.to_string();
    e.downcast_ref::<std::io::Error>().is_some()
        || e.chain()
            .any(|c| c.downcast_ref::<std::io::Error>().is_some())
        || text.contains("desynchronised")
        || text.contains("timed out")
        || text.contains("implausible response size")
}

/// Encode one record as a v2 record batch, the format every broker since 0.11 stores.
fn encode_single_record(key: Option<Vec<u8>>, value: Option<Vec<u8>>) -> Result<Bytes> {
    let timestamp = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(-1);

    let records = vec![Record {
        transactional: false,
        control: false,
        partition_leader_epoch: 0,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        offset: 0,
        sequence: 0,
        timestamp,
        key: key.map(Bytes::from),
        value: value.map(Bytes::from),
        headers: Default::default(),
    }];

    let mut buf = Vec::new();
    RecordBatchEncoder::encode_with_custom_compression::<_, _, Compressor>(
        &mut buf,
        &records,
        &RecordEncodeOptions {
            version: 2,
            compression: Compression::None,
        },
        None,
    )
    .context("encoding the record batch")?;
    Ok(Bytes::from(buf))
}

/// Render one fetched record for a handler.
///
/// `encode_field` is the broker's own helper: printable bytes become text tagged `utf8`,
/// anything else becomes hex tagged `hex`. Never base64, which models cannot read.
fn record_to_json(record: &Record) -> serde_json::Value {
    let (key, key_encoding) = match record.key.as_ref() {
        Some(k) => {
            let (v, e) = encode_field(k.as_ref(), MAX_EVENT_VALUE_BYTES);
            (v, Some(e))
        }
        None => (serde_json::Value::Null, None),
    };
    let (value, value_encoding) = match record.value.as_ref() {
        Some(v) => {
            let (val, e) = encode_field(v.as_ref(), MAX_EVENT_VALUE_BYTES);
            (val, Some(e))
        }
        None => (serde_json::Value::Null, None),
    };

    serde_json::json!({
        "offset": record.offset,
        "timestamp": record.timestamp,
        "key": key,
        "key_encoding": key_encoding,
        "value": value,
        "value_encoding": value_encoding,
    })
}

/// Turn a Metadata response into the structured shape handlers see.
fn metadata_to_json(response: &MetadataResponse) -> serde_json::Value {
    let brokers: Vec<serde_json::Value> = response
        .brokers
        .iter()
        .map(|b| {
            serde_json::json!({
                "node_id": b.node_id.0,
                "host": b.host.to_string(),
                "port": b.port,
            })
        })
        .collect();

    let topics: Vec<serde_json::Value> = response
        .topics
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name.as_ref().map(|n| n.to_string()),
                "error_code": t.error_code,
                "error_name": kafka_error_name(t.error_code),
                "partitions": t.partitions.iter().map(|p| serde_json::json!({
                    "partition": p.partition_index,
                    "leader": p.leader_id.0,
                    "error_code": p.error_code,
                    "replicas": p.replica_nodes.iter().map(|r| r.0).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    serde_json::json!({
        "cluster_id": response.cluster_id.as_ref().map(|c| c.to_string()),
        "controller_id": response.controller_id.0,
        "brokers": brokers,
        "topics": topics,
    })
}

fn str_field(data: &serde_json::Value, key: &str) -> Result<String> {
    data.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .with_context(|| format!("action data is missing '{key}'"))
}

fn i64_field(data: &serde_json::Value, key: &str) -> Result<i64> {
    data.get(key)
        .and_then(|v| v.as_i64())
        .with_context(|| format!("action data is missing '{key}'"))
}
