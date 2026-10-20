//! Server instance management

use crate::utils::clock::Instant;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::server::connection::ConnectionId;

/// Unique identifier for a server instance
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ServerId(u32);

impl ServerId {
    /// Create a new server ID from a u32
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the raw ID value
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Parse from string (expects format "server-123" or just "123")
    pub fn from_string(s: &str) -> Option<Self> {
        let s = s.trim();
        let id_str = s.strip_prefix("server-").unwrap_or(s);
        id_str.parse::<u32>().ok().map(Self)
    }
}

impl std::fmt::Display for ServerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server-{}", self.0)
    }
}

/// Status of a server instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerStatus {
    /// Server is starting up
    Starting,
    /// Server is running and accepting connections
    Running,
    /// Server has been stopped
    Stopped,
    /// Server encountered an error
    Error(String),
}

impl ServerStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Error(_) => "Error",
        }
    }
}

impl std::fmt::Display for ServerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starting => write!(f, "Starting"),
            Self::Running => write!(f, "Running"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Connection state for state machine (Idle/Processing/Accumulating)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProtocolState {
    /// Connection is idle, ready to process data
    Idle,
    /// LLM is currently processing a request
    Processing,
    /// LLM requested more data (WAIT_FOR_MORE)
    Accumulating,
}

/// IMAP session state (RFC 3501)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImapSessionState {
    /// Not authenticated - initial state, only LOGIN/AUTHENTICATE allowed
    NotAuthenticated,
    /// Authenticated - user logged in, can access mailboxes
    Authenticated,
    /// Selected - mailbox selected for operations (FETCH, STORE, etc.)
    Selected,
    /// Logout - client issued LOGOUT, connection closing
    Logout,
}

/// BGP session state (RFC 4271 FSM)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpSessionState {
    /// Idle - initial state, waiting for connection
    Idle,
    /// Connect - TCP connection established, waiting to send OPEN
    Connect,
    /// Active - failed to connect, will retry
    Active,
    /// OpenSent - OPEN message sent, waiting for peer's OPEN
    OpenSent,
    /// OpenConfirm - OPEN received and validated, waiting for KEEPALIVE
    OpenConfirm,
    /// Established - full BGP session established, exchanging routes
    Established,
}

/// OSPF neighbor state (RFC 2328 Section 10.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfNeighborState {
    /// Down - initial state, no Hello received
    Down,
    /// Init - Hello received from neighbor
    Init,
    /// 2-Way - bidirectional communication established
    TwoWay,
    /// ExStart - master/slave negotiation for database exchange
    ExStart,
    /// Exchange - database description packets exchanged
    Exchange,
    /// Loading - link state requests sent
    Loading,
    /// Full - adjacency complete, databases synchronized
    Full,
}

/// Protocol-specific connection information
///
/// This uses flexible storage to avoid centralized enum fighting between protocols.
/// Each protocol defines its own structure and serializes it to JSON.
///
/// Note: This storage is primarily for UI display and metrics.
/// Protocols maintain their own local connection data for I/O operations.
#[derive(Debug, Clone)]
pub struct ProtocolConnectionInfo {
    /// Protocol-specific data as JSON
    /// Protocols can serialize any structure they need here
    pub data: serde_json::Value,
}

impl ProtocolConnectionInfo {
    /// Create new protocol connection info from any serializable data
    pub fn new<T: serde::Serialize>(data: T) -> Self {
        Self {
            data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Create empty protocol connection info
    pub fn empty() -> Self {
        Self {
            data: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Get a reference to a field in the data
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    /// Try to deserialize the data into a specific type
    pub fn try_into<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.data.clone())
    }
}

/// Connection status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connection is active
    Active,
    /// Connection has been closed
    Closed,
}

/// Connection state within a server
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Connection ID
    pub id: ConnectionId,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Local address
    pub local_addr: SocketAddr,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Connection status (Active/Closed)
    pub status: ConnectionStatus,
    /// When status last changed (for cleanup reaper)
    pub status_changed_at: Instant,
    /// Protocol-specific information
    pub protocol_info: ProtocolConnectionInfo,
}

/// How many closed connections a server remembers for the "recently
/// connected" view. Live connections are reaped ~10s after closing (see the
/// cleanup reapers in `app_state.rs`), so without this history they vanish
/// without a trace.
pub const RECENT_CONNECTION_CAPACITY: usize = 50;

/// Summary of a connection that has closed and been removed from
/// [`ServerInstance::connections`]. Wall-clock timestamps (not `Instant`) so
/// the struct is serializable and meaningful across a UI session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClosedConnectionSummary {
    /// The connection's id while it was live ("conn-N").
    pub id: u32,
    pub remote_addr: String,
    /// None when the connection was inserted without passing through
    /// `add_connection` (direct map writes bypass the opened-at bookkeeping).
    pub opened_unix_ms: Option<u64>,
    pub closed_unix_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Snapshot of the protocol-specific display info at close time.
    pub protocol_info: serde_json::Value,
}

/// Wall-clock milliseconds for a past `Instant` (the `SystemTime::now() -
/// elapsed` idiom used elsewhere in this file for log naming).
fn instant_to_unix_ms(at: Instant) -> u64 {
    let system_time = crate::utils::clock::SystemTime::now() - at.elapsed();
    system_time
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A server instance with its own connections, state, and configuration
///
/// `Clone` is derived. It used to hold a `JoinHandle` — which is not `Clone` — so every
/// caller that wanted a copy wrote the fields out by hand and each new field had to be added
/// to all four copies or be silently dropped. Background tasks now live in
/// `AppState::register_server_task`, so the handle is gone and the hand-written copies with
/// it.
#[derive(Debug, Clone)]
pub struct ServerInstance {
    /// Unique server ID
    pub id: ServerId,
    /// Listening port
    pub port: u16,
    /// Protocol name (e.g., "TCP", "HTTP", "SSH")
    pub protocol_name: String,
    /// User instructions for this server
    pub instruction: String,
    /// LLM memory for this server
    pub memory: String,
    /// Server status
    pub status: ServerStatus,
    /// Active connections for this server
    pub connections: HashMap<ConnectionId, ConnectionState>,
    /// When the server was created
    pub created_at: Instant,
    /// When the server status last changed (for cleanup reaper)
    pub status_changed_at: Instant,
    /// Local listening address
    pub local_addr: Option<SocketAddr>,
    /// Protocol-specific startup parameters
    pub startup_params: Option<serde_json::Value>,
    /// Event handler configuration for handling protocol events
    pub event_handler_config: Option<crate::scripting::EventHandlerConfig>,
    /// Protocol-specific server data (flexible storage)
    ///
    /// This replaces protocol-specific feature-gated fields.
    /// Each protocol can store any data structure here by serializing to JSON.
    /// Use get_protocol_data() and set_protocol_data() helper methods.
    pub protocol_data: serde_json::Value,
    /// Log file paths (output_name -> log_file_path)
    pub log_files: HashMap<String, PathBuf>,
    /// Feedback instructions for automatic server adjustment
    /// When set, network requests can provide feedback that triggers LLM-based server adjustments
    pub feedback_instructions: Option<String>,
    /// Accumulated feedback buffer (cleared after processing)
    /// Each entry is a JSON value containing feedback data
    pub feedback_buffer: Vec<serde_json::Value>,
    /// Last time feedback was processed (for debouncing)
    pub last_feedback_processed: Option<Instant>,
    /// Recently closed connections, newest first, capped at
    /// [`RECENT_CONNECTION_CAPACITY`].
    pub recent_connections: VecDeque<ClosedConnectionSummary>,
    /// When each live connection was added, for
    /// [`ClosedConnectionSummary::opened_unix_ms`]. `ConnectionState` itself
    /// is built as a struct literal in ~117 protocol call sites, so the
    /// open-time lives here instead of as a new field there. Public only
    /// because `ServerInstance` is built as a struct literal in a few places;
    /// treat it as `add_connection`/`remove_connection` bookkeeping.
    pub connection_opened_at: HashMap<ConnectionId, Instant>,
    /// How many earlier entries the model is shown per connection; 0 is off. Starts at the
    /// protocol's declared [`crate::protocol::metadata::HistoryMode`], the instance may
    /// override it, and it is hot-applied.
    pub history_entries: u16,
    /// Whether events arriving during a call are delivered together afterwards. Starts at the
    /// protocol's declared [`crate::protocol::metadata::BatchingMode`]; only a protocol that
    /// supports batching may have it on.
    pub batching: bool,
    /// Each live connection's [`ExchangeHistory`](crate::state::exchange_history::ExchangeHistory),
    /// kept beside rather than inside `ConnectionState` for the reason `connection_opened_at`
    /// is, and dropped by `remove_connection` like it.
    pub exchange_history: HashMap<ConnectionId, crate::state::exchange_history::ExchangeHistory>,
}

/// Longest accepted `append_to_log` output name.
pub const MAX_LOG_OUTPUT_NAME_LEN: usize = 64;

/// Check an `append_to_log` `output_name` before it becomes part of a filename.
///
/// Same allowlist as `sqlite::validate_database_name`, for the same reason: the value is
/// model-authored, the model is influenced by the peer, and a name is **rejected** rather
/// than rewritten so the model's own bookkeeping (it reuses the name) matches what is on
/// disk.
pub fn validate_log_output_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!(
            "Invalid output_name: it must not be empty. Allowed: 1-{} characters from A-Z, \
             a-z, 0-9, '_' and '-' (it becomes part of the filename netget_<name>_<time>.log).",
            MAX_LOG_OUTPUT_NAME_LEN
        );
    }
    if name.len() > MAX_LOG_OUTPUT_NAME_LEN {
        anyhow::bail!(
            "Invalid output_name '{}': {} bytes exceeds the {}-byte limit.",
            name,
            name.len(),
            MAX_LOG_OUTPUT_NAME_LEN
        );
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
    {
        anyhow::bail!(
            "Invalid output_name '{}': character {:?} is not allowed. An output name may \
             contain only A-Z, a-z, 0-9, '_' and '-' (it becomes part of the filename \
             netget_<name>_<time>.log).",
            name,
            bad
        );
    }
    Ok(())
}

impl ServerInstance {
    /// Create a new server instance
    pub fn new(id: ServerId, port: u16, protocol_name: String, instruction: String) -> Self {
        let now = Instant::now();
        Self {
            id,
            port,
            protocol_name,
            instruction,
            memory: String::new(),
            status: ServerStatus::Starting,
            connections: HashMap::new(),
            created_at: now,
            status_changed_at: now,
            local_addr: None,
            startup_params: None,
            event_handler_config: None,
            protocol_data: serde_json::Value::Object(serde_json::Map::new()),
            log_files: HashMap::new(),
            feedback_instructions: None,
            feedback_buffer: Vec::new(),
            last_feedback_processed: None,
            recent_connections: VecDeque::new(),
            connection_opened_at: HashMap::new(),
            history_entries: 0,
            batching: false,
            exchange_history: HashMap::new(),
        }
    }

    /// Get protocol-specific data
    pub fn get_protocol_data<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.protocol_data.clone())
    }

    /// Set protocol-specific data
    pub fn set_protocol_data<T: serde::Serialize>(
        &mut self,
        data: T,
    ) -> Result<(), serde_json::Error> {
        self.protocol_data = serde_json::to_value(data)?;
        Ok(())
    }

    /// Get a field from protocol data
    pub fn get_protocol_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.protocol_data.get(key)
    }

    /// Set a field in protocol data
    pub fn set_protocol_field(&mut self, key: String, value: serde_json::Value) {
        if let Some(obj) = self.protocol_data.as_object_mut() {
            obj.insert(key, value);
        } else {
            // Initialize as object if not already
            let mut map = serde_json::Map::new();
            map.insert(key, value);
            self.protocol_data = serde_json::Value::Object(map);
        }
    }

    /// Get or create a log file path for the given output name.
    ///
    /// Format: `netget_<output_name>_<timestamp>_s<server id>.log`, in the process's working
    /// directory. The timestamp is when the *server* was created, so every line a server
    /// writes to one output name lands in one file for that server's whole life.
    ///
    /// **The server id is what makes the name unique, and it was missing.** The timestamp has
    /// one-second resolution, so two servers started in the same second and asked for the same
    /// output name — which is the norm, since `access_logs` is the name eleven tests and most
    /// example prompts use — produced the *same path* and appended into each other's file.
    /// Nothing detected that: each server's own `log_files` map is per-server and perfectly
    /// consistent, so both believed they owned the file.
    ///
    /// **`output_name` is model-authored and becomes part of a filename**, so it is checked
    /// against the same allowlist as a database name and refused otherwise. The prefix and
    /// suffix meant `..` could only escape through a directory literally named `netget_<x>`
    /// in the working directory, which is one `mkdir` away from an append into any file the
    /// process can write, and `append_to_log` is offered to the model on network events.
    pub fn get_or_create_log_path(&mut self, output_name: &str) -> anyhow::Result<PathBuf> {
        validate_log_output_name(output_name)?;
        if let Some(path) = self.log_files.get(output_name) {
            return Ok(path.clone());
        }

        // Calculate the absolute time when the server was created
        // by subtracting the elapsed time from now
        let now = crate::utils::clock::SystemTime::now();
        let elapsed = self.created_at.elapsed();
        let created_system_time = now - elapsed;

        // Convert to DateTime for formatting
        let timestamp = crate::utils::clock::to_local_datetime(created_system_time);
        let timestamp_str = timestamp.format("%Y_%m_%d_%H_%M_%S").to_string();

        let log_filename = format!(
            "netget_{}_{}_s{}.log",
            output_name,
            timestamp_str,
            self.id.as_u32()
        );
        let log_path = PathBuf::from(log_filename);

        self.log_files
            .insert(output_name.to_string(), log_path.clone());
        Ok(log_path)
    }

    /// Get a summary for display
    pub fn summary(&self) -> String {
        format!(
            "#{} {} on port {} ({}) - {} connections",
            self.id.as_u32(),
            self.protocol_name,
            self.port,
            self.status.as_str(),
            self.connections.len()
        )
    }

    /// Add a connection to this server
    pub fn add_connection(&mut self, state: ConnectionState) {
        self.connection_opened_at.insert(state.id, Instant::now());
        self.connections.insert(state.id, state);
    }

    /// Remove a connection from this server, remembering it in
    /// [`Self::recent_connections`].
    pub fn remove_connection(&mut self, id: ConnectionId) -> Option<ConnectionState> {
        let removed = self.connections.remove(&id);
        self.exchange_history.remove(&id);
        if let Some(state) = &removed {
            self.record_closed_connection(state);
        }
        removed
    }

    /// Push a closed-connection summary, newest first, trimming to capacity.
    fn record_closed_connection(&mut self, state: &ConnectionState) {
        let opened_unix_ms = self
            .connection_opened_at
            .remove(&state.id)
            .map(instant_to_unix_ms);
        self.recent_connections.push_front(ClosedConnectionSummary {
            id: state.id.as_u32(),
            remote_addr: state.remote_addr.to_string(),
            opened_unix_ms,
            closed_unix_ms: instant_to_unix_ms(state.status_changed_at),
            bytes_sent: state.bytes_sent,
            bytes_received: state.bytes_received,
            packets_sent: state.packets_sent,
            packets_received: state.packets_received,
            protocol_info: state.protocol_info.data.clone(),
        });
        self.recent_connections.truncate(RECENT_CONNECTION_CAPACITY);
    }

    /// Get a connection by ID
    pub fn get_connection(&self, id: ConnectionId) -> Option<&ConnectionState> {
        self.connections.get(&id)
    }

    /// Get a mutable connection by ID
    pub fn get_connection_mut(&mut self, id: ConnectionId) -> Option<&mut ConnectionState> {
        self.connections.get_mut(&id)
    }

    /// Get all connections
    pub fn get_all_connections(&self) -> Vec<&ConnectionState> {
        self.connections.values().collect()
    }

    /// Clean up old connectionless protocol entries (UDP, DNS, etc.)
    pub fn cleanup_old_connections(&mut self, max_age_secs: u64) {
        let now = Instant::now();
        let stale: Vec<ConnectionId> = self
            .connections
            .values()
            .filter(|state| now.duration_since(state.last_activity).as_secs() >= max_age_secs)
            .map(|state| state.id)
            .collect();
        for id in stale {
            self.remove_connection(id);
        }
    }
}
