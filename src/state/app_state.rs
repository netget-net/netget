//! Application state management

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

use super::client::{ClientId, ClientInstance};
use super::easy::{EasyId, EasyInstance, EasyStatus};
use super::server::{ServerId, ServerInstance};
use super::task::{ScheduledTask, TaskId};
use crate::server::connection::ConnectionId;

/// Own a started child until its handle reaches the task registry. Dropping a
/// Tokio JoinHandle detaches; dropping an unfinished registration must abort.
struct PendingTaskRegistration(Option<tokio::task::JoinHandle<()>>);

impl PendingTaskRegistration {
    fn into_handle(mut self) -> tokio::task::JoinHandle<()> {
        self.0.take().expect("registration owns its task")
    }
}

impl Drop for PendingTaskRegistration {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// Source of an LLM conversation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationSource {
    /// User input from the command line
    User,
    /// Network event from a protocol implementation
    Network {
        server_id: ServerId,
        connection_id: Option<ConnectionId>,
    },
    /// A model deciding what a network client should do next.
    Client { client_id: ClientId },
    /// Scheduled task execution
    Task { task_name: String },
    /// Scripting mode execution
    Scripting,
}

impl ConversationSource {
    pub fn display_label(&self) -> String {
        match self {
            ConversationSource::User => "[User]".to_string(),
            ConversationSource::Network {
                server_id,
                connection_id,
            } => {
                if let Some(conn_id) = connection_id {
                    format!("[Net #{}:{}]", server_id.as_u32(), conn_id)
                } else {
                    format!("[Net #{}]", server_id.as_u32())
                }
            }
            ConversationSource::Task { task_name } => format!("[Task:{}]", task_name),
            ConversationSource::Client { client_id } => format!("[Client #{}]", client_id.as_u32()),
            ConversationSource::Scripting => "[Scripting]".to_string(),
        }
    }
}

/// Information about an active or recently-completed conversation
#[derive(Debug, Clone)]
pub struct ConversationInfo {
    /// Unique conversation ID
    pub id: String,
    /// Source of the conversation
    pub source: ConversationSource,
    /// Details text (truncated input, context, etc.)
    pub details: String,
    /// When the conversation started
    pub start_time: crate::utils::clock::Instant,
    /// When the conversation ended (None if still active)
    pub end_time: Option<crate::utils::clock::Instant>,
}

/// Operating mode for the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Server mode - one or more servers listening
    Server,
    /// Client mode - connecting to remote servers
    Client,
    /// Idle - not yet configured
    Idle,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Server => "Server",
            Self::Client => "Client",
            Self::Idle => "Idle",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Selected scripting mode - which environment is active for the LLM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptingMode {
    /// LLM chooses runtime for each script
    On,
    /// Scripting disabled - LLM only mode
    Off,
    /// Python scripting enabled
    Python,
    /// JavaScript scripting enabled
    JavaScript,
    /// Go scripting enabled
    Go,
    /// Perl scripting enabled
    Perl,
}

impl ScriptingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::On => "On",
            Self::Off => "Off",
            Self::Python => "Python",
            Self::JavaScript => "JavaScript",
            Self::Go => "Go",
            Self::Perl => "Perl",
        }
    }
}

impl std::fmt::Display for ScriptingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Web search mode - controls when web search is allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebSearchMode {
    /// Web search always enabled
    #[default]
    On,
    /// Web search always disabled
    Off,
    /// Ask user for approval before each search
    Ask,
}

impl WebSearchMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Ask => "ask",
        }
    }
}

impl std::fmt::Display for WebSearchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for WebSearchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "on" | "enabled" | "enable" | "true" => Ok(Self::On),
            "off" | "disabled" | "disable" | "false" => Ok(Self::Off),
            "ask" => Ok(Self::Ask),
            _ => Err(format!("Invalid web search mode: {}", s)),
        }
    }
}

/// Event handler mode - controls how LLM should configure event handlers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventHandlerMode {
    /// LLM chooses handler types (script/static/llm) as appropriate
    #[default]
    Any,
    /// Force all events to use script handlers
    Script,
    /// Force all events to use static response handlers
    Static,
    /// Force all events to use LLM handlers
    Llm,
}

impl EventHandlerMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "ANY",
            Self::Script => "SCRIPT",
            Self::Static => "STATIC",
            Self::Llm => "LLM",
        }
    }
}

impl std::fmt::Display for EventHandlerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for EventHandlerMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "script" => Ok(Self::Script),
            "static" => Ok(Self::Static),
            "llm" => Ok(Self::Llm),
            _ => Err(format!("Invalid event handler mode: {}", s)),
        }
    }
}

/// Request for web search approval (sent from tool executor to UI)
pub struct WebApprovalRequest {
    pub url: String,
    pub response_tx: oneshot::Sender<WebApprovalResponse>,
}

/// Response from user for web search approval
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebApprovalResponse {
    /// Allow this single request
    Allow,
    /// Deny this request
    Deny,
    /// Always allow (switch to ON mode for session)
    AlwaysAllow,
}

/// A single request/response access-log entry.
///
/// Captured for every network event a protocol server handles: the request is
/// the structured event data, the response is the action JSON the LLM (or a
/// script/static handler) produced. Used by the `list_access_logs` /
/// `get_access_log` MCP tools for debugging.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AccessLogEntry {
    /// Monotonic entry id (assigned in arrival order)
    pub id: u64,
    /// Unix time in milliseconds when the entry was recorded
    pub unix_ms: u64,
    /// Server that handled the request (absent on client-side entries).
    /// Serialization skips `None`, so pre-existing server entries keep their
    /// exact JSON shape for MCP consumers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<u32>,
    /// Client that produced/handled the event (absent on server-side entries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<u32>,
    /// Protocol name (e.g. "http", "dns")
    pub protocol: String,
    /// Connection the request arrived on, if the protocol is connection-oriented
    pub connection_id: Option<u32>,
    /// Event type id (e.g. "http_request")
    pub event_type: String,
    /// The request: structured event data
    pub request: serde_json::Value,
    /// The response: action JSON produced for this request.
    ///
    /// Server entries record actions as executed (failures appear as
    /// `FAILED: <action>` envelopes). Client entries record the actions the
    /// handler/LLM *produced* — execution happens later inside the client's
    /// connection loop, which does not report back here.
    pub response: Vec<serde_json::Value>,
}

impl AccessLogEntry {
    /// Which instance this entry belongs to.
    pub fn owner(&self) -> Option<AccessLogOwner> {
        match (self.server_id, self.client_id) {
            (Some(id), _) => Some(AccessLogOwner::Server(id)),
            (None, Some(id)) => Some(AccessLogOwner::Client(id)),
            (None, None) => None,
        }
    }
}

/// The instance an access-log entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLogOwner {
    Server(u32),
    Client(u32),
}

/// Maximum number of access-log entries retained in memory (ring buffer).
const ACCESS_LOG_CAPACITY: usize = 1000;

/// One instance's accumulated feedback, taken out of its buffer for processing.
///
/// Exactly one of `server_id` / `client_id` is set.
#[derive(Debug, Clone)]
pub struct DueFeedback {
    /// The server this feedback belongs to, if it is server feedback
    pub server_id: Option<ServerId>,
    /// The client this feedback belongs to, if it is client feedback
    pub client_id: Option<super::ClientId>,
    /// The `feedback_instructions` the instance was started with
    pub instructions: String,
    /// The instance's current instruction, so the model can adjust it
    pub instruction: String,
    /// The instance's current memory
    pub memory: String,
    /// The accumulated entries, removed from the buffer
    pub entries: Vec<serde_json::Value>,
}

/// Global application state
#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppStateInner>>,
    pub llm_activity: super::llm_activity::LlmActivityTracker,
    pub event_journal: Arc<crate::events::journal::EventJournal>,
}

struct AppStateInner {
    /// Current operating mode
    mode: Mode,
    /// All server instances
    servers: HashMap<ServerId, ServerInstance>,
    /// All client instances
    clients: HashMap<ClientId, ClientInstance>,
    /// Tor client instances (for directory queries)
    #[cfg(unix)]
    tor_clients: HashMap<ClientId, Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>,
    /// All easy protocol instances
    easy_instances: HashMap<EasyId, EasyInstance>,
    /// Mapping from underlying server ID to easy ID (for event routing)
    server_to_easy: HashMap<ServerId, EasyId>,
    /// Mapping from underlying client ID to easy ID (for event routing)
    client_to_easy: HashMap<ClientId, EasyId>,
    /// Unified ID counter for servers, connections, and clients
    /// This ensures all IDs are unique across all three types
    next_unified_id: u32,
    #[allow(dead_code)]
    /// Next server ID to assign (DEPRECATED - use next_unified_id)
    next_server_id: u32,
    #[allow(dead_code)]
    /// Next client ID to assign (DEPRECATED - use next_unified_id)
    next_client_id: u32,
    /// Current Ollama model (None = not yet selected/validated)
    ollama_model: Option<String>,
    /// Configured LLM client (with mock config, lock settings, etc.)
    llm_client: Option<crate::llm::OllamaClient>,
    /// Rate limiter for LLM calls (concurrency + token throttling)
    rate_limiter: crate::llm::RateLimiter,
    /// Available scripting environments (Python, Node.js)
    scripting_env: crate::scripting::ScriptingEnvironment,
    /// Currently selected scripting mode (LLM, Python, or JavaScript)
    selected_scripting_mode: ScriptingMode,
    /// Event handler mode (controls how LLM configures event handlers)
    event_handler_mode: EventHandlerMode,
    /// Web search mode (On/Off/Ask)
    web_search_mode: WebSearchMode,
    /// Channel for sending web approval requests to UI
    web_approval_tx: Option<mpsc::UnboundedSender<WebApprovalRequest>>,
    /// Whether to include disabled protocols (for testing)
    include_disabled_protocols: bool,
    /// Minimum protocol maturity that may be started (from `--min-stability`).
    /// `None` means no gate — the default, current behaviour.
    min_stability: Option<crate::protocol::metadata::DevelopmentState>,
    /// Whether Ollama API locking is enabled (for concurrent test execution)
    /// Ollama API base URL (default: http://localhost:11434)
    ollama_url: String,
    /// Unique instance ID for this NetGet process (for multi-instance isolation)
    instance_id: String,
    /// Scheduled tasks registry
    tasks: HashMap<TaskId, ScheduledTask>,
    /// In-flight scheduled executions, cancelled with their task or scope.
    scheduled_executions: HashMap<TaskId, tokio::task::JoinHandle<()>>,
    /// Workers cancelled when one peer closes, even while an injected write blocks.
    peer_tasks: HashMap<(ServerId, u32), Vec<tokio::task::JoinHandle<()>>>,
    /// Next task ID to assign
    next_task_id: u64,
    /// Conversation state for User Input Agent
    user_conversation_state: Option<Arc<std::sync::Mutex<crate::llm::ConversationState>>>,
    /// Task name to ID mapping (for user-friendly task_id strings)
    task_names: HashMap<String, TaskId>,
    /// System capabilities detected at startup
    system_capabilities: crate::privilege::SystemCapabilities,
    /// Active and recently-completed LLM conversations
    conversations: Vec<ConversationInfo>,
    /// Total LLM input tokens (prompt tokens)
    total_input_tokens: u64,
    /// Total LLM output tokens (completion tokens)
    total_output_tokens: u64,
    /// Total number of LLM calls made
    total_llm_calls: u64,
    /// SQLite database manager
    _database_manager: crate::state::DatabaseManager,
    /// Server protocols that have been documented (enables open_server for these protocols)
    documented_server_protocols: std::collections::HashSet<String>,
    /// Client protocols that have been documented (enables open_client for these protocols)
    documented_client_protocols: std::collections::HashSet<String>,
    /// Recent request/response access-log entries (bounded ring buffer)
    access_logs: std::collections::VecDeque<AccessLogEntry>,
    /// Next access-log entry id to assign
    next_access_log_id: u64,
    /// Declared pipes: `from` server's `on` event forwarded into `to` server.
    /// Keyed by pipe id. Torn down when either endpoint server closes.
    pipes: HashMap<crate::pipe::PipeId, crate::pipe::PipeSpec>,
    /// Maximum LLM calls a single client session may make (0 = unlimited)
    client_llm_call_limit: u32,
    /// LLM calls consumed so far, per client session.
    ///
    /// Kept here rather than on `ClientInstance` so the budget is owned by the
    /// component that enforces it; the entry is dropped by `remove_client`.
    client_llm_calls: HashMap<ClientId, u32>,
    /// Background tasks owned by each live client (read loops, transport drivers,
    /// in-flight requests, …).
    ///
    /// A `Vec` per client, not a single slot: several protocols spawn more than one
    /// task per connection (DNS spawns the hickory transport driver *and* the LLM
    /// conversation task); retaining only the last one would leak the rest.
    ///
    /// Lives here rather than on `ClientInstance` because the handles are only ever
    /// touched through `register_client_task` / `remove_client`, and `ClientInstance`
    /// is constructed by callers outside this module.
    client_tasks: HashMap<ClientId, Vec<tokio::task::JoinHandle<()>>>,
    /// Background tasks owned by each live server (accept loops, datagram readers,
    /// interface readers, …).
    ///
    /// A `Vec` per server for the same reason as `client_tasks`: a protocol may
    /// legitimately own more than one long-lived loop. WireGuard has a UDP listener
    /// and a TUN reader; OpenVPN had to fuse both under a single `select!` task
    /// purely because the previous single-slot registry silently dropped whichever
    /// handle was registered first, leaving `stop_server` able to abort only the
    /// last one.
    ///
    /// Lives here rather than on `ServerInstance` because the handles are only ever
    /// touched through `register_server_task` / `remove_server`, and `ServerInstance`
    /// is constructed by callers outside this module.
    server_tasks: HashMap<ServerId, Vec<tokio::task::JoinHandle<()>>>,
    /// Type-erased handles to the *running* instance of each server.
    ///
    /// Async protocol actions are dispatched on the stateless protocol struct from
    /// the registry, which has no channel or socket, so anything needing live state
    /// could only return `NoAction`. This is where the live half is reachable from.
    /// See `crate::state::server_handles` for the full rationale and the wiring
    /// still needed in `src/llm/actions/`.
    server_handles: HashMap<ServerId, crate::state::server_handles::ServerHandle>,
    /// Command channels into running clients' connection loops (the dashboard's
    /// \[send\] button and any future programmatic client control). See
    /// `crate::state::client_handles` for the design.
    client_handles: HashMap<ClientId, crate::state::client_handles::ClientHandle>,
    /// Events parked by a `manual` handler, waiting for a human to compose the
    /// answer at the dashboard. See `crate::state::intercepts`.
    pub(crate) pending_intercepts: Vec<crate::state::intercepts::PendingIntercept>,
    /// Monotonic id source for [`Self::pending_intercepts`].
    pub(crate) next_intercept_id: u64,
    /// Command channels into individual server connections, for protocols that
    /// adopted peer messaging (the dashboard's "message this peer"). Reuses the
    /// client command types: a command is just {action, reply}.
    peer_handles: HashMap<(ServerId, u32), crate::state::client_handles::ClientHandle>,
}

impl AppStateInner {
    fn remove_scheduled_task(&mut self, id: TaskId) -> Option<ScheduledTask> {
        if let Some(handle) = self.scheduled_executions.remove(&id) {
            handle.abort();
        }
        let task = self.tasks.remove(&id)?;
        if self.task_names.get(&task.name) == Some(&id) {
            self.task_names.remove(&task.name);
        }
        Some(task)
    }

    fn remove_peer(&mut self, server_id: ServerId, connection_id: u32) {
        self.peer_handles.remove(&(server_id, connection_id));
        for handle in self
            .peer_tasks
            .remove(&(server_id, connection_id))
            .unwrap_or_default()
        {
            handle.abort();
        }
    }

    /// Tear down everything a server owns, other than its own map entry.
    ///
    /// Called from every path that drops a server — [`AppState::remove_server`] and
    /// [`AppState::cleanup_old_servers`] — so that no caller can forget one half of
    /// it. Forgetting used to be easy and expensive: the MCP `stop_server` /
    /// `stop_all` tools called `remove_server` without the scheduled-task cleanup the
    /// TUI does, and every orphaned recurring task then kept firing on its interval,
    /// each tick producing an LLM prompt for a server that no longer existed.
    /// Abort everything the server owns. Returns the aborted listener and connection tasks:
    /// an abort only *requests* cancellation, and the socket a task holds is closed when the
    /// runtime next polls it, so a caller that needs the port free awaits these.
    fn teardown_server(&mut self, server_id: ServerId) -> Vec<tokio::task::JoinHandle<()>> {
        // Dropping a JoinHandle only DETACHES the task in Tokio, so the abort is what
        // actually releases the listening socket.
        let aborted = self.server_tasks.remove(&server_id).unwrap_or_default();
        for handle in &aborted {
            handle.abort();
        }
        // A live-instance handle must never outlive the server it points at.
        self.server_handles.remove(&server_id);
        self.peer_handles.retain(|(sid, _), _| *sid != server_id);
        self.peer_tasks.retain(|(sid, _), handles| {
            if *sid != server_id {
                return true;
            }
            for handle in handles {
                handle.abort();
            }
            false
        });
        self.drop_tasks_for_server(server_id);

        // Tear down any pipe touching this server (as source or sink), mirroring
        // scheduled-task scoping: a pipe cannot outlive either of its endpoints.
        let doomed: Vec<crate::pipe::PipeId> = self
            .pipes
            .iter()
            .filter(|(_, p)| p.from == server_id.as_u32() || p.to == server_id.as_u32())
            .map(|(&pid, _)| pid)
            .collect();
        for pid in doomed {
            self.pipes.remove(&pid);
        }
        aborted
    }

    /// Remove the scheduled tasks scoped to a server, including the tasks scoped to
    /// that server's individual connections.
    fn drop_tasks_for_server(&mut self, server_id: ServerId) {
        use crate::state::task::TaskScope;

        let task_ids_to_remove: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, task)| match &task.scope {
                TaskScope::Server(sid) => *sid == server_id,
                // A connection cannot outlive its server, so its tasks go too.
                TaskScope::Connection(sid, _) => *sid == server_id,
                _ => false,
            })
            .map(|(&id, _)| id)
            .collect();

        for id in task_ids_to_remove {
            self.remove_scheduled_task(id);
        }
    }
}

/// Default ceiling on LLM calls per client session.
///
/// Clients drive their own event loops, so a response handler that always
/// re-issues a request loops forever: the observed DNS-client runaway made 211
/// model calls before the process died. 100 is well above any legitimate
/// LLM-driven client session (the busiest real one — an SSH session issuing a
/// command per response — is a handful of calls) while capping the blast radius of
/// a non-converging loop to a bounded, affordable number of round-trips.
///
/// Override with `NETGET_CLIENT_LLM_CALL_LIMIT`; `0` disables the cap.
pub const DEFAULT_CLIENT_LLM_CALL_LIMIT: u32 = 100;

/// Read the per-client LLM call limit from the environment, falling back to
/// [`DEFAULT_CLIENT_LLM_CALL_LIMIT`] when unset or unparseable.
fn client_llm_call_limit_from_env() -> u32 {
    std::env::var("NETGET_CLIENT_LLM_CALL_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_CLIENT_LLM_CALL_LIMIT)
}

impl AppState {
    /// Create a new application state
    pub fn new() -> Self {
        Self::new_with_options(false, "http://localhost:11434".to_string())
    }

    /// Create a new application state with options
    pub fn new_with_options(include_disabled_protocols: bool, ollama_url: String) -> Self {
        // Detect scripting environments at startup
        let scripting_env = crate::scripting::ScriptingEnvironment::detect();

        // Detect system capabilities at startup
        let system_capabilities = crate::privilege::SystemCapabilities::detect();

        // Default to ON mode - LLM chooses runtime dynamically
        let selected_scripting_mode = ScriptingMode::On;
        let event_handler_mode = EventHandlerMode::default();

        // Generate unique instance ID: process_id + timestamp + random bytes
        let instance_id = Self::generate_instance_id();

        // Create default rate limiter (will be configured from CLI args later)
        let rate_limiter = crate::llm::RateLimiter::new(crate::llm::RateLimiterConfig::default());

        Self {
            llm_activity: super::llm_activity::LlmActivityTracker::default(),
            event_journal: Arc::new(crate::events::journal::EventJournal::default()),
            inner: Arc::new(RwLock::new(AppStateInner {
                mode: Mode::Idle,
                servers: HashMap::new(),
                clients: HashMap::new(),
                #[cfg(unix)]
                tor_clients: HashMap::new(),
                easy_instances: HashMap::new(),
                server_to_easy: HashMap::new(),
                client_to_easy: HashMap::new(),
                next_unified_id: 1,
                next_server_id: 1,
                next_client_id: 1,
                ollama_model: None,
                llm_client: None,
                rate_limiter,
                scripting_env,
                selected_scripting_mode,
                event_handler_mode,
                web_search_mode: WebSearchMode::On, // Default to enabled
                web_approval_tx: None,              // Will be set by TUI
                include_disabled_protocols,
                min_stability: None,
                ollama_url,
                instance_id,
                tasks: HashMap::new(),
                scheduled_executions: HashMap::new(),
                peer_tasks: HashMap::new(),
                next_task_id: 1,
                user_conversation_state: None,
                task_names: HashMap::new(),
                system_capabilities,
                conversations: Vec::new(),
                total_input_tokens: 0,
                total_output_tokens: 0,
                total_llm_calls: 0,
                _database_manager: crate::state::DatabaseManager::new(),
                documented_server_protocols: std::collections::HashSet::new(),
                documented_client_protocols: std::collections::HashSet::new(),
                access_logs: std::collections::VecDeque::new(),
                next_access_log_id: 1,
                pipes: HashMap::new(),
                client_llm_call_limit: client_llm_call_limit_from_env(),
                client_llm_calls: HashMap::new(),
                client_tasks: HashMap::new(),
                server_tasks: HashMap::new(),
                server_handles: HashMap::new(),
                client_handles: HashMap::new(),
                pending_intercepts: Vec::new(),
                next_intercept_id: 1,
                peer_handles: HashMap::new(),
            })),
        }
    }

    /// Generate a unique instance ID for this NetGet process
    /// Format: claude-{pid}-{timestamp}-{random4}
    fn generate_instance_id() -> String {
        use crate::utils::clock::{SystemTime, UNIX_EPOCH};

        let pid = crate::utils::clock::process_id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate 4 random hex characters for additional uniqueness
        let random_bytes: [u8; 2] = rand::random();
        let random_hex = hex::encode(random_bytes);

        format!("claude-{}-{}-{}", pid, timestamp, random_hex)
    }

    /// Get the current mode
    pub async fn get_mode(&self) -> Mode {
        self.inner.read().await.mode
    }

    /// Set the mode
    pub async fn set_mode(&self, mode: Mode) {
        self.inner.write().await.mode = mode;
    }

    /// Add a new server instance and return its ID
    pub async fn add_server(&self, mut server: ServerInstance) -> ServerId {
        let mut inner = self.inner.write().await;
        let id = ServerId::new(inner.next_unified_id);
        inner.next_unified_id += 1;
        server.id = id;
        inner.servers.insert(id, server);

        // Set mode to Server if this is the first server
        if inner.mode == Mode::Idle {
            inner.mode = Mode::Server;
        }

        id
    }

    /// Remove a server instance, aborting its background tasks and cancelling the
    /// scheduled tasks scoped to it.
    ///
    /// The cleanup is done here rather than left to callers: MCP's `stop_server` and
    /// `stop_all` did the removal without it, so every server- and connection-scoped
    /// scheduled task survived its server and kept firing on its interval.
    pub async fn remove_server(&self, id: ServerId) -> Option<ServerInstance> {
        let (server, aborted) = {
            let mut inner = self.inner.write().await;
            let server = inner.servers.remove(&id);
            let aborted = inner.teardown_server(id);
            // Set mode to Idle if no more servers and no clients
            if inner.servers.is_empty() && inner.clients.is_empty() {
                inner.mode = Mode::Idle;
            }
            (server, aborted)
        };
        // Outside the lock: wait for the aborted tasks to be dropped, so the listening socket
        // is closed when this returns. A stop followed by a start on the same port otherwise
        // races the runtime. Bounded, because a task stuck in blocking code never yields.
        for handle in aborted {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        }
        server
    }

    /// Declare a pipe: forward `from`'s `on` events into `to` as `as_action`,
    /// rendering `map` templates against the event data.
    ///
    /// Fails cleanly if either endpoint does not exist, or if the edge would
    /// close a cycle among existing pipes (including the self-loop `from == to`).
    pub async fn add_pipe(
        &self,
        from: ServerId,
        on: String,
        to: ServerId,
        as_action: String,
        map: std::collections::BTreeMap<String, String>,
    ) -> anyhow::Result<crate::pipe::PipeId> {
        let mut inner = self.inner.write().await;
        if !inner.servers.contains_key(&from) {
            anyhow::bail!("pipe source server #{} does not exist", from.as_u32());
        }
        if !inner.servers.contains_key(&to) {
            anyhow::bail!("pipe target server #{} does not exist", to.as_u32());
        }
        let existing: Vec<crate::pipe::PipeSpec> = inner.pipes.values().cloned().collect();
        if crate::pipe::would_create_cycle(&existing, from.as_u32(), to.as_u32()) {
            anyhow::bail!(
                "pipe #{} -> #{} refused: it would create a delivery cycle",
                from.as_u32(),
                to.as_u32()
            );
        }
        let id = inner.next_unified_id;
        inner.next_unified_id += 1;
        inner.pipes.insert(
            id,
            crate::pipe::PipeSpec {
                id,
                from: from.as_u32(),
                on,
                to: to.as_u32(),
                as_action,
                map,
            },
        );
        Ok(id)
    }

    /// Remove a pipe by id, returning it if present.
    pub async fn remove_pipe(&self, id: crate::pipe::PipeId) -> Option<crate::pipe::PipeSpec> {
        self.inner.write().await.pipes.remove(&id)
    }

    /// All declared pipes (cloned).
    pub async fn list_pipes(&self) -> Vec<crate::pipe::PipeSpec> {
        self.inner.read().await.pipes.values().cloned().collect()
    }

    /// Pipes whose source is `from` and that tap `event_id`.
    pub async fn pipes_matching(
        &self,
        from: ServerId,
        event_id: &str,
    ) -> Vec<crate::pipe::PipeSpec> {
        self.inner
            .read()
            .await
            .pipes
            .values()
            .filter(|p| p.from == from.as_u32() && p.on == event_id)
            .cloned()
            .collect()
    }

    /// Register a background task owned by a server so it can be aborted on stop.
    ///
    /// Protocol `spawn` implementations call this with the `JoinHandle` of every
    /// long-lived task they spawn — accept loop, datagram reader, interface reader —
    /// right after spawning it. Handles ACCUMULATE: registering a second task no
    /// longer discards the first, so a protocol with two loops gets both aborted.
    ///
    /// Finished handles are pruned on each registration so a protocol that registers
    /// a task per connection cannot grow the vector without bound.
    ///
    /// If the server was already removed (raced with stop), the task is aborted
    /// immediately to avoid leaking the listener.
    /// Cancellation, including dropping the returned future before its first
    /// poll, aborts the child until ownership has transferred into the registry.
    pub fn register_server_task(
        &self,
        id: ServerId,
        handle: tokio::task::JoinHandle<()>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        // This guard must exist before the async block: an async fn would leave
        // an unpolled future holding only the raw, detach-on-drop JoinHandle.
        let pending = PendingTaskRegistration(Some(handle));
        async move {
            let mut inner = self.inner.write().await;
            if !inner.servers.contains_key(&id) {
                return;
            }
            let tasks = inner.server_tasks.entry(id).or_default();
            tasks.retain(|h| !h.is_finished());
            tasks.push(pending.into_handle());
        }
    }

    /// Spawn a task the server owns and register it, in one call.
    ///
    /// **Prefer this over `tokio::spawn` + `register_server_task` for per-connection tasks.**
    /// A measurement on 15 September 2026 found 301 `tokio::spawn` calls across
    /// `src/server/*/mod.rs` against 159 `register_server_task` calls, in 102 protocols — and
    /// the unregistered ones are almost entirely the per-connection tasks, because the accept
    /// loop is the handle a protocol remembers to register and the connection it just accepted
    /// is the one it forgets. The consequence is the one the root `CLAUDE.md` records:
    /// `stop_server` releases the listening socket and **in-flight connections keep running**,
    /// still answering, still costing LLM budget, on a server the operator has stopped.
    ///
    /// Two properties make this safe to call per connection, both inherited from
    /// [`Self::register_server_task`]: finished handles are pruned on every registration, so
    /// the vector cannot grow without bound however many connections arrive; and a task
    /// spawned against an already-removed server is aborted immediately rather than leaking
    /// past its owner, which closes the accept-then-stop race.
    ///
    /// Returns an [`tokio::task::AbortHandle`] for the rare caller that needs to cancel the
    /// task itself before the server stops; most callers discard it.
    pub async fn spawn_server_task<F>(&self, id: ServerId, future: F) -> tokio::task::AbortHandle
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        let abort = handle.abort_handle();
        self.register_server_task(id, handle).await;
        abort
    }

    /// The client-side twin of [`Self::spawn_server_task`]. Same reasoning: a client that
    /// spawns a task per request should not have to remember two calls.
    pub async fn spawn_client_task<F>(&self, id: ClientId, future: F) -> tokio::task::AbortHandle
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        let abort = handle.abort_handle();
        self.register_client_task(id, handle).await;
        abort
    }

    /// Register a handle to the *running* instance of a server, so protocol actions
    /// can reach its live state.
    ///
    /// A protocol's `spawn()` calls this with whatever type carries its live state —
    /// typically a struct of `mpsc::Sender`s and shared views. The type is erased
    /// here so `AppState` never learns any protocol's types; the protocol recovers
    /// it with [`Self::server_handle`].
    ///
    /// Registering against an already-removed server is a no-op: the handle is
    /// dropped rather than resurrecting an entry for a server that is gone.
    ///
    /// # Reaching this from an action
    ///
    /// Async actions are dispatched through `Server::execute_action()` on the
    /// *stateless* protocol struct, which is why they can only return `NoAction`
    /// today. Making this registry reachable needs one change in
    /// `src/llm/actions/`, both parts mechanical:
    ///
    /// ```ignore
    /// // src/llm/actions/protocol_trait.rs, in `trait Server`:
    /// fn execute_action_with_state(
    ///     &self,
    ///     action: serde_json::Value,
    ///     state: AppState,                       // cheap: AppState is an Arc
    ///     server_id: Option<crate::state::ServerId>,
    /// ) -> std::pin::Pin<
    ///     Box<dyn std::future::Future<Output = anyhow::Result<ActionResult>> + Send + '_>,
    /// > {
    ///     // Default keeps every existing protocol working untouched.
    ///     let _ = (state, server_id);
    ///     let result = self.execute_action(action);
    ///     Box::pin(async move { result })
    /// }
    ///
    /// // src/llm/actions/executor.rs, replacing the `proto.execute_action(...)` call:
    /// match proto
    ///     .execute_action_with_state(action.clone(), state.clone(), server_id)
    ///     .await
    /// { /* unchanged */ }
    /// ```
    ///
    /// A protocol that needs live state then overrides `execute_action_with_state`,
    /// calls `state.server_handle::<MyHandle>(server_id?)`, and talks to its own
    /// running server. Nothing about the stateless path changes.
    pub async fn register_server_handle<T: std::any::Any + Send + Sync>(
        &self,
        id: ServerId,
        handle: std::sync::Arc<T>,
    ) {
        let mut inner = self.inner.write().await;
        if !inner.servers.contains_key(&id) {
            return;
        }
        inner.server_handles.insert(id, handle);
    }

    /// Look up the live-instance handle of a server, downcast to the protocol's own
    /// handle type.
    ///
    /// Returns `None` if the server is gone, never registered a handle, or
    /// registered one of a different type — a protocol asking for someone else's
    /// handle gets a miss, not a panic.
    pub async fn server_handle<T: std::any::Any + Send + Sync>(
        &self,
        id: ServerId,
    ) -> Option<std::sync::Arc<T>> {
        self.inner
            .read()
            .await
            .server_handles
            .get(&id)
            .cloned()
            .and_then(|h| h.downcast::<T>().ok())
    }

    /// Whether a server has registered a live-instance handle
    pub async fn has_server_handle(&self, id: ServerId) -> bool {
        self.inner.read().await.server_handles.contains_key(&id)
    }

    // ===== Manual-handler intercepts (see crate::state::intercepts) =====

    /// Park an event for a human to answer. Returns the intercept id and the
    /// receiver the dispatcher must await (under its own timeout).
    pub async fn park_intercept(
        &self,
        owner: crate::state::intercepts::InterceptOwner,
        connection_id: Option<u32>,
        event_type: &str,
        description: &str,
        event_data: Option<serde_json::Value>,
        timeout_secs: u64,
    ) -> (u64, tokio::sync::oneshot::Receiver<Vec<serde_json::Value>>) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let mut inner = self.inner.write().await;
        let id = inner.next_intercept_id;
        inner.next_intercept_id += 1;
        inner.pending_intercepts.retain(|entry| !entry.is_dead());
        inner
            .pending_intercepts
            .push(crate::state::intercepts::PendingIntercept {
                id,
                owner,
                connection_id,
                event_type: event_type.to_string(),
                description: description.to_string(),
                event_data,
                created_unix_ms: crate::state::intercepts::now_unix_ms(),
                timeout_secs,
                reply_tx: Some(reply_tx),
            });
        let entry = inner.pending_intercepts.last().expect("just parked");
        let (server_id, client_id) = match owner {
            crate::state::intercepts::InterceptOwner::Server(id) => (Some(id.as_u32()), None),
            crate::state::intercepts::InterceptOwner::Client(id) => (None, Some(id.as_u32())),
        };
        self.event_journal.publish(crate::events::journal::INTERCEPT_PENDING, serde_json::json!({
            "intercept_id": id, "server_id": server_id, "client_id": client_id,
            "connection_id": connection_id, "event_type": event_type,
            "deadline_unix_ms": entry.created_unix_ms.saturating_add(timeout_secs.saturating_mul(1000)),
        }));
        (id, reply_rx)
    }

    /// Pending intercepts, oldest first, with dead entries pruned.
    pub async fn list_intercepts(&self) -> Vec<crate::state::intercepts::InterceptView> {
        let mut inner = self.inner.write().await;
        inner.pending_intercepts.retain(|entry| !entry.is_dead());
        inner.pending_intercepts.iter().map(|e| e.view()).collect()
    }

    /// Answer a parked event with the operator's actions.
    ///
    /// Errors if the intercept is gone — already answered, dismissed, or the
    /// waiting dispatcher gave up (timeout / connection closed). The answer is
    /// then NOT delivered anywhere; the peer has already received the
    /// fail-closed reply.
    pub async fn resolve_intercept(
        &self,
        id: u64,
        actions: Vec<serde_json::Value>,
    ) -> std::result::Result<(), String> {
        let entry = {
            let mut inner = self.inner.write().await;
            let Some(index) = inner.pending_intercepts.iter().position(|e| e.id == id) else {
                return Err(format!("request #{id} is no longer waiting"));
            };
            inner.pending_intercepts.remove(index)
        };
        let Some(tx) = entry.reply_tx else {
            return Err(format!("request #{id} was already answered"));
        };
        tx.send(actions).map_err(|_| {
            format!(
                "request #{id} timed out before this answer — the peer already got the \
                 fail-closed reply"
            )
        })
    }

    /// Refuse a parked event: the dispatcher sees "no answer" immediately and
    /// takes the fail-closed path instead of waiting out its timeout.
    pub async fn dismiss_intercept(&self, id: u64) -> bool {
        let mut inner = self.inner.write().await;
        let before = inner.pending_intercepts.len();
        // Dropping the entry drops its sender, which wakes the dispatcher's
        // `await` with RecvError.
        inner.pending_intercepts.retain(|e| e.id != id);
        inner.pending_intercepts.len() != before
    }

    /// Drop a parked entry without answering (the dispatcher cleans up after
    /// its own timeout so the list never shows a question nobody is waiting on).
    pub async fn remove_intercept(&self, id: u64) {
        let mut inner = self.inner.write().await;
        inner.pending_intercepts.retain(|e| e.id != id);
    }

    // ===== Peer command handles (message one server connection) =====

    /// Register a command channel into one connection of a server. Only
    /// protocols that adopted peer messaging call this; the dashboard offers
    /// "message this peer" exactly where a handle exists.
    pub async fn register_peer_handle(
        &self,
        server_id: ServerId,
        connection_id: u32,
        handle: crate::state::client_handles::ClientHandle,
    ) {
        let mut inner = self.inner.write().await;
        if !inner.servers.contains_key(&server_id) {
            return;
        }
        inner
            .peer_handles
            .insert((server_id, connection_id), handle);
    }

    /// Whether a connection accepts injected actions.
    pub async fn has_peer_handle(&self, server_id: ServerId, connection_id: u32) -> bool {
        self.inner
            .read()
            .await
            .peer_handles
            .contains_key(&(server_id, connection_id))
    }

    /// Drop a connection's command handle (the owning loop does this when the
    /// connection closes).
    pub async fn remove_peer_handle(&self, server_id: ServerId, connection_id: u32) {
        self.inner
            .write()
            .await
            .remove_peer(server_id, connection_id);
    }

    /// Track a peer worker under its connection. A close racing registration
    /// aborts it immediately; registration never revives a removed handle.
    pub fn register_peer_task(
        &self,
        server_id: ServerId,
        connection_id: u32,
        handle: tokio::task::JoinHandle<()>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        // Construct ownership before polling: dropping an unpolled registration
        // must abort the already-running worker, just like client/server tasks.
        let pending = PendingTaskRegistration(Some(handle));
        async move {
            let mut inner = self.inner.write().await;
            if !inner.servers.contains_key(&server_id)
                || !inner.peer_handles.contains_key(&(server_id, connection_id))
            {
                return;
            }
            let tasks = inner
                .peer_tasks
                .entry((server_id, connection_id))
                .or_default();
            tasks.retain(|task| !task.is_finished());
            tasks.push(pending.into_handle());
        }
    }

    /// Execute one action inside a server connection's own task and wait for
    /// the outcome. Same lock discipline as `send_to_client`: clone the handle
    /// out, drop the guard, then await.
    pub async fn send_to_peer(
        &self,
        server_id: ServerId,
        connection_id: u32,
        action: serde_json::Value,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::state::client_handles::ClientSendOutcome> {
        use crate::state::client_handles::{ClientCommand, ClientSendOutcome};

        let handle = {
            let inner = self.inner.read().await;
            inner.peer_handles.get(&(server_id, connection_id)).cloned()
        };
        let Some(handle) = handle else {
            anyhow::bail!(
                "connection #{connection_id} on server #{} does not accept injected actions",
                server_id.as_u32()
            );
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let command = ClientCommand { action, reply_tx };
        if handle.command_tx.try_send(command).is_err() {
            // Full queue or a closed channel: either way the peer is not
            // taking commands right now. Prune a dead entry so the UI stops
            // offering it.
            let mut inner = self.inner.write().await;
            if let Some(entry) = inner.peer_handles.get(&(server_id, connection_id)) {
                if entry.command_tx.is_closed() {
                    inner.peer_handles.remove(&(server_id, connection_id));
                    return Ok(ClientSendOutcome::Disconnected);
                }
            }
            anyhow::bail!("connection #{connection_id} is busy — try again");
        }
        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Ok(ClientSendOutcome::Disconnected),
            Err(_) => anyhow::bail!("no outcome within {}s", timeout.as_secs()),
        }
    }

    // ===== Client command handles (see crate::state::client_handles) =====

    /// Register the command channel for a running client. No-op if the client
    /// row is already gone (raced with `stop_client`) — the caller's receiver
    /// is then the only reference and sends fail cleanly.
    pub async fn register_client_handle(
        &self,
        id: ClientId,
        handle: crate::state::client_handles::ClientHandle,
    ) {
        let mut inner = self.inner.write().await;
        if !inner.clients.contains_key(&id) {
            return;
        }
        inner.client_handles.insert(id, handle);
    }

    /// The command handle for a client, if its loop registered one.
    pub async fn client_handle(
        &self,
        id: ClientId,
    ) -> Option<crate::state::client_handles::ClientHandle> {
        self.inner.read().await.client_handles.get(&id).cloned()
    }

    /// Whether a running client accepts injected commands. The UI uses this to
    /// grey out \[send\] for clients that have not adopted the channel.
    pub async fn has_client_handle(&self, id: ClientId) -> bool {
        self.inner.read().await.client_handles.contains_key(&id)
    }

    /// Drop a client's command handle (called by the loop on exit; also done
    /// by `remove_client`).
    pub async fn remove_client_handle(&self, id: ClientId) {
        self.inner.write().await.client_handles.remove(&id);
    }

    /// Execute one action inside a running client's connection loop and wait
    /// for the outcome.
    ///
    /// Lock discipline: the handle is cloned out under the read guard and the
    /// guard dropped before any await on the channel.
    pub async fn send_to_client(
        &self,
        id: ClientId,
        action: serde_json::Value,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::state::client_handles::ClientSendOutcome> {
        use crate::state::client_handles::ClientCommand;

        let handle = match self.client_handle(id).await {
            Some(handle) => handle,
            None => {
                anyhow::bail!(
                    "client #{} does not accept injected commands \
                     (not running, or its protocol has not adopted the command channel)",
                    id.as_u32()
                )
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let command = ClientCommand { action, reply_tx };

        // A full channel within the timeout means the loop is alive but busy;
        // a closed channel means the loop exited.
        match tokio::time::timeout(timeout, handle.command_tx.send(command)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => anyhow::bail!(
                "client #{}'s connection loop is not running (channel closed)",
                id.as_u32()
            ),
            Err(_) => anyhow::bail!(
                "client #{} is busy (command queue full after {:?})",
                id.as_u32(),
                timeout
            ),
        }

        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => anyhow::bail!(
                "client #{}'s connection loop dropped the command without executing it \
                 (loop shutting down)",
                id.as_u32()
            ),
            Err(_) => anyhow::bail!(
                "client #{} did not report an outcome within {:?}",
                id.as_u32(),
                timeout
            ),
        }
    }

    /// Number of background tasks currently tracked for a server
    pub async fn server_task_count(&self, id: ServerId) -> usize {
        self.inner
            .read()
            .await
            .server_tasks
            .get(&id)
            .map(|t| t.len())
            .unwrap_or(0)
    }

    /// Get a server instance (cloned)
    pub async fn get_server(&self, id: ServerId) -> Option<ServerInstance> {
        self.inner.read().await.servers.get(&id).cloned()
    }

    /// Get all server IDs
    pub async fn get_all_server_ids(&self) -> Vec<ServerId> {
        self.inner.read().await.servers.keys().copied().collect()
    }

    /// Get all servers (cloned)
    pub async fn get_all_servers(&self) -> Vec<ServerInstance> {
        self.inner.read().await.servers.values().cloned().collect()
    }

    /// Update server status
    pub async fn update_server_status(&self, id: ServerId, status: super::server::ServerStatus) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&id) {
            server.status = status;
            server.status_changed_at = crate::utils::clock::Instant::now();
        }
    }

    /// Update server local listening address
    pub async fn update_server_local_addr(&self, id: ServerId, local_addr: std::net::SocketAddr) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&id) {
            server.local_addr = Some(local_addr);
        }
    }

    /// Get instruction for a specific server
    pub async fn get_instruction(&self, server_id: ServerId) -> Option<String> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .map(|s| s.instruction.clone())
    }

    /// Set instruction for a specific server
    pub async fn set_instruction(&self, server_id: ServerId, instruction: String) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            server.instruction = instruction;
        }
    }

    /// Get memory for a specific server
    pub async fn get_memory(&self, server_id: ServerId) -> Option<String> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .map(|s| s.memory.clone())
    }

    /// Set memory for a specific server
    pub async fn set_memory(&self, server_id: ServerId, memory: String) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            server.memory = memory;
        }
    }

    /// Append to memory for a specific server
    pub async fn append_memory(&self, server_id: ServerId, text: String) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if !server.memory.is_empty() {
                server.memory.push('\n');
            }
            server.memory.push_str(&text);
        }
    }

    /// Add feedback to a server's feedback buffer
    ///
    /// Feedback is accumulated and processed later via debounced LLM invocation
    /// Returns Ok if feedback was added, Err if server not found or feedback_instructions not set
    pub async fn add_server_feedback(
        &self,
        server_id: ServerId,
        feedback: serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(server) = inner.servers.get_mut(&server_id) {
            // Only accumulate feedback if feedback_instructions is set
            if server.feedback_instructions.is_some() {
                server.feedback_buffer.push(feedback);
                Ok(())
            } else {
                anyhow::bail!(
                    "Server {} has no feedback_instructions configured",
                    server_id
                )
            }
        } else {
            anyhow::bail!("Server {} not found", server_id)
        }
    }

    /// Take the feedback that is due for processing, emptying those buffers.
    ///
    /// Leading-edge debounce: an instance is due as soon as it has any buffered feedback
    /// and `debounce` has elapsed since its last processing (so the first feedback after a
    /// quiet period is acted on at the next tick, and a burst is coalesced into one call).
    /// `last_feedback_processed` is stamped here rather than after the LLM answers, so a
    /// slow or failing call cannot re-trigger itself on every tick.
    ///
    /// Draining here — under the same write lock that stamps the timestamp — is what makes
    /// the caller safe to run from a 1s timer: two ticks can never take the same entries.
    pub async fn take_due_feedback(&self, debounce: std::time::Duration) -> Vec<DueFeedback> {
        let now = crate::utils::clock::Instant::now();
        let mut due = Vec::new();
        let mut inner = self.inner.write().await;

        for (id, server) in inner.servers.iter_mut() {
            let Some(instructions) = server.feedback_instructions.clone() else {
                continue;
            };
            if server.feedback_buffer.is_empty() {
                continue;
            }
            if let Some(last) = server.last_feedback_processed {
                if now.duration_since(last) < debounce {
                    continue;
                }
            }
            server.last_feedback_processed = Some(now);
            due.push(DueFeedback {
                server_id: Some(*id),
                client_id: None,
                instructions,
                instruction: server.instruction.clone(),
                memory: server.memory.clone(),
                entries: std::mem::take(&mut server.feedback_buffer),
            });
        }

        for (id, client) in inner.clients.iter_mut() {
            let Some(instructions) = client.feedback_instructions.clone() else {
                continue;
            };
            if client.feedback_buffer.is_empty() {
                continue;
            }
            if let Some(last) = client.last_feedback_processed {
                if now.duration_since(last) < debounce {
                    continue;
                }
            }
            client.last_feedback_processed = Some(now);
            due.push(DueFeedback {
                server_id: None,
                client_id: Some(*id),
                instructions,
                instruction: client.instruction.clone(),
                memory: client.memory.clone(),
                entries: std::mem::take(&mut client.feedback_buffer),
            });
        }

        due
    }

    /// Add feedback to a client's feedback buffer
    ///
    /// Feedback is accumulated and processed later via debounced LLM invocation
    /// Returns Ok if feedback was added, Err if client not found or feedback_instructions not set
    pub async fn add_client_feedback(
        &self,
        client_id: super::ClientId,
        feedback: serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(client) = inner.clients.get_mut(&client_id) {
            // Only accumulate feedback if feedback_instructions is set
            if client.feedback_instructions.is_some() {
                client.feedback_buffer.push(feedback);
                Ok(())
            } else {
                anyhow::bail!(
                    "Client {} has no feedback_instructions configured",
                    client_id
                )
            }
        } else {
            anyhow::bail!("Client {} not found", client_id)
        }
    }

    /// Get the Ollama model name
    pub async fn get_ollama_model(&self) -> Option<String> {
        self.inner.read().await.ollama_model.clone()
    }

    /// Set the Ollama model name
    pub async fn set_ollama_model(&self, model: Option<String>) {
        self.inner.write().await.ollama_model = model;
    }

    /// Get the scripting environment information
    pub async fn get_scripting_env(&self) -> crate::scripting::ScriptingEnvironment {
        self.inner.read().await.scripting_env.clone()
    }

    /// Set scripting environment
    ///
    /// This is primarily used for testing to inject a mock environment.
    /// In production, the environment is auto-detected at startup.
    pub async fn set_scripting_env(&self, env: crate::scripting::ScriptingEnvironment) {
        self.inner.write().await.scripting_env = env;
    }

    /// Get the currently selected scripting mode
    pub async fn get_selected_scripting_mode(&self) -> ScriptingMode {
        self.inner.read().await.selected_scripting_mode
    }

    /// Set the selected scripting mode
    pub async fn set_selected_scripting_mode(&self, mode: ScriptingMode) {
        self.inner.write().await.selected_scripting_mode = mode;
    }

    /// Cycle between ON and OFF scripting modes
    /// Returns the new mode and whether any switch occurred
    pub async fn cycle_scripting_mode(&self) -> (ScriptingMode, bool) {
        let mut inner = self.inner.write().await;
        let current = inner.selected_scripting_mode;

        // Toggle between ON and OFF only
        // If currently on a specific language, treat as ON and toggle to OFF
        let next = match current {
            ScriptingMode::On
            | ScriptingMode::Python
            | ScriptingMode::JavaScript
            | ScriptingMode::Go
            | ScriptingMode::Perl => ScriptingMode::Off,
            ScriptingMode::Off => ScriptingMode::On,
        };

        inner.selected_scripting_mode = next;
        (next, true)
    }

    /// Check if server documentation has been read (enables open_server)
    pub async fn is_server_docs_read(&self) -> bool {
        !self
            .inner
            .read()
            .await
            .documented_server_protocols
            .is_empty()
    }

    /// Check if client documentation has been read (enables open_client)
    pub async fn is_client_docs_read(&self) -> bool {
        !self
            .inner
            .read()
            .await
            .documented_client_protocols
            .is_empty()
    }

    /// Mark server protocols as documented
    pub async fn mark_server_protocols_documented(&self, protocols: &[String]) {
        let mut inner = self.inner.write().await;
        for protocol in protocols {
            if crate::llm::conversation_state::ConversationState::valid_documented_protocol(
                protocol,
            ) && inner.documented_server_protocols.len()
                < crate::llm::conversation_state::ConversationState::MAX_DOCUMENTED_PROTOCOLS
            {
                inner.documented_server_protocols.insert(protocol.clone());
            }
        }
    }

    /// Mark client protocols as documented
    pub async fn mark_client_protocols_documented(&self, protocols: &[String]) {
        let mut inner = self.inner.write().await;
        for protocol in protocols {
            if crate::llm::conversation_state::ConversationState::valid_documented_protocol(
                protocol,
            ) && inner.documented_client_protocols.len()
                < crate::llm::conversation_state::ConversationState::MAX_DOCUMENTED_PROTOCOLS
            {
                inner.documented_client_protocols.insert(protocol.clone());
            }
        }
    }

    /// Get all documented server protocols
    pub async fn get_documented_server_protocols(&self) -> std::collections::HashSet<String> {
        self.inner.read().await.documented_server_protocols.clone()
    }

    /// Get all documented client protocols
    pub async fn get_documented_client_protocols(&self) -> std::collections::HashSet<String> {
        self.inner.read().await.documented_client_protocols.clone()
    }

    /// Get the currently selected event handler mode
    pub async fn get_event_handler_mode(&self) -> EventHandlerMode {
        self.inner.read().await.event_handler_mode
    }

    /// Set the event handler mode
    pub async fn set_event_handler_mode(&self, mode: EventHandlerMode) {
        self.inner.write().await.event_handler_mode = mode;
    }

    /// Cycle event handler mode through ANY -> SCRIPT -> STATIC -> LLM -> ANY
    /// Returns the new mode
    pub async fn cycle_event_handler_mode(&self) -> EventHandlerMode {
        let mut inner = self.inner.write().await;
        inner.event_handler_mode = match inner.event_handler_mode {
            EventHandlerMode::Any => EventHandlerMode::Script,
            EventHandlerMode::Script => EventHandlerMode::Static,
            EventHandlerMode::Static => EventHandlerMode::Llm,
            EventHandlerMode::Llm => EventHandlerMode::Any,
        };
        inner.event_handler_mode
    }

    /// Get the current web search mode
    pub async fn get_web_search_mode(&self) -> WebSearchMode {
        self.inner.read().await.web_search_mode
    }

    /// Set the web search mode
    pub async fn set_web_search_mode(&self, mode: WebSearchMode) {
        self.inner.write().await.web_search_mode = mode;
    }

    /// Cycle web search mode through ON -> ASK -> OFF -> ON and return the new state
    pub async fn cycle_web_search_mode(&self) -> WebSearchMode {
        let mut inner = self.inner.write().await;
        inner.web_search_mode = match inner.web_search_mode {
            WebSearchMode::On => WebSearchMode::Ask,
            WebSearchMode::Ask => WebSearchMode::Off,
            WebSearchMode::Off => WebSearchMode::On,
        };
        inner.web_search_mode
    }

    /// Set the web approval channel (called by TUI on startup)
    pub async fn set_web_approval_channel(&self, tx: mpsc::UnboundedSender<WebApprovalRequest>) {
        self.inner.write().await.web_approval_tx = Some(tx);
    }

    /// Get a clone of the web approval channel
    pub async fn get_web_approval_channel(
        &self,
    ) -> Option<mpsc::UnboundedSender<WebApprovalRequest>> {
        self.inner.read().await.web_approval_tx.clone()
    }

    /// Get whether disabled protocols should be included
    pub async fn get_include_disabled_protocols(&self) -> bool {
        self.inner.read().await.include_disabled_protocols
    }

    /// Get the minimum stability required to start a protocol, if any
    /// (`None` = no gate).
    pub async fn get_min_stability(&self) -> Option<crate::protocol::metadata::DevelopmentState> {
        self.inner.read().await.min_stability
    }

    /// Set the minimum stability required to start a protocol (from
    /// `--min-stability`). `None` disables the gate.
    pub async fn set_min_stability(
        &self,
        min: Option<crate::protocol::metadata::DevelopmentState>,
    ) {
        self.inner.write().await.min_stability = min;
    }

    /// Get the Ollama API base URL
    pub async fn get_ollama_url(&self) -> String {
        self.inner.read().await.ollama_url.clone()
    }

    /// Set the configured LLM client
    pub async fn set_llm_client(&self, client: crate::llm::OllamaClient) {
        self.inner.write().await.llm_client = Some(client);
    }

    /// Get the configured LLM client
    pub async fn get_llm_client(&self) -> Option<crate::llm::OllamaClient> {
        self.inner.read().await.llm_client.clone()
    }

    /// Get the rate limiter
    pub async fn get_rate_limiter(&self) -> crate::llm::RateLimiter {
        self.inner.read().await.rate_limiter.clone()
    }

    /// Configure the rate limiter
    pub async fn configure_rate_limiter(
        &self,
        config: crate::llm::RateLimiterConfig,
    ) -> anyhow::Result<()> {
        let rate_limiter = self.inner.read().await.rate_limiter.clone();
        rate_limiter.update_config(config).await
    }

    /// Get the unique instance ID for this NetGet process
    pub async fn get_instance_id(&self) -> String {
        self.inner.read().await.instance_id.clone()
    }

    /// Get system capabilities detected at startup
    pub async fn get_system_capabilities(&self) -> crate::privilege::SystemCapabilities {
        self.inner.read().await.system_capabilities.clone()
    }

    /// Get the next unified ID (for connections)
    /// This ensures all IDs (servers, connections, clients) are unique across all types
    pub async fn get_next_unified_id(&self) -> u32 {
        let mut inner = self.inner.write().await;
        let id = inner.next_unified_id;
        inner.next_unified_id += 1;
        id
    }

    /// Update event handler configuration for a server
    pub async fn set_event_handler_config(
        &self,
        server_id: ServerId,
        config: Option<crate::scripting::EventHandlerConfig>,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            server.event_handler_config = config;
        }
    }

    /// Get event handler configuration for a server
    pub async fn get_event_handler_config(
        &self,
        server_id: ServerId,
    ) -> Option<crate::scripting::EventHandlerConfig> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .and_then(|s| s.event_handler_config.clone())
    }

    /// Get a summary of current state for LLM context
    pub async fn get_summary(&self) -> String {
        let inner = self.inner.read().await;
        let total_connections: usize = inner.servers.values().map(|s| s.connections.len()).sum();
        format!(
            "Mode: {}, Servers: {}, Clients: {}, Total Connections: {}",
            inner.mode,
            inner.servers.len(),
            inner.clients.len(),
            total_connections
        )
    }

    /// Get protocol name for a server
    pub async fn get_protocol_name(&self, server_id: ServerId) -> Option<String> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .map(|s| s.protocol_name.clone())
    }

    /// Reap idle bookkeeping entries on **connectionless** servers (UDP, raw
    /// IP, link-level): their "connections" are per-remote-address records
    /// that nothing ever closes, so staleness is the only signal.
    ///
    /// Connection-oriented servers are skipped on purpose. This used to run
    /// over every server, and an idle TCP-style connection — a telnet peer
    /// whose line was parked ten seconds for a human's manual answer, a BGP
    /// session between keepalives — was evicted from the state map and shown
    /// as `(closed)` while its socket was alive; every later stat update and
    /// the real close then targeted an entry that was already gone. Which
    /// servers qualify comes from `ProtocolMetadataV2::connectionless`, so a
    /// protocol the registry does not know is left alone.
    pub async fn cleanup_old_connections(&self, max_age_secs: u64) {
        let mut inner = self.inner.write().await;
        for server in inner.servers.values_mut() {
            let connectionless = crate::protocol::server_registry::registry()
                .resolve(&server.protocol_name)
                .map(|p| p.metadata().connectionless)
                .unwrap_or(false);
            if connectionless {
                server.cleanup_old_connections(max_age_secs);
            }
        }
    }

    /// Cleanup old closed connections (removes connections that have been closed for more than max_age_secs)
    pub async fn cleanup_closed_connections(&self, max_age_secs: u64) {
        use super::server::ConnectionStatus;
        let now = crate::utils::clock::Instant::now();

        let mut inner = self.inner.write().await;
        for server in inner.servers.values_mut() {
            let to_remove: Vec<crate::server::connection::ConnectionId> = server
                .connections
                .iter()
                .filter(|(_, conn)| {
                    conn.status == ConnectionStatus::Closed
                        && now.duration_since(conn.status_changed_at).as_secs() >= max_age_secs
                })
                .map(|(id, _)| *id)
                .collect();

            for id in to_remove {
                server.remove_connection(id);
            }
        }
    }

    /// Cleanup old stopped/error servers (removes servers that have been stopped/error for more than max_age_secs)
    ///
    /// Reaping a server here runs the same teardown as [`Self::remove_server`]:
    /// background tasks aborted, scoped scheduled tasks cancelled. It previously
    /// dropped the map entry alone, which detached (rather than aborted) whatever
    /// the server was still running and left its scheduled tasks firing.
    ///
    /// Must be driven by *some* loop or it never runs. The TUI ticks it; MCP mode has
    /// its own reaper (`mcp_stdio::tools::spawn_state_reaper`), without which an
    /// LLM-initiated `close_server` left entries in `AppState` forever.
    pub async fn cleanup_old_servers(&self, max_age_secs: u64) {
        use super::server::ServerStatus;
        let now = crate::utils::clock::Instant::now();

        let mut inner = self.inner.write().await;
        let to_remove: Vec<ServerId> = inner
            .servers
            .iter()
            .filter(|(_, server)| {
                let age = now.duration_since(server.status_changed_at).as_secs();
                // Remove if stopped and status changed more than max_age_secs ago
                // (Error servers are removed immediately on failure)
                matches!(server.status, ServerStatus::Stopped) && age >= max_age_secs
            })
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            inner.servers.remove(&id);
            // Detached on purpose: this sweep holds the state lock and must not wait.
            drop(inner.teardown_server(id));
        }

        // Set mode to Idle if no more servers and no clients
        if inner.servers.is_empty() && inner.clients.is_empty() {
            inner.mode = Mode::Idle;
        }
    }

    /// Add a connection to a specific server
    pub async fn add_connection_to_server(
        &self,
        server_id: ServerId,
        connection: super::server::ConnectionState,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            server.add_connection(connection);
        }
    }

    /// Mark a connection as closed (instead of removing it immediately)
    pub async fn close_connection_on_server(
        &self,
        server_id: ServerId,
        connection_id: crate::server::connection::ConnectionId,
    ) {
        use super::server::ConnectionStatus;
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.get_connection_mut(connection_id) {
                conn.status = ConnectionStatus::Closed;
                conn.status_changed_at = crate::utils::clock::Instant::now();
            }
        }

        self.remove_peer_handle(server_id, connection_id.as_u32())
            .await;

        // Clean up any tasks associated with this connection
        self.cleanup_connection_tasks(server_id, connection_id)
            .await;
    }

    /// Remove a connection from a specific server (used by cleanup task)
    pub async fn remove_connection_from_server(
        &self,
        server_id: ServerId,
        connection_id: crate::server::connection::ConnectionId,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            server.remove_connection(connection_id);
        }

        self.remove_peer_handle(server_id, connection_id.as_u32())
            .await;

        // Clean up any tasks associated with this connection (safety measure)
        // Tasks should already be cleaned up when connection was closed,
        // but this ensures no orphaned tasks remain
        self.cleanup_connection_tasks(server_id, connection_id)
            .await;
    }

    /// Recently closed connections for a server, newest first. Empty when the
    /// server does not exist.
    pub async fn get_recent_connections(
        &self,
        server_id: ServerId,
    ) -> Vec<super::server::ClosedConnectionSummary> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .map(|server| server.recent_connections.iter().cloned().collect())
            .unwrap_or_default()
    }

    // ========== Proxy Filter Configuration Methods ==========

    /// Get proxy filter configuration for a server
    #[cfg(unix)]
    pub async fn get_proxy_filter_config(
        &self,
        server_id: ServerId,
    ) -> Option<crate::server::proxy::filter::ProxyFilterConfig> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .and_then(|s| {
                s.protocol_data
                    .get("proxy_filter_config")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
            })
    }

    /// Set proxy filter configuration for a server
    #[cfg(unix)]
    pub async fn set_proxy_filter_config(
        &self,
        server_id: ServerId,
        config: crate::server::proxy::filter::ProxyFilterConfig,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Ok(value) = serde_json::to_value(&config) {
                server.set_protocol_field("proxy_filter_config".to_string(), value);
            }
        }
    }

    /// Update proxy filter configuration by merging with existing config
    #[cfg(unix)]
    pub async fn update_proxy_filter_config(
        &self,
        server_id: ServerId,
        update_fn: impl FnOnce(&mut crate::server::proxy::filter::ProxyFilterConfig),
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            let mut config = server
                .protocol_data
                .get("proxy_filter_config")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_else(crate::server::proxy::filter::ProxyFilterConfig::default);

            update_fn(&mut config);

            if let Ok(value) = serde_json::to_value(&config) {
                server.set_protocol_field("proxy_filter_config".to_string(), value);
            }
        }
    }

    /// Get SOCKS5 filter configuration for a server
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn get_socks5_filter_config(
        &self,
        server_id: ServerId,
    ) -> Option<crate::server::socks5::filter::Socks5FilterConfig> {
        self.inner
            .read()
            .await
            .servers
            .get(&server_id)
            .and_then(|s| {
                s.protocol_data
                    .get("socks5_filter_config")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
            })
    }

    /// Set SOCKS5 filter configuration for a server
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn set_socks5_filter_config(
        &self,
        server_id: ServerId,
        config: crate::server::socks5::filter::Socks5FilterConfig,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Ok(value) = serde_json::to_value(&config) {
                server.set_protocol_field("socks5_filter_config".to_string(), value);
            }
        }
    }

    /// Update SOCKS5 connection target address
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn update_socks5_target(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        target_addr: Option<String>,
        username: Option<String>,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                // Update fields in the flexible storage
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    if let Some(target) = target_addr {
                        obj.insert("target_addr".to_string(), serde_json::Value::String(target));
                    } else {
                        obj.insert("target_addr".to_string(), serde_json::Value::Null);
                    }
                    if let Some(user) = username {
                        obj.insert("username".to_string(), serde_json::Value::String(user));
                    } else {
                        obj.insert("username".to_string(), serde_json::Value::Null);
                    }
                }
            }
        }
    }

    // ========== IMAP Connection State Methods ==========

    /// Update IMAP connection session state
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn update_imap_session_state(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        session_state: crate::state::server::ImapSessionState,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    obj.insert(
                        "session_state".to_string(),
                        serde_json::to_value(&session_state).unwrap_or(serde_json::Value::Null),
                    );
                }
            }
        }
    }

    /// Update IMAP connection full state (session, user, mailbox)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn update_imap_connection_state(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        session_state: Option<crate::state::server::ImapSessionState>,
        authenticated_user: Option<Option<String>>,
        selected_mailbox: Option<Option<String>>,
        mailbox_read_only: Option<bool>,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    if let Some(s) = session_state {
                        obj.insert(
                            "session_state".to_string(),
                            serde_json::to_value(&s).unwrap_or(serde_json::Value::Null),
                        );
                    }
                    if let Some(u) = authenticated_user {
                        obj.insert(
                            "authenticated_user".to_string(),
                            serde_json::to_value(&u).unwrap_or(serde_json::Value::Null),
                        );
                    }
                    if let Some(m) = selected_mailbox {
                        obj.insert(
                            "selected_mailbox".to_string(),
                            serde_json::to_value(&m).unwrap_or(serde_json::Value::Null),
                        );
                    }
                    if let Some(r) = mailbox_read_only {
                        obj.insert("mailbox_read_only".to_string(), serde_json::Value::Bool(r));
                    }
                }
            }
        }
    }

    /// Get IMAP connection state
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn get_imap_connection_state(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
    ) -> Option<(
        crate::state::server::ImapSessionState,
        Option<String>,
        Option<String>,
    )> {
        let inner = self.inner.read().await;
        if let Some(server) = inner.servers.get(&server_id) {
            if let Some(conn) = server.connections.get(&connection_id) {
                let session_state = conn
                    .protocol_info
                    .data
                    .get("session_state")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())?;
                let authenticated_user = conn
                    .protocol_info
                    .data
                    .get("authenticated_user")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                let selected_mailbox = conn
                    .protocol_info
                    .data
                    .get("selected_mailbox")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                return Some((
                    session_state,
                    authenticated_user.flatten(),
                    selected_mailbox.flatten(),
                ));
            }
        }
        None
    }

    /// Update IMAP protocol state (Idle/Processing/Accumulating)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn update_imap_protocol_state(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        protocol_state: crate::state::server::ProtocolState,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    obj.insert(
                        "state".to_string(),
                        serde_json::to_value(&protocol_state).unwrap_or(serde_json::Value::Null),
                    );
                }
            }
        }
    }

    /// Update connection stats (bytes/packets)
    pub async fn update_connection_stats(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        bytes_received: Option<u64>,
        bytes_sent: Option<u64>,
        packets_received: Option<u64>,
        packets_sent: Option<u64>,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(br) = bytes_received {
                    conn.bytes_received += br;
                }
                if let Some(bs) = bytes_sent {
                    conn.bytes_sent += bs;
                }
                if let Some(pr) = packets_received {
                    conn.packets_received += pr;
                }
                if let Some(ps) = packets_sent {
                    conn.packets_sent += ps;
                }
                conn.last_activity = crate::utils::clock::Instant::now();
            }
        }
    }

    /// Update connection status
    pub async fn update_connection_status(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        status: crate::state::server::ConnectionStatus,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                conn.status = status;
                conn.status_changed_at = crate::utils::clock::Instant::now();
            }
        }
    }

    /// Update VNC connection authentication status
    pub async fn update_vnc_connection_auth(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        authenticated: bool,
        username: Option<String>,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    obj.insert(
                        "authenticated".to_string(),
                        serde_json::Value::Bool(authenticated),
                    );
                    obj.insert(
                        "username".to_string(),
                        serde_json::to_value(&username).unwrap_or(serde_json::Value::Null),
                    );
                }
            }
        }
    }

    /// Update Bitcoin connection info
    pub async fn update_bitcoin_connection_info(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        last_message_type: String,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    obj.insert(
                        "last_message_type".to_string(),
                        serde_json::Value::String(last_message_type.clone()),
                    );
                    // Mark handshake complete if we've seen both version and verack
                    if last_message_type == "verack" {
                        obj.insert(
                            "handshake_complete".to_string(),
                            serde_json::Value::Bool(true),
                        );
                    }
                }
            }
        }
    }

    /// Update TFTP connection block number and total bytes
    pub async fn update_tftp_connection_block(
        &self,
        server_id: ServerId,
        connection_id: ConnectionId,
        block_number: u16,
        block_bytes: usize,
    ) {
        if let Some(server) = self.inner.write().await.servers.get_mut(&server_id) {
            if let Some(conn) = server.connections.get_mut(&connection_id) {
                if let Some(obj) = conn.protocol_info.data.as_object_mut() {
                    obj.insert(
                        "current_block".to_string(),
                        serde_json::Value::Number(block_number.into()),
                    );
                    // Update total bytes
                    let current_total =
                        obj.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    obj.insert(
                        "total_bytes".to_string(),
                        serde_json::Value::Number((current_total + block_bytes as u64).into()),
                    );
                }
            }
        }
    }

    /// Get VNC write half for sending framebuffer updates
    ///
    /// Note: This method is deprecated. Write halves are now managed locally
    /// within protocol modules and not stored in centralized state.
    pub async fn get_vnc_write_half(
        &self,
        _connection_id: ConnectionId,
    ) -> Option<std::sync::Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>>
    {
        // Write halves are no longer stored in centralized state
        // Protocols manage their own local connection data for I/O
        None
    }

    // ========== Client Management Methods ==========

    /// Add a new client instance and return its ID
    pub async fn add_client(&self, mut client: ClientInstance) -> ClientId {
        let mut inner = self.inner.write().await;
        let id = ClientId::new(inner.next_unified_id);
        inner.next_unified_id += 1;
        client.id = id;
        inner.clients.insert(id, client);

        // Set mode to Client if this is the first client (and no servers)
        if inner.mode == Mode::Idle {
            inner.mode = Mode::Client;
        }

        id
    }

    /// Remove a client instance, aborting every background task it owns.
    ///
    /// Dropping a `JoinHandle` only DETACHES the task in Tokio — it keeps running,
    /// keeps its socket open and keeps calling the LLM. Every handle registered via
    /// [`Self::register_client_task`] is therefore aborted explicitly here, which is
    /// what makes `stop_client` actually stop a client rather than just forgetting it.
    /// Disconnect a client but KEEP its row, so it can be reconnected later.
    ///
    /// Aborts the connection tasks (which closes the socket), drops the command
    /// handle, and marks the client Disconnected. Scheduled tasks and
    /// configuration survive — this is "hang up", not "remove".
    pub async fn disconnect_client(&self, id: ClientId) -> bool {
        {
            let mut inner = self.inner.write().await;
            if !inner.clients.contains_key(&id) {
                return false;
            }
            for handle in inner.client_tasks.remove(&id).unwrap_or_default() {
                handle.abort();
            }
            inner.client_handles.remove(&id);
        }
        self.update_client_status(id, super::client::ClientStatus::Disconnected)
            .await;
        true
    }

    pub async fn remove_client(&self, id: ClientId) -> Option<ClientInstance> {
        let client = {
            let mut inner = self.inner.write().await;
            let client = inner.clients.remove(&id);
            inner.client_llm_calls.remove(&id);
            // A command handle must never outlive the client it points at.
            inner.client_handles.remove(&id);

            for handle in inner.client_tasks.remove(&id).unwrap_or_default() {
                handle.abort();
            }

            let task_ids: Vec<_> = inner
                .tasks
                .iter()
                .filter_map(|(task_id, task)| {
                    matches!(task.scope, crate::state::task::TaskScope::Client(cid) if cid == id)
                        .then_some(*task_id)
                })
                .collect();
            for task_id in task_ids {
                inner.remove_scheduled_task(task_id);
            }

            // Set mode to Idle if no more clients and no servers
            if inner.clients.is_empty() && inner.servers.is_empty() {
                inner.mode = Mode::Idle;
            }

            client
        };
        // Guard dropped above: resident-script teardown awaits child kills and
        // must not run under the state lock.
        crate::scripting::ResidentScriptManager::shutdown_client(id.as_u32()).await;

        client
    }

    /// Register a background task owned by a client so it can be aborted on stop.
    ///
    /// Client `connect()` implementations call this with the `JoinHandle` of every
    /// task they spawn — read loop, transport driver, in-flight request — right
    /// after spawning it. Like `register_server_task`, handles accumulate: a
    /// client that spawns three tasks gets all three aborted, none silently dropped.
    ///
    /// If the client is already gone (raced with `stop_client`), the task is aborted
    /// on the spot so it cannot outlive its owner.
    /// Dropping its future, even before polling or while waiting for the state
    /// lock, aborts the child until the registry has taken ownership.
    pub fn register_client_task(
        &self,
        id: ClientId,
        handle: tokio::task::JoinHandle<()>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        let pending = PendingTaskRegistration(Some(handle));
        async move {
            let mut inner = self.inner.write().await;
            if !inner.clients.contains_key(&id) {
                return;
            }
            let tasks = inner.client_tasks.entry(id).or_default();
            // Prune completed per-request tasks without growing the registry.
            tasks.retain(|h| !h.is_finished());
            tasks.push(pending.into_handle());
        }
    }

    /// Number of background tasks currently tracked for a client
    pub async fn client_task_count(&self, id: ClientId) -> usize {
        self.inner
            .read()
            .await
            .client_tasks
            .get(&id)
            .map(|t| t.len())
            .unwrap_or(0)
    }

    /// Consume one LLM call from a client's budget.
    ///
    /// Returns `Ok(calls_used)` while the client is under its cap, and `Err(message)`
    /// once the cap is reached. Clients hand-roll their own event loops and at least
    /// one of them (DNS) could re-enter the LLM path indefinitely; an unbounded loop
    /// burns real money against a paid endpoint, so the budget is a hard stop rather
    /// than a warning.
    ///
    /// The limit is per client session (not per event) and is configurable via
    /// [`Self::set_client_llm_call_limit`] or `NETGET_CLIENT_LLM_CALL_LIMIT`
    /// (`0` disables the cap entirely).
    pub async fn try_consume_client_llm_call(&self, id: ClientId) -> Result<u32, String> {
        let mut inner = self.inner.write().await;
        let limit = inner.client_llm_call_limit;
        if !inner.clients.contains_key(&id) {
            // Client already removed — nothing to budget. Let the caller proceed and
            // discover the removal through its own state checks.
            return Ok(0);
        }
        let used = inner.client_llm_calls.entry(id).or_insert(0);

        if limit > 0 && *used >= limit {
            return Err(format!(
                "client {} exceeded its LLM call budget ({} calls). \
                 The client's event loop is not converging — it keeps invoking the model \
                 instead of terminating. Refusing further LLM calls; stop the client or \
                 raise NETGET_CLIENT_LLM_CALL_LIMIT (0 = unlimited).",
                id, limit
            ));
        }

        *used += 1;
        Ok(*used)
    }

    /// Number of LLM calls a client has consumed so far
    pub async fn get_client_llm_calls(&self, id: ClientId) -> u32 {
        self.inner
            .read()
            .await
            .client_llm_calls
            .get(&id)
            .copied()
            .unwrap_or(0)
    }

    /// Get the per-client LLM call cap (0 = unlimited)
    pub async fn get_client_llm_call_limit(&self) -> u32 {
        self.inner.read().await.client_llm_call_limit
    }

    /// Set the per-client LLM call cap (0 = unlimited)
    pub async fn set_client_llm_call_limit(&self, limit: u32) {
        self.inner.write().await.client_llm_call_limit = limit;
    }

    /// Get a client instance (cloned)
    pub async fn get_client(&self, id: ClientId) -> Option<ClientInstance> {
        self.inner.read().await.clients.get(&id).cloned()
    }

    /// Get all client IDs
    pub async fn get_all_client_ids(&self) -> Vec<ClientId> {
        self.inner.read().await.clients.keys().copied().collect()
    }

    /// Get all clients (cloned)
    pub async fn get_all_clients(&self) -> Vec<ClientInstance> {
        self.inner.read().await.clients.values().cloned().collect()
    }

    /// Update client status
    pub async fn update_client_status(&self, id: ClientId, status: super::client::ClientStatus) {
        if let Some(client) = self.inner.write().await.clients.get_mut(&id) {
            client.record_status_transition(&status);
            client.status = status;
            client.status_changed_at = crate::utils::clock::Instant::now();
        }
    }

    /// Get instruction for a specific client
    pub async fn get_instruction_for_client(&self, client_id: ClientId) -> Option<String> {
        self.inner
            .read()
            .await
            .clients
            .get(&client_id)
            .map(|c| c.instruction.clone())
    }

    /// Set instruction for a specific client
    pub async fn set_instruction_for_client(&self, client_id: ClientId, instruction: String) {
        if let Some(client) = self.inner.write().await.clients.get_mut(&client_id) {
            client.instruction = instruction;
        }
    }

    /// Get memory for a specific client
    pub async fn get_memory_for_client(&self, client_id: ClientId) -> Option<String> {
        self.inner
            .read()
            .await
            .clients
            .get(&client_id)
            .map(|c| c.memory.clone())
    }

    /// Set memory for a specific client
    pub async fn set_memory_for_client(&self, client_id: ClientId, memory: String) {
        if let Some(client) = self.inner.write().await.clients.get_mut(&client_id) {
            client.memory = memory;
        }
    }

    /// Append to memory for a specific client
    pub async fn append_memory_for_client(&self, client_id: ClientId, text: String) {
        if let Some(client) = self.inner.write().await.clients.get_mut(&client_id) {
            if !client.memory.is_empty() {
                client.memory.push('\n');
            }
            client.memory.push_str(&text);
        }
    }

    /// Get protocol name for a client
    pub async fn get_protocol_name_for_client(&self, client_id: ClientId) -> Option<String> {
        self.inner
            .read()
            .await
            .clients
            .get(&client_id)
            .map(|c| c.protocol_name.clone())
    }

    /// Execute a closure with mutable access to a client
    pub async fn with_client_mut<F, R>(&self, client_id: ClientId, f: F) -> Option<R>
    where
        F: FnOnce(&mut ClientInstance) -> R,
    {
        self.inner.write().await.clients.get_mut(&client_id).map(f)
    }

    /// Update event handler configuration for a client
    pub async fn set_client_event_handler_config(
        &self,
        client_id: ClientId,
        config: Option<crate::scripting::EventHandlerConfig>,
    ) {
        if let Some(client) = self.inner.write().await.clients.get_mut(&client_id) {
            client.event_handler_config = config;
        }
    }

    /// Get event handler configuration for a client
    pub async fn get_client_event_handler_config(
        &self,
        client_id: ClientId,
    ) -> Option<crate::scripting::EventHandlerConfig> {
        self.inner
            .read()
            .await
            .clients
            .get(&client_id)
            .and_then(|c| c.event_handler_config.clone())
    }

    /// Cleanup old disconnected clients (removes clients that have been disconnected for more than max_age_secs)
    pub async fn cleanup_old_clients(&self, max_age_secs: u64) {
        use super::client::ClientStatus;
        let now = crate::utils::clock::Instant::now();

        let mut inner = self.inner.write().await;
        let to_remove: Vec<ClientId> = inner
            .clients
            .iter()
            .filter(|(_, client)| {
                let age = now.duration_since(client.status_changed_at).as_secs();
                // Remove if disconnected and status changed more than max_age_secs ago
                matches!(client.status, ClientStatus::Disconnected) && age >= max_age_secs
            })
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            inner.clients.remove(&id);
        }

        // Set mode to Idle if no more clients and no servers
        if inner.clients.is_empty() && inner.servers.is_empty() {
            inner.mode = Mode::Idle;
        }
    }

    // ========== Easy Protocol Management ==========

    /// Add a new easy protocol instance
    pub async fn add_easy_instance(&self, mut easy_instance: EasyInstance) -> EasyId {
        let mut inner = self.inner.write().await;
        let id = EasyId::new(inner.next_unified_id);
        inner.next_unified_id += 1;
        easy_instance.id = id;
        inner.easy_instances.insert(id, easy_instance);
        id
    }

    /// Remove an easy protocol instance
    pub async fn remove_easy_instance(&self, id: EasyId) -> Option<EasyInstance> {
        let mut inner = self.inner.write().await;
        let instance = inner.easy_instances.remove(&id);

        // Remove from routing maps if present
        if let Some(ref inst) = instance {
            if let Some(server_id) = inst.underlying_server_id {
                inner.server_to_easy.remove(&server_id);
            }
            if let Some(client_id) = inst.underlying_client_id {
                inner.client_to_easy.remove(&client_id);
            }
        }

        instance
    }

    /// Link an underlying server to an easy protocol instance (for event routing)
    pub async fn link_server_to_easy(&self, server_id: ServerId, easy_id: EasyId) {
        let mut inner = self.inner.write().await;
        inner.server_to_easy.insert(server_id, easy_id);
        if let Some(easy_instance) = inner.easy_instances.get_mut(&easy_id) {
            easy_instance.set_underlying_server(server_id);
        }
    }

    /// Link an underlying client to an easy protocol instance (for event routing)
    pub async fn link_client_to_easy(&self, client_id: ClientId, easy_id: EasyId) {
        let mut inner = self.inner.write().await;
        inner.client_to_easy.insert(client_id, easy_id);
        if let Some(easy_instance) = inner.easy_instances.get_mut(&easy_id) {
            easy_instance.set_underlying_client(client_id);
        }
    }

    /// Get easy ID for a given server ID (returns None if server is not managed by an easy protocol)
    pub async fn get_easy_for_server(&self, server_id: ServerId) -> Option<EasyId> {
        self.inner
            .read()
            .await
            .server_to_easy
            .get(&server_id)
            .copied()
    }

    /// Get easy ID for a given client ID (returns None if client is not managed by an easy protocol)
    pub async fn get_easy_for_client(&self, client_id: ClientId) -> Option<EasyId> {
        self.inner
            .read()
            .await
            .client_to_easy
            .get(&client_id)
            .copied()
    }

    /// Get easy protocol instance
    pub async fn get_easy_instance(&self, id: EasyId) -> Option<EasyInstance> {
        // Note: EasyInstance doesn't impl Clone because it contains JoinHandle
        // Instead we provide specific access methods
        self.inner.read().await.easy_instances.get(&id).map(|inst| {
            // Clone all fields except JoinHandle
            let mut cloned = EasyInstance::new(
                inst.id,
                inst.protocol_name.clone(),
                inst.underlying_protocol.clone(),
                inst.user_instruction.clone(),
            );
            cloned.underlying_server_id = inst.underlying_server_id;
            cloned.underlying_client_id = inst.underlying_client_id;
            cloned.status = inst.status.clone();
            cloned.created_at = inst.created_at;
            cloned.status_changed_at = inst.status_changed_at;
            // Note: handle is NOT cloned (cannot clone JoinHandle)
            cloned
        })
    }

    /// Update easy protocol status
    pub async fn update_easy_status(&self, id: EasyId, status: EasyStatus) {
        if let Some(instance) = self.inner.write().await.easy_instances.get_mut(&id) {
            instance.set_status(status);
        }
    }

    /// Get all easy protocol instances
    pub async fn get_all_easy_instances(&self) -> Vec<EasyInstance> {
        self.inner
            .read()
            .await
            .easy_instances
            .values()
            .map(|inst| {
                // Clone all fields except JoinHandle
                let mut cloned = EasyInstance::new(
                    inst.id,
                    inst.protocol_name.clone(),
                    inst.underlying_protocol.clone(),
                    inst.user_instruction.clone(),
                );
                cloned.underlying_server_id = inst.underlying_server_id;
                cloned.underlying_client_id = inst.underlying_client_id;
                cloned.status = inst.status.clone();
                cloned.created_at = inst.created_at;
                cloned.status_changed_at = inst.status_changed_at;
                cloned
            })
            .collect()
    }

    /// Execute a closure with mutable access to an easy instance
    pub async fn with_easy_mut<F, R>(&self, easy_id: EasyId, f: F) -> Option<R>
    where
        F: FnOnce(&mut EasyInstance) -> R,
    {
        self.inner
            .write()
            .await
            .easy_instances
            .get_mut(&easy_id)
            .map(f)
    }

    // ========== Backwards Compatibility Methods ==========
    // These methods help bridge old single-server code to new multi-server architecture
    // They typically operate on "the first server" or aggregate across all servers.
    // "First" is the lowest id, the instance started earliest: the maps are HashMaps, whose
    // iteration order is arbitrary, so `.next()` would pick a different server from run to run.

    /// Get the first server's port (for backwards compat)
    pub async fn get_port(&self) -> Option<u16> {
        self.inner
            .read()
            .await
            .servers
            .values()
            .min_by_key(|s| s.id)
            .map(|s| s.port)
    }

    /// Get the first server's protocol name (for backwards compat)
    pub async fn get_first_protocol_name(&self) -> Option<String> {
        self.inner
            .read()
            .await
            .servers
            .values()
            .min_by_key(|s| s.id)
            .map(|s| s.protocol_name.clone())
    }

    /// Get the first server's instruction (for backwards compat)
    pub async fn get_first_instruction(&self) -> String {
        self.inner
            .read()
            .await
            .servers
            .values()
            .min_by_key(|s| s.id)
            .map(|s| s.instruction.clone())
            .unwrap_or_default()
    }

    /// Get the first server's memory (for backwards compat)
    pub async fn get_first_memory(&self) -> String {
        self.inner
            .read()
            .await
            .servers
            .values()
            .min_by_key(|s| s.id)
            .map(|s| s.memory.clone())
            .unwrap_or_default()
    }

    /// Get the first server's ID (for backwards compat)
    pub async fn get_first_server_id(&self) -> Option<ServerId> {
        self.inner.read().await.servers.keys().min().copied()
    }

    /// Get the first client's ID (for backwards compat)
    pub async fn get_first_client_id(&self) -> Option<ClientId> {
        self.inner.read().await.clients.keys().min().copied()
    }

    /// Get local address of first server (for backwards compat)
    pub async fn get_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner
            .read()
            .await
            .servers
            .values()
            .min_by_key(|s| s.id)
            .and_then(|s| s.local_addr)
    }

    /// Execute a closure with mutable access to a server
    pub async fn with_server_mut<F, R>(&self, server_id: ServerId, f: F) -> Option<R>
    where
        F: FnOnce(&mut ServerInstance) -> R,
    {
        self.inner.write().await.servers.get_mut(&server_id).map(f)
    }

    // ===== Task Management Methods =====

    /// Add a new scheduled task
    pub async fn add_task(&self, mut task: ScheduledTask) -> TaskId {
        let mut inner = self.inner.write().await;
        let id = TaskId::new(inner.next_task_id);
        inner.next_task_id += 1;
        // Constructors accept a placeholder ID. Every later status update and
        // completion uses the ID on the stored task, so it must match the map key.
        task.id = id;

        inner.task_names.insert(task.name.clone(), id);
        inner.tasks.insert(id, task);
        id
    }

    /// Get a task by ID or name
    pub async fn get_task(&self, id_or_name: &str) -> Option<ScheduledTask> {
        let inner = self.inner.read().await;

        // Try parsing as numeric ID first
        if let Some(id) = TaskId::from_string(id_or_name) {
            return inner.tasks.get(&id).cloned();
        }

        // Try looking up by name
        if let Some(&id) = inner.task_names.get(id_or_name) {
            return inner.tasks.get(&id).cloned();
        }

        None
    }

    /// Remove a task
    pub async fn remove_task(&self, id: TaskId) -> Option<ScheduledTask> {
        let mut inner = self.inner.write().await;
        inner.remove_scheduled_task(id)
    }

    /// Start a claimed task while holding its ownership lock. Removal cannot
    /// race between spawn and registration; a previously removed claim is skipped.
    pub async fn spawn_scheduled_task<F>(&self, id: TaskId, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut inner = self.inner.write().await;
        if !inner
            .tasks
            .get(&id)
            .is_some_and(|task| task.status == crate::state::task::TaskStatus::Executing)
        {
            return false;
        }
        if inner
            .scheduled_executions
            .get(&id)
            .is_some_and(|handle| !handle.is_finished())
        {
            return false;
        }
        inner.scheduled_executions.insert(id, tokio::spawn(future));
        true
    }

    /// Get all tasks
    pub async fn get_all_tasks(&self) -> Vec<ScheduledTask> {
        self.inner.read().await.tasks.values().cloned().collect()
    }

    /// Atomically claim scheduled tasks whose deadline has arrived.
    ///
    /// A separate snapshot and status update lets concurrent timer ticks both
    /// execute the same task. Mark each task while holding the selection lock.
    pub async fn claim_due_tasks(&self) -> Vec<ScheduledTask> {
        use crate::state::task::TaskStatus;
        let mut inner = self.inner.write().await;
        let now = crate::utils::clock::Instant::now();
        let active: std::collections::HashSet<_> = inner
            .scheduled_executions
            .iter()
            .filter_map(|(id, handle)| (!handle.is_finished()).then_some(*id))
            .collect();
        inner
            .scheduled_executions
            .retain(|_, handle| !handle.is_finished());
        inner
            .tasks
            .values_mut()
            .filter_map(|task| {
                if task.status == TaskStatus::Scheduled
                    && task.next_execution <= now
                    && !active.contains(&task.id)
                {
                    task.status = TaskStatus::Executing;
                    Some(task.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get tasks for a specific server
    pub async fn get_server_tasks(&self, server_id: ServerId) -> Vec<ScheduledTask> {
        use crate::state::task::TaskScope;

        self.inner
            .read()
            .await
            .tasks
            .values()
            .filter(|task| matches!(&task.scope, TaskScope::Server(sid) if *sid == server_id))
            .cloned()
            .collect()
    }

    /// Get tasks for a specific connection
    pub async fn get_connection_tasks(
        &self,
        server_id: ServerId,
        connection_id: crate::server::connection::ConnectionId,
    ) -> Vec<ScheduledTask> {
        use crate::state::task::TaskScope;

        self.inner
            .read()
            .await
            .tasks
            .values()
            .filter(|task| {
                matches!(
                    &task.scope,
                    TaskScope::Connection(sid, cid) if *sid == server_id && *cid == connection_id
                )
            })
            .cloned()
            .collect()
    }

    /// Update task status
    pub async fn update_task_status(&self, id: TaskId, status: crate::state::task::TaskStatus) {
        if let Some(task) = self.inner.write().await.tasks.get_mut(&id) {
            task.status = status;
        }
    }

    /// Update task next execution time
    pub async fn update_task_next_execution(&self, id: TaskId, next: crate::utils::clock::Instant) {
        if let Some(task) = self.inner.write().await.tasks.get_mut(&id) {
            task.next_execution = next;
        }
    }

    /// Record task execution result
    pub async fn record_task_execution(
        &self,
        id: TaskId,
        result: &crate::state::task::TaskExecutionResult,
    ) {
        use crate::state::task::TaskType;

        let mut inner = self.inner.write().await;
        if let Some(task) = inner.tasks.get_mut(&id) {
            if result.success {
                task.failure_count = 0;
                task.last_error = None;
            } else {
                task.failure_count = task.failure_count.saturating_add(1);
                task.last_error = result.error.clone();
            }

            // Update execution count for recurring tasks
            if let TaskType::Recurring {
                ref mut executions_count,
                ..
            } = task.task_type
            {
                *executions_count = executions_count.saturating_add(1);
            }
        }
    }

    /// Clean up the scheduled tasks associated with a server.
    ///
    /// Both server-scoped tasks and the connection-scoped tasks of *that server's*
    /// connections are removed: a connection cannot outlive its server, so leaving
    /// its tasks behind leaves them firing against a server that no longer exists.
    ///
    /// Callers rarely need this — [`Self::remove_server`] and
    /// [`Self::cleanup_old_servers`] already do it. It stays public for the TUI,
    /// which marks a server `Stopped` and leaves the entry in place for the reaper.
    pub async fn cleanup_server_tasks(&self, server_id: ServerId) {
        let mut inner = self.inner.write().await;
        inner.drop_tasks_for_server(server_id);
    }

    /// Clean up tasks associated with a connection
    pub async fn cleanup_connection_tasks(
        &self,
        server_id: ServerId,
        connection_id: crate::server::connection::ConnectionId,
    ) {
        use crate::state::task::TaskScope;

        let mut inner = self.inner.write().await;

        // Collect task IDs to remove
        let task_ids_to_remove: Vec<TaskId> = inner
            .tasks
            .iter()
            .filter(|(_, task)| {
                matches!(
                    &task.scope,
                    TaskScope::Connection(sid, cid) if *sid == server_id && *cid == connection_id
                )
            })
            .map(|(&id, _)| id)
            .collect();

        // Remove tasks and their name mappings
        for id in task_ids_to_remove {
            inner.remove_scheduled_task(id);
        }
    }

    /// Clean up tasks associated with a client
    pub async fn cleanup_client_tasks(&self, client_id: ClientId) {
        use crate::state::task::TaskScope;

        let mut inner = self.inner.write().await;

        // Collect task IDs to remove
        let task_ids_to_remove: Vec<TaskId> = inner
            .tasks
            .iter()
            .filter(|(_, task)| matches!(&task.scope, TaskScope::Client(cid) if *cid == client_id))
            .map(|(&id, _)| id)
            .collect();

        // Remove tasks and their name mappings
        for id in task_ids_to_remove {
            inner.remove_scheduled_task(id);
        }
    }

    // ===== Conversation Management Methods =====

    /// Register a new conversation
    pub async fn register_conversation(
        &self,
        id: String,
        source: ConversationSource,
        details: String,
    ) {
        let info = ConversationInfo {
            id,
            source,
            details,
            start_time: crate::utils::clock::Instant::now(),
            end_time: None,
        };

        self.inner.write().await.conversations.push(info);
    }

    /// Mark a conversation as ended
    pub async fn end_conversation(&self, id: &str) {
        let mut inner = self.inner.write().await;
        if let Some(conv) = inner.conversations.iter_mut().find(|c| c.id == id) {
            conv.end_time = Some(crate::utils::clock::Instant::now());
        }
    }

    /// Get all active conversations and recently-completed ones (within 1 second)
    pub async fn get_active_conversations(&self) -> Vec<ConversationInfo> {
        let inner = self.inner.read().await;
        let now = crate::utils::clock::Instant::now();

        inner
            .conversations
            .iter()
            .filter(|conv| {
                // Include if still active (no end_time)
                conv.end_time.is_none() ||
                // Or if ended within the last 1 second
                conv.end_time.map(|end| now.duration_since(end).as_secs() < 1).unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Get conversations for the "Running" column (User + Global tasks)
    pub async fn get_input_conversations(&self) -> Vec<ConversationInfo> {
        let all_convs = self.get_active_conversations().await;
        all_convs
            .into_iter()
            .filter(|conv| {
                matches!(
                    &conv.source,
                    ConversationSource::User | ConversationSource::Scripting // Global tasks would be ConversationSource::Task but we need to filter by scope
                )
            })
            .collect()
    }

    /// Clean up old completed conversations (older than 1 second)
    pub async fn cleanup_old_conversations(&self) {
        let mut inner = self.inner.write().await;
        let now = crate::utils::clock::Instant::now();

        inner.conversations.retain(|conv| {
            // Keep if still active
            conv.end_time.is_none() ||
            // Or if ended less than 1 second ago
            conv.end_time.map(|end| now.duration_since(end).as_secs() < 1).unwrap_or(false)
        });
    }

    /// Get or create the user conversation state
    pub async fn get_or_create_user_conversation_state(
        &self,
    ) -> Arc<std::sync::Mutex<crate::llm::ConversationState>> {
        let mut inner = self.inner.write().await;

        if inner.user_conversation_state.is_none() {
            // Create with default 50k character limit for conversation history
            let mut conversation_state = crate::llm::ConversationState::new(50000);

            // Sync documented protocols from AppState to ConversationState
            // This ensures the LLM knows which protocols have been documented
            // even when conversation history has been truncated
            if !inner.documented_server_protocols.is_empty() {
                let protocols: Vec<String> =
                    inner.documented_server_protocols.iter().cloned().collect();
                conversation_state.mark_server_protocols_documented(&protocols);
            }
            if !inner.documented_client_protocols.is_empty() {
                let protocols: Vec<String> =
                    inner.documented_client_protocols.iter().cloned().collect();
                conversation_state.mark_client_protocols_documented(&protocols);
            }

            inner.user_conversation_state =
                Some(Arc::new(std::sync::Mutex::new(conversation_state)));
        } else {
            // Sync documented protocols if conversation state already exists
            // This ensures protocols documented in this session are reflected
            if let Some(ref conv_state) = inner.user_conversation_state {
                if let Ok(mut state) = conv_state.lock() {
                    // Only sync if AppState has more protocols than ConversationState
                    for protocol in &inner.documented_server_protocols {
                        if !state.documented_server_protocols.contains(protocol) {
                            state.mark_server_protocols_documented(std::slice::from_ref(protocol));
                        }
                    }
                    for protocol in &inner.documented_client_protocols {
                        if !state.documented_client_protocols.contains(protocol) {
                            state.mark_client_protocols_documented(std::slice::from_ref(protocol));
                        }
                    }
                }
            }
        }

        inner.user_conversation_state.as_ref().unwrap().clone()
    }

    /// Clear user conversation history
    pub async fn clear_user_conversation_history(&self) {
        let inner = self.inner.read().await;
        if let Some(conversation_state) = &inner.user_conversation_state {
            if let Ok(mut state) = conversation_state.lock() {
                state.clear_history();
            }
        }
    }

    /// Get formatted conversation history for prompts
    pub async fn get_user_conversation_history(&self) -> Option<String> {
        let inner = self.inner.read().await;
        if let Some(conversation_state) = &inner.user_conversation_state {
            if let Ok(state) = conversation_state.lock() {
                if !state.is_empty() {
                    return Some(state.get_history_for_prompt());
                }
            }
        }
        None
    }

    // ===== Access Log Methods =====

    /// Record a request/response access-log entry (ring buffer, oldest dropped past capacity).
    /// Returns the assigned entry id.
    pub async fn record_access_log(
        &self,
        owner: AccessLogOwner,
        protocol: &str,
        connection_id: Option<u32>,
        event_type: &str,
        request: serde_json::Value,
        response: Vec<serde_json::Value>,
    ) -> u64 {
        self.record_access_log_inner(
            owner,
            protocol,
            connection_id,
            event_type,
            request,
            response,
            true,
        )
        .await
    }

    /// [`Self::record_access_log`] without the connection's history: for a caller that logs an
    /// event's *arrival* while the event goes on to a model call that records it with its answer
    /// — recording both would show the model the same event twice.
    pub async fn record_access_log_only(
        &self,
        owner: AccessLogOwner,
        protocol: &str,
        connection_id: Option<u32>,
        event_type: &str,
        request: serde_json::Value,
        response: Vec<serde_json::Value>,
    ) -> u64 {
        self.record_access_log_inner(
            owner,
            protocol,
            connection_id,
            event_type,
            request,
            response,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_access_log_inner(
        &self,
        owner: AccessLogOwner,
        protocol: &str,
        connection_id: Option<u32>,
        event_type: &str,
        request: serde_json::Value,
        response: Vec<serde_json::Value>,
        history: bool,
    ) -> u64 {
        let unix_ms = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let (server_id, client_id) = match owner {
            AccessLogOwner::Server(id) => (Some(id), None),
            AccessLogOwner::Client(id) => (None, Some(id)),
        };

        let mut inner = self.inner.write().await;

        if history {
            // The same exchange, into the connection's history — every event the access log sees
            // is one the model may need to know happened, whoever answered it. Only for a
            // connection the server still holds: an id it has removed (or never registered) would
            // otherwise leave an entry nothing ever clears.
            match owner {
                AccessLogOwner::Server(sid) => {
                    if let (Some(conn), Some(server)) =
                        (connection_id, inner.servers.get_mut(&ServerId::new(sid)))
                    {
                        let conn = crate::server::connection::ConnectionId::new(conn);
                        let limit = server.history_entries;
                        if limit > 0 && server.connections.contains_key(&conn) {
                            server
                                .exchange_history
                                .entry(conn)
                                .or_default()
                                .record(event_type, &request, &response, limit);
                        }
                    }
                }
                AccessLogOwner::Client(cid) => {
                    if let Some(client) = inner.clients.get_mut(&ClientId::new(cid)) {
                        let limit = client.history_entries;
                        client
                            .exchange_history
                            .record(event_type, &request, &response, limit);
                    }
                }
            }
        }

        let id = inner.next_access_log_id;
        inner.next_access_log_id += 1;
        inner.access_logs.push_back(AccessLogEntry {
            id,
            unix_ms,
            server_id,
            client_id,
            protocol: protocol.to_string(),
            connection_id,
            event_type: event_type.to_string(),
            request,
            response,
        });
        while inner.access_logs.len() > ACCESS_LOG_CAPACITY {
            inner.access_logs.pop_front();
        }
        self.event_journal.publish(
            crate::events::journal::ACCESS_RECORDED,
            serde_json::json!({
                "access_log_id": id, "server_id": server_id, "client_id": client_id,
                "protocol": protocol, "connection_id": connection_id, "event_type": event_type,
            }),
        );
        id
    }

    /// The history block to show the model ahead of an event on this server connection, or
    /// `None` when history is off or nothing has happened yet. See
    /// [`crate::state::exchange_history`].
    pub async fn render_server_history(
        &self,
        server_id: ServerId,
        connection_id: Option<crate::server::connection::ConnectionId>,
    ) -> Option<String> {
        let conn = connection_id?;
        let inner = self.inner.read().await;
        let server = inner.servers.get(&server_id)?;
        server
            .exchange_history
            .get(&conn)?
            .render(server.history_entries)
    }

    /// The history block for a client's next prompt — see [`Self::render_server_history`].
    pub async fn render_client_history(&self, client_id: ClientId) -> Option<String> {
        let inner = self.inner.read().await;
        let client = inner.clients.get(&client_id)?;
        client.exchange_history.render(client.history_entries)
    }

    /// An instance's history and batching settings as `(history entries, batching)`.
    pub async fn server_conversation_settings(&self, server_id: ServerId) -> Option<(u16, bool)> {
        let inner = self.inner.read().await;
        inner
            .servers
            .get(&server_id)
            .map(|s| (s.history_entries, s.batching))
    }

    /// See [`Self::server_conversation_settings`].
    pub async fn client_conversation_settings(&self, client_id: ClientId) -> Option<(u16, bool)> {
        let inner = self.inner.read().await;
        inner
            .clients
            .get(&client_id)
            .map(|c| (c.history_entries, c.batching))
    }

    /// Change a server's history and batching settings in place (no restart). Lowering the
    /// history limit trims what every connection keeps; `0` drops it.
    pub async fn set_server_conversation_settings(
        &self,
        server_id: ServerId,
        history_entries: u16,
        batching: bool,
    ) {
        let mut inner = self.inner.write().await;
        if let Some(server) = inner.servers.get_mut(&server_id) {
            server.history_entries = history_entries;
            server.batching = batching;
            if history_entries == 0 {
                server.exchange_history.clear();
            } else {
                for history in server.exchange_history.values_mut() {
                    history.trim(history_entries);
                }
            }
        }
    }

    /// See [`Self::set_server_conversation_settings`].
    pub async fn set_client_conversation_settings(
        &self,
        client_id: ClientId,
        history_entries: u16,
        batching: bool,
    ) {
        let mut inner = self.inner.write().await;
        if let Some(client) = inner.clients.get_mut(&client_id) {
            client.history_entries = history_entries;
            client.batching = batching;
            if history_entries == 0 {
                client.exchange_history = Default::default();
            } else {
                client.exchange_history.trim(history_entries);
            }
        }
    }

    /// How many access-log entries have ever been recorded — one per network event a server
    /// or client handled (whatever answered it: handler, model or operator), plus one per
    /// injected action. Unlike the ring buffer this never shrinks, so it is a monotonic count
    /// of handled events for the life of the process (`--exit-after-events` reads it).
    pub async fn access_log_total(&self) -> u64 {
        self.inner.read().await.next_access_log_id.saturating_sub(1)
    }

    /// Return the most recent access-log entries, newest first (up to `limit`).
    /// Pass `None` for the full retained buffer.
    pub async fn list_access_logs(&self, limit: Option<usize>) -> Vec<AccessLogEntry> {
        self.list_access_logs_for(None, limit).await
    }

    /// Return the most recent access-log entries for one instance (or all,
    /// with `owner: None`), newest first (up to `limit`).
    pub async fn list_access_logs_for(
        &self,
        owner: Option<AccessLogOwner>,
        limit: Option<usize>,
    ) -> Vec<AccessLogEntry> {
        let inner = self.inner.read().await;
        let take = limit.unwrap_or(ACCESS_LOG_CAPACITY);
        inner
            .access_logs
            .iter()
            .rev()
            .filter(|entry| owner.is_none() || entry.owner() == owner)
            .take(take)
            .cloned()
            .collect()
    }

    /// Look up a single access-log entry by id.
    pub async fn get_access_log(&self, id: u64) -> Option<AccessLogEntry> {
        let inner = self.inner.read().await;
        inner.access_logs.iter().find(|e| e.id == id).cloned()
    }

    // ===== LLM Token Tracking Methods =====

    /// Record LLM call tokens
    pub async fn record_llm_tokens(&self, input_tokens: u64, output_tokens: u64) {
        let mut inner = self.inner.write().await;
        inner.total_input_tokens += input_tokens;
        inner.total_output_tokens += output_tokens;
        inner.total_llm_calls += 1;
    }

    /// Get LLM token statistics
    pub async fn get_llm_stats(&self) -> (u64, u64, u64) {
        let inner = self.inner.read().await;
        (
            inner.total_input_tokens,
            inner.total_output_tokens,
            inner.total_llm_calls,
        )
    }

    /// Reset LLM token statistics
    pub async fn reset_llm_stats(&self) {
        let mut inner = self.inner.write().await;
        inner.total_input_tokens = 0;
        inner.total_output_tokens = 0;
        inner.total_llm_calls = 0;
    }

    // ===== Database Management =====

    /// Create a new database
    #[cfg(feature = "sqlite")]
    pub async fn create_database(
        &self,
        name: String,
        path: String,
        owner: crate::state::DatabaseOwner,
        init_sql: Option<&str>,
    ) -> anyhow::Result<crate::state::DatabaseId> {
        use anyhow::Context;

        let mut inner = self.inner.write().await;
        let id = crate::state::DatabaseId::new(inner.next_unified_id);
        inner.next_unified_id += 1;

        inner
            ._database_manager
            .create_database(id, name, path, owner, init_sql)
            .context("Failed to create database")?;

        Ok(id)
    }

    /// Execute a SQL query on a database
    #[cfg(feature = "sqlite")]
    pub async fn execute_sql(
        &self,
        db_id: crate::state::DatabaseId,
        sql: &str,
    ) -> anyhow::Result<crate::state::QueryResult> {
        let mut inner = self.inner.write().await;
        inner._database_manager.execute_query(db_id, sql)
    }

    /// Get all databases
    #[cfg(feature = "sqlite")]
    pub async fn get_all_databases(&self) -> Vec<crate::state::DatabaseInstance> {
        let inner = self.inner.read().await;
        inner
            ._database_manager
            .get_all_instances()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get a database by ID
    #[cfg(feature = "sqlite")]
    pub async fn get_database(
        &self,
        db_id: crate::state::DatabaseId,
    ) -> Option<crate::state::DatabaseInstance> {
        let inner = self.inner.read().await;
        inner._database_manager.get_instance(db_id).cloned()
    }

    /// Delete a database
    #[cfg(feature = "sqlite")]
    pub async fn delete_database(&self, db_id: crate::state::DatabaseId) -> anyhow::Result<()> {
        let mut inner = self.inner.write().await;
        inner._database_manager.delete_database(db_id)
    }

    /// Get databases owned by a server
    #[cfg(feature = "sqlite")]
    pub async fn get_databases_by_server(
        &self,
        server_id: crate::state::ServerId,
    ) -> Vec<crate::state::DatabaseInstance> {
        let inner = self.inner.read().await;
        inner
            ._database_manager
            .get_databases_by_server(server_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get databases owned by a client
    #[cfg(feature = "sqlite")]
    pub async fn get_databases_by_client(
        &self,
        client_id: crate::state::ClientId,
    ) -> Vec<crate::state::DatabaseInstance> {
        let inner = self.inner.read().await;
        inner
            ._database_manager
            .get_databases_by_client(client_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Delete all databases owned by a server (called when server closes)
    #[cfg(feature = "sqlite")]
    pub async fn cleanup_databases_for_server(
        &self,
        server_id: crate::state::ServerId,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.write().await;
        inner
            ._database_manager
            .delete_databases_by_server(server_id)
    }

    /// Delete all databases owned by a client (called when client disconnects)
    #[cfg(feature = "sqlite")]
    pub async fn cleanup_databases_for_client(
        &self,
        client_id: crate::state::ClientId,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.write().await;
        inner
            ._database_manager
            .delete_databases_by_client(client_id)
    }

    /// Test-only helper to add a server with a specific ID (bypasses auto-increment)
    ///
    /// WARNING: This method is intended for testing only. In production code, use `add_server()`
    /// which properly assigns server IDs.
    pub async fn add_server_with_id(&self, server: ServerInstance) {
        let mut inner = self.inner.write().await;
        inner.servers.insert(server.id, server);

        // Set mode to Server if this is the first server
        if inner.mode == Mode::Idle {
            inner.mode = Mode::Server;
        }
    }

    /// Store Tor client instance for directory queries
    #[cfg(unix)]
    pub async fn set_tor_client(
        &self,
        client_id: ClientId,
        tor_client: Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
    ) {
        let mut inner = self.inner.write().await;
        inner.tor_clients.insert(client_id, tor_client);
    }

    /// Get Tor client instance by client ID
    #[cfg(unix)]
    pub async fn get_tor_client(
        &self,
        client_id: ClientId,
    ) -> Option<Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>> {
        let inner = self.inner.read().await;
        inner.tor_clients.get(&client_id).cloned()
    }

    /// Remove Tor client instance (called when client closes)
    #[cfg(unix)]
    pub async fn remove_tor_client(&self, client_id: ClientId) {
        let mut inner = self.inner.write().await;
        inner.tor_clients.remove(&client_id);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
