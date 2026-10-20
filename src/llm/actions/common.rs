//! Common actions available in all prompts
//!
//! This module defines actions that are available in both user input
//! and network event prompts (show_message, memory operations, etc.).

use super::{ActionDefinition, Parameter};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Flexible deserializers for numeric types that accept both numbers and strings
mod flexible_deserializers {
    use serde::{Deserialize, Deserializer};

    /// Deserialize u32 from either a number or a string
    pub fn deserialize_u32_flexible<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum U32OrString {
            Number(u32),
            String(String),
        }

        match U32OrString::deserialize(deserializer)? {
            U32OrString::Number(n) => Ok(n),
            U32OrString::String(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }

    /// Deserialize Option<u32> from either a number or a string
    pub fn deserialize_option_u32_flexible<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum U32OrString {
            Number(u32),
            String(String),
        }

        match Option::<U32OrString>::deserialize(deserializer)? {
            Some(U32OrString::Number(n)) => Ok(Some(n)),
            Some(U32OrString::String(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }

    /// Deserialize u64 from either a number or a string
    #[allow(dead_code)]
    pub fn deserialize_u64_flexible<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum U64OrString {
            Number(u64),
            String(String),
        }

        match U64OrString::deserialize(deserializer)? {
            U64OrString::Number(n) => Ok(n),
            U64OrString::String(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }

    /// Deserialize Option<u64> from either a number or a string
    pub fn deserialize_option_u64_flexible<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum U64OrString {
            Number(u64),
            String(String),
        }

        match Option::<U64OrString>::deserialize(deserializer)? {
            Some(U64OrString::Number(n)) => Ok(Some(n)),
            Some(U64OrString::String(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }

    /// Deserialize u16 from either a number or a string
    #[allow(dead_code)]
    pub fn deserialize_u16_flexible<'de, D>(deserializer: D) -> Result<u16, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum U16OrString {
            Number(u16),
            String(String),
        }

        match U16OrString::deserialize(deserializer)? {
            U16OrString::Number(n) => Ok(n),
            U16OrString::String(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }

    /// Deserialize Option<u16> from either a number or a string
    pub fn deserialize_option_u16_flexible<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum U16OrString {
            Number(u16),
            String(String),
        }

        match Option::<U16OrString>::deserialize(deserializer)? {
            Some(U16OrString::Number(n)) => Ok(Some(n)),
            Some(U16OrString::String(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Type alias for protocol groups mapping
type ProtocolGroups = std::collections::HashMap<
    &'static str,
    Vec<(String, std::sync::Arc<dyn crate::llm::actions::Server>)>,
>;

/// Task definition for attaching to a server at creation time
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerTaskDefinition {
    pub task_id: String,
    pub recurring: bool,
    #[serde(
        default,
        deserialize_with = "flexible_deserializers::deserialize_option_u64_flexible"
    )]
    pub delay_secs: Option<u64>,
    #[serde(
        default,
        deserialize_with = "flexible_deserializers::deserialize_option_u64_flexible"
    )]
    pub interval_secs: Option<u64>,
    #[serde(
        default,
        deserialize_with = "flexible_deserializers::deserialize_option_u64_flexible"
    )]
    pub max_executions: Option<u64>,
    pub instruction: String,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// Common actions available in all contexts
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommonAction {
    /// Display a message to the user
    ShowMessage { message: String },

    /// Open a new server
    OpenServer {
        // === NEW FLEXIBLE BINDING FIELDS ===
        /// MAC address (for layer 2 protocols like ARP spoofing)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac_address: Option<String>,
        /// Network interface to bind (for raw protocols like ICMP, ARP, DataLink)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
        /// Host address (hostname or IP) to bind (IPv4, IPv6, or hostname)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// Port to bind (for socket-based protocols like TCP, HTTP, DNS)
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "flexible_deserializers::deserialize_option_u16_flexible"
        )]
        port: Option<u16>,

        protocol: String,
        #[serde(default)]
        send_first: bool,
        #[serde(default)]
        initial_memory: Option<String>,
        /// Server instruction for LLM (optional - only required if not using event handlers)
        #[serde(default)]
        instruction: String,
        #[serde(default)]
        startup_params: Option<serde_json::Value>,
        // Event handler configuration
        #[serde(default)]
        event_handlers: Option<Vec<serde_json::Value>>,
        // Scheduled tasks to create with this server
        #[serde(default)]
        scheduled_tasks: Option<Vec<ServerTaskDefinition>>,
        // Feedback instructions for automatic server adjustment
        #[serde(default)]
        feedback_instructions: Option<String>,
        /// Earlier entries per connection the model is shown; 0 = off; omitted = protocol default
        #[serde(default)]
        history: Option<u16>,
        /// Batch events arriving during a call; omitted = protocol default
        #[serde(default)]
        batching: Option<bool>,
    },

    /// Close a specific server
    CloseServer {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        server_id: u32,
    },

    /// Close all servers
    CloseAllServers,

    /// Open a new client connection
    OpenClient {
        protocol: String,
        remote_addr: String,
        /// Client instruction for LLM (optional - only required if not using event handlers)
        #[serde(default)]
        instruction: String,
        #[serde(default)]
        startup_params: Option<serde_json::Value>,
        #[serde(default)]
        initial_memory: Option<String>,
        // Event handler configuration
        #[serde(default)]
        event_handlers: Option<Vec<serde_json::Value>>,
        // Scheduled tasks to create with this client
        #[serde(default)]
        scheduled_tasks: Option<Vec<ServerTaskDefinition>>,
        // Feedback instructions for automatic client adjustment
        #[serde(default)]
        feedback_instructions: Option<String>,
        /// Earlier entries on the session the model is shown; 0 = off; omitted = protocol default
        #[serde(default)]
        history: Option<u16>,
        /// Batch events arriving during a call; omitted = protocol default
        #[serde(default)]
        batching: Option<bool>,
    },

    /// Close a specific client
    CloseClient {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        client_id: u32,
    },

    /// Close all clients
    CloseAllClients,

    /// Close a specific connection by its unified ID
    CloseConnectionById {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        connection_id: u32,
    },

    /// Reconnect a disconnected client
    ReconnectClient {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        client_id: u32,
    },

    /// Update the client instruction
    UpdateClientInstruction {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        client_id: u32,
        instruction: String,
    },

    /// Update a running server in place, by id. Only the fields supplied are
    /// changed. Binding fields (port/host/interface/mac_address) or a
    /// startup_params change trigger a clean stop+start; every other field is
    /// applied without dropping connections. Fixes the "spawn a second server
    /// instead of updating" problem by making update a first-class operation.
    UpdateServer {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        server_id: u32,
        #[serde(
            default,
            deserialize_with = "flexible_deserializers::deserialize_option_u16_flexible"
        )]
        port: Option<u16>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        mac_address: Option<String>,
        #[serde(default)]
        send_first: bool,
        #[serde(default)]
        instruction: Option<String>,
        #[serde(default, alias = "memory")]
        initial_memory: Option<String>,
        #[serde(default)]
        startup_params: Option<serde_json::Value>,
        #[serde(default)]
        event_handlers: Option<Vec<serde_json::Value>>,
        #[serde(default)]
        scheduled_tasks: Option<Vec<ServerTaskDefinition>>,
        #[serde(default)]
        feedback_instructions: Option<String>,
        #[serde(default)]
        history: Option<u16>,
        #[serde(default)]
        batching: Option<bool>,
    },

    /// Update a running client in place, by id. Mirror of `update_server`: a
    /// remote_addr or startup_params change reconnects, everything else applies
    /// in place.
    UpdateClient {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_u32_flexible")]
        client_id: u32,
        #[serde(default)]
        remote_addr: Option<String>,
        #[serde(default)]
        instruction: Option<String>,
        #[serde(default, alias = "memory")]
        initial_memory: Option<String>,
        #[serde(default)]
        startup_params: Option<serde_json::Value>,
        #[serde(default)]
        event_handlers: Option<Vec<serde_json::Value>>,
        #[serde(default)]
        scheduled_tasks: Option<Vec<ServerTaskDefinition>>,
        #[serde(default)]
        feedback_instructions: Option<String>,
        #[serde(default)]
        history: Option<u16>,
        #[serde(default)]
        batching: Option<bool>,
    },

    /// Update the server instruction (combines with existing)
    UpdateInstruction { instruction: String },

    /// Change the LLM model
    ChangeModel { model: String },

    /// Replace this instance's memory completely
    SetMemory { value: String },

    /// Append to this instance's memory
    AppendMemory { value: String },

    /// Append content to a log file
    AppendToLog {
        output_name: String,
        content: String,
    },

    /// Schedule a task (one-shot or recurring)
    ScheduleTask {
        task_id: String,
        recurring: bool,
        #[serde(
            default,
            deserialize_with = "flexible_deserializers::deserialize_option_u64_flexible"
        )]
        delay_secs: Option<u64>,
        #[serde(
            default,
            deserialize_with = "flexible_deserializers::deserialize_option_u64_flexible"
        )]
        interval_secs: Option<u64>,
        #[serde(
            default,
            deserialize_with = "flexible_deserializers::deserialize_option_u64_flexible"
        )]
        max_executions: Option<u64>,
        #[serde(
            default,
            deserialize_with = "flexible_deserializers::deserialize_option_u32_flexible"
        )]
        server_id: Option<u32>,
        #[serde(default)]
        connection_id: Option<String>,
        #[serde(
            default,
            deserialize_with = "flexible_deserializers::deserialize_option_u32_flexible"
        )]
        client_id: Option<u32>,
        instruction: String,
        #[serde(default)]
        context: Option<serde_json::Value>,
        // Script configuration fields
        #[serde(default)]
        script_runtime: Option<String>,
        #[serde(default)]
        script_language: Option<String>,
        #[serde(default)]
        script_path: Option<String>,
        #[serde(default)]
        script_inline: Option<String>,
        #[serde(default)]
        script_handles: Option<Vec<String>>,
    },

    /// Cancel a scheduled task
    CancelTask { task_id: String },

    /// Provide feedback for automatic server/client adjustment
    /// This action accumulates feedback for later LLM processing (if feedback_instructions is set)
    ProvideFeedback {
        /// Feedback data (free-form JSON describing what to learn/adjust)
        feedback: serde_json::Value,
    },

    /// Create a new SQLite database (file-based or in-memory)
    #[cfg(feature = "sqlite")]
    CreateDatabase {
        name: String,
        #[serde(default)]
        is_memory: bool, // true = in-memory (:memory:), false = file-based (./netget_db_<name>.db)
        #[serde(default)]
        owner: Option<String>, // "server-N", "client-N", or "global"
        #[serde(default)]
        schema_ddl: Option<String>, // Initial DDL statements to create tables
    },

    /// Delete a database
    #[cfg(feature = "sqlite")]
    DeleteDatabase { database_id: u32 },
}

impl CommonAction {
    /// Parse from JSON value
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        // BACKWARD COMPATIBILITY: Handle old field names
        let mut value_mut = value.clone();
        if let Some(obj) = value_mut.as_object_mut() {
            // TOLERANCE: some models nest parameters under args/arguments/parameters
            // (OpenAI tool-call style) instead of placing them flat on the object.
            // Flatten them so {"type":"open_server","args":{"port":8123}} parses.
            for wrapper in ["args", "arguments", "parameters"] {
                if let Some(serde_json::Value::Object(inner)) = obj.remove(wrapper) {
                    for (k, v) in inner {
                        obj.entry(k).or_insert(v);
                    }
                }
            }
        }
        if let Some(obj) = value_mut.as_object_mut() {
            // BACKWARD COMPATIBILITY: Rename base_stack to protocol (if protocol doesn't exist)
            if matches!(
                obj.get("type").and_then(|v| v.as_str()),
                Some("open_server") | Some("open_client")
            ) {
                if let Some(base_stack) = obj.remove("base_stack") {
                    // Only set protocol if it doesn't already exist
                    if !obj.contains_key("protocol") {
                        obj.insert("protocol".to_string(), base_stack);
                    }
                }
            }

            // BACKWARD COMPATIBILITY: Convert old script_inline/script_handles format to new event_handlers format
            // Check if this is an open_server or open_client action with old script fields
            if matches!(
                obj.get("type").and_then(|v| v.as_str()),
                Some("open_server") | Some("open_client")
            ) {
                if let (Some(script_inline), Some(script_handles)) = (
                    obj.get("script_inline").and_then(|v| v.as_str()),
                    obj.get("script_handles").and_then(|v| v.as_array()),
                ) {
                    // Convert to new event_handlers format
                    let mut event_handlers = Vec::new();

                    // Create a handler for each event type in script_handles
                    for event_type in script_handles {
                        if let Some(event_type_str) = event_type.as_str() {
                            event_handlers.push(serde_json::json!({
                                "event_pattern": event_type_str,
                                "handler": {
                                    "type": "script",
                                    "language": "python",
                                    "code": script_inline
                                }
                            }));
                        }
                    }

                    // Add event_handlers field if we created any
                    if !event_handlers.is_empty() {
                        obj.insert(
                            "event_handlers".to_string(),
                            serde_json::json!(event_handlers),
                        );
                    }

                    // Remove old fields
                    obj.remove("script_inline");
                    obj.remove("script_handles");
                }
            }
        }

        serde_json::from_value(value_mut).context("Failed to parse common action")
    }
}

/// Get action definition for show_message
pub fn show_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "show_message".to_string(),
        description: "Display a message to the user controlling NetGet".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Message to display".to_string(),
            required: true,
        }],
        example: json!({
            "type": "show_message",
            "message": "Server started successfully on port 8080"
        }),
        log_template: None,
    }
}

/// Get action definition for open_server
pub fn open_server_action(
    _selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_enabled: bool,
) -> ActionDefinition {
    let name = "open_server".to_string();
    let mut description = "Start a new server.\n\n\
        PARAMETER USAGE RULES:\n\
        1. ONLY use parameters that are explicitly documented below\n\
        2. DO NOT invent new parameters, even if they seem logical\n\
        3. For custom requirements (timeouts, special behavior, etc.):\n\
           - Put them in the 'instruction' field as natural language\n\n\
        EXAMPLE - User says 'open HTTP server with 30 second timeout':\n\
        ❌ WRONG: {\"type\": \"open_server\", \"protocol\": \"http\", \"timeout\": 30}\n\
        ✅ RIGHT: {\"type\": \"open_server\", \"protocol\": \"http\", \"instruction\": \"HTTP server with 30 second timeout\"}\n\n\
        TASK SCHEDULING RULES:\n\
        FOR PERIODIC TASKS (heartbeat, every X seconds/minutes):\n\
        - Use 'scheduled_tasks' parameter with interval_secs\n\
        - DO NOT use event_handlers for time-based tasks\n\n\
        EXAMPLE - User says 'send heartbeat every 10 seconds':\n\
        ❌ WRONG: {\"event_handlers\": [{\"event_pattern\": \"*\", \"handler\": {...}}]}\n\
        ✅ RIGHT: {\"scheduled_tasks\": [{\"task_id\": \"heartbeat\", \"recurring\": true, \"interval_secs\": 10, \"instruction\": \"Send heartbeat log\"}]}\n\n\
        FOR NETWORK EVENTS (data received, connection made):\n\
        - Use 'event_handlers' parameter\n\
        - Only for responding to actual network events".to_string();

    if !is_enabled {
        description.push_str(" ⚠️ DISABLED: You must first read protocol documentation using the read_documentation tool. This tool lists all available protocols (both server and client) and provides detailed configuration information including when to use server vs client mode.");
        return ActionDefinition {
            name,
            description,
            parameters: vec![],
            example: json!({}),
            log_template: None,
        };
    }

    let mut parameters = vec![
            Parameter {
                name: "mac_address".to_string(),
                type_hint: "string".to_string(),
                description: "Optional: MAC address for Layer 2 protocols (e.g., ARP spoofing). Format: \"00:11:22:33:44:55\". Most protocols don't need this.".to_string(),
                required: false,
            },
            Parameter {
                name: "interface".to_string(),
                type_hint: "string".to_string(),
                description: "Optional: Network interface to bind (for raw protocols like ICMP, ARP, DataLink). \
                    Common interface names: \"lo\" or \"lo0\" (loopback), \"eth0\" or \"en0\" (Ethernet), \"wlan0\" (WiFi). \
                    NOTE: Only specify if the protocol specifically requires it (e.g., DataLink). Most port-based protocols (TCP, HTTP, DNS) don't use this. \
                    If you need to discover available interfaces, you can try common names like \"lo\" for loopback or use the system's default interface by omitting this parameter.".to_string(),
                required: false,
            },
            Parameter {
                name: "host".to_string(),
                type_hint: "string".to_string(),
                description: "Optional: Host address to bind (IPv4, IPv6, or hostname). Examples: \"127.0.0.1\" (loopback), \"0.0.0.0\" (all interfaces), \"::\". Protocols will use sensible defaults if omitted.".to_string(),
                required: false,
            },
            Parameter {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: "Optional: Port number to listen on. Use 0 to automatically find an available port. Required for port-based protocols (TCP, HTTP, DNS). Raw protocols (ICMP, ARP) don't use this.".to_string(),
                required: false,
            },
            Parameter {
                name: "protocol".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Protocol to use. ALWAYS prefer high-level protocols when user keywords match: \
                    if user says 'dns' or 'dns server' → use 'dns' (NOT 'udp'), \
                    if user says 'http' or 'web server' → use 'http' (NOT 'tcp'), \
                    if user says 'smtp' or 'mail server' → use 'smtp' (NOT 'tcp'). \
                    Only use low-level protocols (tcp, udp) for custom protocols without a specific high-level match. \
                    Available: {}",
                    all_base_stacks(false, None).join(", ")
                ),
                required: true,
            },
            Parameter {
                name: "send_first".to_string(),
                type_hint: "boolean".to_string(),
                description: "True if server sends data first (FTP, SMTP), false if it waits for client (HTTP)".to_string(),
                required: false,
            },
            Parameter {
                name: "initial_memory".to_string(),
                type_hint: "string".to_string(),
                description: "Optional initial memory as a string. Use for storing persistent context across connections. Example: \"user_count: 0\"".to_string(),
                required: false,
            },
            Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "Detailed instructions for handling network events. \
                    Use this field for custom requirements that don't have dedicated parameters \
                    (e.g., 'with 30 second timeout', 'log all requests to file', 'rate limit to 10 requests per second', etc.)".to_string(),
                required: true,
            },
            Parameter {
                name: "startup_params".to_string(),
                type_hint: "object".to_string(),
                description: "Optional protocol-specific startup parameters. ONLY the \
                              parameters the protocol's documentation declares are accepted: an \
                              undeclared key is refused by name and THE SERVER DOES NOT START. \
                              A protocol that declares none takes no startup_params at all. \
                              Anything the protocol does not declare - what the server should \
                              answer, which mailbox or database exists, what data to serve - \
                              belongs in 'instruction', not here."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "scheduled_tasks".to_string(),
                type_hint: "array".to_string(),
                description: "Optional: Array of TIME-BASED tasks that execute periodically or after a delay. \
                    \
                    USE WHEN: User says 'every X seconds/minutes', 'heartbeat', 'periodic', 'scheduled', or describes time-based automation. \
                    \
                    EXAMPLES: \
                    - 'send heartbeat every 10 seconds' → scheduled_tasks with interval_secs: 10 \
                    - 'check status every minute' → scheduled_tasks with interval_secs: 60 \
                    - 'cleanup after 30 seconds' → scheduled_tasks with delay_secs: 30 \
                    \
                    DO NOT use event_handlers for periodic tasks - event_handlers respond to network events, NOT time-based triggers! \
                    \
                    Each task has: task_id (string), recurring (boolean), interval_secs (for periodic) OR delay_secs (for one-shot), max_executions (optional), instruction (what to do), context (optional).".to_string(),
                required: false,
            },
        ];

    // Add event_handlers parameter with description based on handler mode
    let handler_mode_guidance = "You can configure different handlers for different events. Each handler specifies an event_pattern (specific event ID or \"*\" for all events) and a handler type (script, static, or llm). Handlers are matched in order - first match wins.";

    let available_runtimes = env.format_available();
    let event_handlers_description = format!(
        "Optional: Array of event handlers to configure how events are processed. {}\\n\\n\
Each handler has:\\n\
- event_pattern: Event ID to match (e.g., \\\"tcp_data_received\\\") or \\\"*\\\" for all events\\n\
- handler: Object with:\\n\
  - type: \\\"script\\\" (inline code), \\\"static\\\" (predefined actions), or \\\"llm\\\" (dynamic processing)\\n\\n\
REQUIRED FIELDS BY TYPE:\\n\
  - For script: language ({}), code (inline script)\\n\
  - For static: actions (array of action objects)\\n\
  - For llm: instruction (string, REQUIRED) - describes how the LLM should handle this event\\n\\n\
CRITICAL: LLM handlers MUST include 'instruction' field. Example: {{\\\"type\\\": \\\"llm\\\", \\\"instruction\\\": \\\"Handle HTTP requests...\\\"}}\\n\\n\
SCRIPT EVENT DATA STRUCTURE:\\n\
Scripts receive JSON via stdin with this structure:\\n\
{{\\n\
  \\\"event_type_id\\\": \\\"http_request\\\",  // Event type identifier\\n\
  \\\"server\\\": {{\\\"id\\\": 1, \\\"port\\\": 8080, \\\"stack\\\": \\\"HTTP\\\", \\\"memory\\\": \\\"\\\", \\\"instruction\\\": \\\"...\\\"}},\\n\
  \\\"connection\\\": {{\\\"id\\\": \\\"1\\\", \\\"remote_addr\\\": \\\"127.0.0.1:12345\\\"}},  // Optional\\n\
  \\\"event\\\": {{\\n\
    // Protocol-specific event data (fields vary by event type)\\n\
    // For HTTP: method, path, query_string, query, headers, body\\n\
    // For TCP: data (hex-encoded bytes)\\n\
    // For DNS: query_id, domain, query_type\\n\
  }}\\n\
}}\\n\\n\
IMPORTANT: Event data is directly under data['event'], NOT data['event']['data']!\\n\
Access pattern: data['event']['field_name'] (e.g., data['event']['method'])\\n\\n\
CRITICAL - COMMON MISTAKES TO AVOID:\\n\
❌ WRONG: data['event']['request']['query_string']      # NO 'request' wrapper!\\n\
❌ WRONG: data['event']['http_request']['query_string'] # NO 'http_request' wrapper!\\n\
❌ WRONG: data['event']['data']['method']               # NO 'data' wrapper!\\n\
✅ RIGHT: data['event']['query_string']                 # Direct access\\n\
✅ RIGHT: data['event']['method']                       # Direct access\\n\\n\
The event_type_id tells you WHAT event occurred, but data fields are DIRECTLY under data['event'].\\n\\n\
Example HTTP script (sum query parameters x and y):\\n\
{{\\\"event_pattern\\\": \\\"http_request\\\", \\\"handler\\\": {{\\\"type\\\": \\\"script\\\", \\\"language\\\": \\\"python\\\", \\\"code\\\": \\\"<http_sum_script>\\\"}}}}\\n\\n\
<http_sum_script>\\n\
import json\\n\
import sys\\n\
\\n\
data = json.load(sys.stdin)\\n\
# Access event data: data['event']['field_name']\\n\
query_params = data['event']['query']  # Pre-parsed query parameters object\\n\
x = float(query_params['x'])\\n\
y = float(query_params['y'])\\n\
result = x + y\\n\
\\n\
print(json.dumps({{\\n\
  'actions': [{{\\n\
    'type': 'send_http_response',\\n\
    'status': 200,\\n\
    'body': str(result)\\n\
  }}]\\n\
}}))\\n\
</http_sum_script>\\n\\n\
Example TCP script (echo received data):\\n\
{{\\\"event_pattern\\\": \\\"tcp_data_received\\\", \\\"handler\\\": {{\\\"type\\\": \\\"script\\\", \\\"language\\\": \\\"python\\\", \\\"code\\\": \\\"<tcp_echo_script>\\\"}}}}\\n\\n\
<tcp_echo_script>\\n\
import json\\n\
import sys\\n\
\\n\
data = json.load(sys.stdin)\\n\
# TCP data is hex-encoded in data['event']['data']\\n\
received_hex = data['event']['data']\\n\
\\n\
print(json.dumps({{\\n\
  'actions': [{{\\n\
    'type': 'send_tcp_data',\\n\
    'data': received_hex  # Echo back the same hex data\\n\
  }}]\\n\
}}))\\n\
</tcp_echo_script>\\n\\n\
Example static handler:\\n\
{{\\\"event_pattern\\\": \\\"*\\\", \\\"handler\\\": {{\\\"type\\\": \\\"static\\\", \\\"actions\\\": [{{\\\"type\\\": \\\"send_data\\\", \\\"data\\\": \\\"Welcome\\\"}}]}}}}\\n\\n\
Example LLM handler:\\n\
{{\\\"event_pattern\\\": \\\"http_request\\\", \\\"handler\\\": {{\\\"type\\\": \\\"llm\\\", \\\"instruction\\\": \\\"You are a recipe website\\\"}}}}",
        handler_mode_guidance,
        available_runtimes
    );

    parameters.push(Parameter {
        name: "event_handlers".to_string(),
        type_hint: "array".to_string(),
        description: event_handlers_description,
        required: false,
    });

    parameters.push(Parameter {
        name: "feedback_instructions".to_string(),
        type_hint: "string".to_string(),
        description: "Optional: Instructions for automatic server adjustment based on network request feedback. When set, network requests can provide feedback via the 'provide_feedback' action. Feedback is accumulated and debounced (leading edge), then the LLM is invoked with these instructions to decide how to adjust the server behavior (e.g., update instructions, modify handlers, change configuration). Example: \"Adjust response time if clients are timing out\" or \"Learn from failed requests and improve error handling\".".to_string(),
        required: false,
    });

    parameters.push(Parameter {
        name: "history".to_string(),
        type_hint: "number".to_string(),
        description: "Optional: how many earlier exchanges on the same connection you are shown with each new event (each event and what answered it). 0 turns it off. Omit to keep the protocol's default — conversational protocols (telnet, IRC, SMTP, databases) show 40, independent requests (DNS, HTTP) none; get_protocol_docs names the default. Memory is separate: use it for anything that must outlive the connection.".to_string(),
        required: false,
    });

    parameters.push(Parameter {
        name: "batching".to_string(),
        type_hint: "boolean".to_string(),
        description: "Optional: when events arrive on a connection while you are still answering an earlier one, hold them and give them to you together in one follow-up call. Omit to keep the protocol's default. Refused on a protocol that answers each event as it arrives.".to_string(),
        required: false,
    });

    let example = json!({
        "type": "open_server",
        "port": 21,
        "protocol": "tcp",
        "send_first": true,
        "initial_memory": "login_count: 0\nfiles: data.txt,readme.md",
        "instruction": "You are an FTP server. Respond to FTP commands like USER, PASS, LIST, RETR, QUIT with appropriate FTP response codes."
    });

    ActionDefinition {
        name,
        description,
        parameters,
        example,
        log_template: None,
    }
}

/// Get action definition for close_server
pub fn close_server_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_server".to_string(),
        description: "Stop a specific server by ID.".to_string(),
        parameters: vec![Parameter {
            name: "server_id".to_string(),
            type_hint: "number".to_string(),
            description: "Server ID to close (e.g., 1, 2).".to_string(),
            required: true,
        }],
        example: json!({
            "type": "close_server",
            "server_id": 1
        }),
        log_template: None,
    }
}

/// Get action definition for close_all_servers
pub fn close_all_servers_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_all_servers".to_string(),
        description: "Stop all running servers.".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_all_servers"
        }),
        log_template: None,
    }
}

/// Get action definition for open_client
pub fn open_client_action(
    _selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_enabled: bool,
) -> ActionDefinition {
    let name = "open_client".to_string();
    let mut description = "Connect to a remote server as a client.".to_string();

    if !is_enabled {
        description.push_str(" ⚠️ DISABLED: You must first read protocol documentation using the read_documentation tool. This tool lists all available protocols (both server and client) and provides detailed configuration information including when to use server vs client mode.");
        return ActionDefinition {
            name,
            description,
            parameters: vec![],
            example: serde_json::Value::Null,
            log_template: None,
        };
    }

    let mut parameters = vec![
        Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: "Protocol to use for connection (e.g., 'tcp', 'http', 'redis', 'ssh')".to_string(),
            required: true,
        },
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote server address as 'hostname:port' or 'IP:port' (e.g., 'example.com:80', '192.168.1.1:6379', 'localhost:8080')".to_string(),
            required: true,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "Detailed instructions for controlling the client (how to send data, interpret responses, make decisions)".to_string(),
            required: true,
        },
        Parameter {
            name: "initial_memory".to_string(),
            type_hint: "string".to_string(),
            description: "Optional initial memory as a string. Use for storing persistent context. Example: \"auth_token: abc123\\nrequest_count: 0\"".to_string(),
            required: false,
        },
        Parameter {
            name: "startup_params".to_string(),
            type_hint: "object".to_string(),
            description: "Optional protocol-specific startup parameters. ONLY the parameters \
                          the protocol's documentation declares are accepted; an undeclared key \
                          is refused by name and the client does not connect. Behavioural \
                          detail belongs in 'instruction', not here. For example, HTTP clients \
                          may accept default headers or user agent settings."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "scheduled_tasks".to_string(),
            type_hint: "array".to_string(),
            description: "Optional: Array of scheduled tasks to create with this client. Each task will be attached to the client and execute at specified intervals or delays. Tasks are automatically cleaned up when the client disconnects.".to_string(),
            required: false,
        },
    ];

    // Add event_handlers parameter
    let handler_mode_guidance = "You can configure different handlers for different client events. Each handler specifies an event_pattern (specific event ID or \"*\" for all events) and a handler type (script, static, or llm). Handlers are matched in order - first match wins.";

    let available_runtimes = env.format_available();
    let event_handlers_description = format!(
        "Optional: Array of event handlers to configure how client events are processed. {}\\n\\n\
Each handler has:\\n\
- event_pattern: Event ID to match (e.g., \\\"http_response_received\\\") or \\\"*\\\" for all events\\n\
- handler: Object with:\\n\
  - type: \\\"script\\\" (inline code), \\\"static\\\" (predefined actions), or \\\"llm\\\" (dynamic processing)\\n\
  - For script: language ({}), code (inline script)\\n\
  - For static: actions (array of action objects)\\n\
  - For llm: instruction (REQUIRED - describes how the LLM should handle this event)\\n\\n\
Note: Client scripts use the same event data structure as server scripts (see open_server documentation for details).\\n\
Access pattern: data['event']['field_name'] (e.g., data['event']['status_code'] for HTTP responses)\\n\\n\
Example script handler: {{\\\"event_pattern\\\": \\\"redis_response_received\\\", \\\"handler\\\": {{\\\"type\\\": \\\"script\\\", \\\"language\\\": \\\"python\\\", \\\"code\\\": \\\"import json,sys;data=json.load(sys.stdin);print(json.dumps({{'actions':[{{'type':'execute_redis_command','command':'PING'}}]}}))\\\"}}}}\\n\\n\
Example static handler: {{\\\"event_pattern\\\": \\\"*\\\", \\\"handler\\\": {{\\\"type\\\": \\\"static\\\", \\\"actions\\\": [{{\\\"type\\\": \\\"send_http_request\\\", \\\"method\\\": \\\"GET\\\", \\\"path\\\": \\\"/\\\"}}]}}}}\\n\\n\
Example LLM handler: {{\\\"event_pattern\\\": \\\"http_response_received\\\", \\\"handler\\\": {{\\\"type\\\": \\\"llm\\\", \\\"instruction\\\": \\\"You are a recipe website\\\"}}}}",
        handler_mode_guidance,
        available_runtimes
    );

    parameters.push(Parameter {
        name: "event_handlers".to_string(),
        type_hint: "array".to_string(),
        description: event_handlers_description,
        required: false,
    });

    parameters.push(Parameter {
        name: "feedback_instructions".to_string(),
        type_hint: "string".to_string(),
        description: "Optional: Instructions for automatic client adjustment based on server response feedback. When set, server responses can provide feedback via the 'provide_feedback' action. Feedback is accumulated and debounced (leading edge), then the LLM is invoked with these instructions to decide how to adjust the client behavior (e.g., update request strategy, modify retry logic, change authentication method). Example: \"Adjust request rate if server is throttling\" or \"Learn from error responses and modify request format\".".to_string(),
        required: false,
    });

    parameters.push(Parameter {
        name: "history".to_string(),
        type_hint: "number".to_string(),
        description: "Optional: how many earlier exchanges on this client's session you are shown with each new event (each event and what answered it). 0 turns it off. Omit to keep the protocol's default — conversational protocols (telnet, IRC, SMTP, databases) show 40, independent requests (DNS, HTTP) none; get_protocol_docs names the default. Memory is separate: use it for anything that must outlive the connection.".to_string(),
        required: false,
    });

    parameters.push(Parameter {
        name: "batching".to_string(),
        type_hint: "boolean".to_string(),
        description: "Optional: when events arrive on a connection while you are still answering an earlier one, hold them and give them to you together in one follow-up call. Omit to keep the protocol's default. Refused on a protocol that answers each event as it arrives.".to_string(),
        required: false,
    });

    let example = json!({
        "type": "open_client",
        "protocol": "http",
        "remote_addr": "example.com:80",
        "instruction": "Send a GET request to /api/status and log the response code."
    });

    ActionDefinition {
        name,
        description,
        parameters,
        example,
        log_template: None,
    }
}

/// Get action definition for close_client
pub fn close_client_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_client".to_string(),
        description: "Disconnect a specific client by ID.".to_string(),
        parameters: vec![Parameter {
            name: "client_id".to_string(),
            type_hint: "number".to_string(),
            description: "Client ID to close (e.g., 1, 2).".to_string(),
            required: true,
        }],
        example: json!({
            "type": "close_client",
            "client_id": 1
        }),
        log_template: None,
    }
}

/// Get action definition for close_all_clients
pub fn close_all_clients_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_all_clients".to_string(),
        description: "Disconnect all active clients.".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_all_clients"
        }),
        log_template: None,
    }
}

/// Get action definition for close_connection_by_id
pub fn close_connection_by_id_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection_by_id".to_string(),
        description: "Close a specific connection by its unified ID.".to_string(),
        parameters: vec![Parameter {
            name: "connection_id".to_string(),
            type_hint: "number".to_string(),
            description: "Unified ID of the connection to close (e.g., 3, 5).".to_string(),
            required: true,
        }],
        example: json!({
            "type": "close_connection_by_id",
            "connection_id": 3
        }),
        log_template: None,
    }
}

/// Get action definition for reconnect_client
pub fn reconnect_client_action() -> ActionDefinition {
    ActionDefinition {
        name: "reconnect_client".to_string(),
        description: "Reconnect a disconnected client to its remote server.".to_string(),
        parameters: vec![Parameter {
            name: "client_id".to_string(),
            type_hint: "number".to_string(),
            description: "Client ID to reconnect (e.g., 1, 2).".to_string(),
            required: true,
        }],
        example: json!({
            "type": "reconnect_client",
            "client_id": 1
        }),
        log_template: None,
    }
}

/// Get action definition for update_client_instruction
pub fn update_client_instruction_action() -> ActionDefinition {
    ActionDefinition {
        name: "update_client_instruction".to_string(),
        description:
            "Update the instruction for a specific client (replaces existing instruction)."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "client_id".to_string(),
                type_hint: "number".to_string(),
                description: "Client ID to update (e.g., 1, 2).".to_string(),
                required: true,
            },
            Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "New instruction for the client.".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "update_client_instruction",
            "client_id": 1,
            "instruction": "Switch to POST requests with JSON payload"
        }),
        log_template: None,
    }
}

/// Get action definition for update_server
pub fn update_server_action() -> ActionDefinition {
    ActionDefinition {
        name: "update_server".to_string(),
        description: "Update a RUNNING server in place, by its id, instead of opening a second \
            one. Supply only the fields you want to change. Changing the instruction, memory, \
            event_handlers, feedback_instructions, scheduled_tasks, history or batching is applied \
            WITHOUT dropping \
            connections. Changing the port, host, interface, mac_address or startup_params \
            requires a clean stop+start (connections are dropped and the server gets a new id). \
            Prefer this over open_server when a server for the protocol already exists."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "server_id".to_string(),
                type_hint: "number".to_string(),
                description: "Id of the server to update (from the running servers list)."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "New LLM instruction (hot-applied).".to_string(),
                required: false,
            },
            Parameter {
                name: "event_handlers".to_string(),
                type_hint: "array".to_string(),
                description: "Replacement deterministic event handlers (hot-applied). Same shape \
                    as open_server's."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "startup_params".to_string(),
                type_hint: "object".to_string(),
                description: "Startup parameters to merge in. Validated against the protocol \
                    schema; triggers a restart."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: "New port to bind. Triggers a restart.".to_string(),
                required: false,
            },
            Parameter {
                name: "history".to_string(),
                type_hint: "number".to_string(),
                description: "Earlier exchanges per connection shown with each event; 0 turns \
                    it off (hot-applied)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "batching".to_string(),
                type_hint: "boolean".to_string(),
                description: "Batch events arriving during a call (hot-applied; refused where \
                    the protocol cannot batch)."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "update_server",
            "server_id": 1,
            "instruction": "Return 503 for every request now."
        }),
        log_template: None,
    }
}

/// Get action definition for update_client
pub fn update_client_action() -> ActionDefinition {
    ActionDefinition {
        name: "update_client".to_string(),
        description: "Update a RUNNING client in place, by its id, instead of opening a second \
            one. Supply only the fields you want to change. Changing the instruction, memory, \
            event_handlers, feedback_instructions, scheduled_tasks, history or batching is applied \
            in place. \
            Changing the remote_addr or startup_params reconnects (new id)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "client_id".to_string(),
                type_hint: "number".to_string(),
                description: "Id of the client to update.".to_string(),
                required: true,
            },
            Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "New LLM instruction (hot-applied).".to_string(),
                required: false,
            },
            Parameter {
                name: "event_handlers".to_string(),
                type_hint: "array".to_string(),
                description: "Replacement deterministic event handlers (hot-applied).".to_string(),
                required: false,
            },
            Parameter {
                name: "remote_addr".to_string(),
                type_hint: "string".to_string(),
                description: "New remote address 'host:port'. Triggers a reconnect.".to_string(),
                required: false,
            },
            Parameter {
                name: "history".to_string(),
                type_hint: "number".to_string(),
                description: "Earlier exchanges per connection shown with each event; 0 turns \
                    it off (hot-applied)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "batching".to_string(),
                type_hint: "boolean".to_string(),
                description: "Batch events arriving during a call (hot-applied; refused where \
                    the protocol cannot batch)."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "update_client",
            "client_id": 1,
            "instruction": "Log every response you receive."
        }),
        log_template: None,
    }
}

/// Get action definition for update_instruction
pub fn update_instruction_action() -> ActionDefinition {
    ActionDefinition {
        name: "update_instruction".to_string(),
        description: "Update the current server instruction (combines with existing instruction)"
            .to_string(),
        parameters: vec![Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "New instruction to add/combine".to_string(),
            required: true,
        }],
        example: json!({
            "type": "update_instruction",
            "instruction": "For all HTTP requests, return status 404 with 'Not Found' message."
        }),
        log_template: None,
    }
}

/// Get action definition for change_model
pub fn change_model_action() -> ActionDefinition {
    ActionDefinition {
        name: "change_model".to_string(),
        description: "Switch to a different LLM model".to_string(),
        parameters: vec![Parameter {
            name: "model".to_string(),
            type_hint: "string".to_string(),
            description: "Model name (e.g., 'llama3.2:latest')".to_string(),
            required: true,
        }],
        example: json!({
            "type": "change_model",
            "model": "llama3.2:latest"
        }),
        log_template: None,
    }
}

/// Get action definition for set_memory
pub fn set_memory_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_memory".to_string(),
        description: "Replace this server's (or client's) memory with new content. Any existing memory is discarded. Memory is shared by every connection and outlives each one; the bounded history of the current connection is shown to you separately and ends with it, so keep here anything you will need later.".to_string(),
        parameters: vec![
            Parameter {
                name: "value".to_string(),
                type_hint: "string".to_string(),
                description: "New memory value as a string. Replaces all existing memory.".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "set_memory",
            "value": "session_id: abc123\nuser_preferences: dark_mode=true\nlast_command: LIST"
        }),
        log_template: None,
    }
}

/// Get action definition for append_memory
pub fn append_memory_action() -> ActionDefinition {
    ActionDefinition {
        name: "append_memory".to_string(),
        description: "Add new content to the end of this server's (or client's) memory. Existing memory is preserved and a newline is automatically added before the new content. Memory is shared by every connection and outlives each one; the history of the current connection is bounded and ends with it.".to_string(),
        parameters: vec![
            Parameter {
                name: "value".to_string(),
                type_hint: "string".to_string(),
                description: "Text to append as a string. Will be added after existing memory with newline separator.".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "append_memory",
            "value": "connection_count: 5\nlast_file_requested: readme.md"
        }),
        log_template: None,
    }
}

/// Get action definition for append_to_log
pub fn append_to_log_action() -> ActionDefinition {
    ActionDefinition {
        name: "append_to_log".to_string(),
        description: "If you are asked to log information for the user, use this to append logs to a file. Use this to create access logs, audit trails, or any persistent logging.".to_string(),
        parameters: vec![
            Parameter {
                name: "output_name".to_string(),
                type_hint: "string".to_string(),
                description: "Name of the log output (e.g., 'access_logs'). Used to construct the log filename netget_<name>_<time>.log, so it may contain only A-Z, a-z, 0-9, '_' and '-' (1-64 characters); anything else is refused.".to_string(),
                required: true,
            },
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "Content to append to the log file.".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "append_to_log",
            "output_name": "access_logs",
            "content": "127.0.0.1 - - [29/Oct/2025:12:34:56 +0000] \"GET /index.html HTTP/1.1\" 200 1234"
        }),
        log_template: None,
    }
}

/// Get action definition for provide_feedback
pub fn provide_feedback_action() -> ActionDefinition {
    ActionDefinition {
        name: "provide_feedback".to_string(),
        description: "Provide feedback for automatic server/client adjustment. Only available when feedback_instructions was set during server/client creation. Feedback is accumulated and debounced (leading edge), then periodically the LLM is invoked with the feedback_instructions to decide how to adjust the server/client behavior. Use this to signal issues, patterns, or learning opportunities that should trigger automatic adaptation.".to_string(),
        parameters: vec![
            Parameter {
                name: "feedback".to_string(),
                type_hint: "object".to_string(),
                description: "Structured feedback data describing what should be learned or adjusted. Can include any relevant context like error rates, performance metrics, client behaviors, failed requests, etc. Example: {\"issue\": \"client_timeout\", \"details\": \"Client disconnected after 5s\", \"suggestion\": \"Increase response speed\"}".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "provide_feedback",
            "feedback": {
                "issue": "authentication_failed",
                "username": "guest",
                "attempts": 3,
                "suggestion": "Consider blocking IP after multiple failures"
            }
        }),
        log_template: None,
    }
}

/// Get action definition for schedule_task
pub fn schedule_task_action(
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
) -> ActionDefinition {
    let mut parameters = vec![
        Parameter {
            name: "task_id".to_string(),
            type_hint: "string".to_string(),
            description: "Unique identifier for this task (e.g., 'cleanup_logs', 'sse_heartbeat'). Used to reference or cancel the task later.".to_string(),
            required: true,
        },
        Parameter {
            name: "recurring".to_string(),
            type_hint: "boolean".to_string(),
            description: "True for recurring task (executes at intervals), false for one-shot task (executes once after delay).".to_string(),
            required: true,
        },
        Parameter {
            name: "delay_secs".to_string(),
            type_hint: "number".to_string(),
            description: "For one-shot tasks (recurring=false): delay in seconds before executing. For recurring tasks: optional initial delay before first execution (defaults to interval_secs if not provided).".to_string(),
            required: false,
        },
        Parameter {
            name: "interval_secs".to_string(),
            type_hint: "number".to_string(),
            description: "For recurring tasks (recurring=true): interval in seconds between executions. Required when recurring=true.".to_string(),
            required: false,
        },
        Parameter {
            name: "max_executions".to_string(),
            type_hint: "number".to_string(),
            description: "For recurring tasks: maximum number of times to execute. If omitted, task runs indefinitely until cancelled.".to_string(),
            required: false,
        },
        Parameter {
            name: "server_id".to_string(),
            type_hint: "number".to_string(),
            description: "Optional: Server ID to scope this task to. If provided, task uses server's instruction and protocol actions. If omitted, task is global and uses user input actions.".to_string(),
            required: false,
        },
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: Connection ID (e.g., 'conn-123') to scope this task to a specific connection. Requires server_id to be specified. Task will be automatically cleaned up when the connection closes. Useful for connection-specific timeouts, session cleanup, or per-connection monitoring.".to_string(),
            required: false,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "number".to_string(),
            description: "Optional: Client ID to scope this task to. If provided, task uses client's instruction and protocol actions. Task will be automatically cleaned up when the client disconnects. Useful for client-specific timeouts, reconnection logic, or per-client monitoring.".to_string(),
            required: false,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "Instruction/prompt for LLM when task executes. Describes what the task should do.".to_string(),
            required: true,
        },
        Parameter {
            name: "context".to_string(),
            type_hint: "object".to_string(),
            description: "Optional: Additional context data to pass to LLM when task executes (e.g., thresholds, parameters).".to_string(),
            required: false,
        },
    ];

    // Add script parameters based on scripting mode
    match selected_mode {
        crate::state::app_state::ScriptingMode::On => {
            // ON mode: LLM chooses runtime from available options
            let available_runtimes = env.format_available();
            parameters.extend(vec![
                Parameter {
                    name: "script_runtime".to_string(),
                    type_hint: "string".to_string(),
                    description: format!(
                        "Required when script_inline is provided: Choose runtime for script execution. Available: {}",
                        available_runtimes
                    ),
                    required: false,
                },
                Parameter {
                    name: "script_inline".to_string(),
                    type_hint: "string".to_string(),
                    description: "Optional: Inline script code to handle task execution instead of LLM. Must match the script_runtime language. If provided, script_runtime MUST also be specified.".to_string(),
                    required: false,
                },
                Parameter {
                    name: "script_handles".to_string(),
                    type_hint: "array".to_string(),
                    description: "Optional: Event types the script handles (e.g., [\"scheduled_task_cleanup\"]). Defaults to [\"all\"].".to_string(),
                    required: false,
                },
            ]);
        }
        crate::state::app_state::ScriptingMode::Off => {
            // OFF mode: no script parameters
        }
        crate::state::app_state::ScriptingMode::Python
        | crate::state::app_state::ScriptingMode::JavaScript
        | crate::state::app_state::ScriptingMode::Go
        | crate::state::app_state::ScriptingMode::Perl => {
            let lang = selected_mode.as_str();
            parameters.extend(vec![
                Parameter {
                    name: "script_inline".to_string(),
                    type_hint: "string".to_string(),
                    description: format!(
                        "Optional: Inline {} script code to handle task execution instead of LLM. If provided, the script will be executed for each task trigger.",
                        lang
                    ),
                    required: false,
                },
                Parameter {
                    name: "script_handles".to_string(),
                    type_hint: "array".to_string(),
                    description: "Optional: Event types the script handles (e.g., [\"scheduled_task_cleanup\"]). Defaults to [\"all\"].".to_string(),
                    required: false,
                },
            ]);
        }
    }

    ActionDefinition {
        name: "schedule_task".to_string(),
        description: "Schedule a task (one-shot or recurring). The task will call the LLM or execute a script with the provided instruction. One-shot tasks execute once after a delay and are automatically removed. Recurring tasks execute at intervals until cancelled or max_executions is reached. Useful for delayed operations, timeouts, periodic health checks, heartbeats, SSE messages, metrics collection, etc.".to_string(),
        parameters,
        example: json!({
            "type": "schedule_task",
            "task_id": "sse_heartbeat",
            "recurring": true,
            "interval_secs": 30,
            "server_id": 1,
            "instruction": "Send SSE heartbeat to all active connections"
        }),
        log_template: None,
    }
}

/// Get action definition for cancel_task
pub fn cancel_task_action() -> ActionDefinition {
    ActionDefinition {
        name: "cancel_task".to_string(),
        description: "Cancel a scheduled task by its task_id. Works for both one-shot and recurring tasks. The task is immediately removed and will not execute again.".to_string(),
        parameters: vec![Parameter {
            name: "task_id".to_string(),
            type_hint: "string".to_string(),
            description: "ID of the task to cancel (the task_id used when scheduling).".to_string(),
            required: true,
        }],
        example: json!({
            "type": "cancel_task",
            "task_id": "cleanup_logs"
        }),
        log_template: None,
    }
}

/// Get action definition for create_database
#[cfg(feature = "sqlite")]
pub fn create_database_action() -> ActionDefinition {
    ActionDefinition {
        name: "create_database".to_string(),
        description: "Create a new SQLite database (in-memory or file-based). Use this to store protocol state (e.g., NFS file system, DNS cache, user sessions). The database persists for the lifetime of the owning server/client, or forever if global. You can execute DDL to create tables during creation.".to_string(),
        parameters: vec![
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description: "Database name (user-friendly identifier). This will be used to construct the filename as './netget_db_<name>.db' for file-based databases.".to_string(),
                required: true,
            },
            Parameter {
                name: "is_memory".to_string(),
                type_hint: "boolean".to_string(),
                description: "true = in-memory database (fast, data lost on close), false = file-based database (persistent, saved to ./netget_db_<name>.db). Defaults to false (file-based).".to_string(),
                required: false,
            },
            Parameter {
                name: "owner".to_string(),
                type_hint: "string".to_string(),
                description: "Owner scope: 'server-N' (auto-deleted when server closes), 'client-N' (auto-deleted when client disconnects), or 'global' (persists across servers/clients). Omit to default to current context.".to_string(),
                required: false,
            },
            Parameter {
                name: "schema_ddl".to_string(),
                type_hint: "string".to_string(),
                description: "SQL DDL statements to create initial schema (e.g., 'CREATE TABLE files (path TEXT PRIMARY KEY, content BLOB);'). Use semicolons to separate multiple statements.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "create_database",
            "name": "nfs_storage",
            "is_memory": true,
            "owner": "server-1",
            "schema_ddl": "CREATE TABLE files (path TEXT PRIMARY KEY, content BLOB, size INTEGER, modified INTEGER);"
        }),
        log_template: None,
    }
}

/// Get action definition for delete_database
#[cfg(feature = "sqlite")]
pub fn delete_database_action() -> ActionDefinition {
    ActionDefinition {
        name: "delete_database".to_string(),
        description: "Delete a database and remove its file (if file-based). This is permanent and cannot be undone. Server/client-owned databases are automatically deleted when the owner closes.".to_string(),
        parameters: vec![
            Parameter {
                name: "database_id".to_string(),
                type_hint: "number".to_string(),
                description: "Database ID to delete".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "delete_database",
            "database_id": 1
        }),
        log_template: None,
    }
}

/// Get all common action definitions
///
/// Actions are organized logically:
/// 1. Server Management - Create/destroy servers
/// 2. Client Management - Create/destroy/control clients
/// 3. Server Configuration - Configure running servers
/// 4. Task Management - Schedule/cancel tasks
/// 5. Database Management - Create/query/manage SQLite databases
/// 6. System/Utility - Model changes, messages, logging
pub fn get_all_common_actions(
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_open_server_enabled: bool,
    is_open_client_enabled: bool,
) -> Vec<ActionDefinition> {
    #[allow(unused_mut)]
    let mut actions = vec![];

    // === Server Management ===
    // Only include open_server when enabled (after docs are read)
    if is_open_server_enabled {
        actions.push(open_server_action(selected_mode, env, true));
    }
    actions.push(close_server_action());
    actions.push(close_all_servers_action());

    // === Client Management ===
    // Only include open_client when enabled (after docs are read)
    if is_open_client_enabled {
        actions.push(open_client_action(selected_mode, env, true));
    }
    actions.push(close_client_action());
    actions.push(close_all_clients_action());

    // === Connection Management ===
    actions.push(close_connection_by_id_action());

    // === Client Configuration ===
    actions.push(reconnect_client_action());
    actions.push(update_client_instruction_action());
    actions.push(update_client_action());

    // === Server Configuration ===
    actions.push(update_server_action());
    actions.push(update_instruction_action());
    actions.push(set_memory_action());
    actions.push(append_memory_action());

    // === Task Management ===
    actions.push(schedule_task_action(selected_mode, env));
    actions.push(cancel_task_action());

    // === System/Utility ===
    // actions.push(change_model_action());
    actions.push(show_message_action());
    actions.push(append_to_log_action());

    // === Database Management ===
    #[cfg(feature = "sqlite")]
    {
        actions.push(create_database_action());
        actions.push(delete_database_action());
    }

    actions
}

/// Get common actions for user input (all common actions with enhanced open_server and open_client)
pub fn get_user_input_common_actions(
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_open_server_enabled: bool,
    is_open_client_enabled: bool,
) -> Vec<ActionDefinition> {
    get_all_common_actions(
        selected_mode,
        env,
        is_open_server_enabled,
        is_open_client_enabled,
    )
}

/// Get common actions for network events (exclude server management actions)
///
/// Network events only get server configuration and utility actions,
/// not server management (can't create/destroy servers from event handlers).
pub fn get_network_event_common_actions() -> Vec<ActionDefinition> {
    vec![
        // === Server Configuration ===
        set_memory_action(),
        append_memory_action(),
        // === System/Utility ===
        show_message_action(),
        append_to_log_action(),
        // === Feedback/Learning ===
        // Note: provide_feedback is added conditionally in action_helper.rs
        // only when feedback_instructions is set on the server/client
    ]
}

/// Get all protocol names that should be available to the LLM
/// Filters out protocols with ProtocolState::Disabled unless include_disabled is true
/// Dynamically determined from the ProtocolRegistry based on compiled features
fn all_base_stacks(
    include_disabled: bool,
    min_stability: Option<crate::protocol::metadata::DevelopmentState>,
) -> Vec<String> {
    let registry = crate::protocol::server_registry::registry();

    // Get all registered protocols from the registry (only includes compiled features)
    let mut protocols: Vec<String> = registry
        .all_protocols()
        .into_iter()
        .map(|(protocol_name, _protocol)| protocol_name)
        .filter(|protocol_name| {
            let meta = registry.metadata(protocol_name);
            // Availability to the model: Incomplete is hidden unless
            // --include-disabled-protocols overrides it.
            let available = include_disabled
                || meta
                    .as_ref()
                    .map(|m| m.is_available_to_llm())
                    .unwrap_or(true);
            // Operator floor: never offer a protocol below --min-stability, even
            // when include_disabled is set. Unknown metadata is not hidden.
            let meets_min = match (min_stability, meta.as_ref()) {
                (Some(min), Some(m)) => m.state >= min,
                _ => true,
            };
            available && meets_min
        })
        .collect();

    // Sort protocols alphabetically for deterministic output
    protocols.sort();
    protocols
}

/// Generate comprehensive base stack documentation with startup parameters
/// Returns formatted text listing all available stacks and their configuration options
pub fn generate_base_stack_documentation(
    include_disabled: bool,
    min_stability: Option<crate::protocol::metadata::DevelopmentState>,
) -> String {
    let mut doc = String::from("## Available Base Stacks\n\n");

    // Group protocols by their group_name
    let registry = crate::protocol::server_registry::registry();
    let mut groups: ProtocolGroups = std::collections::HashMap::new();

    for protocol_name in all_base_stacks(include_disabled, min_stability) {
        if let Some(protocol) = registry.get(&protocol_name) {
            let group = protocol.group_name();
            groups
                .entry(group)
                .or_default()
                .push((protocol_name.clone(), protocol));
        }
    }

    // Sort groups alphabetically
    let mut sorted_group_names: Vec<&'static str> = groups.keys().copied().collect();
    sorted_group_names.sort();

    for group_name in sorted_group_names {
        if let Some(protocols) = groups.get_mut(group_name) {
            if protocols.is_empty() {
                continue;
            }

            // Output group header
            doc.push_str(&format!("### {}\n", group_name));

            // Sort protocols alphabetically within group
            protocols.sort_by(|a, b| a.0.cmp(&b.0));

            // Output each protocol with keywords on one line
            for (protocol_name, protocol) in protocols {
                let keywords = protocol.keywords();
                if !keywords.is_empty() {
                    doc.push_str(&format!("{} ({})\n", protocol_name, keywords.join(", ")));
                } else {
                    doc.push_str(&format!("{}\n", protocol_name));
                }
            }
            doc.push('\n');
        }
    }

    doc
}
