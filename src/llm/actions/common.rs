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

    /// Deserialize a connection id from `3`, `"3"` or `"conn-3"`.
    ///
    /// Everything else in NetGet names a connection `conn-N` (events, scripts, the Current
    /// State section of the prompt, `schedule_task`'s `connection_id`), so the model will
    /// copy that form; refusing it here made `close_connection_by_id` fail on exactly the id
    /// it had just been shown.
    pub fn deserialize_connection_id_flexible<'de, D>(deserializer: D) -> Result<u32, D::Error>
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
            U32OrString::String(s) => crate::server::connection::ConnectionId::from_string(&s)
                .map(|id| id.as_u32())
                .ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "invalid connection id '{s}': expected 'conn-N' or N"
                    ))
                }),
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

    /// Close one live connection on a running server, by its id (`conn-N` or `N`)
    CloseConnectionById {
        #[serde(deserialize_with = "flexible_deserializers::deserialize_connection_id_flexible")]
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

    /// Replace the whole instruction of the instance in context (the old one is discarded).
    ///
    /// Not offered to the operator prompt, where no instance is in context and the handler
    /// can only fall back to the first server; `update_server` / `update_client` name theirs.
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
        // Accepted only so that a reply carrying them can be refused by name: a scheduled
        // task always calls the model with its instruction and runs no script.
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

/// Whether a definition is being built for a server or a client: the two share the
/// `event_handlers` shape but not the script input or the examples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerSide {
    Server,
    Client,
}

/// The `event_handlers` parameter description of `open_server` / `open_client`.
///
/// `script_languages` is the rendered list of languages a script handler may name, or
/// `None` when scripting is off — in which case nothing about scripts is said at all, so the
/// model is not offered a handler type the operator has switched off.
pub fn event_handlers_description(side: HandlerSide, script_languages: Option<&str>) -> String {
    let mut d = String::from(
        "Optional: rules deciding who answers each event, so that predictable events need no \
         model call. Each rule is {\"event_pattern\": \"<event id>\" or \"*\", \"handler\": {...}}. \
         Event ids come from read_documentation. Rules are checked in order and the first match \
         answers; an event no rule matches is answered by the model using 'instruction'.\n\
         \n\
         Handler types:\n\
         - {\"type\": \"static\", \"actions\": [...]}: fixed actions, no model call. A string may \
         contain {{event.<field>}}, replaced by that field of the triggering event; a string that \
         is only the reference keeps the field's JSON type (\"query_id\": \"{{event.query_id}}\" \
         stays a number).\n",
    );
    if let Some(languages) = script_languages {
        d.push_str(&format!(
            "- {{\"type\": \"script\", \"language\": \"<language>\", \"code\": \"...\"}}: runs code \
             for each event, no model call. language is one of: {languages}.\n"
        ));
    }
    d.push_str(
        "- {\"type\": \"llm\", \"instruction\": \"<how to handle this event>\"}: the model \
         answers, with this instruction added to the instance's own. 'instruction' is \
         required.\n\
         - {\"type\": \"manual\", \"timeout_secs\": 300}: the event waits for a person to answer \
         it at the NetGet dashboard; unanswered after timeout_secs (default 300) it fails closed.\n",
    );

    match side {
        HandlerSide::Server => {
            if script_languages.is_some() {
                d.push_str(
                    r#"
A script reads one JSON object on stdin and prints {"actions": [...]}:
{
  "event_type_id": "tcp_data_received",
  "server": {"id": 1, "port": 8080, "stack": "ETH>IP>TCP", "memory": "", "instruction": "..."},
  "connection": {"id": "conn-3", "remote_addr": "127.0.0.1:54321", "bytes_sent": 0, "bytes_received": 0},
  "event": {"data": "hello\r\n", "encoding": "utf8"}
}
The event's fields sit directly under data["event"]: data["event"]["path"], never data["event"]["request"]["path"] or data["event"]["data"]["path"]. "connection" is absent for events that belong to no connection.

Example script (TCP echo: send back exactly what arrived, in the encoding it arrived in):
{"event_pattern": "tcp_data_received", "handler": {"type": "script", "language": "python", "code": "<tcp_echo>"}}

<tcp_echo>
import json, sys
data = json.load(sys.stdin)
event = data["event"]
print(json.dumps({"actions": [{"type": "send_tcp_data", "data": event["data"], "encoding": event.get("encoding", "utf8")}]}))
</tcp_echo>
"#,
                );
            }
            d.push_str(
                r#"
Example static handler (a TCP greeting; tcp_connection_opened is raised only when the server is opened with send_first: true):
{"event_pattern": "tcp_connection_opened", "handler": {"type": "static", "actions": [{"type": "send_tcp_data", "data": "Welcome\r\n"}]}}

Example LLM handler:
{"event_pattern": "http_request", "handler": {"type": "llm", "instruction": "You are a recipe website; answer every page in HTML"}}"#,
            );
        }
        HandlerSide::Client => {
            if script_languages.is_some() {
                d.push_str(
                    r#"
A client script gets the same input as a server script except that "client" replaces "server" and there is no "connection":
{"event_type_id": "redis_connected", "client": {"id": 1, "remote_addr": "127.0.0.1:6379", "protocol": "redis", "memory": "", "instruction": "..."}, "event": {...}}

Example script (once, on connect):
{"event_pattern": "redis_connected", "handler": {"type": "script", "language": "python", "code": "<on_connect>"}}

<on_connect>
import json, sys
print(json.dumps({"actions": [{"type": "execute_redis_command", "command": "PING"}]}))
</on_connect>
"#,
                );
            }
            d.push_str(
                r#"
Example static handler (one request when the client connects):
{"event_pattern": "http_connected", "handler": {"type": "static", "actions": [{"type": "send_http_request", "method": "GET", "path": "/"}]}}

Key a handler that sends something to the connect event, not to "*" or to the response event: a request sent in answer to every response provokes another response, and the client loops.

Example LLM handler:
{"event_pattern": "http_response_received", "handler": {"type": "llm", "instruction": "Log the status code; if it is not 200, retry once"}}"#,
            );
        }
    }
    d
}

/// The `history` parameter description shared by `open_server` and `open_client`.
fn history_description(scope: &str) -> String {
    format!(
        "Optional: how many earlier exchanges on {scope} you are shown with each new event (each \
         event and what answered it). 0 turns it off. Omit to keep the protocol's default: \
         conversational protocols (telnet, IRC, SMTP, databases) show 40, independent requests \
         (DNS, HTTP) none; read_documentation names each protocol's default. Memory is separate: \
         use it for anything that must outlive the connection."
    )
}

const BATCHING_DESCRIPTION: &str = "Optional: when events arrive on a connection while you are \
    still answering an earlier one, hold them and give them to you together in one follow-up \
    call. Omit to keep the protocol's default. Refused on a protocol that answers each event as \
    it arrives.";

/// The `scheduled_tasks` parameter description shared by every action that takes one.
fn scheduled_tasks_description(owner: &str) -> String {
    format!(
        "Optional: time-based tasks attached to this {owner}, removed with it. Use them for \
         anything said in time ('every 10 seconds', 'heartbeat', 'after 30 seconds'), never \
         event_handlers, which answer network events. Each task: task_id (string), recurring \
         (boolean), interval_secs (recurring) or delay_secs (one-shot), max_executions \
         (optional), instruction (what the model should do when it fires), context (optional \
         object). Example: [{{\"task_id\": \"heartbeat\", \"recurring\": true, \"interval_secs\": \
         10, \"instruction\": \"Send a heartbeat to every connected client\"}}]"
    )
}

/// The list of script languages a handler may name, for the prompt, or `None` when the
/// operator has scripting off or no language it allows is installed (a script handler
/// could then only fall back to the model).
pub fn script_languages_for_prompt(
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
) -> Option<String> {
    use crate::scripting::ScriptLanguage;
    use crate::state::app_state::ScriptingMode;
    let only = match selected_mode {
        ScriptingMode::Off => return None,
        ScriptingMode::On => None,
        ScriptingMode::Python => Some(ScriptLanguage::Python),
        ScriptingMode::JavaScript => Some(ScriptLanguage::JavaScript),
        ScriptingMode::Go => Some(ScriptLanguage::Go),
        ScriptingMode::Perl => Some(ScriptLanguage::Perl),
    };
    let installed = [
        ScriptLanguage::Python,
        ScriptLanguage::JavaScript,
        ScriptLanguage::Go,
        ScriptLanguage::Perl,
    ]
    .into_iter()
    .any(|lang| only.is_none_or(|o| o == lang) && env.is_available(lang));
    installed.then(|| crate::llm::event_handler_executor::describe_script_languages(env, only))
}

/// The `protocol` parameter description of `open_server`, listing the protocols the
/// operator allows: `include_disabled` and `min_stability` are the
/// `--include-disabled-protocols` / `--min-stability` settings. Startup refuses a protocol
/// below the floor, so the list must not offer one.
pub fn open_server_protocol_description(
    include_disabled: bool,
    min_stability: Option<crate::protocol::metadata::DevelopmentState>,
) -> String {
    format!(
        "Protocol to serve. Prefer the specific protocol the user names: 'dns' (not 'udp'), \
         'http' or 'web server' (not 'tcp'), 'smtp' or 'mail server' (not 'tcp'). Use 'tcp' or \
         'udp' only for a custom protocol with no match. Available: {}",
        all_base_stacks(include_disabled, min_stability).join(", ")
    )
}

/// Narrow the protocol lists in `open_server` and `read_documentation` to what the operator
/// allows (see [`open_server_protocol_description`]). The definitions are built without
/// access to the settings, so every prompt that offers them applies this before rendering.
pub fn restrict_protocol_lists(
    actions: &mut [ActionDefinition],
    include_disabled: bool,
    min_stability: Option<crate::protocol::metadata::DevelopmentState>,
) {
    for action in actions.iter_mut() {
        match action.name.as_str() {
            "open_server" => {
                if let Some(p) = action.parameters.iter_mut().find(|p| p.name == "protocol") {
                    p.description =
                        open_server_protocol_description(include_disabled, min_stability);
                }
            }
            "read_documentation" => {
                *action =
                    super::tools::read_documentation_action_for(include_disabled, min_stability);
            }
            _ => {}
        }
    }
}

/// Get action definition for open_server
pub fn open_server_action(
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_enabled: bool,
) -> ActionDefinition {
    let name = "open_server".to_string();
    let mut description = r#"Start a new server.

Use only the parameters listed below; an unknown parameter is an error. A requirement with no parameter of its own (a timeout, a rate limit, what to serve) goes in 'instruction' as plain language:
WRONG: {"type": "open_server", "protocol": "http", "timeout": 30}
RIGHT: {"type": "open_server", "protocol": "http", "instruction": "HTTP server with a 30 second timeout"}

Anything said in time ('every 10 seconds', 'heartbeat') goes in 'scheduled_tasks'; 'event_handlers' only answer network events."#
        .to_string();

    if !is_enabled {
        description.push_str(
            "\n\nNOT AVAILABLE YET: call the read_documentation tool for the protocol first; \
             open_server is offered once you have read it.",
        );
        return ActionDefinition {
            name,
            description,
            parameters: vec![],
            example: json!({}),
            log_template: None,
        };
    }

    let script_languages = script_languages_for_prompt(selected_mode, env);
    let parameters = vec![
        Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: open_server_protocol_description(false, None),
            required: true,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "Required unless event_handlers answer every event. How the model \
                should answer this server's events, in plain language, including any \
                requirement with no parameter of its own ('30 second timeout', 'log every \
                request')."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Optional: port to listen on. Omit it to use the protocol's \
                well-known port (53 for dns, 6379 for redis); if that port needs privileges \
                this process lacks, or is already in use, the server starts on an \
                OS-assigned port instead and says so. 0 asks for an OS-assigned port. A port \
                you give is used as given. Protocols that bind no port (link-layer, raw, \
                pipes) ignore it."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: address to bind. Omitted, the server listens on \
                127.0.0.1 (this machine only); \"0.0.0.0\" or \"::\" exposes it to other \
                machines, so use them only when the user asks for that."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: network interface for link-layer and raw protocols (arp, \
                datalink, icmp), e.g. \"lo0\"/\"lo\" (loopback), \"en0\"/\"eth0\". Socket \
                protocols ignore it; omit it unless the protocol's documentation asks for it."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "mac_address".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: source MAC address for layer-2 protocols, \
                \"00:11:22:33:44:55\". Only meaningful with 'interface'."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "send_first".to_string(),
            type_hint: "boolean".to_string(),
            description: "Optional: the server speaks first on each new connection (a banner \
                or prompt). Honoured only by protocols whose documentation declares it, such \
                as tcp; protocols like ftp and smtp already greet by themselves."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "initial_memory".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: the server's memory to start with, shown to the model with \
                every event and kept across connections. Example: \"user_count: 0\""
                .to_string(),
            required: false,
        },
        Parameter {
            name: "startup_params".to_string(),
            type_hint: "object".to_string(),
            description: "Optional protocol-specific startup parameters. ONLY the parameters \
                the protocol's documentation (read_documentation) declares are accepted: an \
                undeclared key is refused by name and THE SERVER DOES NOT START. A protocol \
                that declares none takes no startup_params at all. Anything the protocol does \
                not declare - what the server should answer, which mailbox or database exists, \
                what data to serve - belongs in 'instruction', not here."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "event_handlers".to_string(),
            type_hint: "array".to_string(),
            description: event_handlers_description(
                HandlerSide::Server,
                script_languages.as_deref(),
            ),
            required: false,
        },
        Parameter {
            name: "scheduled_tasks".to_string(),
            type_hint: "array".to_string(),
            description: scheduled_tasks_description("server"),
            required: false,
        },
        Parameter {
            name: "feedback_instructions".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: instructions for adjusting this server automatically. \
                When set, the model answering its events may call 'provide_feedback'; the \
                feedback is collected and the model is later asked, with these instructions, \
                how to change the server (instruction, handlers, configuration). Example: \
                \"Learn from failed requests and improve error handling\"."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "history".to_string(),
            type_hint: "number".to_string(),
            description: history_description("the same connection"),
            required: false,
        },
        Parameter {
            name: "batching".to_string(),
            type_hint: "boolean".to_string(),
            description: BATCHING_DESCRIPTION.to_string(),
            required: false,
        },
    ];

    let example = json!({
        "type": "open_server",
        "protocol": "ftp",
        "instruction": "FTP server with one user, alice / secret, whose home directory holds readme.txt containing 'hello'."
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
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_enabled: bool,
) -> ActionDefinition {
    let name = "open_client".to_string();
    let mut description =
        "Connect to a remote server as a client: NetGet opens the connection and the model (or \
         the event handlers) decides what to send and how to read each answer."
            .to_string();

    if !is_enabled {
        description.push_str(
            "\n\nNOT AVAILABLE YET: call the read_documentation tool for the protocol first; \
             open_client is offered once you have read it.",
        );
        return ActionDefinition {
            name,
            description,
            parameters: vec![],
            example: serde_json::Value::Null,
            log_template: None,
        };
    }

    let script_languages = script_languages_for_prompt(selected_mode, env);
    let parameters = vec![
        Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: "Client protocol (e.g. 'tcp', 'http', 'redis', 'ssh'); \
                read_documentation lists every client protocol."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address to connect to, 'host:port' (e.g. 'example.com:80', \
                '192.168.1.1:6379', 'localhost:8080')."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "Required unless event_handlers answer every event. What the client \
                should do: what to send, how to read the answers, when to stop."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "initial_memory".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: the client's memory to start with, shown to the model with \
                every event. Example: \"auth_token: abc123\\nrequest_count: 0\""
                .to_string(),
            required: false,
        },
        Parameter {
            name: "startup_params".to_string(),
            type_hint: "object".to_string(),
            description: "Optional protocol-specific startup parameters. ONLY the parameters \
                the protocol's documentation declares are accepted; an undeclared key is \
                refused by name and the client does not connect. Behavioural detail belongs \
                in 'instruction', not here."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "event_handlers".to_string(),
            type_hint: "array".to_string(),
            description: event_handlers_description(
                HandlerSide::Client,
                script_languages.as_deref(),
            ),
            required: false,
        },
        Parameter {
            name: "scheduled_tasks".to_string(),
            type_hint: "array".to_string(),
            description: scheduled_tasks_description("client"),
            required: false,
        },
        Parameter {
            name: "feedback_instructions".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: instructions for adjusting this client automatically. \
                When set, the model answering its events may call 'provide_feedback'; the \
                feedback is collected and the model is later asked, with these instructions, \
                how to change the client. Example: \"Slow down if the server throttles\"."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "history".to_string(),
            type_hint: "number".to_string(),
            description: history_description("this client's session"),
            required: false,
        },
        Parameter {
            name: "batching".to_string(),
            type_hint: "boolean".to_string(),
            description: BATCHING_DESCRIPTION.to_string(),
            required: false,
        },
    ];

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
        description: "Close one live connection on a running server. Connection ids are \
            listed under each server in Current State."
            .to_string(),
        parameters: vec![Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Id of the connection to close, as listed: \"conn-3\" (a bare 3 is \
                accepted too)."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "close_connection_by_id",
            "connection_id": "conn-3"
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
        description: "Change a RUNNING server, by its id, instead of opening a second one. \
            Supply only the fields you want to change; each one you supply REPLACES the \
            current value (scheduled_tasks are added). Changing the instruction, memory, \
            event_handlers, feedback_instructions, scheduled_tasks, history or batching is \
            applied WITHOUT dropping connections. Changing the port, host, interface, \
            mac_address or startup_params restarts the server: its connections \
            are dropped and it gets a new id. Use this whenever the user wants to change a \
            server that exists."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "server_id".to_string(),
                type_hint: "number".to_string(),
                description: "Id of the server to change (Current State lists them).".to_string(),
                required: true,
            },
            Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "New instruction; replaces the whole current one, so restate \
                    anything that should still hold."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "memory".to_string(),
                type_hint: "string".to_string(),
                description: "New memory; replaces the current memory.".to_string(),
                required: false,
            },
            Parameter {
                name: "event_handlers".to_string(),
                type_hint: "array".to_string(),
                description: "Replacement event handlers, same shape as open_server's; they \
                    replace every current rule."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "scheduled_tasks".to_string(),
                type_hint: "array".to_string(),
                description: "Tasks to add to the server, same shape as open_server's.".to_string(),
                required: false,
            },
            Parameter {
                name: "feedback_instructions".to_string(),
                type_hint: "string".to_string(),
                description: "New feedback instructions (see open_server).".to_string(),
                required: false,
            },
            Parameter {
                name: "history".to_string(),
                type_hint: "number".to_string(),
                description: "Earlier exchanges per connection shown with each event; 0 \
                    turns it off."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "batching".to_string(),
                type_hint: "boolean".to_string(),
                description: "Batch events arriving during a call (refused where the \
                    protocol cannot batch)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: "New port. Restarts the server.".to_string(),
                required: false,
            },
            Parameter {
                name: "host".to_string(),
                type_hint: "string".to_string(),
                description: "New bind address. Restarts the server.".to_string(),
                required: false,
            },
            Parameter {
                name: "interface".to_string(),
                type_hint: "string".to_string(),
                description: "New network interface (link-layer and raw protocols). Restarts \
                    the server."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "mac_address".to_string(),
                type_hint: "string".to_string(),
                description: "New source MAC address (layer-2 protocols). Restarts the server."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "startup_params".to_string(),
                type_hint: "object".to_string(),
                description: "Startup parameters to merge in, validated against the \
                    protocol's declared ones. Restarts the server."
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
        description: "Change a RUNNING client, by its id, instead of opening a second one. \
            Supply only the fields you want to change; each one you supply REPLACES the \
            current value (scheduled_tasks are added). Changing the instruction, memory, \
            event_handlers, feedback_instructions, scheduled_tasks, history or batching is \
            applied in place. Changing the remote_addr or startup_params reconnects, and the \
            client gets a new id."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "client_id".to_string(),
                type_hint: "number".to_string(),
                description: "Id of the client to change (Current State lists them).".to_string(),
                required: true,
            },
            Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "New instruction; replaces the whole current one.".to_string(),
                required: false,
            },
            Parameter {
                name: "memory".to_string(),
                type_hint: "string".to_string(),
                description: "New memory; replaces the current memory.".to_string(),
                required: false,
            },
            Parameter {
                name: "event_handlers".to_string(),
                type_hint: "array".to_string(),
                description: "Replacement event handlers, same shape as open_client's; they \
                    replace every current rule."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "scheduled_tasks".to_string(),
                type_hint: "array".to_string(),
                description: "Tasks to add to the client, same shape as open_client's.".to_string(),
                required: false,
            },
            Parameter {
                name: "feedback_instructions".to_string(),
                type_hint: "string".to_string(),
                description: "New feedback instructions (see open_client).".to_string(),
                required: false,
            },
            Parameter {
                name: "history".to_string(),
                type_hint: "number".to_string(),
                description: "Earlier exchanges on the session shown with each event; 0 \
                    turns it off."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "batching".to_string(),
                type_hint: "boolean".to_string(),
                description: "Batch events arriving during a call (refused where the \
                    protocol cannot batch)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "remote_addr".to_string(),
                type_hint: "string".to_string(),
                description: "New address 'host:port'. Reconnects.".to_string(),
                required: false,
            },
            Parameter {
                name: "startup_params".to_string(),
                type_hint: "object".to_string(),
                description: "Startup parameters to merge in, validated against the \
                    protocol's declared ones. Reconnects."
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
///
/// Offered where one instance is in context (feedback processing). The operator prompt has
/// none, so it offers `update_server` / `update_client` instead; see
/// [`get_user_input_common_actions`].
pub fn update_instruction_action() -> ActionDefinition {
    ActionDefinition {
        name: "update_instruction".to_string(),
        description: "Replace the instruction of the server or client this prompt is about. \
            The current instruction is discarded, so the new one must restate everything that \
            should still hold."
            .to_string(),
        parameters: vec![Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "The complete new instruction.".to_string(),
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
        description: "Replace this server's (or client's) memory with new content; the old \
            memory is discarded. Memory is shown to the model with every event, is shared by \
            all of the instance's connections and outlives each one, unlike the history of a \
            single connection, which ends with it. Keep here anything needed later."
            .to_string(),
        parameters: vec![Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "New memory value as a string. Replaces all existing memory.".to_string(),
            required: true,
        }],
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
        description: "Add text to the end of this server's (or client's) memory, after a \
            newline; existing memory is kept. Memory is shown to the model with every event, \
            is shared by all of the instance's connections and outlives each one."
            .to_string(),
        parameters: vec![Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "Text to append as a string. Will be added after existing memory with \
                newline separator."
                .to_string(),
            required: true,
        }],
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
///
/// A task always calls the model with its instruction; it runs no script. The handler
/// refuses a reply that carries script fields rather than dropping them.
pub fn schedule_task_action() -> ActionDefinition {
    let parameters = vec![
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
            description: "Optional: id of the server to attach the task to (Current State lists them). When it fires, the model gets that server's instruction and actions, and the task is removed with the server. Omit server_id, client_id and connection_id for a global task, which gets these operator actions.".to_string(),
            required: false,
        },
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Optional: id of one of that server's connections (e.g. 'conn-3', listed under the server in Current State), to attach the task to it; requires server_id. The task is removed when the connection closes.".to_string(),
            required: false,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "number".to_string(),
            description: "Optional: id of the client to attach the task to (Current State lists them). When it fires, the model gets that client's instruction and actions, and the task is removed when the client disconnects.".to_string(),
            required: false,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "What the model should do each time the task fires.".to_string(),
            required: true,
        },
        Parameter {
            name: "context".to_string(),
            type_hint: "object".to_string(),
            description: "Optional: data handed to the model with the instruction each time the task fires (e.g. thresholds).".to_string(),
            required: false,
        },
    ];

    ActionDefinition {
        name: "schedule_task".to_string(),
        description: "Schedule a task (one-shot or recurring). Each time it fires, the model \
            is called with the task's instruction and acts on it; a task runs no script. \
            One-shot tasks execute once after a delay and are then removed. Recurring tasks \
            execute at intervals until cancelled or max_executions is reached. Useful for \
            delayed operations, timeouts, periodic health checks, heartbeats, SSE messages, \
            metrics collection, etc."
            .to_string(),
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
    actions.push(schedule_task_action());
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

/// Actions in [`get_user_input_common_actions`] that the operator prompt does not offer.
///
/// Each acts on "the instance this prompt is about", which is right where there is one
/// (feedback processing) and wrong at the operator prompt, where there is none and the
/// handler could only fall back to whichever server happens to be first. `update_server` /
/// `update_client` change an instance named by id, its memory included.
pub const NOT_OFFERED_TO_OPERATOR: &[&str] = &["update_instruction", "set_memory", "append_memory"];

/// The common actions the operator prompt offers: [`get_user_input_common_actions`] less
/// [`NOT_OFFERED_TO_OPERATOR`].
pub fn get_operator_common_actions(
    selected_mode: crate::state::app_state::ScriptingMode,
    env: &crate::scripting::ScriptingEnvironment,
    is_open_server_enabled: bool,
    is_open_client_enabled: bool,
) -> Vec<ActionDefinition> {
    let mut actions = get_user_input_common_actions(
        selected_mode,
        env,
        is_open_server_enabled,
        is_open_client_enabled,
    );
    actions.retain(|a| !NOT_OFFERED_TO_OPERATOR.contains(&a.name.as_str()));
    actions
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
pub(crate) fn all_base_stacks(
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
