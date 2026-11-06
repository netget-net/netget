//! Action-based system for LLM interactions
//!
//! This module provides a unified action system where both user input
//! and network events return arrays of actions to execute.

pub mod client_trait;
pub mod common;
pub mod executor;
pub mod protocol_trait;
pub mod summary;
pub mod tools;

// Re-export commonly used functions and types
pub use client_trait::{
    audit_client_action_declarations, client_action_names_for_pattern, client_llm_action_set,
    Client,
};
// Export the Client trait
pub use common::{
    generate_base_stack_documentation, get_network_event_common_actions,
    get_user_input_common_actions,
};
pub use protocol_trait::{Protocol, Server};
// Export StartupExamples for protocol implementations
pub use summary::{summarize_action, summarize_actions};
pub use tools::{
    execute_tool, get_all_tool_actions, get_network_event_tool_actions, is_tool_name, ToolAction,
    ToolResult, TOOL_ACTION_NAMES,
};

use crate::protocol::log_template::LogTemplate;
use serde::{Deserialize, Serialize};

/// Examples showing how to start a protocol with different handler modes
///
/// These examples are required for every protocol and are used in:
/// - Protocol documentation (shown when user requests docs)
/// - Prompt templates to guide LLM in creating servers/clients
///
/// Each example is a complete `open_server` action JSON that can be
/// directly executed. The examples must be validated by tests.
#[derive(Clone, Debug, Serialize)]
pub struct StartupExamples {
    /// Complete open_server action with LLM handler mode
    /// Shows how to start the protocol with LLM-controlled responses
    pub llm_mode: serde_json::Value,

    /// Complete open_server action with script handler mode
    /// Shows event_handlers with script type handlers
    pub script_mode: serde_json::Value,

    /// Complete open_server action with static handler mode
    /// Shows event_handlers with static type handlers and predefined actions
    pub static_mode: serde_json::Value,
}

impl StartupExamples {
    /// Create new startup examples
    pub fn new(
        llm_mode: serde_json::Value,
        script_mode: serde_json::Value,
        static_mode: serde_json::Value,
    ) -> Self {
        Self {
            llm_mode,
            script_mode,
            static_mode,
        }
    }

    /// Validate that all examples are well-formed open_server actions
    ///
    /// Returns Ok(()) if valid, Err with description if invalid.
    /// This is called by parameterized tests to ensure examples stay valid.
    pub fn validate(&self, protocol_name: &str) -> Result<(), String> {
        self.validate_example(&self.llm_mode, "llm_mode", protocol_name)?;
        self.validate_example(&self.script_mode, "script_mode", protocol_name)?;
        self.validate_example(&self.static_mode, "static_mode", protocol_name)?;
        Ok(())
    }

    fn validate_example(
        &self,
        example: &serde_json::Value,
        mode_name: &str,
        protocol_name: &str,
    ) -> Result<(), String> {
        // Must be an object
        let obj = example.as_object().ok_or_else(|| {
            format!(
                "Protocol {} {} example must be a JSON object",
                protocol_name, mode_name
            )
        })?;

        // Must have "type" field
        let action_type = obj.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
            format!(
                "Protocol {} {} example missing 'type' field",
                protocol_name, mode_name
            )
        })?;

        // Type must be "open_server" or "open_client"
        if action_type != "open_server" && action_type != "open_client" {
            return Err(format!(
                "Protocol {} {} example has type '{}', expected 'open_server' or 'open_client'",
                protocol_name, mode_name, action_type
            ));
        }

        // Must have "base_stack" field
        if !obj.contains_key("base_stack") {
            return Err(format!(
                "Protocol {} {} example missing 'base_stack' field",
                protocol_name, mode_name
            ));
        }

        // For script_mode and static_mode, must have event_handlers
        if mode_name == "script_mode" || mode_name == "static_mode" {
            let handlers = obj.get("event_handlers").ok_or_else(|| {
                format!(
                    "Protocol {} {} example missing 'event_handlers' array",
                    protocol_name, mode_name
                )
            })?;

            if !handlers.is_array() {
                return Err(format!(
                    "Protocol {} {} example 'event_handlers' must be an array",
                    protocol_name, mode_name
                ));
            }
        }

        // For llm_mode, should have instruction
        if mode_name == "llm_mode" && !obj.contains_key("instruction") {
            return Err(format!(
                "Protocol {} llm_mode example missing 'instruction' field",
                protocol_name
            ));
        }

        Ok(())
    }

    /// Convert examples to prompt text for LLM documentation
    pub fn to_prompt_text(&self) -> String {
        let mut text = String::new();

        text.push_str("### Starting this Protocol\n\n");

        text.push_str("**LLM Mode** (LLM handles all responses intelligently):\n");
        text.push_str("```json\n");
        text.push_str(&serde_json::to_string_pretty(&self.llm_mode).unwrap_or_default());
        text.push_str("\n```\n\n");

        text.push_str("**Script Mode** (code-based deterministic responses):\n");
        text.push_str("```json\n");
        text.push_str(&serde_json::to_string_pretty(&self.script_mode).unwrap_or_default());
        text.push_str("\n```\n\n");

        text.push_str("**Static Mode** (fixed, unchanging responses):\n");
        text.push_str("```json\n");
        text.push_str(&serde_json::to_string_pretty(&self.static_mode).unwrap_or_default());
        text.push_str("\n```\n\n");

        text
    }
}

/// Definition of a configuration parameter for prompt generation
///
/// This describes a startup parameter that a protocol accepts,
/// including its name, type, description, and an example value.
#[derive(Debug, Clone, Serialize)]
pub struct ParameterDefinition {
    /// Parameter name (e.g., "certificate_mode", "max_connections")
    pub name: String,

    /// Type hint for the LLM (e.g., "string", "number", "boolean", "object")
    pub type_hint: String,

    /// Human-readable description of what this parameter does
    pub description: String,

    /// Whether this parameter is required
    pub required: bool,

    /// JSON example showing a valid value for this parameter
    pub example: serde_json::Value,

    /// The value the protocol uses when the caller omits this parameter, when there is one.
    ///
    /// Declared where the code already falls back to a fixed value, so the operator can see
    /// the value before choosing to change it: the dashboard's create form pre-fills it (and
    /// does not submit it unless edited), and `get_protocol_docs` prints it. `None` means
    /// omitting the parameter changes behaviour in a way no single value describes — a feature
    /// switched off, a value derived from something else — or the parameter is required.
    ///
    /// Must parse as [`Self::type_hint`]; `tests/startup_param_defaults_test.rs` checks every
    /// declaration. Point it at the constant the code falls back to
    /// (`Some(json!(IDLE_TIMEOUT.as_secs()))`), never a literal repeating it, or the two drift.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
}

impl ParameterDefinition {
    /// Convert to prompt text format for LLM
    pub fn to_prompt_text(&self) -> String {
        let required = if self.required {
            "required"
        } else {
            "optional"
        };
        let mut text = format!(
            "\"{}\": {}  // {} ({})\nExample: {}",
            self.name,
            self.type_hint,
            self.description,
            required,
            serde_json::to_string(&self.example).unwrap_or_default()
        );
        if let Some(default) = &self.default {
            text.push_str(&format!(
                "\nDefault when omitted: {}",
                serde_json::to_string(default).unwrap_or_default()
            ));
        }
        text
    }
}

/// Controls how this tool/action behaves in conversations and which paths expose it
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCategory {
    /// Information-gathering tool: results returned to LLM for further processing
    /// Examples: read_file, web_search, read_documentation, list_models
    InformationTool,
    /// Action: executed with acknowledgment, LLM may continue
    /// Examples: open_server, close_server, set_memory, notify_operator
    Action,
    /// Protocol-specific sync action: executed during network event handling
    /// Examples: send_http_response, send_tcp_data, send_dns_a_response
    ProtocolAction,
}

/// Definition of an action for prompt generation
///
/// This describes an action to the LLM, including its name,
/// description, parameters, and an example.
#[derive(Debug, Clone)]
pub struct ActionDefinition {
    /// Action type name (e.g., "send_tcp_data", "close_connection")
    pub name: String,

    /// Human-readable description of what this action does
    pub description: String,

    /// List of parameters this action accepts
    pub parameters: Vec<Parameter>,

    /// JSON example showing how to use this action
    pub example: serde_json::Value,

    /// Log template for action execution logging
    /// Defines protocol-specific log formats at INFO/DEBUG/TRACE levels
    pub log_template: Option<LogTemplate>,
}

impl ActionDefinition {
    /// Check if this is a tool action (returns information and triggers LLM re-invocation)
    ///
    /// Delegates to [`tools::is_tool_name`] — the single source of truth shared with
    /// [`ToolAction::is_tool_action`], which decides at runtime whether the model is
    /// re-invoked. Classifying here independently is what previously rendered
    /// `read_documentation` under the "Available Actions" heading, whose boilerplate
    /// tells the model it will *not* be invoked again — the opposite of what happens.
    pub fn is_tool(&self) -> bool {
        tools::is_tool_name(&self.name)
    }

    /// Convert to prompt text format for LLM
    pub fn to_prompt_text(&self) -> String {
        let mut text = format!("{}\n\n{}\n", self.name, self.description);

        // Only show schema if there are parameters
        if !self.parameters.is_empty() {
            text.push_str("\nParameters:\n");
            for param in &self.parameters {
                let required = if param.required {
                    "required"
                } else {
                    "optional"
                };
                text.push_str(&format!(
                    "- {}: {} ({}) - {}\n",
                    param.name, param.type_hint, required, param.description
                ));
            }
        }

        text.push_str("\nExample:\n```json\n");
        text.push_str(&serde_json::to_string_pretty(&self.example).unwrap_or_default());
        text.push_str("\n```");
        text
    }

    /// Add a log template to this action definition
    ///
    /// The log template defines protocol-specific log formats at INFO/DEBUG/TRACE levels.
    /// This enables standardized, centralized logging without per-action logging code.
    ///
    /// # Example
    /// ```rust,ignore
    /// ActionDefinition {
    ///     name: "send_http_response".to_string(),
    ///     // ...other fields...
    ///     log_template: None,
    /// }
    /// .with_log_template(
    ///     LogTemplate::new()
    ///         .with_info("HTTP {status}, {output_bytes}B")
    ///         .with_debug("Response: status={status}, body_len={output_bytes}")
    /// )
    /// ```
    pub fn with_log_template(mut self, template: LogTemplate) -> Self {
        self.log_template = Some(template);
        self
    }

    /// Derive the tool category from the action name
    pub fn category(&self) -> ToolCategory {
        if self.is_tool() {
            ToolCategory::InformationTool
        } else if self.is_common_action() {
            ToolCategory::Action
        } else {
            ToolCategory::ProtocolAction
        }
    }

    /// Whether this action should be exposed as an MCP tool in STDIO mode
    pub fn mcp_visible(&self) -> bool {
        match self.category() {
            ToolCategory::InformationTool => {
                // Expose information tools except generate_random (MCP clients can do this)
                !matches!(
                    self.name.as_str(),
                    "generate_random" | "list_network_interfaces"
                )
            }
            ToolCategory::Action => {
                // Expose management actions, exclude internal-only ones
                !matches!(
                    self.name.as_str(),
                    "notify_operator" | "append_to_log" | "provide_feedback"
                )
            }
            ToolCategory::ProtocolAction => {
                // Protocol-specific actions are not exposed via MCP
                // (they are handled by the protocol server's internal LLM)
                false
            }
        }
    }

    /// Check if this is a common (non-protocol-specific) action
    fn is_common_action(&self) -> bool {
        matches!(
            self.name.as_str(),
            "notify_operator"
                | "open_server"
                | "close_server"
                | "close_all_servers"
                | "open_client"
                | "close_client"
                | "close_all_clients"
                | "reconnect_client"
                | "update_client_instruction"
                | "update_client"
                | "update_server"
                | "close_connection_by_id"
                | "update_instruction"
                | "set_memory"
                | "append_memory"
                | "append_to_log"
                | "change_model"
                | "schedule_task"
                | "cancel_task"
                | "provide_feedback"
                | "create_database"
                | "delete_database"
        )
    }

    /// Convert to OpenAI/Ollama native tool calling schema
    ///
    /// Returns a JSON value in the format:
    /// ```json
    /// {
    ///   "type": "function",
    ///   "function": {
    ///     "name": "action_name",
    ///     "description": "What this action does",
    ///     "parameters": {
    ///       "type": "object",
    ///       "properties": { ... },
    ///       "required": [ ... ]
    ///     }
    ///   }
    /// }
    /// ```
    pub fn to_tool_schema(&self) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &self.parameters {
            let mut prop = serde_json::Map::new();
            // Map type_hint to JSON Schema type
            let json_type = match param.type_hint.as_str() {
                "number" | "integer" => "number",
                "boolean" | "bool" => "boolean",
                "array" => "array",
                "object" => "object",
                _ => "string",
            };
            prop.insert(
                "type".to_string(),
                serde_json::Value::String(json_type.to_string()),
            );
            // A closed value set becomes a JSON-Schema enum, so native
            // tool-calling backends constrain the model to the valid values.
            if let Some(choices) = param.choices() {
                prop.insert(
                    "enum".to_string(),
                    serde_json::Value::Array(
                        choices.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
            }
            prop.insert(
                "description".to_string(),
                serde_json::Value::String(param.description.clone()),
            );
            properties.insert(param.name.clone(), serde_json::Value::Object(prop));
            if param.required {
                required.push(serde_json::Value::String(param.name.clone()));
            }
        }

        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }
            }
        })
    }

    /// Convert to MCP tool schema for rmcp
    ///
    /// Returns a JSON value in the format:
    /// ```json
    /// {
    ///   "name": "action_name",
    ///   "description": "What this action does",
    ///   "inputSchema": {
    ///     "type": "object",
    ///     "properties": { ... },
    ///     "required": [ ... ]
    ///   }
    /// }
    /// ```
    pub fn to_mcp_tool_schema(&self) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &self.parameters {
            let mut prop = serde_json::Map::new();
            let json_type = match param.type_hint.as_str() {
                "number" | "integer" => "number",
                "boolean" | "bool" => "boolean",
                "array" => "array",
                "object" => "object",
                _ => "string",
            };
            prop.insert(
                "type".to_string(),
                serde_json::Value::String(json_type.to_string()),
            );
            // Same as `to_tool_schema`: a closed value set is advertised as an enum.
            if let Some(choices) = param.choices() {
                prop.insert(
                    "enum".to_string(),
                    serde_json::Value::Array(
                        choices.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
            }
            prop.insert(
                "description".to_string(),
                serde_json::Value::String(param.description.clone()),
            );
            properties.insert(param.name.clone(), serde_json::Value::Object(prop));
            if param.required {
                required.push(serde_json::Value::String(param.name.clone()));
            }
        }

        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        })
    }
}

/// Parameter definition for an action
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Parameter name (e.g., "output", "connection_id")
    pub name: String,

    /// Type hint for the LLM (e.g., "string", "number", "boolean").
    ///
    /// A parameter whose value comes from a **closed set** declares it here as a
    /// quoted alternation — `"utf8" | "hex"` — normally written via
    /// [`Parameter::with_choices`]. [`Parameter::choices`] parses it back out.
    /// The spelling is deliberate: it reads as a TypeScript-style literal union
    /// in the LLM prompt, maps to `"enum"` in the native tool-calling schemas,
    /// and cannot collide with the *type* unions some protocols already use
    /// (`"number | string"`, `"array | object"`), whose segments are unquoted.
    pub type_hint: String,

    /// Description of what this parameter does
    pub description: String,

    /// Whether this parameter is required
    pub required: bool,
}

impl Parameter {
    /// Declare the closed set of values this parameter accepts.
    ///
    /// Encodes the choices into `type_hint` as a quoted alternation
    /// (`"utf8" | "hex"`), which is what [`Parameter::choices`] recognises.
    /// The TUI composer renders such a parameter as a cycling selector instead
    /// of a free-text field, and the native tool schemas advertise the set as a
    /// JSON-Schema `enum`. The chosen value is always submitted as a plain
    /// string.
    ///
    /// ```rust,ignore
    /// Parameter { name: "encoding".into(), type_hint: "string".into(), … }
    ///     .with_choices(["utf8", "hex"])
    /// ```
    pub fn with_choices<I, S>(mut self, choices: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let rendered: Vec<String> = choices
            .into_iter()
            .map(|c| format!("\"{}\"", c.into()))
            .collect();
        if !rendered.is_empty() {
            self.type_hint = rendered.join(" | ");
        }
        self
    }

    /// The closed set of values this parameter accepts, if it declares one.
    ///
    /// Recognises a `type_hint` that is a quoted alternation of two or more
    /// literals (`"utf8" | "hex"`, as written by [`Parameter::with_choices`]).
    /// Unquoted alternations — the *type* unions like `"number | string"` used
    /// by jsonrpc and torrent_tracker — are deliberately not choices: they name
    /// kinds of values, not the values themselves.
    pub fn choices(&self) -> Option<Vec<String>> {
        let segments: Vec<&str> = self.type_hint.split('|').map(str::trim).collect();
        if segments.len() < 2 {
            return None;
        }
        let mut values = Vec::with_capacity(segments.len());
        for segment in segments {
            let inner = segment.strip_prefix('"')?.strip_suffix('"')?;
            if inner.is_empty() {
                return None;
            }
            values.push(inner.to_string());
        }
        Some(values)
    }
}

/// The first JSON value in `text`, starting the scan at `start`, that is shaped like an answer:
/// an object, or an array whose items are all objects. Anything else (a bare string, a number,
/// an array of words quoted in the model's prose) is skipped and the scan resumes at the next
/// `{` or `[`.
fn first_answer_shaped_value(text: &str, start: usize) -> Option<serde_json::Value> {
    let mut from = start;
    loop {
        let candidate = &text[from..];
        let value = serde_json::Deserializer::from_str(candidate)
            .into_iter::<serde_json::Value>()
            .next()
            .and_then(|r| r.ok());
        match value {
            Some(v @ serde_json::Value::Object(_)) => return Some(v),
            Some(serde_json::Value::Array(items)) if items.iter().all(|i| i.is_object()) => {
                return Some(serde_json::Value::Array(items))
            }
            _ => {}
        }
        // Resume at the next opening bracket after this one.
        let next = text[from + 1..]
            .find(['{', '['])
            .map(|offset| from + 1 + offset)?;
        from = next;
    }
}

/// Normalize an LLM-emitted action/tool-call object into the canonical flat
/// `{"type": <name>, <params...>}` shape that the action/tool parsers expect.
///
/// Tolerates the common OpenAI/tool-calling variants that some models (notably
/// MLX/gemma builds) emit instead of NetGet's format:
///   - the action name under `type`, `function`, or `name`;
///   - parameters nested under `args`, `arguments`, or `parameters` rather than flat.
///
/// A former action name is rewritten to its current one (`show_message` → `notify_operator`,
/// see [`common::canonical_action_name`]), so an answer written against the old vocabulary is
/// validated and executed as the action it names.
///
/// A value with no recognizable name key, or a non-object, is returned unchanged.
pub fn normalize_action_object(value: &serde_json::Value) -> serde_json::Value {
    let obj = match value.as_object() {
        Some(o) => o,
        None => return value.clone(),
    };

    // `name` is BOTH a tool-calling spelling of the action name
    // ({"name": "send_x", "arguments": {…}}) and a legitimate *parameter* of
    // real actions — send_nntp_group's newsgroup, create_database's database,
    // openid/oci_registry/dc fields. Consume it as the action name only when
    // nothing else supplies one; otherwise it is data and must survive, or the
    // executor sees the action with the field silently missing and fails it
    // with "Missing 'name' field" against a model answer that had it.
    let (name, name_was_the_action) = match obj.get("type").and_then(|v| v.as_str()) {
        Some(t) => (t.to_string(), false),
        None => match obj.get("function").and_then(|v| v.as_str()) {
            Some(f) => (f.to_string(), false),
            None => match obj.get("name").and_then(|v| v.as_str()) {
                Some(n) => (n.to_string(), true),
                None => return value.clone(),
            },
        },
    };

    let mut out = serde_json::Map::new();
    out.insert(
        "type".to_string(),
        serde_json::Value::String(common::canonical_action_name(&name).to_string()),
    );

    // Flat params: keep everything except wrapper keys and whichever key
    // supplied the action name.
    for (k, v) in obj {
        let is_wrapper = matches!(
            k.as_str(),
            "type" | "function" | "args" | "arguments" | "parameters"
        );
        if is_wrapper || (k == "name" && name_was_the_action) {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    // Merge nested params up to the top level (flat params win on conflict).
    for wrapper in ["args", "arguments", "parameters"] {
        if let Some(serde_json::Value::Object(inner)) = obj.get(wrapper) {
            for (k, v) in inner {
                out.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }

    serde_json::Value::Object(out)
}

/// Response from LLM containing tools and/or actions
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionResponse {
    /// Array of protocol-specific actions to execute in order
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,

    /// Array of tool calls (read_file, web_search, generate_random, etc.)
    /// Tools are executed before actions and their results feed back to the LLM
    #[serde(default)]
    pub tools: Vec<serde_json::Value>,
}

impl ActionResponse {
    /// Parse from JSON string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let trimmed = s.trim();

        // Strip markdown code fences if present (```json ... ``` or ``` ... ```)
        let json_str = if trimmed.starts_with("```") {
            // Find the first newline after opening fence
            let start = trimmed.find('\n').unwrap_or(3);
            // Find the closing fence (must be after start)
            let end = trimmed[start..]
                .rfind("```")
                .map(|pos| start + pos)
                .unwrap_or(trimmed.len());
            // Extract content between fences (ensure valid slice)
            if start <= end {
                trimmed[start..end].trim()
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        // Strip any extra characters before the JSON object or array.
        // Sometimes LLMs add extra text like "Y{" instead of just "{". Take whichever
        // of `{` or `[` comes FIRST — preferring `{` unconditionally would strip the
        // leading `[` off a top-level array and corrupt it.
        let json_start = match (json_str.find('{'), json_str.find('[')) {
            (Some(b), Some(k)) => b.min(k),
            (Some(b), None) => b,
            (None, Some(k)) => k,
            (None, None) => 0,
        };
        let clean_json = &json_str[json_start..];

        // Take the FIRST complete JSON value and ignore whatever follows it.
        //
        // `serde_json::from_str` requires the *whole* string to be one value, and that single
        // property discarded 29 of 30 answers in the first real-model eval
        // (`EVAL_RESULTS.md`). Small models routinely append prose after the JSON:
        //
        //     {"actions": [{"type": "send_http_response", "status": 200, …}]}
        //     Explanation: Since this is an HTTP request event, I'm emitting a …
        //
        // The model had named the right action with the right parameters *every time*, and
        // NetGet threw the reply away with `Invalid JSON` — so the protocol behaved as though
        // the backend had failed. Nothing in the suite could see it, because every mock
        // returns exactly the JSON the test author wrote; the defect lives precisely in the
        // gap between a mock and a model.
        //
        // The trailing-fence case already worked (the stripper above cuts at the closing
        // ```), which is why this looked like a fenced-output problem rather than a parsing
        // one.
        //
        // `StreamDeserializer` stops at the end of the first value instead of demanding it be
        // the last thing in the string. A string that is entirely one value parses exactly as
        // before, so this only ever widens what is accepted.
        //
        // The first value has to be something an answer can be: an object, or an array of
        // objects. Prose often brackets a word before the JSON starts ("the containers
        // ["eval-web"] are ..."), and taking that array made a bare string the model's
        // "action". Such a value is skipped and the scan moves to the next `{` or `[`.
        let first_value = first_answer_shaped_value(json_str, json_start);

        if let Some(json_value) = first_value {
            use crate::llm::actions::tools::ToolAction;
            match json_value {
                // Case 1: Full response object with tools and/or actions fields
                serde_json::Value::Object(ref map)
                    if map.contains_key("tools") || map.contains_key("actions") =>
                {
                    match serde_json::from_value::<ActionResponse>(json_value.clone()) {
                        Ok(mut response) => {
                            // Normalize each entry (flatten nested args, map function->type).
                            for a in response.actions.iter_mut() {
                                *a = normalize_action_object(a);
                            }
                            for t in response.tools.iter_mut() {
                                *t = normalize_action_object(t);
                            }
                            // Separate tools and actions if mixed (support cross-contamination)
                            Self::separate_tools_and_actions(&mut response);
                            return Ok(response);
                        }
                        Err(e) => {
                            anyhow::bail!(
                                "Failed to parse action response\n\n❌ Expected format:\n{{\n  \"tools\": [...],\n  \"actions\": [...]\n}}\n\n❌ Actual response:\n{}\n\nError: {}",
                                clean_json,
                                e
                            )
                        }
                    }
                }

                // Case 1b: OpenAI-style tool-call wrapper
                // {"tool_calls": [{"function"/"name": "...", "args"/"arguments"/"parameters": {...}}]}
                // Many models (e.g. MLX/gemma builds) emit this instead of the native format.
                serde_json::Value::Object(ref map)
                    if map.contains_key("tool_calls") || map.contains_key("tool_call") =>
                {
                    let mut response = ActionResponse::empty();
                    let calls = map.get("tool_calls").or_else(|| map.get("tool_call"));
                    let items: Vec<serde_json::Value> = match calls {
                        Some(serde_json::Value::Array(a)) => a.clone(),
                        Some(v @ serde_json::Value::Object(_)) => vec![v.clone()],
                        _ => Vec::new(),
                    };
                    for item in &items {
                        let norm = normalize_action_object(item);
                        if ToolAction::is_tool_action(&norm) {
                            response.tools.push(norm);
                        } else {
                            response.actions.push(norm);
                        }
                    }
                    return Ok(response);
                }

                // Case 2: Single action/tool object at top level. Accept a name under
                // `type`, `function`, or `name`; normalize flattens any nested args.
                serde_json::Value::Object(ref map)
                    if map.contains_key("type")
                        || map.contains_key("function")
                        || map.contains_key("name") =>
                {
                    let norm = normalize_action_object(&json_value);
                    let mut response = ActionResponse::empty();
                    if ToolAction::is_tool_action(&norm) {
                        response.tools.push(norm);
                    } else {
                        response.actions.push(norm);
                    }
                    return Ok(response);
                }

                // Case 3: Top-level array [{"type": "..."}, ...]
                serde_json::Value::Array(items) => {
                    let mut response = ActionResponse::empty();

                    for item in &items {
                        let norm = normalize_action_object(item);
                        if ToolAction::is_tool_action(&norm) {
                            response.tools.push(norm);
                        } else {
                            response.actions.push(norm);
                        }
                    }
                    return Ok(response);
                }

                // Case 4: Empty object {} - return empty response
                serde_json::Value::Object(ref map) if map.is_empty() => {
                    return Ok(ActionResponse::empty());
                }

                // Unrecognized format
                _ => {
                    anyhow::bail!(
                        "Failed to parse action response: Unrecognized format\n\n❌ Expected one of:\n\
                        1. {{\n     \"tools\": [...],\n     \"actions\": [...]\n   }}\n\
                        2. {{\"type\": \"...\", ...}}\n\
                        3. [{{\"type\": \"...\"}}, ...]\n\n❌ Actual response:\n{}",
                        clean_json
                    )
                }
            }
        } else {
            anyhow::bail!(
                "Failed to parse action response: Invalid JSON\n\n❌ Actual response:\n{}",
                clean_json
            )
        }
    }

    /// Separate tools and actions if they are mixed (cross-contamination support)
    /// This handles cases where tools are in the actions array or vice versa
    fn separate_tools_and_actions(response: &mut ActionResponse) {
        use crate::llm::actions::tools::ToolAction;

        // Check tools array for misplaced actions
        if !response.tools.is_empty() {
            let (actual_tools, misplaced_actions): (Vec<_>, Vec<_>) = response
                .tools
                .clone()
                .into_iter()
                .partition(|item| ToolAction::is_tool_action(item));

            response.tools = actual_tools;
            response.actions.extend(misplaced_actions);
        }

        // Check actions array for misplaced tools
        if !response.actions.is_empty() {
            let (misplaced_tools, actual_actions): (Vec<_>, Vec<_>) = response
                .actions
                .clone()
                .into_iter()
                .partition(|item| ToolAction::is_tool_action(item));

            response.actions = actual_actions;
            response.tools.extend(misplaced_tools);
        }
    }

    /// Create empty action response
    pub fn empty() -> Self {
        Self {
            actions: Vec::new(),
            tools: Vec::new(),
        }
    }

    /// Get all actions (combining tools and actions for backward compatibility)
    pub fn all_actions(&self) -> Vec<serde_json::Value> {
        let mut all = self.tools.clone();
        all.extend(self.actions.clone());
        all
    }
}

impl std::str::FromStr for ActionResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ActionResponse::from_str(s)
    }
}
