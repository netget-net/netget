//! Event type definitions for protocol-specific events
//!
//! Each protocol defines a set of event types that can trigger LLM calls or script execution.
//! Event types have unique IDs and associated actions that can be used to respond to the event.

use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::log_template::LogTemplate;
use serde_json::Value as JsonValue;

/// Represents a type of event that a protocol can emit
///
/// Events are the triggers for LLM calls or script execution.
/// Each event has a unique ID and a list of actions that can be used to respond.
#[derive(Clone, Debug)]
pub struct EventType {
    /// Unique identifier for this event type (e.g., "http_request", "ssh_auth")
    pub id: String,

    /// Human-readable description of when this event occurs
    pub description: String,

    /// Actions that can be used to respond to this event
    /// These are protocol-specific sync actions
    ///
    /// This list — not [`Server::get_sync_actions`](crate::llm::actions::Server::get_sync_actions)
    /// — is what `call_llm` advertises to the model, so an event that leaves it empty offers the
    /// model nothing protocol-specific and every protocol action it returns is rejected as
    /// unknown. Narrowing is deliberate and supported (SSH's `ssh_auth` accepts only
    /// `ssh_auth_decision`), but *silently* empty is always a bug. If an event genuinely needs no
    /// protocol action, say so with [`EventType::with_no_actions`] rather than leaving this empty.
    pub actions: Vec<ActionDefinition>,

    /// Set by [`EventType::with_no_actions`] to record that this event was *deliberately* left
    /// without protocol actions, as opposed to having had `with_actions(...)` forgotten.
    ///
    /// `call_llm` treats an empty `actions` list as a bug unless this is set: see
    /// [`EventType::has_no_usable_actions`].
    no_actions_intentional: bool,

    /// Parameters describing the expected structure of event data
    /// This documents what fields should be present in the event data JSON
    /// Uses the same Parameter structure as actions
    pub parameters: Vec<Parameter>,

    /// Required response example for this event
    /// Used in prompt templates to show the expected action response
    /// This MUST use protocol-specific action types (e.g., send_dns_a_response, not send_data)
    ///
    /// This field is required - every event type must have at least one valid response example.
    /// This ensures prompts always show relevant, protocol-specific examples.
    pub response_example: JsonValue,

    /// Optional alternative response examples
    /// Shows other valid ways to respond to this event
    /// Displayed after the primary response_example
    pub alternative_examples: Vec<JsonValue>,

    /// Log template for this event type
    /// Defines protocol-specific log formats at INFO/DEBUG/TRACE levels
    pub log_template: Option<LogTemplate>,

    /// Raised for every new connection before the peer has sent anything, and answered with
    /// nothing whenever the instruction does not ask the server to speak first. Set with
    /// [`EventType::raised_on_every_connection`].
    ///
    /// Read by the dashboard (`src/tui/modal/form.rs`): an interactively created server routes
    /// these to a zero-action static rule ahead of its `*` → manual wildcard, so a human is
    /// not asked "someone connected — say anything?" for every connection.
    pub on_every_connection: bool,
}

/// The event data of a connect event (one declared
/// [`EventType::raised_on_every_connection`]): how much the peer has sent, which is nothing,
/// and which answer that calls for.
///
/// An empty object was not enough. With `{}` as the whole event, llama3.1:8b told to "echo back
/// what the client sent" greeted every connection with "Hello, client! What's your request?",
/// and told to "send back the client's text in upper case" sent `CLIENT TEXT IN UPPER CASE` -
/// it read the connect event as a request and invented the request (`tcp/echo` 5/5 -> 1/5,
/// `tcp/uppercase` 5/5 -> 0/5 when these events began firing on every connection). Two
/// wordings of this data were measured before this one, and both are worth knowing:
///
/// * a `received: "nothing - the client has only connected"` field was echoed back verbatim -
///   any string here is something an echo instruction will send;
/// * "no actions unless the instruction explicitly says to greet" made the model answer "ask
///   for a login name as soon as somebody connects" with `show_message`, which never reaches
///   the client (`telnet/login-prompt` 5/5 -> 1/5). The hint has to say where a greeting goes.
pub fn connect_event_data() -> JsonValue {
    serde_json::json!({
        "bytes_received": 0,
        "answer_with": "If the instruction says to greet, show a banner, prompt or ask for \
                        something as soon as someone connects, send that text to the client \
                        now with this protocol's send action (show_message only reaches the \
                        operator's screen, never the client). Otherwise answer with no actions \
                        ({\"actions\": []}): the client has sent 0 bytes, so there is nothing \
                        to echo, transform or answer yet.",
    })
}

/// The parameters [`connect_event_data`] fills, for a connect event's declaration.
pub fn connect_event_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "bytes_received".to_string(),
            type_hint: "number".to_string(),
            description: "How much the client has sent: always 0 on a connect event".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which answer a connect event calls for".to_string(),
            required: true,
        },
    ]
}

impl EventType {
    /// Create a new event type with a required response example
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this event type (e.g., "http_request", "dns_query")
    /// * `description` - Human-readable description of when this event occurs
    /// * `response_example` - Required example showing how to respond to this event
    ///
    /// The response_example MUST use protocol-specific action types (e.g., send_dns_a_response)
    /// not generic actions like send_data. This ensures prompts show relevant examples.
    ///
    /// # Example
    /// ```rust,ignore
    /// EventType::new(
    ///     "dns_query",
    ///     "DNS query received from client",
    ///     json!({"type": "send_dns_a_response", "query_id": 0, "domain": "example.com", "ip": "1.2.3.4"})
    /// )
    /// ```
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        response_example: JsonValue,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            actions: Vec::new(),
            no_actions_intentional: false,
            parameters: Vec::new(),
            response_example,
            alternative_examples: Vec::new(),
            log_template: None,
            on_every_connection: false,
        }
    }

    /// Declare that this is a connect event: raised for every new connection before the peer
    /// has sent anything, answered with no actions when there is nothing to say first. See
    /// [`EventType::on_every_connection`].
    pub fn raised_on_every_connection(mut self) -> Self {
        self.on_every_connection = true;
        self
    }

    /// Add an action to this event type
    pub fn with_action(mut self, action: ActionDefinition) -> Self {
        self.actions.push(action);
        self
    }

    /// Add multiple actions to this event type
    pub fn with_actions(mut self, actions: Vec<ActionDefinition>) -> Self {
        self.actions.extend(actions);
        self
    }

    /// Declare that this event deliberately offers the model no protocol-specific action.
    ///
    /// Use this for events that are purely informational (a connection closed, a peer went away)
    /// where the only sensible responses are the common actions — `set_memory`, `show_message`,
    /// `append_to_log`. It exists so that "this event needs no action" is written down and
    /// distinguishable from "somebody forgot `with_actions(...)`", which is the failure mode that
    /// silently disabled sixteen protocols. `call_llm` reports the latter and repairs it at
    /// runtime; see [`EventType::has_no_usable_actions`].
    pub fn with_no_actions(mut self) -> Self {
        self.no_actions_intentional = true;
        self
    }

    /// The response example to actually show a model, with placeholders repaired.
    ///
    /// `response_example` is rendered verbatim into the prompt (`src/llm/actions/tools.rs`) and
    /// into the MCP protocol docs (`src/mcp_stdio/docs.rs`), so it teaches the model how to
    /// answer this event. 215 of them across 92 files are the literal
    /// `{"type": "placeholder", "event_id": "..."}`, which teaches an action type that does not
    /// exist and that the executor rejects as unknown.
    ///
    /// Rather than leave those rendering as-is, derive a real one: the first action attached to
    /// this event is by construction a valid answer to it, and its `example` is a complete,
    /// protocol-specific action object. Events that legitimately have no action
    /// ([`Self::with_no_actions`]) fall back to `show_message`, which is a common action and is
    /// always accepted.
    ///
    /// A declared example that is not a placeholder is returned untouched, so this changes
    /// nothing for the events that already carry a real one. `tests/placeholder_examples_test.rs`
    /// asserts no registered protocol renders a placeholder through this path.
    pub fn effective_response_example(&self) -> JsonValue {
        if !Self::is_placeholder(&self.response_example) {
            return self.response_example.clone();
        }
        if let Some(action) = self.actions.first() {
            if !Self::is_placeholder(&action.example) {
                return action.example.clone();
            }
        }
        serde_json::json!({
            "type": "show_message",
            "message": format!("Handled {}", self.id),
        })
    }

    /// Whether a response example is the `{"type": "placeholder", ...}` stand-in.
    pub fn is_placeholder(example: &JsonValue) -> bool {
        example.get("type").and_then(|t| t.as_str()) == Some("placeholder")
    }

    /// True when this event advertises no protocol action *and* never said it meant to.
    ///
    /// This is exactly the bug shape: the protocol declares sync actions, but the event type the
    /// model is prompted with lists none of them, so the model's only vocabulary is the common
    /// actions and every protocol action it produces is rejected as unknown.
    pub fn has_no_usable_actions(&self) -> bool {
        self.actions.is_empty() && !self.no_actions_intentional
    }

    /// Add a parameter describing expected event data field
    pub fn with_parameter(mut self, parameter: Parameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    /// Add multiple parameters describing expected event data
    pub fn with_parameters(mut self, parameters: Vec<Parameter>) -> Self {
        self.parameters.extend(parameters);
        self
    }

    /// Add an alternative response example for this event
    ///
    /// This shows another valid way to respond to this event.
    /// The primary response_example is set in the constructor;
    /// use this method to add additional alternatives.
    ///
    /// # Example
    /// ```rust,ignore
    /// .with_alternative_example(json!({
    ///     "type": "disconnect"
    /// }))
    /// ```
    pub fn with_alternative_example(mut self, example: JsonValue) -> Self {
        self.alternative_examples.push(example);
        self
    }

    /// Add a log template for this event type
    ///
    /// The log template defines protocol-specific log formats at INFO/DEBUG/TRACE levels.
    /// This enables standardized, centralized logging without per-protocol logging code.
    ///
    /// # Example
    /// ```rust,ignore
    /// EventType::new("http_request", "HTTP request received", json!({...}))
    ///     .with_log_template(
    ///         LogTemplate::new()
    ///             .with_info("{client_ip} {method} {path} -> {status}")
    ///             .with_debug("HTTP {method} {path} from {client_ip}:{client_port}")
    ///             .with_trace("HTTP request: {json_pretty(.)}")
    ///     )
    /// ```
    pub fn with_log_template(mut self, template: LogTemplate) -> Self {
        self.log_template = Some(template);
        self
    }

    /// Get action names for this event type
    pub fn action_names(&self) -> Vec<String> {
        self.actions.iter().map(|a| a.name.clone()).collect()
    }

    /// Convert this event type to a prompt description
    ///
    /// This creates a formatted string that describes the event and what actions
    /// are available to respond to it. Used in LLM prompts.
    ///
    /// # Returns
    /// A formatted string describing the event type, its context, and available actions
    pub fn to_prompt_description(&self) -> String {
        let mut result = String::new();

        // Event type header
        result.push_str(&format!("Event Type: {}\n", self.id));
        result.push_str(&format!("Description: {}\n\n", self.description));

        // Event input parameters (if available)
        if !self.parameters.is_empty() {
            result.push_str("Event Input Data:\n");
            for param in &self.parameters {
                result.push_str(&format!(
                    "  - {} ({}){}: {}\n",
                    param.name,
                    param.type_hint,
                    if param.required {
                        ", required"
                    } else {
                        ", optional"
                    },
                    param.description
                ));
            }
            result.push('\n');
        }

        // Available actions for this event
        if !self.actions.is_empty() {
            result.push_str("Available actions for this event:\n\n");
            for (i, action) in self.actions.iter().enumerate() {
                result.push_str(&format!("{}. {}\n\n", i + 1, action.to_prompt_text()));
            }
        } else {
            result.push_str("No specific actions available for this event.\n");
        }

        result
    }
}

/// Represents a specific event instance with type and data
///
/// This combines an EventType (which defines what can happen) with
/// the actual event data (what did happen). It's the complete package
/// that gets passed to call_llm().
///
/// # Example
/// ```rust,ignore
/// // Create an event instance for HTTP request
/// let event = Event::new(
///     &HTTP_REQUEST_EVENT,  // EventType constant
///     json!({
///         "method": "GET",
///         "path": "/api/users",
///         "headers": {"User-Agent": "curl/7.0"}
///     })
/// );
///
/// call_llm(&llm_client, &state, server_id, conn_id, &event, &protocol).await?;
/// ```
#[derive(Clone, Debug)]
pub struct Event {
    /// The type of event (reference to EventType constant)
    pub event_type: &'static EventType,

    /// The event-specific data (e.g., HTTP headers, SSH username, etc.)
    pub data: JsonValue,
}

impl Event {
    /// Create a new event instance
    ///
    /// # Arguments
    /// * `event_type` - Reference to the EventType constant
    /// * `data` - JSON data with event-specific context
    ///
    /// # Example
    /// ```rust,ignore
    /// let event = Event::new(
    ///     &SSH_AUTH_EVENT,
    ///     json!({"username": "alice", "auth_type": "password"})
    /// );
    /// ```
    pub fn new(event_type: &'static EventType, data: JsonValue) -> Self {
        Self { event_type, data }
    }

    /// Get the event type ID (for script routing)
    pub fn id(&self) -> &str {
        &self.event_type.id
    }

    /// Get the event description for prompts
    pub fn to_prompt_description(&self) -> String {
        self.event_type.to_prompt_description()
    }

    /// What the model reads about the event it is answering: its description and the fields
    /// its data carries — not its actions. The system prompt already lists the offered actions;
    /// repeating them here numbered from 1 (the system prompt numbers from 0) contradicted it
    /// twice: on the fallback path, where the event declares none but the protocol's are
    /// offered ("No specific actions available"), and in a batch, where earlier events'
    /// actions are offered but only the newest event's were listed "for this event".
    pub fn to_trigger_description(&self) -> String {
        let mut result = format!("{}\n", self.event_type.description);
        if !self.event_type.parameters.is_empty() {
            result.push_str("Fields in the data below:\n");
            for param in &self.event_type.parameters {
                result.push_str(&format!(
                    "  - {} ({}): {}\n",
                    param.name, param.type_hint, param.description
                ));
            }
        }
        result
    }
}

/// Format event types for inclusion in LLM prompts
pub fn format_event_types_for_prompt(event_types: &[EventType]) -> String {
    if event_types.is_empty() {
        return String::new();
    }

    let mut result = String::from("\nEVENT TYPES:\n");
    result.push_str("This protocol can emit the following event types:\n\n");

    for event_type in event_types {
        result.push_str(&format!(
            "• {} - {}\n",
            event_type.id, event_type.description
        ));
        result.push_str(&format!(
            "  Available actions: {}\n",
            event_type.action_names().join(", ")
        ));
    }

    result.push('\n');
    result
}

/// Generate script template instructions for event types
pub fn format_script_template_for_prompt(event_types: &[EventType]) -> String {
    if event_types.is_empty() {
        return String::new();
    }

    let event_ids: Vec<String> = event_types
        .iter()
        .map(|e| format!("\"{}\"", e.id))
        .collect();

    format!(
        r#"
SCRIPT TEMPLATE for this protocol:
When creating a script, structure it with a switch/case on the event type:

Python example:
import json, sys
data = json.load(sys.stdin)
event_type = data['event_type_id']

if event_type == "event_id_1":
    # Handle this event type
    result = {{"actions": [{{"type": "action_name", "param": value}}]}}
elif event_type == "event_id_2":
    # Handle another event type
    result = {{"actions": [{{"type": "other_action", "param": value}}]}}
else:
    # Unknown event - fallback to LLM
    result = {{"fallback_to_llm": true, "fallback_reason": "Unknown event type"}}

print(json.dumps(result))

JavaScript example:
const data = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
const eventType = data.event_type_id;
let result;

switch (eventType) {{
  case "event_id_1":
    result = {{"actions": [{{"type": "action_name", "param": value}}]}};
    break;
  case "event_id_2":
    result = {{"actions": [{{"type": "other_action", "param": value}}]}};
    break;
  default:
    result = {{"fallback_to_llm": true, "fallback_reason": "Unknown event type"}};
}}

console.log(JSON.stringify(result));

Event types for this protocol: {}
"#,
        event_ids.join(", ")
    )
}
