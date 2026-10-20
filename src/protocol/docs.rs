//! Protocol documentation: the shared renderers, and the `--docs` dump.
//!
//! Three surfaces describe a protocol: the model's own `read_documentation` tool
//! (`llm::actions::tools`), MCP's `get_protocol_docs` (`mcp_stdio::docs`) and the `--docs`
//! flag below. Their framing differs — the model starts instances with `open_server` /
//! `open_client`, an MCP caller with `start_server` / `start_client` — but what they say
//! about the protocol itself must not: an event's field names (a script handler reads `path`,
//! not `uri`), an action's parameter schema, a startup parameter's default. Every one of
//! those is rendered by the functions in this module and nowhere else, so the three cannot
//! drift apart.

use std::fmt::Write as _;

use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition};
use crate::protocol::metadata::{FailureMode, ProtocolMetadataV2};
use crate::protocol::EventType;
use crate::state::app_state::AppState;

/// What `failure_mode` means for a peer, in one sentence.
pub fn failure_mode_text(mode: FailureMode) -> &'static str {
    match mode {
        FailureMode::Answers => {
            "answers — the peer gets the protocol's own error reply carrying a category \
             (overloaded or unavailable), never an invented success and never the error text"
        }
        FailureMode::DeliberatelySilent => {
            "deliberately silent — nothing is written, because every reply this protocol \
             defines would assert something the server does not know; the log records \
             `decision=…` instead"
        }
    }
}

/// What a server started without a `port` listens on, from its declared well-known port.
///
/// Static on purpose: it names the declared port and the rule, not this process's privilege
/// or what is bound right now (MCP's `get_protocol_docs` resolves that live).
pub fn well_known_port_text(metadata: &ProtocolMetadataV2) -> String {
    match metadata.well_known_port {
        Some(port) => format!(
            "omit `port` to listen on the well-known port {port} ({}). If this process cannot \
             bind it (below 1024 without privilege, or already in use) the server starts on an \
             OS-assigned port and the result says so. An explicit port, `0` included, is used \
             as given.",
            metadata.well_known_transport.as_str()
        ),
        None => "this protocol has no well-known port; omit `port` (or pass `0`) for an \
                 OS-assigned port, reported when the server starts."
            .to_string(),
    }
}

/// A server's `open_server` examples (`get_startup_examples()`), as the documentation shows
/// them.
///
/// Many protocols wrote their examples with the old `base_stack` key and a placeholder
/// `"port": 8080`. `open_server` reads `base_stack` as `protocol`, so the key is shown under
/// its real name; and the port is left out, because an omitted port is the protocol's
/// well-known port (the **Port** line beside the examples says which) and a model copies the
/// example's number instead of the one the user asked for.
pub fn server_startup_examples_text(mut examples: crate::llm::actions::StartupExamples) -> String {
    for example in [
        &mut examples.llm_mode,
        &mut examples.script_mode,
        &mut examples.static_mode,
    ] {
        if let Some(obj) = example.as_object_mut() {
            if let Some(stack) = obj.remove("base_stack") {
                obj.entry("protocol").or_insert(stack);
            }
            obj.remove("port");
        }
    }
    examples.to_prompt_text()
}

/// One event: its description, the fields of its data, what may answer it, and an example
/// handler response. `heading` is the Markdown heading prefix for the event's own title
/// (`"####"`, `"###"`).
pub fn render_event(out: &mut String, event: &EventType, heading: &str) {
    let _ = writeln!(out, "{heading} `{}`\n", event.id);
    let _ = writeln!(out, "{}\n", event.description);

    if event.parameters.is_empty() {
        out.push_str("Event data: (no documented fields)\n\n");
    } else {
        out.push_str("Event data fields (a script reads these as `data['event'][…]`):\n\n");
        for param in &event.parameters {
            render_parameter(out, param);
        }
        out.push('\n');
    }

    let action_names: Vec<String> = event
        .actions
        .iter()
        .map(|a| format!("`{}`", a.name))
        .collect();
    if !action_names.is_empty() {
        let _ = writeln!(out, "Respond with: {}\n", action_names.join(", "));
    }

    out.push_str("Example handler response:\n\n```json\n");
    let example = serde_json::json!({ "actions": [event.effective_response_example()] });
    out.push_str(&serde_json::to_string_pretty(&example).unwrap_or_default());
    out.push_str("\n```\n\n");

    for alt in &event.alternative_examples {
        out.push_str("Alternative:\n\n```json\n");
        let example = serde_json::json!({ "actions": [alt.clone()] });
        out.push_str(&serde_json::to_string_pretty(&example).unwrap_or_default());
        out.push_str("\n```\n\n");
    }
}

/// One action: its description, its parameter schema and its JSON example.
pub fn render_action(out: &mut String, action: &ActionDefinition, heading: &str) {
    let _ = writeln!(out, "{heading} `{}`\n", action.name);
    let _ = writeln!(out, "{}\n", action.description);
    if action.parameters.is_empty() {
        out.push_str("Parameters: none.\n\n");
    } else {
        out.push_str("Parameters:\n\n");
        for param in &action.parameters {
            render_parameter(out, param);
        }
        out.push('\n');
    }
    out.push_str("```json\n");
    out.push_str(&serde_json::to_string_pretty(&action.example).unwrap_or_default());
    out.push_str("\n```\n\n");
}

/// One field of an event or parameter of an action, as a list item.
pub fn render_parameter(out: &mut String, param: &Parameter) {
    let _ = writeln!(
        out,
        "- `{}` ({}, {}) — {}",
        param.name,
        param.type_hint,
        if param.required {
            "**required**"
        } else {
            "optional"
        },
        param.description
    );
}

/// One startup parameter, as a list item, with the value the protocol uses when it is
/// omitted where the protocol declares one (`ParameterDefinition::default`).
pub fn render_startup_param(out: &mut String, param: &ParameterDefinition) {
    let example = serde_json::to_string(&param.example).unwrap_or_default();
    let default = param
        .default
        .as_ref()
        .map(|d| {
            format!(
                ", default: `{}`",
                serde_json::to_string(d).unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "- `{}` ({}, {}{}) — {} Example: `{}`",
        param.name,
        param.type_hint,
        if param.required {
            "**required**"
        } else {
            "optional"
        },
        default,
        param.description,
        example
    );
}

/// The async actions not already among the sync ones — what an instance can do on its own
/// initiative rather than in answer to an event.
pub fn instance_only_actions<P: Protocol + ?Sized>(
    p: &P,
    sync_actions: &[ActionDefinition],
    state: &AppState,
) -> Vec<ActionDefinition> {
    p.get_async_actions(state)
        .into_iter()
        .filter(|a| !sync_actions.iter().any(|s| s.name == a.name))
        .collect()
}

/// A fresh application state, for documentation rendered where no live one is at hand.
///
/// `get_async_actions` takes the state; what a newly started instance would be offered is
/// what the documentation describes. Built once per process, because building one probes
/// the scripting environment.
pub fn fresh_state() -> &'static AppState {
    static STATE: std::sync::LazyLock<AppState> = std::sync::LazyLock::new(AppState::new);
    &STATE
}

/// Render documentation for every server and client protocol in this build (`--docs`).
pub fn render_all_protocol_docs() -> String {
    let state = fresh_state();

    let mut out = String::new();
    out.push_str("# NetGet protocol documentation\n\n");
    out.push_str(
        "Every protocol compiled into this binary: what it is, its startup parameters, the \
         events it raises with their fields, and every action it accepts with its parameters \
         — the same descriptions the model and MCP's `get_protocol_docs` are given. Names in \
         parentheses are keywords you can use in a prompt.\n\n",
    );

    // Servers
    let server_registry = crate::protocol::server_registry::registry();
    let mut servers = server_registry.all_protocols();
    servers.sort_by(|a, b| a.0.cmp(&b.0));
    out.push_str(&format!("## Server protocols ({})\n\n", servers.len()));
    for (name, p) in &servers {
        let port = well_known_port_text(&p.metadata());
        let examples = server_startup_examples_text(p.get_startup_examples());
        out.push_str(&render_protocol_doc(
            name,
            p.as_ref(),
            Some(&port),
            Some(&examples),
            state,
        ));
    }

    // Clients
    let mut client_names = crate::protocol::CLIENT_REGISTRY.list_protocols();
    client_names.sort();
    out.push_str(&format!("## Client protocols ({})\n\n", client_names.len()));
    for name in &client_names {
        if let Some(p) = crate::protocol::CLIENT_REGISTRY.get(name) {
            let examples = p.get_startup_examples().to_prompt_text();
            out.push_str(&render_protocol_doc(
                name,
                p.as_ref(),
                None,
                Some(&examples),
                state,
            ));
        }
    }

    out
}

fn render_protocol_doc<P: Protocol + ?Sized>(
    name: &str,
    p: &P,
    port: Option<&str>,
    examples: Option<&str>,
    state: &AppState,
) -> String {
    let mut s = String::new();
    let meta = p.metadata();

    let keywords = p.keywords();
    if keywords.is_empty() {
        s.push_str(&format!("### {}\n\n", name));
    } else {
        s.push_str(&format!("### {} ({})\n\n", name, keywords.join(", ")));
    }
    s.push_str(&format!("- Stack: `{}`\n", p.stack_name()));
    s.push_str(&format!("- Maturity: {}\n", meta.state.as_str()));
    s.push_str(&format!(
        "- Privilege: {}\n",
        meta.privilege_requirement.description()
    ));
    let desc = p.description();
    if !desc.is_empty() {
        s.push_str(&format!("- Description: {}\n", desc));
    }
    if !keywords.is_empty() {
        s.push_str(&format!("- Keywords: {}\n", keywords.join(", ")));
    }
    if let Some(port) = port {
        s.push_str(&format!("- Port: {}\n", port));
    }
    s.push_str(&format!("- History: {}\n", meta.history.describe()));
    s.push_str(&format!("- Batching: {}\n", meta.batching.describe()));
    if let Some(notes) = meta.notes {
        s.push_str(&format!("- Notes: {}\n", notes));
    }
    s.push('\n');

    let params = p.get_startup_parameters();
    if !params.is_empty() {
        s.push_str("**Startup parameters:**\n\n");
        for param in &params {
            render_startup_param(&mut s, param);
        }
        s.push('\n');
    }

    let events = p.get_event_types();
    if !events.is_empty() {
        s.push_str("**Events:**\n\n");
        for ev in &events {
            render_event(&mut s, ev, "####");
        }
    }

    let sync_actions = p.get_sync_actions();
    if !sync_actions.is_empty() {
        s.push_str("**Response actions** (answer an event):\n\n");
        for action in &sync_actions {
            render_action(&mut s, action, "####");
        }
    }

    let own_actions = instance_only_actions(p, &sync_actions, state);
    if !own_actions.is_empty() {
        s.push_str("**Instance actions** (taken on the instance's own initiative):\n\n");
        for action in &own_actions {
            render_action(&mut s, action, "####");
        }
    }

    // Setup examples (LLM / script / static).
    if let Some(examples) = examples.filter(|e| !e.trim().is_empty()) {
        s.push_str("**Examples:**\n\n");
        s.push_str(examples);
        s.push('\n');
    }

    s.push('\n');
    s
}
