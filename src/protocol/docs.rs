//! Human-readable documentation dump for every compiled-in protocol.
//!
//! Backs the `--docs` CLI flag. Renders, for each registered server and client
//! protocol, what the model is told about it: base-stack identity, keywords,
//! startup parameters, events and their actions, and setup examples. Everything
//! is read live from the registries and the `Protocol` trait, so it never goes
//! stale relative to the build.

use crate::llm::actions::protocol_trait::Protocol;

/// Render documentation for every server and client protocol in this build.
pub fn render_all_protocol_docs() -> String {
    let mut out = String::new();
    out.push_str("# NetGet protocol documentation\n\n");
    out.push_str(
        "Every protocol compiled into this binary, as the model sees it. Names in \
         parentheses are keywords you can use in a prompt.\n\n",
    );

    // Servers
    let server_registry = crate::protocol::server_registry::registry();
    let mut servers = server_registry.all_protocols();
    servers.sort_by(|a, b| a.0.cmp(&b.0));
    out.push_str(&format!("## Server protocols ({})\n\n", servers.len()));
    for (name, p) in &servers {
        out.push_str(&render_protocol_doc(name, p.as_ref()));
    }

    // Clients
    let mut client_names = crate::protocol::CLIENT_REGISTRY.list_protocols();
    client_names.sort();
    out.push_str(&format!("## Client protocols ({})\n\n", client_names.len()));
    for name in &client_names {
        if let Some(p) = crate::protocol::CLIENT_REGISTRY.get(name) {
            out.push_str(&render_protocol_doc(name, p.as_ref()));
        }
    }

    out
}

fn render_protocol_doc<P: Protocol + ?Sized>(name: &str, p: &P) -> String {
    let mut s = String::new();
    let meta = p.metadata();

    s.push_str(&format!("### {}\n", name));
    s.push_str(&format!("- Stack: `{}`\n", p.stack_name()));
    s.push_str(&format!("- Maturity: {:?}\n", meta.state));
    s.push_str(&format!("- Privilege: {:?}\n", meta.privilege_requirement));
    let desc = p.description();
    if !desc.is_empty() {
        s.push_str(&format!("- Description: {}\n", desc));
    }
    let keywords = p.keywords();
    if !keywords.is_empty() {
        s.push_str(&format!("- Keywords: {}\n", keywords.join(", ")));
    }
    s.push_str(&format!("- History: {}\n", meta.history.describe()));
    s.push_str(&format!("- Batching: {}\n", meta.batching.describe()));
    if let Some(notes) = meta.notes {
        s.push_str(&format!("- Notes: {}\n", notes));
    }

    // Startup parameters
    let params = p.get_startup_parameters();
    if !params.is_empty() {
        s.push_str("\n**Startup parameters:**\n");
        for param in &params {
            let req = if param.required {
                "required"
            } else {
                "optional"
            };
            s.push_str(&format!(
                "- `{}` ({}, {}): {}\n",
                param.name, param.type_hint, req, param.description
            ));
        }
    }

    // Events and the actions attached to each
    let events = p.get_event_types();
    if !events.is_empty() {
        s.push_str("\n**Events:**\n");
        for ev in &events {
            s.push_str(&format!("- `{}` — {}\n", ev.id, ev.description));
            for action in &ev.actions {
                s.push_str(&format!(
                    "    - action `{}`: {}\n",
                    action.name, action.description
                ));
            }
        }
    }

    // Sync (user/network triggered) actions declared outside an event
    let sync_actions = p.get_sync_actions();
    if !sync_actions.is_empty() {
        s.push_str("\n**Actions:**\n");
        for action in &sync_actions {
            s.push_str(&format!("- `{}`: {}\n", action.name, action.description));
            for param in &action.parameters {
                let req = if param.required {
                    "required"
                } else {
                    "optional"
                };
                s.push_str(&format!(
                    "    - `{}` ({}, {}): {}\n",
                    param.name, param.type_hint, req, param.description
                ));
            }
        }
    }

    // Setup examples (LLM / script / static), if the protocol provides real ones
    let examples = p.get_startup_examples().to_prompt_text();
    if !examples.trim().is_empty() {
        s.push_str("\n**Examples:**\n");
        s.push_str(&examples);
        s.push('\n');
    }

    s.push('\n');
    s
}
