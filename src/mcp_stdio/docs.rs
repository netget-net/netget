//! MCP-shaped protocol documentation.
//!
//! The model's own `read_documentation` tool (`llm::actions::tools`) frames a
//! protocol around the `open_server` / `open_client` **actions**. Neither exists
//! on the MCP surface: an MCP caller has `start_server` / `start_client` tools
//! with a fixed argument list.
//!
//! This module renders documentation aimed at an MCP caller — the exact tool
//! arguments that apply, the protocol's event ids with their field names and
//! types (needed to write an `event_handlers` script), its action names with
//! parameter schemas and examples, its startup parameters, its privilege
//! requirement, its maturity, what it writes when the model cannot answer
//! (`failure_mode`), and whether it keeps per-connection state (`connectionless`).
//!
//! Every action is rendered in full — parameters and a JSON example — including
//! the async ones, because those are invocable from MCP: a client's through
//! `send_to_client`, a server's through `send_to_peer` on a connection whose
//! protocol registers a peer handle.
//!
//! Nothing here mentions `open_server`, `open_client` or `base_stack`.
//!
//! What it says about the protocol itself — events and their fields, actions and their
//! parameters, startup parameters and their defaults — comes from the renderers in
//! `crate::protocol::docs`, which the model's `read_documentation` and `--docs` use too.

use std::fmt::Write as _;

use crate::llm::actions::ActionDefinition;
use crate::protocol::docs::{failure_mode_text, render_action, render_event, render_startup_param};
use crate::state::app_state::AppState;

/// Render MCP-shaped documentation for one protocol.
///
/// Returns `None` when the protocol is in neither registry (i.e. not compiled
/// into this build).
pub async fn render_protocol_docs(protocol: &str, state: &AppState) -> Option<String> {
    let server_registry = crate::protocol::server_registry::registry();
    let client_registry = &crate::protocol::CLIENT_REGISTRY;

    // Registries disagree on case: servers are keyed upper-ish, clients lower-ish.
    // Try the parse helpers first, then the raw casings.
    let server = server_registry
        .parse_from_str(protocol)
        .and_then(|name| server_registry.get(&name))
        .or_else(|| server_registry.get(protocol))
        .or_else(|| server_registry.get(&protocol.to_uppercase()))
        .or_else(|| server_registry.get(&protocol.to_lowercase()));

    let client = client_registry
        .parse_from_str(protocol)
        .and_then(|name| client_registry.get(&name))
        .or_else(|| client_registry.get(protocol))
        .or_else(|| client_registry.get(&protocol.to_lowercase()))
        .or_else(|| client_registry.get(&protocol.to_uppercase()));

    if server.is_none() && client.is_none() {
        return None;
    }

    let mut out = String::new();
    let _ = writeln!(out, "# `{}` — MCP reference\n", protocol.to_lowercase());

    match (server.is_some(), client.is_some()) {
        (true, true) => out.push_str(
            "Available as a **server** (`start_server`) and as a **client** (`start_client`).\n\n",
        ),
        (true, false) => out.push_str(
            "Available as a **server** (`start_server`). No client implementation is compiled in.\n\n",
        ),
        (false, true) => out.push_str(
            "Available as a **client** (`start_client`). No server implementation is compiled in.\n\n",
        ),
        (false, false) => unreachable!(),
    }

    if let Some(server) = server {
        let metadata = server.metadata();
        let binding = server.default_binding();

        let _ = writeln!(out, "## Server — `start_server`\n");
        let _ = writeln!(out, "{}\n", server.description());
        let _ = writeln!(out, "- **maturity**: {}", metadata.state.as_str());
        let _ = writeln!(
            out,
            "- **privilege required**: {}",
            metadata.privilege_requirement.description()
        );
        let _ = writeln!(out, "- **network stack**: {}", server.stack_name());
        let _ = writeln!(out, "- **implementation**: {}", metadata.implementation);
        let _ = writeln!(out, "- **LLM controls**: {}", metadata.llm_control);
        let _ = writeln!(
            out,
            "- **when the model cannot answer**: {}",
            failure_mode_text(metadata.failure_mode)
        );
        let _ = writeln!(
            out,
            "- **connections**: {}",
            if metadata.connectionless {
                "connectionless — each datagram stands alone; a peer idle for ~10s is \
                 forgotten, and there is no per-connection state to rely on"
            } else {
                "connection-oriented — each peer has a connection id (see `server_status`) \
                 that lives until either side closes it"
            }
        );
        let _ = writeln!(out, "- **history**: {}", metadata.history.describe());
        let _ = writeln!(out, "- **batching**: {}", metadata.batching.describe());
        if let Some(notes) = metadata.notes {
            let _ = writeln!(out, "- **notes**: {}", notes);
        }
        out.push('\n');

        // --- start_server arguments -----------------------------------------
        out.push_str("### `start_server` arguments\n\n");
        let _ = writeln!(
            out,
            "- `protocol` (string, **required**) — `\"{}\"`",
            protocol.to_lowercase()
        );

        let interface_based = binding
            .as_ref()
            .map(|b| b.interface.is_some())
            .unwrap_or(false);

        if interface_based {
            let default_iface = binding
                .as_ref()
                .and_then(|b| b.interface.clone())
                .unwrap_or_else(|| "lo".to_string());
            let _ = writeln!(
                out,
                "- `interface` (string) — NIC to bind. This protocol is interface-bound, \
                 not port-bound. Default `\"{}\"`.",
                default_iface
            );
            let _ = writeln!(
                out,
                "- `mac_address` (string) — source MAC for layer-2 frames, e.g. \
                 `\"02:00:00:00:00:01\"`. Optional."
            );
            out.push_str("- `port` / `host` — ignored by this protocol.\n");
        } else {
            let default_host = binding
                .as_ref()
                .and_then(|b| b.host.clone())
                .unwrap_or_else(|| crate::protocol::default_port::DEFAULT_HOST.to_string());
            // The same resolution `start_server` applies when `port` is omitted, against this
            // process's privilege and what is bound right now.
            let caps = state.get_system_capabilities().await;
            let default = crate::protocol::default_port::default_port_for_server(
                server.as_ref(),
                None,
                &caps,
            );
            match default.as_ref().map(|d| (d.well_known, d.fallback, d.port)) {
                Some((Some(p), None, _)) => {
                    let _ = writeln!(
                        out,
                        "- `port` (number) — listen port. Omit it for the well-known port \
                         `{p}`. Pass `0` for an OS-assigned port; an explicit port, `0` \
                         included, is always used as given."
                    );
                }
                Some((Some(_), Some(_), _)) => {
                    let _ = writeln!(
                        out,
                        "- `port` (number) — listen port. Omitted, this server starts on an \
                         OS-assigned port: {}. The chosen port is reported in the tool result \
                         and by `list_servers`. An explicit port is always used as given.",
                        default.as_ref().map(|d| d.describe()).unwrap_or_default()
                    );
                }
                _ => out.push_str(
                    "- `port` (number) — listen port. This protocol has no well-known port, so \
                     omitting it (or passing `0`) asks the OS for a free one; the chosen port is \
                     reported in the tool result and by `list_servers`.\n",
                ),
            }
            let _ = writeln!(
                out,
                "- `host` (string) — bind address. Default `\"{}\"`.",
                default_host
            );
        }

        out.push_str(
            "- `event_handlers` (array) — **preferred**. Deterministic, in-process, no LLM \
             call. Each entry is `{\"event_pattern\": \"<event id>\" | \"*\", \"handler\": {…}}`, \
             matched in order, first match wins; an optional `\"match\": {\"method\": \"GET\", \
             \"path\": \"/a\"}` narrows a rule to events whose fields equal those values \
             (keys are field paths like `headers.host`). `handler` is one of `{\"type\":\"script\",\
             \"language\":\"python\"|\"javascript\",\"code\":\"…\"}`, \
             `{\"type\":\"static\",\"actions\":[…]}`, or `{\"type\":\"llm\",\"instruction\":\"…\"}`. \
             A script receives the event as JSON on stdin (fields under `data['event']`) and \
             must print `{\"actions\":[…]}` to stdout. Use the event ids and field names \
             listed below.\n",
        );
        out.push_str(
            "- `instruction` (string) — natural-language fallback. Costs one model call per \
             event; use only when the response genuinely needs reasoning.\n",
        );

        let startup_params = server.get_startup_parameters();
        if startup_params.is_empty() {
            out.push_str("- `startup_params` (object) — this protocol declares none.\n");
        } else {
            let names: Vec<String> = startup_params
                .iter()
                .map(|p| format!("`{}`", p.name))
                .collect();
            let _ = writeln!(
                out,
                "- `startup_params` (object) — this protocol accepts {}. Schema below. \
                 Passing a key this protocol does not declare is an error.",
                names.join(", ")
            );
        }

        if startup_params.iter().any(|p| p.name == "send_first") {
            out.push_str(
                "- `send_first` (boolean) — when true the server speaks first on connect \
                 (FTP/SMTP-style greeting banner) instead of waiting for the client. \
                 Equivalent to `startup_params.send_first`.\n",
            );
        }

        out.push_str(
            "- `initial_memory` (string) — seeds the server's LLM memory before the first \
             event.\n",
        );
        out.push_str(
            "- `feedback_instructions` (string) — natural-language instructions for the \
             automatic feedback loop that adjusts the server as it runs.\n",
        );
        out.push_str(
            "- `scheduled_tasks` (array) — server-scoped recurring/delayed LLM tasks. Each \
             entry: `{\"task_id\":\"…\",\"recurring\":true,\"interval_secs\":60,\
             \"instruction\":\"…\"}` (or `\"recurring\":false` with `\"delay_secs\"`). \
             Removed when the server stops.\n",
        );
        out.push_str(
            "- `history` (number) — earlier exchanges on the same connection the model is shown \
             with each event; 0 turns it off. Omit for the default above.\n",
        );
        out.push_str(
            "- `batching` (boolean) — deliver events that arrive during a call together \
             afterwards. Omit for the default above.\n",
        );
        out.push_str(
            "- `memoize_ttl_secs` (number) — memoise the model's answers: for this many \
             seconds an event identical to one the model already answered (ignoring per-request \
             ids such as a DNS `query_id`, which the replay echoes back) gets the same actions \
             with no model call, recorded in the access log as answered by `cache`. Off unless \
             set; 0 turns it off. Failures, answers that change memory or tasks, and \
             credential-bearing events are never memoised. With `history` on, answers are kept \
             per connection unless `memoize_across_connections` is true. To replay recorded \
             traffic with no model at all, use the `export_rules` tool instead.\n",
        );
        out.push('\n');

        // --- events ----------------------------------------------------------
        let event_types = server.get_event_types();
        if event_types.is_empty() {
            out.push_str(
                "### Events\n\nThis protocol declares no event types, so `event_handlers` \
                 cannot be targeted at a specific event id — use `\"event_pattern\": \"*\"` \
                 or the `instruction` fallback.\n\n",
            );
        } else {
            let ids: Vec<String> = event_types.iter().map(|e| format!("`{}`", e.id)).collect();
            let _ = writeln!(
                out,
                "### Events ({}) — valid values for `event_pattern`\n",
                ids.join(", ")
            );
            for event in &event_types {
                render_event(&mut out, event, "####");
            }
        }

        // --- actions ---------------------------------------------------------
        let sync_actions = server.get_sync_actions();
        if !sync_actions.is_empty() {
            out.push_str(
                "### Response actions\n\nThese are the action objects a handler may return \
                 (inside `{\"actions\":[…]}` for a script, or as `handler.actions` for a \
                 static handler).\n\n",
            );
            for action in &sync_actions {
                render_action(&mut out, action, "####");
            }
        }

        let async_actions: Vec<ActionDefinition> = server
            .get_async_actions(state)
            .into_iter()
            .filter(|a| !sync_actions.iter().any(|s| s.name == a.name))
            .collect();
        if !async_actions.is_empty() {
            out.push_str(
                "### Server-level actions\n\nThese are not tied to one event. The \
                 `instruction` LLM can use them, and on a live connection whose protocol \
                 registers a peer handle (`server_status` marks those) `send_to_peer` \
                 accepts them alongside the response actions above.\n\n",
            );
            for action in &async_actions {
                render_action(&mut out, action, "####");
            }
        }

        // --- startup params ---------------------------------------------------
        if !startup_params.is_empty() {
            out.push_str("### `startup_params` schema\n\n");
            for param in &startup_params {
                render_startup_param(&mut out, param);
            }
            out.push('\n');
        }

        out.push_str("---\n\n");
    }

    if let Some(client) = client {
        let metadata = client.metadata();

        let _ = writeln!(out, "## Client — `start_client`\n");
        let _ = writeln!(out, "{}\n", client.description());
        let _ = writeln!(out, "- **maturity**: {}", metadata.state.as_str());
        let _ = writeln!(
            out,
            "- **privilege required**: {}",
            metadata.privilege_requirement.description()
        );
        let _ = writeln!(out, "- **network stack**: {}", client.stack_name());
        let _ = writeln!(out, "- **implementation**: {}", metadata.implementation);
        let _ = writeln!(out, "- **LLM controls**: {}", metadata.llm_control);
        let _ = writeln!(out, "- **history**: {}", metadata.history.describe());
        let _ = writeln!(out, "- **batching**: {}", metadata.batching.describe());
        if let Some(notes) = metadata.notes {
            let _ = writeln!(out, "- **notes**: {}", notes);
        }
        out.push('\n');

        out.push_str("### `start_client` arguments\n\n");
        let _ = writeln!(
            out,
            "- `protocol` (string, **required**) — `\"{}\"`",
            protocol.to_lowercase()
        );
        out.push_str(
            "- `remote_addr` (string, **required**) — the server to connect to, \
             `host:port` (e.g. `\"127.0.0.1:6379\"`).\n",
        );
        out.push_str(
            "- `event_handlers` (array) — same shape as `start_server`; deterministic, no \
             LLM call. Target the client event ids listed below.\n",
        );
        out.push_str(
            "- `instruction` (string) — natural-language fallback, one model call per \
             event.\n",
        );

        let startup_params = client.get_startup_parameters();
        if startup_params.is_empty() {
            out.push_str("- `startup_params` (object) — this protocol declares none.\n");
        } else {
            let names: Vec<String> = startup_params
                .iter()
                .map(|p| format!("`{}`", p.name))
                .collect();
            let _ = writeln!(
                out,
                "- `startup_params` (object) — this protocol accepts {}. Schema below.",
                names.join(", ")
            );
        }
        out.push_str("- `initial_memory` (string) — seeds the client's LLM memory.\n");
        out.push_str(
            "- `feedback_instructions` (string) — instructions for the automatic feedback \
             loop.\n",
        );
        out.push_str(
            "- `scheduled_tasks` (array) — client-scoped recurring/delayed LLM tasks, same \
             shape as for `start_server`.\n",
        );
        out.push_str(
            "- `history` (number) — earlier exchanges on the same connection the model is shown \
             with each event; 0 turns it off. Omit for the default above.\n",
        );
        out.push_str(
            "- `batching` (boolean) — deliver events that arrive during a call together \
             afterwards. Omit for the default above.\n",
        );
        out.push_str(
            "- `memoize_ttl_secs` (number) — memoise the model's answers: for this many \
             seconds an event identical to one the model already answered (ignoring per-request \
             ids such as a DNS `query_id`, which the replay echoes back) gets the same actions \
             with no model call, recorded in the access log as answered by `cache`. Off unless \
             set; 0 turns it off. Failures, answers that change memory or tasks, and \
             credential-bearing events are never memoised. With `history` on, answers are kept \
             per connection unless `memoize_across_connections` is true. To replay recorded \
             traffic with no model at all, use the `export_rules` tool instead.\n",
        );
        out.push('\n');

        let event_types = client.get_event_types();
        if event_types.is_empty() {
            out.push_str(
                "### Events\n\nThis client declares no event types; use \
                 `\"event_pattern\": \"*\"` or the `instruction` fallback.\n\n",
            );
        } else {
            let ids: Vec<String> = event_types.iter().map(|e| format!("`{}`", e.id)).collect();
            let _ = writeln!(
                out,
                "### Events ({}) — valid values for `event_pattern`\n",
                ids.join(", ")
            );
            for event in &event_types {
                render_event(&mut out, event, "####");
            }
        }

        let sync_actions = client.get_sync_actions();
        if !sync_actions.is_empty() {
            out.push_str("### Response actions\n\nAction objects a client handler may return.\n\n");
            for action in &sync_actions {
                render_action(&mut out, action, "####");
            }
        }

        let async_actions: Vec<ActionDefinition> = client
            .get_async_actions(state)
            .into_iter()
            .filter(|a| !sync_actions.iter().any(|s| s.name == a.name))
            .collect();
        if !async_actions.is_empty() {
            out.push_str(
                "### Client actions\n\nWhat the client can do on its own initiative. The \
                 `instruction` LLM and handlers can use them, and `send_to_client` puts any \
                 of them — or of the response actions above — on the wire now.\n\n",
            );
            for action in &async_actions {
                render_action(&mut out, action, "####");
            }
        } else if !sync_actions.is_empty() {
            out.push_str(
                "`send_to_client` accepts any of the response actions above to put one on \
                 the wire now.\n\n",
            );
        }

        if !startup_params.is_empty() {
            out.push_str("### `startup_params` schema\n\n");
            for param in &startup_params {
                render_startup_param(&mut out, param);
            }
            out.push('\n');
        }
    }

    Some(out)
}
