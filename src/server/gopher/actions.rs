//! Gopher (RFC 1436) protocol actions.
//!
//! The model authors the whole gopherspace. Nothing here reads a filesystem, and no action
//! carries raw bytes: a menu is an array of structured items and a document is text, so the
//! model never has to produce or parse wire framing. Assembling the tabs, the CRLFs, the
//! `.\r\n` terminator and the leading-dot escaping is this module's job.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Item types RFC 1436 defines that this server will emit.
///
/// Deliberately a closed set: a menu line whose first character is not a type a client
/// recognises is silently skipped by some clients and rendered as garbage by others, and the
/// model has no way to discover the mistake. Refusing it surfaces as an action failure the
/// operator can see instead.
const SUPPORTED_ITEM_TYPES: &[char] = &['0', '1', '3', '7', '9', 'g', 'I', 'h', 'i'];

/// Host and port an informational (`i`) line carries by convention: it is not a link, so
/// there is nothing to point at. `fake`/`(NULL)`/`0` is what real servers write.
const INFO_SELECTOR: &str = "fake";
const INFO_HOST: &str = "(NULL)";
const INFO_PORT: u64 = 0;

pub struct GopherProtocol;

impl GopherProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GopherProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Make one menu field safe to place between tabs.
///
/// A tab or a CR/LF inside a display string, selector or host would forge an extra field or
/// an extra menu line — the model would be writing menu structure by accident. Every control
/// character becomes a space, which is visible and harmless; substituting rather than deleting
/// is deliberate, because deleting joins the two sides into one word that reads as a single
/// legitimate value.
///
/// Reaching for `utils::sanitize::line_field` rather than matching `\t\r\n` alone also closes
/// ESC, which a Gopher client prints straight to a terminal.
fn sanitize_field(s: &str) -> String {
    crate::utils::sanitize::line_field(s)
}

impl Protocol for GopherProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Gopher is purely reactive: the server says nothing until a selector arrives.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_gopher_menu_action(),
            send_gopher_text_action(),
            send_gopher_error_action(),
            close_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Gopher"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_gopher_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>GOPHER"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["gopher"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(70))
            .well_known_port(70)
            .implementation(
                "Hand-rolled RFC 1436 over a plain tokio TCP loop; no library. One selector \
                 line in, one menu or document out, then the server closes - which is what \
                 RFC 1436 specifies and what a client reading to EOF needs.",
            )
            .llm_control(
                "The entire gopherspace: menu items (type, display, selector, host, port), \
                 document text, and type-3 error items. There is no backing store of any kind.",
            )
            .e2e_testing(
                "tests/server/gopher/e2e_test.rs, 5 tests, 10 mocked LLM calls. Two tests drive the \
                 real curl(1) binary - `curl gopher://127.0.0.1:PORT/1/…` for a menu and `/0/…` for a \
                 document - and hard-fail (never skip) when curl is missing or lacks gopher \
                 support. The other three use a raw TCP socket for what curl cannot show: the \
                 type-7 tab-separated search request, the exact type-3 error bytes, and the \
                 fail-closed reply when the model cannot be reached.",
            )
            .notes(
                "curl strips the item-type character from the URL path, so \
                 gopher://host/1/menu and gopher://host/0/menu send the identical selector \
                 '/menu' - the type in a Gopher URL describes the expected reply, and the \
                 server never sees it. curl passes the reply through verbatim: it neither \
                 removes the terminating '.' line nor undoes the doubled leading dots, so \
                 both appear in its output. Not implemented: Gopher+ (the '+' attribute \
                 protocol), TLS ('gophers'), binary transfers, and any filesystem serving.",
            )
            .max_inbound_bytes(crate::server::gopher::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Gopher (RFC 1436) menu and document server"
    }

    fn example_prompt(&self) -> &'static str {
        "Gopher server on port 70 - serve a root menu with an About text file and a Files \
         directory"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven
            json!({
                "type": "open_server",
                "port": 70,
                "base_stack": "gopher",
                "instruction": "Gopher server. For the empty selector serve a root menu with an \
                                About text file at /about.txt and a Files directory at /files. \
                                For /about.txt serve a short document. Anything else is an error."
            }),
            // Script-based
            json!({
                "type": "open_server",
                "port": 70,
                "base_stack": "gopher",
                "event_handlers": [{
                    "event_pattern": "gopher_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "sel = event.get('selector', '')\nif sel in ('', '/'):\n    respond([{'type': 'send_gopher_menu', 'items': [\n        {'type': 'i', 'display': 'Welcome to the hole'},\n        {'type': '0', 'display': 'About', 'selector': '/about.txt', 'host': '127.0.0.1', 'port': 70}]}])\nelif sel == '/about.txt':\n    respond([{'type': 'send_gopher_text', 'text': 'A gopher server with no disk behind it.'}])\nelse:\n    respond([{'type': 'send_gopher_error', 'message': 'No such selector: ' + sel}])"
                    }
                }]
            }),
            // Static handler
            json!({
                "type": "open_server",
                "port": 70,
                "base_stack": "gopher",
                "event_handlers": [{
                    "event_pattern": "gopher_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_gopher_menu",
                            "items": [
                                {"type": "i", "display": "Welcome to the hole"},
                                {"type": "0", "display": "About", "selector": "/about.txt",
                                 "host": "127.0.0.1", "port": 70},
                                {"type": "1", "display": "Files", "selector": "/files",
                                 "host": "127.0.0.1", "port": 70}
                            ]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for GopherProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::gopher::GopherServer;
            GopherServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_gopher_menu" => self.execute_send_gopher_menu(action),
            "send_gopher_text" => self.execute_send_gopher_text(action),
            "send_gopher_error" => self.execute_send_gopher_error(action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Gopher action: {}", action_type)),
        }
    }
}

impl GopherProtocol {
    /// `<type><display>\t<selector>\t<host>\t<port>\r\n` per item, then `.\r\n`.
    fn execute_send_gopher_menu(&self, action: serde_json::Value) -> Result<ActionResult> {
        let items = action
            .get("items")
            .and_then(|v| v.as_array())
            .context("Missing 'items' parameter (must be an array of menu items)")?;

        if items.is_empty() {
            bail!("'items' must contain at least one menu item");
        }

        let mut out = String::new();
        for (index, item) in items.iter().enumerate() {
            let type_str = item
                .get("type")
                .and_then(|v| v.as_str())
                .with_context(|| format!("Menu item {} is missing 'type'", index))?;

            let mut chars = type_str.chars();
            let item_type = match (chars.next(), chars.next()) {
                (Some(c), None) => c,
                _ => bail!(
                    "Menu item {} has 'type' {:?}; a Gopher item type is exactly one character",
                    index,
                    type_str
                ),
            };
            if !SUPPORTED_ITEM_TYPES.contains(&item_type) {
                bail!(
                    "Menu item {} has unsupported item type '{}'. Supported: {}",
                    index,
                    item_type,
                    SUPPORTED_ITEM_TYPES
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            let display = item
                .get("display")
                .and_then(|v| v.as_str())
                .with_context(|| format!("Menu item {} is missing 'display'", index))?;

            let informational = item_type == 'i';

            let selector = item
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or(if informational { INFO_SELECTOR } else { "" });
            let host = item
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or(if informational {
                    INFO_HOST
                } else {
                    "127.0.0.1"
                });
            let port = item
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(if informational { INFO_PORT } else { 70 });

            out.push(item_type);
            out.push_str(&sanitize_field(display));
            out.push('\t');
            out.push_str(&sanitize_field(selector));
            out.push('\t');
            out.push_str(&sanitize_field(host));
            out.push('\t');
            out.push_str(&port.to_string());
            out.push_str("\r\n");
        }

        out.push_str(".\r\n");
        Ok(ActionResult::Output(out.into_bytes()))
    }

    /// A document: CRLF line endings, leading dots doubled, `.\r\n` terminator.
    ///
    /// The doubling ("periodating") is what keeps a line that genuinely begins with a period
    /// from ending the transfer early; RFC 1436 requires the client to undo it, and clients
    /// that do not (curl) simply show the extra dot.
    fn execute_send_gopher_text(&self, action: serde_json::Value) -> Result<ActionResult> {
        let text = action
            .get("text")
            .and_then(|v| v.as_str())
            .context("Missing 'text' parameter")?;

        // One trailing newline is the natural way to write a document and must not become a
        // blank final line; anything beyond that is the author's own blank line and is kept.
        let body = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);

        let mut out = String::new();
        if !body.is_empty() {
            for line in body.split('\n') {
                let line = line.strip_suffix('\r').unwrap_or(line);
                if line.starts_with('.') {
                    out.push('.');
                }
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        out.push_str(".\r\n");
        Ok(ActionResult::Output(out.into_bytes()))
    }

    /// A type-3 item is the only error Gopher has. The conventional form has an empty
    /// selector, host `error.host` and port `1`, which no client will follow.
    fn execute_send_gopher_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Resource not found");

        let out = format!("3{}\t\terror.host\t1\r\n.\r\n", sanitize_field(message));
        Ok(ActionResult::Output(out.into_bytes()))
    }
}

fn send_gopher_menu_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gopher_menu".to_string(),
        description: "Send a Gopher menu (a directory listing). Give structured items; the server \
             assembles the tab-separated lines and the terminating '.' line. Item types: '0' \
             text file, '1' directory, '3' error, '7' search, '9' binary, 'g' GIF, 'I' image, \
             'h' HTML, 'i' informational text (not a link - selector/host/port are filled in \
             for you). The server closes the connection after this reply, which is what RFC \
             1436 specifies, so do not expect a follow-up request on the same connection."
            .to_string(),
        parameters: vec![Parameter {
            name: "items".to_string(),
            type_hint: "array".to_string(),
            description: "Menu items, in display order. Each is an object: 'type' (one character, \
                 required), 'display' (the text the user sees, required), 'selector' (what the \
                 client sends back to fetch this item; optional, defaults to empty), 'host' \
                 and 'port' (where to fetch it; optional, default 127.0.0.1 and 70)"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_gopher_menu",
            "items": [
                {"type": "i", "display": "Welcome to the gopher hole"},
                {"type": "0", "display": "About this server", "selector": "/about.txt",
                 "host": "127.0.0.1", "port": 70},
                {"type": "1", "display": "Files", "selector": "/files",
                 "host": "127.0.0.1", "port": 70},
                {"type": "7", "display": "Search the archive", "selector": "/search",
                 "host": "127.0.0.1", "port": 70}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gopher menu ({items_len} items)")
                .with_debug("Gopher send_gopher_menu: {items_len} items")
                .with_trace("Gopher menu: {json_pretty(items)}"),
        ),
    }
}

fn send_gopher_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gopher_text".to_string(),
        description: "Send a Gopher text document (item type '0'). Give plain text with ordinary \
             newlines; the server converts them to CRLF, escapes any line that begins with a \
             period, and appends the terminating '.' line. The server closes the connection \
             after this reply, which is what RFC 1436 specifies."
            .to_string(),
        parameters: vec![Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "The document body, as plain text".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_gopher_text",
            "text": "About this server\n-----------------\n\nA gopher hole with no disk behind it.\n"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gopher document ({text_len}B)")
                .with_debug("Gopher send_gopher_text: {text_len} bytes")
                .with_trace("Gopher document: {preview(text, 400)}"),
        ),
    }
}

fn send_gopher_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gopher_error".to_string(),
        description:
            "Reply with a Gopher type-3 error item - the only error the protocol has. Use it \
             for an unknown selector. The server closes the connection afterwards."
                .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Error text shown to the user".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_gopher_error",
            "message": "No such selector: /nope"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gopher error: {message}")
                .with_debug("Gopher send_gopher_error: {message}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description:
            "Close the Gopher connection immediately, without a reply. The server already \
             closes after every reply, so this is only needed to hang up on a request you do \
             not want to answer at all."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Gopher connection closed")
                .with_debug("Gopher close_connection"),
        ),
    }
}

/// Raised once per connection, when the client's selector line arrives.
///
/// `search_query` is present only for a type-7 request, where the client sends
/// `<selector>\t<query>`. Its absence is meaningful - it distinguishes "open the search form"
/// from "search for the empty string".
pub static GOPHER_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gopher_request",
        "Client sent a Gopher selector (empty selector means the root menu)",
        json!({
            "type": "send_gopher_menu",
            "items": [
                {"type": "i", "display": "Welcome to the gopher hole"},
                {"type": "0", "display": "About this server", "selector": "/about.txt",
                 "host": "127.0.0.1", "port": 70},
                {"type": "1", "display": "Files", "selector": "/files",
                 "host": "127.0.0.1", "port": 70}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "selector".to_string(),
            type_hint: "string".to_string(),
            description:
                "The selector the client asked for. Empty means the root menu. Note that a \
                 Gopher URL's item-type character is not sent by the client, so this is the \
                 path only."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "search_query".to_string(),
            type_hint: "string".to_string(),
            description:
                "The search terms, present only when the client made a type-7 search request \
                 (selector and query separated by a tab)"
                    .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Gopher {selector}")
            .with_debug("Gopher request: selector={selector} search_query={search_query}")
            .with_trace("Gopher: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_gopher_menu_action(),
        send_gopher_text_action(),
        send_gopher_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_gopher_text",
        "text": "About this server\n-----------------\n\nA gopher hole with no disk behind it.\n"
    }))
});

pub fn get_gopher_event_types() -> Vec<EventType> {
    vec![GOPHER_REQUEST_EVENT.clone()]
}
