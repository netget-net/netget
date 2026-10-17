//! Gopher (RFC 1436) client protocol actions.
//!
//! The model browses gopherspace: it asks for a selector, is handed the reply **already
//! parsed** — a menu as structured items, a document as text, a type-3 item as an error —
//! and decides what to fetch next. Nothing here carries wire framing: no tabs, no CRLFs, no
//! terminating `.` line, and nothing base64.
//!
//! ## Why every action is declared once, in `get_async_actions`
//!
//! A client has one LLM entry point (`call_llm_for_client`), which advertises
//! `client_llm_action_set` = async ∪ sync ∪ the firing event's own list. A client therefore
//! cannot express a narrowing, and duplicating the list into `get_sync_actions()` — which
//! roughly forty clients in this tree do — buys nothing. `get_sync_actions()` is empty and
//! the event types attach no actions of their own; the union is exactly this list either way.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// The `ClientActionResult::Custom` name both fetch verbs produce.
///
/// `send_gopher_request` and `send_gopher_search` differ only in whether a query is attached,
/// so they converge on one custom result and the connection loop has a single fetch path.
pub const GOPHER_FETCH_RESULT: &str = "gopher_fetch";

/// Default item type when the model does not say what it expects.
///
/// `1` (a directory/menu) is the right default because the only request whose type is
/// genuinely unknown in advance is the very first one, and that is the root menu.
pub const DEFAULT_ITEM_TYPE: char = '1';

/// A menu arrived and was parsed into items.
pub static GOPHER_MENU_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gopher_menu_received",
        "A Gopher menu was fetched and parsed into items",
        json!({
            "type": "send_gopher_request",
            "selector": "/about.txt",
            "item_type": "0",
            "host": "127.0.0.1",
            "port": 70
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "selector".to_string(),
            type_hint: "string".to_string(),
            description: "The selector that was asked for (empty means the root menu)".to_string(),
            required: true,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "Host the menu came from".to_string(),
            required: true,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Port the menu came from".to_string(),
            required: true,
        },
        Parameter {
            name: "item_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many items the menu contains".to_string(),
            required: true,
        },
        Parameter {
            name: "items".to_string(),
            type_hint: "array".to_string(),
            description:
                "The menu items in order. Each is an object with 'item_type' (one character), \
                 'item_type_name' (what that character means), 'display' (the text a user \
                 sees), 'selector', 'host' and 'port'. To follow an item, echo its selector, \
                 host, port and item_type back in a send_gopher_request. Items whose \
                 'item_type' is 'i' are informational text, not links - there is nothing to \
                 follow."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "malformed_lines".to_string(),
            type_hint: "array".to_string(),
            description:
                "Lines the server sent that are not well-formed menu lines, kept verbatim so \
                 nothing is silently dropped. Absent when there were none."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the reply hit the client's size cap and was cut short"
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("<- Gopher menu {selector} ({item_count} items)")
            .with_debug("Gopher menu from {host}:{port} selector={selector} items={item_count}")
            .with_trace("Gopher menu items: {json_pretty(items)}"),
    )
});

/// A document arrived; the terminator is gone and the doubled leading dots are undone.
pub static GOPHER_DOCUMENT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gopher_document_received",
        "A Gopher text document was fetched",
        json!({
            "type": "send_gopher_request",
            "selector": "",
            "item_type": "1"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "selector".to_string(),
            type_hint: "string".to_string(),
            description: "The selector that was asked for".to_string(),
            required: true,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "Host the document came from".to_string(),
            required: true,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Port the document came from".to_string(),
            required: true,
        },
        Parameter {
            name: "requested_item_type".to_string(),
            type_hint: "string".to_string(),
            description: "The item type this request asked for. If it is '1' or '7' the reply was \
                 expected to be a menu and no line of it parsed as one, so it is being \
                 reported as a document instead."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description:
                "The document body as plain text: CRLF turned into newlines, the terminating \
                 '.' line removed, and any doubled leading period undone"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "line_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many lines the document has".to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the reply hit the client's size cap and was cut short"
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("<- Gopher document {selector} ({line_count} lines)")
            .with_debug("Gopher document from {host}:{port} selector={selector}")
            .with_trace("Gopher document: {preview(text, 400)}"),
    )
});

/// The server answered with a type-3 item, which is the only error Gopher has.
pub static GOPHER_ERROR_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gopher_error_received",
        "The Gopher server answered with a type-3 error item",
        json!({
            "type": "send_gopher_request",
            "selector": "",
            "item_type": "1"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "selector".to_string(),
            type_hint: "string".to_string(),
            description: "The selector that was asked for".to_string(),
            required: true,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "Host that reported the error".to_string(),
            required: true,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Port that reported the error".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The display text of the type-3 item".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("<- Gopher error for {selector}: {message}")
            .with_debug("Gopher error from {host}:{port} selector={selector}: {message}"),
    )
});

pub fn get_gopher_client_event_types() -> Vec<EventType> {
    vec![
        GOPHER_MENU_RECEIVED_EVENT.clone(),
        GOPHER_DOCUMENT_RECEIVED_EVENT.clone(),
        GOPHER_ERROR_RECEIVED_EVENT.clone(),
    ]
}

/// Gopher client protocol handler.
pub struct GopherClientProtocol;

impl GopherClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GopherClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Reject a field that would forge extra request structure.
///
/// A selector is written to the wire as `<selector>\r\n`, and a type-7 search as
/// `<selector>\t<query>\r\n`. A CR or LF inside either would end the request line early and
/// leave the rest as a second request; a tab inside a selector would turn a plain fetch into
/// a search. Both are the request-side equivalent of the header-injection bug the server side
/// guards against, so they are refused rather than quietly rewritten - the model has to see
/// that its selector was wrong.
fn reject_wire_breaks(field: &str, value: &str, tab_allowed: bool) -> Result<()> {
    if value.contains('\r') || value.contains('\n') {
        bail!("'{field}' must not contain a carriage return or a line feed");
    }
    if !tab_allowed && value.contains('\t') {
        bail!("'{field}' must not contain a tab; a tab is what turns a fetch into a search");
    }
    Ok(())
}

/// Pull the optional `host` / `port` override out of a fetch action.
///
/// Absent means "the address this client was opened against", which is what makes the first
/// request easy to write. A menu item carries its own host and port precisely so that a
/// gopherspace can span servers, so both are settable.
fn fetch_target(action: &serde_json::Value) -> Result<(Option<String>, Option<u16>)> {
    let host = match action.get("host").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() => {
            reject_wire_breaks("host", h, false)?;
            Some(h.to_string())
        }
        _ => None,
    };
    let port = match action.get("port") {
        Some(serde_json::Value::Null) | None => None,
        Some(v) => {
            let n = v
                .as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                .context("'port' must be a number between 1 and 65535")?;
            if n == 0 || n > u16::MAX as u64 {
                bail!("'port' must be a number between 1 and 65535");
            }
            Some(n as u16)
        }
    };
    Ok((host, port))
}

impl Protocol for GopherClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            send_gopher_request_action(),
            send_gopher_search_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // Deliberately empty: a client cannot narrow, so the union above is the whole
        // vocabulary at every point in the session. See the module docs.
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        "Gopher"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_gopher_client_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>GOPHER"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["gopher", "gopher client", "gopherspace", "gopher hole"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Hand-rolled RFC 1436 over plain tokio TCP; no library. Gopher is one request \
                 per connection, so every fetch opens its own socket, writes one selector \
                 line and reads to EOF - the close is the framing. The reply is parsed \
                 according to the item type the request asked for, which is the only thing \
                 that says whether it is a menu or a document.",
            )
            .llm_control(
                "Which selector to fetch, on which host and port, and what the reply was \
                 expected to be. Menus arrive parsed into structured items, so following a \
                 link is echoing an item's fields back in a send_gopher_request.",
            )
            .e2e_testing(
                "tests/client/gopher/e2e_test.rs. Its peer is NetGet's own Gopher server, so \
                 the exchange is same-project evidence: it shows the two halves agree, not \
                 that either matches RFC 1436.",
            )
            .notes(
                "Experimental, and the reason is the evidence rather than the code: no \
                 third-party Gopher server has been pointed at it. The one sniff is \
                 deliberate - a type-3 item is recognised whatever type was asked for, \
                 because it is the protocol's only error channel. Not implemented: Gopher+, \
                 TLS ('gophers'), binary item transfer (types 4/5/6/9/g/I are listed but not \
                 downloaded, since that would mean base64 in an event) and CSO (type 2).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Gopher (RFC 1436) client: fetch menus, documents and searches from a gopher hole"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the Gopher server at 127.0.0.1:70, fetch the root menu and then read the \
         first text file it lists"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven browsing.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:70",
                "base_stack": "gopher",
                "instruction": "Fetch the root menu, then read every text file it lists and \
                                summarise them."
            }),
            // Script-based: decide the next fetch in code, no model call.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:70",
                "base_stack": "gopher",
                "event_handlers": [{
                    "event_pattern": "gopher_menu_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "items = event.get('items', [])\ntexts = [i for i in items if i.get('item_type') == '0']\nif texts:\n    first = texts[0]\n    respond([{'type': 'send_gopher_request', 'selector': first['selector'], 'host': first['host'], 'port': first['port'], 'item_type': '0'}])\nelse:\n    respond([{'type': 'disconnect'}])"
                    }
                }]
            }),
            // Static: read one document and stop.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:70",
                "base_stack": "gopher",
                "event_handlers": [{
                    "event_pattern": "gopher_document_received",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "disconnect"}]
                    }
                }]
            }),
        )
    }
}

impl Client for GopherClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::gopher::GopherClient;
            GopherClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_gopher_request" => {
                // An absent selector is the root menu, which is the single most common
                // request there is - requiring the empty string would be a trap.
                let selector = action
                    .get("selector")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                reject_wire_breaks("selector", &selector, false)?;

                let item_type = parse_item_type(&action)?;
                let (host, port) = fetch_target(&action)?;

                Ok(ClientActionResult::Custom {
                    name: GOPHER_FETCH_RESULT.to_string(),
                    data: json!({
                        "selector": selector,
                        "item_type": item_type.to_string(),
                        "host": host,
                        "port": port,
                        "query": serde_json::Value::Null,
                    }),
                })
            }
            "send_gopher_search" => {
                let selector = action
                    .get("selector")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                reject_wire_breaks("selector", &selector, false)?;

                let query = action
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("send_gopher_search needs a 'query' - the words to search for")?
                    .to_string();
                // A tab inside a query is legal: RFC 1436 splits the request line on the
                // first tab only, so everything after it is the query.
                reject_wire_breaks("query", &query, true)?;

                let (host, port) = fetch_target(&action)?;

                Ok(ClientActionResult::Custom {
                    name: GOPHER_FETCH_RESULT.to_string(),
                    data: json!({
                        "selector": selector,
                        // A search always answers with a menu of results.
                        "item_type": "7",
                        "host": host,
                        "port": port,
                        "query": query,
                    }),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            other => Err(anyhow::anyhow!("Unknown Gopher client action: {}", other)),
        }
    }
}

/// `item_type` is one character. Anything longer is a mistake worth reporting rather than
/// truncating, because the character decides how the reply is read.
fn parse_item_type(action: &serde_json::Value) -> Result<char> {
    let Some(raw) = action.get("item_type").and_then(|v| v.as_str()) else {
        return Ok(DEFAULT_ITEM_TYPE);
    };
    if raw.is_empty() {
        return Ok(DEFAULT_ITEM_TYPE);
    }
    let mut chars = raw.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Ok(c),
        _ => bail!("'item_type' is exactly one character, not {raw:?}"),
    }
}

fn send_gopher_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gopher_request".to_string(),
        description:
            "Fetch one Gopher item. Gopher is one request per connection: this opens its own \
             connection, sends the selector, reads until the server hangs up, and reports the \
             reply back to you as a gopher_menu_received, gopher_document_received or \
             gopher_error_received event. To follow a link from a menu, copy that item's \
             'selector', 'host', 'port' and 'item_type' straight from the menu you were given."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "selector".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The selector to fetch. Leave it out or use the empty string for the root \
                     menu. Never include the item-type character here: a Gopher URL such as \
                     gopher://host/0/about.txt has selector '/about.txt'."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "item_type".to_string(),
                type_hint: "string".to_string(),
                description:
                    "One character saying what you expect back, because the reply itself does \
                     not say: '1' a menu (the default), '7' a search menu, '0' a text \
                     document. Anything else is read as a document. A menu item tells you its \
                     own type - use that."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "host".to_string(),
                type_hint: "string".to_string(),
                description: "Host to fetch from. Defaults to the address this client was opened \
                     against; menu items carry their own host so a gopherspace can span servers."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: "Port to fetch from. Defaults to the port this client was opened \
                              against."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gopher_request",
            "selector": "/about.txt",
            "item_type": "0",
            "host": "127.0.0.1",
            "port": 70
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gopher fetch {selector}")
                .with_debug("Gopher send_gopher_request: selector={selector} type={item_type}"),
        ),
    }
}

fn send_gopher_search_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gopher_search".to_string(),
        description:
            "Run a search against a type-7 item. Same as send_gopher_request except that the \
             search terms are sent with the selector, and the reply is always a menu of \
             results. Use the selector of the '7' item you found in a menu."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "selector".to_string(),
                type_hint: "string".to_string(),
                description: "Selector of the type-7 search item".to_string(),
                required: true,
            },
            Parameter {
                name: "query".to_string(),
                type_hint: "string".to_string(),
                description: "The words to search for".to_string(),
                required: true,
            },
            Parameter {
                name: "host".to_string(),
                type_hint: "string".to_string(),
                description: "Host to search. Defaults to the address this client was opened \
                              against."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: "Port to search. Defaults to the port this client was opened \
                              against."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gopher_search",
            "selector": "/search",
            "query": "burrow"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gopher search {selector} for {query}")
                .with_debug("Gopher send_gopher_search: selector={selector} query={query}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description:
            "Stop here and do nothing further on your own. Gopher replies are never partial - \
             the server closing the connection is what marks a reply complete - so this does \
             not wait for more bytes. It ends the automatic browse and leaves the client idle \
             until someone sends it another request."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Gopher client idle")
                .with_debug("Gopher wait_for_more: browse stopped, client idle"),
        ),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description:
            "End the browsing session. Gopher holds no connection between requests, so there \
             is no socket to close - this marks the client finished, stops it acting on its \
             own, and takes it out of the dashboard's send list."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Gopher browsing session ended")
                .with_debug("Gopher disconnect"),
        ),
    }
}
